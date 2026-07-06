<?php
/**
 * TOTP two-factor authentication.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * WordPress-facing 2FA: profile enrollment, login interstitial, recovery
 * codes, and enforcement policy.
 *
 * This module ALWAYS boots — 2FA is per-user state, and flipping the module
 * off must never silently strip a second factor from enrolled users.
 *
 * Login flow: after the password check passes (authenticate priority 50),
 * the login is parked in a short-lived transient keyed by a random token
 * and an interstitial asks for the code. Cookies are only set after a valid
 * TOTP or recovery code.
 */
class Blt_Secure_Two_Factor implements Blt_Secure_Module {

	const META_SECRET     = '_blt_secure_totp_secret';
	const META_PENDING    = '_blt_secure_totp_pending';
	const META_LAST_SLICE = '_blt_secure_totp_last_slice';
	const META_RECOVERY   = '_blt_secure_recovery_codes';

	const PENDING_TTL  = 5 * MINUTE_IN_SECONDS;
	const MAX_ATTEMPTS = 5;

	/**
	 * Settings.
	 *
	 * @var Blt_Secure_Options
	 */
	private $options;

	/**
	 * Crypto for secret storage.
	 *
	 * @var Blt_Secure_Crypto
	 */
	private $crypto;

	/**
	 * Alerting.
	 *
	 * @var Blt_Secure_Alerting
	 */
	private $alerting;

	/**
	 * TOTP math.
	 *
	 * @var Blt_Secure_Totp
	 */
	private $totp;

	/**
	 * Constructor.
	 *
	 * @param Blt_Secure_Options  $options Settings access.
	 * @param Blt_Secure_Crypto   $crypto Crypto backend.
	 * @param Blt_Secure_Alerting $alerting Event sink.
	 */
	public function __construct( Blt_Secure_Options $options, Blt_Secure_Crypto $crypto, Blt_Secure_Alerting $alerting ) {
		$this->options  = $options;
		$this->crypto   = $crypto;
		$this->alerting = $alerting;
		$this->totp     = new Blt_Secure_Totp();
	}

	/**
	 * Module id.
	 *
	 * @return string
	 */
	public function id() {
		return 'twofa';
	}

	/**
	 * Defaults.
	 *
	 * @return array
	 */
	public function defaults() {
		return array(
			'policy' => 'optional', // optional | required_admins | required_all.
		);
	}

	/**
	 * Always on (see class docblock).
	 *
	 * @return bool
	 */
	public function is_enabled() {
		return true;
	}

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function boot() {
		add_filter( 'authenticate', array( $this, 'maybe_interstitial' ), 50, 1 );
		add_action( 'login_form_blt_2fa', array( $this, 'handle_interstitial' ) );

		add_action( 'show_user_profile', array( $this, 'render_profile_section' ) );
		add_action( 'personal_options_update', array( $this, 'handle_profile_save' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_profile_assets' ) );
		add_action( 'admin_notices', array( $this, 'policy_nag' ) );
	}

	/**
	 * Sanitize section.
	 *
	 * @param array $input Raw input.
	 * @param array $current Current values.
	 * @return array
	 */
	public function sanitize( $input, $current ) {
		$policy  = isset( $input['policy'] ) ? sanitize_key( $input['policy'] ) : 'optional';
		$allowed = array( 'optional', 'required_admins', 'required_all' );

		return array(
			'policy' => in_array( $policy, $allowed, true ) ? $policy : 'optional',
		);
	}

	// -------------------------------------------------------------------
	// State helpers.
	// -------------------------------------------------------------------

	/**
	 * Whether a user has completed enrollment.
	 *
	 * @param int $user_id User id.
	 * @return bool
	 */
	public function is_enrolled( $user_id ) {
		return '' !== (string) get_user_meta( $user_id, self::META_SECRET, true );
	}

	/**
	 * Whether policy demands 2FA for this user.
	 *
	 * @param WP_User $user User.
	 * @return bool
	 */
	public function is_required_for( $user ) {
		$policy = $this->options->get( 'twofa', 'policy', 'optional' );

		if ( 'required_all' === $policy ) {
			return true;
		}
		if ( 'required_admins' === $policy ) {
			return ! empty( array_intersect( array( 'administrator' ), (array) $user->roles ) ) || is_super_admin( $user->ID );
		}
		return false;
	}

	/**
	 * Decrypt a user's TOTP secret. On failure (rotated salts) the user's
	 * 2FA is disabled with an alert rather than silently locking them out.
	 *
	 * @param int $user_id User id.
	 * @return string Base32 secret, or '' when unavailable.
	 */
	private function user_secret( $user_id ) {
		$envelope = (string) get_user_meta( $user_id, self::META_SECRET, true );
		if ( '' === $envelope ) {
			return '';
		}

		$plain = $this->crypto->decrypt( $envelope );
		if ( is_wp_error( $plain ) ) {
			$this->disable_for_user( $user_id );
			$this->alerting->notify( 'twofa_secret_lost', array( 'user' => $user_id ) );
			return '';
		}

		return $plain;
	}

	/**
	 * Remove all 2FA state for a user.
	 *
	 * @param int $user_id User id.
	 * @return void
	 */
	private function disable_for_user( $user_id ) {
		delete_user_meta( $user_id, self::META_SECRET );
		delete_user_meta( $user_id, self::META_PENDING );
		delete_user_meta( $user_id, self::META_LAST_SLICE );
		delete_user_meta( $user_id, self::META_RECOVERY );
	}

	// -------------------------------------------------------------------
	// Login flow.
	// -------------------------------------------------------------------

	/**
	 * After the password passes, divert enrolled users to the interstitial
	 * instead of completing the login.
	 *
	 * @param WP_User|WP_Error|null $user Auth result so far.
	 * @return WP_User|WP_Error|null
	 */
	public function maybe_interstitial( $user ) {
		if ( ! $user instanceof WP_User || ! $this->is_enrolled( $user->ID ) ) {
			return $user;
		}

		// Non-interactive authentication cannot present a code. Application
		// passwords are their own credential and pass through; plain
		// password auth over XML-RPC/REST is refused for 2FA users.
		if ( ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			if ( did_action( 'application_password_did_authenticate' ) ) {
				return $user;
			}
			return new WP_Error(
				'blt_secure_2fa_required',
				__( 'Two-factor authentication is required; password-only API access is disabled for this account. Use an application password.', 'blt-secure' )
			);
		}

		$token = wp_generate_password( 32, false, false );
		set_transient(
			'blt_sec_2fa_' . $token,
			array(
				'user_id'  => $user->ID,
				'remember' => ! empty( $_POST['rememberme'] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'redirect' => isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : '', // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				'attempts' => 0,
			),
			self::PENDING_TTL
		);

		$this->render_interstitial( $token );
		exit;
	}

	/**
	 * Handle the interstitial POST (wp-login.php?action=blt_2fa).
	 *
	 * @return void
	 */
	public function handle_interstitial() {
		if ( 'POST' !== strtoupper( isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '' ) ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		check_admin_referer( 'blt_secure_2fa' );

		$token = isset( $_POST['blt_token'] ) ? sanitize_text_field( wp_unslash( $_POST['blt_token'] ) ) : '';
		$code  = isset( $_POST['blt_code'] ) ? sanitize_text_field( wp_unslash( $_POST['blt_code'] ) ) : '';

		$key     = 'blt_sec_2fa_' . $token;
		$pending = get_transient( $key );

		if ( ! is_array( $pending ) || empty( $pending['user_id'] ) ) {
			$this->login_error_redirect( __( 'Your login session expired. Please sign in again.', 'blt-secure' ) );
		}

		++$pending['attempts'];
		if ( $pending['attempts'] > self::MAX_ATTEMPTS ) {
			delete_transient( $key );
			$this->alerting->notify( 'twofa_bruteforce', array( 'user' => (int) $pending['user_id'] ) );
			$this->login_error_redirect( __( 'Too many incorrect codes. Please sign in again.', 'blt-secure' ) );
		}
		set_transient( $key, $pending, self::PENDING_TTL );

		$user_id = (int) $pending['user_id'];

		if ( ! $this->accept_code( $user_id, $code ) ) {
			$this->render_interstitial( $token, __( 'That code is incorrect or expired. Try the current code from your app, or a recovery code.', 'blt-secure' ) );
			exit;
		}

		delete_transient( $key );

		wp_set_auth_cookie( $user_id, ! empty( $pending['remember'] ) );
		$user = get_user_by( 'id', $user_id );
		/** This action is documented in wp-includes/user.php */
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound

		$redirect = ! empty( $pending['redirect'] ) ? $pending['redirect'] : admin_url();
		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * Try TOTP first, then a recovery code.
	 *
	 * @param int    $user_id User id.
	 * @param string $code Submitted code.
	 * @return bool
	 */
	private function accept_code( $user_id, $code ) {
		$secret = $this->user_secret( $user_id );

		if ( '' !== $secret ) {
			$last  = (int) get_user_meta( $user_id, self::META_LAST_SLICE, true );
			$slice = $this->totp->verify( $secret, $code, $last > 0 ? $last : -1 );
			if ( false !== $slice ) {
				update_user_meta( $user_id, self::META_LAST_SLICE, $slice );
				return true;
			}
		}

		return $this->burn_recovery_code( $user_id, $code );
	}

	/**
	 * Verify and consume a recovery code.
	 *
	 * @param int    $user_id User id.
	 * @param string $code Submitted code.
	 * @return bool
	 */
	private function burn_recovery_code( $user_id, $code ) {
		$code = strtoupper( preg_replace( '/[\s\-]+/', '', (string) $code ) );
		if ( strlen( $code ) < 8 ) {
			return false;
		}

		$hashes = get_user_meta( $user_id, self::META_RECOVERY, true );
		if ( ! is_array( $hashes ) ) {
			return false;
		}

		foreach ( $hashes as $i => $hash ) {
			if ( wp_check_password( $code, $hash ) ) {
				unset( $hashes[ $i ] );
				update_user_meta( $user_id, self::META_RECOVERY, array_values( $hashes ) );
				$this->alerting->notify(
					'twofa_recovery_used',
					array(
						'user'      => $user_id,
						'remaining' => count( $hashes ),
					)
				);
				return true;
			}
		}

		return false;
	}

	/**
	 * Minimal login-styled interstitial (uses core's login_header when
	 * available; degrades to a bare form).
	 *
	 * @param string $token Pending-login token.
	 * @param string $error Optional error message.
	 * @return void
	 */
	private function render_interstitial( $token, $error = '' ) {
		nocache_headers();

		$action_url = add_query_arg( 'action', 'blt_2fa', wp_login_url() );

		if ( function_exists( 'login_header' ) ) {
			$wp_error = $error ? new WP_Error( 'blt_secure_2fa_bad_code', $error ) : null;
			login_header( __( 'Two-Factor Authentication', 'blt-secure' ), '', $wp_error );
		} else {
			// authenticate runs before wp-login.php declares login_header();
			// pull in its definitions without executing the request flow.
			echo '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
			echo '<title>' . esc_html__( 'Two-Factor Authentication', 'blt-secure' ) . '</title>';
			wp_admin_css( 'login', true );
			echo '</head><body class="login"><div id="login" style="width:320px;margin:8% auto;">';
			if ( $error ) {
				echo '<div id="login_error" class="notice notice-error" style="background:#fff;border-left:4px solid #d63638;padding:12px;margin-bottom:16px;">' . esc_html( $error ) . '</div>';
			}
		}
		?>
		<form method="post" action="<?php echo esc_url( $action_url ); ?>" style="background:#fff;padding:26px 24px;box-shadow:0 1px 3px rgba(0,0,0,.13);">
			<?php wp_nonce_field( 'blt_secure_2fa' ); ?>
			<input type="hidden" name="blt_token" value="<?php echo esc_attr( $token ); ?>" />
			<p style="margin:0 0 12px;">
				<label for="blt_code"><?php esc_html_e( 'Enter the 6-digit code from your authenticator app, or a recovery code.', 'blt-secure' ); ?></label>
			</p>
			<p style="margin:0 0 16px;">
				<input type="text" name="blt_code" id="blt_code" class="input" autocomplete="one-time-code" inputmode="numeric" autofocus
					style="width:100%;font-size:24px;letter-spacing:.25em;text-align:center;padding:6px;" />
			</p>
			<p style="margin:0;">
				<button type="submit" class="button button-primary button-large" style="width:100%;"><?php esc_html_e( 'Verify', 'blt-secure' ); ?></button>
			</p>
		</form>
		<?php
		if ( function_exists( 'login_footer' ) ) {
			login_footer();
		} else {
			echo '</div></body></html>';
		}
	}

	/**
	 * Bounce back to the login form with a message.
	 *
	 * @param string $message Error text.
	 * @return void
	 */
	private function login_error_redirect( $message ) {
		wp_safe_redirect( add_query_arg( 'blt_2fa_error', rawurlencode( $message ), wp_login_url() ) );
		exit;
	}

	// -------------------------------------------------------------------
	// Enrollment (profile page).
	// -------------------------------------------------------------------

	/**
	 * Enqueue the bundled QR generator on profile screens.
	 *
	 * @param string $hook Current admin page.
	 * @return void
	 */
	public function enqueue_profile_assets( $hook ) {
		if ( 'profile.php' === $hook ) {
			wp_enqueue_script( 'blt-secure-qrcode', BLT_SECURE_URL . 'admin/js/qrcode.js', array(), BLT_SECURE_VERSION, true );
		}
	}

	/**
	 * Render the 2FA section on the user's own profile.
	 *
	 * @param WP_User $user Profile owner.
	 * @return void
	 */
	public function render_profile_section( $user ) {
		if ( get_current_user_id() !== $user->ID ) {
			return; // Self-service only — admins can't see other users' secrets.
		}
		?>
		<h2><?php esc_html_e( 'Two-Factor Authentication (BLT Secure)', 'blt-secure' ); ?></h2>
		<table class="form-table" role="presentation">
		<?php if ( $this->is_enrolled( $user->ID ) ) : ?>
			<tr>
				<th><?php esc_html_e( 'Status', 'blt-secure' ); ?></th>
				<td>
					<p><strong style="color:#00a32a;">✓ <?php esc_html_e( 'Enabled', 'blt-secure' ); ?></strong></p>
					<?php $remaining = count( (array) get_user_meta( $user->ID, self::META_RECOVERY, true ) ); ?>
					<p class="description">
						<?php
						printf(
							/* translators: %d: number of unused recovery codes */
							esc_html__( '%d recovery codes remaining.', 'blt-secure' ),
							(int) $remaining
						);
						?>
					</p>
					<p>
						<label>
							<input type="checkbox" name="blt_2fa_disable" value="1" />
							<?php esc_html_e( 'Disable two-factor authentication', 'blt-secure' ); ?>
						</label>
					</p>
				</td>
			</tr>
		<?php else : ?>
			<?php
			$pending = (string) get_user_meta( $user->ID, self::META_PENDING, true );
			$secret  = '';
			if ( '' !== $pending ) {
				$plain  = $this->crypto->decrypt( $pending );
				$secret = is_wp_error( $plain ) ? '' : $plain;
			}
			if ( '' === $secret ) {
				$secret   = Blt_Secure_Totp::generate_secret();
				$envelope = $this->crypto->encrypt( $secret );
				if ( ! is_wp_error( $envelope ) ) {
					update_user_meta( $user->ID, self::META_PENDING, $envelope );
				}
			}
			$uri = $this->totp->provisioning_uri( $secret, $user->user_login, wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES ) );
			?>
			<tr>
				<th><?php esc_html_e( 'Set up', 'blt-secure' ); ?></th>
				<td>
					<p class="description"><?php esc_html_e( '1. Scan this QR code with your authenticator app (or enter the key manually). 2. Enter the 6-digit code it shows. 3. Save your profile.', 'blt-secure' ); ?></p>
					<div id="blt-2fa-qr" data-uri="<?php echo esc_attr( $uri ); ?>" style="margin:12px 0;"></div>
					<p><code style="user-select:all;"><?php echo esc_html( $secret ); ?></code></p>
					<p>
						<label for="blt_2fa_code"><?php esc_html_e( 'Confirmation code', 'blt-secure' ); ?></label><br />
						<input type="text" name="blt_2fa_code" id="blt_2fa_code" autocomplete="one-time-code" inputmode="numeric" class="regular-text" style="max-width:140px;letter-spacing:.2em;" />
					</p>
					<script>
					document.addEventListener('DOMContentLoaded', function () {
						var el = document.getElementById('blt-2fa-qr');
						if (el && window.bltQrRender) { window.bltQrRender(el, el.getAttribute('data-uri')); }
					});
					</script>
				</td>
			</tr>
		<?php endif; ?>
		</table>
		<?php
	}

	/**
	 * Handle enrollment/disable submitted with the profile form.
	 *
	 * @param int $user_id Profile owner.
	 * @return void
	 */
	public function handle_profile_save( $user_id ) {
		if ( get_current_user_id() !== (int) $user_id ) {
			return;
		}
		// personal_options_update runs after check_admin_referer('update-user_' . $user_id).

		// Disable request.
		if ( ! empty( $_POST['blt_2fa_disable'] ) && $this->is_enrolled( $user_id ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			$this->disable_for_user( $user_id );
			$this->alerting->notify( 'twofa_disabled', array( 'user' => $user_id ) );
			return;
		}

		// Enrollment confirmation.
		$code = isset( $_POST['blt_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['blt_2fa_code'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( '' === $code || $this->is_enrolled( $user_id ) ) {
			return;
		}

		$pending = (string) get_user_meta( $user_id, self::META_PENDING, true );
		if ( '' === $pending ) {
			return;
		}
		$secret = $this->crypto->decrypt( $pending );
		if ( is_wp_error( $secret ) ) {
			delete_user_meta( $user_id, self::META_PENDING );
			return;
		}

		$slice = $this->totp->verify( $secret, $code );
		if ( false === $slice ) {
			add_action(
				'user_profile_update_errors',
				static function ( $errors ) {
					$errors->add( 'blt_2fa_bad_code', __( 'Two-factor setup: that code did not match — 2FA was NOT enabled. Re-scan and try again.', 'blt-secure' ) );
				}
			);
			return;
		}

		// Code proven — promote pending secret and issue recovery codes.
		update_user_meta( $user_id, self::META_SECRET, $pending );
		update_user_meta( $user_id, self::META_LAST_SLICE, $slice );
		delete_user_meta( $user_id, self::META_PENDING );

		$codes  = array();
		$hashes = array();
		for ( $i = 0; $i < 8; $i++ ) {
			$code_plain = substr( Blt_Secure_Totp::base32_encode( random_bytes( 10 ) ), 0, 10 );
			$codes[]    = $code_plain;
			$hashes[]   = wp_hash_password( $code_plain );
		}
		update_user_meta( $user_id, self::META_RECOVERY, $hashes );
		set_transient( 'blt_sec_2fa_codes_' . $user_id, $codes, 5 * MINUTE_IN_SECONDS );

		add_action( 'admin_notices', array( $this, 'show_recovery_codes_once' ) );
		$this->alerting->notify( 'twofa_enabled', array( 'user' => $user_id ) );
	}

	/**
	 * One-time display of freshly generated recovery codes.
	 *
	 * @return void
	 */
	public function show_recovery_codes_once() {
		$user_id = get_current_user_id();
		$codes   = get_transient( 'blt_sec_2fa_codes_' . $user_id );
		delete_transient( 'blt_sec_2fa_codes_' . $user_id );

		if ( ! is_array( $codes ) || empty( $codes ) ) {
			return;
		}
		?>
		<div class="notice notice-success">
			<p><strong><?php esc_html_e( 'Two-factor authentication is ON.', 'blt-secure' ); ?></strong>
			<?php esc_html_e( 'Save these recovery codes somewhere safe — they are shown only once, and each works once:', 'blt-secure' ); ?></p>
			<pre style="font-size:14px;line-height:1.8;user-select:all;"><?php echo esc_html( implode( "\n", $codes ) ); ?></pre>
		</div>
		<?php
	}

	/**
	 * Nag (never lock out) users the policy covers who haven't enrolled.
	 *
	 * @return void
	 */
	public function policy_nag() {
		$user = wp_get_current_user();
		if ( ! $user->exists() || $this->is_enrolled( $user->ID ) || ! $this->is_required_for( $user ) ) {
			return;
		}
		printf(
			'<div class="notice notice-warning"><p><strong>%s</strong> %s <a href="%s">%s</a></p></div>',
			esc_html__( 'Two-factor authentication is required for your account.', 'blt-secure' ),
			esc_html__( 'Please set it up now:', 'blt-secure' ),
			esc_url( get_edit_profile_url() . '#blt-2fa-qr' ),
			esc_html__( 'Enable 2FA on your profile', 'blt-secure' )
		);
	}
}
