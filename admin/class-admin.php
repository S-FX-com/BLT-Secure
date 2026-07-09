<?php
/**
 * Admin UI: settings page + Cloudflare AJAX actions.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once BLT_SECURE_DIR . 'includes/cloudflare/class-cloudflare-api.php';
require_once BLT_SECURE_DIR . 'includes/cloudflare/class-cloudflare-state.php';
require_once BLT_SECURE_DIR . 'includes/cloudflare/rule-definitions.php';
require_once BLT_SECURE_DIR . 'includes/cloudflare/class-cloudflare-deployer.php';
require_once BLT_SECURE_DIR . 'admin/views/partials.php';

/**
 * One settings page, four tabs. Hardening/Login/Advanced post through the
 * Settings API (section-merging sanitizer — saving one tab never wipes
 * another); the Cloudflare tab drives multi-step deploys over AJAX with a
 * nonce and capability check per action.
 */
class Blt_Secure_Admin {

	/**
	 * Plugin core.
	 *
	 * @var Blt_Secure
	 */
	private $plugin;

	/**
	 * CF state store.
	 *
	 * @var Blt_Secure_Cloudflare_State
	 */
	private $cf_state;

	/**
	 * Constructor.
	 *
	 * @param Blt_Secure $plugin Plugin core.
	 */
	public function __construct( Blt_Secure $plugin ) {
		$this->plugin   = $plugin;
		$this->cf_state = new Blt_Secure_Cloudflare_State();

		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'admin_notices', array( $this, 'salt_rotation_notice' ) );

		add_action( 'wp_ajax_blt_secure_cf_save_token', array( $this, 'ajax_save_token' ) );
		add_action( 'wp_ajax_blt_secure_cf_delete_token', array( $this, 'ajax_delete_token' ) );
		add_action( 'wp_ajax_blt_secure_cf_deploy', array( $this, 'ajax_deploy' ) );
		add_action( 'wp_ajax_blt_secure_cf_remove', array( $this, 'ajax_remove' ) );
		add_action( 'wp_ajax_blt_secure_gh_save_token', array( $this, 'ajax_gh_save_token' ) );
		add_action( 'wp_ajax_blt_secure_gh_delete_token', array( $this, 'ajax_gh_delete_token' ) );
		add_action( 'admin_notices', array( $this, 'update_token_notice' ) );
	}

	/**
	 * Menu entry.
	 *
	 * @return void
	 */
	public function register_menu() {
		add_menu_page(
			__( 'BLT Secure', 'blt-secure' ),
			__( 'BLT Secure', 'blt-secure' ),
			'manage_options',
			'blt-secure',
			array( $this, 'render_page' ),
			'dashicons-shield-alt',
			81
		);
	}

	/**
	 * Settings API registration with the section-merging sanitizer.
	 *
	 * @return void
	 */
	public function register_settings() {
		register_setting(
			'blt_secure',
			Blt_Secure_Options::OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_settings' ),
			)
		);
	}

	/**
	 * Merge the posted sections into the saved array, dispatching each
	 * section to its module's sanitizer.
	 *
	 * @param mixed $input Posted value.
	 * @return array
	 */
	public function sanitize_settings( $input ) {
		$saved = get_option( Blt_Secure_Options::OPTION, array() );
		if ( ! is_array( $saved ) ) {
			$saved = array();
		}
		if ( ! is_array( $input ) ) {
			return $saved;
		}

		$defaults = $this->plugin->options->get_defaults();

		foreach ( $input as $section => $values ) {
			$section = sanitize_key( $section );
			if ( ! is_array( $values ) ) {
				continue;
			}

			$current = isset( $saved[ $section ] ) && is_array( $saved[ $section ] ) ? $saved[ $section ] : array();

			if ( isset( $this->plugin->modules[ $section ] ) ) {
				$saved[ $section ] = $this->plugin->modules[ $section ]->sanitize( $values, $current );
			} elseif ( 'advanced' === $section ) {
				$saved[ $section ] = $this->sanitize_advanced( $values );
			} elseif ( isset( $defaults[ $section ] ) ) {
				// Unknown-but-registered section: keep only known keys, as strings.
				$saved[ $section ] = array_intersect_key( array_map( 'sanitize_text_field', $values ), $defaults[ $section ] );
			}
		}

		$saved['schema_version'] = 1;
		return $saved;
	}

	/**
	 * Advanced tab sanitizer (no module class).
	 *
	 * @param array $input Raw values.
	 * @return array
	 */
	private function sanitize_advanced( array $input ) {
		$mode = isset( $input['trust_cf_header'] ) ? sanitize_key( $input['trust_cf_header'] ) : 'auto';

		return array(
			'trust_cf_header'          => in_array( $mode, array( 'auto', 'always', 'never' ), true ) ? $mode : 'auto',
			'remove_cf_on_uninstall'   => ! empty( $input['remove_cf_on_uninstall'] ),
			'delete_data_on_uninstall' => ! empty( $input['delete_data_on_uninstall'] ),
		);
	}

	/**
	 * Page assets, only on our screen.
	 *
	 * @param string $hook Current admin page.
	 * @return void
	 */
	public function enqueue_assets( $hook ) {
		if ( 'toplevel_page_blt-secure' !== $hook ) {
			return;
		}

		wp_enqueue_style( 'blt-secure-admin', BLT_SECURE_URL . 'admin/css/admin.css', array(), BLT_SECURE_VERSION );
		wp_enqueue_script( 'blt-secure-admin', BLT_SECURE_URL . 'admin/js/admin.js', array(), BLT_SECURE_VERSION, true );
		wp_localize_script(
			'blt-secure-admin',
			'bltSecure',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'blt_secure_cf' ),
				'i18n'    => array(
					'working'   => __( 'Working…', 'blt-secure' ),
					'deployed'  => __( 'Deployed', 'blt-secure' ),
					'removed'   => __( 'Not deployed', 'blt-secure' ),
					'error'     => __( 'Error', 'blt-secure' ),
					'scanning'  => __( 'Running checks…', 'blt-secure' ),
					'scanError' => __( 'The scan could not be completed.', 'blt-secure' ),
					'coreScan'  => __( 'Scanning core files…', 'blt-secure' ),
					'malScan'   => __( 'Scanning wp-content for malware…', 'blt-secure' ),
					'iocSync'   => __( 'Syncing threat-intel feeds…', 'blt-secure' ),
					'polling'   => __( 'Polling Cloudflare…', 'blt-secure' ),
					'baseScan'  => __( 'Checking plugin/theme integrity…', 'blt-secure' ),
				),
			)
		);
	}

	/**
	 * Warn when salt rotation invalidated stored credentials.
	 *
	 * @return void
	 */
	public function salt_rotation_notice() {
		if ( ! current_user_can( 'manage_options' ) || ! $this->plugin->credentials->is_invalidated() ) {
			return;
		}
		printf(
			'<div class="notice notice-error"><p><strong>%s</strong> %s <a href="%s">%s</a></p></div>',
			esc_html__( 'BLT Secure:', 'blt-secure' ),
			esc_html__( 'the WordPress security keys changed, so the stored credentials (Cloudflare token, GitHub updates token) could not be decrypted and were removed. Those features are paused until you re-enter them.', 'blt-secure' ),
			esc_url( admin_url( 'admin.php?page=blt-secure&tab=cloudflare' ) ),
			esc_html__( 'Re-enter tokens', 'blt-secure' )
		);
	}

	/**
	 * Make the no-update-token state visible where it matters: against a
	 * private repo, without a token API calls 404 and update checks silently
	 * find nothing, so the site would quietly fall behind. When the repo is
	 * public (the default), no token is needed and this notice never shows.
	 *
	 * @return void
	 */
	public function update_token_notice() {
		global $pagenow;

		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		// Public repo: updates work without a token, so there is nothing to warn about.
		if ( Blt_Secure_Updater::repo_public() ) {
			return;
		}

		$on_updates_screen = in_array( $pagenow, array( 'plugins.php', 'update-core.php' ), true );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$on_our_screen = 'admin.php' === $pagenow && isset( $_GET['page'] ) && 'blt-secure' === $_GET['page'];
		if ( ! $on_updates_screen && ! $on_our_screen ) {
			return;
		}

		if ( null === $this->plugin->updater || null !== $this->plugin->updater->token() ) {
			return;
		}

		printf(
			'<div class="notice notice-warning"><p><strong>%s</strong> %s <a href="%s">%s</a></p></div>',
			esc_html__( 'BLT Secure:', 'blt-secure' ),
			esc_html__( 'plugin updates cannot be checked — no GitHub access token is configured. Add one on the Advanced tab, or define BLT_SECURE_GITHUB_TOKEN in wp-config.php.', 'blt-secure' ),
			esc_url( admin_url( 'admin.php?page=blt-secure&tab=advanced' ) ),
			esc_html__( 'Add token', 'blt-secure' )
		);
	}

	/**
	 * Render the tabbed page.
	 *
	 * @return void
	 */
	public function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$tab  = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'hardening';
		$tabs = array(
			'hardening'  => __( 'Hardening', 'blt-secure' ),
			'login'      => __( 'Login', 'blt-secure' ),
			'health'     => __( 'Health Check', 'blt-secure' ),
			'scanner'    => __( 'Scanner', 'blt-secure' ),
			'timeline'   => __( 'Timeline', 'blt-secure' ),
			'cloudflare' => __( 'Cloudflare', 'blt-secure' ),
			'advanced'   => __( 'Advanced', 'blt-secure' ),
		);
		if ( ! isset( $tabs[ $tab ] ) ) {
			$tab = 'hardening';
		}

		$options  = $this->plugin->options;
		$cf_state = $this->cf_state;
		$store    = $this->plugin->credentials;
		$admin    = $this;
		$health   = isset( $this->plugin->modules['health'] ) ? $this->plugin->modules['health'] : null;
		$scanner  = isset( $this->plugin->modules['scanner'] ) ? $this->plugin->modules['scanner'] : null;
		$malware  = isset( $this->plugin->modules['malware'] ) ? $this->plugin->modules['malware'] : null;
		$baseline = isset( $this->plugin->modules['baseline'] ) ? $this->plugin->modules['baseline'] : null;
		$ioc      = isset( $this->plugin->modules['ioc'] ) ? $this->plugin->modules['ioc'] : null;
		$timeline = isset( $this->plugin->modules['timeline'] ) ? $this->plugin->modules['timeline'] : null;

		require BLT_SECURE_DIR . 'admin/views/settings-page.php';
	}

	/**
	 * Deploy-card metadata for the Cloudflare tab.
	 *
	 * @return array[]
	 */
	public function cf_cards() {
		return array(
			'waf_managed'  => array(
				'title' => __( 'Managed WAF rules', 'blt-secure' ),
				'desc'  => __( 'Cloudflare Managed Ruleset with the WordPress category emphasized, plus the OWASP Core Ruleset at paranoia level 2. Free-plan zones automatically get the Free Managed Ruleset instead.', 'blt-secure' ),
			),
			'custom_pack'  => array(
				'title' => __( 'Custom rules pack', 'blt-secure' ),
				'desc'  => __( 'Challenge high-abuse hosting ASNs and TOR exits; block wp-config / .env / .git probes outright.', 'blt-secure' ),
			),
			'rate_limit'   => array(
				'title' => __( 'Login rate limiting', 'blt-secure' ),
				'desc'  => __( '5 requests per minute per IP on wp-login.php, xmlrpc.php, and your custom login slug; violators blocked for 10 minutes at the edge.', 'blt-secure' ),
			),
			'leaked_creds' => array(
				'title' => __( 'Leaked-credential check', 'blt-secure' ),
				'desc'  => __( 'Detects logins using breached username/password pairs on the WordPress login form and challenges them before they reach PHP.', 'blt-secure' ),
			),
			'access'       => array(
				'title' => __( 'Cloudflare Access (Zero Trust)', 'blt-secure' ),
				'desc'  => __( 'Puts wp-admin and your login URL behind Cloudflare Access with an email allow-list. An admin-ajax.php bypass is created automatically so front-end features keep working. Requires the token to also carry Account → Access: Apps and Policies: Edit.', 'blt-secure' ),
			),
		);
	}

	// -------------------------------------------------------------------
	// AJAX.
	// -------------------------------------------------------------------

	/**
	 * Shared AJAX guard.
	 *
	 * @return void
	 */
	private function guard() {
		check_ajax_referer( 'blt_secure_cf' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'blt-secure' ) ), 403 );
		}
	}

	/**
	 * Deployer wired to the stored token.
	 *
	 * @return Blt_Secure_Cloudflare_Deployer|WP_Error
	 */
	private function deployer() {
		$token = $this->plugin->credentials->get( 'cf_token' );
		if ( ! is_string( $token ) || '' === $token ) {
			return new WP_Error( 'blt_cf_no_token', __( 'No Cloudflare token is configured.', 'blt-secure' ) );
		}
		return new Blt_Secure_Cloudflare_Deployer( new Blt_Secure_Cloudflare_Api( $token ), $this->cf_state );
	}

	/**
	 * Save + verify a token, discover the zone.
	 *
	 * @return void
	 */
	public function ajax_save_token() {
		$this->guard();

		$token = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- guard() ran check_ajax_referer.
		if ( '' === $token ) {
			wp_send_json_error( array( 'message' => __( 'Token is empty.', 'blt-secure' ) ) );
		}

		if ( ! $this->plugin->credentials->is_available() ) {
			wp_send_json_error( array( 'message' => __( 'This server has no authenticated-encryption support (libsodium or OpenSSL AES-GCM); the token cannot be stored safely and was NOT saved.', 'blt-secure' ) ) );
		}

		$deployer = new Blt_Secure_Cloudflare_Deployer( new Blt_Secure_Cloudflare_Api( $token ), $this->cf_state );
		$host     = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$zone     = $deployer->connect( $host );

		if ( is_wp_error( $zone ) ) {
			wp_send_json_error( array( 'message' => $zone->get_error_message() ) );
		}

		$stored = $this->plugin->credentials->set( 'cf_token', $token );
		if ( is_wp_error( $stored ) ) {
			wp_send_json_error( array( 'message' => $stored->get_error_message() ) );
		}

		wp_send_json_success(
			array(
				'message' => sprintf(
					/* translators: 1: zone name, 2: plan */
					__( 'Connected to zone %1$s (%2$s plan).', 'blt-secure' ),
					$zone['zone_name'],
					$zone['plan'] ? $zone['plan'] : 'unknown'
				),
				'zone'    => $zone,
			)
		);
	}

	/**
	 * Forget the token and deployment state (rules stay at Cloudflare).
	 *
	 * @return void
	 */
	public function ajax_delete_token() {
		$this->guard();

		$this->plugin->credentials->delete( 'cf_token' );
		$this->cf_state->reset();

		wp_send_json_success( array( 'message' => __( 'Token removed. Rules already deployed at Cloudflare were left untouched.', 'blt-secure' ) ) );
	}

	/**
	 * Deploy a feature.
	 *
	 * @return void
	 */
	public function ajax_deploy() {
		$this->guard();

		$feature = isset( $_POST['feature'] ) ? sanitize_key( wp_unslash( $_POST['feature'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- guard() ran check_ajax_referer.
		if ( ! in_array( $feature, Blt_Secure_Cloudflare_Deployer::FEATURES, true ) ) {
			wp_send_json_error( array( 'message' => __( 'Unknown feature.', 'blt-secure' ) ) );
		}

		$deployer = $this->deployer();
		if ( is_wp_error( $deployer ) ) {
			wp_send_json_error( array( 'message' => $deployer->get_error_message() ) );
		}

		$config = array(
			'login_slug' => (string) $this->plugin->options->get( 'login', 'slug', '' ),
			'emails'     => array( get_option( 'admin_email' ) ),
		);
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- guard() ran check_ajax_referer.
		if ( isset( $_POST['paranoia'] ) ) {
			$config['paranoia'] = absint( wp_unslash( $_POST['paranoia'] ) );
		}
		if ( isset( $_POST['score_threshold'] ) ) {
			$config['score_threshold'] = absint( wp_unslash( $_POST['score_threshold'] ) );
		}
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		$result = $deployer->deploy( $feature, $config );

		if ( is_wp_error( $result ) ) {
			$hint = '';
			if ( 'blt_cf_scope' === $result->get_error_code() ) {
				$hint = ' ' . __( 'Your token is missing a permission — edit it at dash.cloudflare.com → My Profile → API Tokens and add the permission named in the card description, then retry.', 'blt-secure' );
			}
			wp_send_json_error( array( 'message' => $result->get_error_message() . $hint ) );
		}

		wp_send_json_success(
			array(
				'message' => __( 'Deployed.', 'blt-secure' ),
				'record'  => $result,
			)
		);
	}

	/**
	 * Save the GitHub updates token after proving it can see the repo.
	 *
	 * @return void
	 */
	public function ajax_gh_save_token() {
		$this->guard();

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- guard() ran check_ajax_referer.
		$token = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';
		if ( '' === $token ) {
			wp_send_json_error( array( 'message' => __( 'Token is empty.', 'blt-secure' ) ) );
		}

		if ( ! $this->plugin->credentials->is_available() ) {
			wp_send_json_error( array( 'message' => __( 'This server has no authenticated-encryption support (libsodium or OpenSSL AES-GCM); the token cannot be stored safely and was NOT saved.', 'blt-secure' ) ) );
		}

		// Verify the token can actually read the plugin repo before storing.
		$repo_path = trim( (string) wp_parse_url( Blt_Secure_Updater::REPO_URL, PHP_URL_PATH ), '/' );
		$response  = wp_remote_get(
			'https://api.github.com/repos/' . $repo_path,
			array(
				'timeout' => 15,
				'headers' => array(
					'Authorization' => 'Bearer ' . $token,
					'Accept'        => 'application/vnd.github+json',
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			wp_send_json_error( array( 'message' => $response->get_error_message() ) );
		}
		$status = (int) wp_remote_retrieve_response_code( $response );
		if ( 200 !== $status ) {
			wp_send_json_error(
				array(
					'message' => sprintf(
						/* translators: 1: repository path, 2: HTTP status code */
						__( 'GitHub rejected the token for %1$s (HTTP %2$d). Use a fine-grained personal access token with read-only Contents permission on that repository.', 'blt-secure' ),
						$repo_path,
						$status
					),
				)
			);
		}

		$stored = $this->plugin->credentials->set( Blt_Secure_Updater::TOKEN_KEY, $token );
		if ( is_wp_error( $stored ) ) {
			wp_send_json_error( array( 'message' => $stored->get_error_message() ) );
		}

		wp_send_json_success( array( 'message' => __( 'Token verified and stored encrypted. Update checks are now enabled.', 'blt-secure' ) ) );
	}

	/**
	 * Forget the GitHub updates token.
	 *
	 * @return void
	 */
	public function ajax_gh_delete_token() {
		$this->guard();

		$this->plugin->credentials->delete( Blt_Secure_Updater::TOKEN_KEY );

		wp_send_json_success( array( 'message' => __( 'Token removed. Update checks against the private repository will stop working.', 'blt-secure' ) ) );
	}

	/**
	 * Remove a feature.
	 *
	 * @return void
	 */
	public function ajax_remove() {
		$this->guard();

		$feature = isset( $_POST['feature'] ) ? sanitize_key( wp_unslash( $_POST['feature'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- guard() ran check_ajax_referer.
		if ( ! in_array( $feature, Blt_Secure_Cloudflare_Deployer::FEATURES, true ) ) {
			wp_send_json_error( array( 'message' => __( 'Unknown feature.', 'blt-secure' ) ) );
		}

		$deployer = $this->deployer();
		if ( is_wp_error( $deployer ) ) {
			wp_send_json_error( array( 'message' => $deployer->get_error_message() ) );
		}

		$result = $deployer->remove( $feature );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ) );
		}

		wp_send_json_success( array( 'message' => __( 'Removed.', 'blt-secure' ) ) );
	}
}
