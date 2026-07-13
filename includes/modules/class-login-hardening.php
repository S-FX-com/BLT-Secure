<?php
/**
 * Login hardening: failed-attempt lockout + login slug rename.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Two features:
 *
 * 1. Lockout — transient counters keyed by client IP and by username; after
 *    N failures either key blocks authentication for the window. The error
 *    is deliberately generic (no remaining-attempts or duration leak).
 *
 * 2. Slug rename — hides wp-login.php behind a custom path using early
 *    request interception (WPS-Hide-Login pattern), not rewrite rules.
 *    Off by default. Escape hatch: define BLT_SECURE_DISABLE_SLUG in
 *    wp-config.php. Disabled entirely on multisite in Phase 1.
 */
class Blt_Secure_Login_Hardening implements Blt_Secure_Module {

	/**
	 * Settings.
	 *
	 * @var Blt_Secure_Options
	 */
	private $options;

	/**
	 * IP resolver.
	 *
	 * @var Blt_Secure_Ip_Resolver
	 */
	private $ips;

	/**
	 * Alerting.
	 *
	 * @var Blt_Secure_Alerting
	 */
	private $alerting;

	/**
	 * Whether the current request targets the custom login slug.
	 *
	 * @var bool
	 */
	private $is_slug_request = false;

	/**
	 * Constructor.
	 *
	 * @param Blt_Secure_Options     $options Settings access.
	 * @param Blt_Secure_Ip_Resolver $ips IP resolver.
	 * @param Blt_Secure_Alerting    $alerting Event sink.
	 */
	public function __construct( Blt_Secure_Options $options, Blt_Secure_Ip_Resolver $ips, Blt_Secure_Alerting $alerting ) {
		$this->options  = $options;
		$this->ips      = $ips;
		$this->alerting = $alerting;
	}

	/**
	 * Module id.
	 *
	 * @return string
	 */
	public function id() {
		return 'login';
	}

	/**
	 * Defaults.
	 *
	 * @return array
	 */
	public function defaults() {
		return array(
			'slug'            => '',
			'backup_key'      => '',
			'lockout_enabled' => true,
			'max_attempts'    => 5,
			'lockout_minutes' => 15,
		);
	}

	/**
	 * Enabled when lockout is on or a slug is configured.
	 *
	 * @return bool
	 */
	public function is_enabled() {
		return (bool) $this->options->get( 'login', 'lockout_enabled', true ) || '' !== $this->active_slug();
	}

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function boot() {
		if ( $this->options->get( 'login', 'lockout_enabled', true ) ) {
			add_filter( 'authenticate', array( $this, 'check_lockout' ), 1, 2 );
			add_action( 'wp_login_failed', array( $this, 'record_failure' ) );
			add_action( 'wp_login', array( $this, 'clear_counters' ), 10, 1 );
		}

		if ( '' !== $this->active_slug() ) {
			$this->intercept_request();
			add_filter( 'site_url', array( $this, 'filter_login_url' ), 10, 3 );
			add_filter( 'network_site_url', array( $this, 'filter_login_url' ), 10, 3 );
			add_filter( 'wp_redirect', array( $this, 'filter_redirect' ) );
			add_action( 'wp_loaded', array( $this, 'block_unauthenticated_admin' ), 9 );
			add_action( 'wp_loaded', array( $this, 'maybe_serve_login' ) );
		}
	}

	/**
	 * Sanitize section.
	 *
	 * @param array $input Raw input.
	 * @param array $current Current values.
	 * @return array
	 */
	public function sanitize( $input, $current ) {
		$slug = isset( $input['slug'] ) ? sanitize_key( wp_unslash( $input['slug'] ) ) : '';

		$reserved = array( 'wp-admin', 'admin', 'login', 'wp-login', 'wp-login-php', 'dashboard', 'wp-content', 'wp-includes', 'wp-json', 'xmlrpc-php', 'feed', 'embed' );
		if ( '' !== $slug && ( in_array( $slug, $reserved, true ) || get_page_by_path( $slug ) ) ) {
			add_settings_error(
				'blt_secure_settings',
				'blt_secure_bad_slug',
				__( 'That login slug is reserved or already used by a page; the login URL was not changed.', 'blt-secure' )
			);
			$slug = isset( $current['slug'] ) ? $current['slug'] : '';
		}

		// Multisite is out of scope for slug hiding in Phase 1.
		if ( is_multisite() ) {
			$slug = '';
		}

		$current_slug = isset( $current['slug'] ) ? (string) $current['slug'] : '';
		$current_key  = isset( $current['backup_key'] ) ? (string) $current['backup_key'] : '';

		$new = array(
			'slug'            => $slug,
			'backup_key'      => self::next_backup_key( $slug, $current_slug, $current_key ),
			'lockout_enabled' => ! empty( $input['lockout_enabled'] ),
			'max_attempts'    => min( 20, max( 3, absint( isset( $input['max_attempts'] ) ? $input['max_attempts'] : 5 ) ) ),
			'lockout_minutes' => min( 1440, max( 5, absint( isset( $input['lockout_minutes'] ) ? $input['lockout_minutes'] : 15 ) ) ),
		);

		if ( $slug && $current_slug !== $slug ) {
			$this->announce_new_slug( $slug, $new['backup_key'] );
		}

		return $new;
	}

	/**
	 * Decide the backup-access key for a settings save: keep the existing key
	 * while the slug is unchanged, mint a fresh one whenever the slug is set
	 * or changed. The key only ever reveals the login *screen* (it is no
	 * authentication bypass), so it lives in the settings option.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string $slug         Newly saved slug ('' = feature off).
	 * @param string $current_slug Previously saved slug.
	 * @param string $current_key  Previously saved key.
	 * @return string
	 */
	public static function next_backup_key( $slug, $current_slug, $current_key ) {
		if ( '' === (string) $slug ) {
			return '';
		}
		if ( '' !== (string) $current_key && (string) $slug === (string) $current_slug ) {
			return (string) $current_key;
		}
		try {
			return bin2hex( random_bytes( 16 ) );
		} catch ( \Exception $e ) {
			return ''; // No CSPRNG available — better no backup URL than a weak one.
		}
	}

	// -------------------------------------------------------------------
	// Lockout.
	// -------------------------------------------------------------------

	/**
	 * Number of attempts before lockout.
	 *
	 * @return int
	 */
	private function max_attempts() {
		return max( 1, absint( $this->options->get( 'login', 'max_attempts', 5 ) ) );
	}

	/**
	 * Lockout window in seconds.
	 *
	 * @return int
	 */
	private function window() {
		return max( 60, absint( $this->options->get( 'login', 'lockout_minutes', 15 ) ) * MINUTE_IN_SECONDS );
	}

	/**
	 * Transient keys for an identity pair.
	 *
	 * @param string $username Attempted username.
	 * @return string[] Keys (ip, user).
	 */
	private function lock_keys( $username ) {
		$keys = array();

		$ip = $this->ips->resolve();
		if ( '' !== $ip ) {
			$keys[] = 'blt_sec_lock_ip_' . sha1( $ip );
		}
		if ( '' !== $username ) {
			$keys[] = 'blt_sec_lock_user_' . sha1( strtolower( $username ) );
		}

		return $keys;
	}

	/**
	 * Refuse authentication while locked. Runs before core handlers so a
	 * locked attacker learns nothing about password validity.
	 *
	 * @param WP_User|WP_Error|null $user Auth result so far.
	 * @param string                $username Attempted username.
	 * @return WP_User|WP_Error|null
	 */
	public function check_lockout( $user, $username ) {
		if ( '' === (string) $username ) {
			return $user;
		}

		foreach ( $this->lock_keys( (string) $username ) as $key ) {
			$state = get_transient( $key );
			if ( is_array( $state ) && isset( $state['count'] ) && $state['count'] >= $this->max_attempts() ) {
				return new WP_Error(
					'blt_secure_locked',
					__( '<strong>Error:</strong> Too many failed login attempts. Please try again later.', 'blt-secure' )
				);
			}
		}

		return $user;
	}

	/**
	 * Count a failed attempt against both keys.
	 *
	 * @param string $username Attempted username.
	 * @return void
	 */
	public function record_failure( $username ) {
		foreach ( $this->lock_keys( (string) $username ) as $key ) {
			$state = get_transient( $key );
			if ( ! is_array( $state ) || ! isset( $state['count'] ) ) {
				$state = array(
					'count' => 0,
					'first' => time(),
				);
			}
			++$state['count'];
			set_transient( $key, $state, $this->window() );

			if ( $state['count'] === $this->max_attempts() ) {
				$this->alerting->notify(
					'lockout',
					array(
						'username' => sanitize_user( (string) $username ),
						'ip'       => $this->ips->resolve(),
					)
				);
			}
		}
	}

	/**
	 * Successful login clears both counters.
	 *
	 * @param string $user_login Username.
	 * @return void
	 */
	public function clear_counters( $user_login ) {
		foreach ( $this->lock_keys( (string) $user_login ) as $key ) {
			delete_transient( $key );
		}
	}

	// -------------------------------------------------------------------
	// Slug rename.
	// -------------------------------------------------------------------

	/**
	 * The active custom slug ('' = feature off). Respects the wp-config
	 * escape hatch and the multisite bail.
	 *
	 * @return string
	 */
	public function active_slug() {
		if ( defined( 'BLT_SECURE_DISABLE_SLUG' ) && BLT_SECURE_DISABLE_SLUG ) {
			return '';
		}
		if ( is_multisite() ) {
			return '';
		}
		return (string) $this->options->get( 'login', 'slug', '' );
	}

	/**
	 * The stored backup-access key ('' when none).
	 *
	 * @return string
	 */
	public function backup_key() {
		return (string) $this->options->get( 'login', 'backup_key', '' );
	}

	/**
	 * The backup-access URL, or '' when the slug feature is off or no key
	 * exists.
	 *
	 * @return string
	 */
	public function backup_url() {
		$key = $this->backup_key();
		if ( '' === $key || '' === $this->active_slug() ) {
			return '';
		}
		return add_query_arg( 'blt_secure_key', $key, home_url( '/' ) );
	}

	/**
	 * Classify the current request: custom slug, blocked original, or other.
	 * Runs during plugins_loaded — before wp-login.php gets going.
	 *
	 * @return void
	 */
	private function intercept_request() {
		if ( php_sapi_name() === 'cli' || defined( 'WP_CLI' ) ) {
			return;
		}

		// Backup access URL: the correct key serves the login screen even if
		// the slug is forgotten. It reveals the login form only — every
		// credential still goes through the normal authentication path.
		$key = $this->backup_key();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- secret-key comparison, not a form action.
		$given = isset( $_GET['blt_secure_key'] ) ? sanitize_text_field( wp_unslash( $_GET['blt_secure_key'] ) ) : '';
		if ( '' !== $key && '' !== $given && hash_equals( $key, $given ) ) {
			$this->is_slug_request = true;
			return;
		}

		$request_path = $this->request_path();
		$slug         = $this->active_slug();
		$home_path    = trim( (string) wp_parse_url( home_url(), PHP_URL_PATH ), '/' );
		$rel_path     = $home_path && 0 === strpos( $request_path, $home_path . '/' )
			? substr( $request_path, strlen( $home_path ) + 1 )
			: $request_path;

		if ( $rel_path === $slug ) {
			$this->is_slug_request = true;
			return;
		}

		// Direct wp-login.php hit → 404 (except flows that must survive:
		// logout with a valid nonce redirects through the slug anyway via
		// the site_url filter; postpass never hits wp-login.php directly
		// as a GET target from users, but plugins POST there).
		if ( 'wp-login.php' === basename( $rel_path ) && $this->should_block_original() ) {
			$this->block_404();
		}
	}

	/**
	 * Whether a direct wp-login.php request should be blocked.
	 *
	 * Whitelisted actions keep third-party integrations alive; everything
	 * interactive must come through the slug. Filterable for site-specific
	 * exceptions (SSO plugins that hardcode wp-login.php).
	 *
	 * @return bool
	 */
	private function should_block_original() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';

		$allowed = array( 'postpass' );

		/**
		 * Filter wp-login.php actions allowed to bypass the hidden slug.
		 *
		 * @param string[] $allowed Action names.
		 * @param string   $action Current action.
		 */
		$allowed = apply_filters( 'blt_secure_login_slug_bypass', $allowed, $action );

		return ! in_array( $action, $allowed, true );
	}

	/**
	 * 404 unauthenticated /wp-admin requests. Without this, core's
	 * auth_redirect() would bounce visitors to the login URL — revealing
	 * the hidden slug. Runs at wp_loaded, when auth cookies are readable.
	 * admin-ajax.php and admin-post.php stay open (front-end features).
	 *
	 * @return void
	 */
	public function block_unauthenticated_admin() {
		if ( ! is_admin() || is_user_logged_in() ) {
			return;
		}
		if ( wp_doing_ajax() || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}

		$script = isset( $_SERVER['SCRIPT_FILENAME'] ) ? basename( sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_FILENAME'] ) ) ) : '';
		if ( in_array( $script, array( 'admin-ajax.php', 'admin-post.php' ), true ) ) {
			return;
		}

		$this->block_404();
	}

	/**
	 * Serve the real login screen for slug requests.
	 *
	 * @return void
	 */
	public function maybe_serve_login() {
		if ( ! $this->is_slug_request ) {
			return;
		}

		global $pagenow, $error, $interim_login, $action, $user_login;

		$pagenow = 'wp-login.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited

		nocache_headers();
		require_once ABSPATH . 'wp-login.php';
		exit;
	}

	/**
	 * Swap wp-login.php for the slug in generated URLs (covers
	 * wp_login_url(), password reset emails, logout links, etc.).
	 *
	 * @param string      $url Full URL.
	 * @param string      $path Path passed to site_url().
	 * @param string|null $scheme Scheme.
	 * @return string
	 */
	public function filter_login_url( $url, $path, $scheme = null ) {
		if ( is_string( $path ) && false !== strpos( $path, 'wp-login.php' ) ) {
			return $this->swap_login_for_slug( $url );
		}
		return $url;
	}

	/**
	 * Same swap for redirects core issues toward wp-login.php.
	 *
	 * @param string $location Redirect target.
	 * @return string
	 */
	public function filter_redirect( $location ) {
		if ( is_string( $location ) && false !== strpos( $location, 'wp-login.php' ) ) {
			return $this->swap_login_for_slug( $location );
		}
		return $location;
	}

	/**
	 * Replace the wp-login.php path segment with the slug, keeping the query.
	 *
	 * @param string $url URL containing wp-login.php.
	 * @return string
	 */
	private function swap_login_for_slug( $url ) {
		$slug = $this->active_slug();
		if ( '' === $slug ) {
			return $url;
		}
		return str_replace( 'wp-login.php', $slug, $url );
	}

	/**
	 * Emit a genuine-looking 404 and stop.
	 *
	 * @return void
	 */
	private function block_404() {
		/**
		 * Fires when a hidden-login request is blocked.
		 *
		 * @param string $path Request path.
		 */
		do_action( 'blt_secure_login_blocked', $this->request_path() );

		status_header( 404 );
		nocache_headers();
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/html; charset=UTF-8' );
		}
		// Minimal body — the theme isn't loaded this early.
		echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>';
		exit;
	}

	/**
	 * Current request path, no query string, trimmed of slashes.
	 *
	 * @return string
	 */
	private function request_path() {
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		return trim( (string) wp_parse_url( $uri, PHP_URL_PATH ), '/' );
	}

	/**
	 * On slug change: admin notice + email so the owner always has the URL
	 * (and the backup-access URL that finds it again if the slug is lost).
	 *
	 * @param string $slug       New slug.
	 * @param string $backup_key Backup-access key ('' = none).
	 * @return void
	 */
	private function announce_new_slug( $slug, $backup_key = '' ) {
		$login_url  = home_url( '/' . $slug );
		$backup_url = '' !== $backup_key ? add_query_arg( 'blt_secure_key', $backup_key, home_url( '/' ) ) : '';

		add_settings_error(
			'blt_secure_settings',
			'blt_secure_new_slug',
			sprintf(
				/* translators: %s: new login URL */
				__( 'Your login URL is now: %s — bookmark it, and save the backup access URL shown below the slug field. If you ever get locked out, add define( \'BLT_SECURE_DISABLE_SLUG\', true ); to wp-config.php.', 'blt-secure' ),
				'<code>' . esc_url( $login_url ) . '</code>'
			),
			'success'
		);

		$body = sprintf(
			/* translators: 1: new login URL, 2: escape hatch code */
			__( "BLT Secure changed this site's login URL to: %1\$s\n\nIf you are ever locked out, add this line to wp-config.php to restore the default login URL:\n\n%2\$s\n", 'blt-secure' ),
			$login_url,
			"define( 'BLT_SECURE_DISABLE_SLUG', true );"
		);
		if ( '' !== $backup_url ) {
			$body .= "\n" . sprintf(
				/* translators: %s: backup access URL */
				__( "Backup access URL (opens the login screen if you forget the slug — keep it private):\n\n%s\n", 'blt-secure' ),
				$backup_url
			);
		}

		wp_mail(
			get_option( 'admin_email' ),
			sprintf(
				/* translators: %s: site name */
				__( '[%s] Your login URL changed', 'blt-secure' ),
				wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES )
			),
			$body
		);
	}
}
