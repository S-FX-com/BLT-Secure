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
	 * Per-IP failure limit = max_attempts x this (shared NAT headroom).
	 */
	const IP_FACTOR = 4;

	/**
	 * Per-username "distributed attack" alert threshold = max_attempts x this.
	 */
	const USER_ALERT_FACTOR = 10;

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
			// Core's wp_authenticate_username_password() (authenticate, priority 20) ignores a
			// WP_Error returned by an earlier filter and re-authenticates, so a priority-1
			// authenticate filter cannot block anything. Enforce at wp_authenticate_user
			// (runs inside that function, before the password hash is even checked, and
			// before the 2FA interstitial at priority 50), and keep a late authenticate
			// guard so nothing else (application passwords, other plugins) can slip past.
			add_filter( 'wp_authenticate_user', array( $this, 'check_lockout_user' ), 1, 2 );
			add_filter( 'authenticate', array( $this, 'check_lockout' ), 99, 2 );
			add_action( 'wp_login_failed', array( $this, 'record_failure' ), 10, 2 );
			add_action( 'wp_login', array( $this, 'clear_counters' ), 10, 1 );
		}

		if ( '' !== $this->active_slug() ) {
			// Core answers a 404 on /login or /login.php with a redirect to wp_login_url(), which is the hidden slug.
			remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );
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
	 * Failures from one client IP (any username) before the IP is blocked.
	 * Higher than the per-pair limit because one IP is often many people
	 * (office NAT, mobile carrier CGNAT).
	 *
	 * @return int
	 */
	private function ip_max_attempts() {
		return $this->max_attempts() * self::IP_FACTOR;
	}

	/**
	 * Failures against one username (from any IP) that raise a "distributed
	 * attack" alert. Never blocks: a global per-username block would let any
	 * stranger lock the real admin out by failing a few logins for "admin".
	 *
	 * @return int
	 */
	private function user_alert_threshold() {
		return $this->max_attempts() * self::USER_ALERT_FACTOR;
	}

	/**
	 * Normalise a submitted login identifier (username OR email, any case,
	 * accent-folded by the DB collation) to the account's real user_login, so
	 * "Admin", "admín" and "admin@example.com" all share one counter. Unknown
	 * names fall back to the lower-cased submission.
	 *
	 * @param string $username Submitted identifier.
	 * @return string
	 */
	private function canonical_username( $username ) {
		$username = trim( (string) $username );
		if ( '' === $username ) {
			return '';
		}

		if ( function_exists( 'get_user_by' ) ) {
			$user = get_user_by( false !== strpos( $username, '@' ) ? 'email' : 'login', $username );
			if ( $user && ! empty( $user->user_login ) ) {
				$username = (string) $user->user_login;
			}
		}

		return strtolower( $username );
	}

	/**
	 * Counter keys for this request.
	 *
	 * Blocking keys: the client network (IPv6 truncated to /64) and the
	 * (network, username) pair. The per-username key is alert-only.
	 *
	 * @param string $username Attempted username or email.
	 * @return array[] List of array( 'key' => string, 'max' => int, 'scope' => string ).
	 */
	private function lock_keys( $username ) {
		$keys     = array();
		$username = $this->canonical_username( $username );

		$net = Blt_Secure_Ip_Resolver::network_key( $this->ips->resolve() );
		if ( '' !== $net ) {
			$keys[] = array(
				'key'   => 'blt_sec_lock_ip_' . sha1( $net ),
				'max'   => $this->ip_max_attempts(),
				'scope' => 'ip',
			);
			if ( '' !== $username ) {
				$keys[] = array(
					'key'   => 'blt_sec_lock_pair_' . sha1( $net . '|' . $username ),
					'max'   => $this->max_attempts(),
					'scope' => 'pair',
				);
			}
		}

		return $keys;
	}

	// -------------------------------------------------------------------
	// Fixed-window counters (pure transient state machine; unit-tested).
	// Shared with the 2FA module.
	//
	// State: array( count, first, until ). The window is anchored on the FIRST
	// failure and is never re-armed by later ones; once `count` reaches `max`
	// the key is locked until `until` (now + window at the moment it tripped).
	// Limit: transients have no atomic increment, so two truly parallel
	// requests can both read the same count. The window anchoring, the
	// pre-verification increment and the generous-but-finite thresholds keep
	// the over-count small; sites with a persistent object cache still get
	// non-atomic behaviour here. Documented, not hidden.
	// -------------------------------------------------------------------

	/**
	 * Read a counter state, discarding expired windows.
	 *
	 * @param string $key Transient key.
	 * @return array|null State, or null when absent/expired.
	 */
	private static function counter_state( $key ) {
		$state = get_transient( $key );
		if ( ! is_array( $state ) || ! isset( $state['count'], $state['first'] ) ) {
			return null;
		}
		$until = isset( $state['until'] ) ? (int) $state['until'] : 0;
		if ( $until > 0 && time() >= $until ) {
			return null; // Lock served its time.
		}
		return $state;
	}

	/**
	 * Whether a counter is currently locked.
	 *
	 * @param string $key Transient key.
	 * @param int    $max Failures that trip the lock.
	 * @return bool
	 */
	public static function counter_locked( $key, $max ) {
		$state = self::counter_state( $key );
		return null !== $state && (int) $state['count'] >= (int) $max && ! empty( $state['until'] ) && time() < (int) $state['until'];
	}

	/**
	 * Record one failure.
	 *
	 * @param string $key    Transient key.
	 * @param int    $max    Failures that trip the lock.
	 * @param int    $window Window / lock duration in seconds.
	 * @return array array( count => int, tripped => bool ); tripped is true only on the hit that crosses $max.
	 */
	public static function counter_hit( $key, $max, $window ) {
		$now   = time();
		$state = self::counter_state( $key );

		// A counting window that elapsed without tripping starts over.
		if ( null !== $state && empty( $state['until'] ) && $now >= (int) $state['first'] + (int) $window ) {
			$state = null;
		}
		if ( null === $state ) {
			$state = array(
				'count' => 0,
				'first' => $now,
				'until' => 0,
			);
		}

		++$state['count'];

		$tripped = false;
		if ( empty( $state['until'] ) && $state['count'] >= (int) $max ) {
			$state['until'] = $now + (int) $window;
			$tripped        = true;
		}

		$expires = ! empty( $state['until'] ) ? (int) $state['until'] : (int) $state['first'] + (int) $window;
		set_transient( $key, $state, max( 1, $expires - $now ) );

		return array(
			'count'   => (int) $state['count'],
			'tripped' => $tripped,
		);
	}

	/**
	 * Forget a counter.
	 *
	 * @param string $key Transient key.
	 * @return void
	 */
	public static function counter_clear( $key ) {
		delete_transient( $key );
	}

	/**
	 * Shared WP_Error for a locked identity. Generic: no duration, no counts.
	 *
	 * @return WP_Error
	 */
	private function locked_error() {
		return new WP_Error(
			'blt_secure_locked',
			__( '<strong>Error:</strong> Too many failed login attempts. Please try again later.', 'blt-secure' )
		);
	}

	/**
	 * Whether the current client / (client, username) is locked.
	 *
	 * @param string $username Attempted username or email.
	 * @return bool
	 */
	private function is_locked( $username ) {
		foreach ( $this->lock_keys( (string) $username ) as $entry ) {
			if ( self::counter_locked( $entry['key'], $entry['max'] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Enforcement point 1 (wp_authenticate_user, priority 1): runs inside
	 * wp_authenticate_username_password / _email_password right after the user
	 * row is found and BEFORE the password hash is checked, so a locked client
	 * costs no hashing and learns nothing about password validity.
	 *
	 * @param WP_User|WP_Error $user     User found by core (or an earlier error).
	 * @param string           $password Submitted password (unused).
	 * @return WP_User|WP_Error
	 */
	public function check_lockout_user( $user, $password = '' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		if ( ! $user instanceof WP_User ) {
			return $user;
		}
		return $this->is_locked( (string) $user->user_login ) ? $this->locked_error() : $user;
	}

	/**
	 * Enforcement point 2 (authenticate, priority 99): the last word. Replaces
	 * ANY earlier result — including a successful WP_User from application
	 * passwords or another plugin's handler — with the lockout error.
	 *
	 * @param WP_User|WP_Error|null $user     Auth result so far.
	 * @param string                $username Attempted username.
	 * @return WP_User|WP_Error|null
	 */
	public function check_lockout( $user, $username = '' ) {
		if ( '' === (string) $username ) {
			return $user; // Cookie re-validation / empty form: nothing to lock.
		}

		return $this->is_locked( (string) $username ) ? $this->locked_error() : $user;
	}

	/**
	 * Count a failed attempt (wp_login_failed).
	 *
	 * @param string        $username Attempted username or email.
	 * @param WP_Error|null $error    The failure (WP 5.4+); lockout rejections are not counted.
	 * @return void
	 */
	public function record_failure( $username, $error = null ) {
		if ( $error instanceof WP_Error && 'blt_secure_locked' === $error->get_error_code() ) {
			return; // Already locked: do not extend or inflate anything.
		}

		$window = $this->window();
		$ip     = $this->ips->resolve();

		foreach ( $this->lock_keys( (string) $username ) as $entry ) {
			$hit = self::counter_hit( $entry['key'], $entry['max'], $window );
			if ( $hit['tripped'] ) {
				$this->alerting->notify(
					'lockout',
					array(
						'username' => sanitize_user( (string) $username ),
						'ip'       => $ip,
						'scope'    => $entry['scope'],
					)
				);
			}
		}

		// Distributed guessing against one account: alert only, never block.
		$name = $this->canonical_username( $username );
		if ( '' !== $name ) {
			$hit = self::counter_hit( 'blt_sec_lock_user_' . sha1( $name ), $this->user_alert_threshold(), $window );
			if ( $hit['tripped'] ) {
				$this->alerting->notify(
					'lockout',
					array(
						'username' => sanitize_user( (string) $username ),
						'ip'       => $ip,
						'scope'    => 'username',
					)
				);
			}
		}
	}

	/**
	 * Successful login clears only the (client, username) pair. The client-wide
	 * counter is deliberately left alone: otherwise an attacker with one valid
	 * account could interleave a good login to keep resetting the IP counter
	 * while spraying other usernames.
	 *
	 * @param string $user_login Username.
	 * @return void
	 */
	public function clear_counters( $user_login ) {
		foreach ( $this->lock_keys( (string) $user_login ) as $entry ) {
			if ( 'pair' === $entry['scope'] ) {
				self::counter_clear( $entry['key'] );
			}
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

		$action = self::raw_action();

		/**
		 * Filter wp-login.php actions allowed to bypass the hidden slug.
		 *
		 * Whitelisted actions keep third-party integrations alive; everything
		 * interactive must come through the slug. The built-in `postpass` is
		 * only honoured for POST requests.
		 *
		 * @param string[] $allowed Action names (exact, case-sensitive match).
		 * @param string   $action  Current raw action.
		 */
		$allowed = apply_filters( 'blt_secure_login_slug_bypass', array( 'postpass' ), $action );

		$decision = self::request_decision(
			array(
				'script'  => isset( $_SERVER['SCRIPT_FILENAME'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_FILENAME'] ) ) : '',
				'uri'     => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
				'method'  => isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '',
				'action'  => $action,
				'slug'    => $this->active_slug(),
				// WordPress in its own directory: generated login URLs live under siteurl, not home.
				'bases'   => array(
					(string) wp_parse_url( home_url(), PHP_URL_PATH ),
					(string) wp_parse_url( site_url(), PHP_URL_PATH ),
				),
				'allowed' => is_array( $allowed ) ? $allowed : array(),
			)
		);

		if ( 'slug' === $decision ) {
			$this->is_slug_request = true;
		} elseif ( 'block' === $decision ) {
			$this->block_404();
		}
	}

	/**
	 * The `action` parameter exactly as wp-login.php will see it.
	 *
	 * wp-login.php reads $_REQUEST *after* wp_magic_quotes() rebuilt it as
	 * GET+POST (POST wins, cookies excluded), but this runs earlier, when
	 * $_REQUEST is still PHP's native array — which includes cookies when
	 * request_order is unset. Re-derive it the way core will, and compare it
	 * raw: sanitising (sanitize_key lower-cases and strips characters) turned
	 * `POSTPASS` or `postpass!` into an allowed `postpass` while wp-login.php
	 * treated the real value as an unknown action and showed the login form.
	 *
	 * @return string '' when absent or not a plain string.
	 */
	private static function raw_action() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing
		$merged = array_merge( $_GET, $_POST );
		return ( isset( $merged['action'] ) && is_string( $merged['action'] ) ) ? $merged['action'] : '';
	}

	/**
	 * Request path as the application will route it: query/fragment removed,
	 * percent-decoded, repeated slashes collapsed, outer slashes trimmed.
	 *
	 * Not wp_parse_url()/parse_url(): both read `//wp-login.php` as an
	 * authority (host `wp-login.php`, empty path), which let the 404 be skipped
	 * while the web server happily collapsed the slashes and ran the script.
	 * Pure function (unit-tested).
	 *
	 * @param string $uri REQUEST_URI.
	 * @return string
	 */
	public static function normalize_request_path( $uri ) {
		$uri  = (string) $uri;
		$path = substr( $uri, 0, strcspn( $uri, '?#' ) );
		$path = (string) preg_replace( '#^[a-z][a-z0-9+.\-]*://[^/]*#i', '', $path ); // Absolute-form request target.
		$path = str_replace( array( "\0", '\\' ), array( '', '/' ), rawurldecode( $path ) );
		$path = (string) preg_replace( '#/+#', '/', $path );

		return trim( $path, '/' );
	}

	/**
	 * Decide what the hidden-login layer does with a request. Pure function
	 * (unit-tested).
	 *
	 * 'slug'  — serve the login screen.
	 * 'block' — direct wp-login.php hit: 404.
	 * 'pass'  — not ours.
	 *
	 * "Direct wp-login.php hit" is decided on the EXECUTING SCRIPT, not on a
	 * URL string, so path-info (/wp-login.php/x), double slashes
	 * (//wp-login.php) and percent-encoding (/wp%2Dlogin.php) cannot dodge it.
	 * The normalised URL basename is a second tripwire for setups where
	 * SCRIPT_FILENAME is unusual.
	 *
	 * @param array $req Keys: script, uri, method, action (raw), slug, bases (path prefixes the slug may live under), allowed (action names).
	 * @return string
	 */
	public static function request_decision( array $req ) {
		$slug = isset( $req['slug'] ) ? (string) $req['slug'] : '';
		$path = self::normalize_request_path( isset( $req['uri'] ) ? $req['uri'] : '' );

		if ( '' !== $slug ) {
			$bases = isset( $req['bases'] ) && is_array( $req['bases'] ) ? $req['bases'] : array( '' );
			foreach ( $bases as $base ) {
				$base = trim( (string) $base, '/' );
				if ( ( '' === $base ? $slug : $base . '/' . $slug ) === $path ) {
					return 'slug';
				}
			}
		}

		$script    = strtolower( basename( str_replace( '\\', '/', isset( $req['script'] ) ? (string) $req['script'] : '' ) ) );
		$login_hit = 'wp-login.php' === $script || 'wp-login.php' === strtolower( basename( $path ) );
		if ( ! $login_hit ) {
			return 'pass';
		}

		$action  = isset( $req['action'] ) ? (string) $req['action'] : '';
		$allowed = isset( $req['allowed'] ) && is_array( $req['allowed'] ) ? $req['allowed'] : array();
		if ( in_array( $action, $allowed, true ) ) {
			$method = strtoupper( isset( $req['method'] ) ? (string) $req['method'] : '' );
			if ( 'postpass' !== $action || 'POST' === $method ) {
				return 'pass';
			}
		}

		return 'block';
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
			// The password-protected-post form is rendered to ANONYMOUS visitors;
			// leave it pointing at wp-login.php?action=postpass (allowed through
			// the 404 for POST) instead of printing the hidden slug into public HTML.
			if ( 'login_post' === $scheme && false !== strpos( $path, 'action=postpass' ) ) {
				return $url;
			}
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
		return self::normalize_request_path( $uri );
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
