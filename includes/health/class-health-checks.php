<?php
/**
 * The BLT Secure health-check catalogue.
 *
 * Each check is a small callback that inspects the site and returns
 * array( 'status' => …, 'message' => …, 'details' => … ). Checks must be
 * read-only and side-effect free; they run on WP-Cron and on demand, never
 * on a front-end page load.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Static catalogue of health checks, modelled on the breadth of common
 * WordPress security scanners. WP-coupled by nature; smoke-tested per the
 * checklist in tasks/todo.md.
 */
class Blt_Secure_Health_Checks {

	/**
	 * Ordered category key => display label.
	 *
	 * @return array
	 */
	public static function categories() {
		return array(
			'core'     => __( 'WordPress & Updates', 'blt-secure' ),
			'users'    => __( 'Users & Login', 'blt-secure' ),
			'config'   => __( 'Configuration & Debug', 'blt-secure' ),
			'files'    => __( 'Files & Permissions', 'blt-secure' ),
			'info'     => __( 'Information Disclosure', 'blt-secure' ),
			'headers'  => __( 'HTTP Response Headers', 'blt-secure' ),
			'database' => __( 'Database', 'blt-secure' ),
		);
	}

	/**
	 * All check definitions.
	 *
	 * @return array[]
	 */
	public static function all() {
		$c = __CLASS__;

		$defs = array(
			// WordPress & updates.
			array( 'core_updated', __( 'WordPress core is up to date', 'blt-secure' ), 'core', array( $c, 'core_updated' ) ),
			array( 'core_auto_updates', __( 'Automatic core updates are enabled', 'blt-secure' ), 'core', array( $c, 'core_auto_updates' ) ),
			array( 'plugins_updated', __( 'All plugins are up to date', 'blt-secure' ), 'core', array( $c, 'plugins_updated' ) ),
			array( 'no_inactive_plugins', __( 'No deactivated plugins are left installed', 'blt-secure' ), 'core', array( $c, 'no_inactive_plugins' ) ),
			array( 'themes_updated', __( 'All themes are up to date', 'blt-secure' ), 'core', array( $c, 'themes_updated' ) ),
			array( 'no_extra_themes', __( 'No unnecessary themes are installed', 'blt-secure' ), 'core', array( $c, 'no_extra_themes' ) ),
			array( 'php_supported', __( 'PHP version is still supported', 'blt-secure' ), 'core', array( $c, 'php_supported' ) ),
			array( 'ssl_enabled', __( 'The site is served over HTTPS', 'blt-secure' ), 'core', array( $c, 'ssl_enabled' ) ),

			// Users & login.
			array( 'no_admin_username', __( 'No account uses the username "admin"', 'blt-secure' ), 'users', array( $c, 'no_admin_username' ) ),
			array( 'user_id_one', __( 'The user with ID 1 is not a predictable admin', 'blt-secure' ), 'users', array( $c, 'user_id_one' ) ),
			array( 'registration_off', __( 'Open user registration is disabled', 'blt-secure' ), 'users', array( $c, 'registration_off' ) ),
			array( 'login_errors_generic', __( 'Login errors do not reveal whether a username exists', 'blt-secure' ), 'users', array( $c, 'login_errors_generic' ) ),
			array( 'enumeration_blocked', __( 'User enumeration is blocked', 'blt-secure' ), 'users', array( $c, 'enumeration_blocked' ) ),
			array( 'login_lockout', __( 'Failed-login lockout is enabled', 'blt-secure' ), 'users', array( $c, 'login_lockout' ) ),
			array( 'two_factor', __( 'Two-factor authentication is available', 'blt-secure' ), 'users', array( $c, 'two_factor' ) ),
			array( 'app_passwords', __( 'Application Passwords are disabled if unused', 'blt-secure' ), 'users', array( $c, 'app_passwords' ) ),
			array( 'xmlrpc_disabled', __( 'XML-RPC is disabled', 'blt-secure' ), 'users', array( $c, 'xmlrpc_disabled' ) ),

			// Configuration & debug.
			array( 'wp_debug_off', __( 'Debug mode (WP_DEBUG) is off', 'blt-secure' ), 'config', array( $c, 'wp_debug_off' ) ),
			array( 'debug_display_off', __( 'Debug output is not shown to visitors', 'blt-secure' ), 'config', array( $c, 'debug_display_off' ) ),
			array( 'debug_log_hidden', __( 'No world-readable debug.log is present', 'blt-secure' ), 'config', array( $c, 'debug_log_hidden' ) ),
			array( 'script_debug_off', __( 'SCRIPT_DEBUG is off', 'blt-secure' ), 'config', array( $c, 'script_debug_off' ) ),
			array( 'savequeries_off', __( 'Database query logging (SAVEQUERIES) is off', 'blt-secure' ), 'config', array( $c, 'savequeries_off' ) ),
			array( 'display_errors_off', __( 'PHP display_errors is off', 'blt-secure' ), 'config', array( $c, 'display_errors_off' ) ),
			array( 'allow_url_include_off', __( 'PHP allow_url_include is off', 'blt-secure' ), 'config', array( $c, 'allow_url_include_off' ) ),
			array( 'file_edit_disabled', __( 'The plugin/theme file editor is disabled', 'blt-secure' ), 'config', array( $c, 'file_edit_disabled' ) ),
			array( 'file_managers_blocked', __( 'File-manager plugins are blocked', 'blt-secure' ), 'config', array( $c, 'file_managers_blocked' ) ),
			array( 'force_ssl_admin', __( 'The admin area is forced over SSL', 'blt-secure' ), 'config', array( $c, 'force_ssl_admin' ) ),
			array( 'keys_defined', __( 'Secret keys and salts are defined', 'blt-secure' ), 'config', array( $c, 'keys_defined' ) ),
			array( 'keys_not_default', __( 'Secret keys are not the default placeholders', 'blt-secure' ), 'config', array( $c, 'keys_not_default' ) ),

			// Files & permissions.
			array( 'wp_config_perms', __( 'wp-config.php is not world-readable', 'blt-secure' ), 'files', array( $c, 'wp_config_perms' ) ),
			array( 'uploads_index', __( 'The uploads folder blocks directory listing', 'blt-secure' ), 'files', array( $c, 'uploads_index' ) ),
			array( 'no_installer_files', __( 'No leftover installer files in the web root', 'blt-secure' ), 'files', array( $c, 'no_installer_files' ) ),
			array( 'timthumb_absent', __( 'The active theme does not ship TimThumb', 'blt-secure' ), 'files', array( $c, 'timthumb_absent' ) ),

			// Information disclosure.
			array( 'version_hidden', __( 'The WordPress version is not exposed in meta/assets', 'blt-secure' ), 'info', array( $c, 'version_hidden' ) ),
			array( 'wlw_hidden', __( 'The Windows Live Writer manifest link is removed', 'blt-secure' ), 'info', array( $c, 'wlw_hidden' ) ),
			array( 'rsd_hidden', __( 'The RSD/EditURI link is removed', 'blt-secure' ), 'info', array( $c, 'rsd_hidden' ) ),
			array( 'rest_link_hidden', __( 'The REST API link is removed from the page head', 'blt-secure' ), 'info', array( $c, 'rest_link_hidden' ) ),
			array( 'readme_absent', __( 'The core readme.html/license.txt are removed', 'blt-secure' ), 'info', array( $c, 'readme_absent' ) ),
			array( 'expose_php_off', __( 'PHP does not advertise its version (expose_php)', 'blt-secure' ), 'info', array( $c, 'expose_php_off' ) ),

			// HTTP response headers.
			array( 'header_nosniff', __( 'X-Content-Type-Options is set', 'blt-secure' ), 'headers', array( $c, 'header_nosniff' ) ),
			array( 'header_xframe', __( 'X-Frame-Options is set', 'blt-secure' ), 'headers', array( $c, 'header_xframe' ) ),
			array( 'header_hsts', __( 'Strict-Transport-Security is set', 'blt-secure' ), 'headers', array( $c, 'header_hsts' ) ),
			array( 'header_referrer', __( 'Referrer-Policy is set', 'blt-secure' ), 'headers', array( $c, 'header_referrer' ) ),
			array( 'header_permissions', __( 'Permissions-Policy is set', 'blt-secure' ), 'headers', array( $c, 'header_permissions' ) ),
			array( 'header_csp', __( 'Content-Security-Policy is set', 'blt-secure' ), 'headers', array( $c, 'header_csp' ) ),
			array( 'header_powered_by', __( 'The server does not send X-Powered-By', 'blt-secure' ), 'headers', array( $c, 'header_powered_by' ) ),

			// Database.
			array( 'table_prefix', __( 'The database table prefix is not the default', 'blt-secure' ), 'database', array( $c, 'table_prefix' ) ),
			array( 'db_password_strength', __( 'The database password looks strong', 'blt-secure' ), 'database', array( $c, 'db_password_strength' ) ),
		);

		$checks = array();
		foreach ( $defs as $d ) {
			$checks[] = array(
				'id'       => $d[0],
				'label'    => $d[1],
				'category' => $d[2],
				'callback' => $d[3],
			);
		}

		/**
		 * Filter the health-check catalogue. Phase 2 detection modules (core
		 * integrity, malware scan) append their own checks here.
		 *
		 * @param array[] $checks Check definitions.
		 */
		return apply_filters( 'blt_secure_health_checks', $checks );
	}

	// ---------------------------------------------------------------------
	// Helpers.
	// ---------------------------------------------------------------------

	/**
	 * Load the wp-admin update/plugin/theme helpers on non-admin requests
	 * (WP-Cron), where they are not included by default.
	 *
	 * @return void
	 */
	private static function load_admin_includes() {
		foreach ( array( 'update.php', 'plugin.php', 'misc.php', 'theme.php' ) as $file ) {
			$path = ABSPATH . 'wp-admin/includes/' . $file;
			if ( is_readable( $path ) ) {
				require_once $path;
			}
		}
	}

	/**
	 * PASS/WARN/FAIL/SKIP shorthand.
	 *
	 * @param string $status  Status constant.
	 * @param string $message Message.
	 * @param string $details Details.
	 * @return array
	 */
	private static function result( $status, $message, $details = '' ) {
		return array(
			'status'  => $status,
			'message' => $message,
			'details' => $details,
		);
	}

	// ---------------------------------------------------------------------
	// WordPress & updates.
	// ---------------------------------------------------------------------

	/**
	 * Whether stored update data is too old (or absent) to trust.
	 *
	 * Pure function (unit-tested). "No data" and "stale data" both mean the
	 * update checks have not run recently, so "up to date" cannot be claimed.
	 *
	 * @param int|null $last_checked Unix time of the last check, or null/0 if never.
	 * @param int      $now          Current time.
	 * @param int      $max_age      Maximum acceptable age in seconds.
	 * @return bool
	 */
	public static function update_data_is_stale( $last_checked, $now, $max_age ) {
		if ( empty( $last_checked ) ) {
			return true;
		}
		return ( (int) $now - (int) $last_checked ) > (int) $max_age;
	}

	/**
	 * A SKIP result when the named update transient is missing or stale, or
	 * null when it is fresh enough to judge.
	 *
	 * @param string $transient Site transient (update_core / update_plugins / update_themes).
	 * @return array|null
	 */
	private static function stale_update_result( $transient ) {
		$data = get_site_transient( $transient );
		$last = is_object( $data ) && isset( $data->last_checked ) ? (int) $data->last_checked : 0;

		/**
		 * Filter how old (seconds) update data may be before the update checks
		 * report "unknown" instead of "up to date".
		 *
		 * @param int $max_age Seconds; default five days.
		 */
		$max = (int) apply_filters( 'blt_secure_update_data_max_age', 5 * DAY_IN_SECONDS );
		if ( self::update_data_is_stale( $last, time(), $max ) ) {
			return self::result(
				Blt_Secure_Health_Result::SKIP,
				__( 'WordPress has not checked for updates recently, so this cannot be verified.', 'blt-secure' ),
				__( 'Update checks may be blocked (a plugin, a constant, or outbound firewall) or WP-Cron may not be running. Open Dashboard → Updates to refresh.', 'blt-secure' )
			);
		}
		return null;
	}

	/**
	 * @return array
	 */
	public static function core_updated() {
		self::load_admin_includes();
		if ( ! function_exists( 'get_core_updates' ) ) {
			return self::result( Blt_Secure_Health_Result::SKIP, __( 'Core update data is unavailable.', 'blt-secure' ) );
		}
		$stale = self::stale_update_result( 'update_core' );
		if ( null !== $stale ) {
			return $stale;
		}
		$updates = get_core_updates();
		if ( ! is_array( $updates ) || empty( $updates ) ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'Your WordPress core is current.', 'blt-secure' ) );
		}
		foreach ( $updates as $update ) {
			if ( isset( $update->response ) && 'upgrade' === $update->response ) {
				return self::result(
					Blt_Secure_Health_Result::FAIL,
					sprintf(
						/* translators: %s: version number */
						__( 'WordPress %s is available. Update from Dashboard → Updates.', 'blt-secure' ),
						isset( $update->current ) ? $update->current : ''
					)
				);
			}
		}
		return self::result( Blt_Secure_Health_Result::PASS, __( 'Your WordPress core is current.', 'blt-secure' ) );
	}

	/**
	 * @return array
	 */
	public static function core_auto_updates() {
		if ( defined( 'WP_AUTO_UPDATE_CORE' ) && false === WP_AUTO_UPDATE_CORE ) {
			return self::result( Blt_Secure_Health_Result::WARN, __( 'Automatic core updates are turned off via WP_AUTO_UPDATE_CORE.', 'blt-secure' ), __( 'Leaving at least minor/security auto-updates enabled keeps the site patched without manual work.', 'blt-secure' ) );
		}
		if ( function_exists( 'wp_is_auto_update_enabled_for_type' ) && ! wp_is_auto_update_enabled_for_type( 'core' ) ) {
			return self::result( Blt_Secure_Health_Result::WARN, __( 'Automatic core updates appear to be disabled.', 'blt-secure' ) );
		}
		return self::result( Blt_Secure_Health_Result::PASS, __( 'Automatic (at least minor/security) core updates are enabled.', 'blt-secure' ) );
	}

	/**
	 * @return array
	 */
	public static function plugins_updated() {
		self::load_admin_includes();
		if ( ! function_exists( 'get_plugin_updates' ) ) {
			return self::result( Blt_Secure_Health_Result::SKIP, __( 'Plugin update data is unavailable.', 'blt-secure' ) );
		}
		$stale = self::stale_update_result( 'update_plugins' );
		if ( null !== $stale ) {
			return $stale;
		}
		$updates = get_plugin_updates();
		$count   = is_array( $updates ) ? count( $updates ) : 0;
		if ( 0 === $count ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'All installed plugins are current.', 'blt-secure' ) );
		}
		return self::result(
			Blt_Secure_Health_Result::FAIL,
			sprintf(
				/* translators: %d: number of plugins */
				_n( '%d plugin has an update available.', '%d plugins have updates available.', $count, 'blt-secure' ),
				$count
			),
			__( 'Outdated plugins are the most common WordPress compromise vector. Update them from Dashboard → Updates.', 'blt-secure' )
		);
	}

	/**
	 * @return array
	 */
	public static function no_inactive_plugins() {
		self::load_admin_includes();
		if ( ! function_exists( 'get_plugins' ) ) {
			return self::result( Blt_Secure_Health_Result::SKIP, __( 'Plugin list unavailable.', 'blt-secure' ) );
		}
		$all      = array_keys( get_plugins() );
		$active   = (array) get_option( 'active_plugins', array() );
		$inactive = array_diff( $all, $active );
		// Network-active plugins are not in active_plugins; treat multisite leniently.
		if ( is_multisite() ) {
			return self::result( Blt_Secure_Health_Result::SKIP, __( 'Skipped on multisite (network-active plugins are tracked separately).', 'blt-secure' ) );
		}
		if ( empty( $inactive ) ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'No deactivated plugins are lying around.', 'blt-secure' ) );
		}
		return self::result(
			Blt_Secure_Health_Result::WARN,
			sprintf(
				/* translators: %d: number of plugins */
				_n( '%d deactivated plugin is still installed.', '%d deactivated plugins are still installed.', count( $inactive ), 'blt-secure' ),
				count( $inactive )
			),
			__( 'Deactivated plugins still receive requests to their files and can be exploited. Delete any you do not need.', 'blt-secure' )
		);
	}

	/**
	 * @return array
	 */
	public static function themes_updated() {
		self::load_admin_includes();
		if ( ! function_exists( 'get_theme_updates' ) ) {
			return self::result( Blt_Secure_Health_Result::SKIP, __( 'Theme update data is unavailable.', 'blt-secure' ) );
		}
		$stale = self::stale_update_result( 'update_themes' );
		if ( null !== $stale ) {
			return $stale;
		}
		$updates = get_theme_updates();
		$count   = is_array( $updates ) ? count( $updates ) : 0;
		if ( 0 === $count ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'All installed themes are current.', 'blt-secure' ) );
		}
		return self::result(
			Blt_Secure_Health_Result::FAIL,
			sprintf(
				/* translators: %d: number of themes */
				_n( '%d theme has an update available.', '%d themes have updates available.', $count, 'blt-secure' ),
				$count
			)
		);
	}

	/**
	 * @return array
	 */
	public static function no_extra_themes() {
		if ( ! function_exists( 'wp_get_themes' ) ) {
			return self::result( Blt_Secure_Health_Result::SKIP, __( 'Theme list unavailable.', 'blt-secure' ) );
		}
		$themes = wp_get_themes();
		// Keep the active theme, its parent, and one fallback default.
		if ( count( $themes ) <= 3 ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'Only the themes you need are installed.', 'blt-secure' ) );
		}
		return self::result(
			Blt_Secure_Health_Result::WARN,
			sprintf(
				/* translators: %d: number of themes */
				__( '%d themes are installed.', 'blt-secure' ),
				count( $themes )
			),
			__( 'Unused themes still get security updates you may forget to apply. Keep only your active theme (plus its parent) and one default fallback.', 'blt-secure' )
		);
	}

	/**
	 * @return array
	 */
	public static function php_supported() {
		$version = PHP_VERSION;

		/**
		 * Filter the PHP end-of-security-support dates (minor version => Y-m-d).
		 * Source: https://www.php.net/supported-versions.php. Versions newer
		 * than the newest key are treated as supported.
		 *
		 * @param array<string,string> $dates Dates.
		 */
		$dates  = apply_filters( 'blt_secure_php_eol_dates', self::php_eol_dates() );
		$status = self::php_support_status( $version, time(), is_array( $dates ) ? $dates : self::php_eol_dates() );

		if ( 'supported' === $status ) {
			return self::result( Blt_Secure_Health_Result::PASS, sprintf( /* translators: %s: PHP version */ __( 'PHP %s still receives security fixes.', 'blt-secure' ), $version ) );
		}
		if ( 'ending' === $status ) {
			return self::result(
				Blt_Secure_Health_Result::WARN,
				sprintf( /* translators: %s: PHP version */ __( 'PHP %s stops receiving security fixes soon.', 'blt-secure' ), $version ),
				__( 'Plan a move to the newest supported PHP version with your host.', 'blt-secure' )
			);
		}
		return self::result(
			Blt_Secure_Health_Result::FAIL,
			sprintf( /* translators: %s: PHP version */ __( 'PHP %s is end-of-life and unpatched.', 'blt-secure' ), $version ),
			__( 'Ask your host to upgrade to a supported PHP version as soon as possible.', 'blt-secure' )
		);
	}

	/**
	 * Last day of security support per PHP minor version.
	 *
	 * @return array<string,string>
	 */
	public static function php_eol_dates() {
		return array(
			'7.4' => '2022-11-28',
			'8.0' => '2023-11-26',
			'8.1' => '2025-12-31',
			'8.2' => '2026-12-31',
			'8.3' => '2027-12-31',
			'8.4' => '2028-12-31',
			'8.5' => '2029-12-31',
		);
	}

	/**
	 * Classify a PHP version against the support calendar.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string               $version PHP_VERSION.
	 * @param int                  $now     Current Unix time.
	 * @param array<string,string> $dates   Minor => end-of-security-support date.
	 * @param int                  $window  Seconds before the date that count as "ending".
	 * @return string 'supported' | 'ending' | 'eol'
	 */
	public static function php_support_status( $version, $now, array $dates, $window = 7776000 ) {
		if ( ! preg_match( '/^(\d+)\.(\d+)/', (string) $version, $m ) ) {
			return 'supported';
		}
		$minor = $m[1] . '.' . $m[2];
		if ( isset( $dates[ $minor ] ) ) {
			$end = strtotime( $dates[ $minor ] . ' 23:59:59 UTC' );
			if ( false === $end ) {
				return 'supported';
			}
			if ( $now > $end ) {
				return 'eol';
			}
			return ( $end - $now ) <= $window ? 'ending' : 'supported';
		}

		// Unknown minor: older than every listed version is EOL, newer is supported.
		$oldest = null;
		foreach ( array_keys( $dates ) as $known ) {
			if ( null === $oldest || version_compare( $known, $oldest, '<' ) ) {
				$oldest = $known;
			}
		}
		return ( null !== $oldest && version_compare( $minor, $oldest, '<' ) ) ? 'eol' : 'supported';
	}

	/**
	 * @return array
	 */
	public static function ssl_enabled() {
		if ( 0 === strpos( strtolower( (string) home_url() ), 'https://' ) ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'Your site address uses HTTPS.', 'blt-secure' ) );
		}
		return self::result(
			Blt_Secure_Health_Result::FAIL,
			__( 'Your site address (WordPress Address) is not HTTPS.', 'blt-secure' ),
			__( 'Install a TLS certificate (most hosts and Cloudflare offer one free) and switch the Site/WordPress Address to https://.', 'blt-secure' )
		);
	}

	// ---------------------------------------------------------------------
	// Users & login.
	// ---------------------------------------------------------------------

	/**
	 * @return array
	 */
	public static function no_admin_username() {
		if ( ! function_exists( 'get_user_by' ) ) {
			return self::result( Blt_Secure_Health_Result::SKIP, __( 'User lookup unavailable.', 'blt-secure' ) );
		}
		$user = get_user_by( 'login', 'admin' );
		if ( ! $user ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'There is no account named "admin".', 'blt-secure' ) );
		}
		$is_admin = in_array( 'administrator', (array) $user->roles, true );
		return self::result(
			$is_admin ? Blt_Secure_Health_Result::FAIL : Blt_Secure_Health_Result::WARN,
			__( 'An account with the username "admin" exists.', 'blt-secure' ),
			__( '"admin" is the first username every brute-force tool tries. Create a new administrator with a unique name, then delete or demote this one.', 'blt-secure' )
		);
	}

	/**
	 * @return array
	 */
	public static function user_id_one() {
		if ( ! function_exists( 'get_user_by' ) ) {
			return self::result( Blt_Secure_Health_Result::SKIP, __( 'User lookup unavailable.', 'blt-secure' ) );
		}
		$user = get_user_by( 'id', 1 );
		if ( ! $user ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'User ID 1 does not exist.', 'blt-secure' ) );
		}
		$login = strtolower( (string) $user->user_login );
		if ( in_array( $login, array( 'admin', 'administrator', 'root', 'webmaster' ), true ) ) {
			return self::result(
				Blt_Secure_Health_Result::WARN,
				__( 'The first account (ID 1) uses a guessable administrator name.', 'blt-secure' ),
				__( 'Attackers assume user ID 1 is a super-admin. Give it a unique login name.', 'blt-secure' )
			);
		}
		return self::result( Blt_Secure_Health_Result::PASS, __( 'The first account does not use a predictable name.', 'blt-secure' ) );
	}

	/**
	 * @return array
	 */
	public static function registration_off() {
		if ( ! get_option( 'users_can_register' ) ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'Open registration is disabled.', 'blt-secure' ) );
		}
		$default_role = get_option( 'default_role' );
		$risky        = in_array( $default_role, array( 'administrator', 'editor', 'author' ), true );
		return self::result(
			$risky ? Blt_Secure_Health_Result::FAIL : Blt_Secure_Health_Result::WARN,
			sprintf(
				/* translators: %s: role name */
				__( 'Anyone can register, and new users get the "%s" role.', 'blt-secure' ),
				(string) $default_role
			),
			__( 'If you do not run a membership site, turn off Settings → General → Membership. If you need it, make sure new users default to Subscriber.', 'blt-secure' )
		);
	}

	/**
	 * @return array
	 */
	public static function login_errors_generic() {
		// Test the real behaviour, not the mere presence of a hook: run a probe
		// through the filter chain. A generic-message filter replaces the text
		// (the probe disappears); a hook that leaves it alone does not count.
		$probe = 'BLT_SECURE_PROBE_The_username_admin_is_not_registered';
		$out   = apply_filters( 'login_errors', $probe ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Probing a core filter on purpose.
		if ( is_string( $out ) && false === strpos( $out, $probe ) ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'Login errors are replaced with a generic message.', 'blt-secure' ) );
		}
		return self::result(
			Blt_Secure_Health_Result::WARN,
			__( 'Login errors say whether the username or the password was wrong.', 'blt-secure' ),
			__( 'That confirms valid usernames to attackers. BLT Secure does not change this message; add a login_errors filter that returns one generic sentence, or use a login-protection plugin that does.', 'blt-secure' )
		);
	}

	/**
	 * @param Blt_Secure_Health_Context $ctx Context.
	 * @return array
	 */
	public static function enumeration_blocked( $ctx ) {
		if ( $ctx->options->get( 'privacy', 'block_enum' ) ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'User enumeration via ?author=N and the REST users endpoint is blocked.', 'blt-secure' ) );
		}
		return self::result(
			Blt_Secure_Health_Result::WARN,
			__( 'Usernames can be harvested via ?author=N and /wp-json/wp/v2/users.', 'blt-secure' ),
			__( 'Enable "Block user enumeration" on the Hardening tab.', 'blt-secure' )
		);
	}

	/**
	 * @param Blt_Secure_Health_Context $ctx Context.
	 * @return array
	 */
	public static function login_lockout( $ctx ) {
		if ( $ctx->options->get( 'login', 'lockout_enabled' ) ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'Repeated failed logins are locked out.', 'blt-secure' ) );
		}
		return self::result(
			Blt_Secure_Health_Result::WARN,
			__( 'There is no limit on failed login attempts.', 'blt-secure' ),
			__( 'Enable the failed-login lockout on the Login tab to slow down brute-force attacks.', 'blt-secure' )
		);
	}

	/**
	 * @param Blt_Secure_Health_Context $ctx Context.
	 * @return array
	 */
	public static function two_factor( $ctx ) {
		$policy = (string) $ctx->options->get( 'twofa', 'policy', 'optional' );
		if ( in_array( $policy, array( 'required_all', 'required_admins' ), true ) ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'Two-factor authentication is required for at least administrators.', 'blt-secure' ) );
		}
		return self::result(
			Blt_Secure_Health_Result::WARN,
			__( 'Two-factor authentication is optional (not enforced).', 'blt-secure' ),
			__( 'On the Login tab, set the two-factor policy to require TOTP at least for administrators.', 'blt-secure' )
		);
	}

	/**
	 * @return array
	 */
	public static function app_passwords() {
		$available = function_exists( 'wp_is_application_passwords_available' ) ? wp_is_application_passwords_available() : true;
		if ( ! $available ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'Application Passwords are disabled.', 'blt-secure' ) );
		}
		return self::result(
			Blt_Secure_Health_Result::WARN,
			__( 'Application Passwords are enabled.', 'blt-secure' ),
			__( 'If no external service or app connects to this site, disable Application Passwords to remove an authentication surface.', 'blt-secure' )
		);
	}

	/**
	 * @param Blt_Secure_Health_Context $ctx Context.
	 * @return array
	 */
	public static function xmlrpc_disabled( $ctx ) {
		if ( ! $ctx->options->get( 'xmlrpc', 'enabled' ) ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'XML-RPC is turned off.', 'blt-secure' ) );
		}
		return self::result(
			Blt_Secure_Health_Result::WARN,
			__( 'XML-RPC is enabled.', 'blt-secure' ),
			__( 'XML-RPC is abused for brute-force amplification and pingback DoS. Disable it on the Hardening tab unless Jetpack or the mobile app needs it.', 'blt-secure' )
		);
	}

	// ---------------------------------------------------------------------
	// Configuration & debug.
	// ---------------------------------------------------------------------

	/**
	 * @return array
	 */
	public static function wp_debug_off() {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			return self::result(
				Blt_Secure_Health_Result::WARN,
				__( 'WP_DEBUG is enabled.', 'blt-secure' ),
				__( 'Debug mode belongs on staging, not production. Set WP_DEBUG to false in wp-config.php.', 'blt-secure' )
			);
		}
		return self::result( Blt_Secure_Health_Result::PASS, __( 'WP_DEBUG is off.', 'blt-secure' ) );
	}

	/**
	 * @return array
	 */
	public static function debug_display_off() {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG && ( ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY ) ) {
			return self::result(
				Blt_Secure_Health_Result::FAIL,
				__( 'Debug output can be shown to visitors (WP_DEBUG_DISPLAY is not false).', 'blt-secure' ),
				__( 'Leaked errors expose paths and query details. Define WP_DEBUG_DISPLAY as false.', 'blt-secure' )
			);
		}
		return self::result( Blt_Secure_Health_Result::PASS, __( 'Debug output is not shown to visitors.', 'blt-secure' ) );
	}

	/**
	 * @return array
	 */
	public static function debug_log_hidden() {
		$log = self::debug_log_path( defined( 'WP_DEBUG_LOG' ) ? WP_DEBUG_LOG : false, WP_CONTENT_DIR );
		if ( ! file_exists( $log ) ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'No debug log file is present.', 'blt-secure' ) );
		}
		if ( ! self::path_in_webroot( $log, ABSPATH ) ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'The debug log is stored outside the web root.', 'blt-secure' ) );
		}
		return self::result(
			Blt_Secure_Health_Result::WARN,
			__( 'A debug log file exists inside the web root and may be downloadable.', 'blt-secure' ),
			__( 'Delete it, or move the log outside the web root by setting WP_DEBUG_LOG to an absolute path above the site folder.', 'blt-secure' )
		);
	}

	/**
	 * Where WordPress writes the debug log: WP_DEBUG_LOG as a path string, else
	 * wp-content/debug.log.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param mixed  $constant    WP_DEBUG_LOG value (false when undefined).
	 * @param string $content_dir WP_CONTENT_DIR.
	 * @return string
	 */
	public static function debug_log_path( $constant, $content_dir ) {
		if ( is_string( $constant ) && '' !== $constant && ! in_array( strtolower( $constant ), array( 'true', 'false', '1', '0' ), true ) ) {
			return $constant;
		}
		return rtrim( (string) $content_dir, '/\\' ) . '/debug.log';
	}

	/**
	 * Whether a path lies inside the web root (ABSPATH).
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string $path    File path.
	 * @param string $webroot ABSPATH.
	 * @return bool
	 */
	public static function path_in_webroot( $path, $webroot ) {
		$path    = str_replace( '\\', '/', (string) $path );
		$webroot = rtrim( str_replace( '\\', '/', (string) $webroot ), '/' ) . '/';
		return 0 === strpos( $path, $webroot );
	}

	/**
	 * @return array
	 */
	public static function script_debug_off() {
		if ( defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ) {
			return self::result( Blt_Secure_Health_Result::WARN, __( 'SCRIPT_DEBUG is enabled.', 'blt-secure' ), __( 'This loads unminified core assets and is meant for development only.', 'blt-secure' ) );
		}
		return self::result( Blt_Secure_Health_Result::PASS, __( 'SCRIPT_DEBUG is off.', 'blt-secure' ) );
	}

	/**
	 * @return array
	 */
	public static function savequeries_off() {
		if ( defined( 'SAVEQUERIES' ) && SAVEQUERIES ) {
			return self::result( Blt_Secure_Health_Result::WARN, __( 'SAVEQUERIES is enabled.', 'blt-secure' ), __( 'Query logging costs memory and performance and should be off in production.', 'blt-secure' ) );
		}
		return self::result( Blt_Secure_Health_Result::PASS, __( 'Database query logging is off.', 'blt-secure' ) );
	}

	/**
	 * @return array
	 */
	public static function display_errors_off() {
		$value = strtolower( trim( (string) ini_get( 'display_errors' ) ) );
		if ( '' === $value || '0' === $value || 'off' === $value || 'false' === $value || 'no' === $value ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'PHP display_errors is off.', 'blt-secure' ) );
		}
		return self::result(
			Blt_Secure_Health_Result::FAIL,
			__( 'PHP display_errors is on.', 'blt-secure' ),
			__( 'Ask your host to set display_errors = Off so PHP errors are never printed to visitors.', 'blt-secure' )
		);
	}

	/**
	 * @return array
	 */
	public static function allow_url_include_off() {
		if ( (bool) ini_get( 'allow_url_include' ) ) {
			return self::result(
				Blt_Secure_Health_Result::FAIL,
				__( 'PHP allow_url_include is on.', 'blt-secure' ),
				__( 'This enables remote file inclusion attacks. Have your host set allow_url_include = Off.', 'blt-secure' )
			);
		}
		return self::result( Blt_Secure_Health_Result::PASS, __( 'PHP allow_url_include is off.', 'blt-secure' ) );
	}

	/**
	 * @param Blt_Secure_Health_Context $ctx Context.
	 * @return array
	 */
	public static function file_edit_disabled( $ctx ) {
		if ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'The theme/plugin file editor is disabled in wp-config.php.', 'blt-secure' ) );
		}
		if ( $ctx->options->get( 'fileguard', 'disallow_file_edit' ) ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'The theme/plugin file editor is disabled by BLT Secure.', 'blt-secure' ) );
		}
		return self::result(
			Blt_Secure_Health_Result::WARN,
			__( 'The built-in theme/plugin file editor is available.', 'blt-secure' ),
			__( 'If wp-admin is compromised, this editor lets an attacker run code instantly. Disable it on the Hardening tab.', 'blt-secure' )
		);
	}

	/**
	 * @param Blt_Secure_Health_Context $ctx Context.
	 * @return array
	 */
	public static function file_managers_blocked( $ctx ) {
		if ( $ctx->options->get( 'fileguard', 'block_file_managers' ) ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'Installation of file-manager plugins is blocked.', 'blt-secure' ) );
		}
		return self::result(
			Blt_Secure_Health_Result::WARN,
			__( 'File-manager plugins can be installed.', 'blt-secure' ),
			__( 'Vulnerable file-manager plugins are a frequent entry point. Block them on the Hardening tab.', 'blt-secure' )
		);
	}

	/**
	 * @return array
	 */
	public static function force_ssl_admin() {
		if ( 0 !== strpos( strtolower( (string) home_url() ), 'https://' ) ) {
			return self::result( Blt_Secure_Health_Result::SKIP, __( 'The site is not on HTTPS yet, so this does not apply.', 'blt-secure' ) );
		}
		if ( defined( 'FORCE_SSL_ADMIN' ) && FORCE_SSL_ADMIN ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'The admin area is forced over SSL.', 'blt-secure' ) );
		}
		return self::result(
			Blt_Secure_Health_Result::WARN,
			__( 'FORCE_SSL_ADMIN is not set.', 'blt-secure' ),
			__( 'Add define( \'FORCE_SSL_ADMIN\', true ); to wp-config.php so logins and cookies are always sent over HTTPS.', 'blt-secure' )
		);
	}

	/**
	 * @return array
	 */
	public static function keys_defined() {
		$keys    = array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT' );
		$missing = array();
		foreach ( $keys as $key ) {
			if ( ! defined( $key ) || '' === (string) constant( $key ) ) {
				$missing[] = $key;
			}
		}
		if ( empty( $missing ) ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'All authentication keys and salts are defined.', 'blt-secure' ) );
		}
		return self::result(
			Blt_Secure_Health_Result::FAIL,
			sprintf(
				/* translators: %d: number of keys */
				__( '%d authentication key(s)/salt(s) are missing.', 'blt-secure' ),
				count( $missing )
			),
			__( 'Generate a fresh set at api.wordpress.org/secret-key/1.1/salt/ and paste them into wp-config.php.', 'blt-secure' )
		);
	}

	/**
	 * @return array
	 */
	public static function keys_not_default() {
		$keys = array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY' );
		foreach ( $keys as $key ) {
			if ( defined( $key ) ) {
				$value = (string) constant( $key );
				if ( '' === $value || false !== strpos( $value, 'put your unique phrase here' ) || strlen( $value ) < 32 ) {
					return self::result(
						Blt_Secure_Health_Result::FAIL,
						__( 'At least one secret key is still a default/placeholder value.', 'blt-secure' ),
						__( 'Replace every key and salt in wp-config.php with a unique set from the WordPress secret-key generator.', 'blt-secure' )
					);
				}
			}
		}
		return self::result( Blt_Secure_Health_Result::PASS, __( 'Secret keys are unique, non-default values.', 'blt-secure' ) );
	}

	// ---------------------------------------------------------------------
	// Files & permissions.
	// ---------------------------------------------------------------------

	/**
	 * @return array
	 */
	public static function wp_config_perms() {
		$path = ABSPATH . 'wp-config.php';
		if ( ! file_exists( $path ) ) {
			// wp-config.php one level up is a valid, hardened layout.
			$path = dirname( ABSPATH ) . '/wp-config.php';
		}
		if ( ! file_exists( $path ) ) {
			return self::result( Blt_Secure_Health_Result::SKIP, __( 'wp-config.php could not be located from PHP.', 'blt-secure' ) );
		}
		$perms = fileperms( $path ) & 0777;
		if ( $perms & 0004 ) {
			return self::result(
				Blt_Secure_Health_Result::FAIL,
				sprintf( /* translators: %o: octal permissions */ __( 'wp-config.php is world-readable (%o).', 'blt-secure' ), $perms ),
				__( 'It holds your database credentials and secret keys. chmod it to 640 (or 600).', 'blt-secure' )
			);
		}
		return self::result( Blt_Secure_Health_Result::PASS, sprintf( /* translators: %o: octal permissions */ __( 'wp-config.php permissions are safe (%o).', 'blt-secure' ), $perms ) );
	}

	/**
	 * @return array
	 */
	public static function uploads_index() {
		$uploads = wp_upload_dir();
		if ( empty( $uploads['basedir'] ) || ! is_dir( $uploads['basedir'] ) ) {
			return self::result( Blt_Secure_Health_Result::SKIP, __( 'The uploads directory could not be located.', 'blt-secure' ) );
		}
		if ( file_exists( trailingslashit( $uploads['basedir'] ) . 'index.php' ) || file_exists( trailingslashit( $uploads['basedir'] ) . 'index.html' ) ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'The uploads folder has an index file blocking directory listing.', 'blt-secure' ) );
		}
		return self::result(
			Blt_Secure_Health_Result::WARN,
			__( 'The uploads folder has no index file.', 'blt-secure' ),
			__( 'If the server allows directory listing, visitors could browse every uploaded file. Add an empty index.php, or disable listing at the server.', 'blt-secure' )
		);
	}

	/**
	 * @return array
	 */
	public static function no_installer_files() {
		$names = @scandir( ABSPATH ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( ! is_array( $names ) ) {
			return self::result( Blt_Secure_Health_Result::SKIP, __( 'The web root could not be listed from PHP.', 'blt-secure' ) );
		}

		$leftovers = array();
		$sample    = false;
		foreach ( array_slice( $names, 0, 3000 ) as $name ) {
			if ( 'wp-config-sample.php' === $name ) {
				$sample = true;
			} elseif ( self::is_leftover_name( $name ) ) {
				$leftovers[] = $name;
			}
		}

		if ( ! empty( $leftovers ) ) {
			return self::result(
				Blt_Secure_Health_Result::FAIL,
				sprintf(
					/* translators: %s: comma-separated file names */
					__( 'Leftover installer, backup or config-copy files are in the web root: %s', 'blt-secure' ),
					implode( ', ', array_slice( $leftovers, 0, 8 ) )
				),
				__( 'Installer scripts, database dumps, site archives and wp-config copies are downloadable by anyone and routinely used to take over sites. Delete them (keep backups outside the web root).', 'blt-secure' )
			);
		}
		if ( $sample ) {
			return self::result(
				Blt_Secure_Health_Result::WARN,
				__( 'A wp-config-sample.php file is present in the web root.', 'blt-secure' ),
				__( 'It is harmless but advertises WordPress. You may delete it.', 'blt-secure' )
			);
		}
		return self::result( Blt_Secure_Health_Result::PASS, __( 'No leftover installer, backup or config-copy files were found in the web root.', 'blt-secure' ) );
	}

	/**
	 * Whether a web-root entry name is a leftover that should not be public:
	 * migration installers, SQL dumps, site archives, wp-config copies,
	 * phpinfo/test scripts, .env, .git, error logs.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string $name Directory entry name.
	 * @return bool
	 */
	public static function is_leftover_name( $name ) {
		$name  = strtolower( (string) $name );
		$exact = array( 'dup-installer', 'phpinfo.php', 'info.php', 'php-info.php', 'pi.php', 'test.php', '.env', '.git', 'debug.log', '.wp-config.php.swp' );
		if ( in_array( $name, $exact, true ) ) {
			return true;
		}
		$patterns = array(
			'/^installer(?:-backup|-data|-log)?\.(?:php|sql|txt)$/',
			'/^wp-config\.(?:php\.)?(?:bak|old|orig|save|swp|txt|copy|backup)$/',
			'/^wp-config\.php~$/',
			'/\.sql(?:\.gz|\.zip)?$/',
			'/^(?:backup|site|www|public_html|website|wordpress|wp)\.(?:zip|tar|tar\.gz|tgz|rar|7z)$/',
			'/backup.*\.(?:zip|tar|tar\.gz|tgz|7z)$/',
		);
		foreach ( $patterns as $pattern ) {
			if ( preg_match( $pattern, $name ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @return array
	 */
	public static function timthumb_absent() {
		$hits = array();

		// Active theme and its parent (child themes inherit the parent's copy).
		$dirs = array_unique( array( get_stylesheet_directory(), get_template_directory() ) );
		foreach ( $dirs as $dir ) {
			$hits = array_merge( $hits, self::find_timthumb( (string) $dir ) );
		}

		// Plugin folders (bounded): old TimThumb copies live in plugins too.
		$plugin_dir = defined( 'WP_PLUGIN_DIR' ) ? WP_PLUGIN_DIR : WP_CONTENT_DIR . '/plugins';
		$plugins    = @glob( trailingslashit( $plugin_dir ) . '*', GLOB_ONLYDIR ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		foreach ( array_slice( is_array( $plugins ) ? $plugins : array(), 0, 200 ) as $dir ) {
			$hits = array_merge( $hits, self::find_timthumb( $dir ) );
		}

		if ( ! empty( $hits ) ) {
			return self::result(
				Blt_Secure_Health_Result::FAIL,
				sprintf(
					/* translators: %s: comma-separated file paths */
					__( 'A TimThumb script was found: %s', 'blt-secure' ),
					implode( ', ', array_slice( array_unique( $hits ), 0, 5 ) )
				),
				__( 'Old TimThumb copies allow remote code execution. Remove it or update the theme/plugin that ships it.', 'blt-secure' )
			);
		}
		return self::result( Blt_Secure_Health_Result::PASS, __( 'No TimThumb script was found in the active theme or plugins.', 'blt-secure' ) );
	}

	/**
	 * TimThumb copies inside one theme/plugin folder. `timthumb.php` is
	 * unambiguous; the generic `thumb.php` only counts when its content
	 * actually identifies TimThumb.
	 *
	 * @param string $dir Folder.
	 * @return string[] Basename-relative hit paths.
	 */
	private static function find_timthumb( $dir ) {
		$hits = array();
		$base = trailingslashit( $dir );
		foreach ( array( 'timthumb.php', 'includes/timthumb.php', 'lib/timthumb.php', 'inc/timthumb.php', 'scripts/timthumb.php' ) as $rel ) {
			if ( file_exists( $base . $rel ) ) {
				$hits[] = basename( $dir ) . '/' . $rel;
			}
		}
		foreach ( array( 'thumb.php', 'includes/thumb.php', 'lib/thumb.php' ) as $rel ) {
			if ( file_exists( $base . $rel ) ) {
				$head = @file_get_contents( $base . $rel, false, null, 0, 8192 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents, WordPress.PHP.NoSilencedErrors.Discouraged
				if ( false !== $head && false !== stripos( $head, 'timthumb' ) ) {
					$hits[] = basename( $dir ) . '/' . $rel;
				}
			}
		}
		return $hits;
	}

	// ---------------------------------------------------------------------
	// Information disclosure.
	// ---------------------------------------------------------------------

	/**
	 * @return array
	 */
	public static function version_hidden() {
		// Judge the real output: the generator tag is emitted through the
		// `the_generator` filter, which "Hide the WordPress version" empties —
		// the wp_head action itself stays registered, so has_action() alone
		// would report a hidden version as exposed forever.
		global $wp_version;
		$sample = '<meta name="generator" content="WordPress ' . $wp_version . '" />';
		$out    = (string) apply_filters( 'the_generator', $sample, 'html' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Probing a core filter on purpose.
		if ( ! has_action( 'wp_head', 'wp_generator' ) || '' === trim( $out ) || false === strpos( $out, (string) $wp_version ) ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'The WordPress version is not printed in the generator tag.', 'blt-secure' ) );
		}
		return self::result(
			Blt_Secure_Health_Result::WARN,
			__( 'The WordPress version is printed in the page <meta> generator tag.', 'blt-secure' ),
			__( 'Enable "Hide the WordPress version" on the Hardening tab so the version is not advertised.', 'blt-secure' )
		);
	}

	/**
	 * @return array
	 */
	public static function wlw_hidden() {
		if ( has_action( 'wp_head', 'wlwmanifest_link' ) ) {
			return self::result( Blt_Secure_Health_Result::WARN, __( 'The Windows Live Writer manifest link is present in the page head.', 'blt-secure' ), __( 'It is obsolete and only adds fingerprinting surface. BLT Secure does not remove it; add remove_action( \'wp_head\', \'wlwmanifest_link\' ) in a small snippet if you want it gone. Advisory only.', 'blt-secure' ) );
		}
		return self::result( Blt_Secure_Health_Result::PASS, __( 'The Windows Live Writer manifest link is removed.', 'blt-secure' ) );
	}

	/**
	 * @return array
	 */
	public static function rsd_hidden() {
		if ( has_action( 'wp_head', 'rsd_link' ) ) {
			return self::result( Blt_Secure_Health_Result::WARN, __( 'The RSD/EditURI link is present in the page head.', 'blt-secure' ), __( 'It is only used by legacy blog clients over XML-RPC. BLT Secure does not remove it; add remove_action( \'wp_head\', \'rsd_link\' ) in a small snippet if you want it gone. Advisory only.', 'blt-secure' ) );
		}
		return self::result( Blt_Secure_Health_Result::PASS, __( 'The RSD/EditURI link is removed.', 'blt-secure' ) );
	}

	/**
	 * @return array
	 */
	public static function rest_link_hidden() {
		$present = has_action( 'wp_head', 'rest_output_link_wp_head' );
		if ( $present ) {
			return self::result( Blt_Secure_Health_Result::WARN, __( 'The REST API link is advertised in the page head.', 'blt-secure' ), __( 'This is informational only; removing it slightly reduces fingerprinting. BLT Secure does not remove it (the REST API is public by design).', 'blt-secure' ) );
		}
		return self::result( Blt_Secure_Health_Result::PASS, __( 'The REST API link is not advertised in the page head.', 'blt-secure' ) );
	}

	/**
	 * @return array
	 */
	public static function readme_absent() {
		$found = array();
		foreach ( array( 'readme.html', 'license.txt' ) as $file ) {
			if ( file_exists( ABSPATH . $file ) ) {
				$found[] = $file;
			}
		}
		if ( empty( $found ) ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'The core readme.html and license.txt are removed.', 'blt-secure' ) );
		}
		return self::result(
			Blt_Secure_Health_Result::WARN,
			sprintf(
				/* translators: %s: comma-separated file names */
				__( 'Fingerprinting files are present: %s.', 'blt-secure' ),
				implode( ', ', $found )
			),
			__( 'readme.html reveals the exact WordPress version. It is safe to delete (it returns on core updates).', 'blt-secure' )
		);
	}

	/**
	 * @return array
	 */
	public static function expose_php_off() {
		if ( (bool) ini_get( 'expose_php' ) ) {
			return self::result(
				Blt_Secure_Health_Result::WARN,
				__( 'PHP advertises its version via the X-Powered-By header (expose_php = On).', 'blt-secure' ),
				__( 'Ask your host to set expose_php = Off.', 'blt-secure' )
			);
		}
		return self::result( Blt_Secure_Health_Result::PASS, __( 'PHP does not advertise its version (expose_php = Off).', 'blt-secure' ) );
	}

	// ---------------------------------------------------------------------
	// HTTP response headers.
	// ---------------------------------------------------------------------

	/**
	 * Shared implementation for "header present" checks.
	 *
	 * @param Blt_Secure_Health_Context $ctx       Context.
	 * @param string                    $header    Header name.
	 * @param string                    $advisory  Guidance when absent.
	 * @param bool                      $advisory_only Absent → WARN (true) or FAIL (false).
	 * @param callable|null             $validator   Returns true when a present value is acceptable.
	 * @return array
	 */
	private static function header_present( $ctx, $header, $advisory, $advisory_only = true, $validator = null ) {
		$value = $ctx->header( $header );
		if ( null === $value ) {
			return self::result( Blt_Secure_Health_Result::SKIP, __( 'The site could not be reached (or did not return a normal page) to read its response headers.', 'blt-secure' ) );
		}
		if ( '' !== $value && null !== $validator && ! call_user_func( $validator, $value ) ) {
			return self::result(
				Blt_Secure_Health_Result::WARN,
				sprintf(
					/* translators: 1: header name, 2: header value */
					__( '%1$s is sent but its value is not protective: %2$s', 'blt-secure' ),
					$header,
					$value
				),
				$advisory
			);
		}
		if ( '' !== $value ) {
			return self::result(
				Blt_Secure_Health_Result::PASS,
				sprintf(
					/* translators: 1: header name, 2: header value */
					__( '%1$s is sent: %2$s', 'blt-secure' ),
					$header,
					$value
				)
			);
		}
		return self::result(
			$advisory_only ? Blt_Secure_Health_Result::WARN : Blt_Secure_Health_Result::FAIL,
			sprintf( /* translators: %s: header name */ __( '%s is not sent.', 'blt-secure' ), $header ),
			$advisory
		);
	}

	/**
	 * @param Blt_Secure_Health_Context $ctx Context.
	 * @return array
	 */
	public static function header_nosniff( $ctx ) {
		return self::header_present( $ctx, 'X-Content-Type-Options', __( 'Enable "Send security headers" on the Hardening tab, or set it at your server/Cloudflare. The value must be "nosniff".', 'blt-secure' ), false, array( __CLASS__, 'valid_nosniff' ) );
	}

	/**
	 * X-Content-Type-Options is only protective as "nosniff". Pure (unit-tested).
	 *
	 * @param string $value Header value.
	 * @return bool
	 */
	public static function valid_nosniff( $value ) {
		return false !== stripos( (string) $value, 'nosniff' );
	}

	/**
	 * X-Frame-Options must be DENY, SAMEORIGIN or ALLOW-FROM. Pure (unit-tested).
	 *
	 * @param string $value Header value.
	 * @return bool
	 */
	public static function valid_xframe( $value ) {
		$value = strtoupper( trim( (string) $value ) );
		return 'DENY' === $value || 'SAMEORIGIN' === $value || 0 === strpos( $value, 'ALLOW-FROM' );
	}

	/**
	 * HSTS only protects with a positive max-age (max-age=0 deletes the
	 * policy). Pure (unit-tested).
	 *
	 * @param string $value Header value.
	 * @return bool
	 */
	public static function valid_hsts( $value ) {
		return (bool) preg_match( '/max-age\s*=\s*"?(\d+)"?/i', (string) $value, $m ) && (int) $m[1] > 0;
	}

	/**
	 * Referrer-Policy: the browser applies the LAST recognized token; the
	 * leaky unsafe-url (and an empty value) do not count. Pure (unit-tested).
	 *
	 * @param string $value Header value.
	 * @return bool
	 */
	public static function valid_referrer( $value ) {
		$ok   = array( 'no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'origin', 'origin-when-cross-origin', 'no-referrer-when-downgrade' );
		$last = '';
		foreach ( explode( ',', strtolower( (string) $value ) ) as $token ) {
			$token = trim( $token );
			if ( in_array( $token, $ok, true ) || 'unsafe-url' === $token ) {
				$last = $token;
			}
		}
		return '' !== $last && 'unsafe-url' !== $last;
	}

	/**
	 * @param Blt_Secure_Health_Context $ctx Context.
	 * @return array
	 */
	public static function header_xframe( $ctx ) {
		// X-Frame-Options or a CSP frame-ancestors directive both satisfy this.
		$csp = $ctx->header( 'Content-Security-Policy' );
		if ( null !== $csp && false !== stripos( $csp, 'frame-ancestors' ) ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'Clickjacking is prevented via a CSP frame-ancestors directive.', 'blt-secure' ) );
		}
		return self::header_present( $ctx, 'X-Frame-Options', __( 'Set X-Frame-Options (SAMEORIGIN) on the Hardening tab to prevent clickjacking.', 'blt-secure' ), false, array( __CLASS__, 'valid_xframe' ) );
	}

	/**
	 * @param Blt_Secure_Health_Context $ctx Context.
	 * @return array
	 */
	public static function header_hsts( $ctx ) {
		if ( 0 !== strpos( strtolower( (string) home_url() ), 'https://' ) ) {
			return self::result( Blt_Secure_Health_Result::SKIP, __( 'HSTS only applies once the site is on HTTPS.', 'blt-secure' ) );
		}
		return self::header_present( $ctx, 'Strict-Transport-Security', __( 'Enable HSTS on the Hardening tab so browsers refuse to connect over plain HTTP. max-age must be greater than 0.', 'blt-secure' ), true, array( __CLASS__, 'valid_hsts' ) );
	}

	/**
	 * @param Blt_Secure_Health_Context $ctx Context.
	 * @return array
	 */
	public static function header_referrer( $ctx ) {
		return self::header_present( $ctx, 'Referrer-Policy', __( 'Set a Referrer-Policy (strict-origin-when-cross-origin) on the Hardening tab; unsafe-url leaks full URLs.', 'blt-secure' ), true, array( __CLASS__, 'valid_referrer' ) );
	}

	/**
	 * @param Blt_Secure_Health_Context $ctx Context.
	 * @return array
	 */
	public static function header_permissions( $ctx ) {
		return self::header_present( $ctx, 'Permissions-Policy', __( 'A Permissions-Policy lets you switch off browser features (camera, geolocation…) you do not use.', 'blt-secure' ), true );
	}

	/**
	 * @param Blt_Secure_Health_Context $ctx Context.
	 * @return array
	 */
	public static function header_csp( $ctx ) {
		$value = $ctx->header( 'Content-Security-Policy' );
		if ( null === $value ) {
			return self::result( Blt_Secure_Health_Result::SKIP, __( 'The site could not be reached to read its response headers.', 'blt-secure' ) );
		}
		if ( '' !== (string) $value ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'A Content-Security-Policy is enforced.', 'blt-secure' ) );
		}
		$report_only = (string) $ctx->header( 'Content-Security-Policy-Report-Only' );
		if ( '' !== $report_only ) {
			return self::result( Blt_Secure_Health_Result::WARN, __( 'A Content-Security-Policy is present but only in Report-Only mode.', 'blt-secure' ), __( 'Once the browser console is clean, switch CSP from Report-Only to enforcing on the Hardening tab.', 'blt-secure' ) );
		}
		return self::result( Blt_Secure_Health_Result::WARN, __( 'No Content-Security-Policy is sent.', 'blt-secure' ), __( 'CSP is the strongest defense against cross-site scripting. Start in Report-Only mode on the Hardening tab.', 'blt-secure' ) );
	}

	/**
	 * @param Blt_Secure_Health_Context $ctx Context.
	 * @return array
	 */
	public static function header_powered_by( $ctx ) {
		$value = $ctx->header( 'X-Powered-By' );
		if ( null === $value ) {
			return self::result( Blt_Secure_Health_Result::SKIP, __( 'The site could not be reached to read its response headers.', 'blt-secure' ) );
		}
		if ( '' === (string) $value ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'The server does not send an X-Powered-By header.', 'blt-secure' ) );
		}
		return self::result(
			Blt_Secure_Health_Result::WARN,
			sprintf( /* translators: %s: header value */ __( 'X-Powered-By reveals the stack: %s', 'blt-secure' ), $value ),
			__( 'Set expose_php = Off (or strip the header at your server/Cloudflare) so the PHP version is not advertised.', 'blt-secure' )
		);
	}

	// ---------------------------------------------------------------------
	// Database.
	// ---------------------------------------------------------------------

	/**
	 * @return array
	 */
	public static function table_prefix() {
		global $wpdb;
		$prefix = isset( $wpdb->base_prefix ) ? $wpdb->base_prefix : ( isset( $wpdb->prefix ) ? $wpdb->prefix : 'wp_' );
		if ( 'wp_' !== $prefix ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'The database table prefix has been customized.', 'blt-secure' ) );
		}
		return self::result(
			Blt_Secure_Health_Result::WARN,
			__( 'The database uses the default "wp_" table prefix.', 'blt-secure' ),
			__( 'A non-default prefix is a minor obstacle to some automated SQL-injection payloads. Changing it on a live site requires care (and a backup).', 'blt-secure' )
		);
	}

	/**
	 * @return array
	 */
	public static function db_password_strength() {
		if ( ! defined( 'DB_PASSWORD' ) ) {
			return self::result( Blt_Secure_Health_Result::SKIP, __( 'The database password is not defined as a constant.', 'blt-secure' ) );
		}
		$password = (string) DB_PASSWORD;
		$length   = strlen( $password );
		// Measure locally only; never store or output the password itself.
		$classes = ( preg_match( '/[a-z]/', $password ) ? 1 : 0 )
			+ ( preg_match( '/[A-Z]/', $password ) ? 1 : 0 )
			+ ( preg_match( '/[0-9]/', $password ) ? 1 : 0 )
			+ ( preg_match( '/[^a-zA-Z0-9]/', $password ) ? 1 : 0 );
		if ( '' === $password ) {
			return self::result( Blt_Secure_Health_Result::FAIL, __( 'The database account has no password.', 'blt-secure' ), __( 'Set a strong password on the database user.', 'blt-secure' ) );
		}
		if ( $length >= 16 && $classes >= 3 ) {
			return self::result( Blt_Secure_Health_Result::PASS, __( 'The database password is long and mixed-character.', 'blt-secure' ) );
		}
		return self::result(
			Blt_Secure_Health_Result::WARN,
			__( 'The database password is short or low-complexity.', 'blt-secure' ),
			__( 'Use at least 16 characters mixing upper/lowercase, digits, and symbols (update it in your host panel and wp-config.php together).', 'blt-secure' )
		);
	}
}
