<?php
/**
 * Core plugin loader.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Singleton that wires options, modules, and admin together.
 */
final class Blt_Secure {

	/**
	 * Shared instance.
	 *
	 * @var Blt_Secure|null
	 */
	private static $instance = null;

	/**
	 * Settings access.
	 *
	 * @var Blt_Secure_Options
	 */
	public $options;

	/**
	 * IP resolver shared by lockout/alerting.
	 *
	 * @var Blt_Secure_Ip_Resolver
	 */
	public $ip_resolver;

	/**
	 * Credential store (encrypted options in Phase 1).
	 *
	 * @var Blt_Secure_Credential_Store
	 */
	public $credentials;

	/**
	 * Scanner finding whitelist ("ignore" list) shared across scanners.
	 *
	 * @var Blt_Secure_Scan_Whitelist
	 */
	public $whitelist;

	/**
	 * Registered modules, keyed by id.
	 *
	 * @var Blt_Secure_Module[]
	 */
	public $modules = array();

	/**
	 * Update checker wiring (null on front-end requests).
	 *
	 * @var Blt_Secure_Updater|null
	 */
	public $updater = null;

	/**
	 * Get the shared instance.
	 *
	 * @return Blt_Secure
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * plugins_loaded entry point.
	 *
	 * @return void
	 */
	public static function boot() {
		self::instance()->init();
	}

	/**
	 * Build shared services and modules; boot the enabled ones.
	 *
	 * @return void
	 */
	private function init() {
		$this->options     = new Blt_Secure_Options();
		$this->ip_resolver = new Blt_Secure_Ip_Resolver( $this->options );
		$this->credentials = new Blt_Secure_Encrypted_Option_Store( new Blt_Secure_Crypto() );
		$this->whitelist   = new Blt_Secure_Scan_Whitelist();

		$alerting = new Blt_Secure_Alerting( $this->options );

		$modules = array(
			$alerting,
			new Blt_Secure_Alert_Channels( $this->options, $this->credentials ),
			new Blt_Secure_Activity( $this->options, $alerting ),
			new Blt_Secure_Upload_Guard( $this->options, $alerting ),
			new Blt_Secure_Headers( $this->options ),
			new Blt_Secure_Privacy( $this->options ),
			new Blt_Secure_Xmlrpc( $this->options ),
			new Blt_Secure_File_Guard( $this->options, $alerting ),
			new Blt_Secure_Login_Hardening( $this->options, $this->ip_resolver, $alerting ),
			new Blt_Secure_Two_Factor( $this->options, new Blt_Secure_Crypto(), $alerting ),
			new Blt_Secure_Health( $this->options ),
			new Blt_Secure_Scanner( $this->options, $alerting, $this->whitelist ),
			new Blt_Secure_Malware( $this->options, $alerting, $this->whitelist ),
			new Blt_Secure_Baseline( $this->options, $alerting, $this->whitelist ),
			new Blt_Secure_Ioc( $this->options, $this->credentials, $alerting ),
			new Blt_Secure_Timeline( $this->options, $this->credentials, $alerting ),
			new Blt_Secure_Fleet( $this->options, $this->credentials, $alerting, $this->whitelist ),
			new Blt_Secure_Badge( $this->options ),
		);

		/**
		 * Filter the module list. Phase 2/3 features (scanner, IOC sync,
		 * integrity monitor) hook in here without touching the loader.
		 *
		 * @param Blt_Secure_Module[] $modules Module instances.
		 * @param Blt_Secure          $plugin  Plugin core.
		 */
		$modules = apply_filters( 'blt_secure_modules', $modules, $this );

		foreach ( $modules as $module ) {
			if ( ! $module instanceof Blt_Secure_Module ) {
				continue;
			}
			$this->modules[ $module->id() ] = $module;
			$this->options->register_defaults( $module->id(), $module->defaults() );
		}

		// Non-module defaults (advanced tab has no module class).
		$this->options->register_defaults(
			'advanced',
			array(
				'trust_cf_header'          => 'auto',
				'remove_cf_on_uninstall'   => false,
				'delete_data_on_uninstall' => false,
			)
		);

		foreach ( $this->modules as $module ) {
			if ( $module->is_enabled() ) {
				$module->boot();
			}
		}

		$this->ip_resolver->boot();

		// Local, read-only findings surface for BLT Connect (the Buoy fleet agent). One
		// add_filter, no I/O, and registered here rather than in a module so a disabled
		// module cannot take it away. BLT Connect is the only transport to Buoy.
		( new Blt_Secure_Buoy_Bridge( $this->whitelist ) )->boot();

		if ( Blt_Secure_Updater::should_load() ) {
			$this->updater = new Blt_Secure_Updater( $this->credentials );
			$this->updater->boot();
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only picks which classes to load; every handler verifies its own nonce.
		$action = isset( $_REQUEST['action'] ) && is_string( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';
		$page   = isset( $GLOBALS['pagenow'] ) ? (string) $GLOBALS['pagenow'] : '';
		if ( self::should_load_admin( is_admin(), wp_doing_ajax(), $action, $page ) ) {
			require_once BLT_SECURE_DIR . 'admin/class-admin.php';
			new Blt_Secure_Admin( $this );
		}

		add_action( 'init', array( $this, 'load_textdomain' ) );
	}

	/**
	 * Whether the admin UI class (and the Cloudflare classes it requires)
	 * should be loaded for this request.
	 *
	 * is_admin() is also true for anonymous admin-ajax.php / admin-post.php
	 * front-end requests, which would otherwise pay for the whole admin stack.
	 * AJAX is loaded only for this plugin's own actions; admin-post.php never
	 * (nothing here uses it). Every other wp-admin page still loads it, which
	 * keeps the Settings API sanitizer registered on options.php POSTs.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param bool   $is_admin   is_admin().
	 * @param bool   $doing_ajax wp_doing_ajax().
	 * @param string $action     Sanitized $_REQUEST['action'].
	 * @param string $pagenow    Current admin script.
	 * @return bool
	 */
	public static function should_load_admin( $is_admin, $doing_ajax, $action, $pagenow ) {
		if ( ! $is_admin ) {
			return false;
		}
		if ( $doing_ajax ) {
			return 0 === strpos( (string) $action, 'blt_secure_' );
		}
		return 'admin-post.php' !== $pagenow;
	}

	/**
	 * Load translations.
	 *
	 * @return void
	 */
	public function load_textdomain() {
		load_plugin_textdomain( 'blt-secure', false, dirname( plugin_basename( BLT_SECURE_FILE ) ) . '/languages' );
	}

	/**
	 * Activation: seed the settings option and schedule maintenance.
	 *
	 * @return void
	 */
	public static function activate() {
		if ( false === get_option( Blt_Secure_Options::OPTION, false ) ) {
			add_option( Blt_Secure_Options::OPTION, array( 'schema_version' => 1 ) );
		}
		if ( ! wp_next_scheduled( 'blt_secure_refresh_cf_ips' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'weekly', 'blt_secure_refresh_cf_ips' );
		}
		if ( ! wp_next_scheduled( Blt_Secure_Health::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', Blt_Secure_Health::CRON_HOOK );
		}
		if ( ! wp_next_scheduled( Blt_Secure_Scanner::CRON_HOOK ) ) {
			wp_schedule_event( time() + ( 2 * HOUR_IN_SECONDS ), 'daily', Blt_Secure_Scanner::CRON_HOOK );
		}
		if ( ! wp_next_scheduled( Blt_Secure_Malware::CRON_HOOK ) ) {
			wp_schedule_event( time() + ( 3 * HOUR_IN_SECONDS ), 'weekly', Blt_Secure_Malware::CRON_HOOK );
		}
		if ( ! wp_next_scheduled( Blt_Secure_Baseline::CRON_HOOK ) ) {
			wp_schedule_event( time() + ( 5 * HOUR_IN_SECONDS ), 'weekly', Blt_Secure_Baseline::CRON_HOOK );
		}
		if ( ! wp_next_scheduled( Blt_Secure_Ioc::CRON_HOOK ) ) {
			wp_schedule_event( time() + ( 4 * HOUR_IN_SECONDS ), 'daily', Blt_Secure_Ioc::CRON_HOOK );
		}
		if ( ! wp_next_scheduled( Blt_Secure_Timeline::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', Blt_Secure_Timeline::CRON_HOOK );
		}
		flush_rewrite_rules();
	}

	/**
	 * Deactivation: unschedule cron, flush. Cloudflare rules are deliberately
	 * left in place — removal is an explicit per-feature action in the UI.
	 *
	 * @return void
	 */
	public static function deactivate() {
		wp_clear_scheduled_hook( 'blt_secure_refresh_cf_ips' );
		wp_clear_scheduled_hook( Blt_Secure_Health::CRON_HOOK );
		wp_clear_scheduled_hook( Blt_Secure_Scanner::CRON_HOOK );
		wp_clear_scheduled_hook( Blt_Secure_Malware::CRON_HOOK );
		wp_clear_scheduled_hook( Blt_Secure_Baseline::CRON_HOOK );
		wp_clear_scheduled_hook( Blt_Secure_Ioc::CRON_HOOK );
		wp_clear_scheduled_hook( Blt_Secure_Timeline::CRON_HOOK );
		wp_clear_scheduled_hook( Blt_Secure_Fleet::CRON_HOOK );
		wp_clear_scheduled_hook( Blt_Secure_Fleet::PULL_HOOK );
		wp_clear_scheduled_hook( Blt_Secure_Fleet::PUSH_HOOK );
		wp_unschedule_hook( Blt_Secure_Alert_Channels::DELIVER_HOOK ); // Queued deliveries carry args, which wp_clear_scheduled_hook() would skip.
		flush_rewrite_rules();
	}
}
