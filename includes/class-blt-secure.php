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

		$alerting = new Blt_Secure_Alerting( $this->options );

		$modules = array(
			$alerting,
			new Blt_Secure_Headers( $this->options ),
			new Blt_Secure_Privacy( $this->options ),
			new Blt_Secure_Xmlrpc( $this->options ),
			new Blt_Secure_File_Guard( $this->options, $alerting ),
			new Blt_Secure_Login_Hardening( $this->options, $this->ip_resolver, $alerting ),
			new Blt_Secure_Two_Factor( $this->options, new Blt_Secure_Crypto(), $alerting ),
			new Blt_Secure_Health( $this->options ),
			new Blt_Secure_Scanner( $this->options, $alerting ),
			new Blt_Secure_Malware( $this->options, $alerting ),
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

		if ( Blt_Secure_Updater::should_load() ) {
			$this->updater = new Blt_Secure_Updater( $this->credentials );
			$this->updater->boot();
		}

		if ( is_admin() ) {
			require_once BLT_SECURE_DIR . 'admin/class-admin.php';
			new Blt_Secure_Admin( $this );
		}

		add_action( 'init', array( $this, 'load_textdomain' ) );
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
		flush_rewrite_rules();
	}
}
