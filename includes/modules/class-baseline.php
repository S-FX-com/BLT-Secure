<?php
/**
 * Baseline module: plugin/theme file-integrity monitoring.
 *
 * Records a hash baseline of every installed plugin and theme (keyed by
 * slug + version) and, on a weekly scan, reports files that changed without
 * a version bump — the signature of a tampered or backdoored extension. A
 * legitimate update changes the version, which re-baselines cleanly.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Enumerates extensions, maintains baselines, and reports drift.
 */
class Blt_Secure_Baseline implements Blt_Secure_Module {

	const RESULTS_OPTION  = 'blt_secure_baseline_results';
	const BASELINE_OPTION = 'blt_secure_baselines';
	const CRON_HOOK       = 'blt_secure_baseline_scan';
	const AJAX_RUN        = 'blt_secure_baseline_scan_run';

	const MAX_FINDINGS = 100;

	/**
	 * Settings.
	 *
	 * @var Blt_Secure_Options
	 */
	private $options;

	/**
	 * Alerting sink.
	 *
	 * @var Blt_Secure_Alerting|null
	 */
	private $alerting;

	/**
	 * Finding whitelist.
	 *
	 * @var Blt_Secure_Scan_Whitelist
	 */
	private $whitelist;

	/**
	 * Constructor.
	 *
	 * @param Blt_Secure_Options             $options   Settings access.
	 * @param Blt_Secure_Alerting|null       $alerting  Alerting sink.
	 * @param Blt_Secure_Scan_Whitelist|null $whitelist Finding whitelist.
	 */
	public function __construct( Blt_Secure_Options $options, $alerting = null, $whitelist = null ) {
		$this->options   = $options;
		$this->alerting  = $alerting;
		$this->whitelist = $whitelist instanceof Blt_Secure_Scan_Whitelist ? $whitelist : new Blt_Secure_Scan_Whitelist();
	}

	/**
	 * The shared finding whitelist.
	 *
	 * @return Blt_Secure_Scan_Whitelist
	 */
	public function whitelist() {
		return $this->whitelist;
	}

	/**
	 * Module id.
	 *
	 * @return string
	 */
	public function id() {
		return 'baseline';
	}

	/**
	 * Defaults.
	 *
	 * @return array
	 */
	public function defaults() {
		return array(
			'enabled'  => true,
			'schedule' => true,
		);
	}

	/**
	 * Enabled?
	 *
	 * @return bool
	 */
	public function is_enabled() {
		return (bool) $this->options->get( 'baseline', 'enabled', true );
	}

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function boot() {
		add_action( self::CRON_HOOK, array( $this, 'run_scan' ) );
		add_filter( 'blt_secure_health_checks', array( $this, 'register_health_check' ) );

		if ( $this->options->get( 'baseline', 'schedule', true ) ) {
			add_action( 'admin_init', array( $this, 'ensure_scheduled' ) );
		}

		if ( is_admin() ) {
			add_action( 'wp_ajax_' . self::AJAX_RUN, array( $this, 'ajax_run' ) );
		}
	}

	/**
	 * Sanitize section.
	 *
	 * @param array $input   Raw input.
	 * @param array $current Current values.
	 * @return array
	 */
	public function sanitize( $input, $current ) {
		return array(
			'enabled'  => ! empty( $input['enabled'] ),
			'schedule' => ! empty( $input['schedule'] ),
		);
	}

	/**
	 * Ensure the weekly scan is scheduled.
	 *
	 * @return void
	 */
	public function ensure_scheduled() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + ( 5 * HOUR_IN_SECONDS ), 'weekly', self::CRON_HOOK );
		}
	}

	/**
	 * Enumerate installed plugins and themes as baseline targets.
	 *
	 * @return array[] Each: [ key, label, dir, version, single (bool) ].
	 */
	private function targets() {
		foreach ( array( 'plugin.php', 'theme.php' ) as $file ) {
			$path = ABSPATH . 'wp-admin/includes/' . $file;
			if ( is_readable( $path ) ) {
				require_once $path;
			}
		}

		$targets = array();

		if ( function_exists( 'get_plugins' ) ) {
			$plugin_dir = defined( 'WP_PLUGIN_DIR' ) ? WP_PLUGIN_DIR : WP_CONTENT_DIR . '/plugins';
			foreach ( get_plugins() as $file => $data ) {
				$dirname   = dirname( $file );
				$single    = ( '.' === $dirname );
				$targets[] = array(
					'key'     => 'plugin/' . ( $single ? $file : $dirname ),
					'label'   => isset( $data['Name'] ) ? $data['Name'] : $file,
					'dir'     => $single ? $plugin_dir . '/' . $file : $plugin_dir . '/' . $dirname,
					'version' => isset( $data['Version'] ) ? (string) $data['Version'] : '',
					'single'  => $single,
				);
			}
		}

		if ( function_exists( 'wp_get_themes' ) ) {
			foreach ( wp_get_themes() as $slug => $theme ) {
				$targets[] = array(
					'key'     => 'theme/' . $slug,
					'label'   => $theme->get( 'Name' ) ? $theme->get( 'Name' ) : $slug,
					'dir'     => $theme->get_stylesheet_directory(),
					'version' => (string) $theme->get( 'Version' ),
					'single'  => false,
				);
			}
		}

		return $targets;
	}

	/**
	 * Hash a target (directory tree, or a single-file plugin).
	 *
	 * @param Blt_Secure_Baseline_Scanner $engine Engine.
	 * @param array                       $target Target descriptor.
	 * @return array|null path => md5, or null when unhashable/too large.
	 */
	private function hash_target( Blt_Secure_Baseline_Scanner $engine, array $target ) {
		if ( empty( $target['single'] ) ) {
			return $engine->hash_dir( $target['dir'] );
		}
		if ( ! is_readable( $target['dir'] ) ) {
			return null;
		}
		$md5 = md5_file( $target['dir'] );
		return false === $md5 ? null : array( basename( $target['dir'] ) => $md5 );
	}

	/**
	 * Run the baseline scan: re-baseline changed versions, report drift.
	 *
	 * @return array Stored results payload.
	 */
	public function run_scan() {
		require_once BLT_SECURE_DIR . 'includes/scanner/class-baseline-scanner.php';

		$engine    = new Blt_Secure_Baseline_Scanner();
		$targets   = $this->targets();
		$baselines = get_option( self::BASELINE_OPTION, array() );
		$baselines = is_array( $baselines ) ? $baselines : array();

		$next     = array();
		$findings = array();

		foreach ( $targets as $target ) {
			$hashes = $this->hash_target( $engine, $target );
			if ( null === $hashes ) {
				// Keep any prior baseline untouched for trees we can't hash.
				if ( isset( $baselines[ $target['key'] ] ) ) {
					$next[ $target['key'] ] = $baselines[ $target['key'] ];
				}
				continue;
			}

			$stored = isset( $baselines[ $target['key'] ] ) ? $baselines[ $target['key'] ] : null;

			// First sight or a legitimate version change → (re)baseline.
			if ( null === $stored || ! isset( $stored['version'] ) || $stored['version'] !== $target['version'] ) {
				$next[ $target['key'] ] = array(
					'version' => $target['version'],
					'hashes'  => $hashes,
				);
				continue;
			}

			// Same version: any change is unexpected.
			$diff                   = Blt_Secure_Baseline_Scanner::diff( isset( $stored['hashes'] ) ? $stored['hashes'] : array(), $hashes );
			$next[ $target['key'] ] = $stored; // Keep baseline so drift keeps surfacing.

			if ( Blt_Secure_Baseline_Scanner::has_changes( $diff ) && count( $findings ) < self::MAX_FINDINGS ) {
				$changed    = array_merge( $diff['modified'], $diff['added'], $diff['removed'] );
				$findings[] = array(
					'key'         => $target['key'],
					'label'       => $target['label'],
					'version'     => $target['version'],
					'added'       => count( $diff['added'] ),
					'modified'    => count( $diff['modified'] ),
					'removed'     => count( $diff['removed'] ),
					'files'       => array_slice( $changed, 0, 10 ),
					// Content-sensitive over the FULL changed set so a later edit re-flags.
					'fingerprint' => Blt_Secure_Baseline_Scanner::drift_fingerprint( $target['key'], $target['version'], $changed, $hashes ),
				);
			}
		}

		update_option( self::BASELINE_OPTION, $next, false );

		$payload = array(
			'time'      => time(),
			'targets'   => count( $targets ),
			'findings'  => $findings,
			'truncated' => count( $findings ) >= self::MAX_FINDINGS,
		);
		update_option( self::RESULTS_OPTION, $payload, false );

		$active = $this->whitelist->active( $findings );
		if ( $this->alerting && ! empty( $active ) ) {
			$this->alerting->notify( 'baseline_drift', array( 'count' => count( $active ) ) );
		}

		return $payload;
	}

	/**
	 * The most recent stored results, or null.
	 *
	 * @return array|null
	 */
	public function latest() {
		$payload = get_option( self::RESULTS_OPTION, null );
		return is_array( $payload ) ? $payload : null;
	}

	/**
	 * Contribute a summary check to the Health Check catalogue.
	 *
	 * @param array[] $checks Existing checks.
	 * @return array[]
	 */
	public function register_health_check( $checks ) {
		$checks[] = array(
			'id'       => 'plugin_theme_integrity',
			'label'    => __( 'Installed plugins and themes match their baseline', 'blt-secure' ),
			'category' => 'files',
			'callback' => array( $this, 'health_check' ),
		);
		return $checks;
	}

	/**
	 * Health-check callback.
	 *
	 * @return array
	 */
	public function health_check() {
		$payload = $this->latest();
		if ( null === $payload ) {
			return array(
				'status'  => Blt_Secure_Health_Result::SKIP,
				'message' => __( 'No baseline scan has run yet — open the Scanner tab and run one.', 'blt-secure' ),
			);
		}

		$count = isset( $payload['findings'] ) ? count( $this->whitelist->active( $payload['findings'] ) ) : 0;
		if ( 0 === $count ) {
			return array(
				'status'  => Blt_Secure_Health_Result::PASS,
				'message' => sprintf(
					/* translators: %d: number of extensions */
					__( 'All %d installed plugins/themes match their recorded baseline.', 'blt-secure' ),
					isset( $payload['targets'] ) ? (int) $payload['targets'] : 0
				),
			);
		}

		return array(
			'status'  => Blt_Secure_Health_Result::FAIL,
			'message' => sprintf(
				/* translators: %d: number of extensions */
				_n( '%d plugin/theme changed without a version update.', '%d plugins/themes changed without a version update.', $count, 'blt-secure' ),
				$count
			),
			'details' => __( 'Files changing without a version bump can mean a compromised extension. Review them on the Scanner tab; reinstall the plugin/theme from a trusted source if you did not make the change.', 'blt-secure' ),
		);
	}

	/**
	 * AJAX: run a scan now.
	 *
	 * @return void
	 */
	public function ajax_run() {
		check_ajax_referer( 'blt_secure_cf' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'blt-secure' ) ), 403 );
		}

		$payload = $this->run_scan();
		wp_send_json_success( $payload );
	}
}
