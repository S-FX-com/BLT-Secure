<?php
/**
 * Scanner module: scheduled + on-demand core file integrity scanning.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Runs Blt_Secure_Core_Scanner on WP-Cron (daily) and on demand, stores the
 * latest result in a non-autoloaded option, and contributes a summary check
 * to the Health Check score via the blt_secure_health_checks filter.
 */
class Blt_Secure_Scanner implements Blt_Secure_Module {

	const RESULTS_OPTION = 'blt_secure_core_scan_results';
	const CRON_HOOK      = 'blt_secure_core_scan';
	const AJAX_RUN       = 'blt_secure_core_scan_run';

	/**
	 * Settings.
	 *
	 * @var Blt_Secure_Options
	 */
	private $options;

	/**
	 * Optional alerting sink.
	 *
	 * @var Blt_Secure_Alerting|null
	 */
	private $alerting;

	/**
	 * Constructor.
	 *
	 * @param Blt_Secure_Options       $options  Settings access.
	 * @param Blt_Secure_Alerting|null $alerting Alerting sink.
	 */
	public function __construct( Blt_Secure_Options $options, $alerting = null ) {
		$this->options  = $options;
		$this->alerting = $alerting;
	}

	/**
	 * Module id.
	 *
	 * @return string
	 */
	public function id() {
		return 'scanner';
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
		return (bool) $this->options->get( 'scanner', 'enabled', true );
	}

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function boot() {
		add_action( self::CRON_HOOK, array( $this, 'run_scan' ) );
		add_filter( 'blt_secure_health_checks', array( $this, 'register_health_check' ) );

		if ( $this->options->get( 'scanner', 'schedule', true ) ) {
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
	 * Ensure the scan is scheduled.
	 *
	 * @return void
	 */
	public function ensure_scheduled() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + ( 2 * HOUR_IN_SECONDS ), 'daily', self::CRON_HOOK );
		}
	}

	/**
	 * Run a scan and persist the result.
	 *
	 * @return array Stored payload.
	 */
	public function run_scan() {
		require_once BLT_SECURE_DIR . 'includes/scanner/class-core-scanner.php';

		$scanner = new Blt_Secure_Core_Scanner();
		$payload = $scanner->run();

		update_option( self::RESULTS_OPTION, $payload, false );

		if ( $this->alerting && empty( $payload['error'] ) && ! empty( $payload['issues'] ) ) {
			$this->alerting->notify(
				'core_integrity_issues',
				array(
					'count'   => count( $payload['issues'] ),
					'version' => $payload['version'],
				)
			);
		}

		/**
		 * Fires after a core integrity scan completes.
		 *
		 * @param array $payload Stored scan payload.
		 */
		do_action( 'blt_secure_core_scanned', $payload );

		return $payload;
	}

	/**
	 * The most recent stored scan, or null.
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
			'id'       => 'core_integrity',
			'label'    => __( 'Core files match the official checksums', 'blt-secure' ),
			'category' => 'files',
			'callback' => array( $this, 'health_check' ),
		);
		return $checks;
	}

	/**
	 * Health-check callback: translate the last scan into a pass/warn/fail.
	 *
	 * @return array
	 */
	public function health_check() {
		$payload = $this->latest();

		if ( null === $payload ) {
			return array(
				'status'  => Blt_Secure_Health_Result::SKIP,
				'message' => __( 'No core scan has run yet — open the Scanner tab and run one.', 'blt-secure' ),
			);
		}
		if ( ! empty( $payload['error'] ) ) {
			return array(
				'status'  => Blt_Secure_Health_Result::SKIP,
				'message' => $payload['error'],
			);
		}

		$count = isset( $payload['issues'] ) ? count( $payload['issues'] ) : 0;
		if ( 0 === $count ) {
			return array(
				'status'  => Blt_Secure_Health_Result::PASS,
				'message' => sprintf(
					/* translators: %d: number of files verified */
					__( 'All %d core files match the official WordPress checksums.', 'blt-secure' ),
					isset( $payload['checked'] ) ? (int) $payload['checked'] : 0
				),
			);
		}

		return array(
			'status'  => Blt_Secure_Health_Result::FAIL,
			'message' => sprintf(
				/* translators: %d: number of files */
				_n( '%d core file differs from the official checksums.', '%d core files differ from the official checksums.', $count, 'blt-secure' ),
				$count
			),
			'details' => __( 'Modified or unexpected core files can indicate a compromise. Review them on the Scanner tab; reinstalling WordPress core from Dashboard → Updates restores the originals.', 'blt-secure' ),
		);
	}

	/**
	 * AJAX: run a scan now and return the payload.
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
