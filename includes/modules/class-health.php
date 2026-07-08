<?php
/**
 * Health Check module: on-demand and scheduled security self-assessment.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Runs the health-check catalogue on WP-Cron (daily) and on demand from the
 * admin, storing the latest results in a non-autoloaded option. The scan is
 * the only place that touches the network/filesystem for these checks —
 * front-end page loads never pay for it.
 */
class Blt_Secure_Health implements Blt_Secure_Module {

	const RESULTS_OPTION = 'blt_secure_health_results';
	const CRON_HOOK      = 'blt_secure_health_scan';
	const AJAX_RUN       = 'blt_secure_health_run';

	/**
	 * Settings.
	 *
	 * @var Blt_Secure_Options
	 */
	private $options;

	/**
	 * Constructor.
	 *
	 * @param Blt_Secure_Options $options Settings access.
	 */
	public function __construct( Blt_Secure_Options $options ) {
		$this->options = $options;
	}

	/**
	 * Module id.
	 *
	 * @return string
	 */
	public function id() {
		return 'health';
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
		return (bool) $this->options->get( 'health', 'enabled', true );
	}

	/**
	 * Register hooks: the cron worker plus the admin-only run action.
	 *
	 * @return void
	 */
	public function boot() {
		add_action( self::CRON_HOOK, array( $this, 'run_scan' ) );

		if ( $this->options->get( 'health', 'schedule', true ) ) {
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
	 * Ensure the daily scan is scheduled.
	 *
	 * @return void
	 */
	public function ensure_scheduled() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
		}
	}

	/**
	 * Build a runner over the current catalogue.
	 *
	 * @return Blt_Secure_Health_Runner
	 */
	private function runner() {
		return new Blt_Secure_Health_Runner( Blt_Secure_Health_Checks::all() );
	}

	/**
	 * Run every check and persist the outcome.
	 *
	 * @return array Stored payload (time, summary, results).
	 */
	public function run_scan() {
		$context = new Blt_Secure_Health_Context( $this->options );
		$results = $this->runner()->run( $context );

		$payload = array(
			'time'    => time(),
			'summary' => Blt_Secure_Health_Runner::summarize( $results ),
			'results' => array_map(
				static function ( $result ) {
					return $result->to_array();
				},
				$results
			),
		);

		update_option( self::RESULTS_OPTION, $payload, false );

		/**
		 * Fires after a health scan completes (e.g. to raise an alert when
		 * the score drops or a new failure appears).
		 *
		 * @param array $payload Stored scan payload.
		 */
		do_action( 'blt_secure_health_scanned', $payload );

		return $payload;
	}

	/**
	 * The most recent stored scan, or null if none has run yet.
	 *
	 * @return array|null
	 */
	public function latest() {
		$payload = get_option( self::RESULTS_OPTION, null );
		return is_array( $payload ) ? $payload : null;
	}

	/**
	 * AJAX: run a scan now and return the fresh payload.
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
