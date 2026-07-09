<?php
/**
 * Timeline module: unified local + Cloudflare-edge security event view.
 *
 * Polls the Cloudflare GraphQL analytics API for recent firewall events on
 * WP-Cron, stores them in a non-autoloaded ring buffer, and merges them with
 * the local security-event log for a single chronological timeline. No-ops
 * quietly when no CF token or zone is configured.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Cloudflare firewall-event poller + unified timeline provider.
 */
class Blt_Secure_Timeline implements Blt_Secure_Module {

	const RESULTS_OPTION = 'blt_secure_cf_events';
	const CRON_HOOK      = 'blt_secure_timeline_poll';
	const AJAX_RUN       = 'blt_secure_timeline_poll_run';

	const LOOKBACK_HOURS = 24;
	const MAX_EVENTS     = 200;

	/**
	 * Settings.
	 *
	 * @var Blt_Secure_Options
	 */
	private $options;

	/**
	 * Credential store (Cloudflare token).
	 *
	 * @var Blt_Secure_Credential_Store
	 */
	private $credentials;

	/**
	 * Local event source.
	 *
	 * @var Blt_Secure_Alerting
	 */
	private $alerting;

	/**
	 * Constructor.
	 *
	 * @param Blt_Secure_Options          $options     Settings access.
	 * @param Blt_Secure_Credential_Store $credentials Credential store.
	 * @param Blt_Secure_Alerting         $alerting    Local event source.
	 */
	public function __construct( Blt_Secure_Options $options, Blt_Secure_Credential_Store $credentials, Blt_Secure_Alerting $alerting ) {
		$this->options     = $options;
		$this->credentials = $credentials;
		$this->alerting    = $alerting;
	}

	/**
	 * Module id.
	 *
	 * @return string
	 */
	public function id() {
		return 'timeline';
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
		return (bool) $this->options->get( 'timeline', 'enabled', true );
	}

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function boot() {
		add_action( self::CRON_HOOK, array( $this, 'poll' ) );

		if ( $this->options->get( 'timeline', 'schedule', true ) ) {
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
	 * Ensure the hourly poll is scheduled.
	 *
	 * @return void
	 */
	public function ensure_scheduled() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', self::CRON_HOOK );
		}
	}

	/**
	 * Poll Cloudflare for recent firewall events and store them.
	 *
	 * @return array Stored payload (time, status, error, events).
	 */
	public function poll() {
		$token = $this->credentials->get( 'cf_token' );
		if ( ! is_string( $token ) || '' === $token ) {
			return $this->store( 'no_token', array(), '' );
		}

		require_once BLT_SECURE_DIR . 'includes/cloudflare/class-cloudflare-api.php';
		require_once BLT_SECURE_DIR . 'includes/cloudflare/class-cloudflare-state.php';
		require_once BLT_SECURE_DIR . 'includes/cloudflare/class-cf-events.php';

		$zone = ( new Blt_Secure_Cloudflare_State() )->zone();
		if ( empty( $zone['zone_id'] ) ) {
			return $this->store( 'no_zone', array(), '' );
		}

		$api    = new Blt_Secure_Cloudflare_Api( $token );
		$since  = time() - ( self::LOOKBACK_HOURS * HOUR_IN_SECONDS );
		$result = $api->graphql(
			Blt_Secure_Cf_Events::query(),
			Blt_Secure_Cf_Events::variables( $zone['zone_id'], $since, self::MAX_EVENTS )
		);

		if ( is_wp_error( $result ) ) {
			$message = $result->get_error_message();
			if ( 'blt_cf_scope' === $result->get_error_code() ) {
				$message .= ' ' . __( 'Add the "Zone → Analytics: Read" permission to your Cloudflare token, then retry.', 'blt-secure' );
			}
			return $this->store( 'error', array(), $message );
		}

		$events = Blt_Secure_Cf_Events::parse( $result );
		return $this->store( 'ok', array_slice( $events, 0, self::MAX_EVENTS ), '' );
	}

	/**
	 * Persist and return the poll result.
	 *
	 * @param string  $status Status slug.
	 * @param array[] $events Cloudflare event rows.
	 * @param string  $error  Error message.
	 * @return array
	 */
	private function store( $status, array $events, $error ) {
		$payload = array(
			'time'   => time(),
			'status' => $status,
			'error'  => $error,
			'events' => $events,
		);
		update_option( self::RESULTS_OPTION, $payload, false );
		return $payload;
	}

	/**
	 * The stored poll payload, or null.
	 *
	 * @return array|null
	 */
	public function latest() {
		$payload = get_option( self::RESULTS_OPTION, null );
		return is_array( $payload ) ? $payload : null;
	}

	/**
	 * The merged, newest-first timeline (local events + stored CF events).
	 *
	 * @param int $limit Max rows.
	 * @return array[]
	 */
	public function timeline( $limit = 100 ) {
		require_once BLT_SECURE_DIR . 'includes/cloudflare/class-cf-events.php';

		$payload = $this->latest();
		$cf      = is_array( $payload ) && ! empty( $payload['events'] ) ? $payload['events'] : array();
		$local   = $this->alerting->recent( $limit );

		return Blt_Secure_Cf_Events::merge( $local, $cf, $limit );
	}

	/**
	 * AJAX: poll now and return the fresh timeline.
	 *
	 * @return void
	 */
	public function ajax_run() {
		check_ajax_referer( 'blt_secure_cf' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'blt-secure' ) ), 403 );
		}

		$payload = $this->poll();
		if ( 'error' === $payload['status'] ) {
			wp_send_json_error( array( 'message' => $payload['error'] ) );
		}
		wp_send_json_success( $payload );
	}
}
