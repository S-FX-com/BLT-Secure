<?php
/**
 * Fleet reporter: push a compact security-posture snapshot to the hosted
 * dashboard (Phase 3).
 *
 * Opt-in and off by default — nothing leaves the site until an operator
 * enrolls it (endpoint + per-site token). The snapshot carries only
 * scores, counts, statuses, and versions: never secrets, credentials, or
 * file contents. See dashboard/README.md for the ingest contract.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Assembles and transmits the posture snapshot on a schedule and on alert.
 */
class Blt_Secure_Fleet implements Blt_Secure_Module {

	const RESULTS_OPTION = 'blt_secure_fleet_state';
	const CRON_HOOK      = 'blt_secure_fleet_report';
	const TOKEN_KEY      = 'fleet_token';

	/**
	 * Minimum seconds between alert-triggered pushes.
	 */
	const PUSH_THROTTLE = 300;

	/**
	 * Settings.
	 *
	 * @var Blt_Secure_Options
	 */
	private $options;

	/**
	 * Credential store (per-site fleet token).
	 *
	 * @var Blt_Secure_Credential_Store
	 */
	private $credentials;

	/**
	 * Constructor.
	 *
	 * @param Blt_Secure_Options          $options     Settings access.
	 * @param Blt_Secure_Credential_Store $credentials Credential store.
	 */
	public function __construct( Blt_Secure_Options $options, Blt_Secure_Credential_Store $credentials ) {
		$this->options     = $options;
		$this->credentials = $credentials;
	}

	/**
	 * Module id.
	 *
	 * @return string
	 */
	public function id() {
		return 'fleet';
	}

	/**
	 * Defaults.
	 *
	 * @return array
	 */
	public function defaults() {
		return array(
			'enabled'  => false,
			'endpoint' => '',
			'schedule' => true,
		);
	}

	/**
	 * Enabled? Off by default; the operator opts in.
	 *
	 * @return bool
	 */
	public function is_enabled() {
		return (bool) $this->options->get( 'fleet', 'enabled', false );
	}

	/**
	 * Register hooks (only reached when enabled).
	 *
	 * @return void
	 */
	public function boot() {
		add_action( self::CRON_HOOK, array( $this, 'report' ) );
		add_action( 'blt_secure_alert', array( $this, 'maybe_push_alert' ), 20, 2 );

		if ( $this->options->get( 'fleet', 'schedule', true ) ) {
			add_action( 'admin_init', array( $this, 'ensure_scheduled' ) );
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
		$endpoint = isset( $input['endpoint'] ) ? esc_url_raw( trim( $input['endpoint'] ) ) : '';
		return array(
			'enabled'  => ! empty( $input['enabled'] ),
			'endpoint' => $endpoint,
			'schedule' => ! empty( $input['schedule'] ),
		);
	}

	/**
	 * Ensure the daily report is scheduled.
	 *
	 * @return void
	 */
	public function ensure_scheduled() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
		}
	}

	// ---------------------------------------------------------------------
	// Pure helpers (unit-tested).
	// ---------------------------------------------------------------------

	/**
	 * High-signal event types worth an immediate push and worth summarizing.
	 *
	 * @return string[]
	 */
	public static function high_signal_types() {
		return array( 'lockout', 'blocked_plugin', 'blocked_upload', 'malware_findings', 'core_integrity_issues', 'baseline_drift', 'activity_admin_granted' );
	}

	/**
	 * Sign a request body: hex HMAC-SHA256 of "{ts}.{body}" with the token.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param int    $ts     Unix timestamp.
	 * @param string $body   Raw JSON body.
	 * @param string $secret Site token.
	 * @return string
	 */
	public static function sign( $ts, $body, $secret ) {
		return hash_hmac( 'sha256', (int) $ts . '.' . (string) $body, (string) $secret );
	}

	/**
	 * Reduce raw stored payloads to the compact snapshot in the ingest
	 * contract. No secrets are read or emitted.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param array $in Raw inputs (see build_snapshot()).
	 * @return array
	 */
	public static function assemble_snapshot( array $in ) {
		$health = isset( $in['health']['summary'] ) && is_array( $in['health']['summary'] ) ? $in['health']['summary'] : array();
		$core   = isset( $in['core'] ) && is_array( $in['core'] ) ? $in['core'] : array();
		$mal    = isset( $in['malware'] ) && is_array( $in['malware'] ) ? $in['malware'] : array();
		$base   = isset( $in['baseline'] ) && is_array( $in['baseline'] ) ? $in['baseline'] : array();
		$ioc    = isset( $in['ioc'] ) && is_array( $in['ioc'] ) ? $in['ioc'] : array();
		$zone   = isset( $in['cf_zone'] ) && is_array( $in['cf_zone'] ) ? $in['cf_zone'] : array();

		return array(
			'schema'      => 1,
			'site'        => isset( $in['site'] ) ? (string) $in['site'] : '',
			'name'        => isset( $in['name'] ) ? (string) $in['name'] : '',
			'reported_at' => isset( $in['reported_at'] ) ? (int) $in['reported_at'] : 0,
			'versions'    => isset( $in['versions'] ) && is_array( $in['versions'] ) ? $in['versions'] : array(),
			'health'      => array(
				'score' => isset( $health['score'] ) ? (int) $health['score'] : null,
				'pass'  => isset( $health['pass'] ) ? (int) $health['pass'] : 0,
				'warn'  => isset( $health['warn'] ) ? (int) $health['warn'] : 0,
				'fail'  => isset( $health['fail'] ) ? (int) $health['fail'] : 0,
			),
			'core'        => array(
				'status' => self::scan_status( $core, 'issues' ),
				'issues' => isset( $core['issues'] ) ? count( (array) $core['issues'] ) : 0,
			),
			'malware'     => array(
				'status'   => self::scan_status( $mal, 'findings' ),
				'findings' => isset( $mal['findings'] ) ? count( (array) $mal['findings'] ) : 0,
			),
			'baseline'    => array(
				'status'   => self::scan_status( $base, 'findings' ),
				'findings' => isset( $base['findings'] ) ? count( (array) $base['findings'] ) : 0,
			),
			'ioc'         => array(
				'status' => isset( $ioc['status'] ) ? (string) $ioc['status'] : 'none',
				'count'  => isset( $ioc['count'] ) ? (int) $ioc['count'] : 0,
			),
			'cloudflare'  => array(
				'connected' => ! empty( $zone['zone_id'] ),
				'plan'      => isset( $zone['plan'] ) ? (string) $zone['plan'] : '',
			),
			'events'      => self::count_events( isset( $in['events'] ) && is_array( $in['events'] ) ? $in['events'] : array() ),
		);
	}

	/**
	 * Derive a scan section's status from its stored payload.
	 *
	 * @param array  $payload Scan payload.
	 * @param string $key     Findings/issues key.
	 * @return string 'none' | 'error' | 'ok' | 'issues'.
	 */
	private static function scan_status( array $payload, $key ) {
		if ( empty( $payload ) ) {
			return 'none';
		}
		if ( ! empty( $payload['error'] ) ) {
			return 'error';
		}
		return ! empty( $payload[ $key ] ) ? 'issues' : 'ok';
	}

	/**
	 * Count recent events by high-signal type.
	 *
	 * @param array[] $events Alerting ring-buffer events.
	 * @return array<string,int>
	 */
	private static function count_events( array $events ) {
		$wanted = array_fill_keys( self::high_signal_types(), 0 );
		foreach ( $events as $event ) {
			$type = isset( $event['type'] ) ? $event['type'] : '';
			if ( isset( $wanted[ $type ] ) ) {
				++$wanted[ $type ];
			}
		}
		return array_filter( $wanted );
	}

	// ---------------------------------------------------------------------
	// Reporting.
	// ---------------------------------------------------------------------

	/**
	 * Gather the raw inputs and assemble the snapshot.
	 *
	 * @return array
	 */
	public function build_snapshot() {
		$zone = get_option( 'blt_secure_cf_state', array() );
		$zone = is_array( $zone ) && isset( $zone['zone'] ) && is_array( $zone['zone'] ) ? $zone['zone'] : array();

		return self::assemble_snapshot(
			array(
				'site'        => (string) home_url(),
				'name'        => (string) get_bloginfo( 'name' ),
				'reported_at' => time(),
				'versions'    => array(
					'plugin' => BLT_SECURE_VERSION,
					'wp'     => (string) get_bloginfo( 'version' ),
					'php'    => PHP_VERSION,
				),
				'health'      => get_option( 'blt_secure_health_results', array() ),
				'core'        => get_option( 'blt_secure_core_scan_results', array() ),
				'malware'     => get_option( 'blt_secure_malware_results', array() ),
				'baseline'    => get_option( 'blt_secure_baseline_results', array() ),
				'ioc'         => get_option( 'blt_secure_ioc_state', array() ),
				'cf_zone'     => $zone,
				'events'      => get_option( 'blt_secure_events', array() ),
			)
		);
	}

	/**
	 * Push the snapshot to the dashboard.
	 *
	 * @return array Stored status.
	 */
	public function report() {
		$endpoint = rtrim( (string) $this->options->get( 'fleet', 'endpoint', '' ), '/' );
		$token    = $this->credentials->get( self::TOKEN_KEY );

		if ( '' === $endpoint || ! is_string( $token ) || '' === $token ) {
			return $this->store( 'not_configured', '' );
		}

		$snapshot = $this->build_snapshot();
		$body     = (string) wp_json_encode( $snapshot );
		$ts       = time();

		$response = wp_remote_post(
			$endpoint . '/v1/snapshot',
			array(
				'timeout' => 15,
				'headers' => array(
					'Authorization'   => 'Bearer ' . $token,
					'Content-Type'    => 'application/json',
					'X-BLT-Timestamp' => (string) $ts,
					'X-BLT-Signature' => self::sign( $ts, $body, $token ),
				),
				'body'    => $body,
			)
		);

		if ( is_wp_error( $response ) ) {
			return $this->store( 'error', $response->get_error_message() );
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( $code < 200 || $code >= 300 ) {
			return $this->store(
				'error',
				sprintf(
					/* translators: %d: HTTP status code */
					__( 'The dashboard rejected the report (HTTP %d).', 'blt-secure' ),
					$code
				)
			);
		}

		return $this->store( 'ok', '' );
	}

	/**
	 * Push immediately (throttled) when a high-signal event fires.
	 *
	 * @param string $type    Event type.
	 * @param array  $context Event context (unused).
	 * @return void
	 */
	public function maybe_push_alert( $type, $context = array() ) {
		unset( $context );
		if ( ! in_array( $type, self::high_signal_types(), true ) ) {
			return;
		}
		if ( get_transient( 'blt_sec_fleet_push' ) ) {
			return;
		}
		set_transient( 'blt_sec_fleet_push', 1, self::PUSH_THROTTLE );
		$this->report();
	}

	/**
	 * Persist and return the report status.
	 *
	 * @param string $status Status slug.
	 * @param string $error  Error message.
	 * @return array
	 */
	private function store( $status, $error ) {
		$payload = array(
			'time'   => time(),
			'status' => $status,
			'error'  => $error,
		);
		update_option( self::RESULTS_OPTION, $payload, false );
		return $payload;
	}

	/**
	 * The last report status, or null.
	 *
	 * @return array|null
	 */
	public function latest() {
		$payload = get_option( self::RESULTS_OPTION, null );
		return is_array( $payload ) ? $payload : null;
	}
}
