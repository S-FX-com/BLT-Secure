<?php
/**
 * Fleet reporter: push a compact security-posture snapshot to the hosted
 * dashboard (Phase 3).
 *
 * LEGACY — superseded by Buoy / BLT Connect (Ed25519 envelopes). This channel
 * is kept working but is frozen: fix defects, do not extend it.
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
	const PULL_HOOK      = 'blt_secure_fleet_pull';
	const PUSH_HOOK      = 'blt_secure_fleet_push';
	const TOKEN_KEY      = 'fleet_token';

	/**
	 * Highest command id this site has executed (autoload no). Commands with
	 * an id at or below it are never run again, which defeats replay of an
	 * old command list by a spoofed or compromised endpoint.
	 */
	const LAST_COMMAND_OPTION = 'blt_secure_fleet_cmd';

	/**
	 * Ingest contract version. 2 = https-only, signed /v1/commands response,
	 * events are counts since the previous successful report.
	 */
	const SCHEMA = 2;

	/**
	 * Most commands executed per pull (the rest wait for the next hourly pull).
	 */
	const MAX_COMMANDS = 5;

	/**
	 * Domain-separation label for the response-signing key.
	 */
	const RESPONSE_KEY_LABEL = 'blt-secure-fleet/v2/response-key';

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
	 * Alerting sink for command-execution audit entries.
	 *
	 * @var Blt_Secure_Alerting|null
	 */
	private $alerting;

	/**
	 * Finding whitelist (so the snapshot mirrors the local active counts).
	 *
	 * @var Blt_Secure_Scan_Whitelist
	 */
	private $whitelist;

	/**
	 * Constructor.
	 *
	 * @param Blt_Secure_Options          $options     Settings access.
	 * @param Blt_Secure_Credential_Store $credentials Credential store.
	 * @param Blt_Secure_Alerting|null    $alerting    Alerting sink (optional).
	 * @param Blt_Secure_Scan_Whitelist|null $whitelist Finding whitelist (optional).
	 */
	public function __construct( Blt_Secure_Options $options, Blt_Secure_Credential_Store $credentials, $alerting = null, $whitelist = null ) {
		$this->options     = $options;
		$this->credentials = $credentials;
		$this->alerting    = $alerting;
		$this->whitelist   = $whitelist instanceof Blt_Secure_Scan_Whitelist ? $whitelist : new Blt_Secure_Scan_Whitelist();
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
			'commands' => false,
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
		add_action( self::PUSH_HOOK, array( $this, 'report' ) );
		add_action( 'blt_secure_alert', array( $this, 'maybe_push_alert' ), 20, 2 );

		if ( $this->options->get( 'fleet', 'commands', false ) ) {
			add_action( self::PULL_HOOK, array( $this, 'pull' ) );
		}

		/*
		 * The stored 'schedule' flag is intentionally NOT consulted: it has no
		 * form field, and before this fix every Advanced-tab save wrote it as
		 * false, so a stored false cannot be told apart from a bug victim.
		 * Reporting is already opt-in (the module only boots when enabled);
		 * a developer who really wants no cron can filter this off.
		 */
		if ( apply_filters( 'blt_secure_fleet_schedule', true ) ) {
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
		$raw      = isset( $input['endpoint'] ) && is_string( $input['endpoint'] ) ? trim( $input['endpoint'] ) : '';
		$endpoint = self::normalize_endpoint( $raw );
		if ( '' !== $endpoint && function_exists( 'esc_url_raw' ) ) {
			$endpoint = esc_url_raw( $endpoint, array( 'https' ) );
		}
		if ( '' !== $raw && '' === $endpoint && function_exists( 'add_settings_error' ) ) {
			add_settings_error(
				'blt_secure_settings',
				'blt_secure_fleet_endpoint',
				__( 'The fleet dashboard endpoint must be an https:// URL; it was not saved.', 'blt-secure' )
			);
		}

		// 'schedule' has no field on the settings form: an absent key means
		// "not shown", never "off", so keep the stored value (default on).
		$schedule = true;
		if ( isset( $input['schedule'] ) ) {
			$schedule = ! empty( $input['schedule'] );
		} elseif ( is_array( $current ) && array_key_exists( 'schedule', $current ) ) {
			$schedule = (bool) $current['schedule'];
		}

		return array(
			'enabled'  => ! empty( $input['enabled'] ),
			'endpoint' => $endpoint,
			'schedule' => $schedule,
			'commands' => ! empty( $input['commands'] ),
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

		if ( $this->options->get( 'fleet', 'commands', false ) ) {
			if ( ! wp_next_scheduled( self::PULL_HOOK ) ) {
				wp_schedule_event( time() + ( 15 * MINUTE_IN_SECONDS ), 'hourly', self::PULL_HOOK );
			}
		} elseif ( wp_next_scheduled( self::PULL_HOOK ) ) {
			wp_clear_scheduled_hook( self::PULL_HOOK );
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
		// Same list the alert channels notify on (one source of truth), minus
		// the fleet's own audit event, which must not trigger a push.
		return array_values( array_diff( Blt_Secure_Alert_Channels::default_types(), array( 'fleet_command' ) ) );
	}

	/**
	 * Normalize the dashboard endpoint: https only, a host, no credentials,
	 * query or fragment, no trailing slash. '' when unusable.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string $url Raw endpoint.
	 * @return string
	 */
	public static function normalize_endpoint( $url ) {
		$parts = wp_parse_url( trim( (string) $url ) );
		if ( ! is_array( $parts ) || empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
			return '';
		}
		if ( 'https' !== strtolower( $parts['scheme'] ) ) {
			return '';
		}
		if ( isset( $parts['user'] ) || isset( $parts['pass'] ) || isset( $parts['query'] ) || isset( $parts['fragment'] ) ) {
			return '';
		}
		$path = isset( $parts['path'] ) ? rtrim( $parts['path'], '/' ) : '';
		$port = isset( $parts['port'] ) ? ':' . (int) $parts['port'] : '';
		return 'https://' . strtolower( $parts['host'] ) . $port . $path;
	}

	/**
	 * Derive the response-verification key from the site token. It is a
	 * different key from the bearer/request-signing secret (HMAC of a fixed
	 * label), so the request signature and the response signature are not
	 * interchangeable.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string $token Site token.
	 * @return string Hex key.
	 */
	public static function response_key( $token ) {
		return hash_hmac( 'sha256', self::RESPONSE_KEY_LABEL, (string) $token );
	}

	/**
	 * Verify the signature on a /v1/commands response: HMAC-SHA256 of
	 * "{ts}.{nonce}.{body}" with response_key(), where the nonce is the one
	 * this request sent (so an old response cannot be replayed) and the
	 * timestamp is fresh.
	 *
	 * Pure function (unit-tested). NOTE: the token is also the bearer secret, so
	 * this proves the responder knows the token — it defeats a blind spoofer or
	 * a replay, not a party that was already sent the token over a broken
	 * transport (hence https-only). The real fix is BLT Connect.
	 *
	 * @param string $token     Site token.
	 * @param string $nonce     Nonce sent with the request.
	 * @param string $ts        Response timestamp header.
	 * @param string $resp_nonce Echoed nonce header.
	 * @param string $signature Response signature header.
	 * @param string $body      Raw response body.
	 * @param int    $now       Current time.
	 * @return bool
	 */
	public static function verify_response( $token, $nonce, $ts, $resp_nonce, $signature, $body, $now ) {
		if ( '' === (string) $nonce || ! is_string( $resp_nonce ) || ! hash_equals( (string) $nonce, $resp_nonce ) ) {
			return false;
		}
		if ( ! preg_match( '/^\d{1,12}$/', (string) $ts ) || abs( (int) $now - (int) $ts ) > 300 ) {
			return false;
		}
		$expected = hash_hmac( 'sha256', (int) $ts . '.' . $nonce . '.' . (string) $body, self::response_key( $token ) );
		return is_string( $signature ) && hash_equals( $expected, strtolower( $signature ) );
	}

	/**
	 * Pick the commands to run now: ids at or below the last executed id are
	 * stale (already run, re-delivered because the ack was lost) and are only
	 * re-acknowledged; the rest run oldest-first, capped per pull.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param array<int,array{id:int,command:string}> $commands Parsed commands.
	 * @param int                                     $last     Last executed id.
	 * @param int                                     $max      Per-pull cap.
	 * @return array{run:array,ack_only:int[]}
	 */
	public static function select_commands( array $commands, $last, $max ) {
		$run      = array();
		$ack_only = array();
		usort(
			$commands,
			static function ( $a, $b ) {
				return $a['id'] <=> $b['id'];
			}
		);
		foreach ( $commands as $command ) {
			if ( $command['id'] <= (int) $last ) {
				$ack_only[] = $command['id'];
			} elseif ( count( $run ) < (int) $max ) {
				$run[] = $command;
			}
		}
		return array(
			'run'      => $run,
			'ack_only' => $ack_only,
		);
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
	 * Whitelist of remotely-triggerable commands mapped to the local WP-Cron
	 * action that performs the work. Only these commands are ever executed;
	 * anything else the dashboard sends is ignored.
	 *
	 * Every action is a parameterless scan/sync trigger already registered by
	 * its own module — the receiver never passes operator-supplied parameters
	 * into local code.
	 *
	 * @return array<string,string> Command slug => WP-Cron action hook.
	 */
	public static function command_map() {
		return array(
			'scan_core'     => 'blt_secure_core_scan',
			'scan_malware'  => 'blt_secure_malware_scan',
			'scan_baseline' => 'blt_secure_baseline_scan',
			'sync_ioc'      => 'blt_secure_ioc_sync',
			'health_scan'   => 'blt_secure_health_scan',
			'report'        => self::CRON_HOOK,
		);
	}

	/**
	 * Resolve a command slug to its local action hook, or null if unknown.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string $command Command slug.
	 * @return string|null
	 */
	public static function hook_for( $command ) {
		$map = self::command_map();
		return isset( $map[ (string) $command ] ) ? $map[ (string) $command ] : null;
	}

	/**
	 * Normalize and whitelist the command list from a `/v1/commands` response.
	 * Malformed entries and unknown/unsupported commands are dropped; operator
	 * parameters are deliberately discarded.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param mixed $decoded Decoded JSON body.
	 * @return array<int,array{id:int,command:string}>
	 */
	public static function parse_commands( $decoded ) {
		if ( ! is_array( $decoded ) || ! isset( $decoded['commands'] ) || ! is_array( $decoded['commands'] ) ) {
			return array();
		}

		$map  = self::command_map();
		$out  = array();
		$seen = array();

		foreach ( $decoded['commands'] as $entry ) {
			if ( ! is_array( $entry ) ) {
				continue;
			}
			$id      = isset( $entry['id'] ) ? (int) $entry['id'] : 0;
			$command = isset( $entry['command'] ) ? (string) $entry['command'] : '';

			if ( $id <= 0 || ! isset( $map[ $command ] ) || isset( $seen[ $id ] ) ) {
				continue;
			}
			$seen[ $id ] = true;
			$out[]       = array(
				'id'      => $id,
				'command' => $command,
			);
		}

		return $out;
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
			'schema'      => self::SCHEMA,
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
			'events'      => self::count_events( isset( $in['events'] ) && is_array( $in['events'] ) ? $in['events'] : array(), isset( $in['events_since'] ) ? (int) $in['events_since'] : 0 ),
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
	 * Count high-signal events newer than $since (the previous successful
	 * report), so the dashboard receives deltas, not the ring buffer's running
	 * totals re-sent on every push.
	 *
	 * @param array[] $events Alerting ring-buffer events.
	 * @param int     $since  Only events after this Unix time (0 = all).
	 * @return array<string,int>
	 */
	private static function count_events( array $events, $since = 0 ) {
		$wanted = array_fill_keys( self::high_signal_types(), 0 );
		foreach ( $events as $event ) {
			$type = isset( $event['type'] ) ? $event['type'] : '';
			if ( isset( $event['time'] ) && (int) $event['time'] <= $since ) {
				continue;
			}
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
				'site'         => (string) home_url(),
				'name'         => (string) get_bloginfo( 'name' ),
				'reported_at'  => time(),
				'versions'     => array(
					'plugin' => BLT_SECURE_VERSION,
					'wp'     => (string) get_bloginfo( 'version' ),
					'php'    => PHP_VERSION,
				),
				'health'       => get_option( 'blt_secure_health_results', array() ),
				// Whitelisted (ignored) findings are excluded so the dashboard
				// mirrors the site's own active counts and health score.
				'core'         => $this->without_ignored( get_option( 'blt_secure_core_scan_results', array() ), 'issues' ),
				'malware'      => $this->without_ignored( get_option( 'blt_secure_malware_results', array() ), 'findings' ),
				'baseline'     => $this->without_ignored( get_option( 'blt_secure_baseline_results', array() ), 'findings' ),
				'ioc'          => get_option( 'blt_secure_ioc_state', array() ),
				'cf_zone'      => $zone,
				'events'       => get_option( 'blt_secure_events', array() ),
				'events_since' => $this->last_ok(),
			)
		);
	}

	/**
	 * Return a scan payload with its finding list filtered to active
	 * (non-whitelisted) findings.
	 *
	 * @param mixed  $payload Stored scan payload.
	 * @param string $key     Finding-list key ('issues' or 'findings').
	 * @return array
	 */
	private function without_ignored( $payload, $key ) {
		if ( ! is_array( $payload ) ) {
			return array();
		}
		if ( ! empty( $payload[ $key ] ) && is_array( $payload[ $key ] ) ) {
			$payload[ $key ] = $this->whitelist->active( $payload[ $key ] );
		}
		return $payload;
	}

	/**
	 * The configured endpoint, validated (https only), or '' when unusable.
	 *
	 * @return string
	 */
	private function endpoint() {
		return self::normalize_endpoint( (string) $this->options->get( 'fleet', 'endpoint', '' ) );
	}

	/**
	 * Unix time of the last successful report (0 = never).
	 *
	 * @return int
	 */
	private function last_ok() {
		$state = $this->latest();
		return is_array( $state ) && isset( $state['last_ok'] ) ? (int) $state['last_ok'] : 0;
	}

	/**
	 * Push the snapshot to the dashboard.
	 *
	 * @return array Stored status.
	 */
	public function report() {
		$raw      = trim( (string) $this->options->get( 'fleet', 'endpoint', '' ) );
		$endpoint = $this->endpoint();
		$token    = $this->credentials->get( self::TOKEN_KEY );

		if ( '' === $raw || ! is_string( $token ) || '' === $token ) {
			return $this->store( 'not_configured', '' );
		}
		if ( '' === $endpoint ) {
			return $this->store( 'error', __( 'The dashboard endpoint must be an https:// URL.', 'blt-secure' ) );
		}

		$snapshot = $this->build_snapshot();
		$body     = (string) wp_json_encode( $snapshot );
		$ts       = time();

		$response = wp_safe_remote_post(
			$endpoint . '/v1/snapshot',
			array(
				'timeout'     => 15,
				'redirection' => 0,
				'headers'     => array(
					'Authorization'   => 'Bearer ' . $token,
					'Content-Type'    => 'application/json',
					'X-BLT-Timestamp' => (string) $ts,
					'X-BLT-Signature' => self::sign( $ts, $body, $token ),
				),
				'body'        => $body,
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

		return $this->store( 'ok', '', $ts );
	}

	/**
	 * Queue an immediate (throttled) push when a high-signal event fires.
	 *
	 * Runs inside the request that raised the alert, so it only schedules a
	 * one-off WP-Cron event — the 15-second HTTP call never blocks a login.
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
		wp_schedule_single_event( time() + 5, self::PUSH_HOOK );
		if ( function_exists( 'spawn_cron' ) ) {
			spawn_cron();
		}
	}

	// ---------------------------------------------------------------------
	// Remote-command receiver (pull model).
	// ---------------------------------------------------------------------

	/**
	 * Pull queued commands from the dashboard, execute the whitelisted ones,
	 * and acknowledge them.
	 *
	 * The request is signed with the per-site token and carries a fresh nonce;
	 * the RESPONSE must carry a signature over "{ts}.{nonce}.{body}" made with
	 * a key derived from the token (see verify_response()), otherwise the
	 * command list is discarded unread. At most MAX_COMMANDS run per pull, and
	 * an id at or below the last executed id is never run again.
	 *
	 * @return int[] IDs of executed commands.
	 */
	public function pull() {
		$endpoint = $this->endpoint();
		$token    = $this->credentials->get( self::TOKEN_KEY );

		if ( '' === $endpoint || ! is_string( $token ) || '' === $token ) {
			return array();
		}

		$ts       = time();
		$nonce    = bin2hex( random_bytes( 16 ) );
		$response = wp_safe_remote_get(
			$endpoint . '/v1/commands',
			array(
				'timeout'     => 15,
				'redirection' => 0,
				'headers'     => array(
					'Authorization'   => 'Bearer ' . $token,
					'X-BLT-Timestamp' => (string) $ts,
					'X-BLT-Signature' => self::sign( $ts, '', $token ),
					'X-BLT-Nonce'     => $nonce,
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return array();
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( $code < 200 || $code >= 300 ) {
			return array();
		}

		$raw_body = (string) wp_remote_retrieve_body( $response );
		if ( ! self::verify_response(
			$token,
			$nonce,
			(string) wp_remote_retrieve_header( $response, 'x-blt-response-timestamp' ),
			(string) wp_remote_retrieve_header( $response, 'x-blt-response-nonce' ),
			(string) wp_remote_retrieve_header( $response, 'x-blt-response-signature' ),
			$raw_body,
			time()
		) ) {
			return array();
		}

		$commands = self::parse_commands( json_decode( $raw_body, true ) );
		if ( empty( $commands ) ) {
			return array();
		}

		$selected = self::select_commands( $commands, (int) get_option( self::LAST_COMMAND_OPTION, 0 ), self::MAX_COMMANDS );

		$done = array();
		foreach ( $selected['run'] as $command ) {
			$this->execute( $command['command'] );
			// Persist after EACH command: a scan that dies mid-run is retried
			// (the dashboard re-delivers un-acked commands), never skipped.
			update_option( self::LAST_COMMAND_OPTION, $command['id'], false );
			$done[] = $command['id'];
		}

		$this->ack( $endpoint, $token, array_merge( $selected['ack_only'], $done ) );
		return $done;
	}

	/**
	 * Run one whitelisted command by firing its local WP-Cron action, and
	 * record an audit event (which is also an alert type). Unknown commands
	 * are ignored; if the owning module is disabled the action simply has no
	 * listener (a safe no-op).
	 *
	 * @param string $command Command slug.
	 * @return void
	 */
	private function execute( $command ) {
		$hook = self::hook_for( $command );
		if ( null === $hook ) {
			return;
		}
		if ( $this->alerting ) {
			$this->alerting->notify( 'fleet_command', array( 'command' => $command ) );
		}
		// $hook is always a blt_secure_* action from the command_map() whitelist.
		do_action( $hook ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.DynamicHooknameFound
	}

	/**
	 * Acknowledge executed commands so the dashboard marks them done.
	 *
	 * @param string $endpoint Dashboard base URL (no trailing slash).
	 * @param string $token    Per-site token.
	 * @param int[]  $ids      Executed command IDs.
	 * @return void
	 */
	private function ack( $endpoint, $token, array $ids ) {
		if ( empty( $ids ) ) {
			return;
		}
		$body = (string) wp_json_encode( array( 'ids' => array_values( $ids ) ) );
		$ts   = time();

		wp_safe_remote_post(
			$endpoint . '/v1/commands/ack',
			array(
				'timeout'     => 15,
				'redirection' => 0,
				'headers'     => array(
					'Authorization'   => 'Bearer ' . $token,
					'Content-Type'    => 'application/json',
					'X-BLT-Timestamp' => (string) $ts,
					'X-BLT-Signature' => self::sign( $ts, $body, $token ),
				),
				'body'        => $body,
			)
		);
	}

	/**
	 * Persist and return the report status.
	 *
	 * @param string $status Status slug.
	 * @param string $error  Error message.
	 * @param int    $ok_at  Time of a successful report (0 = keep the previous).
	 * @return array
	 */
	private function store( $status, $error, $ok_at = 0 ) {
		$payload = array(
			'time'    => time(),
			'status'  => $status,
			'error'   => $error,
			'last_ok' => $ok_at > 0 ? (int) $ok_at : $this->last_ok(),
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
