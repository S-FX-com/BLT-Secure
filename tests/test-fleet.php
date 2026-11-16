<?php
/**
 * Fleet reporter snapshot-assembly + signing tests.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure_Fleet pure helpers.
 */
class Test_Fleet extends TestCase {

	public function test_sign_is_deterministic_hmac() {
		$sig = Blt_Secure_Fleet::sign( 1700000000, '{"a":1}', 'secret' );
		$this->assertSame( hash_hmac( 'sha256', '1700000000.{"a":1}', 'secret' ), $sig );
		// Different token → different signature.
		$this->assertNotSame( $sig, Blt_Secure_Fleet::sign( 1700000000, '{"a":1}', 'other' ) );
	}

	public function test_assemble_snapshot_reduces_raw_payloads() {
		$snapshot = Blt_Secure_Fleet::assemble_snapshot(
			array(
				'site'        => 'https://example.com',
				'name'        => 'Example',
				'reported_at' => 1700000000,
				'versions'    => array( 'plugin' => '1.0.6', 'wp' => '6.5', 'php' => '8.2' ),
				'health'      => array( 'summary' => array( 'score' => 92, 'pass' => 40, 'warn' => 3, 'fail' => 1 ) ),
				'core'        => array( 'error' => '', 'issues' => array( array( 'path' => 'x' ) ) ),
				'malware'     => array( 'error' => '', 'findings' => array() ),
				'baseline'    => array( 'findings' => array() ),
				'ioc'         => array( 'status' => 'ok', 'count' => 1234 ),
				'cf_zone'     => array( 'zone_id' => 'z1', 'plan' => 'pro' ),
				'events'      => array(
					array( 'type' => 'lockout' ),
					array( 'type' => 'lockout' ),
					array( 'type' => 'blocked_upload' ),
					array( 'type' => 'activity_plugin_activated' ), // not high-signal.
				),
			)
		);

		$this->assertSame( Blt_Secure_Fleet::SCHEMA, $snapshot['schema'] );
		$this->assertSame( 2, $snapshot['schema'] );
		$this->assertSame( 'https://example.com', $snapshot['site'] );
		$this->assertSame( 92, $snapshot['health']['score'] );
		$this->assertSame( 'issues', $snapshot['core']['status'] );
		$this->assertSame( 1, $snapshot['core']['issues'] );
		$this->assertSame( 'ok', $snapshot['malware']['status'] );
		$this->assertSame( 0, $snapshot['malware']['findings'] );
		$this->assertTrue( $snapshot['cloudflare']['connected'] );
		$this->assertSame( 'pro', $snapshot['cloudflare']['plan'] );
		$this->assertSame( 1234, $snapshot['ioc']['count'] );
		// Only high-signal events counted; routine activity dropped.
		$this->assertSame( array( 'lockout' => 2, 'blocked_upload' => 1 ), $snapshot['events'] );
	}

	public function test_assemble_snapshot_handles_empty_inputs() {
		$snapshot = Blt_Secure_Fleet::assemble_snapshot( array() );
		$this->assertSame( 'none', $snapshot['core']['status'] );
		$this->assertSame( 'none', $snapshot['malware']['status'] );
		$this->assertFalse( $snapshot['cloudflare']['connected'] );
		$this->assertSame( array(), $snapshot['events'] );
		$this->assertNull( $snapshot['health']['score'] );
	}

	public function test_assemble_snapshot_marks_scan_error() {
		$snapshot = Blt_Secure_Fleet::assemble_snapshot(
			array( 'core' => array( 'error' => 'network down', 'issues' => array() ) )
		);
		$this->assertSame( 'error', $snapshot['core']['status'] );
	}

	public function test_snapshot_carries_no_secret_keys() {
		$snapshot = Blt_Secure_Fleet::assemble_snapshot(
			array( 'site' => 'https://x', 'ioc' => array( 'status' => 'ok', 'count' => 5 ) )
		);
		$json = wp_json_encode( $snapshot );
		foreach ( array( 'token', 'secret', 'webhook', 'password', 'cf_token' ) as $needle ) {
			$this->assertStringNotContainsStringIgnoringCase( $needle, $json );
		}
	}

	public function test_hook_for_maps_only_whitelisted_commands() {
		$this->assertSame( 'blt_secure_core_scan', Blt_Secure_Fleet::hook_for( 'scan_core' ) );
		$this->assertSame( 'blt_secure_malware_scan', Blt_Secure_Fleet::hook_for( 'scan_malware' ) );
		$this->assertSame( Blt_Secure_Fleet::CRON_HOOK, Blt_Secure_Fleet::hook_for( 'report' ) );
		$this->assertNull( Blt_Secure_Fleet::hook_for( 'rm_rf' ) );
		$this->assertNull( Blt_Secure_Fleet::hook_for( '' ) );
	}

	public function test_parse_commands_whitelists_and_normalizes() {
		$parsed = Blt_Secure_Fleet::parse_commands(
			array(
				'commands' => array(
					array( 'id' => 5, 'command' => 'scan_core', 'params' => array( 'evil' => true ) ),
					array( 'id' => '6', 'command' => 'sync_ioc' ),
					array( 'id' => 7, 'command' => 'delete_everything' ), // not whitelisted.
					array( 'id' => 0, 'command' => 'scan_core' ),          // bad id.
					array( 'command' => 'scan_core' ),                     // no id.
					'not-an-array',
					array( 'id' => 5, 'command' => 'health_scan' ),        // duplicate id.
				),
			)
		);

		$this->assertSame(
			array(
				array( 'id' => 5, 'command' => 'scan_core' ),
				array( 'id' => 6, 'command' => 'sync_ioc' ),
			),
			$parsed
		);
		// Operator params are never carried through.
		$this->assertArrayNotHasKey( 'params', $parsed[0] );
	}

	public function test_parse_commands_handles_malformed_bodies() {
		$this->assertSame( array(), Blt_Secure_Fleet::parse_commands( null ) );
		$this->assertSame( array(), Blt_Secure_Fleet::parse_commands( 'x' ) );
		$this->assertSame( array(), Blt_Secure_Fleet::parse_commands( array() ) );
		$this->assertSame( array(), Blt_Secure_Fleet::parse_commands( array( 'commands' => 'nope' ) ) );
	}

	// ---------------------------------------------------------------------
	// Hardening pass: form round-trip, https-only, signed responses, commands.
	// ---------------------------------------------------------------------

	protected function setUp(): void {
		$GLOBALS['blt_test_options']    = array();
		$GLOBALS['blt_test_transients'] = array();
		$GLOBALS['blt_test_actions']    = array();
		$GLOBALS['blt_test_scheduled']  = array();
		$GLOBALS['blt_test_http']       = array();
		$GLOBALS['blt_test_requests']   = array();
		$GLOBALS['blt_test_errors']     = array();
	}

	/**
	 * A fleet module wired to in-memory options and an enrolled token.
	 *
	 * @param array  $fleet_settings Settings for the 'fleet' section.
	 * @param string $token          Enrollment token ('' = none).
	 * @return Blt_Secure_Fleet
	 */
	private function fleet( array $fleet_settings = array(), $token = 'site-secret-token' ) {
		$GLOBALS['blt_test_options']['blt_secure_settings'] = array( 'fleet' => $fleet_settings );
		$options = new Blt_Secure_Options();
		$store   = new Blt_Secure_Encrypted_Option_Store( new Blt_Secure_Crypto() );
		if ( '' !== $token ) {
			$store->set( Blt_Secure_Fleet::TOKEN_KEY, $token );
		}
		$fleet = new Blt_Secure_Fleet( $options, $store, new Blt_Secure_Alerting( $options ) );
		$options->register_defaults( 'fleet', $fleet->defaults() );
		return $fleet;
	}

	public function test_sanitize_keeps_schedule_when_the_form_does_not_post_it() {
		$fleet = $this->fleet();
		// Exactly the fields tab-advanced.php posts for [fleet].
		$posted = array(
			'enabled'  => '1',
			'endpoint' => 'https://fleet.example.com',
			'commands' => '1',
		);

		$this->assertTrue( $fleet->sanitize( $posted, array() )['schedule'], 'default stays on' );
		$this->assertTrue( $fleet->sanitize( $posted, array( 'schedule' => true ) )['schedule'] );
		$this->assertFalse( $fleet->sanitize( $posted, array( 'schedule' => false ) )['schedule'], 'an explicit stored off is kept' );
		// An explicit post still wins.
		$this->assertFalse( $fleet->sanitize( $posted + array( 'schedule' => '' ), array( 'schedule' => true ) )['schedule'] );
	}

	public function test_form_round_trip_never_flips_an_unposted_key() {
		// Every key the settings form does NOT render must come back unchanged.
		$fleet   = $this->fleet();
		$view    = (string) file_get_contents( BLT_SECURE_DIR . 'admin/views/tab-advanced.php' );
		preg_match_all( '/\[fleet\]\[([a-z_]+)\]/', $view, $m );
		$posted_keys = array_unique( $m[1] );
		$unposted    = array_diff( array_keys( $fleet->defaults() ), $posted_keys );
		$this->assertContains( 'schedule', $unposted, 'schedule has no form field (the regression this guards)' );

		$current = array(
			'enabled'  => true,
			'endpoint' => 'https://fleet.example.com',
			'schedule' => false,
			'commands' => false,
		);
		$posted = array_fill_keys( $posted_keys, '1' );
		$posted['endpoint'] = 'https://fleet.example.com';
		$out = $fleet->sanitize( $posted, $current );
		foreach ( $unposted as $key ) {
			$this->assertSame( $current[ $key ], $out[ $key ], "unposted key {$key} was changed by a save" );
		}
	}

	public function test_endpoint_must_be_https_with_a_host() {
		$this->assertSame( 'https://fleet.example.com', Blt_Secure_Fleet::normalize_endpoint( ' https://Fleet.Example.com/ ' ) );
		$this->assertSame( 'https://fleet.example.com:8443/api', Blt_Secure_Fleet::normalize_endpoint( 'https://fleet.example.com:8443/api/' ) );
		foreach ( array( 'http://fleet.example.com', 'ftp://fleet.example.com', 'fleet.example.com', 'https://', 'https://u:p@fleet.example.com', 'https://fleet.example.com/?x=1', 'https://fleet.example.com/#f', '//fleet.example.com', 'javascript:alert(1)', '' ) as $bad ) {
			$this->assertSame( '', Blt_Secure_Fleet::normalize_endpoint( $bad ), $bad );
		}
	}

	public function test_sanitize_rejects_a_plain_http_endpoint_and_says_so() {
		$out = $this->fleet()->sanitize( array( 'enabled' => '1', 'endpoint' => 'http://fleet.example.com' ), array() );
		$this->assertSame( '', $out['endpoint'] );
		$this->assertContains( 'blt_secure_fleet_endpoint', $GLOBALS['blt_test_errors'] );
	}

	public function test_report_refuses_to_send_the_token_over_http() {
		$fleet  = $this->fleet( array( 'enabled' => true, 'endpoint' => 'http://fleet.example.com' ) );
		$result = $fleet->report();
		$this->assertSame( 'error', $result['status'] );
		$this->assertSame( array(), $GLOBALS['blt_test_requests'], 'nothing may leave the site' );
	}

	public function test_report_posts_signed_snapshot_with_safe_transport_options() {
		$fleet  = $this->fleet( array( 'enabled' => true, 'endpoint' => 'https://fleet.example.com' ) );
		$result = $fleet->report();

		$this->assertSame( 'ok', $result['status'] );
		$request = $GLOBALS['blt_test_requests'][0];
		$this->assertSame( 'https://fleet.example.com/v1/snapshot', $request['url'] );
		$this->assertSame( 0, $request['args']['redirection'] );
		$ts = $request['args']['headers']['X-BLT-Timestamp'];
		$this->assertSame( Blt_Secure_Fleet::sign( $ts, $request['args']['body'], 'site-secret-token' ), $request['args']['headers']['X-BLT-Signature'] );
		$this->assertSame( 2, json_decode( $request['args']['body'], true )['schema'] );
	}

	public function test_events_are_deltas_since_the_last_successful_report() {
		$events = array(
			array( 'type' => 'lockout', 'time' => 100 ),
			array( 'type' => 'lockout', 'time' => 200 ),
			array( 'type' => 'blocked_upload', 'time' => 300 ),
		);
		$all   = Blt_Secure_Fleet::assemble_snapshot( array( 'events' => $events ) );
		$delta = Blt_Secure_Fleet::assemble_snapshot( array( 'events' => $events, 'events_since' => 150 ) );
		$this->assertSame( array( 'lockout' => 2, 'blocked_upload' => 1 ), $all['events'] );
		$this->assertSame( array( 'lockout' => 1, 'blocked_upload' => 1 ), $delta['events'] );
	}

	public function test_alert_push_is_queued_not_sent_inline() {
		$fleet = $this->fleet( array( 'enabled' => true, 'endpoint' => 'https://fleet.example.com' ) );

		$fleet->maybe_push_alert( 'lockout' );
		$this->assertSame( array(), $GLOBALS['blt_test_requests'], 'no HTTP on the request that raised the alert' );
		$this->assertCount( 1, $GLOBALS['blt_test_scheduled'] );
		$this->assertSame( Blt_Secure_Fleet::PUSH_HOOK, $GLOBALS['blt_test_scheduled'][0]['hook'] );

		$fleet->maybe_push_alert( 'lockout' ); // throttled.
		$fleet->maybe_push_alert( 'ioc_sync' ); // not high-signal.
		$this->assertCount( 1, $GLOBALS['blt_test_scheduled'] );
	}

	public function test_high_signal_types_track_the_alert_allowlist_without_the_audit_event() {
		$types = Blt_Secure_Fleet::high_signal_types();
		$this->assertContains( 'blocked_plugin_install', $types );
		$this->assertContains( 'twofa_bruteforce', $types );
		$this->assertNotContains( 'blocked_plugin', $types, 'stale slug' );
		$this->assertNotContains( 'fleet_command', $types, 'the audit event must not trigger a push' );
	}

	// -- Signed /v1/commands response ------------------------------------

	public function test_response_signature_matches_the_worker_vectors() {
		// Same constants asserted by dashboard/test/auth.test.js.
		$key = Blt_Secure_Fleet::response_key( 'site-secret-token' );
		$this->assertSame( 'f113ddc2924d21b65a60ecb76e9795f2ea8414d3cf894d5dac29c7b04e442e77', $key );
		$this->assertNotSame( 'site-secret-token', $key );
		$sig = hash_hmac( 'sha256', '1700000000.abcdef0123456789abcd.{"commands":[]}', $key );
		$this->assertSame( '0ed1512e97ee5058793cb6e10b5bf601357b877f88d16429b48027be024329f4', $sig );
		$this->assertTrue( Blt_Secure_Fleet::verify_response( 'site-secret-token', 'abcdef0123456789abcd', '1700000000', 'abcdef0123456789abcd', $sig, '{"commands":[]}', 1700000100 ) );
	}

	public function test_verify_response_rejects_tampering_replay_and_staleness() {
		$token = 'site-secret-token';
		$nonce = 'abcdef0123456789abcd';
		$body  = '{"commands":[{"id":1,"command":"scan_core"}]}';
		$sig   = hash_hmac( 'sha256', "1700000000.{$nonce}.{$body}", Blt_Secure_Fleet::response_key( $token ) );
		$now   = 1700000100;

		$this->assertTrue( Blt_Secure_Fleet::verify_response( $token, $nonce, '1700000000', $nonce, $sig, $body, $now ) );
		// Body changed in transit.
		$this->assertFalse( Blt_Secure_Fleet::verify_response( $token, $nonce, '1700000000', $nonce, $sig, str_replace( 'scan_core', 'sync_ioc', $body ), $now ) );
		// Response for a different request (replayed old list): nonce differs.
		$this->assertFalse( Blt_Secure_Fleet::verify_response( $token, 'ffffffffffffffffffff', '1700000000', $nonce, $sig, $body, $now ) );
		$this->assertFalse( Blt_Secure_Fleet::verify_response( $token, $nonce, '1700000000', 'ffffffffffffffffffff', $sig, $body, $now ) );
		// Stale timestamp.
		$this->assertFalse( Blt_Secure_Fleet::verify_response( $token, $nonce, '1700000000', $nonce, $sig, $body, $now + 1000 ) );
		// Wrong token, request-signing key reused as response key, missing/garbage signature.
		$this->assertFalse( Blt_Secure_Fleet::verify_response( 'other-token', $nonce, '1700000000', $nonce, $sig, $body, $now ) );
		$as_request_sig = hash_hmac( 'sha256', "1700000000.{$nonce}.{$body}", $token );
		$this->assertFalse( Blt_Secure_Fleet::verify_response( $token, $nonce, '1700000000', $nonce, $as_request_sig, $body, $now ) );
		$this->assertFalse( Blt_Secure_Fleet::verify_response( $token, $nonce, '1700000000', $nonce, '', $body, $now ) );
		$this->assertFalse( Blt_Secure_Fleet::verify_response( $token, '', '1700000000', '', $sig, $body, $now ) );
		$this->assertFalse( Blt_Secure_Fleet::verify_response( $token, $nonce, 'abc', $nonce, $sig, $body, $now ) );
	}

	// -- Command selection and pull() ------------------------------------

	public function test_select_commands_caps_orders_and_skips_already_executed() {
		$cmds = array();
		foreach ( array( 9, 3, 12, 4, 5, 6, 7, 8 ) as $id ) {
			$cmds[] = array( 'id' => $id, 'command' => 'scan_core' );
		}
		$picked = Blt_Secure_Fleet::select_commands( $cmds, 4, 5 );

		$this->assertSame( array( 5, 6, 7, 8, 9 ), array_column( $picked['run'], 'id' ), 'oldest first, capped at 5' );
		$this->assertSame( array( 3, 4 ), $picked['ack_only'], 'already executed: re-ack only, never re-run' );
	}

	/**
	 * Queue a signed /v1/commands response for the next HTTP request.
	 *
	 * @param array  $commands  Commands.
	 * @param bool   $signed    Sign it?
	 * @param string $token     Token used to sign.
	 * @return void
	 */
	private function queue_commands_response( array $commands, $signed = true, $token = 'site-secret-token' ) {
		$GLOBALS['blt_test_http'][] = static function ( $method, $url, $args ) use ( $commands, $signed, $token ) {
			$body    = wp_json_encode( array( 'commands' => $commands ) );
			$nonce   = $args['headers']['X-BLT-Nonce'];
			$ts      = (string) time();
			$headers = array();
			if ( $signed ) {
				$headers = array(
					'X-BLT-Response-Timestamp' => $ts,
					'X-BLT-Response-Nonce'     => $nonce,
					'X-BLT-Response-Signature' => hash_hmac( 'sha256', "{$ts}.{$nonce}.{$body}", Blt_Secure_Fleet::response_key( $token ) ),
				);
			}
			return array(
				'response' => array( 'code' => 200 ),
				'body'     => $body,
				'headers'  => $headers,
			);
		};
	}

	private function executed_hooks() {
		$out = array();
		foreach ( $GLOBALS['blt_test_actions'] as $call ) {
			if ( 'blt_secure_alert' !== $call[0] ) {
				$out[] = $call[0];
			}
		}
		return $out;
	}

	public function test_pull_runs_signed_commands_and_persists_the_last_id() {
		$fleet = $this->fleet( array( 'enabled' => true, 'commands' => true, 'endpoint' => 'https://fleet.example.com' ) );
		$this->queue_commands_response(
			array(
				array( 'id' => 21, 'command' => 'scan_core' ),
				array( 'id' => 22, 'command' => 'sync_ioc' ),
			)
		);

		$this->assertSame( array( 21, 22 ), $fleet->pull() );
		$this->assertSame( array( 'blt_secure_core_scan', 'blt_secure_ioc_sync' ), $this->executed_hooks() );
		$this->assertSame( 22, get_option( Blt_Secure_Fleet::LAST_COMMAND_OPTION ) );

		$get = $GLOBALS['blt_test_requests'][0];
		$this->assertSame( 0, $get['args']['redirection'] );
		$this->assertMatchesRegularExpression( '/^[a-f0-9]{32}$/', $get['args']['headers']['X-BLT-Nonce'] );
		$ack = $GLOBALS['blt_test_requests'][1];
		$this->assertSame( '/v1/commands/ack', substr( $ack['url'], -16 ) );
		$this->assertSame( array( 'ids' => array( 21, 22 ) ), json_decode( $ack['args']['body'], true ) );
	}

	public function test_pull_never_replays_an_old_command_list() {
		$fleet = $this->fleet( array( 'enabled' => true, 'commands' => true, 'endpoint' => 'https://fleet.example.com' ) );
		update_option( Blt_Secure_Fleet::LAST_COMMAND_OPTION, 30, false );
		$this->queue_commands_response( array( array( 'id' => 29, 'command' => 'scan_malware' ), array( 'id' => 30, 'command' => 'scan_core' ) ) );

		$this->assertSame( array(), $fleet->pull() );
		$this->assertSame( array(), $this->executed_hooks(), 'ids at or below the last executed id never run' );
		$ack = json_decode( $GLOBALS['blt_test_requests'][1]['args']['body'], true );
		$this->assertSame( array( 'ids' => array( 29, 30 ) ), $ack, 'but they are re-acknowledged so the dashboard stops resending' );
	}

	public function test_pull_caps_commands_per_run() {
		$fleet = $this->fleet( array( 'enabled' => true, 'commands' => true, 'endpoint' => 'https://fleet.example.com' ) );
		$cmds  = array();
		for ( $i = 1; $i <= 12; $i++ ) {
			$cmds[] = array( 'id' => $i, 'command' => 'scan_malware' );
		}
		$this->queue_commands_response( $cmds );

		$this->assertSame( array( 1, 2, 3, 4, 5 ), $fleet->pull() );
		$this->assertCount( 5, $this->executed_hooks() );
		$this->assertSame( 5, get_option( Blt_Secure_Fleet::LAST_COMMAND_OPTION ) );
	}

	public function test_pull_discards_an_unsigned_or_wrongly_signed_response() {
		$fleet = $this->fleet( array( 'enabled' => true, 'commands' => true, 'endpoint' => 'https://fleet.example.com' ) );

		$this->queue_commands_response( array( array( 'id' => 1, 'command' => 'scan_malware' ) ), false );
		$this->assertSame( array(), $fleet->pull(), 'unsigned' );

		$this->queue_commands_response( array( array( 'id' => 2, 'command' => 'scan_malware' ) ), true, 'attacker-guess' );
		$this->assertSame( array(), $fleet->pull(), 'signed with the wrong key' );

		$this->assertSame( array(), $this->executed_hooks() );
		$this->assertFalse( get_option( Blt_Secure_Fleet::LAST_COMMAND_OPTION, false ) );
		$this->assertCount( 2, $GLOBALS['blt_test_requests'], 'no ack was sent either' );
	}

	public function test_pull_refuses_a_non_https_endpoint() {
		$fleet = $this->fleet( array( 'enabled' => true, 'commands' => true, 'endpoint' => 'http://fleet.example.com' ) );
		$this->assertSame( array(), $fleet->pull() );
		$this->assertSame( array(), $GLOBALS['blt_test_requests'] );
	}

	public function test_executing_a_command_is_audited_and_alertable() {
		$this->assertContains( 'fleet_command', Blt_Secure_Alert_Channels::default_types() );
		$fleet = $this->fleet( array( 'enabled' => true, 'commands' => true, 'endpoint' => 'https://fleet.example.com' ) );
		$this->queue_commands_response( array( array( 'id' => 1, 'command' => 'scan_core' ) ) );
		$fleet->pull();

		$types = array();
		foreach ( $GLOBALS['blt_test_actions'] as $call ) {
			if ( 'blt_secure_alert' === $call[0] ) {
				$types[] = $call[1];
			}
		}
		$this->assertSame( array( 'fleet_command' ), $types );
	}
}
