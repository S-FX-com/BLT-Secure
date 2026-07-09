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

		$this->assertSame( 1, $snapshot['schema'] );
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
}
