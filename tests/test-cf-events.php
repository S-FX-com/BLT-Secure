<?php
/**
 * Cloudflare firewall-event query/parse/merge tests.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure_Cf_Events pure helpers.
 */
class Test_Cf_Events extends TestCase {

	public function test_query_targets_firewall_events_dataset() {
		$q = Blt_Secure_Cf_Events::query();
		$this->assertStringContainsString( 'firewallEventsAdaptive', $q );
		$this->assertStringContainsString( 'zones(filter: {zoneTag: $zoneTag})', $q );
	}

	public function test_variables_shape_and_clamping() {
		$vars = Blt_Secure_Cf_Events::variables( 'zone123', 1609459200, 5000 );
		$this->assertSame( 'zone123', $vars['zoneTag'] );
		$this->assertSame( '2021-01-01T00:00:00Z', $vars['since'] );
		$this->assertSame( 1000, $vars['limit'] ); // clamped to max.

		$this->assertSame( 1, Blt_Secure_Cf_Events::variables( 'z', 0, 0 )['limit'] ); // clamped to min.
	}

	public function test_parse_extracts_rows() {
		$data = array(
			'viewer' => array(
				'zones' => array(
					array(
						'firewallEventsAdaptive' => array(
							array(
								'action'                => 'block',
								'datetime'              => '2026-01-02T03:04:05Z',
								'clientIP'              => '203.0.113.7',
								'clientCountryName'     => 'US',
								'clientRequestHTTPHost' => 'example.com',
								'clientRequestPath'     => '/wp-login.php',
								'source'                => 'firewallcustom',
								'ruleId'                => 'abc',
								'userAgent'             => 'curl/8',
							),
						),
					),
				),
			),
		);
		$rows = Blt_Secure_Cf_Events::parse( $data );
		$this->assertCount( 1, $rows );
		$this->assertSame( 'cloudflare', $rows[0]['source'] );
		$this->assertSame( 'block', $rows[0]['action'] );
		$this->assertSame( '203.0.113.7', $rows[0]['ip'] );
		$this->assertSame( '/wp-login.php', $rows[0]['path'] );
		$this->assertSame( strtotime( '2026-01-02T03:04:05Z' ), $rows[0]['time'] );
	}

	public function test_parse_handles_empty_or_missing() {
		$this->assertSame( array(), Blt_Secure_Cf_Events::parse( array() ) );
		$this->assertSame( array(), Blt_Secure_Cf_Events::parse( array( 'viewer' => array( 'zones' => array() ) ) ) );
	}

	public function test_merge_orders_newest_first_and_caps() {
		$local = array(
			array( 'type' => 'lockout', 'context' => array( 'ip' => '1.1.1.1' ), 'time' => 100 ),
			array( 'type' => 'blocked_upload', 'context' => array(), 'time' => 300 ),
		);
		$cf = array(
			array( 'time' => 200, 'source' => 'cloudflare', 'action' => 'block' ),
			array( 'time' => 400, 'source' => 'cloudflare', 'action' => 'challenge' ),
		);

		$merged = Blt_Secure_Cf_Events::merge( $local, $cf, 10 );
		$this->assertCount( 4, $merged );
		$this->assertSame( array( 400, 300, 200, 100 ), array_column( $merged, 'time' ) );
		$this->assertSame( 'cloudflare', $merged[0]['source'] );
		$this->assertSame( 'local', $merged[1]['source'] );

		$capped = Blt_Secure_Cf_Events::merge( $local, $cf, 2 );
		$this->assertCount( 2, $capped );
		$this->assertSame( 400, $capped[0]['time'] );
	}

	public function test_merge_normalizes_local_shape() {
		$merged = Blt_Secure_Cf_Events::merge(
			array( array( 'type' => 'activity_admin_granted', 'context' => array( 'user' => 'bob' ), 'time' => 50 ) ),
			array(),
			10
		);
		$this->assertSame( 'local', $merged[0]['source'] );
		$this->assertSame( 'activity_admin_granted', $merged[0]['action'] );
		$this->assertSame( array( 'user' => 'bob' ), $merged[0]['context'] );
	}
}
