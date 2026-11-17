<?php
/**
 * CIDR matcher tests.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure_Ip_Resolver pure functions.
 */
class Test_Ip_Resolver extends TestCase {

	public function test_ipv4_in_range() {
		$this->assertTrue( Blt_Secure_Ip_Resolver::ip_in_ranges( '104.16.1.1', array( '104.16.0.0/13' ) ) );
		$this->assertTrue( Blt_Secure_Ip_Resolver::ip_in_ranges( '104.23.255.255', array( '104.16.0.0/13' ) ) );
		$this->assertFalse( Blt_Secure_Ip_Resolver::ip_in_ranges( '104.24.0.0', array( '104.16.0.0/13' ) ) );
		$this->assertFalse( Blt_Secure_Ip_Resolver::ip_in_ranges( '8.8.8.8', array( '104.16.0.0/13' ) ) );
	}

	public function test_ipv4_non_octet_boundary() {
		// /20: 173.245.48.0 – 173.245.63.255.
		$this->assertTrue( Blt_Secure_Ip_Resolver::ip_in_ranges( '173.245.48.1', array( '173.245.48.0/20' ) ) );
		$this->assertTrue( Blt_Secure_Ip_Resolver::ip_in_ranges( '173.245.63.254', array( '173.245.48.0/20' ) ) );
		$this->assertFalse( Blt_Secure_Ip_Resolver::ip_in_ranges( '173.245.64.1', array( '173.245.48.0/20' ) ) );
		$this->assertFalse( Blt_Secure_Ip_Resolver::ip_in_ranges( '173.245.47.255', array( '173.245.48.0/20' ) ) );
	}

	public function test_ipv6_in_range() {
		$this->assertTrue( Blt_Secure_Ip_Resolver::ip_in_ranges( '2606:4700::1', array( '2606:4700::/32' ) ) );
		$this->assertTrue( Blt_Secure_Ip_Resolver::ip_in_ranges( '2606:4700:ffff::1', array( '2606:4700::/32' ) ) );
		$this->assertFalse( Blt_Secure_Ip_Resolver::ip_in_ranges( '2606:4701::1', array( '2606:4700::/32' ) ) );
		// /29 crosses a nibble boundary.
		$this->assertTrue( Blt_Secure_Ip_Resolver::ip_in_ranges( '2a06:98c7::1', array( '2a06:98c0::/29' ) ) );
		$this->assertFalse( Blt_Secure_Ip_Resolver::ip_in_ranges( '2a06:98c8::1', array( '2a06:98c0::/29' ) ) );
	}

	public function test_family_mismatch_never_matches() {
		$this->assertFalse( Blt_Secure_Ip_Resolver::ip_in_ranges( '104.16.1.1', array( '2606:4700::/32' ) ) );
		$this->assertFalse( Blt_Secure_Ip_Resolver::ip_in_ranges( '2606:4700::1', array( '104.16.0.0/13' ) ) );
	}

	public function test_garbage_input() {
		$this->assertFalse( Blt_Secure_Ip_Resolver::ip_in_ranges( 'not-an-ip', array( '104.16.0.0/13' ) ) );
		$this->assertFalse( Blt_Secure_Ip_Resolver::ip_in_ranges( '', array( '104.16.0.0/13' ) ) );
		$this->assertFalse( Blt_Secure_Ip_Resolver::ip_in_ranges( '104.16.1.1', array( 'garbage', '' ) ) );
		$this->assertFalse( Blt_Secure_Ip_Resolver::ip_in_ranges( '104.16.1.1', array() ) );
	}

	public function test_shipped_ranges_are_valid() {
		foreach ( Blt_Secure_Ip_Resolver::CF_RANGES as $cidr ) {
			$this->assertTrue( Blt_Secure_Ip_Resolver::is_valid_cidr( $cidr ), "Invalid shipped CIDR: $cidr" );
		}
	}

	public function test_is_valid_cidr() {
		$this->assertTrue( Blt_Secure_Ip_Resolver::is_valid_cidr( '10.0.0.0/8' ) );
		$this->assertTrue( Blt_Secure_Ip_Resolver::is_valid_cidr( '2606:4700::/32' ) );
		$this->assertFalse( Blt_Secure_Ip_Resolver::is_valid_cidr( '10.0.0.0' ) );
		$this->assertFalse( Blt_Secure_Ip_Resolver::is_valid_cidr( '10.0.0.0/33' ) );
		$this->assertFalse( Blt_Secure_Ip_Resolver::is_valid_cidr( 'x/8' ) );
		$this->assertFalse( Blt_Secure_Ip_Resolver::is_valid_cidr( '10.0.0.0/abc' ) );
	}

	public function test_network_key_keeps_ipv4_and_truncates_ipv6_to_slash_64() {
		$this->assertSame( '203.0.113.7', Blt_Secure_Ip_Resolver::network_key( '203.0.113.7' ) );
		$this->assertSame( '2001:db8:1:2::/64', Blt_Secure_Ip_Resolver::network_key( '2001:db8:1:2:3:4:5:6' ) );
		$this->assertSame( Blt_Secure_Ip_Resolver::network_key( '2001:db8:1:2::1' ), Blt_Secure_Ip_Resolver::network_key( '2001:db8:1:2:ffff:ffff:ffff:ffff' ) );
		$this->assertNotSame( Blt_Secure_Ip_Resolver::network_key( '2001:db8:1:2::1' ), Blt_Secure_Ip_Resolver::network_key( '2001:db8:1:3::1' ) );
	}

	public function test_network_key_unmaps_ipv4_mapped_addresses_and_rejects_garbage() {
		$this->assertSame( '203.0.113.7', Blt_Secure_Ip_Resolver::network_key( '::ffff:203.0.113.7' ) );
		$this->assertSame( '', Blt_Secure_Ip_Resolver::network_key( 'not-an-ip' ) );
		$this->assertSame( '', Blt_Secure_Ip_Resolver::network_key( '' ) );
	}

	public function test_ipv4_mapped_peer_matches_cloudflare_ipv4_range() {
		$this->assertTrue( Blt_Secure_Ip_Resolver::ip_in_ranges( '::ffff:104.16.1.1', array( '104.16.0.0/13' ) ) );
		$this->assertFalse( Blt_Secure_Ip_Resolver::ip_in_ranges( '::ffff:8.8.8.8', array( '104.16.0.0/13' ) ) );
	}
}
