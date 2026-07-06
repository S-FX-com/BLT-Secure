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
}
