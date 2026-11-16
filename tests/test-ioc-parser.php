<?php
/**
 * IOC feed parser + IOC rule payload tests.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure_Ioc_Parser pure parsing/validation.
 */
class Test_Ioc_Parser extends TestCase {

	public function test_ip_list_extracts_cidrs_and_skips_comments() {
		$body = "; Spamhaus DROP\n"
			. "# another comment\n"
			. "1.2.3.0/24 ; SBL123\n"
			. "203.0.113.4\n"
			. "\n"
			. "not-an-ip\n"
			. "10.0.0.0/8\n";
		$ips = Blt_Secure_Ioc_Parser::parse_ip_list( $body );

		$this->assertContains( '1.2.3.0/24', $ips );
		$this->assertContains( '203.0.113.4', $ips );
		// Private/reserved space and too-coarse ranges are never blockable.
		$this->assertNotContains( '10.0.0.0/8', $ips );
		$this->assertNotContains( 'not-an-ip', $ips );
		$this->assertCount( 2, $ips );
	}

	public function test_ioc_json_keyed_object_form() {
		$body = wp_json_encode(
			array(
				'1001' => array(
					array( 'ioc_type' => 'ip:port', 'ioc_value' => '198.51.100.5:443' ),
					array( 'ioc_type' => 'domain', 'ioc_value' => 'evil.example' ),
				),
				'1002' => array(
					array( 'ioc_type' => 'ip:port', 'ioc_value' => '203.0.113.9:8080' ),
				),
			)
		);
		$ips = Blt_Secure_Ioc_Parser::parse_ioc_json( $body );

		$this->assertContains( '198.51.100.5', $ips );
		$this->assertContains( '203.0.113.9', $ips );
		$this->assertNotContains( 'evil.example', $ips );
		$this->assertCount( 2, $ips );
	}

	public function test_ioc_json_ignores_non_ip_and_bad_json() {
		$this->assertSame( array(), Blt_Secure_Ioc_Parser::parse_ioc_json( 'not json' ) );
		$this->assertSame( array(), Blt_Secure_Ioc_Parser::parse_ioc_json( wp_json_encode( array( 'x' => array( array( 'ioc_type' => 'url', 'ioc_value' => 'http://x' ) ) ) ) ) );
	}

	public function test_parse_dedupes_across_formats() {
		$body = "203.0.113.4\n203.0.113.4\n";
		$this->assertCount( 1, Blt_Secure_Ioc_Parser::parse( 'ip-list', $body ) );
	}

	public function test_strip_port() {
		$this->assertSame( '1.2.3.4', Blt_Secure_Ioc_Parser::strip_port( '1.2.3.4:443' ) );
		$this->assertSame( '1.2.3.4', Blt_Secure_Ioc_Parser::strip_port( '1.2.3.4' ) );
		$this->assertSame( '2001:db8::1', Blt_Secure_Ioc_Parser::strip_port( '[2001:db8::1]:443' ) );
	}

	public function test_ip_validation() {
		$this->assertTrue( Blt_Secure_Ioc_Parser::is_valid_ip_or_cidr( '8.8.8.8' ) );
		$this->assertTrue( Blt_Secure_Ioc_Parser::is_valid_ip_or_cidr( '2001:db8::1' ) );
		$this->assertTrue( Blt_Secure_Ioc_Parser::is_valid_ip_or_cidr( '10.0.0.0/8' ) );
		$this->assertTrue( Blt_Secure_Ioc_Parser::is_valid_ip_or_cidr( '2001:db8::/32' ) );
		$this->assertFalse( Blt_Secure_Ioc_Parser::is_valid_ip_or_cidr( '10.0.0.0/33' ) );
		$this->assertFalse( Blt_Secure_Ioc_Parser::is_valid_ip_or_cidr( '999.1.1.1' ) );
		$this->assertFalse( Blt_Secure_Ioc_Parser::is_valid_ip_or_cidr( 'abc' ) );
		$this->assertFalse( Blt_Secure_Ioc_Parser::is_valid_ip_or_cidr( '1.2.3.4/x' ) );
	}
}

/**
 * Feed-entry policy: Cloudflare list limits, blockability, protection, cap.
 */
class Test_Ioc_Policy extends TestCase {

	public function test_cloudflare_list_prefix_range() {
		// https://developers.cloudflare.com/waf/tools/lists/custom-lists/ : IPv4 /8-/32, IPv6 /12-/128.
		$this->assertTrue( Blt_Secure_Ioc_Parser::is_cf_list_item( '8.0.0.0/8' ) );
		$this->assertTrue( Blt_Secure_Ioc_Parser::is_cf_list_item( '1.2.3.4' ) );
		$this->assertFalse( Blt_Secure_Ioc_Parser::is_cf_list_item( '8.0.0.0/7' ) );
		$this->assertFalse( Blt_Secure_Ioc_Parser::is_cf_list_item( '0.0.0.0/0' ) );
		$this->assertTrue( Blt_Secure_Ioc_Parser::is_cf_list_item( '2600::/12' ) );
		$this->assertFalse( Blt_Secure_Ioc_Parser::is_cf_list_item( '2600::/11' ) );
		$this->assertFalse( Blt_Secure_Ioc_Parser::is_cf_list_item( 'junk' ) );
	}

	public function test_blockable_rejects_default_routes_private_reserved_and_coarse_ranges() {
		foreach ( array( '0.0.0.0/0', '::/0', '0.0.0.0', '10.1.2.3', '172.16.0.0/16', '192.168.0.0/16', '127.0.0.1', '169.254.1.1', '100.64.0.0/16', '224.0.0.1', '8.0.0.0/8', '1.0.0.0/15', 'fc00::1', '::1', 'fe80::1', 'ff02::1', '::ffff:1.2.3.4', '2a00::/31' ) as $ip ) {
			$this->assertFalse( Blt_Secure_Ioc_Parser::is_blockable( $ip ), $ip );
		}
		foreach ( array( '8.8.8.8', '1.2.0.0/16', '203.0.113.4', '2a00:1450::/32', '2606:4700::1' ) as $ip ) {
			$this->assertTrue( Blt_Secure_Ioc_Parser::is_blockable( $ip ), $ip );
		}
	}

	public function test_accept_normalizes_host_bits_and_ipv6() {
		$this->assertSame( '1.2.3.0/24', Blt_Secure_Ioc_Parser::accept( '1.2.3.77/24' ) );
		$this->assertSame( '2a00:1450::/32', Blt_Secure_Ioc_Parser::accept( '2A00:1450:0000::/32' ) );
		$this->assertSame( '8.8.8.8', Blt_Secure_Ioc_Parser::accept( '8.8.8.8' ) );
		$this->assertSame( '', Blt_Secure_Ioc_Parser::accept( '10.0.0.0/8' ) );
		$this->assertSame( '', Blt_Secure_Ioc_Parser::accept( 'nope' ) );
	}

	public function test_ioc_json_applies_the_same_policy() {
		$body = wp_json_encode(
			array(
				'1' => array(
					array( 'ioc_type' => 'ip:port', 'ioc_value' => '10.0.0.5:443' ),
					array( 'ioc_type' => 'ip:port', 'ioc_value' => '198.51.100.5:443' ),
				),
			)
		);
		$this->assertSame( array( '198.51.100.5' ), Blt_Secure_Ioc_Parser::parse_ioc_json( $body ) );
	}

	public function test_drop_protected_removes_entries_that_would_block_us() {
		$entries = array( '203.0.113.7', '198.51.100.0/24', '104.16.0.0/13', '104.17.5.5', '162.158.0.0/16', '8.8.8.8', '9.9.0.0/16' );
		$kept    = Blt_Secure_Ioc_Parser::drop_protected(
			$entries,
			array( '198.51.100.20', '' ),
			array( '104.16.0.0/13', '172.64.0.0/13' )
		);
		// 198.51.100.0/24 contains the admin IP; 104.16.0.0/13 and 104.17.5.5 are Cloudflare;
		// 162.158.0.0/16 sits inside nothing protected here so it survives.
		$this->assertSame( array( '203.0.113.7', '162.158.0.0/16', '8.8.8.8', '9.9.0.0/16' ), $kept );

		// An entry COARSER than a protected range (it contains the whole range) is dropped too.
		$this->assertSame( array(), Blt_Secure_Ioc_Parser::drop_protected( array( '104.0.0.0/8' ), array(), array( '104.16.0.0/13' ) ) );
	}

	public function test_prioritize_for_cap_keeps_cidrs_before_single_hosts() {
		$ips = array( '9.9.9.1', '9.9.9.2', '1.2.0.0/16', '9.9.9.3', '5.0.0.0/12', '9.9.9.4' );
		// Under the cap: untouched order.
		$this->assertSame( $ips, Blt_Secure_Ioc_Parser::prioritize_for_cap( $ips, 10 ) );
		// Over the cap: largest CIDRs first, then hosts in feed order.
		$this->assertSame( array( '5.0.0.0/12', '1.2.0.0/16', '9.9.9.1' ), Blt_Secure_Ioc_Parser::prioritize_for_cap( $ips, 3 ) );
	}
}

/**
 * IOC firewall rule payload.
 */
class Test_Ioc_Rule extends TestCase {

	public function test_ioc_block_rule_references_the_named_list() {
		$rules = Blt_Secure_Rule_Definitions::ioc_block_rules();
		$this->assertArrayHasKey( 'block', $rules );
		$rule = $rules['block'];

		$this->assertSame( 'blt-secure-ioc-block', $rule['ref'] );
		$this->assertSame( 'block', $rule['action'] );
		$this->assertSame( '(ip.src in $blt_secure_iocs)', $rule['expression'] );
		$this->assertStringContainsString( 'BLT Secure', $rule['description'] );
	}
}
