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
		$this->assertContains( '10.0.0.0/8', $ips );
		$this->assertNotContains( 'not-an-ip', $ips );
		$this->assertCount( 3, $ips );
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
