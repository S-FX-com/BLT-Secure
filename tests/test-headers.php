<?php
/**
 * Security-header value handling.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure_Headers pure helpers.
 */
class Test_Headers extends TestCase {

	public function test_multiline_csp_collapses_to_one_line() {
		$policy = "default-src 'self';\r\nscript-src 'self' https://cdn.example.com;\n\timg-src 'self' data:";
		$this->assertSame(
			"default-src 'self'; script-src 'self' https://cdn.example.com; img-src 'self' data:",
			Blt_Secure_Headers::normalize_header_value( $policy )
		);
	}

	public function test_result_can_never_contain_a_newline_or_control_byte() {
		$value = Blt_Secure_Headers::normalize_header_value( "a\r\nSet-Cookie: x=1\0b" );
		$this->assertDoesNotMatchRegularExpression( '/[\x00-\x1f]/', $value );
	}

	public function test_non_scalar_and_empty_values_become_empty() {
		$this->assertSame( '', Blt_Secure_Headers::normalize_header_value( array( 'x' ) ) );
		$this->assertSame( '', Blt_Secure_Headers::normalize_header_value( "  \n " ) );
		$this->assertSame( 'SAMEORIGIN', Blt_Secure_Headers::normalize_header_value( 'SAMEORIGIN' ) );
	}
}
