<?php
/**
 * Trust-badge render tests.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure_Badge::render() pure helper.
 */
class Test_Badge extends TestCase {

	public function test_render_shows_label_and_shield() {
		$html = Blt_Secure_Badge::render( 'Protected by BLT Secure' );
		$this->assertStringContainsString( 'Protected by BLT Secure', $html );
		$this->assertStringContainsString( '<svg', $html );
		$this->assertStringContainsString( 'blt-secure-badge', $html );
	}

	public function test_render_escapes_label() {
		$html = Blt_Secure_Badge::render( '<script>alert(1)</script>' );
		$this->assertStringNotContainsString( '<script>', $html );
		$this->assertStringContainsString( '&lt;script&gt;', $html );
	}

	public function test_render_falls_back_on_empty_label() {
		$this->assertStringContainsString( 'Protected by BLT Secure', Blt_Secure_Badge::render( '   ' ) );
	}

	public function test_render_discloses_no_security_specifics() {
		$html = strtolower( Blt_Secure_Badge::render( 'Protected by BLT Secure', 'dark' ) );
		foreach ( array( 'score', 'version', 'finding', 'vulnerab', 'fail', 'pass' ) as $needle ) {
			$this->assertStringNotContainsString( $needle, $html );
		}
	}
}
