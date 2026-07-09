<?php
/**
 * Core scanner pure-logic tests (classify, unknown-files, scope).
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure_Core_Scanner static helpers.
 */
class Test_Core_Scanner extends TestCase {

	public function test_classify_missing_when_actual_null() {
		$this->assertSame(
			Blt_Secure_Core_Scanner::STATUS_MISSING,
			Blt_Secure_Core_Scanner::classify( 'abc123', null )
		);
	}

	public function test_classify_modified_when_hash_differs() {
		$this->assertSame(
			Blt_Secure_Core_Scanner::STATUS_MODIFIED,
			Blt_Secure_Core_Scanner::classify( 'abc123', 'def456' )
		);
	}

	public function test_classify_ok_when_hash_matches() {
		$this->assertSame( '', Blt_Secure_Core_Scanner::classify( 'abc123', 'abc123' ) );
	}

	public function test_unknown_files_returns_only_unlisted() {
		$known = array( 'wp-admin/index.php', 'wp-includes/version.php' );
		$found = array( 'wp-admin/index.php', 'wp-includes/version.php', 'wp-includes/evil.php' );

		$this->assertSame(
			array( 'wp-includes/evil.php' ),
			array_values( Blt_Secure_Core_Scanner::unknown_files( $found, $known ) )
		);
	}

	public function test_unknown_files_empty_when_all_known() {
		$known = array( 'wp-admin/index.php' );
		$found = array( 'wp-admin/index.php' );
		$this->assertSame( array(), Blt_Secure_Core_Scanner::unknown_files( $found, $known ) );
	}

	public function test_wp_content_paths_are_out_of_scope() {
		$this->assertFalse( Blt_Secure_Core_Scanner::in_scope( 'wp-content/themes/twentytwentyfour/style.css' ) );
		$this->assertFalse( Blt_Secure_Core_Scanner::in_scope( 'wp-content/plugins/akismet/akismet.php' ) );
	}

	public function test_core_paths_are_in_scope() {
		$this->assertTrue( Blt_Secure_Core_Scanner::in_scope( 'wp-admin/index.php' ) );
		$this->assertTrue( Blt_Secure_Core_Scanner::in_scope( 'wp-includes/version.php' ) );
		$this->assertTrue( Blt_Secure_Core_Scanner::in_scope( 'wp-load.php' ) );
	}
}
