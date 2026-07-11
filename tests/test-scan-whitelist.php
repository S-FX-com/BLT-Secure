<?php
/**
 * Scanner finding whitelist tests.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure_Scan_Whitelist store + pure fingerprint helpers.
 */
class Test_Scan_Whitelist extends TestCase {

	/**
	 * Reset the in-memory option store before each test.
	 *
	 * @return void
	 */
	protected function setUp(): void {
		$GLOBALS['blt_test_options'] = array();
	}

	public function test_fingerprint_is_deterministic() {
		$a = Blt_Secure_Scan_Whitelist::fingerprint( 'core', array( 'modified', 'wp-load.php', 'abc' ) );
		$b = Blt_Secure_Scan_Whitelist::fingerprint( 'core', array( 'modified', 'wp-load.php', 'abc' ) );
		$this->assertSame( $a, $b );
		$this->assertMatchesRegularExpression( '/^[a-f0-9]{40}$/', $a );
	}

	public function test_fingerprint_varies_by_scanner_and_parts() {
		$core = Blt_Secure_Scan_Whitelist::fingerprint( 'core', array( 'modified', 'x.php', 'h' ) );
		$mal  = Blt_Secure_Scan_Whitelist::fingerprint( 'malware', array( 'modified', 'x.php', 'h' ) );
		$this->assertNotSame( $core, $mal, 'Scanner id must namespace the fingerprint.' );

		$h1 = Blt_Secure_Scan_Whitelist::fingerprint( 'core', array( 'modified', 'x.php', 'hash1' ) );
		$h2 = Blt_Secure_Scan_Whitelist::fingerprint( 'core', array( 'modified', 'x.php', 'hash2' ) );
		$this->assertNotSame( $h1, $h2, 'A different content hash must re-flag.' );
	}

	public function test_is_valid_fingerprint() {
		$this->assertTrue( Blt_Secure_Scan_Whitelist::is_valid_fingerprint( str_repeat( 'a', 40 ) ) );
		$this->assertFalse( Blt_Secure_Scan_Whitelist::is_valid_fingerprint( 'short' ) );
		$this->assertFalse( Blt_Secure_Scan_Whitelist::is_valid_fingerprint( str_repeat( 'A', 40 ) ) ); // uppercase.
		$this->assertFalse( Blt_Secure_Scan_Whitelist::is_valid_fingerprint( str_repeat( 'z', 40 ) ) ); // non-hex.
		$this->assertFalse( Blt_Secure_Scan_Whitelist::is_valid_fingerprint( '' ) );
	}

	public function test_add_is_whitelisted_and_remove_round_trip() {
		$wl = new Blt_Secure_Scan_Whitelist();
		$fp = Blt_Secure_Scan_Whitelist::fingerprint( 'malware', array( 'signature', 'a.php', 'md5', 'desc' ) );

		$this->assertFalse( $wl->is_whitelisted( $fp ) );
		$this->assertTrue( $wl->add( $fp, array( 'scanner' => 'malware', 'label' => 'a.php', 'time' => 100, 'user' => 3 ) ) );
		$this->assertTrue( $wl->is_whitelisted( $fp ) );

		$all = $wl->all();
		$this->assertArrayHasKey( $fp, $all );
		$this->assertSame( 'malware', $all[ $fp ]['scanner'] );
		$this->assertSame( 3, $all[ $fp ]['user'] );

		$this->assertTrue( $wl->remove( $fp ) );
		$this->assertFalse( $wl->is_whitelisted( $fp ) );
		$this->assertFalse( $wl->remove( $fp ) ); // Second remove is a no-op.
	}

	public function test_add_rejects_invalid_fingerprint() {
		$wl = new Blt_Secure_Scan_Whitelist();
		$this->assertFalse( $wl->add( 'not-a-fingerprint' ) );
		$this->assertSame( array(), $wl->all() );
	}

	public function test_active_and_ignored_partition_by_fingerprint() {
		$wl = new Blt_Secure_Scan_Whitelist();
		$fp = Blt_Secure_Scan_Whitelist::fingerprint( 'core', array( 'modified', 'kept.php', 'h' ) );
		$wl->add( $fp );

		$findings = array(
			array( 'path' => 'kept.php', 'fingerprint' => $fp ),
			array( 'path' => 'other.php', 'fingerprint' => Blt_Secure_Scan_Whitelist::fingerprint( 'core', array( 'modified', 'other.php', 'h' ) ) ),
			array( 'path' => 'nofp.php' ), // No fingerprint → always active.
		);

		$active  = $wl->active( $findings );
		$ignored = $wl->ignored( $findings );

		$this->assertCount( 2, $active );
		$this->assertCount( 1, $ignored );
		$this->assertSame( 'kept.php', $ignored[0]['path'] );
		$this->assertSame( 2, $wl->count_active( $findings ) );

		// Active list contains the un-whitelisted + the no-fingerprint rows.
		$paths = array_column( $active, 'path' );
		$this->assertContains( 'other.php', $paths );
		$this->assertContains( 'nofp.php', $paths );
		$this->assertNotContains( 'kept.php', $paths );
	}

	public function test_empty_findings_partition_cleanly() {
		$wl = new Blt_Secure_Scan_Whitelist();
		$this->assertSame( array(), $wl->active( array() ) );
		$this->assertSame( array(), $wl->ignored( array() ) );
	}
}
