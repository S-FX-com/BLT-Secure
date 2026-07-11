<?php
/**
 * Baseline diff + YARA helper tests.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure_Baseline_Scanner pure logic.
 */
class Test_Baseline_Scanner extends TestCase {

	public function test_diff_detects_added_modified_removed() {
		$old  = array( 'a.php' => 'h1', 'b.php' => 'h2', 'c.php' => 'h3' );
		$new  = array( 'a.php' => 'h1', 'b.php' => 'CHANGED', 'd.php' => 'h4' );
		$diff = Blt_Secure_Baseline_Scanner::diff( $old, $new );

		$this->assertSame( array( 'd.php' ), $diff['added'] );
		$this->assertSame( array( 'b.php' ), $diff['modified'] );
		$this->assertSame( array( 'c.php' ), $diff['removed'] );
	}

	public function test_diff_clean_when_identical() {
		$map  = array( 'a.php' => 'h1', 'b.php' => 'h2' );
		$diff = Blt_Secure_Baseline_Scanner::diff( $map, $map );
		$this->assertFalse( Blt_Secure_Baseline_Scanner::has_changes( $diff ) );
	}

	public function test_has_changes() {
		$this->assertTrue( Blt_Secure_Baseline_Scanner::has_changes( array( 'added' => array( 'x' ), 'modified' => array(), 'removed' => array() ) ) );
		$this->assertFalse( Blt_Secure_Baseline_Scanner::has_changes( array( 'added' => array(), 'modified' => array(), 'removed' => array() ) ) );
	}

	public function test_is_hashable() {
		$this->assertTrue( Blt_Secure_Baseline_Scanner::is_hashable( 'x/foo.php' ) );
		$this->assertTrue( Blt_Secure_Baseline_Scanner::is_hashable( 'x/foo.inc' ) );
		$this->assertFalse( Blt_Secure_Baseline_Scanner::is_hashable( 'x/style.css' ) );
		$this->assertFalse( Blt_Secure_Baseline_Scanner::is_hashable( 'x/photo.png' ) );
	}

	public function test_drift_fingerprint_is_order_independent_and_stable() {
		$hashes = array( 'a.php' => 'h1', 'b.php' => 'h2' );
		$fp1    = Blt_Secure_Baseline_Scanner::drift_fingerprint( 'plugin/acme', '1.0', array( 'a.php', 'b.php' ), $hashes );
		$fp2    = Blt_Secure_Baseline_Scanner::drift_fingerprint( 'plugin/acme', '1.0', array( 'b.php', 'a.php' ), $hashes );
		$this->assertSame( $fp1, $fp2, 'File order must not change the fingerprint.' );
		$this->assertMatchesRegularExpression( '/^[a-f0-9]{40}$/', $fp1 );
	}

	public function test_drift_fingerprint_changes_when_a_whitelisted_file_is_modified_again() {
		// An admin accepts (ignores) a drift; the fingerprint must change if
		// one of those files is later altered again — otherwise a backdoor
		// edited into an accepted change would stay suppressed forever.
		$before = Blt_Secure_Baseline_Scanner::drift_fingerprint( 'plugin/acme', '1.0', array( 'a.php' ), array( 'a.php' => 'clean-hash' ) );
		$after  = Blt_Secure_Baseline_Scanner::drift_fingerprint( 'plugin/acme', '1.0', array( 'a.php' ), array( 'a.php' => 'evil-hash' ) );
		$this->assertNotSame( $before, $after );
	}

	public function test_drift_fingerprint_varies_by_extension_and_version() {
		$hashes = array( 'a.php' => 'h1' );
		$base   = Blt_Secure_Baseline_Scanner::drift_fingerprint( 'plugin/acme', '1.0', array( 'a.php' ), $hashes );
		$this->assertNotSame( $base, Blt_Secure_Baseline_Scanner::drift_fingerprint( 'plugin/other', '1.0', array( 'a.php' ), $hashes ) );
		$this->assertNotSame( $base, Blt_Secure_Baseline_Scanner::drift_fingerprint( 'plugin/acme', '2.0', array( 'a.php' ), $hashes ) );
	}
}

/**
 * Blt_Secure_Yara capability wrapper.
 */
class Test_Yara extends TestCase {

	public function test_disabled_without_ruleset_by_default() {
		// No ruleset path is configured by default, so YARA is inert even if
		// the extension happens to be present.
		$this->assertSame( '', Blt_Secure_Yara::rules_path() );
		$this->assertFalse( Blt_Secure_Yara::enabled() );
	}

	public function test_scan_file_returns_empty_when_disabled() {
		$this->assertSame( array(), Blt_Secure_Yara::scan_file( __FILE__ ) );
	}

	public function test_rule_names_normalizes_shapes() {
		$matches = array(
			'RuleA',
			array( 'rule' => 'RuleB' ),
			(object) array( 'rule' => 'RuleC' ),
			array( 'norule' => 'x' ),
			'RuleA',
		);
		$this->assertSame( array( 'RuleA', 'RuleB', 'RuleC' ), Blt_Secure_Yara::rule_names( $matches ) );
	}
}
