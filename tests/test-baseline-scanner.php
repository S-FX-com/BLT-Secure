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
