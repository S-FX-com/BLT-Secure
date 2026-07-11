<?php
/**
 * One-click health-fix tests: applying a fix must make its check pass.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure_Health_Fixes registry + remediations.
 */
class Test_Health_Fixes extends TestCase {

	/**
	 * Reset the in-memory option store before each test.
	 *
	 * @return void
	 */
	protected function setUp(): void {
		$GLOBALS['blt_test_options'] = array();
	}

	public function test_every_fix_has_a_label_and_callable() {
		foreach ( Blt_Secure_Health_Fixes::all() as $id => $fix ) {
			$this->assertNotSame( '', (string) $fix['label'], "Fix {$id} has no label" );
			$this->assertTrue( is_callable( $fix['callback'] ), "Fix {$id} is not callable" );
		}
	}

	public function test_is_fixable_only_for_registered_checks() {
		$this->assertTrue( Blt_Secure_Health_Fixes::is_fixable( 'login_lockout' ) );
		$this->assertTrue( Blt_Secure_Health_Fixes::is_fixable( 'header_nosniff' ) );
		// Not fixable from the plugin (wp-config constant, updates, no lever).
		$this->assertFalse( Blt_Secure_Health_Fixes::is_fixable( 'wp_debug_off' ) );
		$this->assertFalse( Blt_Secure_Health_Fixes::is_fixable( 'plugins_updated' ) );
		$this->assertFalse( Blt_Secure_Health_Fixes::is_fixable( 'header_permissions' ) );
		// HSTS (is_ssl() at the origin) and CSP (Report-Only can't clear the
		// warning; enforcing risks breakage) are intentionally not auto-fixed.
		$this->assertFalse( Blt_Secure_Health_Fixes::is_fixable( 'header_hsts' ) );
		$this->assertFalse( Blt_Secure_Health_Fixes::is_fixable( 'header_csp' ) );
		$this->assertFalse( Blt_Secure_Health_Fixes::is_fixable( 'nope' ) );
	}

	public function test_apply_unknown_check_returns_wp_error() {
		$result = Blt_Secure_Health_Fixes::apply( 'not_a_check', new Blt_Secure_Options() );
		$this->assertInstanceOf( 'WP_Error', $result );
	}

	/**
	 * The core promise: for each settings-driven fix, the matching check must
	 * NOT pass beforehand and MUST pass after the fix is applied.
	 */
	public function test_settings_fixes_make_their_check_pass() {
		$pass = Blt_Secure_Health_Result::PASS;

		$cases = array(
			// id => precondition callback (make the check fail first).
			'login_lockout'         => null,
			'enumeration_blocked'   => null,
			'file_edit_disabled'    => null,
			'file_managers_blocked' => null,
			'two_factor'            => null,
			'xmlrpc_disabled'       => static function ( $options ) {
				$options->update_section( 'xmlrpc', array( 'enabled' => true ) );
			},
			'registration_off'      => static function () {
				update_option( 'users_can_register', 1 );
			},
		);

		foreach ( $cases as $id => $precondition ) {
			$GLOBALS['blt_test_options'] = array();
			$options                     = new Blt_Secure_Options();
			if ( $precondition ) {
				$precondition( $options );
			}

			$before = call_user_func( array( 'Blt_Secure_Health_Checks', $id ), new Blt_Secure_Health_Context( $options ) );
			$this->assertNotSame( $pass, $before['status'], "{$id} should not pass before the fix" );

			$this->assertTrue( Blt_Secure_Health_Fixes::apply( $id, $options ), "{$id} fix did not succeed" );

			$after = call_user_func( array( 'Blt_Secure_Health_Checks', $id ), new Blt_Secure_Health_Context( $options ) );
			$this->assertSame( $pass, $after['status'], "{$id} should pass after the fix" );
		}
	}

	public function test_header_fix_enables_the_module_and_the_specific_header() {
		$options = new Blt_Secure_Options();
		$this->assertTrue( Blt_Secure_Health_Fixes::apply( 'header_nosniff', $options ) );
		$this->assertTrue( (bool) $options->get( 'headers', 'enabled' ) );
		$this->assertTrue( (bool) $options->get( 'headers', 'nosniff' ) );
	}

	public function test_dropped_header_fixes_are_not_applied() {
		// CSP and HSTS were removed from the catalogue; applying them errors.
		$this->assertInstanceOf( 'WP_Error', Blt_Secure_Health_Fixes::apply( 'header_csp', new Blt_Secure_Options() ) );
		$this->assertInstanceOf( 'WP_Error', Blt_Secure_Health_Fixes::apply( 'header_hsts', new Blt_Secure_Options() ) );
	}

	public function test_set_section_preserves_other_saved_keys() {
		$options = new Blt_Secure_Options();
		$options->update_section( 'fileguard', array( 'block_file_managers' => true, 'custom_flag' => 'keep' ) );
		Blt_Secure_Health_Fixes::apply( 'file_edit_disabled', $options );
		$this->assertTrue( (bool) $options->get( 'fileguard', 'disallow_file_edit' ) );
		// The unrelated key we saved earlier must survive the fix.
		$this->assertSame( 'keep', $options->get( 'fileguard', 'custom_flag' ) );
		$this->assertTrue( (bool) $options->get( 'fileguard', 'block_file_managers' ) );
	}

	public function test_uploads_index_without_wp_uploads_returns_error() {
		// wp_upload_dir() is not shimmed in the test bootstrap.
		$result = Blt_Secure_Health_Fixes::apply( 'uploads_index', new Blt_Secure_Options() );
		$this->assertInstanceOf( 'WP_Error', $result );
	}
}
