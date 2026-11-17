<?php
/**
 * Two-factor module: the parts that can run without a WordPress install.
 *
 * The interstitial itself (render + exit) is covered by the manual smoke
 * checklist in tasks/todo.md.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

$GLOBALS['blt_test_cookie_user'] = 0;

if ( ! function_exists( 'wp_validate_auth_cookie' ) ) {
	/**
	 * WP shim: the user the auth cookie validates to.
	 *
	 * @return int
	 */
	function wp_validate_auth_cookie() {
		return $GLOBALS['blt_test_cookie_user'];
	}
}

if ( ! function_exists( 'get_userdata' ) ) {
	/**
	 * WP shim.
	 *
	 * @param int $id User id.
	 * @return object
	 */
	function get_userdata( $id ) {
		$user            = new WP_User( $id, 'user' . $id );
		$user->user_pass = 'hashed:correct horse';
		return $user;
	}
}

if ( ! function_exists( 'wp_check_password' ) ) {
	/**
	 * WP shim: "hash" is just a prefix.
	 *
	 * @param string $password Plain.
	 * @param string $hash     Hash.
	 * @return bool
	 */
	function wp_check_password( $password, $hash ) {
		return 'hashed:' . $password === $hash;
	}
}

/**
 * Blt_Secure_Two_Factor logic tests.
 */
class Test_Two_Factor extends TestCase {

	/**
	 * Module under test.
	 *
	 * @var Blt_Secure_Two_Factor
	 */
	private $module;

	/**
	 * Crypto.
	 *
	 * @var Blt_Secure_Crypto
	 */
	private $crypto;

	/**
	 * Fresh state.
	 *
	 * @return void
	 */
	protected function setUp(): void {
		$GLOBALS['blt_test_options']     = array();
		$GLOBALS['blt_test_transients']  = array();
		$GLOBALS['blt_test_user_meta']   = array();
		$GLOBALS['blt_test_cookie_user'] = 0;

		$options      = new Blt_Secure_Options();
		$this->crypto = new Blt_Secure_Crypto();
		$this->module = new Blt_Secure_Two_Factor( $options, $this->crypto, new Blt_Secure_Alerting( $options ) );
	}

	/**
	 * Enter the XML-RPC context (a constant: it cannot be undone, so only the tests that need
	 * the non-interactive branch call this, and the interstitial-path test runs in its own process).
	 *
	 * @return void
	 */
	private function api_context() {
		if ( ! defined( 'XMLRPC_REQUEST' ) ) {
			define( 'XMLRPC_REQUEST', true );
		}
	}

	/**
	 * Enrol a user with a real encrypted secret.
	 *
	 * @param int $id User id.
	 * @return string Plain base32 secret.
	 */
	private function enrol( $id ) {
		$secret   = Blt_Secure_Totp::generate_secret();
		$envelope = $this->crypto->encrypt( $secret );
		if ( is_wp_error( $envelope ) ) {
			$this->markTestSkipped( 'No authenticated cipher available in this PHP build.' );
		}
		update_user_meta( $id, Blt_Secure_Two_Factor::META_SECRET, $envelope );
		return $secret;
	}

	/**
	 * Call a private method.
	 *
	 * @param string $name Method.
	 * @param array  $args Args.
	 * @return mixed
	 */
	private function call_private( $name, array $args ) {
		$method = new ReflectionMethod( Blt_Secure_Two_Factor::class, $name );
		$method->setAccessible( true );
		return $method->invokeArgs( $this->module, $args );
	}

	public function test_unenrolled_user_passes_through() {
		$user = new WP_User( 7, 'bob' );
		$this->assertSame( $user, $this->module->maybe_interstitial( $user, 'bob', 'pw' ) );
	}

	public function test_api_password_only_login_is_refused_for_enrolled_user() {
		$this->api_context();
		$this->enrol( 7 );
		$user = new WP_User( 7, 'bob' );

		$this->module->begin_authentication( null );
		$result = $this->module->maybe_interstitial( $user, 'bob', 'pw' );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'blt_secure_2fa_required', $result->get_error_code() );
	}

	public function test_application_password_for_that_user_passes() {
		$this->api_context();
		$this->enrol( 7 );
		$user = new WP_User( 7, 'bob' );

		$this->module->begin_authentication( null );
		$this->module->note_app_password_auth( $user );

		$this->assertSame( $user, $this->module->maybe_interstitial( $user, 'bob', 'app-pw' ) );
	}

	/**
	 * system.multicall regression: call 1 authenticates the attacker's OWN
	 * application password; call 2 sends the victim's plain password. The old
	 * did_action() check (request-wide) let call 2 skip 2FA.
	 */
	public function test_another_users_application_password_does_not_vouch_for_victim() {
		$this->api_context();
		$this->enrol( 7 );
		$victim   = new WP_User( 7, 'victim' );
		$attacker = new WP_User( 5, 'attacker' );

		$this->module->begin_authentication( null ); // Call 1.
		$this->module->note_app_password_auth( $attacker );
		$this->assertSame( $attacker, $this->module->maybe_interstitial( $attacker, 'attacker', 'app-pw' ) );

		$this->module->begin_authentication( null ); // Call 2: fresh authenticate() run.
		$result = $this->module->maybe_interstitial( $victim, 'victim', 'victim-password' );
		$this->assertInstanceOf( WP_Error::class, $result );
	}

	public function test_app_password_state_does_not_leak_into_the_next_authenticate_run() {
		$this->api_context();
		$this->enrol( 7 );
		$user = new WP_User( 7, 'bob' );

		$this->module->begin_authentication( null );
		$this->module->note_app_password_auth( $user );
		$this->module->begin_authentication( null ); // Next call in the same request.

		$this->assertInstanceOf( WP_Error::class, $this->module->maybe_interstitial( $user, 'bob', 'plain-pw' ) );
	}

	public function test_cookie_revalidation_with_empty_credentials_is_not_a_password_login() {
		$this->enrol( 7 );
		$user = new WP_User( 7, 'bob' );

		// wp-login.php calls wp_signon() with empty credentials; core's cookie handler answers
		// with the already-logged-in user. No second factor demanded again.
		$GLOBALS['blt_test_cookie_user'] = 7;
		$this->assertSame( $user, $this->module->maybe_interstitial( $user, '', '' ) );
	}

	public function test_empty_credentials_without_a_matching_cookie_get_no_exemption() {
		$this->api_context();
		$this->enrol( 7 );
		$user = new WP_User( 7, 'bob' );

		// e.g. an SSO plugin returning a user for empty credentials: still subject to 2FA.
		$GLOBALS['blt_test_cookie_user'] = 9;
		$this->module->begin_authentication( null );
		$this->assertInstanceOf( WP_Error::class, $this->module->maybe_interstitial( $user, '', '' ) );

		$GLOBALS['blt_test_cookie_user'] = 0;
		$this->assertInstanceOf( WP_Error::class, $this->module->maybe_interstitial( $user, '', '' ) );
	}

	public function test_user_lock_trips_after_ten_failures_and_survives_tokens() {
		$key = 'blt_sec_2fa_fail_7';
		for ( $i = 0; $i < Blt_Secure_Two_Factor::USER_MAX_FAILURES - 1; $i++ ) {
			Blt_Secure_Login_Hardening::counter_hit( $key, Blt_Secure_Two_Factor::USER_MAX_FAILURES, Blt_Secure_Two_Factor::USER_FAIL_WINDOW );
		}
		$this->assertFalse( $this->call_private( 'user_locked', array( 7 ) ) );

		Blt_Secure_Login_Hardening::counter_hit( $key, Blt_Secure_Two_Factor::USER_MAX_FAILURES, Blt_Secure_Two_Factor::USER_FAIL_WINDOW );
		$this->assertTrue( $this->call_private( 'user_locked', array( 7 ) ) );
		$this->assertFalse( $this->call_private( 'user_locked', array( 8 ) ), 'Other users are unaffected' );
	}

	public function test_disable_requires_proof() {
		$this->enrol( 7 );

		$this->assertFalse( $this->call_private( 'confirm_disable', array( 7, '' ) ) );
		$this->assertFalse( $this->call_private( 'confirm_disable', array( 7, 'wrong password' ) ) );
		$this->assertTrue( $this->call_private( 'confirm_disable', array( 7, 'correct horse' ) ), 'Account password is accepted' );
	}

	public function test_disable_accepts_a_current_totp_code() {
		$secret = $this->enrol( 7 );
		$totp   = new Blt_Secure_Totp();

		$this->assertTrue( $this->call_private( 'confirm_disable', array( 7, $totp->code( $secret, $totp->slice() ) ) ) );
	}

	public function test_wrong_disable_proofs_count_toward_the_user_lock() {
		$this->enrol( 7 );
		for ( $i = 0; $i < Blt_Secure_Two_Factor::USER_MAX_FAILURES; $i++ ) {
			$this->assertFalse( $this->call_private( 'confirm_disable', array( 7, 'nope' . $i ) ) );
		}

		// Locked now: even the right password no longer works until the window passes.
		$this->assertTrue( $this->call_private( 'user_locked', array( 7 ) ) );
		$this->assertFalse( $this->call_private( 'confirm_disable', array( 7, 'correct horse' ) ) );
	}

	public function test_recovery_codes_notice_is_registered_in_boot_not_in_the_post_handler() {
		$src = file_get_contents( BLT_SECURE_DIR . 'includes/modules/class-two-factor.php' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$this->assertSame( 1, substr_count( $src, "add_action( 'admin_notices', array( \$this, 'show_recovery_codes_once' ) )" ) );

		$boot = substr( $src, strpos( $src, 'public function boot()' ), 1400 );
		$this->assertStringContainsString( 'show_recovery_codes_once', $boot );
	}

	/**
	 * Separate process: the no-API path needs XMLRPC_REQUEST undefined.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_locked_user_is_not_issued_a_token() {
		$options = new Blt_Secure_Options();
		$crypto  = new Blt_Secure_Crypto();
		$module  = new Blt_Secure_Two_Factor( $options, $crypto, new Blt_Secure_Alerting( $options ) );

		$envelope = $crypto->encrypt( Blt_Secure_Totp::generate_secret() );
		if ( is_wp_error( $envelope ) ) {
			$this->markTestSkipped( 'No authenticated cipher available in this PHP build.' );
		}
		update_user_meta( 7, Blt_Secure_Two_Factor::META_SECRET, $envelope );

		for ( $i = 0; $i < Blt_Secure_Two_Factor::USER_MAX_FAILURES; $i++ ) {
			Blt_Secure_Login_Hardening::counter_hit( 'blt_sec_2fa_fail_7', Blt_Secure_Two_Factor::USER_MAX_FAILURES, Blt_Secure_Two_Factor::USER_FAIL_WINDOW );
		}

		$result = $module->maybe_interstitial( new WP_User( 7, 'bob' ), 'bob', 'pw' );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'blt_secure_locked', $result->get_error_code() );
		$this->assertEmpty( array_filter( array_keys( $GLOBALS['blt_test_transients'] ), static function ( $k ) {
			return 0 === strpos( $k, 'blt_sec_2fa_' ) && 0 !== strpos( $k, 'blt_sec_2fa_fail_' );
		} ), 'No pending-login token was created' );
	}
}
