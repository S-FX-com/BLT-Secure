<?php
/**
 * Lockout state machine tests.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure_Login_Hardening lockout behavior (transient shims in bootstrap).
 */
class Test_Lockout extends TestCase {

	/**
	 * Module under test.
	 *
	 * @var Blt_Secure_Login_Hardening
	 */
	private $module;

	/**
	 * Reset state and build the module with default settings.
	 *
	 * @return void
	 */
	protected function setUp(): void {
		$GLOBALS['blt_test_options']    = array();
		$GLOBALS['blt_test_transients'] = array();
		$_SERVER['REMOTE_ADDR']         = '203.0.113.7';
		unset( $_SERVER['HTTP_CF_CONNECTING_IP'] );

		$options = new Blt_Secure_Options();
		$options->register_defaults(
			'login',
			array(
				'slug'            => '',
				'lockout_enabled' => true,
				'max_attempts'    => 5,
				'lockout_minutes' => 15,
			)
		);

		$this->module = new Blt_Secure_Login_Hardening(
			$options,
			new Blt_Secure_Ip_Resolver( $options ),
			new Blt_Secure_Alerting( $options )
		);
	}

	public function test_not_locked_initially() {
		$this->assertNull( $this->module->check_lockout( null, 'admin' ) );
	}

	public function test_locks_after_max_attempts() {
		for ( $i = 0; $i < 4; $i++ ) {
			$this->module->record_failure( 'admin' );
			$this->assertNull( $this->module->check_lockout( null, 'admin' ), "Locked too early at attempt $i" );
		}

		$this->module->record_failure( 'admin' );
		$result = $this->module->check_lockout( null, 'admin' );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'blt_secure_locked', $result->get_error_code() );
	}

	public function test_lock_follows_username_across_ips() {
		for ( $i = 0; $i < 5; $i++ ) {
			$_SERVER['REMOTE_ADDR'] = '203.0.113.' . ( 10 + $i ); // Rotating attacker.
			$this->module->record_failure( 'admin' );
		}

		$_SERVER['REMOTE_ADDR'] = '198.51.100.99'; // Fresh IP, same target user.
		$this->assertInstanceOf( WP_Error::class, $this->module->check_lockout( null, 'admin' ) );
	}

	public function test_lock_follows_ip_across_usernames() {
		for ( $i = 0; $i < 5; $i++ ) {
			$this->module->record_failure( 'user' . $i ); // Username spraying.
		}

		$this->assertInstanceOf( WP_Error::class, $this->module->check_lockout( null, 'yetanotheruser' ) );
	}

	public function test_username_matching_is_case_insensitive() {
		for ( $i = 0; $i < 5; $i++ ) {
			$this->module->record_failure( 'Admin' );
		}

		$_SERVER['REMOTE_ADDR'] = '198.51.100.99';
		$this->assertInstanceOf( WP_Error::class, $this->module->check_lockout( null, 'admin' ) );
	}

	public function test_success_clears_counters() {
		for ( $i = 0; $i < 5; $i++ ) {
			$this->module->record_failure( 'admin' );
		}
		$this->assertInstanceOf( WP_Error::class, $this->module->check_lockout( null, 'admin' ) );

		$this->module->clear_counters( 'admin' );
		$this->assertNull( $this->module->check_lockout( null, 'admin' ) );
	}

	public function test_other_user_other_ip_unaffected() {
		for ( $i = 0; $i < 5; $i++ ) {
			$this->module->record_failure( 'admin' );
		}

		$_SERVER['REMOTE_ADDR'] = '198.51.100.99';
		$this->assertNull( $this->module->check_lockout( null, 'editor' ) );
	}

	public function test_empty_username_passthrough() {
		$this->assertNull( $this->module->check_lockout( null, '' ) );
	}

	// -------------------------------------------------------------------
	// Backup-access key (pure key-rotation policy).
	// -------------------------------------------------------------------

	public function test_backup_key_empty_when_slug_off() {
		$this->assertSame( '', Blt_Secure_Login_Hardening::next_backup_key( '', 'old-slug', 'existingkey' ) );
	}

	public function test_backup_key_generated_when_slug_first_set() {
		$key = Blt_Secure_Login_Hardening::next_backup_key( 'my-login', '', '' );
		$this->assertMatchesRegularExpression( '/^[a-f0-9]{32}$/', $key );
	}

	public function test_backup_key_kept_while_slug_unchanged() {
		$this->assertSame( 'existingkey', Blt_Secure_Login_Hardening::next_backup_key( 'my-login', 'my-login', 'existingkey' ) );
	}

	public function test_backup_key_rotated_when_slug_changes() {
		$key = Blt_Secure_Login_Hardening::next_backup_key( 'new-login', 'my-login', 'existingkey' );
		$this->assertNotSame( 'existingkey', $key );
		$this->assertMatchesRegularExpression( '/^[a-f0-9]{32}$/', $key );
	}

	public function test_backup_key_generated_when_missing_even_if_slug_unchanged() {
		$key = Blt_Secure_Login_Hardening::next_backup_key( 'my-login', 'my-login', '' );
		$this->assertMatchesRegularExpression( '/^[a-f0-9]{32}$/', $key );
	}
}
