<?php
/**
 * Lockout state machine + hidden-login request decision tests.
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

	/**
	 * Count logged lockout alerts.
	 *
	 * @return int
	 */
	private function lockout_alerts() {
		$events = isset( $GLOBALS['blt_test_options']['blt_secure_events'] ) ? $GLOBALS['blt_test_options']['blt_secure_events'] : array();
		$n      = 0;
		foreach ( $events as $event ) {
			if ( 'lockout' === $event['type'] ) {
				++$n;
			}
		}
		return $n;
	}

	/**
	 * Transient key of the client-wide counter for an IP.
	 *
	 * @param string $ip IP.
	 * @return string
	 */
	private function ip_key( $ip ) {
		return 'blt_sec_lock_ip_' . sha1( Blt_Secure_Ip_Resolver::network_key( $ip ) );
	}

	public function test_not_locked_initially() {
		$this->assertNull( $this->module->check_lockout( null, 'admin' ) );
		$user = new WP_User( 1, 'admin' );
		$this->assertSame( $user, $this->module->check_lockout_user( $user, 'x' ) );
	}

	public function test_pair_locks_after_max_attempts() {
		for ( $i = 0; $i < 4; $i++ ) {
			$this->module->record_failure( 'admin' );
			$this->assertNull( $this->module->check_lockout( null, 'admin' ), "Locked too early at attempt $i" );
		}

		$this->module->record_failure( 'admin' );
		$result = $this->module->check_lockout( null, 'admin' );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'blt_secure_locked', $result->get_error_code() );
	}

	/**
	 * The enforcement points must override a successful WP_User. Core's
	 * wp_authenticate_username_password() ignores an earlier WP_Error and returns
	 * a WP_User for a correct password; a lockout that only returns an error at
	 * authenticate priority 1 therefore never blocked anything.
	 */
	public function test_both_enforcement_points_replace_a_valid_user_when_locked() {
		for ( $i = 0; $i < 5; $i++ ) {
			$this->module->record_failure( 'admin' );
		}
		$user = new WP_User( 1, 'admin' );

		// authenticate, priority 99.
		$late = $this->module->check_lockout( $user, 'admin' );
		$this->assertInstanceOf( WP_Error::class, $late );
		$this->assertSame( 'blt_secure_locked', $late->get_error_code() );

		// wp_authenticate_user, priority 1 (runs before the password hash check).
		$early = $this->module->check_lockout_user( $user, 'correct-password' );
		$this->assertInstanceOf( WP_Error::class, $early );
		$this->assertSame( 'blt_secure_locked', $early->get_error_code() );

		// A prior error from another handler is replaced too, so password validity is not leaked.
		$this->assertSame( 'blt_secure_locked', $this->module->check_lockout( new WP_Error( 'incorrect_password' ), 'admin' )->get_error_code() );
	}

	public function test_enforcement_points_are_registered_where_core_cannot_overwrite_them() {
		$src = file_get_contents( BLT_SECURE_DIR . 'includes/modules/class-login-hardening.php' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$this->assertMatchesRegularExpression( "/add_filter\\( 'wp_authenticate_user', array\\( \\\$this, 'check_lockout_user' \\), 1, 2 \\)/", $src );
		$this->assertMatchesRegularExpression( "/add_filter\\( 'authenticate', array\\( \\\$this, 'check_lockout' \\), 99, 2 \\)/", $src );
		$this->assertDoesNotMatchRegularExpression( "/'authenticate', array\\( \\\$this, 'check_lockout' \\), 1,/", $src );
	}

	/**
	 * Remote-lockout guard: strangers failing logins for "admin" from other
	 * addresses must NOT lock the real admin out of their own address.
	 */
	public function test_username_failures_from_other_ips_do_not_lock_the_real_user() {
		for ( $i = 0; $i < 5; $i++ ) {
			$_SERVER['REMOTE_ADDR'] = '203.0.113.' . ( 10 + $i ); // Rotating attacker, 1 failure each.
			$this->module->record_failure( 'admin' );
		}

		$_SERVER['REMOTE_ADDR'] = '198.51.100.99'; // The admin, from home.
		$this->assertNull( $this->module->check_lockout( null, 'admin' ) );
		$this->assertNotInstanceOf( WP_Error::class, $this->module->check_lockout_user( new WP_User( 1, 'admin' ), 'pw' ) );
	}

	public function test_distributed_guessing_alerts_but_never_blocks() {
		$threshold = 5 * Blt_Secure_Login_Hardening::USER_ALERT_FACTOR;
		for ( $i = 0; $i < $threshold; $i++ ) {
			$_SERVER['REMOTE_ADDR'] = '10.' . intdiv( $i, 250 ) . '.' . ( $i % 250 ) . '.1';
			$this->module->record_failure( 'admin' );
		}

		$this->assertSame( 1, $this->lockout_alerts(), 'One distributed-attack alert, no more' );

		$_SERVER['REMOTE_ADDR'] = '198.51.100.99';
		$this->assertNull( $this->module->check_lockout( null, 'admin' ), 'Alert only: a global per-username counter never blocks' );
	}

	public function test_ip_locks_after_ip_threshold_across_usernames() {
		$limit = 5 * Blt_Secure_Login_Hardening::IP_FACTOR;
		for ( $i = 0; $i < $limit - 1; $i++ ) {
			$this->module->record_failure( 'user' . $i ); // Username spraying.
		}
		$this->assertNull( $this->module->check_lockout( null, 'yetanotheruser' ), 'Locked too early' );

		$this->module->record_failure( 'userlast' );
		$this->assertInstanceOf( WP_Error::class, $this->module->check_lockout( null, 'yetanotheruser' ) );
	}

	public function test_ipv6_addresses_in_one_slash_64_share_a_counter() {
		for ( $i = 0; $i < 5; $i++ ) {
			$_SERVER['REMOTE_ADDR'] = '2001:db8:1:2:' . dechex( 0x1000 + $i ) . '::1'; // Rotating inside one /64.
			$this->module->record_failure( 'admin' );
		}

		$_SERVER['REMOTE_ADDR'] = '2001:db8:1:2:ffff::9';
		$this->assertInstanceOf( WP_Error::class, $this->module->check_lockout( null, 'admin' ) );

		$_SERVER['REMOTE_ADDR'] = '2001:db8:1:3::9'; // Different /64.
		$this->assertNull( $this->module->check_lockout( null, 'admin' ) );
	}

	public function test_username_matching_is_case_insensitive() {
		for ( $i = 0; $i < 5; $i++ ) {
			$this->module->record_failure( 'Admin' );
		}

		$this->assertInstanceOf( WP_Error::class, $this->module->check_lockout( null, 'admin' ) );
	}

	public function test_alert_fires_once_per_lockout() {
		for ( $i = 0; $i < 9; $i++ ) {
			$this->module->record_failure( 'admin' );
		}
		$this->assertSame( 1, $this->lockout_alerts() );
	}

	public function test_locked_rejections_are_not_counted_or_extended() {
		for ( $i = 0; $i < 5; $i++ ) {
			$this->module->record_failure( 'admin' );
		}
		$key   = 'blt_sec_lock_pair_' . sha1( Blt_Secure_Ip_Resolver::network_key( '203.0.113.7' ) . '|admin' );
		$state = $GLOBALS['blt_test_transients'][ $key ];

		// wp_login_failed fires for the lockout error itself; that must be a no-op.
		$this->module->record_failure( 'admin', new WP_Error( 'blt_secure_locked', 'x' ) );
		$this->assertSame( $state, $GLOBALS['blt_test_transients'][ $key ] );
	}

	public function test_window_is_anchored_on_first_failure_and_not_rearmed() {
		for ( $i = 0; $i < 5; $i++ ) {
			$this->module->record_failure( 'admin' );
		}
		$key   = 'blt_sec_lock_pair_' . sha1( Blt_Secure_Ip_Resolver::network_key( '203.0.113.7' ) . '|admin' );
		$until = $GLOBALS['blt_test_transients'][ $key ]['until'];
		$this->assertGreaterThan( time(), $until );

		// More failures while locked (not via the lockout error path) never push `until` out.
		Blt_Secure_Login_Hardening::counter_hit( $key, 5, 900 );
		Blt_Secure_Login_Hardening::counter_hit( $key, 5, 900 );
		$this->assertSame( $until, $GLOBALS['blt_test_transients'][ $key ]['until'] );
	}

	public function test_lock_expires() {
		for ( $i = 0; $i < 5; $i++ ) {
			$this->module->record_failure( 'admin' );
		}
		$key                                      = 'blt_sec_lock_pair_' . sha1( Blt_Secure_Ip_Resolver::network_key( '203.0.113.7' ) . '|admin' );
		$GLOBALS['blt_test_transients'][ $key ]['until'] = time() - 1;

		$this->assertNull( $this->module->check_lockout( null, 'admin' ) );
	}

	public function test_untripped_window_that_elapsed_starts_over() {
		$key = 'blt_sec_lock_test';
		Blt_Secure_Login_Hardening::counter_hit( $key, 5, 900 );
		Blt_Secure_Login_Hardening::counter_hit( $key, 5, 900 );
		$GLOBALS['blt_test_transients'][ $key ]['first'] = time() - 901;

		$hit = Blt_Secure_Login_Hardening::counter_hit( $key, 5, 900 );
		$this->assertSame( 1, $hit['count'] );
	}

	public function test_success_clears_only_the_pair() {
		for ( $i = 0; $i < 5; $i++ ) {
			$this->module->record_failure( 'admin' );
		}
		$this->assertInstanceOf( WP_Error::class, $this->module->check_lockout( null, 'admin' ) );

		$this->module->clear_counters( 'admin' );
		$this->assertNull( $this->module->check_lockout( null, 'admin' ) );

		// The client-wide counter survives a successful login (no reset-by-own-account trick).
		$this->assertSame( 5, $GLOBALS['blt_test_transients'][ $this->ip_key( '203.0.113.7' ) ]['count'] );
	}

	public function test_other_user_other_ip_unaffected() {
		for ( $i = 0; $i < 5; $i++ ) {
			$this->module->record_failure( 'admin' );
		}

		$_SERVER['REMOTE_ADDR'] = '198.51.100.99';
		$this->assertNull( $this->module->check_lockout( null, 'editor' ) );
	}

	public function test_same_ip_other_user_not_pair_locked() {
		for ( $i = 0; $i < 5; $i++ ) {
			$this->module->record_failure( 'admin' );
		}
		// A colleague behind the same NAT is not locked by someone else's typos.
		$this->assertNull( $this->module->check_lockout( null, 'editor' ) );
	}

	public function test_empty_username_passthrough() {
		$this->assertNull( $this->module->check_lockout( null, '' ) );
	}

	// -------------------------------------------------------------------
	// Hidden-login request decision (pure).
	// -------------------------------------------------------------------

	/**
	 * Build a request description.
	 *
	 * @param array $over Overrides.
	 * @return array
	 */
	private function req( array $over = array() ) {
		return array_merge(
			array(
				'script'  => '/var/www/html/index.php',
				'uri'     => '/',
				'method'  => 'GET',
				'action'  => '',
				'slug'    => 'my-login',
				'bases'   => array( '', '' ),
				'allowed' => array( 'postpass' ),
			),
			$over
		);
	}

	public function test_slug_request_is_served() {
		$this->assertSame( 'slug', Blt_Secure_Login_Hardening::request_decision( $this->req( array( 'uri' => '/my-login' ) ) ) );
		$this->assertSame( 'slug', Blt_Secure_Login_Hardening::request_decision( $this->req( array( 'uri' => '/my-login/?redirect_to=%2Fx' ) ) ) );
		$this->assertSame( 'slug', Blt_Secure_Login_Hardening::request_decision( $this->req( array( 'uri' => '//my-login' ) ) ) );
	}

	public function test_ordinary_pages_pass() {
		$this->assertSame( 'pass', Blt_Secure_Login_Hardening::request_decision( $this->req( array( 'uri' => '/about/' ) ) ) );
		$this->assertSame( 'pass', Blt_Secure_Login_Hardening::request_decision( $this->req( array( 'uri' => '/my-login-not' ) ) ) );
	}

	public function test_no_slug_configured_never_serves_slug() {
		$this->assertSame( 'pass', Blt_Secure_Login_Hardening::request_decision( $this->req( array( 'slug' => '' ) ) ) );
	}

	/**
	 * @dataProvider direct_login_hits
	 * @param string $uri URI.
	 */
	public function test_every_way_of_reaching_wp_login_is_blocked( $uri ) {
		$decision = Blt_Secure_Login_Hardening::request_decision(
			$this->req(
				array(
					'script' => '/var/www/html/wp-login.php', // What actually executes, whatever the URL says.
					'uri'    => $uri,
				)
			)
		);
		$this->assertSame( 'block', $decision, $uri );
	}

	/**
	 * @return array[]
	 */
	public function direct_login_hits() {
		return array(
			array( '/wp-login.php' ),
			array( '/wp-login.php?action=lostpassword' ),
			array( '//wp-login.php' ),
			array( '///wp-login.php' ),
			array( '/wp-login.php/x' ),
			array( '/wp-login.php/' ),
			array( '/wp%2Dlogin.php' ),
			array( '/./wp-login.php' ),
		);
	}

	public function test_url_tripwire_when_script_name_is_unusual() {
		// Front controller / odd SCRIPT_FILENAME: the normalised URL basename still trips the block.
		$this->assertSame( 'block', Blt_Secure_Login_Hardening::request_decision( $this->req( array( 'uri' => '/wp%2Dlogin.php' ) ) ) );
		$this->assertSame( 'block', Blt_Secure_Login_Hardening::request_decision( $this->req( array( 'uri' => '//wp-login.php' ) ) ) );
	}

	/**
	 * @dataProvider disguised_postpass
	 * @param string $action Raw action.
	 */
	public function test_action_allowlist_is_compared_raw( $action ) {
		$decision = Blt_Secure_Login_Hardening::request_decision(
			$this->req(
				array(
					'script' => '/var/www/html/wp-login.php',
					'uri'    => '/wp-login.php',
					'method' => 'POST',
					'action' => $action,
				)
			)
		);
		$this->assertSame( 'block', $decision, $action );
	}

	/**
	 * @return array[]
	 */
	public function disguised_postpass() {
		return array(
			array( 'POSTPASS' ),
			array( 'PostPass' ),
			array( 'postpass!' ),
			array( 'post pass' ),
			array( 'post\\pass' ),
			array( 'postpass ' ),
			array( '' ),
		);
	}

	public function test_real_postpass_post_passes_but_get_does_not() {
		$base = array(
			'script' => '/var/www/html/wp-login.php',
			'uri'    => '/wp-login.php',
			'action' => 'postpass',
		);
		$this->assertSame( 'pass', Blt_Secure_Login_Hardening::request_decision( $this->req( array_merge( $base, array( 'method' => 'POST' ) ) ) ) );
		$this->assertSame( 'block', Blt_Secure_Login_Hardening::request_decision( $this->req( array_merge( $base, array( 'method' => 'GET' ) ) ) ) );
	}

	public function test_filter_added_actions_pass_on_any_method() {
		$decision = Blt_Secure_Login_Hardening::request_decision(
			$this->req(
				array(
					'script'  => '/var/www/html/wp-login.php',
					'uri'     => '/wp-login.php',
					'method'  => 'GET',
					'action'  => 'sso_callback',
					'allowed' => array( 'postpass', 'sso_callback' ),
				)
			)
		);
		$this->assertSame( 'pass', $decision );
	}

	public function test_slug_under_siteurl_subdirectory_is_served() {
		// WordPress in /wp, home at the root: generated login URLs live under /wp.
		$req = $this->req( array( 'bases' => array( '', '/wp' ) ) );
		$this->assertSame( 'slug', Blt_Secure_Login_Hardening::request_decision( array_merge( $req, array( 'uri' => '/wp/my-login' ) ) ) );
		$this->assertSame( 'slug', Blt_Secure_Login_Hardening::request_decision( array_merge( $req, array( 'uri' => '/my-login' ) ) ) );
		$this->assertSame( 'pass', Blt_Secure_Login_Hardening::request_decision( array_merge( $req, array( 'uri' => '/other/my-login' ) ) ) );
	}

	public function test_normalize_request_path() {
		$this->assertSame( 'wp-login.php', Blt_Secure_Login_Hardening::normalize_request_path( '//wp-login.php' ) );
		$this->assertSame( 'a/b', Blt_Secure_Login_Hardening::normalize_request_path( '/a//b/?x=1#frag' ) );
		$this->assertSame( 'wp-login.php', Blt_Secure_Login_Hardening::normalize_request_path( '/wp%2Dlogin.php' ) );
		$this->assertSame( 'wp-login.php', Blt_Secure_Login_Hardening::normalize_request_path( 'http://example.com/wp-login.php?x' ) );
		$this->assertSame( '', Blt_Secure_Login_Hardening::normalize_request_path( '/?s=wp-login.php' ) );
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
