<?php
/**
 * Health checks: pure logic added with the hardening pass (staleness, PHP
 * support calendar, header value validation, leftover files, debug-log
 * location, self-request status handling) and the safer one-click fixes.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Tests.
 */
class Test_Health_Hardening extends TestCase {

	protected function setUp(): void {
		$GLOBALS['blt_test_options'] = array();
	}

	public function test_update_data_staleness() {
		$now = 1000000;
		$this->assertTrue( Blt_Secure_Health_Checks::update_data_is_stale( 0, $now, 432000 ), 'Never checked' );
		$this->assertTrue( Blt_Secure_Health_Checks::update_data_is_stale( null, $now, 432000 ) );
		$this->assertTrue( Blt_Secure_Health_Checks::update_data_is_stale( $now - 432001, $now, 432000 ) );
		$this->assertFalse( Blt_Secure_Health_Checks::update_data_is_stale( $now - 3600, $now, 432000 ) );
	}

	/**
	 * @dataProvider php_versions
	 * @param string $version  PHP version.
	 * @param string $today    Date "today".
	 * @param string $expected Status.
	 */
	public function test_php_support_calendar( $version, $today, $expected ) {
		$this->assertSame(
			$expected,
			Blt_Secure_Health_Checks::php_support_status( $version, strtotime( $today . ' 12:00:00 UTC' ), Blt_Secure_Health_Checks::php_eol_dates() )
		);
	}

	/**
	 * @return array[]
	 */
	public function php_versions() {
		return array(
			'8.1 after its EOL'      => array( '8.1.30', '2026-11-16', 'eol' ),
			'8.0 long dead'          => array( '8.0.30', '2026-11-16', 'eol' ),
			'7.4 long dead'          => array( '7.4.33', '2026-11-16', 'eol' ),
			'older than 7.4'         => array( '7.2.1', '2026-11-16', 'eol' ),
			'8.2 ends within 90 days' => array( '8.2.20', '2026-11-16', 'ending' ),
			'8.3 fine today'         => array( '8.3.6', '2026-11-16', 'supported' ),
			'newer than the table'   => array( '9.0.1', '2026-11-16', 'supported' ),
			'8.1 before its EOL'     => array( '8.1.2', '2024-01-01', 'supported' ),
			'unparseable'            => array( 'banana', '2026-11-16', 'supported' ),
		);
	}

	public function test_header_validators() {
		$this->assertTrue( Blt_Secure_Health_Checks::valid_nosniff( 'nosniff' ) );
		$this->assertFalse( Blt_Secure_Health_Checks::valid_nosniff( 'sniff' ) );

		$this->assertTrue( Blt_Secure_Health_Checks::valid_xframe( 'SAMEORIGIN' ) );
		$this->assertTrue( Blt_Secure_Health_Checks::valid_xframe( 'deny' ) );
		$this->assertFalse( Blt_Secure_Health_Checks::valid_xframe( 'ALLOWALL' ) );

		$this->assertTrue( Blt_Secure_Health_Checks::valid_hsts( 'max-age=31536000; includeSubDomains' ) );
		$this->assertFalse( Blt_Secure_Health_Checks::valid_hsts( 'max-age=0' ) );
		$this->assertFalse( Blt_Secure_Health_Checks::valid_hsts( 'includeSubDomains' ) );

		$this->assertTrue( Blt_Secure_Health_Checks::valid_referrer( 'strict-origin-when-cross-origin' ) );
		$this->assertTrue( Blt_Secure_Health_Checks::valid_referrer( 'unsafe-url, no-referrer' ), 'The last recognized token wins' );
		$this->assertFalse( Blt_Secure_Health_Checks::valid_referrer( 'no-referrer, unsafe-url' ) );
		$this->assertFalse( Blt_Secure_Health_Checks::valid_referrer( 'unsafe-url' ) );
		$this->assertFalse( Blt_Secure_Health_Checks::valid_referrer( '' ) );
	}

	public function test_only_successful_self_requests_are_judged() {
		$this->assertTrue( Blt_Secure_Health_Context::is_usable_status( 200 ) );
		foreach ( array( 0, 301, 302, 401, 403, 429, 500, 503 ) as $code ) {
			$this->assertFalse( Blt_Secure_Health_Context::is_usable_status( $code ), (string) $code );
		}
	}

	/**
	 * @dataProvider leftover_names
	 * @param string $name     Entry name.
	 * @param bool   $leftover Expected.
	 */
	public function test_leftover_file_detection( $name, $leftover ) {
		$this->assertSame( $leftover, Blt_Secure_Health_Checks::is_leftover_name( $name ) );
	}

	/**
	 * @return array[]
	 */
	public function leftover_names() {
		return array(
			'duplicator installer'  => array( 'installer.php', true ),
			'installer backup'      => array( 'installer-backup.php', true ),
			'dup-installer dir'     => array( 'dup-installer', true ),
			'sql dump'              => array( 'site_2024.sql', true ),
			'gz dump'               => array( 'db.sql.gz', true ),
			'config copy'           => array( 'wp-config.php.bak', true ),
			'config tilde'          => array( 'wp-config.php~', true ),
			'phpinfo'               => array( 'phpinfo.php', true ),
			'dotenv'                => array( '.env', true ),
			'git dir'               => array( '.git', true ),
			'site archive'          => array( 'backup-2024.zip', true ),
			'sample config'         => array( 'wp-config-sample.php', false ),
			'wp-config itself'      => array( 'wp-config.php', false ),
			'index'                 => array( 'index.php', false ),
			'content dir'           => array( 'wp-content', false ),
			'readme'                => array( 'readme.html', false ),
		);
	}

	public function test_debug_log_location_honors_a_custom_path() {
		$this->assertSame( '/var/www/wp-content/debug.log', Blt_Secure_Health_Checks::debug_log_path( true, '/var/www/wp-content/' ) );
		$this->assertSame( '/var/www/wp-content/debug.log', Blt_Secure_Health_Checks::debug_log_path( false, '/var/www/wp-content' ) );
		$this->assertSame( '/var/log/wp.log', Blt_Secure_Health_Checks::debug_log_path( '/var/log/wp.log', '/var/www/wp-content' ) );

		$this->assertTrue( Blt_Secure_Health_Checks::path_in_webroot( '/var/www/html/wp-content/debug.log', '/var/www/html/' ) );
		$this->assertFalse( Blt_Secure_Health_Checks::path_in_webroot( '/var/log/wp.log', '/var/www/html/' ) );
		$this->assertFalse( Blt_Secure_Health_Checks::path_in_webroot( '/var/www/html-private/x.log', '/var/www/html/' ) );
	}

	public function test_registration_fix_snapshots_the_previous_value() {
		$GLOBALS['blt_test_options']['users_can_register'] = 1;
		Blt_Secure_Health_Fixes::fix_registration_off( new Blt_Secure_Options() );
		$this->assertSame( 0, get_option( 'users_can_register' ) );
		$undo = get_option( Blt_Secure_Health_Fixes::UNDO_OPTION );
		$this->assertSame( 1, $undo['registration_off']['value'] );
		$this->assertSame( 'users_can_register', $undo['registration_off']['option'] );
	}

	public function test_activity_role_helpers() {
		$this->assertTrue( Blt_Secure_Activity::is_privileged_roles( array( 'editor' ) ) );
		$this->assertTrue( Blt_Secure_Activity::is_privileged_roles( array( 'subscriber', 'administrator' ) ) );
		$this->assertFalse( Blt_Secure_Activity::is_privileged_roles( array( 'subscriber', 'customer' ) ) );
		$this->assertFalse( Blt_Secure_Activity::is_privileged_roles( array() ) );

		$this->assertSame( array( 'email' ), Blt_Secure_Activity::changed_credentials( 'a@x', 'b@x', 'h', 'h' ) );
		$this->assertSame( array( 'password' ), Blt_Secure_Activity::changed_credentials( 'a@x', 'a@x', 'h1', 'h2' ) );
		$this->assertSame( array( 'email', 'password' ), Blt_Secure_Activity::changed_credentials( 'a@x', 'b@x', 'h1', 'h2' ) );
		$this->assertSame( array(), Blt_Secure_Activity::changed_credentials( 'a@x', 'a@x', 'h', 'h' ) );
	}

	public function test_every_watched_option_is_covered_for_per_option_hooks() {
		foreach ( array( 'siteurl', 'home', 'admin_email', 'default_role', 'users_can_register' ) as $option ) {
			$this->assertContains( $option, Blt_Secure_Activity::watched_options() );
		}
	}
}
