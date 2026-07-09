<?php
/**
 * Activity monitor pure-logic tests.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure_Activity static helpers.
 */
class Test_Activity extends TestCase {

	public function test_admin_grant_detected_for_new_admin() {
		$this->assertTrue( Blt_Secure_Activity::is_admin_grant( 'administrator', array( 'subscriber' ) ) );
		$this->assertTrue( Blt_Secure_Activity::is_admin_grant( 'administrator', array() ) );
	}

	public function test_admin_grant_ignored_when_already_admin() {
		$this->assertFalse( Blt_Secure_Activity::is_admin_grant( 'administrator', array( 'administrator' ) ) );
	}

	public function test_admin_grant_ignored_for_non_admin_role() {
		$this->assertFalse( Blt_Secure_Activity::is_admin_grant( 'editor', array( 'subscriber' ) ) );
		$this->assertFalse( Blt_Secure_Activity::is_admin_grant( 'subscriber', array() ) );
	}

	public function test_watched_options_are_recognized() {
		foreach ( array( 'siteurl', 'home', 'admin_email', 'users_can_register', 'default_role' ) as $option ) {
			$this->assertTrue( Blt_Secure_Activity::is_watched_option( $option ), "Expected {$option} to be watched" );
		}
	}

	public function test_routine_options_are_not_watched() {
		$this->assertFalse( Blt_Secure_Activity::is_watched_option( 'blogname' ) );
		$this->assertFalse( Blt_Secure_Activity::is_watched_option( '_transient_foo' ) );
		$this->assertFalse( Blt_Secure_Activity::is_watched_option( 'cron' ) );
	}
}
