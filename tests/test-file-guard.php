<?php
/**
 * File-manager blocker.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure_File_Guard blocking logic.
 */
class Test_File_Guard extends TestCase {

	/**
	 * Module.
	 *
	 * @var Blt_Secure_File_Guard
	 */
	private $guard;

	/**
	 * Fresh module.
	 *
	 * @return void
	 */
	protected function setUp(): void {
		$GLOBALS['blt_test_options'] = array();
		$options                     = new Blt_Secure_Options();
		$this->guard                 = new Blt_Secure_File_Guard( $options, new Blt_Secure_Alerting( $options ) );
	}

	public function test_slug_matching_tolerates_casual_renames() {
		$blocked = $this->guard->blocked_slugs();
		foreach ( array( 'wp-file-manager', 'WP-File-Manager', 'wp-file-manager-6.9', 'wp-file-manager-1', 'filester.zip', 'file-manager-advanced_2' ) as $slug ) {
			$this->assertTrue( Blt_Secure_File_Guard::slug_matches( $slug, $blocked ), $slug );
		}
	}

	public function test_unrelated_slugs_are_not_blocked() {
		$blocked = $this->guard->blocked_slugs();
		foreach ( array( 'akismet', 'hello-dolly', 'file-uploader-pro', '.', '', 'blt-secure' ) as $slug ) {
			$this->assertFalse( Blt_Secure_File_Guard::slug_matches( $slug, $blocked ), $slug );
		}
	}

	/**
	 * Plugin_Upgrader::install() passes only type/action in hook_extra, so the
	 * upgrader_pre_install check cannot see a fresh install; the unpacked
	 * directory name is what stops it.
	 */
	public function test_fresh_install_is_blocked_by_the_unpacked_directory_name() {
		$result = $this->guard->block_source( '/wp-content/upgrade/wp-file-manager.6.9/wp-file-manager/', '/tmp', null, array( 'type' => 'plugin', 'action' => 'install' ) );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'blt_secure_blocked_plugin', $result->get_error_code() );
	}

	public function test_fresh_install_of_a_normal_plugin_passes() {
		$source = '/wp-content/upgrade/akismet.5.3/akismet/';
		$this->assertSame( $source, $this->guard->block_source( $source, '/tmp', null, array( 'type' => 'plugin' ) ) );
	}

	public function test_themes_and_errors_are_left_alone() {
		$this->assertSame( '/up/file-manager/', $this->guard->block_source( '/up/file-manager/', '/tmp', null, array( 'type' => 'theme' ) ) );
		$error = new WP_Error( 'x', 'y' );
		$this->assertSame( $error, $this->guard->block_source( $error, '/tmp', null, array( 'type' => 'plugin' ) ) );
	}
}
