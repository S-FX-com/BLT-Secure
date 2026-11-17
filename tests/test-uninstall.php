<?php
/**
 * uninstall.php must remove everything the plugin stores.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Contract: options, hooks and user meta in code are all cleaned up.
 */
class Test_Uninstall extends TestCase {

	private $uninstall;

	protected function setUp(): void {
		$this->uninstall = (string) file_get_contents( BLT_SECURE_DIR . 'uninstall.php' );
	}

	private function php_files() {
		$files    = array();
		$iterator = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( BLT_SECURE_DIR . 'includes', FilesystemIterator::SKIP_DOTS ) );
		foreach ( $iterator as $file ) {
			$path = $file->getPathname();
			if ( '.php' === substr( $path, -4 ) && false === strpos( $path, '/includes/lib/' ) && false === strpos( $path, '/includes/blt-family/' ) ) {
				$files[] = $path;
			}
		}
		return $files;
	}

	public function test_every_option_constant_is_deleted() {
		$found = array();
		foreach ( $this->php_files() as $path ) {
			if ( preg_match_all( "/const\\s+[A-Z_]*OPTION\\s*=\\s*'(blt_secure_[a-z_]+)'/", (string) file_get_contents( $path ), $m ) ) {
				$found = array_merge( $found, $m[1] );
			}
		}
		$this->assertNotEmpty( $found );
		foreach ( array_unique( $found ) as $option ) {
			$this->assertStringContainsString( "'{$option}'", $this->uninstall, "{$option} is not removed on uninstall" );
		}
	}

	public function test_credentials_flag_and_command_state_are_deleted() {
		foreach ( Blt_Secure_Encrypted_Option_Store::known_keys() as $key ) {
			$this->assertStringContainsString( "'blt_secure_cred_{$key}'", $this->uninstall );
		}
		$this->assertStringContainsString( "'" . Blt_Secure_Encrypted_Option_Store::INVALID_FLAG_OPTION . "'", $this->uninstall );
		$this->assertStringContainsString( "'" . Blt_Secure_Fleet::LAST_COMMAND_OPTION . "'", $this->uninstall );
	}

	public function test_every_scheduled_hook_is_cleared() {
		$hooks = array( 'blt_secure_refresh_cf_ips', Blt_Secure_Fleet::CRON_HOOK, Blt_Secure_Fleet::PULL_HOOK, Blt_Secure_Fleet::PUSH_HOOK, Blt_Secure_Alert_Channels::DELIVER_HOOK );
		foreach ( $this->php_files() as $path ) {
			if ( preg_match_all( "/const\\s+CRON_HOOK\\s*=\\s*'(blt_secure_[a-z_]+)'/", (string) file_get_contents( $path ), $m ) ) {
				$hooks = array_merge( $hooks, $m[1] );
			}
		}
		foreach ( array_unique( $hooks ) as $hook ) {
			$this->assertStringContainsString( "'{$hook}'", $this->uninstall, "cron hook {$hook} is not cleared on uninstall" );
		}
	}

	public function test_args_carrying_events_are_unscheduled_with_unschedule_hook() {
		// wp_clear_scheduled_hook() only matches events with NO args.
		$this->assertStringContainsString( "wp_unschedule_hook( 'blt_secure_alert_deliver' )", $this->uninstall );
	}

	public function test_family_options_are_never_deleted() {
		$this->assertStringNotContainsString( 'blt_family', $this->uninstall );
	}

	public function test_multisite_visits_every_site_and_removes_the_network_update_state() {
		$this->assertStringContainsString( 'get_sites(', $this->uninstall );
		$this->assertStringContainsString( 'switch_to_blog', $this->uninstall );
		$this->assertStringContainsString( "delete_site_option( 'external_updates-blt-secure' )", $this->uninstall );
		$this->assertStringNotContainsString( "delete_option( 'external_updates-blt-secure' )", $this->uninstall );
	}
}
