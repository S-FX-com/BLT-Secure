<?php
/**
 * Core scanner scope rules: optional files, locale fallback, unknown-file pass.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Scanner double: manifest and on-disk listing are injectable.
 */
class Blt_Test_Core_Scanner extends Blt_Secure_Core_Scanner {

	/**
	 * Manifest to return.
	 *
	 * @var array
	 */
	public $manifest = array();

	/**
	 * Files "on disk" in the core dirs.
	 *
	 * @var string[]
	 */
	public $on_disk = array();

	/**
	 * Whether to behave as if the en_US manifest stood in for the locale.
	 *
	 * @var bool
	 */
	public $fallback = false;

	/**
	 * Manifest.
	 *
	 * @param string $version Version.
	 * @param string $locale  Locale.
	 * @return array
	 */
	protected function fetch_checksums( $version, $locale ) {
		$this->used_fallback = $this->fallback;
		return $this->manifest;
	}

	/**
	 * Listing.
	 *
	 * @return string[]
	 */
	protected function list_core_php_files() {
		return $this->on_disk;
	}
}

/**
 * Tests.
 */
class Test_Core_Scanner_Scope extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wp_version'] = '6.9';
	}

	/**
	 * Paths flagged by a scan.
	 *
	 * @param array $payload Payload.
	 * @return array path => status
	 */
	private function flagged( array $payload ) {
		$out = array();
		foreach ( $payload['issues'] as $issue ) {
			$out[ $issue['path'] ] = $issue['status'];
		}
		return $out;
	}

	public function test_files_the_health_check_tells_users_to_delete_are_not_reported_missing() {
		$scanner           = new Blt_Test_Core_Scanner();
		$scanner->manifest = array(
			'readme.html'          => md5( 'x' ),
			'license.txt'          => md5( 'x' ),
			'wp-config-sample.php' => md5( 'x' ),
			'wp-load.php'          => md5( 'x' ),
		);
		$flagged           = $this->flagged( $scanner->run() );
		$this->assertSame( array( 'wp-load.php' => Blt_Secure_Core_Scanner::STATUS_MISSING ), $flagged );
	}

	public function test_locale_variant_files_are_skipped_when_the_en_us_manifest_stands_in() {
		$scanner           = new Blt_Test_Core_Scanner();
		$scanner->fallback = true;
		$scanner->manifest = array(
			'wp-includes/version.php' => md5( 'x' ),
			'wp-load.php'             => md5( 'x' ),
		);
		$this->assertSame( array( 'wp-load.php' => Blt_Secure_Core_Scanner::STATUS_MISSING ), $this->flagged( $scanner->run() ) );

		$scanner->fallback = false;
		$this->assertArrayHasKey( 'wp-includes/version.php', $this->flagged( $scanner->run() ) );
	}

	public function test_unknown_file_pass_runs_even_when_the_manifest_pass_is_truncated() {
		$scanner = new Blt_Test_Core_Scanner();
		for ( $i = 0; $i < 260; $i++ ) {
			$scanner->manifest[ "wp-includes/f{$i}.php" ] = md5( (string) $i );
		}
		$scanner->on_disk = array( 'wp-includes/backdoor.php', 'wp-load.php' );
		$scanner->manifest['wp-load.php'] = md5( 'x' );

		$payload = $scanner->run();
		$this->assertTrue( $payload['truncated'] );
		$this->assertSame( Blt_Secure_Core_Scanner::STATUS_UNKNOWN, $this->flagged( $payload )['wp-includes/backdoor.php'] );
	}

	public function test_truncated_manifest_pass_does_not_turn_unvisited_core_files_into_unknown() {
		$scanner = new Blt_Test_Core_Scanner();
		// Enough missing files to hit the issue cap well before the end of the manifest.
		for ( $i = 0; $i < 400; $i++ ) {
			$scanner->manifest[ "wp-includes/f{$i}.php" ] = md5( (string) $i );
		}
		// Genuine core files that sit AFTER the cap in manifest order, and a real extra file.
		$late = array( 'wp-includes/zz-late-1.php', 'wp-includes/zz-late-2.php', 'wp-admin/zz-late-3.php' );
		foreach ( $late as $path ) {
			$scanner->manifest[ $path ] = md5( $path );
		}
		$scanner->on_disk = array_merge( $late, array( 'wp-includes/backdoor.php' ) );

		$payload = $scanner->run();
		$flagged = $this->flagged( $payload );

		$this->assertTrue( $payload['truncated'] );
		$this->assertSame( Blt_Secure_Core_Scanner::STATUS_UNKNOWN, $flagged['wp-includes/backdoor.php'], 'The real extra file is still caught.' );
		foreach ( $late as $path ) {
			$this->assertNotSame( Blt_Secure_Core_Scanner::STATUS_UNKNOWN, isset( $flagged[ $path ] ) ? $flagged[ $path ] : '', "{$path} is in the manifest, so it must never be reported as an unknown file." );
		}
	}

	public function test_unknown_pass_has_its_own_allowance() {
		$scanner = new Blt_Test_Core_Scanner();
		for ( $i = 0; $i < 300; $i++ ) {
			$scanner->on_disk[] = "wp-includes/x{$i}.phtml";
		}
		$scanner->manifest = array( 'wp-load.php' => md5( 'x' ) );
		$payload           = $scanner->run();
		$unknown           = array_filter(
			$payload['issues'],
			static function ( $i ) {
				return Blt_Secure_Core_Scanner::STATUS_UNKNOWN === $i['status'];
			}
		);
		$this->assertCount( Blt_Secure_Core_Scanner::MAX_UNKNOWN, $unknown );
		$this->assertTrue( $payload['truncated'] );
	}

	public function test_optional_and_root_allowlists() {
		$this->assertContains( 'readme.html', Blt_Secure_Core_Scanner::optional_files() );
		$this->assertContains( 'wp-config.php', Blt_Secure_Core_Scanner::root_allowlist() );
		$this->assertContains( 'wp-includes/version.php', Blt_Secure_Core_Scanner::locale_variant_files() );
	}
}
