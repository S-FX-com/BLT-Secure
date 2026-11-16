<?php
/**
 * Baseline: confirmed re-baselining (#version-bump laundering), per-extension
 * storage, unmonitored targets, and the new hashable set.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

require_once BLT_SECURE_DIR . 'includes/modules/class-baseline.php';

/**
 * Module double: targets are injectable (the real list needs wp-admin APIs).
 */
class Blt_Test_Baseline extends Blt_Secure_Baseline {

	/**
	 * Targets to scan.
	 *
	 * @var array[]
	 */
	public $fake_targets = array();

	/**
	 * Targets.
	 *
	 * @return array[]
	 */
	protected function targets() {
		return $this->fake_targets;
	}
}

/**
 * Tests.
 */
class Test_Baseline_Confirmation extends TestCase {

	/**
	 * Temp plugin dir.
	 *
	 * @var string
	 */
	private $dir;

	protected function setUp(): void {
		$GLOBALS['blt_test_options'] = array();
		$this->dir                   = sys_get_temp_dir() . '/blt-bl-' . uniqid( '', true );
		mkdir( $this->dir . '/plug', 0777, true );
		file_put_contents( $this->dir . '/plug/plug.php', '<?php // v1' );
	}

	protected function tearDown(): void {
		$this->rrmdir( $this->dir );
		$GLOBALS['blt_test_options'] = array();
	}

	/**
	 * Recursively delete (links removed, never followed).
	 *
	 * @param string $path Path.
	 * @return void
	 */
	private function rrmdir( $path ) {
		if ( is_link( $path ) || is_file( $path ) ) {
			unlink( $path );
			return;
		}
		if ( ! is_dir( $path ) ) {
			return;
		}
		foreach ( scandir( $path ) as $item ) {
			if ( '.' !== $item && '..' !== $item ) {
				$this->rrmdir( $path . '/' . $item );
			}
		}
		rmdir( $path );
	}

	/**
	 * Module over one fake plugin at a given version.
	 *
	 * @param string $version Version.
	 * @return Blt_Test_Baseline
	 */
	private function module( $version ) {
		$module               = new Blt_Test_Baseline( new Blt_Secure_Options() );
		$module->fake_targets = array(
			array(
				'key'     => 'plugin/plug',
				'label'   => 'Plug',
				'dir'     => $this->dir . '/plug',
				'version' => $version,
				'single'  => false,
				'file'    => 'plug/plug.php',
				'slug'    => '',
			),
		);
		return $module;
	}

	// -------------------------------------------------------------------
	// Pure decision logic.
	// -------------------------------------------------------------------

	public function test_decision_table() {
		$stored = array( 'version' => '1.0' );
		$this->assertSame( 'baseline', Blt_Secure_Baseline_Scanner::rebaseline_decision( null, '1.0', false, false ) );
		$this->assertSame( 'compare', Blt_Secure_Baseline_Scanner::rebaseline_decision( $stored, '1.0', true, true ) );
		$this->assertSame( 'flag', Blt_Secure_Baseline_Scanner::rebaseline_decision( $stored, '1.1', false, false ) );
		$this->assertSame( 'accept', Blt_Secure_Baseline_Scanner::rebaseline_decision( $stored, '1.1', true, false ) );
		$this->assertSame( 'accept', Blt_Secure_Baseline_Scanner::rebaseline_decision( $stored, '1.1', false, true ) );
	}

	public function test_manifest_parsing_and_matching() {
		$body     = wp_json_encode(
			array(
				'files' => array(
					'a.php'     => array(
						'md5'    => 'aaa',
						'sha256' => 'x',
					),
					'inc/b.php' => array( 'md5' => array( 'bbb', 'bbb2' ) ),
				),
			)
		);
		$manifest = Blt_Secure_Baseline_Scanner::parse_manifest( $body );
		$this->assertSame( array( 'aaa' ), $manifest['a.php'] );
		$this->assertTrue(
			Blt_Secure_Baseline_Scanner::matches_manifest(
				array(
					'a.php'     => 'aaa',
					'inc/b.php' => 'bbb2',
				),
				$manifest
			)
		);
		$this->assertFalse( Blt_Secure_Baseline_Scanner::matches_manifest( array( 'a.php' => 'tampered' ), $manifest ) );
		$this->assertFalse(
			Blt_Secure_Baseline_Scanner::matches_manifest(
				array(
					'a.php'    => 'aaa',
					'evil.php' => 'ccc',
				),
				$manifest
			),
			'An added file is not vouched for'
		);
		$this->assertFalse( Blt_Secure_Baseline_Scanner::matches_manifest( array(), $manifest ) );
		$this->assertNull( Blt_Secure_Baseline_Scanner::parse_manifest( 'not json' ) );
		$this->assertNull( Blt_Secure_Baseline_Scanner::parse_manifest( '{"files":[]}' ) );
	}

	public function test_upgrade_keys() {
		$this->assertSame(
			array( 'plugin/akismet', 'plugin/hello.php' ),
			Blt_Secure_Baseline::keys_from_upgrade(
				array(
					'type'    => 'plugin',
					'action'  => 'update',
					'plugins' => array( 'akismet/akismet.php', 'hello.php' ),
				)
			)
		);
		$this->assertSame(
			array( 'theme/twentytwenty' ),
			Blt_Secure_Baseline::keys_from_upgrade(
				array(
					'type'   => 'theme',
					'action' => 'update',
					'theme'  => 'twentytwenty',
				)
			)
		);
		$this->assertSame(
			array( 'plugin/new-one' ),
			Blt_Secure_Baseline::keys_from_upgrade(
				array(
					'type'   => 'plugin',
					'action' => 'install',
				),
				array( 'new-one/new-one.php' )
			)
		);
		$this->assertSame(
			array(),
			Blt_Secure_Baseline::keys_from_upgrade(
				array(
					'type'   => 'core',
					'action' => 'update',
				)
			)
		);
		$this->assertSame(
			array(),
			Blt_Secure_Baseline::keys_from_upgrade(
				array(
					'type'   => 'plugin',
					'action' => 'delete',
					'plugin' => 'x/x.php',
				)
			)
		);
	}

	public function test_prune_events_drops_expired_and_junk() {
		$now    = 2000000000;
		$events = array(
			'plugin/fresh' => $now - 10,
			'plugin/old'   => $now - Blt_Secure_Baseline::EVENT_TTL - 5,
			'plugin/junk'  => 'x',
		);
		$this->assertSame( array( 'plugin/fresh' => $now - 10 ), Blt_Secure_Baseline::prune_events( $events, $now ) );
	}

	public function test_store_names_are_stable_distinct_and_short() {
		$a = Blt_Secure_Baseline::store_name( 'plugin/a' );
		$this->assertSame( $a, Blt_Secure_Baseline::store_name( 'plugin/a' ) );
		$this->assertNotSame( $a, Blt_Secure_Baseline::store_name( 'plugin/b' ) );
		$this->assertLessThan( 64, strlen( $a ) );
	}

	public function test_only_unmonitored_helper() {
		$this->assertTrue( Blt_Secure_Baseline::only_unmonitored( array( array( 'kind' => 'unmonitored' ) ) ) );
		$this->assertFalse( Blt_Secure_Baseline::only_unmonitored( array( array( 'kind' => 'unmonitored' ), array( 'kind' => 'drift' ) ) ) );
		$this->assertFalse( Blt_Secure_Baseline::only_unmonitored( array() ) );
	}

	public function test_hashable_set_now_covers_js_json_and_server_config() {
		foreach ( array( 'a.php', 'a.phtml', 'a.phar', 'x/.htaccess', 'x/.user.ini', 'a.js', 'a.json', 'a.PHP5' ) as $path ) {
			$this->assertTrue( Blt_Secure_Baseline_Scanner::is_hashable( $path ), $path );
		}
		foreach ( array( 'a.css', 'a.png', 'a.txt' ) as $path ) {
			$this->assertFalse( Blt_Secure_Baseline_Scanner::is_hashable( $path ), $path );
		}
	}

	// -------------------------------------------------------------------
	// hash_dir.
	// -------------------------------------------------------------------

	public function test_hash_dir_records_links_skips_vendor_noise_and_hashes_config() {
		mkdir( $this->dir . '/plug/node_modules' );
		file_put_contents( $this->dir . '/plug/node_modules/x.js', 'x' );
		file_put_contents( $this->dir . '/plug/.htaccess', 'Deny from all' );
		file_put_contents( $this->dir . '/plug/app.js', 'var a;' );
		$has_link = @symlink( $this->dir . '/plug/plug.php', $this->dir . '/plug/alias.php' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		$engine = new Blt_Secure_Baseline_Scanner();
		$hashes = $engine->hash_dir( $this->dir . '/plug' );
		$this->assertArrayHasKey( 'plug.php', $hashes );
		$this->assertArrayHasKey( '.htaccess', $hashes );
		$this->assertArrayHasKey( 'app.js', $hashes );
		$this->assertArrayNotHasKey( 'node_modules/x.js', $hashes );
		if ( $has_link ) {
			$this->assertStringStartsWith( 'link:', $hashes['alias.php'] );
		}
	}

	public function test_hash_dir_reports_unreadable() {
		$engine = new Blt_Secure_Baseline_Scanner();
		$this->assertNull( $engine->hash_dir( $this->dir . '/missing' ) );
		$this->assertSame( 'unreadable', $engine->last_reason );
	}

	// -------------------------------------------------------------------
	// run_scan: the version-bump laundering fix.
	// -------------------------------------------------------------------

	public function test_first_scan_baselines_and_marks_trust_on_first_use() {
		$payload = $this->module( '1.0' )->run_scan();
		$this->assertSame( array(), $payload['findings'] );
		$index = get_option( Blt_Secure_Baseline::BASELINE_OPTION );
		$this->assertSame( 'first_seen', $index['plugin/plug']['trust'] );
		$this->assertArrayNotHasKey( 'hashes', $index['plugin/plug'], 'Hashes live in their own option' );
		$this->assertArrayHasKey( 'plug.php', get_option( Blt_Secure_Baseline::store_name( 'plugin/plug' ) ) );
	}

	public function test_same_version_modification_is_drift() {
		$this->module( '1.0' )->run_scan();
		file_put_contents( $this->dir . '/plug/plug.php', '<?php eval(base64_decode($_POST[1]));' );

		$payload = $this->module( '1.0' )->run_scan();
		$this->assertCount( 1, $payload['findings'] );
		$this->assertSame( 'drift', $payload['findings'][0]['kind'] );
	}

	public function test_version_header_bump_without_update_event_is_flagged_and_baseline_kept() {
		$this->module( '1.0' )->run_scan();
		$before = get_option( Blt_Secure_Baseline::store_name( 'plugin/plug' ) );

		// Tamperer edits the file AND bumps the Version header.
		file_put_contents( $this->dir . '/plug/plug.php', '<?php // v2 backdoor' );
		$payload = $this->module( '1.0.1' )->run_scan();

		$this->assertCount( 1, $payload['findings'] );
		$this->assertSame( 'version_bump', $payload['findings'][0]['kind'] );
		$index = get_option( Blt_Secure_Baseline::BASELINE_OPTION );
		$this->assertSame( '1.0', $index['plugin/plug']['version'], 'The old baseline must be kept' );
		$this->assertSame( $before, get_option( Blt_Secure_Baseline::store_name( 'plugin/plug' ) ) );

		// Still flagged on the next scan (not laundered by waiting).
		$again = $this->module( '1.0.1' )->run_scan();
		$this->assertCount( 1, $again['findings'] );
	}

	public function test_update_event_confirms_the_version_change() {
		$this->module( '1.0' )->run_scan();
		file_put_contents( $this->dir . '/plug/plug.php', '<?php // v2 real update' );
		$GLOBALS['blt_test_options'][ Blt_Secure_Baseline::EVENTS_OPTION ] = array( 'plugin/plug' => time() + 5 );

		$payload = $this->module( '1.1' )->run_scan();
		$this->assertSame( array(), $payload['findings'] );
		$index = get_option( Blt_Secure_Baseline::BASELINE_OPTION );
		$this->assertSame( '1.1', $index['plugin/plug']['version'] );
		$this->assertSame( 'update_event', $index['plugin/plug']['trust'] );
		$this->assertArrayNotHasKey( 'plugin/plug', get_option( Blt_Secure_Baseline::EVENTS_OPTION ), 'A used event is consumed' );
	}

	public function test_acknowledging_the_finding_accepts_the_new_state() {
		$this->module( '1.0' )->run_scan();
		file_put_contents( $this->dir . '/plug/plug.php', '<?php // v2 manual FTP update' );
		$payload = $this->module( '1.1' )->run_scan();
		$this->assertSame( 'version_bump', $payload['findings'][0]['kind'] );

		( new Blt_Secure_Scan_Whitelist() )->add( $payload['findings'][0]['fingerprint'], array( 'scanner' => 'baseline' ) );

		$after = $this->module( '1.1' )->run_scan();
		$this->assertSame( array(), $after['findings'] );
		$index = get_option( Blt_Secure_Baseline::BASELINE_OPTION );
		$this->assertSame( '1.1', $index['plugin/plug']['version'] );
		$this->assertSame( 'acknowledged', $index['plugin/plug']['trust'] );
	}

	public function test_unhashable_target_is_reported_not_silently_passed() {
		$module                         = $this->module( '1.0' );
		$module->fake_targets[0]['dir'] = $this->dir . '/does-not-exist';
		$payload                        = $module->run_scan();
		$this->assertCount( 1, $payload['findings'] );
		$this->assertSame( 'unmonitored', $payload['findings'][0]['kind'] );
	}

	public function test_legacy_inline_baseline_is_migrated_to_its_own_option() {
		$hashes = array( 'plug.php' => md5( '<?php // v1' ) );
		$GLOBALS['blt_test_options'][ Blt_Secure_Baseline::BASELINE_OPTION ] = array(
			'plugin/plug' => array(
				'version' => '1.0',
				'hashes'  => $hashes,
			),
		);
		$payload = $this->module( '1.0' )->run_scan();
		$this->assertSame( array(), $payload['findings'] );
		$index = get_option( Blt_Secure_Baseline::BASELINE_OPTION );
		$this->assertArrayNotHasKey( 'hashes', $index['plugin/plug'] );
		$this->assertSame( $hashes, get_option( Blt_Secure_Baseline::store_name( 'plugin/plug' ) ) );
	}

	// -------------------------------------------------------------------
	// Upgrade from a baseline written under the narrower (scope 1) hash set.
	// -------------------------------------------------------------------

	/**
	 * Write the baseline the PREVIOUS release would have: PHP-family files only, no `scope` stamp.
	 *
	 * @return array path => md5 as stored.
	 */
	private function seed_legacy_baseline() {
		$hashes = array( 'plug.php' => md5_file( $this->dir . '/plug/plug.php' ) );
		$GLOBALS['blt_test_options'][ Blt_Secure_Baseline::BASELINE_OPTION ]                         = array(
			'plugin/plug' => array(
				'version' => '1.0',
				'trust'   => 'wporg_checksums',
				'time'    => 1700000000,
				'checked' => 1700000000,
				'count'   => 1,
			),
		);
		$GLOBALS['blt_test_options'][ Blt_Secure_Baseline::store_name( 'plugin/plug' ) ] = $hashes;
		return $hashes;
	}

	public function test_legacy_diff_ignores_newly_covered_file_types_and_oversize_files() {
		$baseline = array( 'plug.php' => 'a' );
		$current  = array(
			'plug.php'    => 'a',
			'app.js'      => 'j',     // Newly covered type.
			'.htaccess'   => 'h',     // Newly covered name.
			'new.php'     => 'n',     // Old scope, small: a real addition.
			'huge.php'    => 'g',     // Old scope but over 2 MB: the old scanner skipped it.
			'gone-now.js' => 'x',
		);
		$sizes    = array(
			'new.php'  => 100,
			'huge.php' => Blt_Secure_Baseline_Scanner::LEGACY_MAX_FILE_BYTES + 1,
		);
		$diff     = Blt_Secure_Baseline_Scanner::legacy_diff(
			$baseline,
			$current,
			static function ( $path ) use ( $sizes ) {
				return isset( $sizes[ $path ] ) ? $sizes[ $path ] : null;
			}
		);
		$this->assertSame( array( 'new.php' ), $diff['added'] );
		$this->assertSame( array(), $diff['modified'] );
		$this->assertSame( array(), $diff['removed'] );
	}

	public function test_legacy_diff_keeps_full_evidence_for_previously_monitored_files() {
		$diff = Blt_Secure_Baseline_Scanner::legacy_diff(
			array( 'a.php' => '1', 'b.php' => '2' ),
			array( 'a.php' => 'CHANGED' ),
			static function () {
				return 10;
			}
		);
		$this->assertSame( array( 'a.php' ), $diff['modified'] );
		$this->assertSame( array( 'b.php' ), $diff['removed'] );
	}

	public function test_is_legacy_scope_matches_the_old_hashable_set_only() {
		foreach ( array( 'a.php', 'A.PHP', 'x/y.phtml', 'z.inc', 'w.php5' ) as $path ) {
			$this->assertTrue( Blt_Secure_Baseline_Scanner::is_legacy_scope( $path ), $path );
		}
		foreach ( array( 'a.js', 'b.json', '.htaccess', '.user.ini', 'c.phar', 'd.php8', 'e.txt' ) as $path ) {
			$this->assertFalse( Blt_Secure_Baseline_Scanner::is_legacy_scope( $path ), $path );
		}
	}

	public function test_upgrade_with_unchanged_plugin_is_not_false_drift_and_adopts_the_wider_scope() {
		// A normal plugin: PHP plus JS, JSON and an .htaccess that the old scanner never hashed.
		file_put_contents( $this->dir . '/plug/app.js', 'console.log(1);' );
		file_put_contents( $this->dir . '/plug/block.json', '{}' );
		file_put_contents( $this->dir . '/plug/.htaccess', 'Options -Indexes' );
		$this->seed_legacy_baseline();

		$payload = $this->module( '1.0' )->run_scan();

		$this->assertSame( array(), $payload['findings'], 'Unchanged files must not be reported as "added" after an upgrade.' );
		$index = get_option( Blt_Secure_Baseline::BASELINE_OPTION );
		$this->assertSame( Blt_Secure_Baseline_Scanner::SCOPE, $index['plugin/plug']['scope'] );
		$this->assertSame( 'wporg_checksums', $index['plugin/plug']['trust'], 'The entry keeps the trust it earned.' );
		$this->assertSame( 1700000000, $index['plugin/plug']['time'] );
		$stored = get_option( Blt_Secure_Baseline::store_name( 'plugin/plug' ) );
		$this->assertArrayHasKey( 'app.js', $stored, 'Newly covered files are recorded.' );
		$this->assertArrayHasKey( '.htaccess', $stored );

		// And the wider scope really is monitored from then on.
		file_put_contents( $this->dir . '/plug/app.js', 'document.write(unescape("%3Cscript..."));' );
		$again = $this->module( '1.0' )->run_scan();
		$this->assertCount( 1, $again['findings'] );
		$this->assertSame( array( 'app.js' ), $again['findings'][0]['files'] );
	}

	public function test_upgrade_still_reports_real_changes_to_previously_monitored_files() {
		file_put_contents( $this->dir . '/plug/app.js', 'console.log(1);' );
		$this->seed_legacy_baseline();
		file_put_contents( $this->dir . '/plug/plug.php', '<?php eval(base64_decode($_POST[1]));' );
		file_put_contents( $this->dir . '/plug/dropper.php', '<?php // new file' );

		$payload = $this->module( '1.0' )->run_scan();

		$this->assertCount( 1, $payload['findings'] );
		$finding = $payload['findings'][0];
		$this->assertSame( 'drift', $finding['kind'] );
		$this->assertSame( 1, $finding['modified'] );
		$this->assertSame( 1, $finding['added'], 'Only the new PHP file; the pre-existing app.js is not an addition.' );
		$this->assertNotContains( 'app.js', $finding['files'] );

		$index = get_option( Blt_Secure_Baseline::BASELINE_OPTION );
		$this->assertArrayNotHasKey( 'scope', $index['plugin/plug'], 'A dirty legacy baseline is not upgraded over evidence of tampering.' );
		$stored = get_option( Blt_Secure_Baseline::store_name( 'plugin/plug' ) );
		$this->assertSame( md5( '<?php // v1' ), $stored['plug.php'], 'The original hash is kept so the drift keeps surfacing.' );
	}

	public function test_a_new_javascript_file_alone_is_not_drift_on_a_legacy_baseline() {
		$this->seed_legacy_baseline();
		file_put_contents( $this->dir . '/plug/added-later.js', 'x' );
		$payload = $this->module( '1.0' )->run_scan();
		$this->assertSame( array(), $payload['findings'] );
	}
}
