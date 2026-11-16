<?php
/**
 * Buoy bridge tests: the `blt_secure_findings` payload contract with Buoy's
 * ingestMalwareFindings (DECISIONS D-2026-11-16-01).
 *
 * @package Blt_Secure
 */

require_once dirname( __DIR__ ) . '/includes/class-buoy-bridge.php';

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure_Buoy_Bridge::build() and the provider callback.
 */
class Test_Buoy_Bridge extends TestCase {

	/**
	 * Fresh in-memory options and filters.
	 *
	 * @return void
	 */
	protected function setUp(): void {
		$GLOBALS['blt_test_options'] = array();
	}

	/**
	 * A clean, complete scan payload.
	 *
	 * @param string $key   Findings key.
	 * @param array  $items Findings.
	 * @param array  $extra Extra payload keys.
	 * @return array
	 */
	private function payload( $key, array $items = array(), array $extra = array() ) {
		return array_merge(
			array(
				'time' => 1700000000,
				$key   => $items,
			),
			$extra
		);
	}

	private function malware_row( $type, $path, $severity, $fp ) {
		return array(
			'type'        => $type,
			'path'        => $path,
			'severity'    => $severity,
			'description' => 'Localised text that must never reach the signature.',
			'snippet'     => 'eval(base64_decode($_POST["x"]));',
			'fingerprint' => $fp,
		);
	}

	private function build( $core, $malware, $baseline, $allow_critical = false ) {
		return Blt_Secure_Buoy_Bridge::build( $core, $malware, $baseline, new Blt_Secure_Scan_Whitelist(), $allow_critical );
	}

	public function test_clean_site_is_an_empty_complete_list() {
		$out = $this->build(
			$this->payload( 'issues' ),
			$this->payload( 'findings' ),
			$this->payload( 'findings' )
		);
		$this->assertSame( array(), $out, 'No sentinel: Buoy may resolve everything it has open.' );
	}

	public function test_each_finding_is_exactly_severity_signature_path() {
		$out = $this->build(
			$this->payload( 'issues' ),
			$this->payload( 'findings', array( $this->malware_row( 'signature', 'wp-content/plugins/x/x.php', 'high', str_repeat( 'a', 40 ) ) ) ),
			$this->payload( 'findings' )
		);
		$this->assertCount( 1, $out );
		$this->assertSame( array( 'severity', 'signature', 'path' ), array_keys( $out[0] ) );
		$this->assertSame( 'wp-content/plugins/x/x.php', $out[0]['path'] );
	}

	public function test_no_snippet_or_description_leaves_the_site() {
		$out = $this->build(
			$this->payload( 'issues' ),
			$this->payload( 'findings', array( $this->malware_row( 'signature', 'a.php', 'high', str_repeat( 'b', 40 ) ) ) ),
			$this->payload( 'findings' )
		);
		$json = wp_json_encode( $out );
		$this->assertStringNotContainsString( 'eval(', $json );
		$this->assertStringNotContainsString( 'Localised', $json );
	}

	public function test_critical_is_capped_at_high_unless_allowed() {
		$rows = array( $this->malware_row( 'signature', 'a.php', 'critical', str_repeat( 'c', 40 ) ) );
		$out  = $this->build( $this->payload( 'issues' ), $this->payload( 'findings', $rows ), $this->payload( 'findings' ) );
		$this->assertSame( 'high', $out[0]['severity'], 'critical blocks updates in Buoy until a person triages it.' );

		$out = $this->build( $this->payload( 'issues' ), $this->payload( 'findings', $rows ), $this->payload( 'findings' ), true );
		$this->assertSame( 'critical', $out[0]['severity'] );
	}

	public function test_whitelisted_findings_are_excluded() {
		$fp        = str_repeat( 'd', 40 );
		$whitelist = new Blt_Secure_Scan_Whitelist();
		$whitelist->add( $fp, array( 'label' => 'ignored' ) );

		$out = Blt_Secure_Buoy_Bridge::build(
			$this->payload( 'issues' ),
			$this->payload(
				'findings',
				array(
					$this->malware_row( 'signature', 'ignored.php', 'high', $fp ),
					$this->malware_row( 'signature', 'kept.php', 'high', str_repeat( 'e', 40 ) ),
				)
			),
			$this->payload( 'findings' ),
			$whitelist
		);
		$this->assertSame( array( 'kept.php' ), array_column( $out, 'path' ) );
	}

	public function test_signature_is_stable_across_descriptions_and_distinct_per_finding() {
		$a = $this->malware_row( 'signature', 'a.php', 'high', str_repeat( '1', 40 ) );
		$b = $a;
		// A different language must not change the signature.
		$b['description'] = 'Beschreibung auf Deutsch';
		$c                = $this->malware_row( 'signature', 'a.php', 'high', str_repeat( '2', 40 ) );

		$one = $this->build( $this->payload( 'issues' ), $this->payload( 'findings', array( $a ) ), $this->payload( 'findings' ) );
		$two = $this->build( $this->payload( 'issues' ), $this->payload( 'findings', array( $b ) ), $this->payload( 'findings' ) );
		$thr = $this->build( $this->payload( 'issues' ), $this->payload( 'findings', array( $c ) ), $this->payload( 'findings' ) );

		$this->assertSame( $one[0]['signature'], $two[0]['signature'] );
		$this->assertNotSame( $one[0]['signature'], $thr[0]['signature'] );
	}

	public function test_core_and_baseline_findings_map_with_conservative_severity() {
		$out = $this->build(
			$this->payload(
				'issues',
				array(
					array(
						'path'        => 'wp-includes/version.php',
						'status'      => 'modified',
						'fingerprint' => str_repeat( '3', 40 ),
					),
					array(
						'path'        => 'wp-includes/extra.php',
						'status'      => 'unknown',
						'fingerprint' => str_repeat( '4', 40 ),
					),
				)
			),
			$this->payload( 'findings' ),
			$this->payload(
				'findings',
				array(
					array(
						'key'         => 'plugin:foo',
						'kind'        => 'version_bump',
						'modified'    => 2,
						'added'       => 0,
						'fingerprint' => str_repeat( '5', 40 ),
					),
					array(
						'key'         => 'plugin:bar',
						'kind'        => 'unmonitored',
						'fingerprint' => str_repeat( '6', 40 ),
					),
				)
			)
		);
		$by_path = array();
		foreach ( $out as $row ) {
			$by_path[ $row['path'] ] = $row['severity'];
		}
		$this->assertSame( 'high', $by_path['wp-includes/version.php'] );
		$this->assertSame( 'medium', $by_path['wp-includes/extra.php'] );
		$this->assertSame( 'high', $by_path['plugin:foo'], 'A version bump with differing files looks like tampering.' );
		$this->assertSame( 'low', $by_path['plugin:bar'] );
		$this->assertNotContains( 'critical', array_values( $by_path ) );
	}

	public function test_most_severe_first_and_sorted_before_the_cap() {
		$rows = array();
		for ( $i = 0; $i < 250; $i++ ) {
			$rows[] = $this->malware_row( 'code_in_uploads', sprintf( 'uploads/x%03d.svg', $i ), 'low', sprintf( '%040d', $i ) );
		}
		// The one that matters is last in scan order.
		$rows[] = $this->malware_row( 'signature', 'wp-content/plugins/evil/shell.php', 'high', str_repeat( 'f', 40 ) );

		$out = $this->build( $this->payload( 'issues' ), $this->payload( 'findings', $rows ), $this->payload( 'findings' ) );

		$this->assertSame( 'wp-content/plugins/evil/shell.php', $out[0]['path'], 'High severity must survive the cap.' );
		$this->assertCount( Blt_Secure_Buoy_Bridge::MAX_FINDINGS + 1, $out, '199 real findings plus the sentinel.' );
	}

	public function test_over_the_cap_appends_the_truncation_sentinel_last() {
		$rows = array();
		for ( $i = 0; $i < 230; $i++ ) {
			$rows[] = $this->malware_row( 'signature', sprintf( 'p%03d.php', $i ), 'medium', sprintf( '%040d', $i ) );
		}
		$out  = $this->build( $this->payload( 'issues' ), $this->payload( 'findings', $rows ), $this->payload( 'findings' ) );
		$last = end( $out );
		$this->assertSame( Blt_Secure_Buoy_Bridge::TRUNCATED_SIGNATURE, $last['signature'] );
		$this->assertLessThanOrEqual( 200, count( $out ), 'The agent slices at 200; the sentinel must never be what is cut.' );
	}

	/**
	 * @dataProvider incomplete_payloads
	 *
	 * @param array $core     Core payload.
	 * @param array $malware  Malware payload.
	 * @param array $baseline Baseline payload.
	 */
	public function test_a_scanner_that_did_not_finish_marks_the_list_incomplete( $core, $malware, $baseline ) {
		$out = $this->build( $core, $malware, $baseline );
		$sig = array_column( $out, 'signature' );
		$this->assertContains(
			Blt_Secure_Buoy_Bridge::TRUNCATED_SIGNATURE,
			$sig,
			'Missing or partial scan results are not proof of a clean site; Buoy must not resolve from them.'
		);
	}

	public function incomplete_payloads() {
		$ok = array(
			'time'     => 1,
			'findings' => array(),
		);
		$ci = array(
			'time'   => 1,
			'issues' => array(),
		);
		return array(
			'malware never ran'   => array( $ci, array(), $ok ),
			'core never ran'      => array( array(), $ok, $ok ),
			'baseline never ran'  => array( $ci, $ok, array() ),
			'malware partial'     => array( $ci, array_merge( $ok, array( 'partial' => true ) ), $ok ),
			'malware truncated'   => array( $ci, array_merge( $ok, array( 'truncated' => true ) ), $ok ),
			'core errored'        => array( array_merge( $ci, array( 'error' => 'checksums unavailable' ) ), $ok, $ok ),
			'options not arrays'  => array( false, false, false ),
		);
	}

	public function test_a_finding_without_a_path_is_dropped() {
		$out = $this->build(
			$this->payload( 'issues' ),
			$this->payload( 'findings', array( $this->malware_row( 'signature', '', 'high', str_repeat( '7', 40 ) ) ) ),
			$this->payload( 'findings' )
		);
		$this->assertSame( array(), $out );
	}

	public function test_unknown_severity_is_treated_as_medium_and_values_are_capped() {
		$long = str_repeat( 'a/', 400 ) . 'x.php';
		$out  = $this->build(
			$this->payload( 'issues' ),
			$this->payload( 'findings', array( $this->malware_row( 'signature', $long, 'catastrophic', str_repeat( '8', 40 ) ) ) ),
			$this->payload( 'findings' )
		);
		$this->assertSame( 'medium', $out[0]['severity'] );
		$this->assertLessThanOrEqual( 300, strlen( $out[0]['path'] ) );
		$this->assertLessThanOrEqual( 190, strlen( $out[0]['signature'] ) );
	}

	public function test_provider_reads_the_three_stored_scan_results() {
		$GLOBALS['blt_test_options']['blt_secure_malware_results']  = $this->payload( 'findings', array( $this->malware_row( 'signature', 'a.php', 'high', str_repeat( '9', 40 ) ) ) );
		$GLOBALS['blt_test_options']['blt_secure_core_scan_results'] = $this->payload( 'issues' );
		$GLOBALS['blt_test_options']['blt_secure_baseline_results']  = $this->payload( 'findings' );

		$bridge = new Blt_Secure_Buoy_Bridge( new Blt_Secure_Scan_Whitelist() );
		$out    = $bridge->provide( null );
		$this->assertIsArray( $out );
		$this->assertSame( 'a.php', $out[0]['path'] );
	}

	public function test_boot_registers_the_filter_the_agent_applies() {
		// The bootstrap's add_filter() is a no-op shim, so assert on the source:
		// BLT Connect calls apply_filters( 'blt_secure_findings', null ).
		$source = (string) file_get_contents( dirname( __DIR__ ) . '/includes/class-buoy-bridge.php' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$this->assertStringContainsString( "add_filter( 'blt_secure_findings', array( \$this, 'provide' )", $source );

		$bridge = new Blt_Secure_Buoy_Bridge( new Blt_Secure_Scan_Whitelist() );
		$bridge->boot();
		$this->addToAssertionCount( 1 ); // Registering must not throw or do I/O.
	}

	public function test_the_core_singleton_boots_the_bridge_outside_any_module() {
		// A module can be disabled; the findings surface must not depend on one.
		$root = dirname( __DIR__ );
		$main = (string) file_get_contents( $root . '/blt-secure.php' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$core = (string) file_get_contents( $root . '/includes/class-blt-secure.php' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents

		$this->assertStringContainsString( "includes/class-buoy-bridge.php'", $main );
		$this->assertStringContainsString( 'new Blt_Secure_Buoy_Bridge( $this->whitelist ) )->boot()', $core );
		$this->assertStringNotContainsString( 'Blt_Secure_Buoy_Bridge', substr( $core, 0, (int) strpos( $core, 'private function init()' ) ), 'Wired inside init(), not as a module.' );
	}
}
