<?php
/**
 * Feed changelog diff/entry + persistence tests.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure_Feed_Changelog logic.
 */
class Test_Feed_Changelog extends TestCase {

	protected function setUp(): void {
		$GLOBALS['blt_test_options'] = array();
	}

	public function test_diff_sets_added_and_removed() {
		$diff = Blt_Secure_Feed_Changelog::diff_sets(
			array( '1.1.1.1', '2.2.2.2' ),
			array( '2.2.2.2', '3.3.3.3' )
		);
		$this->assertSame( array( '3.3.3.3' ), $diff['added'] );
		$this->assertSame( array( '1.1.1.1' ), $diff['removed'] );
	}

	public function test_diff_sets_no_change() {
		$diff = Blt_Secure_Feed_Changelog::diff_sets( array( 'a', 'b' ), array( 'a', 'b' ) );
		$this->assertSame( array(), $diff['added'] );
		$this->assertSame( array(), $diff['removed'] );
	}

	public function test_build_entry_counts_and_samples() {
		$diff  = array(
			'added'   => range( 1, 20 ),
			'removed' => array( 'x' ),
		);
		$entry = Blt_Secure_Feed_Changelog::build_entry( $diff, 500, array( 'spamhaus-drop' => 500 ), 1700000000 );

		$this->assertSame( 1700000000, $entry['time'] );
		$this->assertSame( 500, $entry['total'] );
		$this->assertSame( 20, $entry['added'] );
		$this->assertSame( 1, $entry['removed'] );
		$this->assertCount( 10, $entry['sample_added'] ); // capped at SAMPLE.
		$this->assertSame( array( 'spamhaus-drop' => 500 ), $entry['per_feed'] );
	}

	public function test_record_persists_snapshot_and_log() {
		$log = new Blt_Secure_Feed_Changelog();

		// First refresh: everything is "added" relative to an empty snapshot.
		$first = $log->record( array( '1.1.1.1', '2.2.2.2' ), array( 'f' => 2 ) );
		$this->assertSame( 2, $first['added'] );
		$this->assertSame( 0, $first['removed'] );

		// Second refresh: one added, one removed.
		$second = $log->record( array( '2.2.2.2', '3.3.3.3' ), array( 'f' => 2 ) );
		$this->assertSame( 1, $second['added'] );
		$this->assertSame( 1, $second['removed'] );

		$entries = $log->entries( 10 );
		$this->assertCount( 2, $entries );
		// Newest first.
		$this->assertSame( $second['time'], $entries[0]['time'] );
	}
}
