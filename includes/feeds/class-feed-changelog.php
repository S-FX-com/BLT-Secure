<?php
/**
 * Feed changelog: track how the synced indicator set changes over time.
 *
 * Each feed refresh is diffed against the previous snapshot so the admin can
 * see what a sync actually added or removed — useful for auditing a threat
 * feed and for spotting a feed that suddenly balloons or empties. The diff
 * logic is pure and unit-tested; only snapshot/log persistence touches WP.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Records per-refresh indicator diffs into a rolling changelog.
 */
class Blt_Secure_Feed_Changelog {

	const SNAPSHOT_OPTION = 'blt_secure_feed_snapshot';
	const LOG_OPTION      = 'blt_secure_feed_changelog';

	const MAX_ENTRIES = 30;
	const SAMPLE      = 10;

	/**
	 * Diff two indicator sets.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string[] $old Previous indicators.
	 * @param string[] $new Current indicators.
	 * @return array{added:string[],removed:string[]}
	 */
	public static function diff_sets( array $old, array $new ) {
		return array(
			'added'   => array_values( array_diff( $new, $old ) ),
			'removed' => array_values( array_diff( $old, $new ) ),
		);
	}

	/**
	 * Build a changelog entry from a diff.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param array $diff     Result of diff_sets().
	 * @param int   $total    Current indicator count.
	 * @param array $per_feed feed id => count.
	 * @param int   $time     Timestamp.
	 * @return array
	 */
	public static function build_entry( array $diff, $total, array $per_feed, $time ) {
		return array(
			'time'           => (int) $time,
			'total'          => (int) $total,
			'added'          => count( $diff['added'] ),
			'removed'        => count( $diff['removed'] ),
			'per_feed'       => $per_feed,
			'sample_added'   => array_slice( $diff['added'], 0, self::SAMPLE ),
			'sample_removed' => array_slice( $diff['removed'], 0, self::SAMPLE ),
		);
	}

	/**
	 * Record a refresh: diff against the stored snapshot, append a changelog
	 * entry, and save the new snapshot. Fires blt_secure_alert with a
	 * feed_updated event when the set changed (informational; not in the
	 * default notify allowlist).
	 *
	 * @param string[]                 $ips      Current merged indicator set.
	 * @param array                    $per_feed feed id => count.
	 * @param Blt_Secure_Alerting|null $alerting Optional event sink.
	 * @return array The recorded entry.
	 */
	public function record( array $ips, array $per_feed = array(), $alerting = null ) {
		$previous = get_option( self::SNAPSHOT_OPTION, array() );
		$previous = is_array( $previous ) ? $previous : array();

		$diff  = self::diff_sets( $previous, $ips );
		$entry = self::build_entry( $diff, count( $ips ), $per_feed, time() );

		$log   = get_option( self::LOG_OPTION, array() );
		$log   = is_array( $log ) ? $log : array();
		$log[] = $entry;
		if ( count( $log ) > self::MAX_ENTRIES ) {
			$log = array_slice( $log, - self::MAX_ENTRIES );
		}

		update_option( self::LOG_OPTION, $log, false );
		update_option( self::SNAPSHOT_OPTION, $ips, false );

		if ( $alerting && ( $entry['added'] > 0 || $entry['removed'] > 0 ) ) {
			$alerting->notify(
				'feed_updated',
				array(
					'added'   => $entry['added'],
					'removed' => $entry['removed'],
					'total'   => $entry['total'],
				)
			);
		}

		return $entry;
	}

	/**
	 * Recent changelog entries, newest first.
	 *
	 * @param int $limit Max entries.
	 * @return array[]
	 */
	public function entries( $limit = self::MAX_ENTRIES ) {
		$log = get_option( self::LOG_OPTION, array() );
		if ( ! is_array( $log ) ) {
			return array();
		}
		return array_slice( array_reverse( $log ), 0, max( 1, (int) $limit ) );
	}
}
