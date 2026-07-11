<?php
/**
 * Scanner finding whitelist ("ignore" list).
 *
 * Lets an admin acknowledge a specific scanner warning so it no longer counts
 * against the Health Check score, no longer raises alerts, and is moved out of
 * the active findings list on the Scanner tab. Findings are keyed by a stable
 * fingerprint each scanner computes for its own findings (see fingerprint()).
 *
 * For content-based findings (core "modified"/"unknown" files, malware
 * signature/hash matches) the fingerprint includes the file's content hash, so
 * ignoring is scoped to that exact file content — if the file changes, the
 * finding re-appears. Structural findings (a stray file type in uploads,
 * plugin/theme drift) key on path/change-set instead.
 *
 * Stored in the non-autoloaded `blt_secure_scan_whitelist` option.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Reads/writes the whitelist and filters finding lists by it.
 */
class Blt_Secure_Scan_Whitelist {

	const OPTION = 'blt_secure_scan_whitelist';

	/**
	 * Hard cap on stored entries so the option cannot grow without bound. When
	 * exceeded, the oldest entries are dropped.
	 */
	const MAX_ENTRIES = 1000;

	/**
	 * Build a stable fingerprint for a finding.
	 *
	 * Pure function (unit-tested). The scanner id namespaces the parts so two
	 * scanners cannot collide, and the parts are the identity of the finding.
	 *
	 * @param string $scanner Scanner id (e.g. 'core', 'malware', 'baseline').
	 * @param array  $parts   Identity components (path, status, hash, …).
	 * @return string 40-char hex fingerprint.
	 */
	public static function fingerprint( $scanner, array $parts ) {
		$normalized = array();
		foreach ( $parts as $part ) {
			$normalized[] = (string) $part;
		}
		return sha1( (string) $scanner . '|' . implode( '|', $normalized ) );
	}

	/**
	 * All whitelist entries, keyed by fingerprint.
	 *
	 * @return array<string,array>
	 */
	public function all() {
		$stored = get_option( self::OPTION, array() );
		return is_array( $stored ) ? $stored : array();
	}

	/**
	 * Whether a fingerprint is whitelisted.
	 *
	 * @param string $fingerprint Finding fingerprint.
	 * @return bool
	 */
	public function is_whitelisted( $fingerprint ) {
		if ( '' === (string) $fingerprint ) {
			return false;
		}
		$all = $this->all();
		return isset( $all[ (string) $fingerprint ] );
	}

	/**
	 * Add (or refresh) a whitelist entry.
	 *
	 * @param string $fingerprint Finding fingerprint.
	 * @param array  $meta        Display/audit metadata: scanner, label, time, user.
	 * @return bool
	 */
	public function add( $fingerprint, array $meta = array() ) {
		$fingerprint = (string) $fingerprint;
		if ( ! self::is_valid_fingerprint( $fingerprint ) ) {
			return false;
		}

		$all                 = $this->all();
		$all[ $fingerprint ] = array(
			'scanner' => isset( $meta['scanner'] ) ? (string) $meta['scanner'] : '',
			'label'   => isset( $meta['label'] ) ? (string) $meta['label'] : '',
			'time'    => isset( $meta['time'] ) ? (int) $meta['time'] : time(),
			'user'    => isset( $meta['user'] ) ? (int) $meta['user'] : 0,
		);

		// Bound the option: drop the oldest entries beyond the cap.
		if ( count( $all ) > self::MAX_ENTRIES ) {
			uasort(
				$all,
				static function ( $a, $b ) {
					$ta = isset( $a['time'] ) ? (int) $a['time'] : 0;
					$tb = isset( $b['time'] ) ? (int) $b['time'] : 0;
					return $ta <=> $tb;
				}
			);
			$all = array_slice( $all, count( $all ) - self::MAX_ENTRIES, null, true );
		}

		return update_option( self::OPTION, $all, false );
	}

	/**
	 * Remove a whitelist entry.
	 *
	 * @param string $fingerprint Finding fingerprint.
	 * @return bool
	 */
	public function remove( $fingerprint ) {
		$fingerprint = (string) $fingerprint;
		$all         = $this->all();
		if ( ! isset( $all[ $fingerprint ] ) ) {
			return false;
		}
		unset( $all[ $fingerprint ] );
		return update_option( self::OPTION, $all, false );
	}

	/**
	 * Findings that are NOT whitelisted (the ones still worth showing/scoring).
	 *
	 * @param array[] $findings Findings, each optionally carrying 'fingerprint'.
	 * @return array[]
	 */
	public function active( array $findings ) {
		$all = $this->all();
		return array_values(
			array_filter(
				$findings,
				static function ( $finding ) use ( $all ) {
					$fp = is_array( $finding ) && isset( $finding['fingerprint'] ) ? (string) $finding['fingerprint'] : '';
					return '' === $fp || ! isset( $all[ $fp ] );
				}
			)
		);
	}

	/**
	 * Findings that ARE whitelisted.
	 *
	 * @param array[] $findings Findings, each optionally carrying 'fingerprint'.
	 * @return array[]
	 */
	public function ignored( array $findings ) {
		$all = $this->all();
		return array_values(
			array_filter(
				$findings,
				static function ( $finding ) use ( $all ) {
					$fp = is_array( $finding ) && isset( $finding['fingerprint'] ) ? (string) $finding['fingerprint'] : '';
					return '' !== $fp && isset( $all[ $fp ] );
				}
			)
		);
	}

	/**
	 * Count of active (non-whitelisted) findings.
	 *
	 * @param array[] $findings Findings.
	 * @return int
	 */
	public function count_active( array $findings ) {
		return count( $this->active( $findings ) );
	}

	/**
	 * Validate a fingerprint string (defence for the AJAX boundary).
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string $fingerprint Candidate.
	 * @return bool
	 */
	public static function is_valid_fingerprint( $fingerprint ) {
		return (bool) preg_match( '/^[a-f0-9]{40}$/', (string) $fingerprint );
	}
}
