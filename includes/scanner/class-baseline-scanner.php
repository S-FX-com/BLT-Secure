<?php
/**
 * Plugin/theme file-integrity baseline engine.
 *
 * There are no official checksums for arbitrary plugins and themes, so
 * integrity is tracked against a locally-stored baseline: on first sight (or
 * after a legitimate version change) the file hashes are recorded; between
 * versions, any change to those files is unexpected and reported. Keying the
 * baseline by version means a normal update re-baselines cleanly instead of
 * producing false positives.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hashes an extension's PHP files and diffs against a stored baseline.
 */
class Blt_Secure_Baseline_Scanner {

	/**
	 * Skip extensions with more PHP files than this (bounds option size and
	 * scan cost; such trees are hashed as a whole-count only).
	 */
	const MAX_FILES = 5000;

	/**
	 * Skip individual files larger than this when hashing.
	 */
	const MAX_FILE_BYTES = 2097152; // 2 MB.

	/**
	 * Whether a path is a PHP-family source file (the integrity-relevant set).
	 *
	 * @param string $path File path.
	 * @return bool
	 */
	public static function is_hashable( $path ) {
		$ext = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
		return in_array( $ext, array( 'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'pht', 'inc' ), true );
	}

	/**
	 * Diff two path => hash maps.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param array $baseline Baseline hashes.
	 * @param array $current  Current hashes.
	 * @return array{added:string[],modified:string[],removed:string[]}
	 */
	public static function diff( array $baseline, array $current ) {
		$added    = array_values( array_diff( array_keys( $current ), array_keys( $baseline ) ) );
		$removed  = array_values( array_diff( array_keys( $baseline ), array_keys( $current ) ) );
		$modified = array();
		foreach ( $current as $path => $hash ) {
			if ( isset( $baseline[ $path ] ) && ! hash_equals( (string) $baseline[ $path ], (string) $hash ) ) {
				$modified[] = $path;
			}
		}
		sort( $added );
		sort( $removed );
		sort( $modified );
		return array(
			'added'    => $added,
			'modified' => $modified,
			'removed'  => $removed,
		);
	}

	/**
	 * Whether a diff found any change.
	 *
	 * @param array $diff Diff result.
	 * @return bool
	 */
	public static function has_changes( array $diff ) {
		return ! empty( $diff['added'] ) || ! empty( $diff['modified'] ) || ! empty( $diff['removed'] );
	}

	/**
	 * Content-sensitive whitelist fingerprint for a drift finding.
	 *
	 * Pure function (unit-tested). Folds the current hash of every changed
	 * file into the fingerprint so that ignoring a drift finding only
	 * suppresses that exact set of changes — if a whitelisted file is altered
	 * again (e.g. a backdoor edited into an already-accepted change), its hash
	 * differs and the finding re-appears. Removed files (no current hash) key
	 * on a stable marker so re-adding one with content re-flags.
	 *
	 * @param string   $key     Extension key (slug/version namespace).
	 * @param string   $version Extension version.
	 * @param string[] $changed Every changed path (added/modified/removed).
	 * @param array    $current Current path => md5 map.
	 * @return string
	 */
	public static function drift_fingerprint( $key, $version, array $changed, array $current ) {
		$changed = array_values( array_unique( $changed ) );
		sort( $changed );
		$parts = array();
		foreach ( $changed as $file ) {
			$parts[] = $file . ':' . ( isset( $current[ $file ] ) ? (string) $current[ $file ] : 'removed' );
		}
		return Blt_Secure_Scan_Whitelist::fingerprint( 'baseline', array( (string) $key, (string) $version, implode( ',', $parts ) ) );
	}

	/**
	 * Hash every PHP-family file under a directory, dir-relative.
	 *
	 * @param string $dir Absolute directory.
	 * @return array|null path => md5 map, or null when the tree is too large
	 *                    or unreadable.
	 */
	public function hash_dir( $dir ) {
		if ( ! is_dir( $dir ) ) {
			return null;
		}
		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS )
			);
		} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
			return null;
		}

		$hashes = array();
		$prefix = strlen( rtrim( str_replace( '\\', '/', $dir ), '/' ) ) + 1;
		foreach ( $iterator as $file ) {
			if ( ! $file->isFile() || ! self::is_hashable( $file->getPathname() ) ) {
				continue;
			}
			if ( count( $hashes ) >= self::MAX_FILES ) {
				return null; // Too large to baseline reliably.
			}
			if ( $file->getSize() > self::MAX_FILE_BYTES ) {
				continue;
			}
			$rel = str_replace( '\\', '/', substr( $file->getPathname(), $prefix ) );
			$md5 = md5_file( $file->getPathname() );
			if ( false !== $md5 ) {
				$hashes[ $rel ] = $md5;
			}
		}
		return $hashes;
	}
}
