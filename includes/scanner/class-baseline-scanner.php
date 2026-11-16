<?php
/**
 * Plugin/theme file-integrity baseline engine.
 *
 * There are no official checksums for most plugins and themes, so integrity is
 * tracked against a locally-stored baseline: on first sight the file hashes
 * are recorded (trust on first use); between versions, any change to those
 * files is unexpected and reported. A version change re-baselines ONLY when it
 * is confirmed — by a real update event (the upgrader ran), by wp.org's
 * published plugin checksums, or by the admin acknowledging the finding. A
 * bare edit of the Version header is not a confirmation: it would otherwise
 * let a tamperer launder a modification into the baseline.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hashes an extension's code files and diffs against a stored baseline.
 */
class Blt_Secure_Baseline_Scanner {

	/**
	 * Extensions with more hashable files than this are reported as
	 * "unmonitored" rather than silently dropped (bounds scan cost).
	 */
	const MAX_FILES = 20000;

	/**
	 * Files larger than this are not hashed; their size is recorded instead so
	 * a change is still detected.
	 */
	const MAX_FILE_BYTES = 16777216; // 16 MB.

	/**
	 * Why the last hash_dir() call returned null: 'too_large' | 'unreadable' | ''.
	 *
	 * @var string
	 */
	public $last_reason = '';

	/**
	 * Names/extensions worth hashing: every PHP-handler extension, plus the
	 * script and config files an attacker uses to inject behaviour without
	 * touching PHP (JS skimmers, .htaccess/.user.ini handler tricks).
	 *
	 * @param string $path File path.
	 * @return bool
	 */
	public static function is_hashable( $path ) {
		$name = strtolower( basename( str_replace( '\\', '/', (string) $path ) ) );
		if ( in_array( $name, array( '.htaccess', '.user.ini', 'php.ini', 'web.config' ), true ) ) {
			return true;
		}
		$ext = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
		if ( in_array( $ext, array( 'js', 'mjs', 'json' ), true ) ) {
			return true;
		}
		if ( ! class_exists( 'Blt_Secure_Malware_Scanner' ) ) {
			require_once BLT_SECURE_DIR . 'includes/scanner/class-malware-scanner.php';
		}
		return Blt_Secure_Malware_Scanner::is_php_file( $name );
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
	 * Decide what to do with an extension given its stored baseline.
	 *
	 * Pure function (unit-tested).
	 *  - 'baseline': nothing stored — record the current state (trust on first use).
	 *  - 'compare':  same version — any change is drift.
	 *  - 'accept':   version changed AND the change is confirmed — re-baseline.
	 *  - 'flag':     version changed with NO confirmation — keep the old
	 *                baseline and report it.
	 *
	 * @param array|null $stored       Stored index entry (needs 'version'), or null.
	 * @param string     $version      Version found on disk.
	 * @param bool       $confirmed    A real update event or wp.org checksums vouch for it.
	 * @param bool       $acknowledged The admin ignored the "version bumped" finding.
	 * @return string
	 */
	public static function rebaseline_decision( $stored, $version, $confirmed, $acknowledged ) {
		if ( ! is_array( $stored ) || ! isset( $stored['version'] ) ) {
			return 'baseline';
		}
		if ( (string) $stored['version'] === (string) $version ) {
			return 'compare';
		}
		return ( $confirmed || $acknowledged ) ? 'accept' : 'flag';
	}

	/**
	 * Parse a wp.org plugin-checksums JSON body into path => list of md5s.
	 *
	 * Pure function (unit-tested). Returns null on anything unusable.
	 *
	 * @param string $body JSON body of downloads.wordpress.org/plugin-checksums/{slug}/{version}.json.
	 * @return array<string,string[]>|null
	 */
	public static function parse_manifest( $body ) {
		$data = json_decode( (string) $body, true );
		if ( ! is_array( $data ) || empty( $data['files'] ) || ! is_array( $data['files'] ) ) {
			return null;
		}
		$out = array();
		foreach ( $data['files'] as $path => $info ) {
			if ( ! is_array( $info ) || ! isset( $info['md5'] ) ) {
				continue;
			}
			$sums = array_values( array_filter( array_map( 'strval', (array) $info['md5'] ) ) );
			if ( ! empty( $sums ) ) {
				$out[ ltrim( str_replace( '\\', '/', (string) $path ), '/' ) ] = $sums;
			}
		}
		return empty( $out ) ? null : $out;
	}

	/**
	 * Whether every hashed file matches the published manifest. A file that is
	 * absent from the manifest (an addition) or differs fails the match.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param array $hashes   path => md5 for the extension on disk.
	 * @param array $manifest path => md5 list (see parse_manifest()).
	 * @return bool
	 */
	public static function matches_manifest( array $hashes, array $manifest ) {
		if ( empty( $hashes ) ) {
			return false;
		}
		foreach ( $hashes as $path => $hash ) {
			if ( ! isset( $manifest[ $path ] ) || ! in_array( (string) $hash, $manifest[ $path ], true ) ) {
				return false;
			}
		}
		return true;
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
	 * Hash every hashable file under a directory, dir-relative.
	 *
	 * Symlinks are recorded as "link:<target>" (never followed); files over
	 * MAX_FILE_BYTES as "big:<bytes>" so growth/shrinkage still registers.
	 *
	 * @param string $dir Absolute directory.
	 * @return array|null path => hash map, or null when the tree is too large
	 *                    or unreadable (see $last_reason).
	 */
	public function hash_dir( $dir ) {
		$this->last_reason = '';
		if ( ! is_dir( $dir ) ) {
			$this->last_reason = 'unreadable';
			return null;
		}
		try {
			$dir_it   = new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS );
			$filter   = new RecursiveCallbackFilterIterator(
				$dir_it,
				static function ( $current ) {
					if ( $current->isDir() && ! $current->isLink() ) {
						return ! in_array( $current->getFilename(), array( 'node_modules', '.git', '.svn', '.hg' ), true );
					}
					return true;
				}
			);
			$iterator = new RecursiveIteratorIterator( $filter );
		} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
			$this->last_reason = 'unreadable';
			return null;
		}

		$hashes = array();
		$prefix = strlen( rtrim( str_replace( '\\', '/', $dir ), '/' ) ) + 1;
		foreach ( $iterator as $file ) {
			$path = $file->getPathname();
			$rel  = str_replace( '\\', '/', substr( $path, $prefix ) );

			if ( $file->isLink() ) {
				$hashes[ $rel ] = 'link:' . md5( (string) @readlink( $path ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			} elseif ( $file->isFile() && self::is_hashable( $path ) ) {
				if ( $file->getSize() > self::MAX_FILE_BYTES ) {
					$hashes[ $rel ] = 'big:' . $file->getSize();
				} else {
					$md5 = @md5_file( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
					if ( false !== $md5 ) {
						$hashes[ $rel ] = $md5;
					}
				}
			} else {
				continue;
			}

			if ( count( $hashes ) > self::MAX_FILES ) {
				$this->last_reason = 'too_large';
				return null; // Too large to baseline reliably.
			}
		}
		return $hashes;
	}
}
