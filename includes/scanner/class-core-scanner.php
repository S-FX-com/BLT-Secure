<?php
/**
 * Core file integrity scanner.
 *
 * Verifies the installed WordPress core files against the official md5
 * checksums published by api.wordpress.org — the same data `wp core verify-
 * checksums` uses. No local baseline is stored (wp.org is the source of
 * truth), so it works on locked-down shared hosting with nothing to seed.
 *
 * Scope is core only: files under wp-admin/, wp-includes/, and the root
 * wp-*.php scripts. wp-content/ is deliberately excluded — deleting the
 * bundled default themes/plugins is normal and would otherwise read as
 * "missing core files".
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Fetches checksums and diffs them against disk.
 */
class Blt_Secure_Core_Scanner {

	const STATUS_MODIFIED = 'modified';
	const STATUS_MISSING  = 'missing';
	const STATUS_UNKNOWN  = 'unknown';

	/**
	 * Hard cap on reported issues so a badly broken install cannot produce a
	 * multi-megabyte option row.
	 */
	const MAX_ISSUES = 200;

	/**
	 * Extra issues allowed for the unknown-file pass, which always runs (it is
	 * the backdoor check) even when the manifest pass already hit MAX_ISSUES.
	 */
	const MAX_UNKNOWN = 100;

	/**
	 * Manifest files the Health Check itself tells users to delete
	 * (readme.html / license.txt fingerprint the version; wp-config-sample.php
	 * is a leftover) and many hosts remove. Absent is fine — never "missing".
	 * A MODIFIED copy is still reported.
	 *
	 * @return string[]
	 */
	public static function optional_files() {
		$files = array( 'readme.html', 'license.txt', 'wp-config-sample.php' );

		/**
		 * Filter core files whose absence is not reported.
		 *
		 * @param string[] $files ABSPATH-relative paths.
		 */
		$files = apply_filters( 'blt_secure_core_optional_files', $files );
		return is_array( $files ) ? $files : array();
	}

	/**
	 * Files whose content differs between WordPress locales. When the official
	 * manifest for the site's locale is unavailable and the en_US manifest is
	 * used instead, these cannot be compared and are skipped.
	 *
	 * @return string[]
	 */
	public static function locale_variant_files() {
		return array( 'readme.html', 'license.txt', 'wp-includes/version.php', 'wp-config-sample.php' );
	}

	/**
	 * Root-level files that legitimately exist beside core but are not in the
	 * checksum manifest (site-specific config).
	 *
	 * @return string[]
	 */
	public static function root_allowlist() {
		$files = array( 'wp-config.php' );

		/**
		 * Filter root files the unknown-file pass accepts.
		 *
		 * @param string[] $files ABSPATH-relative file names.
		 */
		$files = apply_filters( 'blt_secure_core_root_allowlist', $files );
		return is_array( $files ) ? $files : array();
	}

	/**
	 * Whether the en_US manifest was used for a different site locale.
	 *
	 * @var bool
	 */
	protected $used_fallback = false;

	/**
	 * Decide a file's status from expected vs actual md5.
	 *
	 * Pure function (unit-tested). Returns a status constant, or '' when the
	 * file matches its checksum.
	 *
	 * @param string      $expected Expected md5 hash.
	 * @param string|null $actual   Actual md5, or null when the file is absent.
	 * @return string
	 */
	public static function classify( $expected, $actual ) {
		if ( null === $actual ) {
			return self::STATUS_MISSING;
		}
		if ( ! hash_equals( (string) $expected, (string) $actual ) ) {
			return self::STATUS_MODIFIED;
		}
		return '';
	}

	/**
	 * Files present on disk but absent from the checksum manifest.
	 *
	 * Pure function (unit-tested). Both lists are ABSPATH-relative,
	 * forward-slash paths.
	 *
	 * @param string[] $found On-disk paths under the scanned core dirs.
	 * @param string[] $known Checksum manifest paths.
	 * @return string[]
	 */
	public static function unknown_files( array $found, array $known ) {
		$known_map = array_fill_keys( $known, true );
		$unknown   = array();
		foreach ( $found as $path ) {
			if ( ! isset( $known_map[ $path ] ) ) {
				$unknown[] = $path;
			}
		}
		return $unknown;
	}

	/**
	 * Whether a checksum path is in scope (core dirs, not wp-content).
	 *
	 * @param string $path ABSPATH-relative path.
	 * @return bool
	 */
	public static function in_scope( $path ) {
		return 0 !== strpos( $path, 'wp-content/' );
	}

	/**
	 * Run a full scan and return a storable payload.
	 *
	 * @return array{time:int,version:string,error:string,checked:int,issues:array,truncated:bool}
	 */
	public function run() {
		$version = $this->core_version();
		$locale  = function_exists( 'get_locale' ) ? get_locale() : 'en_US';

		$checksums = $this->fetch_checksums( $version, $locale );
		if ( empty( $checksums ) || ! is_array( $checksums ) ) {
			return $this->payload( $version, __( 'Could not fetch official checksums from api.wordpress.org. Check outbound connectivity and try again.', 'blt-secure' ), 0, array(), false );
		}

		$issues    = array();
		$checked   = 0;
		$truncated = false;
		$known     = array();
		$optional  = self::optional_files();
		$variant   = $this->used_fallback ? self::locale_variant_files() : array();

		foreach ( $checksums as $path => $expected ) {
			$path = ltrim( str_replace( '\\', '/', (string) $path ), '/' );
			if ( ! self::in_scope( $path ) ) {
				continue;
			}
			// Every in-scope manifest path is "known", even once verification has stopped: the
			// unknown-file pass below must never see a genuine core file as an extra one.
			$known[] = $path;
			if ( $truncated ) {
				continue; // Issue cap reached: stop verifying, keep collecting known paths.
			}
			if ( in_array( $path, $variant, true ) ) {
				continue; // Locale-specific content; the en_US manifest cannot vouch for it.
			}
			++$checked;

			$full   = ABSPATH . $path;
			$actual = is_readable( $full ) ? md5_file( $full ) : null;
			if ( false === $actual ) {
				$actual = null;
			}
			$status = self::classify( $expected, $actual );
			if ( '' === $status ) {
				continue;
			}
			if ( self::STATUS_MISSING === $status && in_array( $path, $optional, true ) ) {
				continue;
			}
			if ( count( $issues ) >= self::MAX_ISSUES ) {
				$truncated = true;
				continue;
			}
			$hash     = ( self::STATUS_MODIFIED === $status && is_string( $actual ) ) ? $actual : '';
			$issues[] = array(
				'path'        => $path,
				'status'      => $status,
				'hash'        => $hash,
				'fingerprint' => Blt_Secure_Scan_Whitelist::fingerprint( 'core', array( $status, $path, $hash ) ),
			);
		}

		// Unexpected extra executable files in the core directories and the
		// ABSPATH root (a classic backdoor drop). Always runs — it has its own
		// allowance so a noisy manifest pass cannot switch it off.
		$found   = $this->list_core_php_files();
		$unknown = self::unknown_files( $found, $known );
		$allowed = self::MAX_UNKNOWN;
		foreach ( $unknown as $path ) {
			if ( $allowed <= 0 ) {
				$truncated = true;
				break;
			}
			--$allowed;
			$full     = ABSPATH . $path;
			$md5      = is_readable( $full ) ? md5_file( $full ) : false;
			$hash     = false === $md5 ? '' : (string) $md5;
			$issues[] = array(
				'path'        => $path,
				'status'      => self::STATUS_UNKNOWN,
				'hash'        => $hash,
				'fingerprint' => Blt_Secure_Scan_Whitelist::fingerprint( 'core', array( self::STATUS_UNKNOWN, $path, $hash ) ),
			);
		}

		return $this->payload( $version, '', $checked, $issues, $truncated );
	}

	/**
	 * Assemble the storable payload.
	 *
	 * @param string $version   Core version scanned.
	 * @param string $error     Error message, or '' on success.
	 * @param int    $checked   Number of core files verified.
	 * @param array  $issues    Issue rows.
	 * @param bool   $truncated Whether the issue list was capped.
	 * @return array
	 */
	private function payload( $version, $error, $checked, array $issues, $truncated ) {
		return array(
			'time'      => time(),
			'version'   => (string) $version,
			'error'     => (string) $error,
			'checked'   => (int) $checked,
			'issues'    => $issues,
			'truncated' => (bool) $truncated,
		);
	}

	/**
	 * Installed core version.
	 *
	 * @return string
	 */
	private function core_version() {
		global $wp_version;
		if ( isset( $wp_version ) && '' !== $wp_version ) {
			return $wp_version;
		}
		return function_exists( 'get_bloginfo' ) ? (string) get_bloginfo( 'version' ) : '';
	}

	/**
	 * Fetch the checksum manifest, preferring core's helper and falling back
	 * to a direct API call.
	 *
	 * @param string $version Core version.
	 * @param string $locale  Locale.
	 * @return array|false path => md5 map, or false on failure.
	 */
	protected function fetch_checksums( $version, $locale ) {
		$this->used_fallback = false;
		if ( '' === $version ) {
			return false;
		}
		$locale = empty( $locale ) ? 'en_US' : $locale;

		$update_php = ABSPATH . 'wp-admin/includes/update.php';
		if ( is_readable( $update_php ) ) {
			require_once $update_php;
		}
		if ( function_exists( 'get_core_checksums' ) ) {
			$checksums = get_core_checksums( $version, $locale );
			if ( is_array( $checksums ) && ! empty( $checksums ) ) {
				return $checksums;
			}
			// No manifest for this locale yet: fall back to en_US, but flag it so
			// the files that differ per locale are not compared against it.
			if ( 'en_US' !== $locale ) {
				$checksums = get_core_checksums( $version, 'en_US' );
				if ( is_array( $checksums ) && ! empty( $checksums ) ) {
					$this->used_fallback = true;
					return $checksums;
				}
			}
		}

		// Direct fallback.
		$url      = 'https://api.wordpress.org/core/checksums/1.0/?' . http_build_query(
			array(
				'version' => $version,
				'locale'  => $locale,
			)
		);
		$response = wp_remote_get( $url, array( 'timeout' => 20 ) );
		if ( is_wp_error( $response ) ) {
			return false;
		}
		$body = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( isset( $body['checksums'] ) && is_array( $body['checksums'] ) ) {
			return $body['checksums'];
		}
		return false;
	}

	/**
	 * List every executable-extension file (the malware scanner's PHP
	 * extension set, not just .php) under wp-admin / wp-includes, plus the
	 * ABSPATH root level, ABSPATH-relative.
	 *
	 * @return string[]
	 */
	protected function list_core_php_files() {
		if ( ! class_exists( 'Blt_Secure_Malware_Scanner' ) ) {
			require_once BLT_SECURE_DIR . 'includes/scanner/class-malware-scanner.php';
		}

		$found = array();

		// Root level (one deep): wp-config.php and look-alike wp-*.php drops.
		$root_ok = self::root_allowlist();
		try {
			foreach ( new FilesystemIterator( ABSPATH, FilesystemIterator::SKIP_DOTS ) as $file ) {
				if ( ( $file->isFile() || $file->isLink() ) && Blt_Secure_Malware_Scanner::is_php_file( $file->getFilename() ) && ! in_array( $file->getFilename(), $root_ok, true ) ) {
					$found[] = $file->getFilename();
				}
			}
		} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
			unset( $e );
		}

		foreach ( array( 'wp-admin', 'wp-includes' ) as $dir ) {
			$base = ABSPATH . $dir;
			if ( ! is_dir( $base ) ) {
				continue;
			}
			try {
				$iterator = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $base, FilesystemIterator::SKIP_DOTS )
				);
			} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
				continue;
			}
			foreach ( $iterator as $file ) {
				if ( ! ( $file->isFile() || $file->isLink() ) || ! Blt_Secure_Malware_Scanner::is_php_file( $file->getFilename() ) ) {
					continue;
				}
				$rel     = str_replace( '\\', '/', substr( $file->getPathname(), strlen( ABSPATH ) ) );
				$found[] = ltrim( $rel, '/' );
			}
		}
		return $found;
	}
}
