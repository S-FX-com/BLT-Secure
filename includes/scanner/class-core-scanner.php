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

		foreach ( $checksums as $path => $expected ) {
			$path = ltrim( str_replace( '\\', '/', (string) $path ), '/' );
			if ( ! self::in_scope( $path ) ) {
				continue;
			}
			$known[] = $path;
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
			if ( count( $issues ) >= self::MAX_ISSUES ) {
				$truncated = true;
				break;
			}
			$issues[] = array(
				'path'   => $path,
				'status' => $status,
			);
		}

		// Unexpected extra .php files in the core directories (a classic
		// backdoor drop). Only run when we did not already hit the cap.
		if ( ! $truncated ) {
			$found   = $this->list_core_php_files();
			$unknown = self::unknown_files( $found, $known );
			foreach ( $unknown as $path ) {
				if ( count( $issues ) >= self::MAX_ISSUES ) {
					$truncated = true;
					break;
				}
				$issues[] = array(
					'path'   => $path,
					'status' => self::STATUS_UNKNOWN,
				);
			}
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
		if ( '' === $version ) {
			return false;
		}

		$update_php = ABSPATH . 'wp-admin/includes/update.php';
		if ( is_readable( $update_php ) ) {
			require_once $update_php;
		}
		if ( function_exists( 'get_core_checksums' ) ) {
			$checksums = get_core_checksums( $version, empty( $locale ) ? 'en_US' : $locale );
			if ( is_array( $checksums ) && ! empty( $checksums ) ) {
				return $checksums;
			}
			// Some locales return only a nested set; retry en_US as a floor.
			$checksums = get_core_checksums( $version, 'en_US' );
			if ( is_array( $checksums ) && ! empty( $checksums ) ) {
				return $checksums;
			}
		}

		// Direct fallback.
		$url      = 'https://api.wordpress.org/core/checksums/1.0/?' . http_build_query(
			array(
				'version' => $version,
				'locale'  => empty( $locale ) ? 'en_US' : $locale,
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
	 * List every .php file under the core directories, ABSPATH-relative.
	 *
	 * @return string[]
	 */
	protected function list_core_php_files() {
		$found = array();
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
				if ( ! $file->isFile() || 'php' !== strtolower( $file->getExtension() ) ) {
					continue;
				}
				$rel     = str_replace( '\\', '/', substr( $file->getPathname(), strlen( ABSPATH ) ) );
				$found[] = ltrim( $rel, '/' );
			}
		}
		return $found;
	}
}
