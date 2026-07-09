<?php
/**
 * Optional YARA acceleration for the malware scanner.
 *
 * When the PECL `yara` extension is installed and a compiled/compilable
 * ruleset path is provided (via the blt_secure_yara_rules_path filter, e.g.
 * from a synced feed), files are additionally matched with YARA. Everything
 * here is inert by default — no extension or no ruleset means the malware
 * scanner runs pure-PHP exactly as before — so shipping this changes nothing
 * until an operator opts in.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Thin, defensive wrapper over the yara extension.
 */
class Blt_Secure_Yara {

	/**
	 * Whether the yara extension is loaded and usable.
	 *
	 * @return bool
	 */
	public static function is_available() {
		return extension_loaded( 'yara' ) && function_exists( 'yara_scan' ) && function_exists( 'yara_compile' );
	}

	/**
	 * The configured ruleset path (a .yar file or compiled rules), or ''.
	 *
	 * @return string
	 */
	public static function rules_path() {
		/**
		 * Filter the path to a YARA ruleset to scan with.
		 *
		 * @param string $path Absolute path, or '' to disable YARA.
		 */
		return (string) apply_filters( 'blt_secure_yara_rules_path', '' );
	}

	/**
	 * Whether YARA scanning is fully enabled (extension + readable ruleset).
	 *
	 * @return bool
	 */
	public static function enabled() {
		$path = self::rules_path();
		return self::is_available() && '' !== $path && is_readable( $path );
	}

	/**
	 * Scan a single file, returning the identifiers of any matched rules.
	 *
	 * Never throws: any engine error yields an empty result so a YARA problem
	 * can't break the surrounding scan.
	 *
	 * @param string $path File to scan.
	 * @return string[] Matched rule identifiers.
	 */
	public static function scan_file( $path ) {
		if ( ! self::enabled() || ! is_readable( $path ) ) {
			return array();
		}

		try {
			$rules = yara_compile( self::rules_path() ); // phpcs:ignore
			if ( ! $rules ) {
				return array();
			}
			$matches = yara_scan( $rules, (string) $path ); // phpcs:ignore
			return self::rule_names( is_array( $matches ) ? $matches : array() );
		} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
			return array();
		}
	}

	/**
	 * Extract rule identifiers from a yara_scan() result set.
	 *
	 * Pure function (unit-tested). Accepts either a list of rule-name strings
	 * or a list of match objects/arrays carrying a `rule` field.
	 *
	 * @param array $matches Raw matches.
	 * @return string[]
	 */
	public static function rule_names( array $matches ) {
		$names = array();
		foreach ( $matches as $match ) {
			if ( is_string( $match ) && '' !== $match ) {
				$names[] = $match;
			} elseif ( is_array( $match ) && ! empty( $match['rule'] ) ) {
				$names[] = (string) $match['rule'];
			} elseif ( is_object( $match ) && isset( $match->rule ) ) {
				$names[] = (string) $match->rule;
			}
		}
		return array_values( array_unique( $names ) );
	}
}
