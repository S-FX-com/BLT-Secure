<?php
/**
 * IOC feed parsers — extract IP/CIDR indicators from feed bodies.
 *
 * Pure, side-effect-free parsing so the network layer stays thin and the
 * extraction logic is fully unit-testable against captured feed samples.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Turns raw feed text into a validated list of IPv4/IPv6 addresses and CIDRs.
 */
class Blt_Secure_Ioc_Parser {

	/**
	 * Parse a feed body for the given format.
	 *
	 * @param string $format One of 'ip-list', 'ioc-json'.
	 * @param string $body   Raw response body.
	 * @return string[] Unique, validated IP/CIDR strings.
	 */
	public static function parse( $format, $body ) {
		switch ( $format ) {
			case 'ip-list':
				$ips = self::parse_ip_list( $body );
				break;
			case 'ioc-json':
				$ips = self::parse_ioc_json( $body );
				break;
			default:
				$ips = array();
		}
		return array_values( array_unique( $ips ) );
	}

	/**
	 * Parse a plaintext IP/CIDR list (Spamhaus DROP style): one entry per
	 * line, optional `; comment` or `# comment` trailing/leading text.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string $body Raw text.
	 * @return string[]
	 */
	public static function parse_ip_list( $body ) {
		$out = array();
		foreach ( preg_split( '/\r\n|\r|\n/', (string) $body ) as $line ) {
			$line = trim( $line );
			if ( '' === $line || 0 === strpos( $line, ';' ) || 0 === strpos( $line, '#' ) ) {
				continue;
			}
			// Strip trailing "; SBL..." or "# ..." annotations.
			$line  = trim( preg_split( '/[;#]/', $line, 2 )[0] );
			$token = trim( explode( ' ', $line )[0] );
			if ( '' !== $token && self::is_valid_ip_or_cidr( $token ) ) {
				$out[] = $token;
			}
		}
		return $out;
	}

	/**
	 * Parse a ThreatFox-style recent-IOC JSON export: an object keyed by id,
	 * each value an array of entries carrying `ioc_type` and `ioc_value`. Only
	 * IP indicators are taken; a trailing :port is stripped.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string $body Raw JSON.
	 * @return string[]
	 */
	public static function parse_ioc_json( $body ) {
		$data = json_decode( (string) $body, true );
		if ( ! is_array( $data ) ) {
			return array();
		}

		// Accept either the keyed-object form or a flat list of entries.
		$groups = self::looks_like_entry( $data ) ? array( array( $data ) ) : $data;

		$out = array();
		foreach ( $groups as $group ) {
			foreach ( (array) $group as $entry ) {
				if ( ! is_array( $entry ) ) {
					continue;
				}
				$type  = isset( $entry['ioc_type'] ) ? (string) $entry['ioc_type'] : '';
				$value = isset( $entry['ioc_value'] ) ? (string) $entry['ioc_value'] : '';
				if ( '' === $value || false === strpos( $type, 'ip' ) ) {
					continue;
				}
				$ip = self::strip_port( $value );
				if ( self::is_valid_ip_or_cidr( $ip ) ) {
					$out[] = $ip;
				}
			}
		}
		return $out;
	}

	/**
	 * Whether an array looks like a single IOC entry (has ioc_value).
	 *
	 * @param array $data Candidate.
	 * @return bool
	 */
	private static function looks_like_entry( array $data ) {
		return isset( $data['ioc_value'] );
	}

	/**
	 * Strip a trailing :port from an ip:port value (IPv4 or bracketed IPv6).
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string $value Raw value.
	 * @return string
	 */
	public static function strip_port( $value ) {
		$value = trim( (string) $value );

		// Bracketed IPv6 with optional port: [::1]:443 → ::1.
		if ( '' !== $value && '[' === $value[0] ) {
			$end = strpos( $value, ']' );
			if ( false !== $end ) {
				return substr( $value, 1, $end - 1 );
			}
		}

		// IPv4:port (exactly one colon).
		if ( substr_count( $value, ':' ) === 1 ) {
			return explode( ':', $value )[0];
		}

		return $value;
	}

	/**
	 * Validate an IPv4/IPv6 address or CIDR.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string $ip Candidate.
	 * @return bool
	 */
	public static function is_valid_ip_or_cidr( $ip ) {
		$ip = (string) $ip;

		if ( false !== strpos( $ip, '/' ) ) {
			list( $addr, $mask ) = array_pad( explode( '/', $ip, 2 ), 2, '' );
			if ( ! ctype_digit( $mask ) ) {
				return false;
			}
			$mask = (int) $mask;
			if ( false !== filter_var( $addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
				return $mask >= 0 && $mask <= 32;
			}
			if ( false !== filter_var( $addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
				return $mask >= 0 && $mask <= 128;
			}
			return false;
		}

		return false !== filter_var( $ip, FILTER_VALIDATE_IP );
	}
}
