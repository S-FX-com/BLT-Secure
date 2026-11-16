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
			$entry = '' !== $token ? self::accept( $token ) : '';
			if ( '' !== $entry ) {
				$out[] = $entry;
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
				$ip    = self::strip_port( $value );
				$entry = self::accept( $ip );
				if ( '' !== $entry ) {
					$out[] = $entry;
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

	/**
	 * Validate, normalize and policy-check one indicator. Returns the
	 * normalized entry, or '' when it must not be blocked.
	 *
	 * @param string $ip Candidate IP or CIDR.
	 * @return string
	 */
	public static function accept( $ip ) {
		if ( ! self::is_valid_ip_or_cidr( $ip ) ) {
			return '';
		}
		$entry = self::normalize_entry( $ip );
		return self::is_blockable( $entry ) ? $entry : '';
	}

	/**
	 * Split an IP/CIDR into [packed address, prefix bits], or null.
	 *
	 * @param string $ip IP or CIDR.
	 * @return array|null
	 */
	private static function split( $ip ) {
		$ip   = (string) $ip;
		$bits = null;
		if ( false !== strpos( $ip, '/' ) ) {
			list( $addr, $mask ) = array_pad( explode( '/', $ip, 2 ), 2, '' );
			if ( ! ctype_digit( $mask ) ) {
				return null;
			}
			$ip   = $addr;
			$bits = (int) $mask;
		}
		$packed = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $packed ) {
			return null;
		}
		$max = strlen( $packed ) * 8;
		if ( null === $bits ) {
			$bits = $max;
		}
		if ( $bits > $max ) {
			return null;
		}
		return array( $packed, $bits );
	}

	/**
	 * Zero the host bits of a packed address.
	 *
	 * @param string $packed Packed address.
	 * @param int    $bits Prefix length.
	 * @return string
	 */
	private static function mask_packed( $packed, $bits ) {
		$out = '';
		$len = strlen( $packed );
		for ( $i = 0; $i < $len; $i++ ) {
			$keep = max( 0, min( 8, $bits - 8 * $i ) );
			$mask = 0 === $keep ? 0 : ( 0xFF << ( 8 - $keep ) ) & 0xFF;
			$out .= chr( ord( $packed[ $i ] ) & $mask );
		}
		return $out;
	}

	/**
	 * Canonical form: host bits cleared on CIDRs (Cloudflare wants the network
	 * address), IPv6 compressed and lowercase, single hosts without a mask.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string $ip Valid IP or CIDR.
	 * @return string
	 */
	public static function normalize_entry( $ip ) {
		$parts = self::split( $ip );
		if ( null === $parts ) {
			return (string) $ip;
		}
		list( $packed, $bits ) = $parts;
		if ( false === strpos( (string) $ip, '/' ) ) {
			return (string) inet_ntop( $packed );
		}
		return inet_ntop( self::mask_packed( $packed, $bits ) ) . '/' . $bits;
	}

	/**
	 * Whether an entry is within the prefix range Cloudflare accepts in an IP
	 * list: IPv4 /8-/32, IPv6 /12-/128.
	 *
	 * @see https://developers.cloudflare.com/waf/tools/lists/custom-lists/
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string $ip IP or CIDR.
	 * @return bool
	 */
	public static function is_cf_list_item( $ip ) {
		$parts = self::split( $ip );
		if ( null === $parts ) {
			return false;
		}
		list( $packed, $bits ) = $parts;
		return 4 === strlen( $packed ) ? ( $bits >= 8 ) : ( $bits >= 12 );
	}

	/**
	 * Whether a threat-feed entry is safe to block outright: public address
	 * space only, never a default route, and no ranges coarser than IPv4 /16
	 * or IPv6 /32 (a poisoned or malformed feed must not be able to blackhole
	 * a continent).
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string $ip IP or CIDR (syntactically valid).
	 * @return bool
	 */
	public static function is_blockable( $ip ) {
		$parts = self::split( $ip );
		if ( null === $parts ) {
			return false;
		}
		list( $packed, $bits ) = $parts;
		$addr                  = (string) inet_ntop( self::mask_packed( $packed, $bits ) );

		if ( 4 === strlen( $packed ) ) {
			if ( $bits < 16 ) {
				return false;
			}
			$first  = ord( $packed[0] );
			$second = ord( $packed[1] );
			if ( $first >= 224 || ( 100 === $first && 64 === ( $second & 0xC0 ) ) ) {
				return false; // Multicast/reserved, CGNAT.
			}
		} else {
			if ( $bits < 32 ) {
				return false;
			}
			// IPv4-mapped (::ffff:0:0/96) and other embedded-v4 forms.
			if ( str_repeat( "\0", 10 ) . "\xff\xff" === substr( $packed, 0, 12 ) || 0 === ord( $packed[0] ) ) {
				return false;
			}
			if ( 0xFF === ord( $packed[0] ) ) {
				return false; // Multicast.
			}
		}

		return false !== filter_var( $addr, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
	}

	/**
	 * Whether the packed network ($net/$bits) contains a packed address.
	 *
	 * @param string $net Packed network address.
	 * @param int    $bits Prefix length.
	 * @param string $packed Packed address.
	 * @return bool
	 */
	private static function contains( $net, $bits, $packed ) {
		if ( strlen( $net ) !== strlen( $packed ) ) {
			return false;
		}
		return self::mask_packed( $packed, $bits ) === self::mask_packed( $net, $bits );
	}

	/**
	 * Drop every entry that would block an address or range that must stay
	 * reachable: the protected IPs (this server, the current admin) and the
	 * protected ranges (Cloudflare's own edge). An entry is dropped when it
	 * contains a protected IP or overlaps a protected range in either
	 * direction.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string[] $entries          Indicator IPs/CIDRs.
	 * @param string[] $protected_ips    Single addresses that must never be blocked.
	 * @param string[] $protected_ranges CIDRs that must never be blocked.
	 * @return string[] Surviving entries (re-indexed).
	 */
	public static function drop_protected( array $entries, array $protected_ips, array $protected_ranges ) {
		$ips = array();
		foreach ( $protected_ips as $ip ) {
			$packed = @inet_pton( (string) $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( false !== $packed ) {
				$ips[] = $packed;
			}
		}
		$ranges = array();
		foreach ( $protected_ranges as $range ) {
			$parts = self::split( $range );
			if ( null !== $parts ) {
				$ranges[] = $parts;
			}
		}

		$keep = array();
		foreach ( $entries as $entry ) {
			$parts = self::split( $entry );
			if ( null === $parts ) {
				continue;
			}
			list( $packed, $bits ) = $parts;

			$drop = false;
			foreach ( $ips as $protected ) {
				if ( self::contains( $packed, $bits, $protected ) ) {
					$drop = true;
					break;
				}
			}
			if ( ! $drop ) {
				foreach ( $ranges as $range ) {
					list( $rnet, $rbits ) = $range;
					if ( self::contains( $packed, $bits, $rnet ) || self::contains( $rnet, $rbits, $packed ) ) {
						$drop = true;
						break;
					}
				}
			}
			if ( ! $drop ) {
				$keep[] = $entry;
			}
		}
		return $keep;
	}

	/**
	 * Truncate to a cap without sampling away the high-value entries: CIDR
	 * blocks (largest first) are kept before single hosts, and one CIDR
	 * covers many hosts for a single list item. Single hosts keep their feed
	 * order.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string[] $ips Unique entries.
	 * @param int      $cap Maximum items.
	 * @return string[]
	 */
	public static function prioritize_for_cap( array $ips, $cap ) {
		$cap = max( 1, (int) $cap );
		if ( count( $ips ) <= $cap ) {
			return array_values( $ips );
		}

		$cidrs   = array();
		$singles = array();
		foreach ( $ips as $ip ) {
			if ( false !== strpos( $ip, '/' ) ) {
				$cidrs[] = $ip;
			} else {
				$singles[] = $ip;
			}
		}

		usort(
			$cidrs,
			static function ( $a, $b ) {
				$bits_a = (int) substr( $a, strpos( $a, '/' ) + 1 );
				$bits_b = (int) substr( $b, strpos( $b, '/' ) + 1 );
				if ( $bits_a === $bits_b ) {
					return strcmp( $a, $b );
				}
				return $bits_a < $bits_b ? -1 : 1;
			}
		);

		return array_slice( array_merge( $cidrs, $singles ), 0, $cap );
	}
}
