<?php
/**
 * Pure RFC 6238 TOTP implementation.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * TOTP math with zero WordPress dependencies (fully unit-testable).
 *
 * RFC 4226 (HOTP) dynamic truncation over HMAC-SHA1, RFC 6238 time slices,
 * RFC 4648 base32 for secrets. 6 digits / 30-second period by default —
 * what every authenticator app expects.
 */
class Blt_Secure_Totp {

	const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * Code length.
	 *
	 * @var int
	 */
	private $digits;

	/**
	 * Time-slice length in seconds.
	 *
	 * @var int
	 */
	private $period;

	/**
	 * Constructor.
	 *
	 * @param int $digits Code length (6 or 8).
	 * @param int $period Slice seconds.
	 */
	public function __construct( $digits = 6, $period = 30 ) {
		$this->digits = (int) $digits;
		$this->period = (int) $period;
	}

	/**
	 * Generate a new random secret.
	 *
	 * @param int $bytes Entropy bytes (20 = RFC-recommended for SHA-1).
	 * @return string Base32-encoded secret.
	 */
	public static function generate_secret( $bytes = 20 ) {
		return self::base32_encode( random_bytes( max( 16, (int) $bytes ) ) );
	}

	/**
	 * Current time slice.
	 *
	 * @param int|null $timestamp Unix time (null = now).
	 * @return int
	 */
	public function slice( $timestamp = null ) {
		$timestamp = ( null === $timestamp ) ? time() : (int) $timestamp;
		return (int) floor( $timestamp / $this->period );
	}

	/**
	 * Compute the code for a slice.
	 *
	 * @param string $base32_secret Base32 secret.
	 * @param int    $slice Time slice.
	 * @return string|false Zero-padded code, or false on bad secret.
	 */
	public function code( $base32_secret, $slice ) {
		$key = self::base32_decode( $base32_secret );
		if ( false === $key || '' === $key ) {
			return false;
		}

		// 64-bit big-endian counter (RFC 4226 §5.1) without pack('J') so
		// 32-bit PHP builds keep working.
		$counter = str_pad( '', 4, "\0" ) . pack( 'N', $slice );

		$hash   = hash_hmac( 'sha1', $counter, $key, true );
		$offset = ord( $hash[19] ) & 0x0F;

		$value = ( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 )
			| ( ord( $hash[ $offset + 1 ] ) << 16 )
			| ( ord( $hash[ $offset + 2 ] ) << 8 )
			| ord( $hash[ $offset + 3 ] );

		return str_pad( (string) ( $value % (int) pow( 10, $this->digits ) ), $this->digits, '0', STR_PAD_LEFT );
	}

	/**
	 * Verify a user-supplied code within ±window slices.
	 *
	 * @param string   $base32_secret Base32 secret.
	 * @param string   $user_code Submitted code.
	 * @param int      $last_slice Last successfully used slice (replay guard); pass -1 (or any past value) to skip.
	 * @param int      $window Slices of clock drift tolerated each way.
	 * @param int|null $timestamp Unix time (null = now).
	 * @return int|false The accepted slice (persist it as the new last_slice), or false.
	 */
	public function verify( $base32_secret, $user_code, $last_slice = -1, $window = 1, $timestamp = null ) {
		$user_code = preg_replace( '/\s+/', '', (string) $user_code );
		if ( strlen( $user_code ) !== $this->digits || ! ctype_digit( $user_code ) ) {
			return false;
		}

		$current = $this->slice( $timestamp );

		for ( $offset = - $window; $offset <= $window; $offset++ ) {
			$slice = $current + $offset;
			if ( $slice <= $last_slice ) {
				continue; // Replay guard: each slice is single-use.
			}
			$expected = $this->code( $base32_secret, $slice );
			if ( false !== $expected && hash_equals( $expected, $user_code ) ) {
				return $slice;
			}
		}

		return false;
	}

	/**
	 * otpauth:// provisioning URI for authenticator apps.
	 *
	 * @param string $base32_secret Base32 secret.
	 * @param string $account Account label (user login).
	 * @param string $issuer Issuer label (site name).
	 * @return string
	 */
	public function provisioning_uri( $base32_secret, $account, $issuer ) {
		return sprintf(
			'otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d',
			rawurlencode( $issuer ),
			rawurlencode( $account ),
			rawurlencode( $base32_secret ),
			rawurlencode( $issuer ),
			$this->digits,
			$this->period
		);
	}

	/**
	 * RFC 4648 base32 encode (no padding — authenticator apps don't care).
	 *
	 * @param string $data Binary data.
	 * @return string
	 */
	public static function base32_encode( $data ) {
		if ( '' === $data ) {
			return '';
		}

		$out    = '';
		$buffer = 0;
		$bits   = 0;

		foreach ( str_split( $data ) as $byte ) {
			$buffer = ( $buffer << 8 ) | ord( $byte );
			$bits  += 8;
			while ( $bits >= 5 ) {
				$bits -= 5;
				$out  .= self::BASE32_ALPHABET[ ( $buffer >> $bits ) & 0x1F ];
			}
		}

		if ( $bits > 0 ) {
			$out .= self::BASE32_ALPHABET[ ( $buffer << ( 5 - $bits ) ) & 0x1F ];
		}

		return $out;
	}

	/**
	 * RFC 4648 base32 decode, tolerant of padding/case/spaces.
	 *
	 * @param string $encoded Base32 string.
	 * @return string|false Binary data, or false on invalid input.
	 */
	public static function base32_decode( $encoded ) {
		$encoded = strtoupper( preg_replace( '/[\s=]+/', '', (string) $encoded ) );
		if ( '' === $encoded ) {
			return '';
		}

		$buffer = 0;
		$bits   = 0;
		$out    = '';

		foreach ( str_split( $encoded ) as $char ) {
			$value = strpos( self::BASE32_ALPHABET, $char );
			if ( false === $value ) {
				return false;
			}
			$buffer = ( $buffer << 5 ) | $value;
			$bits  += 5;
			if ( $bits >= 8 ) {
				$bits -= 8;
				$out  .= chr( ( $buffer >> $bits ) & 0xFF );
			}
		}

		return $out;
	}
}
