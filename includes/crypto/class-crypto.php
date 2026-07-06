<?php
/**
 * Authenticated encryption for stored secrets.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * AEAD envelope encryption.
 *
 * Primary: libsodium secretbox (XSalsa20-Poly1305) — bundled with PHP since
 * 7.2, so it is the dependable path on restricted shared hosting. Fallback:
 * OpenSSL AES-256-GCM. If neither is available we refuse to encrypt at all;
 * there is no downgrade to unauthenticated ciphers or plaintext.
 *
 * Envelope formats (versioned so the KDF/cipher can migrate later):
 *   $blt1$ base64( nonce . ciphertext )            — sodium secretbox
 *   $blt2$ base64( iv . tag . ciphertext )         — AES-256-GCM
 *
 * The key is derived on demand from the WP auth salts and never stored.
 */
class Blt_Secure_Crypto {

	const ENVELOPE_SODIUM  = '$blt1$';
	const ENVELOPE_OPENSSL = '$blt2$';

	/**
	 * Injected key for tests; null = derive from WP salts.
	 *
	 * @var string|null
	 */
	private $key_override;

	/**
	 * Constructor.
	 *
	 * @param string|null $key_override Optional 32-byte key (tests only).
	 */
	public function __construct( $key_override = null ) {
		$this->key_override = $key_override;
	}

	/**
	 * Whether an AEAD backend exists on this host.
	 *
	 * @return bool
	 */
	public function is_available() {
		if ( function_exists( 'sodium_crypto_secretbox' ) ) {
			return true;
		}
		return function_exists( 'openssl_encrypt' )
			&& in_array( 'aes-256-gcm', array_map( 'strtolower', openssl_get_cipher_methods() ), true );
	}

	/**
	 * Encrypt a string into a versioned envelope.
	 *
	 * @param string $plaintext Value to protect.
	 * @return string|WP_Error Envelope string.
	 */
	public function encrypt( $plaintext ) {
		$key = $this->key();

		if ( function_exists( 'sodium_crypto_secretbox' ) ) {
			$nonce  = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$cipher = sodium_crypto_secretbox( (string) $plaintext, $nonce, $key );
			return self::ENVELOPE_SODIUM . base64_encode( $nonce . $cipher ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
		}

		if ( $this->is_available() ) {
			$iv     = random_bytes( 12 );
			$tag    = '';
			$cipher = openssl_encrypt( (string) $plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag );
			if ( false !== $cipher ) {
				return self::ENVELOPE_OPENSSL . base64_encode( $iv . $tag . $cipher ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
			}
		}

		return new WP_Error( 'blt_secure_no_aead', __( 'No authenticated encryption backend (libsodium or OpenSSL AES-GCM) is available on this server.', 'blt-secure' ) );
	}

	/**
	 * Decrypt an envelope produced by encrypt().
	 *
	 * @param string $envelope Stored envelope string.
	 * @return string|WP_Error Plaintext.
	 */
	public function decrypt( $envelope ) {
		$envelope = (string) $envelope;
		$key      = $this->key();

		if ( 0 === strpos( $envelope, self::ENVELOPE_SODIUM ) ) {
			if ( ! function_exists( 'sodium_crypto_secretbox_open' ) ) {
				return new WP_Error( 'blt_secure_no_sodium', __( 'This value was encrypted with libsodium, which is no longer available.', 'blt-secure' ) );
			}
			$raw = base64_decode( substr( $envelope, strlen( self::ENVELOPE_SODIUM ) ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
			if ( false === $raw || strlen( $raw ) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
				return $this->tamper_error();
			}
			$nonce  = substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$cipher = substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$plain  = sodium_crypto_secretbox_open( $cipher, $nonce, $key );
			return ( false === $plain ) ? $this->tamper_error() : $plain;
		}

		if ( 0 === strpos( $envelope, self::ENVELOPE_OPENSSL ) ) {
			$raw = base64_decode( substr( $envelope, strlen( self::ENVELOPE_OPENSSL ) ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
			if ( false === $raw || strlen( $raw ) <= 28 ) { // 12 iv + 16 tag.
				return $this->tamper_error();
			}
			$iv     = substr( $raw, 0, 12 );
			$tag    = substr( $raw, 12, 16 );
			$cipher = substr( $raw, 28 );
			$plain  = openssl_decrypt( $cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag );
			return ( false === $plain ) ? $this->tamper_error() : $plain;
		}

		return new WP_Error( 'blt_secure_bad_envelope', __( 'Unrecognized encrypted value format.', 'blt-secure' ) );
	}

	/**
	 * Uniform error for failed authentication (wrong key, tampering, or
	 * rotated salts — callers treat these identically).
	 *
	 * @return WP_Error
	 */
	private function tamper_error() {
		return new WP_Error( 'blt_secure_decrypt_failed', __( 'Stored value could not be decrypted. The security keys in wp-config.php may have changed.', 'blt-secure' ) );
	}

	/**
	 * Derive the 32-byte key from WP salts.
	 *
	 * @return string
	 */
	private function key() {
		if ( null !== $this->key_override ) {
			return $this->key_override;
		}
		return hash( 'sha256', 'blt-secure-v1|' . wp_salt( 'auth' ) . '|' . wp_salt( 'secure_auth' ), true );
	}
}
