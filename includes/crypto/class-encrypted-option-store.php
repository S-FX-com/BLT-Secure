<?php
/**
 * Encrypted wp_options credential store.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Stores secrets as encrypted envelopes in non-autoloaded options.
 *
 * A canary value (encrypt('ok') in blt_secure_crypto_check) detects salt
 * rotation: when the canary stops decrypting, all stored credentials are
 * wiped and is_invalidated() flips so the admin UI can re-prompt, instead of
 * API calls failing silently forever.
 */
class Blt_Secure_Encrypted_Option_Store implements Blt_Secure_Credential_Store {

	const OPTION_PREFIX = 'blt_secure_cred_';
	const CANARY_OPTION = 'blt_secure_crypto_check';

	/**
	 * Crypto backend.
	 *
	 * @var Blt_Secure_Crypto
	 */
	private $crypto;

	/**
	 * Whether salt rotation was detected this request.
	 *
	 * @var bool
	 */
	private $invalidated = false;

	/**
	 * Constructor.
	 *
	 * @param Blt_Secure_Crypto $crypto Crypto backend.
	 */
	public function __construct( Blt_Secure_Crypto $crypto ) {
		$this->crypto = $crypto;
	}

	/**
	 * Whether secrets can be protected on this host.
	 *
	 * @return bool
	 */
	public function is_available() {
		return $this->crypto->is_available();
	}

	/**
	 * Fetch and decrypt a secret.
	 *
	 * @param string $key Credential key.
	 * @return string|null
	 */
	public function get( $key ) {
		if ( ! $this->check_canary() ) {
			return null;
		}

		$envelope = get_option( self::OPTION_PREFIX . sanitize_key( $key ), null );
		if ( ! is_string( $envelope ) || '' === $envelope ) {
			return null;
		}

		$plain = $this->crypto->decrypt( $envelope );
		if ( is_wp_error( $plain ) ) {
			$this->invalidate();
			return null;
		}

		return $plain;
	}

	/**
	 * Encrypt and store a secret.
	 *
	 * @param string $key Credential key.
	 * @param string $value Plaintext secret.
	 * @return true|WP_Error
	 */
	public function set( $key, $value ) {
		$envelope = $this->crypto->encrypt( $value );
		if ( is_wp_error( $envelope ) ) {
			return $envelope;
		}

		// (Re)seed the canary alongside the first write so future salt
		// rotation is detectable.
		if ( ! is_string( get_option( self::CANARY_OPTION, null ) ) || $this->invalidated ) {
			$canary = $this->crypto->encrypt( 'ok' );
			if ( ! is_wp_error( $canary ) ) {
				update_option( self::CANARY_OPTION, $canary, false );
				$this->invalidated = false;
			}
		}

		update_option( self::OPTION_PREFIX . sanitize_key( $key ), $envelope, false );
		return true;
	}

	/**
	 * Remove a secret.
	 *
	 * @param string $key Credential key.
	 * @return void
	 */
	public function delete( $key ) {
		delete_option( self::OPTION_PREFIX . sanitize_key( $key ) );
	}

	/**
	 * Whether stored secrets were found undecryptable this request.
	 *
	 * @return bool
	 */
	public function is_invalidated() {
		return $this->invalidated;
	}

	/**
	 * Verify the canary still decrypts; wipe credentials when it doesn't.
	 *
	 * @return bool True when the store is trustworthy.
	 */
	private function check_canary() {
		if ( $this->invalidated ) {
			return false;
		}

		$canary = get_option( self::CANARY_OPTION, null );
		if ( ! is_string( $canary ) || '' === $canary ) {
			return true; // Nothing stored yet.
		}

		$plain = $this->crypto->decrypt( $canary );
		if ( is_wp_error( $plain ) || 'ok' !== $plain ) {
			$this->invalidate();
			return false;
		}

		return true;
	}

	/**
	 * Salt rotation detected: wipe every stored credential (they are
	 * unrecoverable) and flag for the admin notice.
	 *
	 * @return void
	 */
	private function invalidate() {
		$this->invalidated = true;
		delete_option( self::CANARY_OPTION );
		delete_option( self::OPTION_PREFIX . 'cf_token' );
	}
}
