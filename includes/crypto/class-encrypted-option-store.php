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
	 * Persistent "credentials were found undecryptable" flag (autoload no).
	 * Deliberately NOT under OPTION_PREFIX so it can never be mistaken for a
	 * credential. It outlives the request that detected the rotation (that
	 * request is often cron or a heartbeat nobody sees) and clears when the
	 * admin stores a credential again.
	 */
	const INVALID_FLAG_OPTION = 'blt_secure_crypto_invalid';

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
			// The canary decrypted, so the key is right and only THIS row is
			// bad (tampering or corruption): drop just that row. Wiping every
			// credential here would destroy values the admin just re-entered.
			delete_option( self::OPTION_PREFIX . sanitize_key( $key ) );
			$this->flag_invalid();
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
		delete_option( self::INVALID_FLAG_OPTION );
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
	 * Whether stored secrets were found undecryptable — in this request or in
	 * an earlier one that nobody was watching (persistent flag).
	 *
	 * @return bool
	 */
	public function is_invalidated() {
		return $this->invalidated || (bool) get_option( self::INVALID_FLAG_OPTION, false );
	}

	/**
	 * Persist the invalid flag.
	 *
	 * @return void
	 */
	private function flag_invalid() {
		update_option( self::INVALID_FLAG_OPTION, time(), false );
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
	 * Known credential keys — every key any consumer stores must be listed
	 * so salt rotation wipes them all (they are unrecoverable). invalidate()
	 * additionally enumerates blt_secure_cred_* rows, so a consumer added
	 * later is covered even if it is forgotten here.
	 *
	 * @return string[]
	 */
	public static function known_keys() {
		return array( 'cf_token', 'github_token', 'slack_webhook', 'fleet_token' );
	}

	/**
	 * Every stored credential key: the known list plus any other
	 * blt_secure_cred_* row found in wp_options.
	 *
	 * @return string[]
	 */
	private function all_keys() {
		$keys = self::known_keys();

		global $wpdb;
		if ( isset( $wpdb ) && is_object( $wpdb ) && isset( $wpdb->options ) && method_exists( $wpdb, 'get_col' ) ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$names = $wpdb->get_col(
				$wpdb->prepare(
					"SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
					$wpdb->esc_like( self::OPTION_PREFIX ) . '%'
				)
			);
			foreach ( (array) $names as $name ) {
				$keys[] = substr( (string) $name, strlen( self::OPTION_PREFIX ) );
			}
		}

		return array_values( array_unique( array_filter( $keys ) ) );
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
		foreach ( $this->all_keys() as $key ) {
			delete_option( self::OPTION_PREFIX . $key );
		}
		$this->flag_invalid();
	}
}
