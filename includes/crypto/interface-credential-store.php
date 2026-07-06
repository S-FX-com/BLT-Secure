<?php
/**
 * Credential store contract.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Where secrets (Cloudflare tokens, etc.) live.
 *
 * Phase 1 implements this over encrypted wp_options rows; Phase 3 swaps in a
 * Cloudflare Worker/KV backend without touching any consumer.
 */
interface Blt_Secure_Credential_Store {

	/**
	 * Whether the store can protect secrets on this host.
	 *
	 * @return bool
	 */
	public function is_available();

	/**
	 * Fetch a secret.
	 *
	 * @param string $key Credential key (e.g. 'cf_token').
	 * @return string|null Plaintext secret, or null when absent/undecryptable.
	 */
	public function get( $key );

	/**
	 * Store a secret.
	 *
	 * @param string $key Credential key.
	 * @param string $value Plaintext secret.
	 * @return true|WP_Error
	 */
	public function set( $key, $value );

	/**
	 * Remove a secret.
	 *
	 * @param string $key Credential key.
	 * @return void
	 */
	public function delete( $key );

	/**
	 * Whether previously stored secrets have become undecryptable
	 * (rotated salts). Used to surface a re-enter-credentials notice.
	 *
	 * @return bool
	 */
	public function is_invalidated();
}
