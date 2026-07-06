<?php
/**
 * Crypto + credential store tests.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure_Crypto and Blt_Secure_Encrypted_Option_Store.
 */
class Test_Crypto extends TestCase {

	/**
	 * Reset in-memory options between tests.
	 *
	 * @return void
	 */
	protected function setUp(): void {
		$GLOBALS['blt_test_options'] = array();
	}

	public function test_backend_available() {
		$crypto = new Blt_Secure_Crypto();
		$this->assertTrue( $crypto->is_available(), 'No AEAD backend in test PHP build' );
	}

	public function test_round_trip() {
		$crypto   = new Blt_Secure_Crypto();
		$secret   = 'cf-token-abc123-' . str_repeat( 'x', 40 );
		$envelope = $crypto->encrypt( $secret );

		$this->assertIsString( $envelope );
		$this->assertStringStartsWith( '$blt', $envelope );
		$this->assertStringNotContainsString( $secret, $envelope );
		$this->assertSame( $secret, $crypto->decrypt( $envelope ) );
	}

	public function test_empty_string_round_trip() {
		$crypto   = new Blt_Secure_Crypto();
		$envelope = $crypto->encrypt( '' );
		$this->assertSame( '', $crypto->decrypt( $envelope ) );
	}

	public function test_tamper_detected() {
		$crypto   = new Blt_Secure_Crypto();
		$envelope = $crypto->encrypt( 'sensitive' );

		// Flip a character in the base64 payload.
		$pos                = strlen( $envelope ) - 5;
		$tampered           = $envelope;
		$tampered[ $pos ]   = ( 'A' === $tampered[ $pos ] ) ? 'B' : 'A';
		$result             = $crypto->decrypt( $tampered );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'blt_secure_decrypt_failed', $result->get_error_code() );
	}

	public function test_wrong_key_fails() {
		$key_a = str_repeat( 'a', 32 );
		$key_b = str_repeat( 'b', 32 );

		$envelope = ( new Blt_Secure_Crypto( $key_a ) )->encrypt( 'sensitive' );
		$result   = ( new Blt_Secure_Crypto( $key_b ) )->decrypt( $envelope );

		$this->assertInstanceOf( WP_Error::class, $result );
	}

	public function test_garbage_envelope_rejected() {
		$crypto = new Blt_Secure_Crypto();
		$this->assertInstanceOf( WP_Error::class, $crypto->decrypt( 'not-an-envelope' ) );
		$this->assertInstanceOf( WP_Error::class, $crypto->decrypt( '$blt1$%%%not-base64%%%' ) );
		$this->assertInstanceOf( WP_Error::class, $crypto->decrypt( '$blt1$' . base64_encode( 'short' ) ) );
	}

	public function test_nonces_are_unique() {
		$crypto = new Blt_Secure_Crypto();
		$this->assertNotSame( $crypto->encrypt( 'same' ), $crypto->encrypt( 'same' ) );
	}

	public function test_store_round_trip() {
		$store = new Blt_Secure_Encrypted_Option_Store( new Blt_Secure_Crypto() );

		$this->assertNull( $store->get( 'cf_token' ) );
		$this->assertTrue( $store->set( 'cf_token', 'tok_123' ) );
		$this->assertSame( 'tok_123', $store->get( 'cf_token' ) );

		// Stored value must be an envelope, not plaintext.
		$raw = $GLOBALS['blt_test_options']['blt_secure_cred_cf_token'];
		$this->assertStringNotContainsString( 'tok_123', $raw );

		$store->delete( 'cf_token' );
		$this->assertNull( $store->get( 'cf_token' ) );
	}

	public function test_salt_rotation_wipes_credentials() {
		$key_a = str_repeat( 'a', 32 );
		$key_b = str_repeat( 'b', 32 );

		$store_a = new Blt_Secure_Encrypted_Option_Store( new Blt_Secure_Crypto( $key_a ) );
		$store_a->set( 'cf_token', 'tok_123' );

		// New request with rotated salts (different key).
		$store_b = new Blt_Secure_Encrypted_Option_Store( new Blt_Secure_Crypto( $key_b ) );

		$this->assertNull( $store_b->get( 'cf_token' ) );
		$this->assertTrue( $store_b->is_invalidated() );
		$this->assertArrayNotHasKey( 'blt_secure_cred_cf_token', $GLOBALS['blt_test_options'], 'Unrecoverable credential should be wiped' );

		// Re-storing under the new key recovers the store.
		$this->assertTrue( $store_b->set( 'cf_token', 'tok_456' ) );
		$this->assertSame( 'tok_456', $store_b->get( 'cf_token' ) );
		$this->assertFalse( $store_b->is_invalidated() );
	}
}
