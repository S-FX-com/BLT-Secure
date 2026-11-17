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

	// ---------------------------------------------------------------------
	// Salt-rotation hardening.
	// ---------------------------------------------------------------------

	public function test_known_keys_cover_every_credential_in_use() {
		foreach ( array( 'cf_token', 'github_token', 'slack_webhook', 'fleet_token' ) as $key ) {
			$this->assertContains( $key, Blt_Secure_Encrypted_Option_Store::known_keys() );
		}
		// Contract: every key any module reads from the store is wiped on rotation.
		$used = array();
		foreach ( array( 'includes', 'admin' ) as $dir ) {
			$iterator = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( BLT_SECURE_DIR . $dir, FilesystemIterator::SKIP_DOTS ) );
			foreach ( $iterator as $file ) {
				$path = $file->getPathname();
				if ( '.php' !== substr( $path, -4 ) || false !== strpos( $path, '/lib/' ) || false !== strpos( $path, '/blt-family/' ) ) {
					continue;
				}
				if ( preg_match_all( "/credentials->(?:get|set|delete)\\(\\s*'([a-z_]+)'/", (string) file_get_contents( $path ), $m ) ) {
					$used = array_merge( $used, $m[1] );
				}
				if ( preg_match_all( "/const\\s+TOKEN_KEY\\s*=\\s*'([a-z_]+)'/", (string) file_get_contents( $path ), $c ) ) {
					$used = array_merge( $used, $c[1] );
				}
			}
		}
		foreach ( array_unique( $used ) as $key ) {
			$this->assertContains( $key, Blt_Secure_Encrypted_Option_Store::known_keys(), "credential '{$key}' is not wiped on salt rotation" );
		}
	}

	public function test_rotation_wipes_fleet_and_slack_credentials_too() {
		$a = new Blt_Secure_Encrypted_Option_Store( new Blt_Secure_Crypto( str_repeat( 'a', 32 ) ) );
		foreach ( array( 'cf_token', 'github_token', 'slack_webhook', 'fleet_token' ) as $key ) {
			$a->set( $key, 'value-' . $key );
		}
		$b = new Blt_Secure_Encrypted_Option_Store( new Blt_Secure_Crypto( str_repeat( 'b', 32 ) ) );
		$this->assertNull( $b->get( 'cf_token' ) );

		foreach ( array( 'cf_token', 'github_token', 'slack_webhook', 'fleet_token' ) as $key ) {
			$this->assertArrayNotHasKey( 'blt_secure_cred_' . $key, $GLOBALS['blt_test_options'], "{$key} survived rotation" );
		}
	}

	public function test_reentered_token_survives_later_reads_of_other_credentials() {
		// The regression: stale fleet/slack rows used to wipe a re-entered CF token.
		$a = new Blt_Secure_Encrypted_Option_Store( new Blt_Secure_Crypto( str_repeat( 'a', 32 ) ) );
		$a->set( 'cf_token', 'CF_OLD' );
		$a->set( 'fleet_token', 'FLEET_OLD' );
		$a->set( 'slack_webhook', 'https://hooks.slack.com/x' );

		$key_b = str_repeat( 'b', 32 );
		( new Blt_Secure_Encrypted_Option_Store( new Blt_Secure_Crypto( $key_b ) ) )->get( 'cf_token' ); // Detects rotation.
		( new Blt_Secure_Encrypted_Option_Store( new Blt_Secure_Crypto( $key_b ) ) )->set( 'cf_token', 'CF_NEW' );

		$later = new Blt_Secure_Encrypted_Option_Store( new Blt_Secure_Crypto( $key_b ) );
		$this->assertNull( $later->get( 'fleet_token' ) );
		$this->assertNull( $later->get( 'slack_webhook' ) );
		$this->assertSame( 'CF_NEW', ( new Blt_Secure_Encrypted_Option_Store( new Blt_Secure_Crypto( $key_b ) ) )->get( 'cf_token' ) );
	}

	public function test_a_single_corrupt_row_drops_only_that_row() {
		$key   = str_repeat( 'a', 32 );
		$store = new Blt_Secure_Encrypted_Option_Store( new Blt_Secure_Crypto( $key ) );
		$store->set( 'cf_token', 'CF' );
		$store->set( 'fleet_token', 'FLEET' );
		$GLOBALS['blt_test_options']['blt_secure_cred_fleet_token'] = '$blt1$' . base64_encode( str_repeat( 'x', 60 ) );

		$fresh = new Blt_Secure_Encrypted_Option_Store( new Blt_Secure_Crypto( $key ) );
		$this->assertNull( $fresh->get( 'fleet_token' ) );
		$this->assertSame( 'CF', $fresh->get( 'cf_token' ), 'a valid credential must not be collateral damage' );
		$this->assertArrayNotHasKey( 'blt_secure_cred_fleet_token', $GLOBALS['blt_test_options'] );
	}

	public function test_invalid_flag_persists_across_requests_until_a_credential_is_stored() {
		$a = new Blt_Secure_Encrypted_Option_Store( new Blt_Secure_Crypto( str_repeat( 'a', 32 ) ) );
		$a->set( 'cf_token', 'CF' );
		$key_b = str_repeat( 'b', 32 );
		( new Blt_Secure_Encrypted_Option_Store( new Blt_Secure_Crypto( $key_b ) ) )->get( 'cf_token' ); // Cron request nobody saw.

		// A later, separate request (fresh object) still reports it.
		$admin_request = new Blt_Secure_Encrypted_Option_Store( new Blt_Secure_Crypto( $key_b ) );
		$this->assertTrue( $admin_request->is_invalidated() );
		$this->assertArrayHasKey( Blt_Secure_Encrypted_Option_Store::INVALID_FLAG_OPTION, $GLOBALS['blt_test_options'] );
		$this->assertStringStartsNotWith( Blt_Secure_Encrypted_Option_Store::OPTION_PREFIX, Blt_Secure_Encrypted_Option_Store::INVALID_FLAG_OPTION, 'must never look like a credential row' );

		$admin_request->set( 'cf_token', 'CF2' );
		$this->assertFalse( ( new Blt_Secure_Encrypted_Option_Store( new Blt_Secure_Crypto( $key_b ) ) )->is_invalidated() );
	}
}
