<?php
/**
 * TOTP tests against RFC vectors.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure_Totp.
 */
class Test_Totp extends TestCase {

	/**
	 * RFC 6238 Appendix B vectors — 8 digits, SHA-1, ASCII secret
	 * "12345678901234567890".
	 *
	 * @return array
	 */
	public function rfc6238_vectors() {
		return array(
			array( 59, '94287082' ),
			array( 1111111109, '07081804' ),
			array( 1111111111, '14050471' ),
			array( 1234567890, '89005924' ),
			array( 2000000000, '69279037' ),
			array( 20000000000, '65353130' ),
		);
	}

	/**
	 * @dataProvider rfc6238_vectors
	 *
	 * @param int    $timestamp Test time.
	 * @param string $expected Expected 8-digit code.
	 */
	public function test_rfc6238_appendix_b( $timestamp, $expected ) {
		$totp   = new Blt_Secure_Totp( 8, 30 );
		$secret = Blt_Secure_Totp::base32_encode( '12345678901234567890' );

		$this->assertSame( $expected, $totp->code( $secret, $totp->slice( $timestamp ) ) );
	}

	public function test_six_digit_codes() {
		// 6-digit truncation of the same RFC vectors (last 6 of the 8).
		$totp   = new Blt_Secure_Totp( 6, 30 );
		$secret = Blt_Secure_Totp::base32_encode( '12345678901234567890' );

		$this->assertSame( '287082', $totp->code( $secret, $totp->slice( 59 ) ) );
		$this->assertSame( '005924', $totp->code( $secret, $totp->slice( 1234567890 ) ) );
	}

	public function test_base32_round_trip() {
		foreach ( array( 'f', 'fo', 'foo', 'foob', 'fooba', 'foobar', random_bytes( 20 ) ) as $data ) {
			$this->assertSame( $data, Blt_Secure_Totp::base32_decode( Blt_Secure_Totp::base32_encode( $data ) ) );
		}
	}

	public function test_base32_rfc4648_vectors() {
		$this->assertSame( 'MZXW6YTBOI', Blt_Secure_Totp::base32_encode( 'foobar' ) );
		$this->assertSame( 'foobar', Blt_Secure_Totp::base32_decode( 'MZXW6YTBOI======' ) ); // Padded.
		$this->assertSame( 'foobar', Blt_Secure_Totp::base32_decode( 'mzxw 6ytb oi' ) );     // Lowercase + spaces.
		$this->assertFalse( Blt_Secure_Totp::base32_decode( 'not!base32' ) );
	}

	public function test_verify_accepts_within_window() {
		$totp   = new Blt_Secure_Totp();
		$secret = Blt_Secure_Totp::generate_secret();
		$now    = 1700000000;

		// Exact, one slice behind, one ahead — all accepted at window=1.
		foreach ( array( 0, -30, 30 ) as $drift ) {
			$code  = $totp->code( $secret, $totp->slice( $now + $drift ) );
			$slice = $totp->verify( $secret, $code, -1, 1, $now );
			$this->assertNotFalse( $slice, "Drift $drift rejected" );
		}

		// Two slices out — rejected.
		$code = $totp->code( $secret, $totp->slice( $now + 60 ) );
		$this->assertFalse( $totp->verify( $secret, $code, -1, 1, $now ) );
	}

	public function test_replay_rejected() {
		$totp   = new Blt_Secure_Totp();
		$secret = Blt_Secure_Totp::generate_secret();
		$now    = 1700000000;

		$code  = $totp->code( $secret, $totp->slice( $now ) );
		$slice = $totp->verify( $secret, $code, -1, 1, $now );
		$this->assertNotFalse( $slice );

		// Same code, same window, last_slice persisted → replay blocked.
		$this->assertFalse( $totp->verify( $secret, $code, $slice, 1, $now ) );
	}

	public function test_malformed_codes_rejected() {
		$totp   = new Blt_Secure_Totp();
		$secret = Blt_Secure_Totp::generate_secret();

		$this->assertFalse( $totp->verify( $secret, '' ) );
		$this->assertFalse( $totp->verify( $secret, '12345' ) );
		$this->assertFalse( $totp->verify( $secret, '1234567' ) );
		$this->assertFalse( $totp->verify( $secret, 'abcdef' ) );
		$this->assertFalse( $totp->verify( $secret, '123456; DROP TABLE' ) );
	}

	public function test_code_with_spaces_accepted() {
		$totp   = new Blt_Secure_Totp();
		$secret = Blt_Secure_Totp::generate_secret();
		$now    = 1700000000;

		$code   = $totp->code( $secret, $totp->slice( $now ) );
		$spaced = substr( $code, 0, 3 ) . ' ' . substr( $code, 3 );

		$this->assertNotFalse( $totp->verify( $secret, $spaced, -1, 1, $now ) );
	}

	public function test_provisioning_uri() {
		$totp = new Blt_Secure_Totp();
		$uri  = $totp->provisioning_uri( 'MZXW6YTBOI', 'shane', 'S-FX Client Site' );

		$this->assertStringStartsWith( 'otpauth://totp/S-FX%20Client%20Site:shane?', $uri );
		$this->assertStringContainsString( 'secret=MZXW6YTBOI', $uri );
		$this->assertStringContainsString( 'issuer=S-FX%20Client%20Site', $uri );
		$this->assertStringContainsString( 'digits=6', $uri );
		$this->assertStringContainsString( 'period=30', $uri );
	}

	public function test_generated_secret_shape() {
		$secret = Blt_Secure_Totp::generate_secret();
		$this->assertSame( 32, strlen( $secret ) ); // 20 bytes → 32 base32 chars.
		$this->assertMatchesRegularExpression( '/^[A-Z2-7]+$/', $secret );
		$this->assertNotSame( $secret, Blt_Secure_Totp::generate_secret() );
	}
}
