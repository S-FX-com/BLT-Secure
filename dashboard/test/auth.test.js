/**
 * Tests for the ingest auth core. Runs under Node's built-in test runner
 * (node --test) using the global Web Crypto — the same API the Worker uses.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sha256Hex, hmacHex, tokenHash, timingSafeEqualHex, isFresh, verifySignature } from '../src/auth.js';

test( 'sha256Hex matches the known vector for "abc"', async () => {
	assert.equal(
		await sha256Hex( 'abc' ),
		'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
	);
} );

test( 'hmacHex matches the RFC-style fox vector', async () => {
	assert.equal(
		await hmacHex( 'key', 'The quick brown fox jumps over the lazy dog' ),
		'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8'
	);
} );

test( 'tokenHash is the sha256 of the token', async () => {
	assert.equal( await tokenHash( 'abc' ), await sha256Hex( 'abc' ) );
} );

test( 'verifySignature accepts a matching signature and rejects a bad one', async () => {
	const token = 'site-secret-token';
	const ts = 1700000000;
	const body = '{"schema":1,"site":"https://example.com"}';
	const sig = await hmacHex( token, `${ ts }.${ body }` );

	assert.equal( await verifySignature( token, ts, body, sig ), true );
	assert.equal( await verifySignature( token, ts, body, sig.replace( /.$/, '0' ) ), false );
	assert.equal( await verifySignature( 'wrong-token', ts, body, sig ), false );
	// Any body tampering invalidates the signature.
	assert.equal( await verifySignature( token, ts, body + ' ', sig ), false );
} );

test( 'verifySignature mirrors the plugin format ({ts}.{body})', async () => {
	// The PHP plugin computes hash_hmac('sha256', "$ts.$body", $token); this
	// asserts the JS side reconstructs the same signed string.
	const token = 't';
	const ts = 42;
	const body = 'hello';
	const expected = await hmacHex( token, '42.hello' );
	assert.equal( await verifySignature( token, ts, body, expected ), true );
} );

test( 'timingSafeEqualHex', () => {
	assert.equal( timingSafeEqualHex( 'deadbeef', 'deadbeef' ), true );
	assert.equal( timingSafeEqualHex( 'deadbeef', 'deadbee0' ), false );
	assert.equal( timingSafeEqualHex( 'dead', 'deadbeef' ), false );
} );

test( 'isFresh honors the skew window', () => {
	assert.equal( isFresh( 1000, 1000 ), true );
	assert.equal( isFresh( 1000, 1200 ), true ); // 200s <= 300.
	assert.equal( isFresh( 1000, 1400 ), false ); // 400s > 300.
	assert.equal( isFresh( 'nan', 1000 ), false );
} );
