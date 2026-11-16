/**
 * Tests for Cloudflare Access operator authentication (src/access.js).
 * Keys are generated locally; no network.
 */

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { verifyAccessJwt, authorizeOperator, resetJwksCache, decodeJwt } from '../src/access.js';

const TEAM = 'acme.cloudflareaccess.com';
const ISS = `https://${ TEAM }`;
const AUD = 'aud-tag-123';
const NOW = 1_800_000_000;

const b64url = ( bytes ) =>
	Buffer.from( bytes ).toString( 'base64' ).replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=+$/, '' );
const enc = ( obj ) => b64url( new TextEncoder().encode( JSON.stringify( obj ) ) );

async function makeKey( kid ) {
	const pair = await crypto.subtle.generateKey(
		{ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array( [ 1, 0, 1 ] ), hash: 'SHA-256' },
		true,
		[ 'sign', 'verify' ]
	);
	const jwk = await crypto.subtle.exportKey( 'jwk', pair.publicKey );
	return { priv: pair.privateKey, jwk: { ...jwk, kid } };
}

async function sign( key, kid, claims, alg = 'RS256' ) {
	const input = `${ enc( { alg, kid, typ: 'JWT' } ) }.${ enc( claims ) }`;
	const sig = await crypto.subtle.sign( 'RSASSA-PKCS1-v1_5', key.priv, new TextEncoder().encode( input ) );
	return `${ input }.${ b64url( new Uint8Array( sig ) ) }`;
}

const good = { iss: ISS, aud: [ AUD ], exp: NOW + 600, email: 'op@acme.test' };

beforeEach( () => resetJwksCache() );

test( 'accepts a valid Access JWT', async () => {
	const key = await makeKey( 'k1' );
	const claims = await verifyAccessJwt( await sign( key, 'k1', good ), { jwks: { keys: [ key.jwk ] }, aud: AUD, issuer: ISS, now: NOW } );
	assert.equal( claims.email, 'op@acme.test' );
} );

test( 'rejects wrong aud, wrong issuer, expired, not-yet-valid', async () => {
	const key = await makeKey( 'k1' );
	const opts = { jwks: { keys: [ key.jwk ] }, aud: AUD, issuer: ISS, now: NOW };
	assert.equal( await verifyAccessJwt( await sign( key, 'k1', { ...good, aud: [ 'other' ] } ), opts ), null );
	assert.equal( await verifyAccessJwt( await sign( key, 'k1', { ...good, iss: 'https://evil.cloudflareaccess.com' } ), opts ), null );
	assert.equal( await verifyAccessJwt( await sign( key, 'k1', { ...good, exp: NOW - 1 } ), opts ), null );
	assert.equal( await verifyAccessJwt( await sign( key, 'k1', { ...good, nbf: NOW + 3600 } ), opts ), null );
	assert.equal( await verifyAccessJwt( await sign( key, 'k1', { ...good, exp: undefined } ), opts ), null );
} );

test( 'rejects a bad signature, an unknown kid, and a different key', async () => {
	const key = await makeKey( 'k1' );
	const other = await makeKey( 'k1' ); // same kid, different key material.
	const opts = { jwks: { keys: [ key.jwk ] }, aud: AUD, issuer: ISS, now: NOW };
	assert.equal( await verifyAccessJwt( await sign( other, 'k1', good ), opts ), null );
	assert.equal( await verifyAccessJwt( await sign( key, 'nope', good ), opts ), null );
	const token = await sign( key, 'k1', good );
	const tampered = token.slice( 0, -4 ) + ( token.endsWith( 'AAAA' ) ? 'BBBB' : 'AAAA' );
	assert.equal( await verifyAccessJwt( tampered, opts ), null );
} );

test( 'rejects alg none / HS256 and malformed tokens', async () => {
	const key = await makeKey( 'k1' );
	const opts = { jwks: { keys: [ key.jwk ] }, aud: AUD, issuer: ISS, now: NOW };
	assert.equal( await verifyAccessJwt( `${ enc( { alg: 'none', kid: 'k1' } ) }.${ enc( good ) }.`, opts ), null );
	assert.equal( await verifyAccessJwt( await sign( key, 'k1', good, 'HS256' ), opts ), null );
	assert.equal( decodeJwt( 'a.b' ), null );
	assert.equal( await verifyAccessJwt( 'garbage', opts ), null );
	assert.equal( await verifyAccessJwt( '', opts ), null );
} );

const fetchWith = ( key ) => async () => ( { ok: true, json: async () => ( { keys: [ key.jwk ] } ) } );

test( 'authorizeOperator FAILS CLOSED when team/aud are not configured', async () => {
	const req = new Request( 'https://x.example/', { headers: { 'Cf-Access-Jwt-Assertion': 'whatever' } } );
	for ( const env of [ {}, { ACCESS_TEAM_DOMAIN: TEAM }, { ACCESS_AUD: AUD }, { ACCESS_TEAM_DOMAIN: 'evil.example.com', ACCESS_AUD: AUD } ] ) {
		const r = await authorizeOperator( req, env, { now: NOW } );
		assert.equal( r.ok, false );
		assert.equal( r.status, 503 );
	}
} );

test( 'a spoofed Cf-Access-Authenticated-User-Email header alone is refused', async () => {
	const key = await makeKey( 'k1' );
	const req = new Request( 'https://x.example/', { headers: { 'Cf-Access-Authenticated-User-Email': 'anyone@evil.test' } } );
	const r = await authorizeOperator( req, { ACCESS_TEAM_DOMAIN: TEAM, ACCESS_AUD: AUD }, { now: NOW, fetch: fetchWith( key ) } );
	assert.deepEqual( [ r.ok, r.status ], [ false, 403 ] );
} );

test( 'authorizeOperator accepts a valid JWT and refuses a forged one', async () => {
	const key = await makeKey( 'k1' );
	const env = { ACCESS_TEAM_DOMAIN: TEAM, ACCESS_AUD: AUD };
	const ok = await authorizeOperator(
		new Request( 'https://x.example/', { headers: { 'Cf-Access-Jwt-Assertion': await sign( key, 'k1', good ) } } ),
		env,
		{ now: NOW, fetch: fetchWith( key ) }
	);
	assert.deepEqual( [ ok.ok, ok.email ], [ true, 'op@acme.test' ] );

	const attacker = await makeKey( 'k1' );
	const forged = await authorizeOperator(
		new Request( 'https://x.example/', { headers: { 'Cf-Access-Jwt-Assertion': await sign( attacker, 'k1', good ) } } ),
		env,
		{ now: NOW, fetch: fetchWith( key ) }
	);
	assert.equal( forged.ok, false );
} );
