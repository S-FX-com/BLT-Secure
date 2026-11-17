/**
 * Router tests for the Worker entry (src/index.js) with a fake D1.
 */

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import worker, { COMMANDS, readBody, positiveInt } from '../src/index.js';
import { hmacHex, sha256Hex, signResponse } from '../src/auth.js';
import { resetJwksCache } from '../src/access.js';

const TEAM = 'acme.cloudflareaccess.com';
const AUD = 'aud-tag-123';
const TOKEN = 'a'.repeat(64);

const b64url = ( bytes ) => Buffer.from( bytes ).toString( 'base64' ).replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=+$/, '' );
const enc = ( o ) => b64url( new TextEncoder().encode( JSON.stringify( o ) ) );

let key;
let deps;

beforeEach( async () => {
	resetJwksCache();
	const pair = await crypto.subtle.generateKey(
		{ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array( [ 1, 0, 1 ] ), hash: 'SHA-256' },
		true,
		[ 'sign', 'verify' ]
	);
	const jwk = { ...( await crypto.subtle.exportKey( 'jwk', pair.publicKey ) ), kid: 'k1' };
	key = { priv: pair.privateKey };
	deps = { fetch: async () => ( { ok: true, json: async () => ( { keys: [ jwk ] } ) } ) };
} );

async function accessJwt() {
	const now = Math.floor( Date.now() / 1000 );
	const input = `${ enc( { alg: 'RS256', kid: 'k1' } ) }.${ enc( { iss: `https://${ TEAM }`, aud: [ AUD ], exp: now + 600, email: 'op@acme.test' } ) }`;
	const sig = await crypto.subtle.sign( 'RSASSA-PKCS1-v1_5', key.priv, new TextEncoder().encode( input ) );
	return `${ input }.${ b64url( new Uint8Array( sig ) ) }`;
}

/**
 * Fake D1: `handlers` maps a SQL substring to a function(args) -> row/rows.
 */
function fakeDb( handlers = {} ) {
	const log = [];
	const run = ( sql, args, kind ) => {
		log.push( { sql, args, kind } );
		for ( const [ needle, fn ] of Object.entries( handlers ) ) {
			if ( sql.includes( needle ) ) {
				return fn( args );
			}
		}
		return kind === 'all' ? { results: [] } : kind === 'run' ? { meta: { last_row_id: 7 } } : null;
	};
	return {
		log,
		prepare( sql ) {
			return {
				all: async () => run( sql, [], 'all' ),
				bind: ( ...args ) => ( {
					sql,
					args,
					first: async () => run( sql, args, 'first' ),
					all: async () => run( sql, args, 'all' ),
					run: async () => run( sql, args, 'run' ),
				} ),
			};
		},
		async batch( stmts ) {
			stmts.forEach( ( s ) => log.push( { sql: s.sql, args: s.args, kind: 'batch' } ) );
		},
	};
}

const env = ( DB ) => ( { DB, ACCESS_TEAM_DOMAIN: TEAM, ACCESS_AUD: AUD } );
const call = ( req, e ) => worker.fetch( req, e, {}, deps );

test( 'operator routes refuse a spoofed identity header (no Access JWT)', async () => {
	const e = env( fakeDb() );
	for ( const [ method, path ] of [ [ 'GET', '/' ], [ 'POST', '/admin/sites' ], [ 'POST', '/admin/commands' ], [ 'POST', '/admin/sites/revoke' ] ] ) {
		const res = await call( new Request( `https://x.example${ path }`, { method, headers: { 'Cf-Access-Authenticated-User-Email': 'a@evil.test', 'Content-Type': 'application/json' }, body: method === 'POST' ? '{}' : undefined } ), e );
		assert.equal( res.status, 403, `${ method } ${ path }` );
	}
} );

test( 'operator routes fail closed when Access is not configured', async () => {
	const res = await worker.fetch( new Request( 'https://x.example/', { headers: { 'Cf-Access-Jwt-Assertion': await accessJwt() } } ), { DB: fakeDb(), ACCESS_TEAM_DOMAIN: '', ACCESS_AUD: '' }, {}, deps );
	assert.equal( res.status, 503 );
} );

test( 'dashboard with a valid JWT carries CSP + nosniff', async () => {
	const res = await call( new Request( 'https://x.example/', { headers: { 'Cf-Access-Jwt-Assertion': await accessJwt() } } ), env( fakeDb() ) );
	assert.equal( res.status, 200 );
	assert.equal( res.headers.get( 'X-Content-Type-Options' ), 'nosniff' );
	assert.match( res.headers.get( 'Content-Security-Policy' ), /default-src 'none'/ );
} );

test( 'POST /admin/commands validates content-type, origin, command and site', async () => {
	const jwt = await accessJwt();
	const post = ( body, headers = {} ) =>
		new Request( 'https://x.example/admin/commands', { method: 'POST', headers: { 'Cf-Access-Jwt-Assertion': jwt, 'Content-Type': 'application/json', ...headers }, body } );
	const db = fakeDb( { 'SELECT id FROM sites': () => ( { id: 1 } ), 'COUNT(*)': () => ( { n: 0 } ) } );
	const e = env( db );

	assert.equal( ( await call( post( '{"site_id":1,"command":"scan_core"}', { 'Content-Type': 'text/plain' } ), e ) ).status, 415 );
	assert.equal( ( await call( post( '{"site_id":1,"command":"scan_core"}', { Origin: 'https://evil.test' } ), e ) ).status, 403 );
	assert.equal( ( await call( post( '{"site_id":1,"command":"scan_core"}', { 'Sec-Fetch-Site': 'cross-site' } ), e ) ).status, 403 );
	assert.equal( ( await call( post( '{"site_id":1,"command":"rm_rf"}' ), e ) ).status, 400 );
	assert.equal( ( await call( post( '{"site_id":"1; DROP","command":"scan_core"}' ), e ) ).status, 400 );
	assert.equal( ( await call( post( '{"site_id":-3,"command":"scan_core"}' ), e ) ).status, 400 );
	assert.equal( db.log.filter( ( l ) => l.sql.startsWith( 'INSERT INTO commands' ) ).length, 0 );

	const ok = await call( post( '{"site_id":1,"command":"scan_core"}', { Origin: 'https://x.example' } ), e );
	assert.equal( ok.status, 200 );
	assert.equal( db.log.filter( ( l ) => l.sql.startsWith( 'INSERT INTO commands' ) ).length, 1 );

	const missing = fakeDb( { 'SELECT id FROM sites': () => null } );
	assert.equal( ( await call( post( '{"site_id":99,"command":"scan_core"}' ), env( missing ) ) ).status, 404 );

	const full = fakeDb( { 'SELECT id FROM sites': () => ( { id: 1 } ), 'COUNT(*)': () => ( { n: 50 } ) } );
	assert.equal( ( await call( post( '{"site_id":1,"command":"scan_core"}' ), env( full ) ) ).status, 429 );
} );

test( 'POST /admin/sites/revoke deletes the site and everything keyed to it', async () => {
	const db = fakeDb( { 'SELECT id FROM sites': () => ( { id: 5 } ) } );
	const res = await call(
		new Request( 'https://x.example/admin/sites/revoke', { method: 'POST', headers: { 'Cf-Access-Jwt-Assertion': await accessJwt(), 'Content-Type': 'application/json' }, body: '{"site_id":5}' } ),
		env( db )
	);
	assert.equal( res.status, 200 );
	const deletes = db.log.filter( ( l ) => l.kind === 'batch' && l.sql.startsWith( 'DELETE' ) ).map( ( l ) => l.sql );
	assert.equal( deletes.length, 4 );
	assert.ok( deletes.some( ( s ) => s.startsWith( 'DELETE FROM sites' ) ) );
} );

test( 'oversized ingest bodies are refused before authentication', async () => {
	const res = await call(
		new Request( 'https://x.example/v1/snapshot', { method: 'POST', body: 'x'.repeat( 70000 ), headers: { 'Content-Length': '70000' } } ),
		env( fakeDb() )
	);
	assert.equal( res.status, 413 );
	assert.equal( await readBody( new Request( 'https://x.example/', { method: 'POST', body: 'abc' } ), 2 ), null );
	assert.equal( await readBody( new Request( 'https://x.example/', { method: 'POST', body: 'abc' } ), 10 ), 'abc' );
} );

async function signedHeaders( body = '', extra = {} ) {
	const ts = String( Math.floor( Date.now() / 1000 ) );
	return {
		Authorization: `Bearer ${ TOKEN }`,
		'X-BLT-Timestamp': ts,
		'X-BLT-Signature': await hmacHex( TOKEN, `${ ts }.${ body }` ),
		...extra,
	};
}

test( '/v1/commands needs a nonce and returns a signed, params-free response', async () => {
	const hash = await sha256Hex( TOKEN );
	const db = fakeDb( {
		'FROM sites WHERE token_hash': ( args ) => ( args[ 0 ] === hash ? { id: 3 } : null ),
		'FROM commands WHERE site_id': () => ( { results: [ { id: 12, command: 'scan_core' } ] } ),
	} );
	const e = env( db );

	const noNonce = await call( new Request( 'https://x.example/v1/commands', { headers: await signedHeaders() } ), e );
	assert.equal( noNonce.status, 400 );

	const nonce = 'abcdef0123456789abcd';
	const res = await call( new Request( 'https://x.example/v1/commands', { headers: await signedHeaders( '', { 'X-BLT-Nonce': nonce } ) } ), e );
	assert.equal( res.status, 200 );
	const body = await res.text();
	assert.deepEqual( JSON.parse( body ), { commands: [ { id: 12, command: 'scan_core' } ] } );
	assert.equal( res.headers.get( 'X-BLT-Response-Nonce' ), nonce );
	assert.equal( res.headers.get( 'X-BLT-Response-Signature' ), await signResponse( TOKEN, res.headers.get( 'X-BLT-Response-Timestamp' ), nonce, body ) );
} );

test( 'a snapshot no newer than the stored one is acknowledged but not re-recorded', async () => {
	const hash = await sha256Hex( TOKEN );
	const now = Math.floor( Date.now() / 1000 );
	const snap = JSON.stringify( { schema: 2, site: 'https://s.test', reported_at: now, events: { lockout: 2 } } );
	const db = fakeDb( {
		'FROM sites WHERE token_hash': ( args ) => ( args[ 0 ] === hash ? { id: 3 } : null ),
		'SELECT reported_at FROM snapshots': () => ( { reported_at: now } ),
	} );
	const res = await call( new Request( 'https://x.example/v1/snapshot', { method: 'POST', body: snap, headers: await signedHeaders( snap ) } ), env( db ) );
	assert.equal( res.status, 200 );
	assert.equal( ( await res.json() ).duplicate, true );
	assert.equal( db.log.filter( ( l ) => l.sql.startsWith( 'INSERT INTO snapshots' ) || l.sql.startsWith( 'INSERT INTO events' ) ).length, 0 );
} );

test( 'v1 snapshots are rejected (contract bump, no backward compat)', async () => {
	const hash = await sha256Hex( TOKEN );
	const snap = JSON.stringify( { schema: 1, site: 'https://s.test' } );
	const db = fakeDb( { 'FROM sites WHERE token_hash': ( args ) => ( args[ 0 ] === hash ? { id: 3 } : null ) } );
	const res = await call( new Request( 'https://x.example/v1/snapshot', { method: 'POST', body: snap, headers: await signedHeaders( snap ) } ), env( db ) );
	assert.equal( res.status, 400 );
} );

test( 'helpers', () => {
	assert.deepEqual( COMMANDS, [ 'scan_core', 'scan_malware', 'scan_baseline', 'sync_ioc', 'health_scan', 'report' ] );
	assert.equal( positiveInt( 5 ), 5 );
	assert.equal( positiveInt( '12' ), 12 );
	assert.equal( positiveInt( '1e3' ), null );
	assert.equal( positiveInt( 0 ), null );
	assert.equal( positiveInt( null ), null );
} );
