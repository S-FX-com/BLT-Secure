/**
 * Tests for snapshot validation/normalization.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseSnapshot } from '../src/snapshot.js';

const valid = {
	schema: 1,
	site: 'https://example.com',
	name: 'Example',
	reported_at: 1700000000,
	versions: { plugin: '1.0.6', wp: '6.5', php: '8.2' },
	health: { score: 92, pass: 40, warn: 3, fail: 1 },
	core: { status: 'ok', issues: 0 },
	malware: { status: 'issues', findings: 2 },
	baseline: { status: 'ok', findings: 0 },
	ioc: { status: 'ok', count: 1234 },
	cloudflare: { connected: true, plan: 'pro' },
	events: { lockout: 2, blocked_upload: 1 },
};

test( 'accepts and normalizes a valid snapshot', () => {
	const r = parseSnapshot( valid );
	assert.equal( r.ok, true );
	assert.equal( r.value.site, 'https://example.com' );
	assert.equal( r.value.health.score, 92 );
	assert.equal( r.value.malware.count, 2 );
	assert.equal( r.value.cloudflare.connected, true );
	assert.deepEqual( r.value.events, { lockout: 2, blocked_upload: 1 } );
} );

test( 'rejects non-objects', () => {
	assert.equal( parseSnapshot( null ).ok, false );
	assert.equal( parseSnapshot( 'x' ).ok, false );
	assert.equal( parseSnapshot( [ 1, 2 ] ).ok, false );
} );

test( 'rejects an unsupported schema', () => {
	assert.equal( parseSnapshot( { ...valid, schema: 2 } ).ok, false );
} );

test( 'rejects a non-http site', () => {
	assert.equal( parseSnapshot( { ...valid, site: 'ftp://x' } ).ok, false );
	assert.equal( parseSnapshot( { ...valid, site: 'javascript:alert(1)' } ).ok, false );
} );

test( 'coerces junk counts to non-negative ints and whitelists events', () => {
	const r = parseSnapshot( {
		...valid,
		malware: { status: 'ok', findings: -5 },
		events: { lockout: '3', evil: { nested: true } },
	} );
	assert.equal( r.ok, true );
	assert.equal( r.value.malware.count, 0 ); // negative → 0.
	assert.equal( r.value.events.lockout, 3 );
	assert.equal( r.value.events.evil, 0 ); // non-numeric → 0, structure dropped.
} );

test( 'defaults missing sections to safe values', () => {
	const r = parseSnapshot( { schema: 1, site: 'https://x.test' } );
	assert.equal( r.ok, true );
	assert.equal( r.value.core.status, 'none' );
	assert.equal( r.value.health.score, null );
	assert.equal( r.value.cloudflare.connected, false );
	assert.deepEqual( r.value.events, {} );
} );
