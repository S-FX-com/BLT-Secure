/**
 * Tests for db helpers that carry logic (command ack path).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeIds, markDone, pendingCommands, recordEvents, REDELIVER_AFTER, COMMAND_TTL, MAX_PER_PULL } from '../src/db.js';

test( 'sanitizeIds keeps only positive integers', () => {
	assert.deepEqual( sanitizeIds( [ 1, 2, 3 ] ), [ 1, 2, 3 ] );
	assert.deepEqual( sanitizeIds( [ '4', '5' ] ), [ 4, 5 ] );
	assert.deepEqual( sanitizeIds( [ 0, -1, 2.5, 'x', null, 7 ] ), [ 7 ] );
	assert.deepEqual( sanitizeIds( 'nope' ), [] );
	assert.deepEqual( sanitizeIds( undefined ), [] );
} );

/**
 * Minimal D1 stand-in that records the batched statements.
 * @returns {{ prepare: Function, batch: Function, _binds: Array }}
 */
function fakeDb() {
	const binds = [];
	return {
		_binds: binds,
		prepare( sql ) {
			return {
				bind( ...args ) {
					return { sql, args };
				},
			};
		},
		async batch( stmts ) {
			stmts.forEach( ( s ) => binds.push( s ) );
		},
	};
}

test( 'markDone binds (now, id, siteId) per id and is site-scoped', async () => {
	const db = fakeDb();
	await markDone( db, 42, [ 10, 11 ], 1700000000 );
	assert.equal( db._binds.length, 2 );
	assert.deepEqual( db._binds[ 0 ].args, [ 1700000000, 10, 42 ] );
	assert.deepEqual( db._binds[ 1 ].args, [ 1700000000, 11, 42 ] );
	assert.match( db._binds[ 0 ].sql, /status = 'done'/ );
	assert.match( db._binds[ 0 ].sql, /site_id = \?/ );
} );

test( 'markDone with no ids issues no writes', async () => {
	const db = fakeDb();
	await markDone( db, 42, [], 1700000000 );
	assert.equal( db._binds.length, 0 );
} );

test( 'pendingCommands re-sends stale deliveries, expires old ones, and is capped', async () => {
	let captured;
	const db = {
		prepare( sql ) {
			return {
				bind( ...args ) {
					captured = { sql, args };
					return { all: async () => ( { results: [] } ) };
				},
			};
		},
	};
	await pendingCommands( db, 9, 1000000 );
	assert.deepEqual( captured.args, [ 9, 1000000 - COMMAND_TTL, 1000000 - REDELIVER_AFTER ] );
	assert.match( captured.sql, /status = 'pending' OR \(status = 'delivered' AND delivered_at < \?3\)/ );
	assert.match( captured.sql, new RegExp( 'LIMIT ' + MAX_PER_PULL + '$' ) );
} );

test( 'recordEvents trims old rows in the same batch', async () => {
	const stmts = [];
	const db = {
		prepare( sql ) {
			return { bind: ( ...args ) => ( { sql, args } ) };
		},
		async batch( s ) {
			stmts.push( ...s );
		},
	};
	await recordEvents( db, 3, 2000000, { lockout: 2 } );
	assert.equal( stmts.length, 2 );
	assert.match( stmts[ 1 ].sql, /^DELETE FROM events WHERE ts < \?$/ );
	await recordEvents( db, 3, 2000000, {} );
	assert.equal( stmts.length, 2 ); // nothing to record → no writes at all.
} );
