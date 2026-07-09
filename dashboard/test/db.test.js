/**
 * Tests for db helpers that carry logic (command ack path).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeIds, markDone } from '../src/db.js';

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
