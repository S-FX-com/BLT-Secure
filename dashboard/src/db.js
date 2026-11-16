/**
 * D1 query helpers for the fleet dashboard.
 *
 * Thin wrappers over the D1 prepared-statement API. Kept separate from the
 * router so the SQL is easy to read and the request handler stays about
 * auth + routing.
 */

/**
 * Find a site by the SHA-256 of its token.
 * @param {D1Database} db
 * @param {string} hash
 * @returns {Promise<object|null>}
 */
export function getSiteByTokenHash( db, hash ) {
	return db.prepare( 'SELECT * FROM sites WHERE token_hash = ?' ).bind( hash ).first();
}

/**
 * Create a site row from a token hash; returns the new id.
 * @param {D1Database} db
 * @param {string} hash
 * @param {number} now
 * @returns {Promise<number>}
 */
export async function createSite( db, hash, now ) {
	const res = await db
		.prepare( 'INSERT INTO sites (token_hash, enrolled_at, last_seen) VALUES (?, ?, ?)' )
		.bind( hash, now, now )
		.run();
	return res.meta.last_row_id;
}

/**
 * Update identity + last-seen for a site.
 * @param {D1Database} db
 * @param {number} siteId
 * @param {string} url
 * @param {string} name
 * @param {number} now
 * @returns {Promise<void>}
 */
export async function touchSite( db, siteId, url, name, now ) {
	await db
		.prepare( 'UPDATE sites SET site_url = ?, name = ?, last_seen = ? WHERE id = ?' )
		.bind( url, name, now, siteId )
		.run();
}

/**
 * Store (replace) the latest snapshot for a site.
 * @param {D1Database} db
 * @param {number} siteId
 * @param {number} reportedAt
 * @param {string} payloadJson
 * @returns {Promise<void>}
 */
export async function upsertSnapshot( db, siteId, reportedAt, payloadJson ) {
	await db
		.prepare(
			'INSERT INTO snapshots (site_id, reported_at, payload) VALUES (?1, ?2, ?3) ' +
				'ON CONFLICT(site_id) DO UPDATE SET reported_at = ?2, payload = ?3'
		)
		.bind( siteId, reportedAt, payloadJson )
		.run();
}

/**
 * Append event counts for a site.
 * @param {D1Database} db
 * @param {number} siteId
 * @param {number} ts
 * @param {Record<string, number>} events
 * @returns {Promise<void>}
 */
export async function recordEvents( db, siteId, ts, events ) {
	const entries = Object.entries( events || {} );
	if ( ! entries.length ) {
		return;
	}
	const stmt = db.prepare( 'INSERT INTO events (site_id, ts, type, count) VALUES (?, ?, ?, ?)' );
	await db.batch( [
		...entries.map( ( [ type, count ] ) => stmt.bind( siteId, ts, type, count ) ),
		// Retention: the table is append-only, so trim it as we write.
		db.prepare( 'DELETE FROM events WHERE ts < ?' ).bind( ts - EVENT_RETENTION ),
	] );
}

/**
 * reported_at of a site's stored snapshot (0 when none).
 * @param {D1Database} db
 * @param {number} siteId
 * @returns {Promise<number>}
 */
export async function getSnapshotReportedAt( db, siteId ) {
	const row = await db.prepare( 'SELECT reported_at FROM snapshots WHERE site_id = ?' ).bind( siteId ).first();
	return row && Number.isFinite( Number( row.reported_at ) ) ? Number( row.reported_at ) : 0;
}

/**
 * Whether a site row exists.
 * @param {D1Database} db
 * @param {number} siteId
 * @returns {Promise<boolean>}
 */
export async function siteExists( db, siteId ) {
	return !! ( await db.prepare( 'SELECT id FROM sites WHERE id = ?' ).bind( siteId ).first() );
}

/**
 * How many unfinished commands a site has queued.
 * @param {D1Database} db
 * @param {number} siteId
 * @param {number} now
 * @returns {Promise<number>}
 */
export async function countQueued( db, siteId, now ) {
	const row = await db
		.prepare( "SELECT COUNT(*) AS n FROM commands WHERE site_id = ? AND status IN ('pending','delivered') AND created_at >= ?" )
		.bind( siteId, now - COMMAND_TTL )
		.first();
	return row ? Number( row.n ) || 0 : 0;
}

/**
 * Queue one (already validated) command. Operator params are not stored: the
 * plugin ignores them, so there is nothing to carry.
 * @param {D1Database} db
 * @param {number} siteId
 * @param {string} command
 * @param {number} now
 * @returns {Promise<void>}
 */
export async function queueCommand( db, siteId, command, now ) {
	await db
		.prepare( "INSERT INTO commands (site_id, created_at, command, params, status) VALUES (?, ?, ?, '{}', 'pending')" )
		.bind( siteId, now, command )
		.run();
}

/**
 * Revoke a site: delete it and everything keyed to it (its token stops
 * working immediately). Explicit deletes — not reliant on FK cascade.
 * @param {D1Database} db
 * @param {number} siteId
 * @returns {Promise<void>}
 */
export async function deleteSite( db, siteId ) {
	await db.batch( [
		db.prepare( 'DELETE FROM commands WHERE site_id = ?' ).bind( siteId ),
		db.prepare( 'DELETE FROM events WHERE site_id = ?' ).bind( siteId ),
		db.prepare( 'DELETE FROM snapshots WHERE site_id = ?' ).bind( siteId ),
		db.prepare( 'DELETE FROM sites WHERE id = ?' ).bind( siteId ),
	] );
}

/** A delivered-but-unacknowledged command is re-sent after this many seconds. */
export const REDELIVER_AFTER = 900;
/** Commands older than this never run (a stale queue must not fire months later). */
export const COMMAND_TTL = 7 * 86400;
/** Most commands handed out per pull; the plugin also caps execution. */
export const MAX_PER_PULL = 5;
/** Most unfinished commands a site may have queued. */
export const MAX_QUEUED = 50;
/** Event rows are kept this long. */
export const EVENT_RETENTION = 90 * 86400;

/**
 * Commands to hand a site: pending ones, plus ones delivered but never
 * acknowledged for REDELIVER_AFTER seconds (the plugin died mid-run or the ack
 * was lost). Delivery only ever means "sent", never "done".
 * @param {D1Database} db
 * @param {number} siteId
 * @param {number} now
 * @returns {Promise<object[]>}
 */
export async function pendingCommands( db, siteId, now ) {
	const res = await db
		.prepare(
			'SELECT id, command FROM commands WHERE site_id = ?1 AND created_at >= ?2 ' +
				"AND (status = 'pending' OR (status = 'delivered' AND delivered_at < ?3)) ORDER BY id LIMIT " +
				MAX_PER_PULL
		)
		.bind( siteId, now - COMMAND_TTL, now - REDELIVER_AFTER )
		.all();
	return res.results || [];
}

/**
 * Mark commands delivered.
 * @param {D1Database} db
 * @param {number[]} ids
 * @param {number} now
 * @returns {Promise<void>}
 */
export async function markDelivered( db, ids, now ) {
	if ( ! ids.length ) {
		return;
	}
	const stmt = db.prepare( "UPDATE commands SET status = 'delivered', delivered_at = ? WHERE id = ?" );
	await db.batch( ids.map( ( id ) => stmt.bind( now, id ) ) );
}

/**
 * Coerce an untrusted ack `ids` value into a list of positive integers.
 * @param {unknown} ids
 * @returns {number[]}
 */
export function sanitizeIds( ids ) {
	if ( ! Array.isArray( ids ) ) {
		return [];
	}
	return ids.map( Number ).filter( ( n ) => Number.isInteger( n ) && n > 0 );
}

/**
 * Mark delivered commands done, scoped to the acknowledging site so one site
 * can never close another's commands.
 * @param {D1Database} db
 * @param {number} siteId
 * @param {number[]} ids
 * @param {number} now
 * @returns {Promise<void>}
 */
export async function markDone( db, siteId, ids, now ) {
	if ( ! ids.length ) {
		return;
	}
	const stmt = db.prepare(
		"UPDATE commands SET status = 'done', delivered_at = COALESCE(delivered_at, ?) " +
			"WHERE id = ? AND site_id = ? AND status = 'delivered'"
	);
	await db.batch( ids.map( ( id ) => stmt.bind( now, id, siteId ) ) );
}

/**
 * List all sites with their latest snapshot payload (for the UI).
 * @param {D1Database} db
 * @returns {Promise<object[]>}
 */
export async function listSites( db ) {
	const res = await db
		.prepare(
			'SELECT s.id, s.site_url, s.name, s.last_seen, snap.payload ' +
				'FROM sites s LEFT JOIN snapshots snap ON snap.site_id = s.id ORDER BY s.last_seen DESC'
		)
		.all();
	return res.results || [];
}
