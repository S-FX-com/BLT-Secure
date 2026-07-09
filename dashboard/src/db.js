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
	await db.batch( entries.map( ( [ type, count ] ) => stmt.bind( siteId, ts, type, count ) ) );
}

/**
 * Pending commands for a site (for the pull model).
 * @param {D1Database} db
 * @param {number} siteId
 * @returns {Promise<object[]>}
 */
export async function pendingCommands( db, siteId ) {
	const res = await db
		.prepare( "SELECT id, command, params FROM commands WHERE site_id = ? AND status = 'pending' ORDER BY id" )
		.bind( siteId )
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
