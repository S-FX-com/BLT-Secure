/**
 * BLT Secure fleet dashboard — Cloudflare Worker entry.
 *
 * Routes:
 *   POST /v1/snapshot      ingest a posture snapshot (per-site token + HMAC)
 *   GET  /v1/commands      pull queued remote commands (per-site token + HMAC)
 *   GET  /                 operator dashboard (must sit behind Cloudflare Access)
 *   POST /admin/sites      enroll a site → returns a one-time token (behind Access)
 *   POST /admin/commands   queue a command for a site (behind Access)
 *
 * The /v1/* endpoints are authenticated by the plugin's per-site token +
 * HMAC signature; the operator routes are gated by Cloudflare Access in front
 * of the Worker (optionally enforced here when ACCESS_ENFORCED = "1").
 */

import { tokenHash, verifySignature, isFresh, sha256Hex } from './auth.js';
import { parseSnapshot } from './snapshot.js';
import * as db from './db.js';
import { renderDashboard } from './ui.js';

const MAX_BODY = 65536; // 64 KB — snapshots are small.

/**
 * @param {object} data
 * @param {number} [status]
 * @returns {Response}
 */
function json( data, status = 200 ) {
	return new Response( JSON.stringify( data ), {
		status,
		headers: { 'Content-Type': 'application/json' },
	} );
}

/**
 * Authenticate a /v1 request: verify the Bearer token, HMAC signature, and
 * timestamp freshness. Returns the site row, or a Response to short-circuit.
 * @param {Request} request
 * @param {object} env
 * @param {string} body Raw request body (already read).
 * @returns {Promise<{ site: object } | { response: Response }>}
 */
async function authenticate( request, env, body ) {
	const auth = request.headers.get( 'Authorization' ) || '';
	const token = auth.startsWith( 'Bearer ' ) ? auth.slice( 7 ).trim() : '';
	const ts = request.headers.get( 'X-BLT-Timestamp' ) || '';
	const sig = request.headers.get( 'X-BLT-Signature' ) || '';

	if ( ! token || ! ts || ! sig ) {
		return { response: json( { error: 'missing credentials' }, 401 ) };
	}
	if ( ! isFresh( ts, Math.floor( Date.now() / 1000 ) ) ) {
		return { response: json( { error: 'stale request' }, 401 ) };
	}

	const site = await db.getSiteByTokenHash( env.DB, await tokenHash( token ) );
	if ( ! site ) {
		return { response: json( { error: 'unknown site' }, 401 ) };
	}
	if ( ! ( await verifySignature( token, ts, body, sig ) ) ) {
		return { response: json( { error: 'bad signature' }, 401 ) };
	}
	return { site };
}

/**
 * Guard operator routes. Cloudflare Access should front them; when
 * ACCESS_ENFORCED is "1" we also require the Access-injected identity header.
 * @param {Request} request
 * @param {object} env
 * @returns {Response|null}
 */
function guardOperator( request, env ) {
	if ( '1' === env.ACCESS_ENFORCED && ! request.headers.get( 'Cf-Access-Authenticated-User-Email' ) ) {
		return json( { error: 'forbidden' }, 403 );
	}
	return null;
}

/**
 * Random hex token.
 * @param {number} [bytes]
 * @returns {string}
 */
function randomToken( bytes = 32 ) {
	const buf = new Uint8Array( bytes );
	crypto.getRandomValues( buf );
	return [ ...buf ].map( ( b ) => b.toString( 16 ).padStart( 2, '0' ) ).join( '' );
}

export default {
	/**
	 * @param {Request} request
	 * @param {object} env
	 * @returns {Promise<Response>}
	 */
	async fetch( request, env ) {
		const url = new URL( request.url );
		const { pathname } = url;
		const now = Math.floor( Date.now() / 1000 );

		try {
			// ---- Ingest ----------------------------------------------------
			if ( 'POST' === request.method && '/v1/snapshot' === pathname ) {
				const body = await request.text();
				if ( body.length > MAX_BODY ) {
					return json( { error: 'body too large' }, 413 );
				}
				const auth = await authenticate( request, env, body );
				if ( auth.response ) {
					return auth.response;
				}

				let parsed;
				try {
					parsed = parseSnapshot( JSON.parse( body ) );
				} catch ( e ) {
					return json( { error: 'invalid json' }, 400 );
				}
				if ( ! parsed.ok ) {
					return json( { error: parsed.error }, 400 );
				}

				const snap = parsed.value;
				await db.touchSite( env.DB, auth.site.id, snap.site, snap.name, now );
				await db.upsertSnapshot( env.DB, auth.site.id, snap.reported_at || now, JSON.stringify( snap ) );
				await db.recordEvents( env.DB, auth.site.id, now, snap.events );
				return json( { ok: true } );
			}

			// ---- Pull commands (remote-actions, pull model) ---------------
			if ( 'GET' === request.method && '/v1/commands' === pathname ) {
				const auth = await authenticate( request, env, '' );
				if ( auth.response ) {
					return auth.response;
				}
				const commands = await db.pendingCommands( env.DB, auth.site.id );
				await db.markDelivered( env.DB, commands.map( ( c ) => c.id ), now );
				return json( { commands } );
			}

			// ---- Ack executed commands (pull model) -----------------------
			if ( 'POST' === request.method && '/v1/commands/ack' === pathname ) {
				const body = await request.text();
				if ( body.length > MAX_BODY ) {
					return json( { error: 'body too large' }, 413 );
				}
				const auth = await authenticate( request, env, body );
				if ( auth.response ) {
					return auth.response;
				}
				let ids;
				try {
					ids = JSON.parse( body ).ids;
				} catch ( e ) {
					return json( { error: 'invalid json' }, 400 );
				}
				if ( ! Array.isArray( ids ) ) {
					return json( { error: 'ids array required' }, 400 );
				}
				const clean = db.sanitizeIds( ids );
				await db.markDone( env.DB, auth.site.id, clean, now );
				return json( { ok: true, done: clean.length } );
			}

			// ---- Operator: enroll a site ----------------------------------
			if ( 'POST' === request.method && '/admin/sites' === pathname ) {
				const blocked = guardOperator( request, env );
				if ( blocked ) {
					return blocked;
				}
				const token = randomToken();
				const id = await db.createSite( env.DB, await sha256Hex( token ), now );
				// The raw token is shown exactly once; only its hash is stored.
				return json( { id, token } );
			}

			// ---- Operator: queue a command --------------------------------
			if ( 'POST' === request.method && '/admin/commands' === pathname ) {
				const blocked = guardOperator( request, env );
				if ( blocked ) {
					return blocked;
				}
				const payload = await request.json().catch( () => null );
				if ( ! payload || ! payload.site_id || ! payload.command ) {
					return json( { error: 'site_id and command required' }, 400 );
				}
				await env.DB.prepare(
					"INSERT INTO commands (site_id, created_at, command, params, status) VALUES (?, ?, ?, ?, 'pending')"
				)
					.bind( Number( payload.site_id ), now, String( payload.command ), JSON.stringify( payload.params || {} ) )
					.run();
				return json( { ok: true } );
			}

			// ---- Operator: dashboard --------------------------------------
			if ( 'GET' === request.method && '/' === pathname ) {
				const blocked = guardOperator( request, env );
				if ( blocked ) {
					return blocked;
				}
				const sites = await db.listSites( env.DB );
				return new Response( renderDashboard( sites ), {
					headers: { 'Content-Type': 'text/html; charset=utf-8' },
				} );
			}

			return json( { error: 'not found' }, 404 );
		} catch ( e ) {
			return json( { error: 'server error' }, 500 );
		}
	},
};
