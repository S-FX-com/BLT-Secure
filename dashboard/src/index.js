/**
 * BLT Secure fleet dashboard — Cloudflare Worker entry.
 *
 * LEGACY — superseded by Buoy / BLT Connect (Ed25519 envelopes). Frozen:
 * defects only, no new features.
 *
 * Routes:
 *   POST /v1/snapshot       ingest a posture snapshot (per-site token + HMAC)
 *   GET  /v1/commands       pull queued remote commands (per-site token + HMAC;
 *                           the RESPONSE is signed — see auth.js signResponse)
 *   POST /v1/commands/ack   acknowledge executed commands
 *   GET  /                  operator dashboard
 *   POST /admin/sites       enroll a site → returns a one-time token
 *   POST /admin/sites/revoke  delete a site (its token stops working)
 *   POST /admin/commands    queue a command for a site
 *
 * The /v1/* endpoints are authenticated by the plugin's per-site token +
 * HMAC signature. The operator routes verify the Cloudflare Access JWT
 * (src/access.js) and fail CLOSED when ACCESS_TEAM_DOMAIN / ACCESS_AUD are
 * not configured. A bare Access identity header is never trusted.
 */

import { tokenHash, verifySignature, isFresh, sha256Hex, isValidNonce, signResponse } from './auth.js';
import { authorizeOperator } from './access.js';
import { parseSnapshot } from './snapshot.js';
import * as db from './db.js';
import { renderDashboard } from './ui.js';

const MAX_BODY = 65536; // 64 KB — snapshots are small.

/** The only commands the plugin will run; the Worker refuses to queue anything else. */
export const COMMANDS = [ 'scan_core', 'scan_malware', 'scan_baseline', 'sync_ioc', 'health_scan', 'report' ];

/**
 * Headers every response carries.
 * @param {string} contentType
 * @returns {Record<string,string>}
 */
function baseHeaders( contentType ) {
	return {
		'Content-Type': contentType,
		'X-Content-Type-Options': 'nosniff',
		'Cache-Control': 'no-store',
		'Referrer-Policy': 'no-referrer',
		'Content-Security-Policy':
			"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
	};
}

/**
 * @param {object} data
 * @param {number} [status]
 * @param {Record<string,string>} [extra] extra headers
 * @returns {Response}
 */
function json( data, status = 200, extra = {} ) {
	return new Response( JSON.stringify( data ), {
		status,
		headers: { ...baseHeaders( 'application/json' ), ...extra },
	} );
}

/**
 * Read a request body with a hard size cap BEFORE buffering it all: refuse on
 * a declared Content-Length over the cap and abort a streamed body that
 * exceeds it.
 * @param {Request} request
 * @param {number} max bytes
 * @returns {Promise<string|null>} null when too large
 */
export async function readBody( request, max = MAX_BODY ) {
	const declared = Number( request.headers.get( 'Content-Length' ) );
	if ( Number.isFinite( declared ) && declared > max ) {
		return null;
	}
	if ( ! request.body ) {
		return '';
	}
	const reader = request.body.getReader();
	const chunks = [];
	let total = 0;
	for ( ;; ) {
		const { done, value } = await reader.read();
		if ( done ) {
			break;
		}
		total += value.length;
		if ( total > max ) {
			await reader.cancel();
			return null;
		}
		chunks.push( value );
	}
	const all = new Uint8Array( total );
	let offset = 0;
	for ( const chunk of chunks ) {
		all.set( chunk, offset );
		offset += chunk.length;
	}
	return new TextDecoder().decode( all );
}

/**
 * Authenticate a /v1 request: verify the Bearer token, HMAC signature, and
 * timestamp freshness. Returns the site row (and the presented token, needed
 * to sign the response), or a Response to short-circuit.
 * @param {Request} request
 * @param {object} env
 * @param {string} body Raw request body (already read).
 * @returns {Promise<{ site: object, token: string } | { response: Response }>}
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
	return { site, token };
}

/**
 * Guard operator routes: verify the Cloudflare Access JWT (fail closed), and
 * for state-changing requests refuse cross-site browser requests.
 * @param {Request} request
 * @param {object} env
 * @param {{ mutating?: boolean, deps?: object }} [opts]
 * @returns {Promise<Response|null>}
 */
async function guardOperator( request, env, opts = {} ) {
	const result = await authorizeOperator( request, env, opts.deps );
	if ( ! result.ok ) {
		return json( { error: result.error }, result.status );
	}
	if ( opts.mutating ) {
		const origin = request.headers.get( 'Origin' );
		const site = request.headers.get( 'Sec-Fetch-Site' );
		if ( ( origin && origin !== new URL( request.url ).origin ) || 'cross-site' === site ) {
			return json( { error: 'cross-site request refused' }, 403 );
		}
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

/**
 * Parse a positive integer id from untrusted input (no coercion of junk).
 * @param {*} value
 * @returns {number|null}
 */
export function positiveInt( value ) {
	const n = 'number' === typeof value ? value : 'string' === typeof value && /^\d{1,12}$/.test( value ) ? Number( value ) : NaN;
	return Number.isSafeInteger( n ) && n > 0 ? n : null;
}

export default {
	/**
	 * @param {Request} request
	 * @param {object} env
	 * @param {object} [ctx]
	 * @param {object} [deps] Test seam (fetch / now for Access verification).
	 * @returns {Promise<Response>}
	 */
	async fetch( request, env, ctx, deps ) {
		const url = new URL( request.url );
		const { pathname } = url;
		const now = Math.floor( Date.now() / 1000 );

		try {
			// ---- Ingest ----------------------------------------------------
			if ( 'POST' === request.method && '/v1/snapshot' === pathname ) {
				const body = await readBody( request );
				if ( null === body ) {
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
				const reportedAt = snap.reported_at || now;
				if ( ! isFresh( reportedAt, now, 600 ) ) {
					return json( { error: 'stale snapshot' }, 400 );
				}

				// Replay / duplicate guard: a snapshot no newer than the stored one
				// is acknowledged but changes nothing (so events are not counted twice).
				if ( reportedAt <= ( await db.getSnapshotReportedAt( env.DB, auth.site.id ) ) ) {
					return json( { ok: true, duplicate: true } );
				}

				await db.touchSite( env.DB, auth.site.id, snap.site, snap.name, now );
				await db.upsertSnapshot( env.DB, auth.site.id, reportedAt, JSON.stringify( snap ) );
				await db.recordEvents( env.DB, auth.site.id, now, snap.events );
				return json( { ok: true } );
			}

			// ---- Pull commands (remote-actions, pull model) ---------------
			if ( 'GET' === request.method && '/v1/commands' === pathname ) {
				const nonce = request.headers.get( 'X-BLT-Nonce' ) || '';
				if ( ! isValidNonce( nonce ) ) {
					return json( { error: 'nonce required' }, 400 );
				}
				const auth = await authenticate( request, env, '' );
				if ( auth.response ) {
					return auth.response;
				}
				const commands = await db.pendingCommands( env.DB, auth.site.id, now );
				await db.markDelivered( env.DB, commands.map( ( c ) => c.id ), now );

				// The signature proves the responder holds the site token and binds
				// this answer to this request's nonce (no replay of an old list).
				const payload = JSON.stringify( { commands: commands.map( ( c ) => ( { id: c.id, command: c.command } ) ) } );
				return new Response( payload, {
					status: 200,
					headers: {
						...baseHeaders( 'application/json' ),
						'X-BLT-Response-Timestamp': String( now ),
						'X-BLT-Response-Nonce': nonce,
						'X-BLT-Response-Signature': await signResponse( auth.token, now, nonce, payload ),
					},
				} );
			}

			// ---- Ack executed commands (pull model) -----------------------
			if ( 'POST' === request.method && '/v1/commands/ack' === pathname ) {
				const body = await readBody( request );
				if ( null === body ) {
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
				const clean = db.sanitizeIds( ids ).slice( 0, 100 );
				await db.markDone( env.DB, auth.site.id, clean, now );
				return json( { ok: true, done: clean.length } );
			}

			// ---- Operator: enroll a site ----------------------------------
			if ( 'POST' === request.method && '/admin/sites' === pathname ) {
				const blocked = await guardOperator( request, env, { mutating: true, deps } );
				if ( blocked ) {
					return blocked;
				}
				const token = randomToken();
				const id = await db.createSite( env.DB, await sha256Hex( token ), now );
				// The raw token is shown exactly once; only its hash is stored.
				return json( { id, token } );
			}

			// ---- Operator: revoke a site ----------------------------------
			if ( 'POST' === request.method && '/admin/sites/revoke' === pathname ) {
				const blocked = await guardOperator( request, env, { mutating: true, deps } );
				if ( blocked ) {
					return blocked;
				}
				if ( ! ( request.headers.get( 'Content-Type' ) || '' ).toLowerCase().startsWith( 'application/json' ) ) {
					return json( { error: 'application/json required' }, 415 );
				}
				const raw = await readBody( request, 1024 );
				let payload = null;
				try {
					payload = null === raw ? null : JSON.parse( raw );
				} catch ( e ) {
					payload = null;
				}
				const siteId = payload ? positiveInt( payload.site_id ) : null;
				if ( ! siteId || ! ( await db.siteExists( env.DB, siteId ) ) ) {
					return json( { error: 'unknown site_id' }, 404 );
				}
				await db.deleteSite( env.DB, siteId );
				return json( { ok: true } );
			}

			// ---- Operator: queue a command --------------------------------
			if ( 'POST' === request.method && '/admin/commands' === pathname ) {
				const blocked = await guardOperator( request, env, { mutating: true, deps } );
				if ( blocked ) {
					return blocked;
				}
				if ( ! ( request.headers.get( 'Content-Type' ) || '' ).toLowerCase().startsWith( 'application/json' ) ) {
					return json( { error: 'application/json required' }, 415 );
				}
				const raw = await readBody( request, 4096 );
				if ( null === raw ) {
					return json( { error: 'body too large' }, 413 );
				}
				let payload = null;
				try {
					payload = JSON.parse( raw );
				} catch ( e ) {
					payload = null;
				}
				const siteId = payload ? positiveInt( payload.site_id ) : null;
				if ( ! siteId || 'string' !== typeof payload.command || ! COMMANDS.includes( payload.command ) ) {
					return json( { error: 'site_id and a known command required' }, 400 );
				}
				if ( ! ( await db.siteExists( env.DB, siteId ) ) ) {
					return json( { error: 'unknown site_id' }, 404 );
				}
				if ( ( await db.countQueued( env.DB, siteId, now ) ) >= db.MAX_QUEUED ) {
					return json( { error: 'too many queued commands for this site' }, 429 );
				}
				await db.queueCommand( env.DB, siteId, payload.command, now );
				return json( { ok: true } );
			}

			// ---- Operator: dashboard --------------------------------------
			if ( 'GET' === request.method && '/' === pathname ) {
				const blocked = await guardOperator( request, env, { deps } );
				if ( blocked ) {
					return blocked;
				}
				const sites = await db.listSites( env.DB );
				return new Response( renderDashboard( sites ), {
					headers: baseHeaders( 'text/html; charset=utf-8' ),
				} );
			}

			return json( { error: 'not found' }, 404 );
		} catch ( e ) {
			return json( { error: 'server error' }, 500 );
		}
	},
};
