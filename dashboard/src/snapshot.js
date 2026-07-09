/**
 * Validation + normalization for incoming posture snapshots.
 *
 * The Worker never trusts the plugin's JSON blindly: parseSnapshot enforces
 * the contract shape and whitelists the fields it stores, so a compromised
 * or buggy client cannot inject arbitrary structure into D1. Pure and
 * unit-tested.
 */

/**
 * @typedef {{ ok: true, value: object } | { ok: false, error: string }} ParseResult
 */

/**
 * Coerce to a non-negative integer.
 * @param {*} value
 * @returns {number}
 */
function int( value ) {
	const n = Number( value );
	return Number.isFinite( n ) && n >= 0 ? Math.floor( n ) : 0;
}

/**
 * Coerce to a short-ish string.
 * @param {*} value
 * @param {number} [max]
 * @returns {string}
 */
function str( value, max = 255 ) {
	return 'string' === typeof value ? value.slice( 0, max ) : '';
}

/**
 * Normalize a scan section ({status, count/issues/findings}).
 * @param {*} section
 * @param {string} countKey
 * @returns {{status: string, count: number}}
 */
function scanSection( section, countKey ) {
	const s = section && 'object' === typeof section ? section : {};
	return {
		status: str( s.status, 16 ) || 'none',
		count: int( s[ countKey ] ),
	};
}

/**
 * Validate and normalize a raw snapshot object.
 * @param {*} raw Parsed JSON.
 * @returns {ParseResult}
 */
export function parseSnapshot( raw ) {
	if ( ! raw || 'object' !== typeof raw || Array.isArray( raw ) ) {
		return { ok: false, error: 'not an object' };
	}
	if ( 1 !== Number( raw.schema ) ) {
		return { ok: false, error: 'unsupported schema' };
	}
	const site = str( raw.site, 255 );
	if ( ! /^https?:\/\//i.test( site ) ) {
		return { ok: false, error: 'invalid site url' };
	}

	const versions = raw.versions && 'object' === typeof raw.versions ? raw.versions : {};
	const health = raw.health && 'object' === typeof raw.health ? raw.health : {};

	// Whitelist event counts to plain type => int.
	const events = {};
	if ( raw.events && 'object' === typeof raw.events && ! Array.isArray( raw.events ) ) {
		for ( const [ type, count ] of Object.entries( raw.events ) ) {
			events[ str( type, 64 ) ] = int( count );
		}
	}

	return {
		ok: true,
		value: {
			schema: 1,
			site,
			name: str( raw.name, 200 ),
			reported_at: int( raw.reported_at ),
			versions: {
				plugin: str( versions.plugin, 32 ),
				wp: str( versions.wp, 32 ),
				php: str( versions.php, 32 ),
			},
			health: {
				score: null === health.score || undefined === health.score ? null : int( health.score ),
				pass: int( health.pass ),
				warn: int( health.warn ),
				fail: int( health.fail ),
			},
			core: scanSection( raw.core, 'issues' ),
			malware: scanSection( raw.malware, 'findings' ),
			baseline: scanSection( raw.baseline, 'findings' ),
			ioc: scanSection( raw.ioc, 'count' ),
			cloudflare: {
				connected: !! ( raw.cloudflare && raw.cloudflare.connected ),
				plan: str( raw.cloudflare && raw.cloudflare.plan, 32 ),
			},
			events,
		},
	};
}
