/**
 * Cloudflare Access operator authentication.
 *
 * The Worker's operator routes (`/`, `/admin/*`) verify the signed
 * `Cf-Access-Jwt-Assertion` JWT that Cloudflare Access attaches: RS256 against
 * the team's JWKS, with the application AUD and the team issuer checked, plus
 * expiry. A bare `Cf-Access-Authenticated-User-Email` header is NEVER trusted —
 * a client can send it to any hostname that reaches the Worker without Access
 * (for example workers.dev).
 *
 * Fails CLOSED: when ACCESS_TEAM_DOMAIN or ACCESS_AUD is not configured every
 * operator request is refused.
 *
 * LEGACY — superseded by Buoy / BLT Connect.
 *
 * Runtime-agnostic (Web Crypto + fetch): unit-tested under Node.
 */

const decoder = new TextDecoder();

/**
 * base64url → bytes.
 * @param {string} value
 * @returns {Uint8Array}
 */
export function b64urlToBytes( value ) {
	const padded = String( value ).replace( /-/g, '+' ).replace( /_/g, '/' ).padEnd( Math.ceil( String( value ).length / 4 ) * 4, '=' );
	const bin = atob( padded );
	const out = new Uint8Array( bin.length );
	for ( let i = 0; i < bin.length; i++ ) {
		out[ i ] = bin.charCodeAt( i );
	}
	return out;
}

/**
 * Split + decode a compact JWT without trusting it.
 * @param {string} token
 * @returns {{ header: object, payload: object, signingInput: string, signature: Uint8Array } | null}
 */
export function decodeJwt( token ) {
	const parts = String( token || '' ).split( '.' );
	if ( 3 !== parts.length || parts.some( ( p ) => '' === p ) ) {
		return null;
	}
	try {
		return {
			header: JSON.parse( decoder.decode( b64urlToBytes( parts[ 0 ] ) ) ),
			payload: JSON.parse( decoder.decode( b64urlToBytes( parts[ 1 ] ) ) ),
			signingInput: `${ parts[ 0 ] }.${ parts[ 1 ] }`,
			signature: b64urlToBytes( parts[ 2 ] ),
		};
	} catch ( e ) {
		return null;
	}
}

/**
 * Verify an Access JWT. Returns the claims, or null for ANY failure.
 * @param {string} token
 * @param {{ jwks: { keys: object[] }, aud: string, issuer: string, now: number }} opts now = unix seconds
 * @returns {Promise<object|null>}
 */
export async function verifyAccessJwt( token, { jwks, aud, issuer, now } ) {
	const jwt = decodeJwt( token );
	if ( ! jwt || ! jwt.header || 'RS256' !== jwt.header.alg || ! jwt.header.kid ) {
		return null;
	}
	const jwk = ( jwks && Array.isArray( jwks.keys ) ? jwks.keys : [] ).find(
		( k ) => k && k.kid === jwt.header.kid && 'RSA' === k.kty
	);
	if ( ! jwk ) {
		return null;
	}

	let ok = false;
	try {
		const key = await crypto.subtle.importKey(
			'jwk',
			{ kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
			{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
			false,
			[ 'verify' ]
		);
		ok = await crypto.subtle.verify(
			'RSASSA-PKCS1-v1_5',
			key,
			jwt.signature,
			new TextEncoder().encode( jwt.signingInput )
		);
	} catch ( e ) {
		return null;
	}
	if ( ! ok ) {
		return null;
	}

	const claims = jwt.payload;
	if ( ! claims || 'object' !== typeof claims || claims.iss !== issuer ) {
		return null;
	}
	const audiences = Array.isArray( claims.aud ) ? claims.aud : [ claims.aud ];
	if ( ! aud || ! audiences.includes( aud ) ) {
		return null;
	}
	if ( ! Number.isFinite( claims.exp ) || claims.exp <= now ) {
		return null;
	}
	if ( undefined !== claims.nbf && ( ! Number.isFinite( claims.nbf ) || claims.nbf > now + 60 ) ) {
		return null;
	}
	return claims;
}

const JWKS_TTL = 600; // seconds
let jwksCache = { team: '', at: 0, jwks: null };

/**
 * Fetch (and cache) the team's JWKS.
 * @param {string} team e.g. "acme.cloudflareaccess.com"
 * @param {number} now unix seconds
 * @param {typeof fetch} fetchFn
 * @param {boolean} [force] bypass the cache (unknown kid)
 * @returns {Promise<object|null>}
 */
export async function getJwks( team, now, fetchFn, force = false ) {
	if ( ! force && jwksCache.jwks && jwksCache.team === team && now - jwksCache.at < JWKS_TTL ) {
		return jwksCache.jwks;
	}
	// A forced refresh is still rate-limited so a stream of forged kids cannot
	// turn the Worker into a JWKS-fetch amplifier.
	if ( force && jwksCache.team === team && now - jwksCache.at < 30 && jwksCache.jwks ) {
		return jwksCache.jwks;
	}
	try {
		const res = await fetchFn( `https://${ team }/cdn-cgi/access/certs` );
		if ( ! res.ok ) {
			return jwksCache.team === team ? jwksCache.jwks : null;
		}
		const jwks = await res.json();
		if ( ! jwks || ! Array.isArray( jwks.keys ) ) {
			return null;
		}
		jwksCache = { team, at: now, jwks };
		return jwks;
	} catch ( e ) {
		return jwksCache.team === team ? jwksCache.jwks : null;
	}
}

/** Test helper: forget the cached JWKS. */
export function resetJwksCache() {
	jwksCache = { team: '', at: 0, jwks: null };
}

/**
 * Authorize an operator request.
 * @param {Request} request
 * @param {{ ACCESS_TEAM_DOMAIN?: string, ACCESS_AUD?: string }} env
 * @param {{ fetch?: typeof fetch, now?: number }} [deps]
 * @returns {Promise<{ ok: true, email: string } | { ok: false, status: number, error: string }>}
 */
export async function authorizeOperator( request, env, deps = {} ) {
	const team = String( env.ACCESS_TEAM_DOMAIN || '' ).trim().toLowerCase();
	const aud = String( env.ACCESS_AUD || '' ).trim();
	if ( ! /^[a-z0-9-]+\.cloudflareaccess\.com$/.test( team ) || ! aud ) {
		return { ok: false, status: 503, error: 'operator access is not configured' };
	}

	const token = request.headers.get( 'Cf-Access-Jwt-Assertion' ) || '';
	if ( ! token ) {
		return { ok: false, status: 403, error: 'forbidden' };
	}

	const now = deps.now ?? Math.floor( Date.now() / 1000 );
	const fetchFn = deps.fetch ?? fetch;
	const issuer = `https://${ team }`;

	let jwks = await getJwks( team, now, fetchFn );
	let claims = jwks ? await verifyAccessJwt( token, { jwks, aud, issuer, now } ) : null;
	if ( ! claims && jwks ) {
		// Possibly a rotated signing key: refresh once (rate-limited) and retry.
		const fresh = await getJwks( team, now, fetchFn, true );
		if ( fresh && fresh !== jwks ) {
			claims = await verifyAccessJwt( token, { jwks: fresh, aud, issuer, now } );
		}
	}
	if ( ! claims ) {
		return { ok: false, status: jwks ? 403 : 503, error: jwks ? 'forbidden' : 'could not load Access keys' };
	}
	return { ok: true, email: String( claims.email || claims.sub || '' ) };
}
