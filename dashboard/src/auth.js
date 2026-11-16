/**
 * Request authentication for the fleet ingest API.
 *
 * LEGACY — superseded by Buoy / BLT Connect (Ed25519 envelopes). Frozen:
 * defects only, no new features.
 *
 * Mirrors the plugin's Blt_Secure_Fleet signing: the per-site token is the
 * HMAC secret and the Bearer credential. The Worker stores only the token's
 * SHA-256 (for lookup) — never the raw token — and recomputes the HMAC from
 * the presented Bearer value to verify body integrity + replay freshness.
 *
 * Pure, runtime-agnostic (Web Crypto): unit-tested under Node and identical
 * in the Workers runtime.
 */

const encoder = new TextEncoder();

/**
 * Lowercase hex of a byte buffer.
 * @param {ArrayBuffer} buf
 * @returns {string}
 */
function toHex( buf ) {
	return [ ...new Uint8Array( buf ) ].map( ( b ) => b.toString( 16 ).padStart( 2, '0' ) ).join( '' );
}

/**
 * SHA-256 hex of a string.
 * @param {string} value
 * @returns {Promise<string>}
 */
export async function sha256Hex( value ) {
	return toHex( await crypto.subtle.digest( 'SHA-256', encoder.encode( value ) ) );
}

/**
 * The stored lookup key for a token.
 * @param {string} token
 * @returns {Promise<string>}
 */
export function tokenHash( token ) {
	return sha256Hex( String( token ) );
}

/**
 * Lowercase hex HMAC-SHA256 of `message` keyed by `secret`.
 * @param {string} secret
 * @param {string} message
 * @returns {Promise<string>}
 */
export async function hmacHex( secret, message ) {
	const key = await crypto.subtle.importKey(
		'raw',
		encoder.encode( String( secret ) ),
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		[ 'sign' ]
	);
	return toHex( await crypto.subtle.sign( 'HMAC', key, encoder.encode( String( message ) ) ) );
}

/**
 * Constant-time comparison of two equal-purpose hex strings.
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
export function timingSafeEqualHex( a, b ) {
	a = String( a );
	b = String( b );
	if ( a.length !== b.length ) {
		return false;
	}
	let diff = 0;
	for ( let i = 0; i < a.length; i++ ) {
		diff |= a.charCodeAt( i ) ^ b.charCodeAt( i );
	}
	return 0 === diff;
}

/**
 * Whether a timestamp is within the allowed skew of now (replay guard).
 * @param {number} ts
 * @param {number} now
 * @param {number} [maxSkew] seconds
 * @returns {boolean}
 */
export function isFresh( ts, now, maxSkew = 300 ) {
	ts = Number( ts );
	now = Number( now );
	if ( ! Number.isFinite( ts ) || ! Number.isFinite( now ) ) {
		return false;
	}
	return Math.abs( now - ts ) <= maxSkew;
}

/**
 * Verify the signature the plugin computed over `${ts}.${body}`.
 * @param {string} token Presented Bearer token (the HMAC secret).
 * @param {string|number} ts
 * @param {string} body Raw request body.
 * @param {string} signature Presented X-BLT-Signature.
 * @returns {Promise<boolean>}
 */
export async function verifySignature( token, ts, body, signature ) {
	const expected = await hmacHex( token, `${ String( ts ) }.${ String( body ) }` );
	return timingSafeEqualHex( expected, signature );
}

/**
 * Domain-separation label for the response-signing key. MUST match
 * Blt_Secure_Fleet::RESPONSE_KEY_LABEL in the plugin.
 */
export const RESPONSE_KEY_LABEL = 'blt-secure-fleet/v2/response-key';

/**
 * Whether a request nonce is acceptable (opaque, 16-64 alphanumerics).
 * @param {string} nonce
 * @returns {boolean}
 */
export function isValidNonce( nonce ) {
	return /^[A-Za-z0-9]{16,64}$/.test( String( nonce || '' ) );
}

/**
 * Derive the response-signing key from the site token: HMAC(token, label),
 * hex. A different secret from the bearer token and request-signing key, so
 * a request signature can never double as a response signature.
 * @param {string} token
 * @returns {Promise<string>}
 */
export function responseKey( token ) {
	return hmacHex( token, RESPONSE_KEY_LABEL );
}

/**
 * Sign a /v1/commands response: hex HMAC of `${ts}.${nonce}.${body}`.
 * Binding the request's nonce means a captured response cannot be replayed
 * against a later request.
 * @param {string} token
 * @param {string|number} ts
 * @param {string} nonce
 * @param {string} body
 * @returns {Promise<string>}
 */
export async function signResponse( token, ts, nonce, body ) {
	return hmacHex( await responseKey( token ), `${ String( ts ) }.${ nonce }.${ String( body ) }` );
}
