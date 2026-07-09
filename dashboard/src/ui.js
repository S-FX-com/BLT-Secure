/**
 * Minimal server-rendered dashboard UI.
 *
 * Intended to sit behind Cloudflare Access (email allow-list) — there is no
 * auth in the app itself for the operator view; the Access layer gates it.
 * Renders a fleet table from the stored snapshots.
 */

/**
 * HTML-escape a value.
 * @param {*} value
 * @returns {string}
 */
function esc( value ) {
	return String( value ?? '' ).replace( /[&<>"']/g, ( c ) =>
		( { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' } )[ c ]
	);
}

/**
 * Coarse posture badge from a snapshot payload.
 * @param {object} snap
 * @returns {string}
 */
function posture( snap ) {
	const fail =
		( snap?.core?.count || 0 ) +
		( snap?.malware?.count || 0 ) +
		( snap?.baseline?.count || 0 ) +
		( snap?.health?.fail || 0 );
	if ( ! snap ) {
		return '—';
	}
	return fail > 0 ? `⚠ ${ fail } issue(s)` : '✓ clean';
}

/**
 * Render the fleet dashboard page.
 * @param {object[]} sites Rows from listSites().
 * @returns {string} HTML.
 */
export function renderDashboard( sites ) {
	const rows = sites
		.map( ( row ) => {
			let snap = null;
			try {
				snap = row.payload ? JSON.parse( row.payload ) : null;
			} catch ( e ) {
				snap = null;
			}
			const seen = row.last_seen ? new Date( row.last_seen * 1000 ).toISOString().replace( 'T', ' ' ).slice( 0, 16 ) : '—';
			return (
				'<tr>' +
				`<td>${ esc( row.name || row.site_url || '#' + row.id ) }</td>` +
				`<td>${ esc( snap?.site || row.site_url || '' ) }</td>` +
				`<td>${ esc( snap?.health?.score ?? '—' ) }</td>` +
				`<td>${ esc( posture( snap ) ) }</td>` +
				`<td>${ esc( snap?.versions?.plugin || '—' ) }</td>` +
				`<td>${ esc( seen ) }</td>` +
				'</tr>'
			);
		} )
		.join( '' );

	return `<!doctype html>
<html lang="en"><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>BLT Secure — Fleet</title>
<style>
 body{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#1d2327}
 h1{font-size:20px}
 table{border-collapse:collapse;width:100%;max-width:1000px}
 th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #e0e0e0}
 th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:#646970}
 tr:hover td{background:#f6f7f7}
</style></head><body>
<h1>BLT Secure — Fleet</h1>
<p>${ esc( sites.length ) } site(s) reporting.</p>
<table>
<thead><tr><th>Site</th><th>URL</th><th>Score</th><th>Posture</th><th>Plugin</th><th>Last seen (UTC)</th></tr></thead>
<tbody>${ rows || '<tr><td colspan="6">No sites enrolled yet.</td></tr>' }</tbody>
</table>
</body></html>`;
}
