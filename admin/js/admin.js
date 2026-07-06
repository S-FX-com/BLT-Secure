/**
 * BLT Secure admin — Cloudflare tab AJAX.
 *
 * @package Blt_Secure
 */

( function () {
	'use strict';

	if ( typeof window.bltSecure === 'undefined' ) {
		return;
	}

	var cfg = window.bltSecure;

	function post( action, data ) {
		var body = new URLSearchParams();
		body.set( 'action', action );
		body.set( '_ajax_nonce', cfg.nonce );
		Object.keys( data || {} ).forEach( function ( key ) {
			body.set( key, data[ key ] );
		} );

		return fetch( cfg.ajaxUrl, {
			method: 'POST',
			credentials: 'same-origin',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: body.toString()
		} ).then( function ( response ) {
			return response.json();
		} );
	}

	function setMessage( el, text, isError ) {
		if ( el ) {
			el.textContent = text || '';
			el.style.color = isError ? '#b32d2e' : '';
		}
	}

	// Token connect.
	var connectBtn = document.getElementById( 'blt-cf-connect' );
	if ( connectBtn ) {
		connectBtn.addEventListener( 'click', function () {
			var tokenInput = document.getElementById( 'blt-cf-token' );
			var status = document.getElementById( 'blt-cf-status' );

			connectBtn.disabled = true;
			setMessage( status, cfg.i18n.working, false );

			post( 'blt_secure_cf_save_token', { token: tokenInput.value } ).then( function ( json ) {
				if ( json.success ) {
					setMessage( status, json.data.message, false );
					window.location.reload();
				} else {
					connectBtn.disabled = false;
					setMessage( status, json.data.message, true );
				}
			} ).catch( function () {
				connectBtn.disabled = false;
				setMessage( status, cfg.i18n.error, true );
			} );
		} );
	}

	// Token disconnect.
	var disconnectBtn = document.getElementById( 'blt-cf-disconnect' );
	if ( disconnectBtn ) {
		disconnectBtn.addEventListener( 'click', function () {
			disconnectBtn.disabled = true;
			post( 'blt_secure_cf_delete_token', {} ).then( function () {
				window.location.reload();
			} );
		} );
	}

	// Deploy / remove cards.
	document.querySelectorAll( '.blt-card' ).forEach( function ( card ) {
		var feature = card.getAttribute( 'data-feature' );
		var message = card.querySelector( '.blt-card-message' );
		var badge = card.querySelector( '.blt-badge' );

		function run( action, extra ) {
			var buttons = card.querySelectorAll( 'button' );
			buttons.forEach( function ( b ) {
				b.disabled = true;
			} );
			setMessage( message, cfg.i18n.working, false );

			var data = { feature: feature };
			Object.keys( extra || {} ).forEach( function ( k ) {
				data[ k ] = extra[ k ];
			} );

			post( action, data ).then( function ( json ) {
				buttons.forEach( function ( b ) {
					b.disabled = false;
				} );
				if ( json.success ) {
					setMessage( message, json.data.message, false );
					if ( badge ) {
						var deployed = 'blt_secure_cf_deploy' === action;
						badge.textContent = deployed ? cfg.i18n.deployed : cfg.i18n.removed;
						badge.className = 'blt-badge' + ( deployed ? ' blt-badge-ok' : '' );
					}
				} else {
					setMessage( message, json.data.message, true );
				}
			} ).catch( function () {
				buttons.forEach( function ( b ) {
					b.disabled = false;
				} );
				setMessage( message, cfg.i18n.error, true );
			} );
		}

		var deployBtn = card.querySelector( '.blt-deploy' );
		if ( deployBtn ) {
			deployBtn.addEventListener( 'click', function () {
				var extra = {};
				var paranoia = card.querySelector( '.blt-paranoia' );
				var threshold = card.querySelector( '.blt-threshold' );
				if ( paranoia ) {
					extra.paranoia = paranoia.value;
				}
				if ( threshold ) {
					extra.score_threshold = threshold.value;
				}
				run( 'blt_secure_cf_deploy', extra );
			} );
		}

		var removeBtn = card.querySelector( '.blt-remove' );
		if ( removeBtn ) {
			removeBtn.addEventListener( 'click', function () {
				run( 'blt_secure_cf_remove', {} );
			} );
		}
	} );
}() );
