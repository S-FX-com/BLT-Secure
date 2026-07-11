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

	// GitHub updates token (Advanced tab) — same flow as the CF token.
	var ghConnectBtn = document.getElementById( 'blt-gh-connect' );
	if ( ghConnectBtn ) {
		ghConnectBtn.addEventListener( 'click', function () {
			var tokenInput = document.getElementById( 'blt-gh-token' );
			var status = document.getElementById( 'blt-gh-status' );

			ghConnectBtn.disabled = true;
			setMessage( status, cfg.i18n.working, false );

			post( 'blt_secure_gh_save_token', { token: tokenInput.value } ).then( function ( json ) {
				if ( json.success ) {
					setMessage( status, json.data.message, false );
					window.location.reload();
				} else {
					ghConnectBtn.disabled = false;
					setMessage( status, json.data.message, true );
				}
			} ).catch( function () {
				ghConnectBtn.disabled = false;
				setMessage( status, cfg.i18n.error, true );
			} );
		} );
	}

	var ghDisconnectBtn = document.getElementById( 'blt-gh-disconnect' );
	if ( ghDisconnectBtn ) {
		ghDisconnectBtn.addEventListener( 'click', function () {
			ghDisconnectBtn.disabled = true;
			post( 'blt_secure_gh_delete_token', {} ).then( function () {
				window.location.reload();
			} );
		} );
	}

	// Slack webhook (Advanced tab) — same flow as the GitHub token.
	var slackConnectBtn = document.getElementById( 'blt-slack-connect' );
	if ( slackConnectBtn ) {
		slackConnectBtn.addEventListener( 'click', function () {
			var input = document.getElementById( 'blt-slack-webhook' );
			var status = document.getElementById( 'blt-slack-status' );

			slackConnectBtn.disabled = true;
			setMessage( status, cfg.i18n.working, false );

			post( 'blt_secure_slack_save', { webhook: input.value } ).then( function ( json ) {
				if ( json.success ) {
					setMessage( status, json.data.message, false );
					window.location.reload();
				} else {
					slackConnectBtn.disabled = false;
					setMessage( status, json.data.message, true );
				}
			} ).catch( function () {
				slackConnectBtn.disabled = false;
				setMessage( status, cfg.i18n.error, true );
			} );
		} );
	}

	var slackDisconnectBtn = document.getElementById( 'blt-slack-disconnect' );
	if ( slackDisconnectBtn ) {
		slackDisconnectBtn.addEventListener( 'click', function () {
			slackDisconnectBtn.disabled = true;
			post( 'blt_secure_slack_delete', {} ).then( function () {
				window.location.reload();
			} );
		} );
	}

	// Fleet enrollment token (Advanced tab).
	var fleetConnectBtn = document.getElementById( 'blt-fleet-connect' );
	if ( fleetConnectBtn ) {
		fleetConnectBtn.addEventListener( 'click', function () {
			var input = document.getElementById( 'blt-fleet-token' );
			var status = document.getElementById( 'blt-fleet-status' );

			fleetConnectBtn.disabled = true;
			setMessage( status, cfg.i18n.working, false );

			post( 'blt_secure_fleet_save', { token: input.value } ).then( function ( json ) {
				if ( json.success ) {
					window.location.reload();
				} else {
					fleetConnectBtn.disabled = false;
					setMessage( status, json.data.message, true );
				}
			} ).catch( function () {
				fleetConnectBtn.disabled = false;
				setMessage( status, cfg.i18n.error, true );
			} );
		} );
	}

	var fleetDisconnectBtn = document.getElementById( 'blt-fleet-disconnect' );
	if ( fleetDisconnectBtn ) {
		fleetDisconnectBtn.addEventListener( 'click', function () {
			fleetDisconnectBtn.disabled = true;
			post( 'blt_secure_fleet_delete', {} ).then( function () {
				window.location.reload();
			} );
		} );
	}

	var fleetReportBtn = document.getElementById( 'blt-fleet-report' );
	if ( fleetReportBtn ) {
		fleetReportBtn.addEventListener( 'click', function () {
			var msg = document.getElementById( 'blt-fleet-msg' );
			fleetReportBtn.disabled = true;
			setMessage( msg, cfg.i18n.reporting, false );

			post( 'blt_secure_fleet_report', {} ).then( function ( json ) {
				fleetReportBtn.disabled = false;
				setMessage( msg, ( json.data && json.data.message ) || '', ! json.success );
			} ).catch( function () {
				fleetReportBtn.disabled = false;
				setMessage( msg, cfg.i18n.error, true );
			} );
		} );
	}

	// Health check: run a scan, then reload to render the fresh results.
	var hcRunBtn = document.getElementById( 'blt-hc-run' );
	if ( hcRunBtn ) {
		hcRunBtn.addEventListener( 'click', function () {
			var status = document.getElementById( 'blt-hc-status' );
			hcRunBtn.disabled = true;
			setMessage( status, cfg.i18n.scanning, false );

			post( 'blt_secure_health_run', {} ).then( function ( json ) {
				if ( json.success ) {
					window.location.reload();
				} else {
					hcRunBtn.disabled = false;
					setMessage( status, ( json.data && json.data.message ) || cfg.i18n.scanError, true );
				}
			} ).catch( function () {
				hcRunBtn.disabled = false;
				setMessage( status, cfg.i18n.scanError, true );
			} );
		} );
	}

	// Core scanner: run a scan, then reload to render the flagged files.
	var scanRunBtn = document.getElementById( 'blt-scan-run' );
	if ( scanRunBtn ) {
		scanRunBtn.addEventListener( 'click', function () {
			var status = document.getElementById( 'blt-scan-status' );
			scanRunBtn.disabled = true;
			setMessage( status, cfg.i18n.coreScan, false );

			post( 'blt_secure_core_scan_run', {} ).then( function ( json ) {
				if ( json.success ) {
					window.location.reload();
				} else {
					scanRunBtn.disabled = false;
					setMessage( status, ( json.data && json.data.message ) || cfg.i18n.scanError, true );
				}
			} ).catch( function () {
				scanRunBtn.disabled = false;
				setMessage( status, cfg.i18n.scanError, true );
			} );
		} );
	}

	// Malware scanner: run a scan, then reload to render the findings.
	var mwRunBtn = document.getElementById( 'blt-mw-run' );
	if ( mwRunBtn ) {
		mwRunBtn.addEventListener( 'click', function () {
			var status = document.getElementById( 'blt-mw-status' );
			mwRunBtn.disabled = true;
			setMessage( status, cfg.i18n.malScan, false );

			post( 'blt_secure_malware_scan_run', {} ).then( function ( json ) {
				if ( json.success ) {
					window.location.reload();
				} else {
					mwRunBtn.disabled = false;
					setMessage( status, ( json.data && json.data.message ) || cfg.i18n.scanError, true );
				}
			} ).catch( function () {
				mwRunBtn.disabled = false;
				setMessage( status, cfg.i18n.scanError, true );
			} );
		} );
	}

	// IOC feed sync (Advanced tab).
	var iocRunBtn = document.getElementById( 'blt-ioc-run' );
	if ( iocRunBtn ) {
		iocRunBtn.addEventListener( 'click', function () {
			var status = document.getElementById( 'blt-ioc-status' );
			iocRunBtn.disabled = true;
			setMessage( status, cfg.i18n.iocSync, false );

			post( 'blt_secure_ioc_sync_run', {} ).then( function ( json ) {
				if ( json.success ) {
					window.location.reload();
				} else {
					iocRunBtn.disabled = false;
					setMessage( status, ( json.data && json.data.message ) || cfg.i18n.scanError, true );
				}
			} ).catch( function () {
				iocRunBtn.disabled = false;
				setMessage( status, cfg.i18n.scanError, true );
			} );
		} );
	}

	// Timeline: poll Cloudflare, then reload to render the merged view.
	var tlRunBtn = document.getElementById( 'blt-tl-run' );
	if ( tlRunBtn ) {
		tlRunBtn.addEventListener( 'click', function () {
			var status = document.getElementById( 'blt-tl-status' );
			tlRunBtn.disabled = true;
			setMessage( status, cfg.i18n.polling, false );

			post( 'blt_secure_timeline_poll_run', {} ).then( function ( json ) {
				if ( json.success ) {
					window.location.reload();
				} else {
					tlRunBtn.disabled = false;
					setMessage( status, ( json.data && json.data.message ) || cfg.i18n.scanError, true );
				}
			} ).catch( function () {
				tlRunBtn.disabled = false;
				setMessage( status, cfg.i18n.scanError, true );
			} );
		} );
	}

	// Baseline integrity check.
	var blRunBtn = document.getElementById( 'blt-bl-run' );
	if ( blRunBtn ) {
		blRunBtn.addEventListener( 'click', function () {
			var status = document.getElementById( 'blt-bl-status' );
			blRunBtn.disabled = true;
			setMessage( status, cfg.i18n.baseScan, false );

			post( 'blt_secure_baseline_scan_run', {} ).then( function ( json ) {
				if ( json.success ) {
					window.location.reload();
				} else {
					blRunBtn.disabled = false;
					setMessage( status, ( json.data && json.data.message ) || cfg.i18n.scanError, true );
				}
			} ).catch( function () {
				blRunBtn.disabled = false;
				setMessage( status, cfg.i18n.scanError, true );
			} );
		} );
	}

	// Whitelist: ignore / restore scanner findings (event-delegated so it
	// works for every finding row across all three scanner sections).
	document.addEventListener( 'click', function ( event ) {
		var ignoreBtn = event.target.closest ? event.target.closest( '.blt-wl-ignore' ) : null;
		if ( ignoreBtn ) {
			event.preventDefault();
			var item = ignoreBtn.closest( 'li' );
			ignoreBtn.disabled = true;
			post( 'blt_secure_whitelist_add', {
				fingerprint: ignoreBtn.getAttribute( 'data-fp' ),
				scanner: ignoreBtn.getAttribute( 'data-scanner' ) || '',
				label: ignoreBtn.getAttribute( 'data-label' ) || ''
			} ).then( function ( json ) {
				if ( json.success && item ) {
					item.parentNode.removeChild( item );
				} else {
					ignoreBtn.disabled = false;
				}
			} ).catch( function () {
				ignoreBtn.disabled = false;
			} );
			return;
		}

		var restoreBtn = event.target.closest ? event.target.closest( '.blt-wl-restore' ) : null;
		if ( restoreBtn ) {
			event.preventDefault();
			var row = restoreBtn.closest( 'li' );
			restoreBtn.disabled = true;
			post( 'blt_secure_whitelist_remove', {
				fingerprint: restoreBtn.getAttribute( 'data-fp' )
			} ).then( function ( json ) {
				if ( json.success && row ) {
					row.parentNode.removeChild( row );
				} else {
					restoreBtn.disabled = false;
				}
			} ).catch( function () {
				restoreBtn.disabled = false;
			} );
		}
	} );

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
