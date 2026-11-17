<?php
/**
 * Uninstall cleanup for BLT Secure.
 *
 * Deletes plugin options, user meta, and transients. Optionally removes the
 * Cloudflare rules this plugin deployed, but only when the site owner opted
 * in via the "Remove Cloudflare rules on uninstall" setting AND the stored
 * token still decrypts. Uninstall must never fatal.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

/**
 * Clean up ONE site (the current blog). On multisite it is run once per site.
 *
 * @return void
 */
function blt_secure_uninstall_site() {
	$blt_secure_settings = get_option( 'blt_secure_settings', array() );
	$blt_secure_advanced = isset( $blt_secure_settings['advanced'] ) && is_array( $blt_secure_settings['advanced'] )
		? $blt_secure_settings['advanced']
		: array();

	// Optional Cloudflare teardown — best-effort, opted in, never fatal.
	if ( ! empty( $blt_secure_advanced['remove_cf_on_uninstall'] ) ) {
		try {
			require_once __DIR__ . '/includes/crypto/class-crypto.php';
			require_once __DIR__ . '/includes/crypto/interface-credential-store.php';
			require_once __DIR__ . '/includes/crypto/class-encrypted-option-store.php';
			require_once __DIR__ . '/includes/cloudflare/class-cloudflare-api.php';
			require_once __DIR__ . '/includes/cloudflare/class-cloudflare-state.php';
			require_once __DIR__ . '/includes/cloudflare/rule-definitions.php';
			require_once __DIR__ . '/includes/cloudflare/class-cloudflare-deployer.php';

			$blt_secure_store = new Blt_Secure_Encrypted_Option_Store( new Blt_Secure_Crypto() );
			$blt_secure_token = $blt_secure_store->get( 'cf_token' );

			if ( is_string( $blt_secure_token ) && '' !== $blt_secure_token ) {
				$blt_secure_api      = new Blt_Secure_Cloudflare_Api( $blt_secure_token );
				$blt_secure_deployer = new Blt_Secure_Cloudflare_Deployer( $blt_secure_api, new Blt_Secure_Cloudflare_State() );
				$blt_secure_deployer->remove_all();
			}
		} catch ( Throwable $blt_secure_e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
			// Swallow everything: uninstall must complete regardless.
		}
	}

	// Delete data only if the site owner opted in (default: keep settings).
	if ( ! empty( $blt_secure_advanced['delete_data_on_uninstall'] ) ) {
		global $wpdb;

		$GLOBALS['blt_secure_purge_network'] = true;

		delete_option( 'blt_secure_settings' );
		delete_option( 'blt_secure_cf_state' );
		delete_option( 'blt_secure_events' );
		delete_option( 'blt_secure_cf_ips' );
		delete_option( 'blt_secure_crypto_check' );
		delete_option( 'blt_secure_cred_cf_token' );
		delete_option( 'blt_secure_cred_github_token' );
		delete_option( 'blt_secure_cred_slack_webhook' );
		delete_option( 'blt_secure_cred_fleet_token' );
		delete_option( 'blt_secure_crypto_invalid' );
		delete_option( 'blt_secure_fleet_cmd' );
		delete_option( 'blt_secure_fleet_state' );
		delete_option( 'blt_secure_health_results' );
		delete_option( 'blt_secure_health_fix_undo' );
		delete_option( 'blt_secure_core_scan_results' );
		delete_option( 'blt_secure_malware_results' );
		delete_option( 'blt_secure_malware_lock' );
		delete_option( 'blt_secure_ioc_state' );
		delete_option( 'blt_secure_feed_changelog' );
		delete_option( 'blt_secure_feed_snapshot' );
		delete_option( 'blt_secure_cf_events' );
		delete_option( 'blt_secure_baseline_results' );
		delete_option( 'blt_secure_baselines' );
		delete_option( 'blt_secure_baseline_events' );
		delete_option( 'blt_secure_scan_whitelist' );

		// plugin-update-checker cron (per site; its state is a network option,
		// removed once after the per-site loop).
		wp_clear_scheduled_hook( 'puc_cron_check_updates-blt-secure' );

		// Per-user 2FA data.
		delete_metadata( 'user', 0, '_blt_secure_totp_secret', '', true );
		delete_metadata( 'user', 0, '_blt_secure_totp_pending', '', true );
		delete_metadata( 'user', 0, '_blt_secure_totp_last_slice', '', true );
		delete_metadata( 'user', 0, '_blt_secure_recovery_codes', '', true );

		// Lockout + pending-2FA transients (options-table backed on most hosts).
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			"DELETE FROM {$wpdb->options}
			 WHERE option_name LIKE '\_transient\_blt\_sec\_%'
			    OR option_name LIKE '\_transient\_timeout\_blt\_sec\_%'"
		);

		wp_clear_scheduled_hook( 'blt_secure_refresh_cf_ips' );
		wp_clear_scheduled_hook( 'blt_secure_health_scan' );
		wp_clear_scheduled_hook( 'blt_secure_core_scan' );
		wp_clear_scheduled_hook( 'blt_secure_malware_scan' );
		wp_clear_scheduled_hook( 'blt_secure_ioc_sync' );
		wp_clear_scheduled_hook( 'blt_secure_timeline_poll' );
		wp_clear_scheduled_hook( 'blt_secure_baseline_scan' );
		wp_clear_scheduled_hook( 'blt_secure_fleet_report' );
		wp_clear_scheduled_hook( 'blt_secure_fleet_pull' );
		wp_clear_scheduled_hook( 'blt_secure_fleet_push' );
		wp_unschedule_hook( 'blt_secure_alert_deliver' ); // Queued deliveries carry args.
	}
}

if ( is_multisite() ) {
	// Options and cron are per-site: visit every site, not just the one the
	// uninstall happened to run on. The plugin-update-checker state is a
	// NETWORK option and is removed once, below.
	$blt_secure_site_ids = get_sites(
		array(
			'fields' => 'ids',
			'number' => 0,
		)
	);
	foreach ( $blt_secure_site_ids as $blt_secure_site_id ) {
		switch_to_blog( (int) $blt_secure_site_id );
		blt_secure_uninstall_site();
		restore_current_blog();
	}
} else {
	blt_secure_uninstall_site();
}

// plugin-update-checker stores its state with update_site_option() — on
// multisite that is a network option, which delete_option() does not touch.
// Removed once, and only if at least one site opted in to data removal.
if ( ! empty( $GLOBALS['blt_secure_purge_network'] ) ) {
	delete_site_option( 'external_updates-blt-secure' );
}
