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

	delete_option( 'blt_secure_settings' );
	delete_option( 'blt_secure_cf_state' );
	delete_option( 'blt_secure_events' );
	delete_option( 'blt_secure_cf_ips' );
	delete_option( 'blt_secure_crypto_check' );
	delete_option( 'blt_secure_cred_cf_token' );
	delete_option( 'blt_secure_cred_github_token' );
	delete_option( 'blt_secure_cred_slack_webhook' );
	delete_option( 'blt_secure_health_results' );
	delete_option( 'blt_secure_core_scan_results' );
	delete_option( 'blt_secure_malware_results' );
	delete_option( 'blt_secure_ioc_state' );
	delete_option( 'blt_secure_cf_events' );
	delete_option( 'blt_secure_baseline_results' );
	delete_option( 'blt_secure_baselines' );

	// plugin-update-checker state.
	delete_option( 'external_updates-blt-secure' );
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
}
