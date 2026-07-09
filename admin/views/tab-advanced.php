<?php
/**
 * Advanced tab: IP trust, uninstall behavior, recent events.
 *
 * @var Blt_Secure_Options $options Settings.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$blt_secure_advanced = $options->section( 'advanced' );
$blt_secure_opt      = Blt_Secure_Options::OPTION;
$blt_secure_events   = get_option( 'blt_secure_events', array() );
$blt_secure_events   = is_array( $blt_secure_events ) ? array_slice( array_reverse( $blt_secure_events ), 0, 20 ) : array();
?>
<form method="post" action="options.php" class="blt-settings">
	<?php settings_fields( 'blt_secure' ); ?>

	<div class="blt-section">
		<h2><?php esc_html_e( 'Client IP detection', 'blt-secure' ); ?></h2>
		<?php
		blt_secure_setting_open(
			__( 'Trust CF-Connecting-IP', 'blt-secure' ),
			__( 'Affects the failed-login lockout: with the wrong setting behind a proxy, one attacker could lock out everyone (or no one).', 'blt-secure' )
		);
		blt_secure_setting_control();
		?>
			<select id="blt-trust-cf" name="<?php echo esc_attr( $blt_secure_opt ); ?>[advanced][trust_cf_header]">
				<option value="auto" <?php selected( $blt_secure_advanced['trust_cf_header'], 'auto' ); ?>><?php esc_html_e( 'Auto (recommended)', 'blt-secure' ); ?></option>
				<option value="always" <?php selected( $blt_secure_advanced['trust_cf_header'], 'always' ); ?>><?php esc_html_e( 'Always', 'blt-secure' ); ?></option>
				<option value="never" <?php selected( $blt_secure_advanced['trust_cf_header'], 'never' ); ?>><?php esc_html_e( 'Never (use REMOTE_ADDR)', 'blt-secure' ); ?></option>
			</select>
		<?php
		blt_secure_setting_close();
		?>
	</div>

	<div class="blt-section">
		<h2><?php esc_html_e( 'Uninstall behavior', 'blt-secure' ); ?></h2>
		<?php
		blt_secure_setting_open( __( 'Delete all data on uninstall', 'blt-secure' ), __( 'Remove all plugin settings and user 2FA data when the plugin is uninstalled.', 'blt-secure' ) );
		blt_secure_setting_control();
		blt_secure_toggle( $blt_secure_opt . '[advanced][delete_data_on_uninstall]', ! empty( $blt_secure_advanced['delete_data_on_uninstall'] ) );
		blt_secure_setting_close();

		blt_secure_setting_open( __( 'Remove Cloudflare rules on uninstall', 'blt-secure' ), __( 'Best-effort removal of the Cloudflare rules this plugin deployed (requires the stored token to still work). Deactivating never touches Cloudflare — removal is always explicit.', 'blt-secure' ) );
		blt_secure_setting_control();
		blt_secure_toggle( $blt_secure_opt . '[advanced][remove_cf_on_uninstall]', ! empty( $blt_secure_advanced['remove_cf_on_uninstall'] ) );
		blt_secure_setting_close();
		?>
	</div>

	<?php $blt_secure_alerts = $options->section( 'alerts' ); ?>
	<div class="blt-section">
		<h2><?php esc_html_e( 'Alert notifications', 'blt-secure' ); ?></h2>
		<p class="blt-section-desc"><?php esc_html_e( 'Get notified when a high-signal security event occurs (lockouts, blocked uploads, malware or integrity findings, a new administrator). Notifications of the same type are throttled to avoid floods.', 'blt-secure' ); ?></p>
		<?php
		blt_secure_setting_open( __( 'Email notifications', 'blt-secure' ), __( 'Send alerts by email.', 'blt-secure' ) );
		blt_secure_setting_control();
		blt_secure_toggle( $blt_secure_opt . '[alerts][email_enabled]', ! empty( $blt_secure_alerts['email_enabled'] ) );
		blt_secure_setting_close();
		?>
		<div class="blt-setting">
			<div class="blt-setting-info">
				<div class="blt-setting-title"><?php esc_html_e( 'Notification email', 'blt-secure' ); ?></div>
				<p class="blt-setting-desc"><?php esc_html_e( 'Where to send email alerts. Leave blank to use the site admin email.', 'blt-secure' ); ?></p>
			</div>
			<div class="blt-setting-control">
				<input type="email" name="<?php echo esc_attr( $blt_secure_opt ); ?>[alerts][email_to]" value="<?php echo esc_attr( isset( $blt_secure_alerts['email_to'] ) ? $blt_secure_alerts['email_to'] : '' ); ?>" class="regular-text" placeholder="<?php echo esc_attr( (string) get_option( 'admin_email' ) ); ?>" />
			</div>
		</div>
		<?php
		blt_secure_setting_open( __( 'Slack notifications', 'blt-secure' ), __( 'Post alerts to a Slack channel via an incoming webhook (configured below).', 'blt-secure' ) );
		blt_secure_setting_control();
		blt_secure_toggle( $blt_secure_opt . '[alerts][slack_enabled]', ! empty( $blt_secure_alerts['slack_enabled'] ) );
		blt_secure_setting_close();
		?>
	</div>

	<?php $blt_secure_fleet = $options->section( 'fleet' ); ?>
	<div class="blt-section">
		<h2><?php esc_html_e( 'Fleet reporting', 'blt-secure' ); ?></h2>
		<p class="blt-section-desc"><?php esc_html_e( 'Push a compact security-posture snapshot (scores, counts, statuses, versions — never secrets or file contents) to your BLT Secure fleet dashboard. Off by default.', 'blt-secure' ); ?></p>
		<?php
		blt_secure_setting_open( __( 'Enable fleet reporting', 'blt-secure' ), __( 'Send a daily snapshot and an immediate push when a high-signal event occurs.', 'blt-secure' ) );
		blt_secure_setting_control();
		blt_secure_toggle( $blt_secure_opt . '[fleet][enabled]', ! empty( $blt_secure_fleet['enabled'] ) );
		blt_secure_setting_close();
		?>
		<div class="blt-setting">
			<div class="blt-setting-info">
				<div class="blt-setting-title"><?php esc_html_e( 'Dashboard endpoint', 'blt-secure' ); ?></div>
				<p class="blt-setting-desc"><?php esc_html_e( 'The base URL of your fleet dashboard Worker (e.g. https://fleet.example.com).', 'blt-secure' ); ?></p>
			</div>
			<div class="blt-setting-control">
				<input type="url" name="<?php echo esc_attr( $blt_secure_opt ); ?>[fleet][endpoint]" value="<?php echo esc_attr( isset( $blt_secure_fleet['endpoint'] ) ? $blt_secure_fleet['endpoint'] : '' ); ?>" class="regular-text" placeholder="https://fleet.example.com" />
			</div>
		</div>
	</div>

	<?php submit_button(); ?>
</form>

<div class="blt-section">
	<h2><?php esc_html_e( 'Fleet enrollment', 'blt-secure' ); ?></h2>
	<div class="blt-setting">
		<div class="blt-setting-info">
			<div class="blt-setting-title"><?php esc_html_e( 'Enrollment token', 'blt-secure' ); ?></div>
			<?php if ( is_string( $store->get( Blt_Secure_Fleet::TOKEN_KEY ) ) ) : ?>
				<p id="blt-fleet-status" class="blt-setting-desc">
					<span class="blt-badge blt-badge-ok">✓</span>
					<?php esc_html_e( 'An enrollment token is stored encrypted.', 'blt-secure' ); ?>
				</p>
				<p>
					<button type="button" class="button button-primary" id="blt-fleet-report"><?php esc_html_e( 'Send report now', 'blt-secure' ); ?></button>
					<button type="button" class="button" id="blt-fleet-disconnect"><?php esc_html_e( 'Remove token', 'blt-secure' ); ?></button>
					<span id="blt-fleet-msg" class="blt-card-message"></span>
				</p>
			<?php else : ?>
				<p>
					<input type="password" id="blt-fleet-token" class="regular-text" autocomplete="off" placeholder="<?php esc_attr_e( 'paste enrollment token', 'blt-secure' ); ?>" />
					<button type="button" class="button" id="blt-fleet-connect"><?php esc_html_e( 'Save token', 'blt-secure' ); ?></button>
				</p>
				<p id="blt-fleet-status" class="blt-setting-desc"></p>
				<p class="blt-setting-desc"><?php esc_html_e( 'Generate an enrollment token for this site in your fleet dashboard and paste it here. It is stored encrypted and used to authenticate reports.', 'blt-secure' ); ?></p>
			<?php endif; ?>
		</div>
	</div>
</div>

<div class="blt-section">
	<h2><?php esc_html_e( 'Slack webhook', 'blt-secure' ); ?></h2>
	<div class="blt-setting">
		<div class="blt-setting-info">
			<div class="blt-setting-title"><?php esc_html_e( 'Incoming webhook URL', 'blt-secure' ); ?></div>
			<?php if ( is_string( $store->get( 'slack_webhook' ) ) ) : ?>
				<p id="blt-slack-status" class="blt-setting-desc">
					<span class="blt-badge blt-badge-ok">✓</span>
					<?php esc_html_e( 'A Slack webhook is stored encrypted. Enable "Slack notifications" above to use it.', 'blt-secure' ); ?>
				</p>
				<p><button type="button" class="button" id="blt-slack-disconnect"><?php esc_html_e( 'Remove webhook', 'blt-secure' ); ?></button></p>
			<?php else : ?>
				<p>
					<input type="url" id="blt-slack-webhook" class="regular-text" autocomplete="off" placeholder="https://hooks.slack.com/services/…" />
					<button type="button" class="button" id="blt-slack-connect"><?php esc_html_e( 'Verify & save', 'blt-secure' ); ?></button>
				</p>
				<p id="blt-slack-status" class="blt-setting-desc"></p>
				<p class="blt-setting-desc"><?php esc_html_e( 'Create an incoming webhook in your Slack workspace (Apps → Incoming Webhooks) and paste the URL here. A test message is sent when you save; the URL is stored encrypted.', 'blt-secure' ); ?></p>
			<?php endif; ?>
		</div>
	</div>
</div>

<div class="blt-section">
	<h2><?php esc_html_e( 'Plugin updates', 'blt-secure' ); ?></h2>
	<div class="blt-setting">
		<div class="blt-setting-info">
			<div class="blt-setting-title"><?php esc_html_e( 'GitHub access token', 'blt-secure' ); ?></div>
			<?php $blt_secure_repo_public = Blt_Secure_Updater::repo_public(); ?>
			<?php if ( defined( 'BLT_SECURE_GITHUB_TOKEN' ) && BLT_SECURE_GITHUB_TOKEN ) : ?>
				<p class="blt-setting-desc">
					<span class="blt-badge blt-badge-ok">✓</span>
					<?php esc_html_e( 'The token is provided by the BLT_SECURE_GITHUB_TOKEN constant in wp-config.php.', 'blt-secure' ); ?>
				</p>
			<?php elseif ( is_string( $store->get( Blt_Secure_Updater::TOKEN_KEY ) ) ) : ?>
				<p id="blt-gh-status" class="blt-setting-desc">
					<span class="blt-badge blt-badge-ok">✓</span>
					<?php esc_html_e( 'A token is stored encrypted and used for update checks.', 'blt-secure' ); ?>
				</p>
				<p><button type="button" class="button" id="blt-gh-disconnect"><?php esc_html_e( 'Remove token', 'blt-secure' ); ?></button></p>
			<?php else : ?>
				<?php if ( $blt_secure_repo_public ) : ?>
					<p id="blt-gh-status-public" class="blt-setting-desc">
						<span class="blt-badge blt-badge-ok">✓</span>
						<?php esc_html_e( 'Updates are enabled automatically — the plugin repository is public, so no token is required.', 'blt-secure' ); ?>
					</p>
				<?php endif; ?>
				<p>
					<input type="password" id="blt-gh-token" class="regular-text" autocomplete="off" placeholder="<?php esc_attr_e( 'github_pat_…', 'blt-secure' ); ?>" />
					<button type="button" class="button" id="blt-gh-connect"><?php esc_html_e( 'Verify & save', 'blt-secure' ); ?></button>
				</p>
				<p id="blt-gh-status" class="blt-setting-desc"></p>
				<p class="blt-setting-desc">
					<?php
					if ( $blt_secure_repo_public ) {
						esc_html_e( 'A token is optional: add one only to raise the GitHub API rate limit on hosts that share an outbound IP, or if the repository is later made private. Create a fine-grained personal access token with read-only Contents permission on S-FX-com/BLT-Secure (or a classic token with the repo scope). The token is stored encrypted. Alternatively, define BLT_SECURE_GITHUB_TOKEN in wp-config.php.', 'blt-secure' );
					} else {
						esc_html_e( 'BLT Secure updates itself from a private GitHub repository, which requires a token. Create a fine-grained personal access token with read-only Contents permission on S-FX-com/BLT-Secure (or a classic token with the repo scope). The token is stored encrypted. Alternatively, define BLT_SECURE_GITHUB_TOKEN in wp-config.php.', 'blt-secure' );
					}
					?>
				</p>
			<?php endif; ?>
		</div>
	</div>
</div>

<div class="blt-section">
	<h2><?php esc_html_e( 'Threat-intel blocklist (Cloudflare)', 'blt-secure' ); ?></h2>
	<div class="blt-setting">
		<div class="blt-setting-info">
			<div class="blt-setting-title"><?php esc_html_e( 'IOC feed sync', 'blt-secure' ); ?></div>
			<?php
			$blt_secure_ioc_state  = $ioc ? $ioc->latest() : null;
			$blt_secure_ioc_status = is_array( $blt_secure_ioc_state ) && isset( $blt_secure_ioc_state['status'] ) ? $blt_secure_ioc_state['status'] : '';
			$blt_secure_ioc_msg    = '';
			switch ( $blt_secure_ioc_status ) {
				case 'ok':
					$blt_secure_ioc_msg = sprintf(
						/* translators: 1: number of indicators, 2: human time diff */
						__( '%1$d indicators synced to the Cloudflare IP List %2$s ago.', 'blt-secure' ),
						isset( $blt_secure_ioc_state['count'] ) ? (int) $blt_secure_ioc_state['count'] : 0,
						human_time_diff( (int) $blt_secure_ioc_state['time'], time() )
					);
					break;
				case 'no_token':
					$blt_secure_ioc_msg = __( 'Connect a Cloudflare token on the Cloudflare tab to enable edge blocking.', 'blt-secure' );
					break;
				case 'no_feeds':
					$blt_secure_ioc_msg = __( 'No threat-intel feeds are enabled. Enable an ip-list or ioc-json feed in feeds/feeds.json.', 'blt-secure' );
					break;
				case 'empty':
					$blt_secure_ioc_msg = __( 'The enabled feeds returned no usable indicators.', 'blt-secure' );
					break;
				case 'error':
					$blt_secure_ioc_msg = isset( $blt_secure_ioc_state['error'] ) ? $blt_secure_ioc_state['error'] : __( 'The last sync failed.', 'blt-secure' );
					break;
				default:
					$blt_secure_ioc_msg = __( 'No sync has run yet. Enable feeds and connect Cloudflare, then sync.', 'blt-secure' );
			}
			?>
			<p class="blt-setting-desc">
				<?php if ( 'ok' === $blt_secure_ioc_status ) : ?>
					<span class="blt-badge blt-badge-ok">✓</span>
				<?php endif; ?>
				<?php echo esc_html( $blt_secure_ioc_msg ); ?>
			</p>
			<p class="blt-setting-desc">
				<?php esc_html_e( 'Pulls the enabled abuse.ch / Spamhaus-style feeds and blocks their IPs at the Cloudflare edge. Requires the token to also carry Account → Account Filter Lists: Edit.', 'blt-secure' ); ?>
			</p>
			<p>
				<button type="button" class="button" id="blt-ioc-run"><?php esc_html_e( 'Sync now', 'blt-secure' ); ?></button>
				<span id="blt-ioc-status" class="blt-card-message"></span>
			</p>
			<?php
			$blt_secure_changelog = ( new Blt_Secure_Feed_Changelog() )->entries( 10 );
			if ( ! empty( $blt_secure_changelog ) ) :
				?>
				<p class="blt-setting-title" style="margin-top:16px;"><?php esc_html_e( 'Recent feed changes', 'blt-secure' ); ?></p>
				<ul class="blt-hc-list">
					<?php foreach ( $blt_secure_changelog as $blt_secure_cl ) : ?>
						<li class="blt-hc-item blt-hc-skip">
							<span class="blt-hc-body">
								<span class="blt-hc-title"><?php echo esc_html( wp_date( 'Y-m-d H:i', (int) $blt_secure_cl['time'] ) ); ?></span>
								<span class="blt-hc-msg">
									<?php
									printf(
										/* translators: 1: total, 2: added, 3: removed */
										esc_html__( '%1$d indicators (+%2$d / −%3$d since last refresh)', 'blt-secure' ),
										(int) $blt_secure_cl['total'],
										(int) $blt_secure_cl['added'],
										(int) $blt_secure_cl['removed']
									);
									?>
								</span>
							</span>
						</li>
					<?php endforeach; ?>
				</ul>
			<?php endif; ?>
		</div>
	</div>
</div>

<h2><?php esc_html_e( 'Recent security events', 'blt-secure' ); ?></h2>
<?php if ( empty( $blt_secure_events ) ) : ?>
	<p class="description"><?php esc_html_e( 'No events recorded yet.', 'blt-secure' ); ?></p>
<?php else : ?>
	<table class="widefat striped" style="max-width:900px;">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Time', 'blt-secure' ); ?></th>
				<th><?php esc_html_e( 'Event', 'blt-secure' ); ?></th>
				<th><?php esc_html_e( 'Details', 'blt-secure' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $blt_secure_events as $blt_secure_event ) : ?>
				<tr>
					<td><?php echo esc_html( wp_date( 'Y-m-d H:i:s', isset( $blt_secure_event['time'] ) ? (int) $blt_secure_event['time'] : 0 ) ); ?></td>
					<td><code><?php echo esc_html( isset( $blt_secure_event['type'] ) ? $blt_secure_event['type'] : '' ); ?></code></td>
					<td><code><?php echo esc_html( wp_json_encode( isset( $blt_secure_event['context'] ) ? $blt_secure_event['context'] : array() ) ); ?></code></td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>
<?php endif; ?>
