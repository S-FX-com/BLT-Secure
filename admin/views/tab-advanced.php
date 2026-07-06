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

$blt_advanced = $options->section( 'advanced' );
$blt_opt      = Blt_Secure_Options::OPTION;
$blt_events   = get_option( 'blt_secure_events', array() );
$blt_events   = is_array( $blt_events ) ? array_slice( array_reverse( $blt_events ), 0, 20 ) : array();
?>
<form method="post" action="options.php">
	<?php settings_fields( 'blt_secure' ); ?>

	<h2><?php esc_html_e( 'Client IP detection', 'blt-secure' ); ?></h2>
	<table class="form-table" role="presentation">
		<tr>
			<th scope="row"><label for="blt-trust-cf"><?php esc_html_e( 'Trust CF-Connecting-IP', 'blt-secure' ); ?></label></th>
			<td>
				<select id="blt-trust-cf" name="<?php echo esc_attr( $blt_opt ); ?>[advanced][trust_cf_header]">
					<option value="auto" <?php selected( $blt_advanced['trust_cf_header'], 'auto' ); ?>><?php esc_html_e( 'Auto — only when the request comes from Cloudflare’s published IP ranges (recommended)', 'blt-secure' ); ?></option>
					<option value="always" <?php selected( $blt_advanced['trust_cf_header'], 'always' ); ?>><?php esc_html_e( 'Always (only if Cloudflare fronts every request)', 'blt-secure' ); ?></option>
					<option value="never" <?php selected( $blt_advanced['trust_cf_header'], 'never' ); ?>><?php esc_html_e( 'Never (use REMOTE_ADDR)', 'blt-secure' ); ?></option>
				</select>
				<p class="description"><?php esc_html_e( 'Affects the failed-login lockout: with the wrong setting behind a proxy, one attacker could lock out everyone (or no one).', 'blt-secure' ); ?></p>
			</td>
		</tr>
	</table>

	<h2><?php esc_html_e( 'Uninstall behavior', 'blt-secure' ); ?></h2>
	<table class="form-table" role="presentation">
		<tr>
			<th scope="row"><?php esc_html_e( 'On uninstall', 'blt-secure' ); ?></th>
			<td>
				<label><input type="checkbox" name="<?php echo esc_attr( $blt_opt ); ?>[advanced][delete_data_on_uninstall]" value="1" <?php checked( $blt_advanced['delete_data_on_uninstall'] ); ?> />
				<?php esc_html_e( 'Delete all plugin settings and user 2FA data when the plugin is uninstalled', 'blt-secure' ); ?></label><br />
				<label><input type="checkbox" name="<?php echo esc_attr( $blt_opt ); ?>[advanced][remove_cf_on_uninstall]" value="1" <?php checked( $blt_advanced['remove_cf_on_uninstall'] ); ?> />
				<?php esc_html_e( 'Also remove the Cloudflare rules this plugin deployed (best-effort; requires the stored token to still work)', 'blt-secure' ); ?></label>
				<p class="description"><?php esc_html_e( 'Deactivating the plugin never touches Cloudflare — removal is always an explicit action.', 'blt-secure' ); ?></p>
			</td>
		</tr>
	</table>

	<?php submit_button(); ?>
</form>

<h2><?php esc_html_e( 'Recent security events', 'blt-secure' ); ?></h2>
<?php if ( empty( $blt_events ) ) : ?>
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
			<?php foreach ( $blt_events as $blt_event ) : ?>
				<tr>
					<td><?php echo esc_html( wp_date( 'Y-m-d H:i:s', isset( $blt_event['time'] ) ? (int) $blt_event['time'] : 0 ) ); ?></td>
					<td><code><?php echo esc_html( isset( $blt_event['type'] ) ? $blt_event['type'] : '' ); ?></code></td>
					<td><code><?php echo esc_html( wp_json_encode( isset( $blt_event['context'] ) ? $blt_event['context'] : array() ) ); ?></code></td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>
<?php endif; ?>
