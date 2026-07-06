<?php
/**
 * Hardening tab: headers, privacy, XML-RPC, file guard.
 *
 * @var Blt_Secure_Options $options Settings.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$blt_headers   = $options->section( 'headers' );
$blt_privacy   = $options->section( 'privacy' );
$blt_xmlrpc    = $options->section( 'xmlrpc' );
$blt_fileguard = $options->section( 'fileguard' );
$blt_opt       = Blt_Secure_Options::OPTION;
?>
<form method="post" action="options.php">
	<?php settings_fields( 'blt_secure' ); ?>

	<h2><?php esc_html_e( 'Security headers', 'blt-secure' ); ?></h2>
	<table class="form-table" role="presentation">
		<tr>
			<th scope="row"><?php esc_html_e( 'Send security headers', 'blt-secure' ); ?></th>
			<td>
				<label><input type="checkbox" name="<?php echo esc_attr( $blt_opt ); ?>[headers][enabled]" value="1" <?php checked( $blt_headers['enabled'] ); ?> />
				<?php esc_html_e( 'Enable this module (headers already sent by your host or Cloudflare are never duplicated)', 'blt-secure' ); ?></label>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'HSTS', 'blt-secure' ); ?></th>
			<td>
				<label><input type="checkbox" name="<?php echo esc_attr( $blt_opt ); ?>[headers][hsts]" value="1" <?php checked( $blt_headers['hsts'] ); ?> />
				<?php esc_html_e( 'Strict-Transport-Security (sent only over HTTPS)', 'blt-secure' ); ?></label><br />
				<label><?php esc_html_e( 'max-age (seconds):', 'blt-secure' ); ?>
					<input type="number" name="<?php echo esc_attr( $blt_opt ); ?>[headers][hsts_max_age]" value="<?php echo esc_attr( $blt_headers['hsts_max_age'] ); ?>" class="small-text" style="width:110px;" /></label><br />
				<label><input type="checkbox" name="<?php echo esc_attr( $blt_opt ); ?>[headers][hsts_subdomains]" value="1" <?php checked( $blt_headers['hsts_subdomains'] ); ?> />
				<?php esc_html_e( 'includeSubDomains', 'blt-secure' ); ?></label><br />
				<label><input type="checkbox" name="<?php echo esc_attr( $blt_opt ); ?>[headers][hsts_preload]" value="1" <?php checked( $blt_headers['hsts_preload'] ); ?> />
				<?php esc_html_e( 'preload — effectively irreversible; only enable if you know what this means', 'blt-secure' ); ?></label>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="blt-x-frame"><?php esc_html_e( 'X-Frame-Options', 'blt-secure' ); ?></label></th>
			<td>
				<select id="blt-x-frame" name="<?php echo esc_attr( $blt_opt ); ?>[headers][x_frame]">
					<option value="SAMEORIGIN" <?php selected( $blt_headers['x_frame'], 'SAMEORIGIN' ); ?>>SAMEORIGIN</option>
					<option value="DENY" <?php selected( $blt_headers['x_frame'], 'DENY' ); ?>>DENY</option>
					<option value="" <?php selected( $blt_headers['x_frame'], '' ); ?>><?php esc_html_e( 'Off', 'blt-secure' ); ?></option>
				</select>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Other headers', 'blt-secure' ); ?></th>
			<td>
				<label><input type="checkbox" name="<?php echo esc_attr( $blt_opt ); ?>[headers][nosniff]" value="1" <?php checked( $blt_headers['nosniff'] ); ?> />
				<code>X-Content-Type-Options: nosniff</code></label><br />
				<label for="blt-referrer"><?php esc_html_e( 'Referrer-Policy:', 'blt-secure' ); ?></label>
				<select id="blt-referrer" name="<?php echo esc_attr( $blt_opt ); ?>[headers][referrer_policy]">
					<?php foreach ( array( 'strict-origin-when-cross-origin', 'strict-origin', 'same-origin', 'no-referrer', 'no-referrer-when-downgrade', '' ) as $blt_rp ) : ?>
						<option value="<?php echo esc_attr( $blt_rp ); ?>" <?php selected( $blt_headers['referrer_policy'], $blt_rp ); ?>>
							<?php echo '' === $blt_rp ? esc_html__( 'Off', 'blt-secure' ) : esc_html( $blt_rp ); ?>
						</option>
					<?php endforeach; ?>
				</select>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Content-Security-Policy', 'blt-secure' ); ?></th>
			<td>
				<label><input type="checkbox" name="<?php echo esc_attr( $blt_opt ); ?>[headers][csp_enabled]" value="1" <?php checked( $blt_headers['csp_enabled'] ); ?> />
				<?php esc_html_e( 'Send CSP on the front-end (never sent inside wp-admin)', 'blt-secure' ); ?></label><br />
				<label><input type="checkbox" name="<?php echo esc_attr( $blt_opt ); ?>[headers][csp_report_only]" value="1" <?php checked( $blt_headers['csp_report_only'] ); ?> />
				<strong><?php esc_html_e( 'Report-Only mode', 'blt-secure' ); ?></strong> —
				<?php esc_html_e( 'watch your browser console for violations before enforcing', 'blt-secure' ); ?></label>
				<textarea name="<?php echo esc_attr( $blt_opt ); ?>[headers][csp_policy]" rows="4" class="large-text code"><?php echo esc_textarea( $blt_headers['csp_policy'] ); ?></textarea>
			</td>
		</tr>
	</table>

	<h2><?php esc_html_e( 'Privacy', 'blt-secure' ); ?></h2>
	<table class="form-table" role="presentation">
		<tr>
			<th scope="row"><?php esc_html_e( 'Fingerprinting', 'blt-secure' ); ?></th>
			<td>
				<label><input type="checkbox" name="<?php echo esc_attr( $blt_opt ); ?>[privacy][hide_version]" value="1" <?php checked( $blt_privacy['hide_version'] ); ?> />
				<?php esc_html_e( 'Hide the WordPress version (generator tag and core asset ?ver=)', 'blt-secure' ); ?></label><br />
				<label><input type="checkbox" name="<?php echo esc_attr( $blt_opt ); ?>[privacy][block_enum]" value="1" <?php checked( $blt_privacy['block_enum'] ); ?> />
				<?php esc_html_e( 'Block user enumeration (?author=N and the REST users endpoint for visitors)', 'blt-secure' ); ?></label>
			</td>
		</tr>
	</table>

	<h2><?php esc_html_e( 'XML-RPC', 'blt-secure' ); ?></h2>
	<table class="form-table" role="presentation">
		<tr>
			<th scope="row"><?php esc_html_e( 'XML-RPC services', 'blt-secure' ); ?></th>
			<td>
				<label><input type="checkbox" name="<?php echo esc_attr( $blt_opt ); ?>[xmlrpc][enabled]" value="1" <?php checked( $blt_xmlrpc['enabled'] ); ?> />
				<?php esc_html_e( 'Allow XML-RPC (needed by Jetpack and the WordPress mobile apps; leave off otherwise)', 'blt-secure' ); ?></label>
			</td>
		</tr>
	</table>

	<h2><?php esc_html_e( 'File guard', 'blt-secure' ); ?></h2>
	<table class="form-table" role="presentation">
		<tr>
			<th scope="row"><?php esc_html_e( 'File editing', 'blt-secure' ); ?></th>
			<td>
				<?php if ( defined( 'DISALLOW_FILE_EDIT' ) ) : ?>
					<p>
						<code>DISALLOW_FILE_EDIT</code>
						<?php echo DISALLOW_FILE_EDIT ? esc_html__( 'is already enabled in wp-config.php — nothing to do here.', 'blt-secure' ) : esc_html__( 'is explicitly disabled in wp-config.php, which overrides this setting.', 'blt-secure' ); ?>
					</p>
				<?php else : ?>
					<label><input type="checkbox" name="<?php echo esc_attr( $blt_opt ); ?>[fileguard][disallow_file_edit]" value="1" <?php checked( $blt_fileguard['disallow_file_edit'] ); ?> />
					<?php esc_html_e( 'Disable the theme/plugin file editors in wp-admin', 'blt-secure' ); ?></label>
				<?php endif; ?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'File-manager plugins', 'blt-secure' ); ?></th>
			<td>
				<label><input type="checkbox" name="<?php echo esc_attr( $blt_opt ); ?>[fileguard][block_file_managers]" value="1" <?php checked( $blt_fileguard['block_file_managers'] ); ?> />
				<?php esc_html_e( 'Block installation and activation of file-manager plugins (a common compromise vector)', 'blt-secure' ); ?></label>
			</td>
		</tr>
	</table>

	<?php submit_button(); ?>
</form>
