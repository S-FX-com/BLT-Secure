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

$blt_secure_headers   = $options->section( 'headers' );
$blt_secure_privacy   = $options->section( 'privacy' );
$blt_secure_xmlrpc    = $options->section( 'xmlrpc' );
$blt_secure_fileguard = $options->section( 'fileguard' );
$blt_secure_opt       = Blt_Secure_Options::OPTION;
?>
<form method="post" action="options.php" class="blt-settings">
	<?php settings_fields( 'blt_secure' ); ?>

	<div class="blt-section">
		<h2><?php esc_html_e( 'Security headers', 'blt-secure' ); ?></h2>

		<?php
		blt_secure_setting_open(
			__( 'Send security headers', 'blt-secure' ),
			__( 'Emit hardening headers on the front-end and login pages. Headers already sent by your host or Cloudflare are never duplicated.', 'blt-secure' )
		);
		blt_secure_setting_control();
		blt_secure_toggle( $blt_secure_opt . '[headers][enabled]', ! empty( $blt_secure_headers['enabled'] ) );
		blt_secure_setting_close();
		?>

		<div class="blt-setting">
			<div class="blt-setting-info">
				<div class="blt-setting-title"><?php esc_html_e( 'HTTP Strict Transport Security (HSTS)', 'blt-secure' ); ?></div>
				<p class="blt-setting-desc"><?php esc_html_e( 'Tells browsers to only ever connect over HTTPS. Sent only on secure requests.', 'blt-secure' ); ?></p>
				<div class="blt-subfields">
					<label><?php esc_html_e( 'max-age (seconds):', 'blt-secure' ); ?>
						<input type="number" name="<?php echo esc_attr( $blt_secure_opt ); ?>[headers][hsts_max_age]" value="<?php echo esc_attr( $blt_secure_headers['hsts_max_age'] ); ?>" class="small-text" style="width:120px;" /></label>
					<label><input type="checkbox" name="<?php echo esc_attr( $blt_secure_opt ); ?>[headers][hsts_subdomains]" value="1" <?php checked( $blt_secure_headers['hsts_subdomains'] ); ?> />
					<?php esc_html_e( 'includeSubDomains', 'blt-secure' ); ?></label>
					<label><input type="checkbox" name="<?php echo esc_attr( $blt_secure_opt ); ?>[headers][hsts_preload]" value="1" <?php checked( $blt_secure_headers['hsts_preload'] ); ?> />
					<?php esc_html_e( 'preload — effectively irreversible; only enable if you know what this means', 'blt-secure' ); ?></label>
				</div>
			</div>
			<div class="blt-setting-control">
				<?php blt_secure_toggle( $blt_secure_opt . '[headers][hsts]', ! empty( $blt_secure_headers['hsts'] ) ); ?>
			</div>
		</div>

		<?php
		blt_secure_setting_open( __( 'X-Frame-Options', 'blt-secure' ), __( 'Controls whether other sites may embed your pages in a frame (clickjacking defense).', 'blt-secure' ) );
		blt_secure_setting_control();
		?>
			<select name="<?php echo esc_attr( $blt_secure_opt ); ?>[headers][x_frame]">
				<option value="SAMEORIGIN" <?php selected( $blt_secure_headers['x_frame'], 'SAMEORIGIN' ); ?>>SAMEORIGIN</option>
				<option value="DENY" <?php selected( $blt_secure_headers['x_frame'], 'DENY' ); ?>>DENY</option>
				<option value="" <?php selected( $blt_secure_headers['x_frame'], '' ); ?>><?php esc_html_e( 'Off', 'blt-secure' ); ?></option>
			</select>
		<?php
		blt_secure_setting_close();

		blt_secure_setting_open( __( 'X-Content-Type-Options', 'blt-secure' ), __( 'Sends "nosniff" so browsers do not guess (and mis-execute) a file’s content type.', 'blt-secure' ) );
		blt_secure_setting_control();
		blt_secure_toggle( $blt_secure_opt . '[headers][nosniff]', ! empty( $blt_secure_headers['nosniff'] ) );
		blt_secure_setting_close();

		blt_secure_setting_open( __( 'Referrer-Policy', 'blt-secure' ), __( 'Controls how much referrer information is shared when visitors follow links off your site.', 'blt-secure' ) );
		blt_secure_setting_control();
		?>
			<select name="<?php echo esc_attr( $blt_secure_opt ); ?>[headers][referrer_policy]">
				<?php foreach ( array( 'strict-origin-when-cross-origin', 'strict-origin', 'same-origin', 'no-referrer', 'no-referrer-when-downgrade', '' ) as $blt_secure_rp ) : ?>
					<option value="<?php echo esc_attr( $blt_secure_rp ); ?>" <?php selected( $blt_secure_headers['referrer_policy'], $blt_secure_rp ); ?>>
						<?php echo '' === $blt_secure_rp ? esc_html__( 'Off', 'blt-secure' ) : esc_html( $blt_secure_rp ); ?>
					</option>
				<?php endforeach; ?>
			</select>
		<?php
		blt_secure_setting_close();
		?>

		<div class="blt-setting">
			<div class="blt-setting-info">
				<div class="blt-setting-title"><?php esc_html_e( 'Content-Security-Policy', 'blt-secure' ); ?></div>
				<p class="blt-setting-desc"><?php esc_html_e( 'The strongest defense against cross-site scripting. Never sent inside wp-admin. Start in Report-Only mode and watch the browser console before enforcing.', 'blt-secure' ); ?></p>
				<div class="blt-subfields">
					<label><input type="checkbox" name="<?php echo esc_attr( $blt_secure_opt ); ?>[headers][csp_report_only]" value="1" <?php checked( $blt_secure_headers['csp_report_only'] ); ?> />
					<strong><?php esc_html_e( 'Report-Only mode', 'blt-secure' ); ?></strong></label>
					<textarea name="<?php echo esc_attr( $blt_secure_opt ); ?>[headers][csp_policy]" rows="4" class="large-text code"><?php echo esc_textarea( $blt_secure_headers['csp_policy'] ); ?></textarea>
				</div>
			</div>
			<div class="blt-setting-control">
				<?php blt_secure_toggle( $blt_secure_opt . '[headers][csp_enabled]', ! empty( $blt_secure_headers['csp_enabled'] ) ); ?>
			</div>
		</div>
	</div>

	<div class="blt-section">
		<h2><?php esc_html_e( 'Privacy', 'blt-secure' ); ?></h2>

		<?php
		blt_secure_setting_open( __( 'Hide the WordPress version', 'blt-secure' ), __( 'Removes the generator meta tag and the core ?ver= query strings that reveal your exact version.', 'blt-secure' ) );
		blt_secure_setting_control();
		blt_secure_toggle( $blt_secure_opt . '[privacy][hide_version]', ! empty( $blt_secure_privacy['hide_version'] ) );
		blt_secure_setting_close();

		blt_secure_setting_open( __( 'Block user enumeration', 'blt-secure' ), __( 'Stops username harvesting via ?author=N and the REST /wp/v2/users endpoint for visitors.', 'blt-secure' ) );
		blt_secure_setting_control();
		blt_secure_toggle( $blt_secure_opt . '[privacy][block_enum]', ! empty( $blt_secure_privacy['block_enum'] ) );
		blt_secure_setting_close();
		?>
	</div>

	<div class="blt-section">
		<h2><?php esc_html_e( 'XML-RPC', 'blt-secure' ); ?></h2>

		<?php
		blt_secure_setting_open( __( 'Allow XML-RPC', 'blt-secure' ), __( 'Needed by Jetpack and the WordPress mobile apps. Leave off otherwise — it is abused for brute-force amplification and pingback DoS.', 'blt-secure' ) );
		blt_secure_setting_control();
		blt_secure_toggle( $blt_secure_opt . '[xmlrpc][enabled]', ! empty( $blt_secure_xmlrpc['enabled'] ) );
		blt_secure_setting_close();
		?>
	</div>

	<div class="blt-section">
		<h2><?php esc_html_e( 'File guard', 'blt-secure' ); ?></h2>

		<?php if ( defined( 'DISALLOW_FILE_EDIT' ) ) : ?>
			<?php
			blt_secure_setting_open(
				__( 'Disable the theme/plugin file editor', 'blt-secure' ),
				DISALLOW_FILE_EDIT
					? __( 'DISALLOW_FILE_EDIT is already enabled in wp-config.php — nothing to do here.', 'blt-secure' )
					: __( 'DISALLOW_FILE_EDIT is explicitly disabled in wp-config.php, which overrides this setting.', 'blt-secure' )
			);
			blt_secure_setting_control();
			blt_secure_toggle( $blt_secure_opt . '[fileguard][disallow_file_edit]', DISALLOW_FILE_EDIT, array( 'disabled' => true ) );
			blt_secure_setting_close();
			?>
		<?php else : ?>
			<?php
			blt_secure_setting_open( __( 'Disable the theme/plugin file editor', 'blt-secure' ), __( 'Removes the built-in code editors from wp-admin so a compromised login cannot instantly run code.', 'blt-secure' ) );
			blt_secure_setting_control();
			blt_secure_toggle( $blt_secure_opt . '[fileguard][disallow_file_edit]', ! empty( $blt_secure_fileguard['disallow_file_edit'] ) );
			blt_secure_setting_close();
			?>
		<?php endif; ?>

		<?php
		blt_secure_setting_open( __( 'Block file-manager plugins', 'blt-secure' ), __( 'Blocks installation and activation of file-manager plugins, a common compromise vector.', 'blt-secure' ) );
		blt_secure_setting_control();
		blt_secure_toggle( $blt_secure_opt . '[fileguard][block_file_managers]', ! empty( $blt_secure_fileguard['block_file_managers'] ) );
		blt_secure_setting_close();
		?>
	</div>

	<?php submit_button(); ?>
</form>
