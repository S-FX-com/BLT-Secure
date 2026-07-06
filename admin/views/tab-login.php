<?php
/**
 * Login tab: slug rename, lockout, 2FA policy.
 *
 * @var Blt_Secure_Options $options Settings.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$blt_secure_login = $options->section( 'login' );
$blt_secure_twofa = $options->section( 'twofa' );
$blt_secure_opt   = Blt_Secure_Options::OPTION;
?>
<form method="post" action="options.php">
	<?php settings_fields( 'blt_secure' ); ?>

	<h2><?php esc_html_e( 'Login URL', 'blt-secure' ); ?></h2>
	<table class="form-table" role="presentation">
		<tr>
			<th scope="row"><label for="blt-login-slug"><?php esc_html_e( 'Custom login slug', 'blt-secure' ); ?></label></th>
			<td>
				<?php if ( is_multisite() ) : ?>
					<p class="description"><?php esc_html_e( 'Login URL renaming is not available on multisite installations yet.', 'blt-secure' ); ?></p>
				<?php elseif ( defined( 'BLT_SECURE_DISABLE_SLUG' ) && BLT_SECURE_DISABLE_SLUG ) : ?>
					<p class="description"><code>BLT_SECURE_DISABLE_SLUG</code> <?php esc_html_e( 'is set in wp-config.php — the custom slug is bypassed and wp-login.php works normally.', 'blt-secure' ); ?></p>
				<?php else : ?>
					<code><?php echo esc_html( untrailingslashit( home_url() ) ); ?>/</code>
					<input type="text" id="blt-login-slug" name="<?php echo esc_attr( $blt_secure_opt ); ?>[login][slug]" value="<?php echo esc_attr( $blt_secure_login['slug'] ); ?>" class="regular-text" style="max-width:200px;" placeholder="<?php esc_attr_e( 'my-secret-login', 'blt-secure' ); ?>" />
					<p class="description">
						<?php esc_html_e( 'Leave empty to keep the default wp-login.php. When set, wp-login.php and unauthenticated wp-admin return 404. You will receive the new URL by email; bookmark it.', 'blt-secure' ); ?>
					</p>
				<?php endif; ?>
			</td>
		</tr>
	</table>

	<h2><?php esc_html_e( 'Failed-login lockout', 'blt-secure' ); ?></h2>
	<table class="form-table" role="presentation">
		<tr>
			<th scope="row"><?php esc_html_e( 'Lockout', 'blt-secure' ); ?></th>
			<td>
				<label><input type="checkbox" name="<?php echo esc_attr( $blt_secure_opt ); ?>[login][lockout_enabled]" value="1" <?php checked( $blt_secure_login['lockout_enabled'] ); ?> />
				<?php esc_html_e( 'Temporarily block sign-in after repeated failures (counted per IP and per username)', 'blt-secure' ); ?></label>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="blt-max-attempts"><?php esc_html_e( 'Attempts before lockout', 'blt-secure' ); ?></label></th>
			<td>
				<input type="number" id="blt-max-attempts" name="<?php echo esc_attr( $blt_secure_opt ); ?>[login][max_attempts]" value="<?php echo esc_attr( $blt_secure_login['max_attempts'] ); ?>" min="3" max="20" class="small-text" />
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="blt-lockout-minutes"><?php esc_html_e( 'Lockout duration (minutes)', 'blt-secure' ); ?></label></th>
			<td>
				<input type="number" id="blt-lockout-minutes" name="<?php echo esc_attr( $blt_secure_opt ); ?>[login][lockout_minutes]" value="<?php echo esc_attr( $blt_secure_login['lockout_minutes'] ); ?>" min="5" max="1440" class="small-text" />
			</td>
		</tr>
	</table>

	<h2><?php esc_html_e( 'Two-factor authentication', 'blt-secure' ); ?></h2>
	<table class="form-table" role="presentation">
		<tr>
			<th scope="row"><label for="blt-2fa-policy"><?php esc_html_e( 'Policy', 'blt-secure' ); ?></label></th>
			<td>
				<select id="blt-2fa-policy" name="<?php echo esc_attr( $blt_secure_opt ); ?>[twofa][policy]">
					<option value="optional" <?php selected( $blt_secure_twofa['policy'], 'optional' ); ?>><?php esc_html_e( 'Optional (users opt in on their profile)', 'blt-secure' ); ?></option>
					<option value="required_admins" <?php selected( $blt_secure_twofa['policy'], 'required_admins' ); ?>><?php esc_html_e( 'Required for administrators', 'blt-secure' ); ?></option>
					<option value="required_all" <?php selected( $blt_secure_twofa['policy'], 'required_all' ); ?>><?php esc_html_e( 'Required for everyone', 'blt-secure' ); ?></option>
				</select>
				<p class="description">
					<?php esc_html_e( 'Users covered by a “required” policy who have not enrolled yet see a persistent reminder — they are never locked out by the policy alone. Each user sets up 2FA on their own profile page.', 'blt-secure' ); ?>
				</p>
			</td>
		</tr>
	</table>

	<?php submit_button(); ?>
</form>
