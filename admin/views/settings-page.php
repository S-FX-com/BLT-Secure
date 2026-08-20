<?php
/**
 * Settings page shell.
 *
 * Context vars from Blt_Secure_Admin::render_page():
 *
 * @var string                       $tab      Active tab.
 * @var array                        $tabs     Tab labels.
 * @var Blt_Secure_Options           $options  Settings.
 * @var Blt_Secure_Cloudflare_State  $cf_state CF state.
 * @var Blt_Secure_Credential_Store  $store    Credential store.
 * @var Blt_Secure_Admin             $admin    Controller.
 * @var Blt_Secure_Updater|null      $updater  Update checker wiring.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="wrap blt-ui blt-ui-wide blt-secure-wrap">
	<div class="blt-admin-page-header">
		<h1>
			<?php
			// Pre-sanitized SVG from the shared brand helper (wp_kses with an
			// explicit SVG subset); wp_kses_post() would strip the element.
			echo BLT_Family_Brand::inline_mark( BLT_SECURE_DIR ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			?>
			<?php esc_html_e( 'BLT Secure', 'blt-secure' ); ?>
			<span class="blt-admin-page-header-sub"><?php echo esc_html( $tabs[ $tab ] ); ?></span>
		</h1>
	</div>

	<?php
	// Tells core's notice-relocating JS where the page heading ends, so
	// notices land under the header block instead of inside it.
	?>
	<hr class="wp-header-end" />

	<?php settings_errors( 'blt_secure_settings' ); ?>

	<nav class="blt-settings-tabs">
		<?php foreach ( $tabs as $blt_secure_slug => $blt_secure_label ) : ?>
			<a href="<?php echo esc_url( Blt_Secure_Admin::tab_url( $blt_secure_slug ) ); ?>"
				class="blt-settings-tab <?php echo $tab === $blt_secure_slug ? 'is-active' : ''; ?>">
				<?php echo esc_html( $blt_secure_label ); ?>
			</a>
		<?php endforeach; ?>
	</nav>

	<?php require BLT_SECURE_DIR . 'admin/views/tab-' . $tab . '.php'; ?>
</div>
