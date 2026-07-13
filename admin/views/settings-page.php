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
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="wrap blt-secure-wrap">
	<h1><?php esc_html_e( 'BLT Secure', 'blt-secure' ); ?></h1>

	<?php settings_errors( 'blt_secure_settings' ); ?>

	<nav class="nav-tab-wrapper">
		<?php foreach ( $tabs as $blt_secure_slug => $blt_secure_label ) : ?>
			<a href="<?php echo esc_url( Blt_Secure_Admin::tab_url( $blt_secure_slug ) ); ?>"
				class="nav-tab <?php echo $tab === $blt_secure_slug ? 'nav-tab-active' : ''; ?>">
				<?php echo esc_html( $blt_secure_label ); ?>
			</a>
		<?php endforeach; ?>
	</nav>

	<?php require BLT_SECURE_DIR . 'admin/views/tab-' . $tab . '.php'; ?>
</div>
