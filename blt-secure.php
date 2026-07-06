<?php
/**
 * Plugin Name:       BLT Secure
 * Plugin URI:        https://s-fx.com/plugins/blt-secure/
 * Description:       WordPress hardening with Cloudflare edge enforcement — login protection, 2FA, security headers, and one-click WAF deployment.
 * Version:           0.1.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            S-FX.com Small Business Solutions
 * Author URI:        https://s-fx.com/
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       blt-secure
 * Domain Path:       /languages
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'BLT_SECURE_VERSION', '0.1.0' );
define( 'BLT_SECURE_FILE', __FILE__ );
define( 'BLT_SECURE_DIR', plugin_dir_path( __FILE__ ) );
define( 'BLT_SECURE_URL', plugin_dir_url( __FILE__ ) );

require_once BLT_SECURE_DIR . 'includes/interface-blt-module.php';
require_once BLT_SECURE_DIR . 'includes/class-options.php';
require_once BLT_SECURE_DIR . 'includes/class-ip-resolver.php';
require_once BLT_SECURE_DIR . 'includes/crypto/class-crypto.php';
require_once BLT_SECURE_DIR . 'includes/crypto/interface-credential-store.php';
require_once BLT_SECURE_DIR . 'includes/crypto/class-encrypted-option-store.php';
require_once BLT_SECURE_DIR . 'includes/modules/class-alerting.php';
require_once BLT_SECURE_DIR . 'includes/modules/class-headers.php';
require_once BLT_SECURE_DIR . 'includes/modules/class-privacy.php';
require_once BLT_SECURE_DIR . 'includes/modules/class-xmlrpc.php';
require_once BLT_SECURE_DIR . 'includes/modules/class-file-guard.php';
require_once BLT_SECURE_DIR . 'includes/modules/class-login-hardening.php';
require_once BLT_SECURE_DIR . 'includes/modules/class-totp.php';
require_once BLT_SECURE_DIR . 'includes/modules/class-two-factor.php';
require_once BLT_SECURE_DIR . 'includes/class-updater.php';
require_once BLT_SECURE_DIR . 'includes/class-blt-secure.php';

/**
 * Return the shared plugin instance.
 *
 * @return Blt_Secure
 */
function blt_secure() {
	return Blt_Secure::instance();
}

add_action( 'plugins_loaded', array( 'Blt_Secure', 'boot' ), 1 );

register_activation_hook( __FILE__, array( 'Blt_Secure', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'Blt_Secure', 'deactivate' ) );
