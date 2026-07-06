<?php
/**
 * Minimal WordPress shims so pure-logic classes load without a WP install.
 *
 * Only what the classes under test actually touch is shimmed. Anything that
 * needs real WP behavior belongs in the manual smoke checklist, not here.
 *
 * @package Blt_Secure
 */

define( 'ABSPATH', __DIR__ . '/fake-abspath/' );
define( 'BLT_SECURE_DIR', dirname( __DIR__ ) . '/' );
define( 'BLT_SECURE_VERSION', 'tests' );

if ( ! class_exists( 'WP_Error' ) ) {
	/**
	 * Minimal WP_Error stand-in.
	 */
	class WP_Error {
		/**
		 * Error code.
		 *
		 * @var string
		 */
		private $code;

		/**
		 * Error message.
		 *
		 * @var string
		 */
		private $message;

		/**
		 * Error data.
		 *
		 * @var mixed
		 */
		private $data;

		/**
		 * Constructor.
		 *
		 * @param string $code Code.
		 * @param string $message Message.
		 * @param mixed  $data Data.
		 */
		public function __construct( $code = '', $message = '', $data = null ) {
			$this->code    = $code;
			$this->message = $message;
			$this->data    = $data;
		}

		/**
		 * Get code.
		 *
		 * @return string
		 */
		public function get_error_code() {
			return $this->code;
		}

		/**
		 * Get message.
		 *
		 * @return string
		 */
		public function get_error_message() {
			return $this->message;
		}

		/**
		 * Get data.
		 *
		 * @return mixed
		 */
		public function get_error_data() {
			return $this->data;
		}
	}
}

if ( ! function_exists( 'is_wp_error' ) ) {
	/**
	 * WP shim.
	 *
	 * @param mixed $thing Value.
	 * @return bool
	 */
	function is_wp_error( $thing ) {
		return $thing instanceof WP_Error;
	}
}

if ( ! function_exists( '__' ) ) {
	/**
	 * WP shim.
	 *
	 * @param string $text Text.
	 * @param string $domain Domain.
	 * @return string
	 */
	function __( $text, $domain = 'default' ) { // phpcs:ignore
		return $text;
	}
}

if ( ! function_exists( 'wp_salt' ) ) {
	/**
	 * WP shim — deterministic per scheme for tests.
	 *
	 * @param string $scheme Scheme.
	 * @return string
	 */
	function wp_salt( $scheme = 'auth' ) {
		return 'test-salt-' . $scheme;
	}
}

if ( ! function_exists( 'sanitize_key' ) ) {
	/**
	 * WP shim.
	 *
	 * @param string $key Key.
	 * @return string
	 */
	function sanitize_key( $key ) {
		return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $key ) );
	}
}

if ( ! function_exists( 'apply_filters' ) ) {
	/**
	 * WP shim — pass-through.
	 *
	 * @param string $hook Hook.
	 * @param mixed  $value Value.
	 * @return mixed
	 */
	function apply_filters( $hook, $value ) { // phpcs:ignore
		return $value;
	}
}

// In-memory options for store tests.
$GLOBALS['blt_test_options'] = array();

if ( ! function_exists( 'get_option' ) ) {
	/**
	 * WP shim.
	 *
	 * @param string $name Option name.
	 * @param mixed  $default_value Default.
	 * @return mixed
	 */
	function get_option( $name, $default_value = false ) {
		return array_key_exists( $name, $GLOBALS['blt_test_options'] ) ? $GLOBALS['blt_test_options'][ $name ] : $default_value;
	}
}

if ( ! function_exists( 'update_option' ) ) {
	/**
	 * WP shim.
	 *
	 * @param string $name Option name.
	 * @param mixed  $value Value.
	 * @param mixed  $autoload Autoload flag (ignored).
	 * @return bool
	 */
	function update_option( $name, $value, $autoload = null ) { // phpcs:ignore
		$GLOBALS['blt_test_options'][ $name ] = $value;
		return true;
	}
}

if ( ! function_exists( 'delete_option' ) ) {
	/**
	 * WP shim.
	 *
	 * @param string $name Option name.
	 * @return bool
	 */
	function delete_option( $name ) {
		unset( $GLOBALS['blt_test_options'][ $name ] );
		return true;
	}
}

$blt_test_requires = array(
	'includes/crypto/class-crypto.php',
	'includes/crypto/interface-credential-store.php',
	'includes/crypto/class-encrypted-option-store.php',
	'includes/modules/class-totp.php',
	'includes/class-ip-resolver.php',
	'includes/cloudflare/rule-definitions.php',
);
foreach ( $blt_test_requires as $blt_test_file ) {
	if ( file_exists( BLT_SECURE_DIR . $blt_test_file ) ) {
		require_once BLT_SECURE_DIR . $blt_test_file;
	}
}
