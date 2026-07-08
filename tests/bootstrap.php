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

if ( ! function_exists( 'add_action' ) ) {
	/**
	 * WP shim — no-op.
	 */
	function add_action() {}
}

if ( ! function_exists( 'add_filter' ) ) {
	/**
	 * WP shim — no-op.
	 */
	function add_filter() {}
}

if ( ! function_exists( 'do_action' ) ) {
	/**
	 * WP shim — no-op.
	 */
	function do_action() {}
}

if ( ! function_exists( 'wp_unslash' ) ) {
	/**
	 * WP shim.
	 *
	 * @param mixed $value Value.
	 * @return mixed
	 */
	function wp_unslash( $value ) {
		return is_string( $value ) ? stripslashes( $value ) : $value;
	}
}

if ( ! function_exists( 'sanitize_text_field' ) ) {
	/**
	 * WP shim.
	 *
	 * @param string $str Value.
	 * @return string
	 */
	function sanitize_text_field( $str ) {
		return trim( preg_replace( '/[\r\n\t ]+/', ' ', wp_strip_all_tags( (string) $str ) ) );
	}
}

if ( ! function_exists( 'wp_strip_all_tags' ) ) {
	/**
	 * WP shim.
	 *
	 * @param string $text Value.
	 * @return string
	 */
	function wp_strip_all_tags( $text ) {
		return strip_tags( (string) $text ); // phpcs:ignore
	}
}

if ( ! function_exists( 'sanitize_user' ) ) {
	/**
	 * WP shim.
	 *
	 * @param string $username Value.
	 * @return string
	 */
	function sanitize_user( $username ) {
		return preg_replace( '/[^a-zA-Z0-9 _.\-@]/', '', (string) $username );
	}
}

if ( ! function_exists( 'absint' ) ) {
	/**
	 * WP shim.
	 *
	 * @param mixed $maybeint Value.
	 * @return int
	 */
	function absint( $maybeint ) {
		return abs( (int) $maybeint );
	}
}

if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
	define( 'MINUTE_IN_SECONDS', 60 );
	define( 'HOUR_IN_SECONDS', 3600 );
	define( 'DAY_IN_SECONDS', 86400 );
}

// In-memory transients for lockout tests.
$GLOBALS['blt_test_transients'] = array();

if ( ! function_exists( 'get_transient' ) ) {
	/**
	 * WP shim.
	 *
	 * @param string $key Key.
	 * @return mixed
	 */
	function get_transient( $key ) {
		return array_key_exists( $key, $GLOBALS['blt_test_transients'] ) ? $GLOBALS['blt_test_transients'][ $key ] : false;
	}
}

if ( ! function_exists( 'set_transient' ) ) {
	/**
	 * WP shim — TTL ignored (state machine only).
	 *
	 * @param string $key Key.
	 * @param mixed  $value Value.
	 * @param int    $ttl TTL.
	 * @return bool
	 */
	function set_transient( $key, $value, $ttl = 0 ) { // phpcs:ignore
		$GLOBALS['blt_test_transients'][ $key ] = $value;
		return true;
	}
}

if ( ! function_exists( 'delete_transient' ) ) {
	/**
	 * WP shim.
	 *
	 * @param string $key Key.
	 * @return bool
	 */
	function delete_transient( $key ) {
		unset( $GLOBALS['blt_test_transients'][ $key ] );
		return true;
	}
}

if ( ! function_exists( 'wp_json_encode' ) ) {
	/**
	 * WP shim.
	 *
	 * @param mixed $data Data.
	 * @return string|false
	 */
	function wp_json_encode( $data ) {
		return json_encode( $data ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode
	}
}

if ( ! function_exists( 'wp_remote_retrieve_response_code' ) ) {
	/**
	 * WP shim.
	 *
	 * @param array $response Response array.
	 * @return int|string
	 */
	function wp_remote_retrieve_response_code( $response ) {
		return isset( $response['response']['code'] ) ? $response['response']['code'] : '';
	}
}

if ( ! function_exists( 'wp_remote_retrieve_body' ) ) {
	/**
	 * WP shim.
	 *
	 * @param array $response Response array.
	 * @return string
	 */
	function wp_remote_retrieve_body( $response ) {
		return isset( $response['body'] ) ? $response['body'] : '';
	}
}

if ( ! function_exists( 'sanitize_email' ) ) {
	/**
	 * WP shim.
	 *
	 * @param string $email Email.
	 * @return string
	 */
	function sanitize_email( $email ) {
		$email = filter_var( (string) $email, FILTER_VALIDATE_EMAIL );
		return false === $email ? '' : $email;
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
	'includes/interface-blt-module.php',
	'includes/class-options.php',
	'includes/crypto/class-crypto.php',
	'includes/crypto/interface-credential-store.php',
	'includes/crypto/class-encrypted-option-store.php',
	'includes/modules/class-totp.php',
	'includes/modules/class-alerting.php',
	'includes/modules/class-login-hardening.php',
	'includes/class-ip-resolver.php',
	'includes/class-updater.php',
	'includes/health/class-health-result.php',
	'includes/health/class-health-context.php',
	'includes/health/class-health-runner.php',
	'includes/health/class-health-checks.php',
	'includes/cloudflare/rule-definitions.php',
	'includes/cloudflare/class-cloudflare-api.php',
	'includes/cloudflare/class-cloudflare-state.php',
	'includes/cloudflare/class-cloudflare-deployer.php',
);
foreach ( $blt_test_requires as $blt_test_file ) {
	if ( file_exists( BLT_SECURE_DIR . $blt_test_file ) ) {
		require_once BLT_SECURE_DIR . $blt_test_file;
	}
}
