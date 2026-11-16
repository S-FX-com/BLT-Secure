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
	 * WP shim — records the call (tests assert on $GLOBALS['blt_test_actions']).
	 */
	function do_action() {
		$args                            = func_get_args();
		$GLOBALS['blt_test_actions'][] = $args;
		if ( isset( $GLOBALS['blt_test_on_action'] ) && is_callable( $GLOBALS['blt_test_on_action'] ) ) {
			call_user_func_array( $GLOBALS['blt_test_on_action'], $args );
		}
	}
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

if ( ! function_exists( 'esc_html' ) ) {
	/**
	 * WP shim.
	 *
	 * @param string $text Value.
	 * @return string
	 */
	function esc_html( $text ) {
		return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'esc_attr' ) ) {
	/**
	 * WP shim.
	 *
	 * @param string $text Value.
	 * @return string
	 */
	function esc_attr( $text ) {
		return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
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
	'includes/feeds/class-feeds.php',
	'includes/feeds/class-ioc-parser.php',
	'includes/feeds/class-feed-changelog.php',
	'includes/modules/class-alerting.php',
	'includes/modules/class-alert-channels.php',
	'includes/modules/class-fleet.php',
	'includes/modules/class-badge.php',
	'includes/modules/class-activity.php',
	'includes/modules/class-upload-guard.php',
	'includes/modules/class-login-hardening.php',
	'includes/class-ip-resolver.php',
	'includes/class-updater.php',
	'includes/health/class-health-result.php',
	'includes/health/class-health-context.php',
	'includes/health/class-health-runner.php',
	'includes/health/class-health-checks.php',
	'includes/health/class-health-fixes.php',
	'includes/scanner/class-scan-whitelist.php',
	'includes/scanner/class-core-scanner.php',
	'includes/scanner/class-malware-scanner.php',
	'includes/scanner/class-baseline-scanner.php',
	'includes/scanner/class-yara.php',
	'includes/cloudflare/rule-definitions.php',
	'includes/cloudflare/class-cf-events.php',
	'includes/cloudflare/class-cloudflare-api.php',
	'includes/cloudflare/class-cloudflare-state.php',
	'includes/cloudflare/class-cloudflare-deployer.php',
);
foreach ( $blt_test_requires as $blt_test_file ) {
	if ( file_exists( BLT_SECURE_DIR . $blt_test_file ) ) {
		require_once BLT_SECURE_DIR . $blt_test_file;
	}
}

// ---------------------------------------------------------------------------
// Shims for the login / 2FA / file-guard / privacy tests.
// ---------------------------------------------------------------------------

if ( ! class_exists( 'WP_User' ) ) {
	/**
	 * Minimal WP_User stand-in.
	 */
	class WP_User {
		/**
		 * User id.
		 *
		 * @var int
		 */
		public $ID;

		/**
		 * Login name.
		 *
		 * @var string
		 */
		public $user_login;

		/**
		 * Roles.
		 *
		 * @var string[]
		 */
		public $roles = array();

		/**
		 * Constructor.
		 *
		 * @param int    $id    Id.
		 * @param string $login Login.
		 */
		public function __construct( $id = 0, $login = '' ) {
			$this->ID         = (int) $id;
			$this->user_login = $login;
		}
	}
}

$GLOBALS['blt_test_user_meta'] = array();

if ( ! function_exists( 'get_user_meta' ) ) {
	/**
	 * WP shim.
	 *
	 * @param int    $user_id User id.
	 * @param string $key     Meta key.
	 * @param bool   $single  Single (ignored).
	 * @return mixed
	 */
	function get_user_meta( $user_id, $key, $single = false ) { // phpcs:ignore
		return isset( $GLOBALS['blt_test_user_meta'][ $user_id ][ $key ] ) ? $GLOBALS['blt_test_user_meta'][ $user_id ][ $key ] : '';
	}
}

if ( ! function_exists( 'update_user_meta' ) ) {
	/**
	 * WP shim.
	 *
	 * @param int    $user_id User id.
	 * @param string $key     Meta key.
	 * @param mixed  $value   Value.
	 * @return bool
	 */
	function update_user_meta( $user_id, $key, $value ) {
		$GLOBALS['blt_test_user_meta'][ $user_id ][ $key ] = $value;
		return true;
	}
}

if ( ! function_exists( 'delete_user_meta' ) ) {
	/**
	 * WP shim.
	 *
	 * @param int    $user_id User id.
	 * @param string $key     Meta key.
	 * @return bool
	 */
	function delete_user_meta( $user_id, $key ) {
		unset( $GLOBALS['blt_test_user_meta'][ $user_id ][ $key ] );
		return true;
	}
}

if ( ! function_exists( 'untrailingslashit' ) ) {
	/**
	 * WP shim.
	 *
	 * @param string $value Path.
	 * @return string
	 */
	function untrailingslashit( $value ) {
		return rtrim( (string) $value, '/\\' );
	}
}

if ( ! function_exists( 'get_current_user_id' ) ) {
	/**
	 * WP shim.
	 *
	 * @return int
	 */
	function get_current_user_id() {
		return 0;
	}
}

foreach ( array( 'includes/modules/class-headers.php', 'includes/modules/class-privacy.php', 'includes/modules/class-file-guard.php', 'includes/modules/class-two-factor.php' ) as $blt_test_file ) {
	if ( file_exists( BLT_SECURE_DIR . $blt_test_file ) ) {
		require_once BLT_SECURE_DIR . $blt_test_file;
	}
}

// ---------------------------------------------------------------------------
// Shims for the fleet / alert-channel / hardening-pass tests. Each records or
// replays state held in a $GLOBALS['blt_test_*'] array; tests reset them.
// ---------------------------------------------------------------------------

$GLOBALS['blt_test_actions']   = array();
$GLOBALS['blt_test_scheduled'] = array();
$GLOBALS['blt_test_http']      = array();
$GLOBALS['blt_test_mail']      = array();
$GLOBALS['blt_test_errors']    = array();

if ( ! function_exists( 'wp_parse_url' ) ) {
	/**
	 * WP shim.
	 *
	 * @param string $url       URL.
	 * @param int    $component Component.
	 * @return mixed
	 */
	function wp_parse_url( $url, $component = -1 ) {
		return parse_url( (string) $url, $component ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url
	}
}

if ( ! function_exists( 'esc_url_raw' ) ) {
	/**
	 * WP shim — pass-through.
	 *
	 * @param string $url       URL.
	 * @param array  $protocols Ignored.
	 * @return string
	 */
	function esc_url_raw( $url, $protocols = null ) { // phpcs:ignore
		return (string) $url;
	}
}

if ( ! function_exists( 'add_settings_error' ) ) {
	/**
	 * WP shim — records.
	 *
	 * @param string $setting Setting.
	 * @param string $code    Code.
	 * @param string $message Message.
	 * @return void
	 */
	function add_settings_error( $setting, $code, $message ) { // phpcs:ignore
		$GLOBALS['blt_test_errors'][] = $code;
	}
}

if ( ! function_exists( 'wp_schedule_single_event' ) ) {
	/**
	 * WP shim — records the scheduled event.
	 *
	 * @param int    $timestamp When.
	 * @param string $hook      Hook.
	 * @param array  $args      Args.
	 * @return bool
	 */
	function wp_schedule_single_event( $timestamp, $hook, $args = array() ) {
		$GLOBALS['blt_test_scheduled'][] = array(
			'time' => $timestamp,
			'hook' => $hook,
			'args' => $args,
		);
		return true;
	}
}

if ( ! function_exists( 'get_bloginfo' ) ) {
	/**
	 * WP shim.
	 *
	 * @param string $show What.
	 * @return string
	 */
	function get_bloginfo( $show = '' ) { // phpcs:ignore
		return 'Test Site';
	}
}

if ( ! function_exists( 'home_url' ) ) {
	/**
	 * WP shim.
	 *
	 * @return string
	 */
	function home_url() {
		return 'https://example.test';
	}
}

if ( ! function_exists( 'wp_mail' ) ) {
	/**
	 * WP shim — records.
	 *
	 * @param string $to      To.
	 * @param string $subject Subject.
	 * @param string $body    Body.
	 * @return bool
	 */
	function wp_mail( $to, $subject, $body ) {
		$GLOBALS['blt_test_mail'][] = array( $to, $subject, $body );
		return true;
	}
}

if ( ! function_exists( 'wp_remote_retrieve_header' ) ) {
	/**
	 * WP shim.
	 *
	 * @param array  $response Response.
	 * @param string $header   Header name.
	 * @return string
	 */
	function wp_remote_retrieve_header( $response, $header ) {
		$headers = isset( $response['headers'] ) ? array_change_key_case( (array) $response['headers'], CASE_LOWER ) : array();
		return isset( $headers[ strtolower( $header ) ] ) ? $headers[ strtolower( $header ) ] : '';
	}
}

if ( ! function_exists( 'wp_safe_remote_post' ) ) {
	/**
	 * WP shim — records the request and replays a queued response (or a stub).
	 *
	 * @param string $url  URL.
	 * @param array  $args Args.
	 * @return array|WP_Error
	 */
	function wp_safe_remote_post( $url, $args = array() ) {
		return blt_test_http_request( 'POST', $url, $args );
	}
}

if ( ! function_exists( 'wp_safe_remote_get' ) ) {
	/**
	 * WP shim — see wp_safe_remote_post().
	 *
	 * @param string $url  URL.
	 * @param array  $args Args.
	 * @return array|WP_Error
	 */
	function wp_safe_remote_get( $url, $args = array() ) {
		return blt_test_http_request( 'GET', $url, $args );
	}
}

if ( ! function_exists( 'blt_test_http_request' ) ) {
	/**
	 * Record an HTTP request; respond with the next queued response callable
	 * (receives the request) or a bare 200.
	 *
	 * @param string $method Method.
	 * @param string $url    URL.
	 * @param array  $args   Args.
	 * @return array|WP_Error
	 */
	function blt_test_http_request( $method, $url, $args ) {
		$GLOBALS['blt_test_requests'][] = array(
			'method' => $method,
			'url'    => $url,
			'args'   => $args,
		);
		$next = array_shift( $GLOBALS['blt_test_http'] );
		if ( is_callable( $next ) ) {
			return $next( $method, $url, $args );
		}
		return array(
			'response' => array( 'code' => 200 ),
			'body'     => '',
			'headers'  => array(),
		);
	}
}

$GLOBALS['blt_test_requests'] = array();
