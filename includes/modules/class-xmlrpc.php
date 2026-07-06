<?php
/**
 * XML-RPC kill switch.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Disables XML-RPC by default; a single toggle re-enables it for sites that
 * need Jetpack or the mobile apps.
 *
 * Layers when off:
 * 1. Early exit with a proper XML-RPC fault before WP parses the payload.
 * 2. xmlrpc_enabled=false (kills authenticated methods).
 * 3. xmlrpc_methods=[] (kills pingback and other anonymous methods).
 * 4. X-Pingback header removed; pings closed.
 */
class Blt_Secure_Xmlrpc implements Blt_Secure_Module {

	/**
	 * Settings.
	 *
	 * @var Blt_Secure_Options
	 */
	private $options;

	/**
	 * Constructor.
	 *
	 * @param Blt_Secure_Options $options Settings access.
	 */
	public function __construct( Blt_Secure_Options $options ) {
		$this->options = $options;
	}

	/**
	 * Module id.
	 *
	 * @return string
	 */
	public function id() {
		return 'xmlrpc';
	}

	/**
	 * Defaults — XML-RPC off.
	 *
	 * @return array
	 */
	public function defaults() {
		return array(
			'enabled' => false,
		);
	}

	/**
	 * The module boots when XML-RPC is DISABLED (it exists to block).
	 *
	 * @return bool
	 */
	public function is_enabled() {
		return ! $this->options->get( 'xmlrpc', 'enabled', false );
	}

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function boot() {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			$this->reject_request();
		}

		add_filter( 'xmlrpc_enabled', '__return_false' );
		add_filter( 'xmlrpc_methods', '__return_empty_array' );
		add_filter( 'wp_headers', array( $this, 'remove_pingback_header' ) );
		add_filter( 'pings_open', '__return_false' );
	}

	/**
	 * Sanitize section.
	 *
	 * @param array $input Raw input.
	 * @param array $current Current values.
	 * @return array
	 */
	public function sanitize( $input, $current ) {
		return array(
			'enabled' => ! empty( $input['enabled'] ),
		);
	}

	/**
	 * Strip the X-Pingback advertisement.
	 *
	 * @param array $headers Response headers.
	 * @return array
	 */
	public function remove_pingback_header( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	/**
	 * Answer xmlrpc.php with a fault before WP parses the request body.
	 *
	 * @return void
	 */
	private function reject_request() {
		if ( ! headers_sent() ) {
			status_header( 405 );
			header( 'Content-Type: text/xml; charset=UTF-8' );
		}
		echo '<?xml version="1.0" encoding="UTF-8"?><methodResponse><fault><value><struct>'
			. '<member><name>faultCode</name><value><int>405</int></value></member>'
			. '<member><name>faultString</name><value><string>XML-RPC services are disabled on this site.</string></value></member>'
			. '</struct></value></fault></methodResponse>';
		exit;
	}
}
