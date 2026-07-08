<?php
/**
 * Shared state passed to every health check.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Bundles the services a check needs and memoizes the expensive lookups
 * (the site's own response headers, update data) so a full scan touches the
 * network at most once. Constructed only when a scan actually runs — never
 * on a normal page load.
 */
class Blt_Secure_Health_Context {

	/**
	 * Settings access.
	 *
	 * @var Blt_Secure_Options
	 */
	public $options;

	/**
	 * Memoized lowercased response headers from the site's front page, or
	 * false when the self-request failed. Null until first requested.
	 *
	 * @var array|false|null
	 */
	private $headers = null;

	/**
	 * Constructor.
	 *
	 * @param Blt_Secure_Options $options Settings.
	 */
	public function __construct( Blt_Secure_Options $options ) {
		$this->options = $options;
	}

	/**
	 * Fetch (once) the front page and return its headers as a lowercased
	 * name => value map, or false if the request could not be made.
	 *
	 * @return array|false
	 */
	public function response_headers() {
		if ( null !== $this->headers ) {
			return $this->headers;
		}

		$response = wp_remote_get(
			home_url( '/' ),
			array(
				'timeout'     => 8,
				'redirection' => 2,
				'sslverify'   => false, // Self-request; a local cert quirk shouldn't fail the scan.
				'headers'     => array( 'X-BLT-Secure-Healthcheck' => '1' ),
				'user-agent'  => 'BLT-Secure-HealthCheck/' . BLT_SECURE_VERSION,
			)
		);

		if ( is_wp_error( $response ) ) {
			$this->headers = false;
			return $this->headers;
		}

		$raw           = wp_remote_retrieve_headers( $response );
		$list          = is_object( $raw ) && method_exists( $raw, 'getAll' ) ? $raw->getAll() : (array) $raw;
		$this->headers = array();
		foreach ( $list as $name => $value ) {
			$this->headers[ strtolower( (string) $name ) ] = is_array( $value ) ? implode( ', ', $value ) : (string) $value;
		}

		return $this->headers;
	}

	/**
	 * Read a single response header value (lowercased lookup), or '' when
	 * absent. Returns null when the self-request failed entirely, so callers
	 * can SKIP rather than report a false negative.
	 *
	 * @param string $name Header name.
	 * @return string|null
	 */
	public function header( $name ) {
		$headers = $this->response_headers();
		if ( false === $headers ) {
			return null;
		}
		$name = strtolower( $name );
		return isset( $headers[ $name ] ) ? $headers[ $name ] : '';
	}
}
