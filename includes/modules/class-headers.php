<?php
/**
 * Security headers module.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Sends security headers on front-end and login responses.
 *
 * Rules of the road:
 * - Never duplicate a header the host/CDN already set (headers_list check).
 * - HSTS only over SSL; includeSubDomains/preload each need explicit opt-in.
 * - CSP is never sent inside wp-admin, and defaults to Report-Only.
 */
class Blt_Secure_Headers implements Blt_Secure_Module {

	const CSP_STARTER = "default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' data: https:; frame-ancestors 'self'; object-src 'none'; base-uri 'self'";

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
		return 'headers';
	}

	/**
	 * Defaults.
	 *
	 * @return array
	 */
	public function defaults() {
		return array(
			'enabled'         => true,
			'hsts'            => false,
			'hsts_max_age'    => 31536000,
			'hsts_subdomains' => false,
			'hsts_preload'    => false,
			'x_frame'         => 'SAMEORIGIN',
			'nosniff'         => true,
			'referrer_policy' => 'strict-origin-when-cross-origin',
			'csp_enabled'     => false,
			'csp_report_only' => true,
			'csp_policy'      => self::CSP_STARTER,
		);
	}

	/**
	 * Enabled?
	 *
	 * @return bool
	 */
	public function is_enabled() {
		return (bool) $this->options->get( 'headers', 'enabled', true );
	}

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function boot() {
		add_action( 'send_headers', array( $this, 'send' ) );
		add_action( 'login_init', array( $this, 'send' ) );
	}

	/**
	 * Sanitize section.
	 *
	 * @param array $input Raw input.
	 * @param array $current Current values.
	 * @return array
	 */
	public function sanitize( $input, $current ) {
		$x_frame_allowed  = array( '', 'SAMEORIGIN', 'DENY' );
		$referrer_allowed = array(
			'',
			'no-referrer',
			'same-origin',
			'strict-origin',
			'strict-origin-when-cross-origin',
			'no-referrer-when-downgrade',
		);

		$x_frame  = isset( $input['x_frame'] ) ? strtoupper( sanitize_text_field( $input['x_frame'] ) ) : 'SAMEORIGIN';
		$referrer = isset( $input['referrer_policy'] ) ? sanitize_text_field( $input['referrer_policy'] ) : 'strict-origin-when-cross-origin';

		$policy = isset( $input['csp_policy'] ) ? trim( sanitize_textarea_field( $input['csp_policy'] ) ) : '';
		if ( '' === $policy ) {
			$policy = self::CSP_STARTER;
		}

		return array(
			'enabled'         => ! empty( $input['enabled'] ),
			'hsts'            => ! empty( $input['hsts'] ),
			'hsts_max_age'    => max( 0, absint( isset( $input['hsts_max_age'] ) ? $input['hsts_max_age'] : 31536000 ) ),
			'hsts_subdomains' => ! empty( $input['hsts_subdomains'] ),
			'hsts_preload'    => ! empty( $input['hsts_preload'] ),
			'x_frame'         => in_array( $x_frame, $x_frame_allowed, true ) ? $x_frame : 'SAMEORIGIN',
			'nosniff'         => ! empty( $input['nosniff'] ),
			'referrer_policy' => in_array( $referrer, $referrer_allowed, true ) ? $referrer : 'strict-origin-when-cross-origin',
			'csp_enabled'     => ! empty( $input['csp_enabled'] ),
			'csp_report_only' => ! empty( $input['csp_report_only'] ),
			'csp_policy'      => $policy,
		);
	}

	/**
	 * Emit headers for this response.
	 *
	 * @return void
	 */
	public function send() {
		if ( headers_sent() ) {
			return;
		}

		$s = $this->options->section( 'headers' );

		if ( ! empty( $s['hsts'] ) && is_ssl() ) {
			$hsts = 'max-age=' . absint( $s['hsts_max_age'] );
			if ( ! empty( $s['hsts_subdomains'] ) ) {
				$hsts .= '; includeSubDomains';
			}
			if ( ! empty( $s['hsts_preload'] ) ) {
				$hsts .= '; preload';
			}
			$this->send_if_absent( 'Strict-Transport-Security', $hsts );
		}

		if ( ! empty( $s['x_frame'] ) ) {
			$this->send_if_absent( 'X-Frame-Options', $s['x_frame'] );
		}

		if ( ! empty( $s['nosniff'] ) ) {
			$this->send_if_absent( 'X-Content-Type-Options', 'nosniff' );
		}

		if ( ! empty( $s['referrer_policy'] ) ) {
			$this->send_if_absent( 'Referrer-Policy', $s['referrer_policy'] );
		}

		// CSP: never inside wp-admin — core's inline scripts don't survive it.
		if ( ! empty( $s['csp_enabled'] ) && ! is_admin() ) {
			/**
			 * Filter the CSP policy string before it is sent.
			 *
			 * @param string $policy Policy directives.
			 */
			$policy = apply_filters( 'blt_secure_csp_policy', $s['csp_policy'] );
			if ( '' !== $policy ) {
				$name = ! empty( $s['csp_report_only'] ) ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
				$this->send_if_absent( $name, $policy );
			}
		}
	}

	/**
	 * Send a header unless something (host, CDN, another plugin) already did.
	 *
	 * @param string $name Header name.
	 * @param string $value Header value.
	 * @return void
	 */
	private function send_if_absent( $name, $value ) {
		foreach ( headers_list() as $sent ) {
			if ( 0 === stripos( $sent, $name . ':' ) ) {
				return;
			}
		}
		header( $name . ': ' . $value );
	}
}
