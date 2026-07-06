<?php
/**
 * Cloudflare API client.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Thin Bearer-token client over wp_remote_request.
 *
 * Maps Cloudflare's errors[] into typed WP_Errors the deployer keys UX off:
 *  - blt_cf_auth        → token invalid/expired
 *  - blt_cf_scope       → token lacks a permission (per-card "insufficient scope")
 *  - blt_cf_plan        → feature not available on the zone's plan
 *  - blt_cf_validation  → payload rejected (our bug or API drift)
 *  - blt_cf_http        → transport-level failure
 *
 * The transport is injectable so tests can run canned responses through the
 * full request/error-mapping path.
 */
class Blt_Secure_Cloudflare_Api {

	const BASE = 'https://api.cloudflare.com/client/v4';

	/**
	 * API token.
	 *
	 * @var string
	 */
	private $token;

	/**
	 * Transport callable (signature of wp_remote_request).
	 *
	 * @var callable
	 */
	private $transport;

	/**
	 * Constructor.
	 *
	 * @param string        $token API token.
	 * @param callable|null $transport Optional transport override (tests).
	 */
	public function __construct( $token, $transport = null ) {
		$this->token     = (string) $token;
		$this->transport = $transport ? $transport : 'wp_remote_request';
	}

	/**
	 * GET.
	 *
	 * @param string $path API path.
	 * @param array  $query Query args.
	 * @return array|WP_Error Decoded result.
	 */
	public function get( $path, array $query = array() ) {
		return $this->request( 'GET', $path . ( $query ? '?' . http_build_query( $query ) : '' ) );
	}

	/**
	 * POST.
	 *
	 * @param string $path API path.
	 * @param array|null $body JSON body.
	 * @return array|WP_Error
	 */
	public function post( $path, $body = null ) {
		return $this->request( 'POST', $path, $body );
	}

	/**
	 * PATCH.
	 *
	 * @param string $path API path.
	 * @param array|null $body JSON body.
	 * @return array|WP_Error
	 */
	public function patch( $path, $body = null ) {
		return $this->request( 'PATCH', $path, $body );
	}

	/**
	 * PUT.
	 *
	 * @param string $path API path.
	 * @param array|null $body JSON body.
	 * @return array|WP_Error
	 */
	public function put( $path, $body = null ) {
		return $this->request( 'PUT', $path, $body );
	}

	/**
	 * DELETE.
	 *
	 * @param string $path API path.
	 * @return array|WP_Error
	 */
	public function delete( $path ) {
		return $this->request( 'DELETE', $path );
	}

	/**
	 * Verify the token itself (needs no extra scopes).
	 *
	 * @return true|WP_Error
	 */
	public function verify_token() {
		$result = $this->get( '/user/tokens/verify' );
		return is_wp_error( $result ) ? $result : true;
	}

	/**
	 * Discover the zone for a host by stripping subdomain labels until a
	 * zone name matches (site.example.co.uk → example.co.uk).
	 *
	 * @param string $host Hostname from home_url.
	 * @return array|WP_Error Zone object (id, name, account.id, plan).
	 */
	public function discover_zone( $host ) {
		$labels = explode( '.', strtolower( (string) $host ) );

		while ( count( $labels ) >= 2 ) {
			$candidate = implode( '.', $labels );
			$result    = $this->get( '/zones', array( 'name' => $candidate ) );

			if ( is_wp_error( $result ) ) {
				return $result;
			}
			if ( ! empty( $result[0]['id'] ) ) {
				return $result[0];
			}

			array_shift( $labels );
		}

		return new WP_Error( 'blt_cf_no_zone', __( 'No Cloudflare zone matching this site was found with this token.', 'blt-secure' ) );
	}

	/**
	 * Issue a request and normalize the response.
	 *
	 * @param string     $method HTTP method.
	 * @param string     $path Path under the API base.
	 * @param array|null $body JSON body.
	 * @return array|WP_Error Cloudflare "result" member.
	 */
	private function request( $method, $path, $body = null ) {
		$args = array(
			'method'  => $method,
			'timeout' => 15,
			'headers' => array(
				'Authorization' => 'Bearer ' . $this->token,
				'Content-Type'  => 'application/json',
			),
		);
		if ( null !== $body ) {
			$args['body'] = wp_json_encode( $body );
		}

		$response = call_user_func( $this->transport, self::BASE . $path, $args );

		if ( is_wp_error( $response ) ) {
			return new WP_Error( 'blt_cf_http', $response->get_error_message() );
		}

		$status  = (int) wp_remote_retrieve_response_code( $response );
		$decoded = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( ! is_array( $decoded ) ) {
			return new WP_Error(
				'blt_cf_http',
				sprintf(
					/* translators: %d: HTTP status code */
					__( 'Cloudflare returned an unreadable response (HTTP %d).', 'blt-secure' ),
					$status
				)
			);
		}

		if ( ! empty( $decoded['success'] ) ) {
			return isset( $decoded['result'] ) ? (array) $decoded['result'] : array();
		}

		return $this->map_error( $status, isset( $decoded['errors'] ) ? (array) $decoded['errors'] : array() );
	}

	/**
	 * Map Cloudflare errors[] to a typed WP_Error.
	 *
	 * @param int   $status HTTP status.
	 * @param array $errors Cloudflare error objects.
	 * @return WP_Error
	 */
	private function map_error( $status, array $errors ) {
		$first   = isset( $errors[0] ) ? (array) $errors[0] : array();
		$code    = isset( $first['code'] ) ? (int) $first['code'] : 0;
		$message = isset( $first['message'] ) ? (string) $first['message'] : __( 'Unknown Cloudflare API error.', 'blt-secure' );

		// Token invalid / expired / malformed.
		if ( in_array( $code, array( 10000, 10001, 6003 ), true ) || 401 === $status ) {
			return new WP_Error( 'blt_cf_auth', $message, array( 'status' => $status, 'cf_code' => $code ) );
		}

		// Authorized token, missing permission.
		if ( 403 === $status || 10014 === $code ) {
			return new WP_Error( 'blt_cf_scope', $message, array( 'status' => $status, 'cf_code' => $code ) );
		}

		// Plan restrictions surface as ruleset validation refusals mentioning
		// the plan, or dedicated codes on some endpoints.
		if ( false !== stripos( $message, 'plan' ) || in_array( $code, array( 20040, 20041 ), true ) ) {
			return new WP_Error( 'blt_cf_plan', $message, array( 'status' => $status, 'cf_code' => $code ) );
		}

		// Ruleset engine validation.
		if ( in_array( $code, array( 10021, 20217 ), true ) || 400 === $status ) {
			return new WP_Error( 'blt_cf_validation', $message, array( 'status' => $status, 'cf_code' => $code ) );
		}

		return new WP_Error( 'blt_cf_error', $message, array( 'status' => $status, 'cf_code' => $code ) );
	}
}
