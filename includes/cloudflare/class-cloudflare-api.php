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
 *  - blt_cf_rate_limited → HTTP 429 (after bounded retries)
 *
 * The transport is injectable so tests can run canned responses through the
 * full request/error-mapping path.
 */
class Blt_Secure_Cloudflare_Api {

	const BASE = 'https://api.cloudflare.com/client/v4';

	/**
	 * Credential-store key the Cloudflare API token is stored under.
	 */
	const TOKEN_KEY = 'cf_token';

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
	 * Sleep callable (seconds) used for 429 backoff and bulk-operation polling.
	 *
	 * @var callable
	 */
	private $sleeper;

	/**
	 * `result_info` of the most recent REST response.
	 *
	 * @var array
	 */
	private $last_info = array();

	/**
	 * Maximum 429 retries per request, and the longest single wait (seconds).
	 */
	const MAX_RETRIES    = 2;
	const MAX_RETRY_WAIT = 5;

	/**
	 * Constructor.
	 *
	 * @param string        $token API token.
	 * @param callable|null $transport Optional transport override (tests).
	 * @param callable|null $sleeper Optional sleep override (tests); receives seconds.
	 */
	public function __construct( $token, $transport = null, $sleeper = null ) {
		$this->token     = (string) $token;
		$this->transport = $transport ? $transport : 'wp_remote_request';
		$this->sleeper   = $sleeper ? $sleeper : array( __CLASS__, 'default_sleep' );
	}

	/**
	 * Default sleeper.
	 *
	 * @param int $seconds Seconds.
	 * @return void
	 */
	public static function default_sleep( $seconds ) {
		sleep( (int) $seconds );
	}

	/**
	 * Pause (bounded) — used between bulk-operation polls.
	 *
	 * @param int $seconds Seconds.
	 * @return void
	 */
	public function pause( $seconds ) {
		call_user_func( $this->sleeper, max( 0, min( self::MAX_RETRY_WAIT, (int) $seconds ) ) );
	}

	/**
	 * URL-path segment for an id (ids come from API responses and stored
	 * state, so never concatenate them raw).
	 *
	 * @param mixed $id Identifier.
	 * @return string
	 */
	public static function seg( $id ) {
		return rawurlencode( (string) $id );
	}

	/**
	 * Whether this request context may sleep/retry. Never on a front-end
	 * page load: only wp-admin, WP-Cron, WP-CLI, or a non-WordPress context.
	 *
	 * @return bool
	 */
	private function may_retry() {
		if ( ! function_exists( 'is_admin' ) ) {
			return true;
		}
		if ( is_admin() || ( defined( 'DOING_CRON' ) && DOING_CRON ) || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return true;
		}
		return false;
	}

	/**
	 * `result_info` of the last REST response (pagination metadata).
	 *
	 * @return array
	 */
	public function last_result_info() {
		return $this->last_info;
	}

	/**
	 * The effective Cloudflare API token for this site, or '' when none.
	 *
	 * The single place the Cloudflare token is resolved — the admin
	 * deployer, the Cloudflare tab, the IOC sync and the timeline poll all
	 * come through here, so the precedence below is defined once.
	 *
	 * Precedence: this plugin's own encrypted credential row, then the
	 * shared BLT family store (opt-in per plugin, off by default). The
	 * fallback lives here and NOT inside Blt_Secure_Encrypted_Option_Store:
	 * that store also holds single-consumer secrets (the Slack webhook, the
	 * fleet enrollment token, the GitHub updates token), and a blanket
	 * fallback in its get() would make every one of them resolve from the
	 * shared row.
	 *
	 * @param Blt_Secure_Credential_Store $store Credential store.
	 * @return string
	 */
	public static function resolve_token( Blt_Secure_Credential_Store $store ) {
		$token = $store->get( self::TOKEN_KEY );
		$token = is_string( $token ) ? $token : '';

		if ( '' === $token && class_exists( 'BLT_Family' ) ) {
			$token = (string) BLT_Family::get( 'blt-secure', 'cloudflare', 'api_token' );
		}

		return $token;
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
	 * GET every page of a list endpoint (page/per_page), following
	 * result_info.total_pages; bounded at 20 pages.
	 *
	 * @param string $path  API path.
	 * @param array  $query Extra query args.
	 * @return array|WP_Error Concatenated results.
	 */
	public function get_all( $path, array $query = array() ) {
		$all      = array();
		$per_page = 50;
		for ( $page = 1; $page <= 20; $page++ ) {
			$result = $this->get(
				$path,
				array_merge(
					$query,
					array(
						'page'     => $page,
						'per_page' => $per_page,
					)
				)
			);
			if ( is_wp_error( $result ) ) {
				return $result;
			}
			$all   = array_merge( $all, array_values( $result ) );
			$info  = $this->last_info;
			$total = isset( $info['total_pages'] ) ? (int) $info['total_pages'] : 0;
			if ( $total > 0 ) {
				if ( $page >= $total ) {
					break;
				}
			} elseif ( count( $result ) < $per_page ) {
				break;
			}
		}
		return $all;
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
	 * Run a GraphQL analytics query. The GraphQL endpoint uses a different
	 * envelope than the REST API ({data, errors} rather than {success,
	 * result}), so it gets its own path here.
	 *
	 * @param string $query     GraphQL query document.
	 * @param array  $variables Query variables.
	 * @return array|WP_Error The `data` member on success.
	 */
	public function graphql( $query, array $variables = array() ) {
		$args = array(
			'method'      => 'POST',
			'timeout'     => 20,
			'redirection' => 0,
			'headers'     => array(
				'Authorization' => 'Bearer ' . $this->token,
				'Content-Type'  => 'application/json',
			),
			'body'        => wp_json_encode(
				array(
					'query'     => $query,
					'variables' => $variables,
				)
			),
		);

		$response = call_user_func( $this->transport, self::BASE . '/graphql', $args );
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
					__( 'Cloudflare returned an unreadable GraphQL response (HTTP %d).', 'blt-secure' ),
					$status
				)
			);
		}

		if ( 401 === $status || 403 === $status ) {
			return new WP_Error(
				403 === $status ? 'blt_cf_scope' : 'blt_cf_auth',
				__( 'The Cloudflare token cannot read analytics for this zone.', 'blt-secure' ),
				array( 'status' => $status )
			);
		}

		if ( ! empty( $decoded['errors'] ) ) {
			$first   = (array) $decoded['errors'][0];
			$message = isset( $first['message'] ) ? (string) $first['message'] : __( 'Cloudflare GraphQL error.', 'blt-secure' );
			$code    = ( false !== stripos( $message, 'permission' ) || false !== stripos( $message, 'not authorized' ) || false !== stripos( $message, 'does not have access' ) ) ? 'blt_cf_scope' : 'blt_cf_error';
			return new WP_Error( $code, $message, array( 'status' => $status ) );
		}

		return isset( $decoded['data'] ) && is_array( $decoded['data'] ) ? $decoded['data'] : array();
	}

	/**
	 * Verify the token itself (needs no extra scopes).
	 *
	 * @return true|WP_Error
	 */
	public function verify_token() {
		$result = $this->get( '/user/tokens/verify' );
		if ( ! is_wp_error( $result ) ) {
			return true;
		}

		// /user/tokens/verify is the user-token endpoint; an account-owned
		// token may be rejected there while being perfectly valid. Fall back to
		// a minimal zone read, which any working zone-scoped token can do.
		if ( in_array( $result->get_error_code(), array( 'blt_cf_auth', 'blt_cf_validation', 'blt_cf_error' ), true ) ) {
			$probe = $this->get( '/zones', array( 'per_page' => 1 ) );
			if ( ! is_wp_error( $probe ) ) {
				return true;
			}
		}

		return $result;
	}

	/**
	 * Discover the zone for a host by stripping subdomain labels until a
	 * zone name matches (site.example.co.uk → example.co.uk).
	 *
	 * @param string $host Hostname from home_url.
	 * @return array|WP_Error Zone object (id, name, account.id, plan).
	 */
	public function discover_zone( $host ) {
		$labels    = explode( '.', strtolower( (string) $host ) );
		$remaining = count( $labels );

		while ( $remaining >= 2 ) {
			$candidate = implode( '.', $labels );
			$result    = $this->get(
				'/zones',
				array(
					'name'     => $candidate,
					'per_page' => 50,
				)
			);

			if ( is_wp_error( $result ) ) {
				return $result;
			}
			// Prefer an active zone over a pending/moved duplicate of the name.
			$found = null;
			foreach ( $result as $zone ) {
				if ( ! is_array( $zone ) || empty( $zone['id'] ) ) {
					continue;
				}
				if ( null === $found ) {
					$found = $zone;
				}
				if ( isset( $zone['status'] ) && 'active' === $zone['status'] ) {
					$found = $zone;
					break;
				}
			}
			if ( null !== $found ) {
				return $found;
			}

			array_shift( $labels );
			--$remaining;
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
			'method'              => $method,
			'timeout'             => 15,
			'redirection'         => 0, // The Bearer token must never follow a redirect off api.cloudflare.com.
			'limit_response_size' => 5 * 1024 * 1024,
			'headers'             => array(
				'Authorization' => 'Bearer ' . $this->token,
				'Content-Type'  => 'application/json',
			),
		);
		if ( null !== $body ) {
			$args['body'] = wp_json_encode( $body );
		}

		$this->last_info = array();
		$attempt         = 0;

		do {
			$response = call_user_func( $this->transport, self::BASE . $path, $args );

			if ( is_wp_error( $response ) ) {
				return new WP_Error( 'blt_cf_http', $response->get_error_message() );
			}

			$status = (int) wp_remote_retrieve_response_code( $response );

			// 429: honour Retry-After, bounded, and only where sleeping is allowed.
			if ( 429 === $status && $attempt < self::MAX_RETRIES && $this->may_retry() ) {
				$wait = (int) self::header_value( $response, 'retry-after' );
				if ( $wait < 1 ) {
					$wait = 1 << $attempt; // 1s, 2s.
				}
				call_user_func( $this->sleeper, min( self::MAX_RETRY_WAIT, $wait ) );
				++$attempt;
				continue;
			}

			break;
		} while ( true );

		$decoded = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( ! is_array( $decoded ) ) {
			if ( 429 === $status ) {
				return new WP_Error( 'blt_cf_rate_limited', __( 'Cloudflare is rate limiting this site\'s API requests. Wait a minute and retry.', 'blt-secure' ), array( 'status' => 429 ) );
			}
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
			$this->last_info = isset( $decoded['result_info'] ) && is_array( $decoded['result_info'] ) ? $decoded['result_info'] : array();
			return isset( $decoded['result'] ) ? (array) $decoded['result'] : array();
		}

		return $this->map_error( $status, isset( $decoded['errors'] ) ? (array) $decoded['errors'] : array() );
	}

	/**
	 * Case-insensitive response header lookup that works with both plain
	 * arrays and WordPress's CaseInsensitiveDictionary.
	 *
	 * @param mixed  $response Transport response.
	 * @param string $name Lowercase header name.
	 * @return string
	 */
	private static function header_value( $response, $name ) {
		if ( ! is_array( $response ) || ! isset( $response['headers'] ) ) {
			return '';
		}
		$headers = $response['headers'];
		if ( is_array( $headers ) ) {
			foreach ( $headers as $key => $value ) {
				if ( strtolower( (string) $key ) === $name ) {
					return is_array( $value ) ? (string) reset( $value ) : (string) $value;
				}
			}
			return '';
		}
		if ( $headers instanceof ArrayAccess && isset( $headers[ $name ] ) ) {
			return (string) $headers[ $name ];
		}
		return '';
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
		$data    = array(
			'status'  => $status,
			'cf_code' => $code,
		);

		// Throttled (retries, where allowed, are already exhausted).
		if ( 429 === $status ) {
			return new WP_Error( 'blt_cf_rate_limited', $message, $data );
		}

		// Token invalid / expired / malformed.
		if ( 401 === $status || in_array( $code, array( 1000, 10001, 6003, 6111 ), true ) ) {
			return new WP_Error( 'blt_cf_auth', $message, $data );
		}

		// Plan/entitlement refusals. Checked BEFORE the generic 403 so a
		// "not available on your plan" refusal is not reported as a missing
		// token permission. Word-boundary match: "explanation" is not a plan.
		if ( in_array( $code, array( 20040, 20041 ), true ) || 1 === preg_match( '/\bplan\b|entitle|upgrade/i', $message ) ) {
			return new WP_Error( 'blt_cf_plan', $message, $data );
		}

		// Authorized token, missing permission. Cloudflare returns code 10000
		// ("Authentication error") with HTTP 403 for an insufficient token
		// scope, so 403 wins over the 10000 code; a 10000 without 403 is auth.
		if ( 403 === $status || 10014 === $code ) {
			return new WP_Error( 'blt_cf_scope', $message, $data );
		}
		if ( 10000 === $code ) {
			return new WP_Error( 'blt_cf_auth', $message, $data );
		}

		// Ruleset engine validation.
		if ( in_array( $code, array( 10021, 20217 ), true ) || 400 === $status ) {
			return new WP_Error( 'blt_cf_validation', $message, $data );
		}

		return new WP_Error( 'blt_cf_error', $message, $data );
	}
}
