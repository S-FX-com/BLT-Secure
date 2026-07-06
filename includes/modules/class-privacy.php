<?php
/**
 * Privacy hardening: hide WP version, block user enumeration.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Removes version fingerprints and closes the two classic user-enumeration
 * doors: ?author=N (including its canonical-redirect leak) and the REST
 * users endpoint for logged-out requests.
 */
class Blt_Secure_Privacy implements Blt_Secure_Module {

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
		return 'privacy';
	}

	/**
	 * Defaults.
	 *
	 * @return array
	 */
	public function defaults() {
		return array(
			'hide_version' => true,
			'block_enum'   => true,
		);
	}

	/**
	 * Enabled when either sub-feature is on.
	 *
	 * @return bool
	 */
	public function is_enabled() {
		return $this->options->get( 'privacy', 'hide_version', true )
			|| $this->options->get( 'privacy', 'block_enum', true );
	}

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function boot() {
		if ( $this->options->get( 'privacy', 'hide_version', true ) ) {
			add_filter( 'the_generator', '__return_empty_string' );
			add_filter( 'style_loader_src', array( $this, 'strip_core_ver' ) );
			add_filter( 'script_loader_src', array( $this, 'strip_core_ver' ) );
		}

		if ( $this->options->get( 'privacy', 'block_enum', true ) ) {
			add_action( 'template_redirect', array( $this, 'block_author_query' ), 0 );
			add_filter( 'redirect_canonical', array( $this, 'block_author_canonical' ), 10, 2 );
			add_filter( 'rest_pre_dispatch', array( $this, 'block_rest_users' ), 10, 3 );
		}
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
			'hide_version' => ! empty( $input['hide_version'] ),
			'block_enum'   => ! empty( $input['block_enum'] ),
		);
	}

	/**
	 * Remove ?ver= only when it equals the core version — plugin/theme
	 * versions are legitimate cache busters and stay.
	 *
	 * @param string $src Asset URL.
	 * @return string
	 */
	public function strip_core_ver( $src ) {
		global $wp_version;

		if ( is_string( $src ) && false !== strpos( $src, 'ver=' ) ) {
			$query = wp_parse_url( $src, PHP_URL_QUERY );
			if ( $query ) {
				parse_str( $query, $args );
				if ( isset( $args['ver'] ) && $args['ver'] === $wp_version ) {
					$src = remove_query_arg( 'ver', $src );
				}
			}
		}

		return $src;
	}

	/**
	 * 404 numeric ?author= requests from visitors.
	 *
	 * @return void
	 */
	public function block_author_query() {
		if ( is_user_logged_in() || ! is_author() ) {
			return;
		}

		// Only numeric probes — real author archive links keep working.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['author'] ) && is_numeric( wp_unslash( $_GET['author'] ) ) ) {
			$this->send_404();
		}
	}

	/**
	 * The canonical redirect from ?author=1 to /author/username/ IS the
	 * enumeration — suppress it for visitors.
	 *
	 * @param string $redirect_url Proposed redirect.
	 * @param string $requested_url Original URL.
	 * @return string|false
	 */
	public function block_author_canonical( $redirect_url, $requested_url ) {
		if ( is_user_logged_in() ) {
			return $redirect_url;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['author'] ) && is_numeric( wp_unslash( $_GET['author'] ) ) ) {
			$this->send_404();
		}

		return $redirect_url;
	}

	/**
	 * Require authentication for the REST users endpoints.
	 *
	 * @param mixed           $result Dispatch short-circuit value.
	 * @param WP_REST_Server  $server Server.
	 * @param WP_REST_Request $request Request.
	 * @return mixed
	 */
	public function block_rest_users( $result, $server, $request ) {
		if ( null !== $result ) {
			return $result;
		}

		$route = $request->get_route();
		if ( preg_match( '#^/wp/v2/users\b#', $route ) && ! is_user_logged_in() ) {
			return new WP_Error(
				'rest_forbidden',
				__( 'Sorry, you are not allowed to list users.', 'blt-secure' ),
				array( 'status' => 401 )
			);
		}

		return $result;
	}

	/**
	 * Render a real 404.
	 *
	 * @return void
	 */
	private function send_404() {
		global $wp_query;

		if ( $wp_query instanceof WP_Query ) {
			$wp_query->set_404();
		}
		status_header( 404 );
		nocache_headers();

		$template = get_404_template();
		if ( $template ) {
			include $template;
		}
		exit;
	}
}
