<?php
/**
 * Client IP resolution, Cloudflare-aware.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Resolves the real client IP.
 *
 * CF-Connecting-IP is honored only when REMOTE_ADDR is actually inside
 * Cloudflare's published ranges — otherwise the header is attacker-supplied
 * and trusting it lets one client spoof lockouts for everyone.
 * X-Forwarded-For is never trusted (filterable for hosts that need it).
 *
 * The shipped static range list is the real dependency; the weekly WP-Cron
 * refresh from api.cloudflare.com/client/v4/ips is a bonus that may never
 * fire on low-traffic sites.
 */
class Blt_Secure_Ip_Resolver {

	const IPS_OPTION = 'blt_secure_cf_ips';

	/**
	 * Cloudflare published ranges (fallback snapshot).
	 *
	 * @var string[]
	 */
	const CF_RANGES = array(
		'173.245.48.0/20',
		'103.21.244.0/22',
		'103.22.200.0/22',
		'103.31.4.0/22',
		'141.101.64.0/18',
		'108.162.192.0/18',
		'190.93.240.0/20',
		'188.114.96.0/20',
		'197.234.240.0/22',
		'198.41.128.0/17',
		'162.158.0.0/15',
		'104.16.0.0/13',
		'104.24.0.0/14',
		'172.64.0.0/13',
		'131.0.72.0/22',
		'2400:cb00::/32',
		'2606:4700::/32',
		'2803:f800::/32',
		'2405:b500::/32',
		'2405:8100::/32',
		'2a06:98c0::/29',
		'2c0f:f248::/32',
	);

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
	 * Register the range-refresh cron handler.
	 *
	 * @return void
	 */
	public function boot() {
		add_action( 'blt_secure_refresh_cf_ips', array( $this, 'refresh_ranges' ) );
	}

	/**
	 * Resolve the client IP for this request.
	 *
	 * @return string IP address, or '' when indeterminable.
	 */
	public function resolve() {
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$cf_ip  = isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) : '';

		$mode = $this->options->get( 'advanced', 'trust_cf_header', 'auto' );

		$use_cf = false;
		if ( '' !== $cf_ip && false !== filter_var( $cf_ip, FILTER_VALIDATE_IP ) ) {
			if ( 'always' === $mode ) {
				$use_cf = true;
			} elseif ( 'auto' === $mode ) {
				$use_cf = self::ip_in_ranges( $remote, $this->ranges() );
			}
		}

		/**
		 * Filter the resolved client IP (e.g. to trust a different proxy header).
		 *
		 * @param string $ip Resolved IP.
		 * @param string $remote REMOTE_ADDR.
		 * @param string $cf_ip CF-Connecting-IP header value.
		 */
		return apply_filters( 'blt_secure_client_ip', $use_cf ? $cf_ip : $remote, $remote, $cf_ip );
	}

	/**
	 * Current Cloudflare ranges: refreshed copy when present, else snapshot.
	 *
	 * @return string[]
	 */
	public function ranges() {
		$stored = get_option( self::IPS_OPTION, null );
		$ranges = ( is_array( $stored ) && ! empty( $stored ) ) ? $stored : self::CF_RANGES;

		/**
		 * Filter the trusted Cloudflare CIDR ranges.
		 *
		 * @param string[] $ranges CIDR strings.
		 */
		return apply_filters( 'blt_secure_cloudflare_ips', $ranges );
	}

	/**
	 * WP-Cron: refresh ranges from the public Cloudflare endpoint (no token).
	 *
	 * @return void
	 */
	public function refresh_ranges() {
		$response = wp_remote_get( 'https://api.cloudflare.com/client/v4/ips', array( 'timeout' => 15 ) );
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return; // Keep whatever we have.
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $body['success'] ) || empty( $body['result'] ) ) {
			return;
		}

		$ranges = array_merge(
			isset( $body['result']['ipv4_cidrs'] ) ? (array) $body['result']['ipv4_cidrs'] : array(),
			isset( $body['result']['ipv6_cidrs'] ) ? (array) $body['result']['ipv6_cidrs'] : array()
		);

		$ranges = array_values( array_filter( array_map( 'sanitize_text_field', $ranges ), array( __CLASS__, 'is_valid_cidr' ) ) );

		if ( count( $ranges ) >= 10 ) { // Sanity floor — never replace a good list with a truncated one.
			update_option( self::IPS_OPTION, $ranges, false );
		}
	}

	/**
	 * Whether an IP falls inside any of the CIDR ranges. Pure function.
	 *
	 * @param string   $ip IP address.
	 * @param string[] $ranges CIDR strings.
	 * @return bool
	 */
	public static function ip_in_ranges( $ip, array $ranges ) {
		$packed = @inet_pton( (string) $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $packed ) {
			return false;
		}

		foreach ( $ranges as $cidr ) {
			if ( self::ip_in_cidr_packed( $packed, $cidr ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * CIDR validity check. Pure function.
	 *
	 * @param string $cidr Candidate CIDR.
	 * @return bool
	 */
	public static function is_valid_cidr( $cidr ) {
		if ( ! is_string( $cidr ) || false === strpos( $cidr, '/' ) ) {
			return false;
		}
		list( $net, $bits ) = explode( '/', $cidr, 2 );

		$packed = @inet_pton( $net ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $packed || ! ctype_digit( $bits ) ) {
			return false;
		}

		return (int) $bits <= ( strlen( $packed ) * 8 );
	}

	/**
	 * Binary-mask CIDR match (no extensions beyond core inet_pton).
	 *
	 * @param string $packed inet_pton()-packed IP.
	 * @param string $cidr CIDR string.
	 * @return bool
	 */
	private static function ip_in_cidr_packed( $packed, $cidr ) {
		if ( ! is_string( $cidr ) || false === strpos( $cidr, '/' ) ) {
			return false;
		}
		list( $net, $bits ) = explode( '/', $cidr, 2 );

		$net_packed = @inet_pton( $net ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		$bits       = (int) $bits;

		// Family mismatch (v4 vs v6) → packed lengths differ.
		if ( false === $net_packed || strlen( $net_packed ) !== strlen( $packed ) ) {
			return false;
		}
		if ( $bits < 0 || $bits > strlen( $packed ) * 8 ) {
			return false;
		}

		$full_bytes = intdiv( $bits, 8 );
		$rem_bits   = $bits % 8;

		if ( $full_bytes > 0 && 0 !== substr_compare( $packed, $net_packed, 0, $full_bytes ) ) {
			return false;
		}

		if ( $rem_bits > 0 ) {
			$mask = 0xFF << ( 8 - $rem_bits ) & 0xFF;
			if ( ( ord( $packed[ $full_bytes ] ) & $mask ) !== ( ord( $net_packed[ $full_bytes ] ) & $mask ) ) {
				return false;
			}
		}

		return true;
	}
}
