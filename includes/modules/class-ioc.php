<?php
/**
 * IOC sync module: pull threat-intel feeds into a Cloudflare IP List.
 *
 * Reads the enabled ip-list / ioc-json feeds from the feed catalogue,
 * fetches and parses them, then pushes the merged indicator set to an
 * account IP List that a single custom firewall rule blocks. Runs on
 * WP-Cron; no-ops quietly when no CF token is configured or no feeds are
 * enabled, so it is safe to ship on by default.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Orchestrates feed fetch → parse → Cloudflare IP List sync.
 */
class Blt_Secure_Ioc implements Blt_Secure_Module {

	const RESULTS_OPTION = 'blt_secure_ioc_state';
	const CRON_HOOK      = 'blt_secure_ioc_sync';
	const AJAX_RUN       = 'blt_secure_ioc_sync_run';

	/**
	 * Cloudflare custom lists cap at 10,000 items per account on Free, Pro and
	 * Business (shared by every list in the account; 500,000 on Enterprise).
	 */
	const MAX_IPS = 10000;

	/**
	 * Settings.
	 *
	 * @var Blt_Secure_Options
	 */
	private $options;

	/**
	 * Credential store (for the Cloudflare token).
	 *
	 * @var Blt_Secure_Credential_Store
	 */
	private $credentials;

	/**
	 * Optional alerting sink.
	 *
	 * @var Blt_Secure_Alerting|null
	 */
	private $alerting;

	/**
	 * Constructor.
	 *
	 * @param Blt_Secure_Options          $options     Settings access.
	 * @param Blt_Secure_Credential_Store $credentials Credential store.
	 * @param Blt_Secure_Alerting|null    $alerting    Alerting sink.
	 */
	public function __construct( Blt_Secure_Options $options, Blt_Secure_Credential_Store $credentials, $alerting = null ) {
		$this->options     = $options;
		$this->credentials = $credentials;
		$this->alerting    = $alerting;
	}

	/**
	 * Module id.
	 *
	 * @return string
	 */
	public function id() {
		return 'ioc';
	}

	/**
	 * Defaults.
	 *
	 * @return array
	 */
	public function defaults() {
		return array(
			'enabled'  => true,
			'schedule' => true,
		);
	}

	/**
	 * Enabled?
	 *
	 * @return bool
	 */
	public function is_enabled() {
		return (bool) $this->options->get( 'ioc', 'enabled', true );
	}

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function boot() {
		add_action( self::CRON_HOOK, array( $this, 'run_sync' ) );

		if ( $this->options->get( 'ioc', 'schedule', true ) ) {
			add_action( 'admin_init', array( $this, 'ensure_scheduled' ) );
		}

		if ( is_admin() ) {
			add_action( 'wp_ajax_' . self::AJAX_RUN, array( $this, 'ajax_run' ) );
		}
	}

	/**
	 * Sanitize section.
	 *
	 * @param array $input   Raw input.
	 * @param array $current Current values.
	 * @return array
	 */
	public function sanitize( $input, $current ) {
		return array(
			'enabled'  => ! empty( $input['enabled'] ),
			'schedule' => ! empty( $input['schedule'] ),
		);
	}

	/**
	 * Ensure the daily sync is scheduled.
	 *
	 * @return void
	 */
	public function ensure_scheduled() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + ( 4 * HOUR_IN_SECONDS ), 'daily', self::CRON_HOOK );
		}
	}

	/**
	 * Fold fetched feed responses into one indicator set.
	 *
	 * A feed counts as FAILED on a transport error, a non-200 status, or a
	 * body that yields no usable entries (a changed format must not silently
	 * shrink the blocklist). Pure function (unit-tested).
	 *
	 * @param array[] $fetched Each: id, format, code, body, error.
	 * @return array{ips:string[],per_feed:array,failed:array}
	 */
	public static function collect( array $fetched ) {
		$ips      = array();
		$per_feed = array();
		$failed   = array();

		foreach ( $fetched as $item ) {
			$id    = isset( $item['id'] ) ? (string) $item['id'] : '';
			$error = isset( $item['error'] ) ? (string) $item['error'] : '';
			$code  = isset( $item['code'] ) ? (int) $item['code'] : 0;

			if ( '' !== $error ) {
				$failed[ $id ] = $error;
				continue;
			}
			if ( 200 !== $code ) {
				$failed[ $id ] = sprintf( 'HTTP %d', $code );
				continue;
			}

			$parsed = Blt_Secure_Ioc_Parser::parse( isset( $item['format'] ) ? $item['format'] : '', isset( $item['body'] ) ? (string) $item['body'] : '' );
			if ( empty( $parsed ) ) {
				$failed[ $id ] = 'no usable entries';
				continue;
			}

			$per_feed[ $id ] = count( $parsed );
			$ips             = array_merge( $ips, $parsed );
		}

		return array(
			'ips'      => array_values( array_unique( $ips ) ),
			'per_feed' => $per_feed,
			'failed'   => $failed,
		);
	}

	/**
	 * Addresses and ranges that must never be blocked: this server, the admin
	 * running a manual sync, and Cloudflare's own edge.
	 *
	 * @return array{ips:string[],ranges:string[]}
	 */
	private function protected_targets() {
		$ips = array();
		if ( isset( $_SERVER['SERVER_ADDR'] ) ) {
			$ips[] = sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ) );
		}
		// A manual sync runs in the admin's own request; cron has no admin IP.
		if ( is_admin() && isset( $_SERVER['REMOTE_ADDR'] ) ) {
			$ips[] = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
		}

		$ranges = array();
		if ( class_exists( 'Blt_Secure_Ip_Resolver' ) ) {
			$stored = get_option( Blt_Secure_Ip_Resolver::IPS_OPTION, null );
			$ranges = ( is_array( $stored ) && ! empty( $stored ) ) ? $stored : Blt_Secure_Ip_Resolver::CF_RANGES;
		}

		/**
		 * Filter the addresses the IOC sync must never block (e.g. an office
		 * IP, a monitoring service, a payment webhook sender).
		 *
		 * @param string[] $ips Single IPs and/or CIDR ranges.
		 */
		$extra = apply_filters( 'blt_secure_ioc_never_block', array() );
		foreach ( (array) $extra as $item ) {
			if ( false !== strpos( (string) $item, '/' ) ) {
				$ranges[] = (string) $item;
			} else {
				$ips[] = (string) $item;
			}
		}

		return array(
			'ips'    => array_values( array_filter( $ips ) ),
			'ranges' => array_values( array_filter( $ranges ) ),
		);
	}

	/**
	 * Fetch feeds, parse, and push indicators to Cloudflare.
	 *
	 * @return array Stored status payload.
	 */
	public function run_sync() {
		require_once BLT_SECURE_DIR . 'includes/feeds/class-ioc-parser.php';
		require_once BLT_SECURE_DIR . 'includes/cloudflare/class-cloudflare-api.php';

		$token = Blt_Secure_Cloudflare_Api::resolve_token( $this->credentials );
		if ( '' === $token ) {
			return $this->store( array( 'status' => 'no_token' ) );
		}

		$feeds = array_merge(
			Blt_Secure_Feeds::by_format( 'ip-list' ),
			Blt_Secure_Feeds::by_format( 'ioc-json' )
		);
		if ( empty( $feeds ) ) {
			return $this->store( array( 'status' => 'no_feeds' ) );
		}

		$fetched = array();
		foreach ( $feeds as $feed ) {
			$item = array(
				'id'     => $feed['id'],
				'format' => $feed['format'],
				'code'   => 0,
				'body'   => '',
				'error'  => '',
			);
			if ( 0 !== stripos( $feed['url'], 'https://' ) ) {
				$item['error'] = 'feed URL is not https';
				$fetched[]     = $item;
				continue;
			}
			$response = wp_remote_get(
				$feed['url'],
				array(
					'timeout'             => 25,
					'redirection'         => 2,
					'limit_response_size' => 8 * 1024 * 1024,
					'user-agent'          => 'BLT-Secure-IOC/' . BLT_SECURE_VERSION,
				)
			);
			if ( is_wp_error( $response ) ) {
				$item['error'] = $response->get_error_message();
			} else {
				$item['code'] = (int) wp_remote_retrieve_response_code( $response );
				$item['body'] = wp_remote_retrieve_body( $response );
			}
			$fetched[] = $item;
		}

		$collected = self::collect( $fetched );

		// Never REPLACE the Cloudflare list from a partial picture: one failed
		// feed would silently shrink the blocklist.
		if ( ! empty( $collected['failed'] ) ) {
			$parts = array();
			foreach ( $collected['failed'] as $id => $reason ) {
				$parts[] = $id . ': ' . $reason;
			}
			return $this->store(
				array(
					'status' => 'error',
					'error'  => sprintf(
						/* translators: %s: failed feeds and reasons */
						__( 'A threat-intel feed failed (%s), so the Cloudflare list was left unchanged.', 'blt-secure' ),
						implode( '; ', $parts )
					),
				)
			);
		}

		$ips = $collected['ips'];

		// Drop anything that would block this server, the admin or Cloudflare's edge.
		$protected = $this->protected_targets();
		$before    = count( $ips );
		$ips       = Blt_Secure_Ioc_Parser::drop_protected( $ips, $protected['ips'], $protected['ranges'] );
		$dropped   = $before - count( $ips );

		/**
		 * Filter the maximum number of indicators pushed to Cloudflare. The
		 * item quota is shared by every custom list in the account.
		 *
		 * @param int $max Maximum items.
		 */
		$max       = max( 1, (int) apply_filters( 'blt_secure_ioc_max_items', self::MAX_IPS ) );
		$truncated = count( $ips ) > $max;
		$ips       = Blt_Secure_Ioc_Parser::prioritize_for_cap( $ips, $max );

		if ( empty( $ips ) ) {
			return $this->store(
				array(
					'status' => 'empty',
					'error'  => '',
				)
			);
		}

		require_once BLT_SECURE_DIR . 'includes/cloudflare/class-cloudflare-api.php';
		require_once BLT_SECURE_DIR . 'includes/cloudflare/class-cloudflare-state.php';
		require_once BLT_SECURE_DIR . 'includes/cloudflare/rule-definitions.php';
		require_once BLT_SECURE_DIR . 'includes/cloudflare/class-cloudflare-deployer.php';

		$deployer = new Blt_Secure_Cloudflare_Deployer(
			new Blt_Secure_Cloudflare_Api( $token ),
			new Blt_Secure_Cloudflare_State(),
			(string) wp_parse_url( home_url(), PHP_URL_HOST )
		);
		$result   = $deployer->sync_ioc_list( $ips );

		if ( is_wp_error( $result ) ) {
			$message = $result->get_error_message();
			if ( 'blt_cf_scope' === $result->get_error_code() ) {
				$message .= ' ' . __( 'Add the "Account → Account Filter Lists: Edit" permission to your Cloudflare token, then retry.', 'blt-secure' );
			}
			return $this->store(
				array(
					'status' => 'error',
					'error'  => $message,
				)
			);
		}

		if ( $this->alerting ) {
			$this->alerting->notify( 'ioc_sync', array( 'count' => count( $ips ) ) );
		}

		// Record what this refresh changed relative to the last one.
		( new Blt_Secure_Feed_Changelog() )->record( $ips, $collected['per_feed'], $this->alerting );

		return $this->store(
			array(
				'status'    => 'ok',
				'count'     => count( $ips ),
				'per_feed'  => $collected['per_feed'],
				'dropped'   => $dropped,
				'truncated' => $truncated,
				'pending'   => ! empty( $result['list_pending'] ),
			)
		);
	}

	/**
	 * Persist and return the sync status (stamped with the time).
	 *
	 * @param array $payload Status fields.
	 * @return array
	 */
	private function store( array $payload ) {
		$payload['time'] = time();
		update_option( self::RESULTS_OPTION, $payload, false );
		return $payload;
	}

	/**
	 * The most recent stored sync status, or null.
	 *
	 * @return array|null
	 */
	public function latest() {
		$payload = get_option( self::RESULTS_OPTION, null );
		return is_array( $payload ) ? $payload : null;
	}

	/**
	 * AJAX: run a sync now and return the status.
	 *
	 * @return void
	 */
	public function ajax_run() {
		check_ajax_referer( 'blt_secure_cf' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'blt-secure' ) ), 403 );
		}

		$payload = $this->run_sync();
		if ( isset( $payload['status'] ) && 'error' === $payload['status'] ) {
			wp_send_json_error( array( 'message' => isset( $payload['error'] ) ? $payload['error'] : __( 'Sync failed.', 'blt-secure' ) ) );
		}
		wp_send_json_success( $payload );
	}
}
