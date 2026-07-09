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
	 * Cloudflare IP Lists cap at 10k items on the free tier.
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
	 * Fetch feeds, parse, and push indicators to Cloudflare.
	 *
	 * @return array Stored status payload.
	 */
	public function run_sync() {
		require_once BLT_SECURE_DIR . 'includes/feeds/class-ioc-parser.php';

		$token = $this->credentials->get( 'cf_token' );
		if ( ! is_string( $token ) || '' === $token ) {
			return $this->store( array( 'status' => 'no_token' ) );
		}

		$feeds = array_merge(
			Blt_Secure_Feeds::by_format( 'ip-list' ),
			Blt_Secure_Feeds::by_format( 'ioc-json' )
		);
		if ( empty( $feeds ) ) {
			return $this->store( array( 'status' => 'no_feeds' ) );
		}

		$ips        = array();
		$per_feed   = array();
		$feed_error = '';
		foreach ( $feeds as $feed ) {
			$response = wp_remote_get(
				$feed['url'],
				array(
					'timeout'    => 25,
					'user-agent' => 'BLT-Secure-IOC/' . BLT_SECURE_VERSION,
				)
			);
			if ( is_wp_error( $response ) ) {
				$feed_error = $response->get_error_message();
				continue;
			}
			$parsed                  = Blt_Secure_Ioc_Parser::parse( $feed['format'], wp_remote_retrieve_body( $response ) );
			$per_feed[ $feed['id'] ] = count( $parsed );
			$ips                     = array_merge( $ips, $parsed );
		}

		$ips = array_values( array_unique( $ips ) );
		if ( count( $ips ) > self::MAX_IPS ) {
			$ips = array_slice( $ips, 0, self::MAX_IPS );
		}

		if ( empty( $ips ) ) {
			return $this->store(
				array(
					'status' => 'empty',
					'error'  => $feed_error,
				)
			);
		}

		require_once BLT_SECURE_DIR . 'includes/cloudflare/class-cloudflare-api.php';
		require_once BLT_SECURE_DIR . 'includes/cloudflare/class-cloudflare-state.php';
		require_once BLT_SECURE_DIR . 'includes/cloudflare/rule-definitions.php';
		require_once BLT_SECURE_DIR . 'includes/cloudflare/class-cloudflare-deployer.php';

		$deployer = new Blt_Secure_Cloudflare_Deployer(
			new Blt_Secure_Cloudflare_Api( $token ),
			new Blt_Secure_Cloudflare_State()
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
		( new Blt_Secure_Feed_Changelog() )->record( $ips, $per_feed, $this->alerting );

		return $this->store(
			array(
				'status'   => 'ok',
				'count'    => count( $ips ),
				'per_feed' => $per_feed,
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
