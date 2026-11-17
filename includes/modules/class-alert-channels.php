<?php
/**
 * Alert channels: deliver security events to email and Slack.
 *
 * Subscribes to the blt_secure_alert action (fired by Blt_Secure_Alerting for
 * every recorded event) and forwards the high-signal ones to the configured
 * channels. A per-type throttle prevents a burst (e.g. repeated lockouts)
 * from flooding an inbox or Slack channel.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Email + Slack notifier for security events.
 */
class Blt_Secure_Alert_Channels implements Blt_Secure_Module {

	/**
	 * Minimum seconds between notifications of the same event type.
	 */
	const THROTTLE_SECONDS = 900;

	/**
	 * Cron hook that performs the actual mail / Slack delivery.
	 */
	const DELIVER_HOOK = 'blt_secure_alert_deliver';

	/**
	 * Hard cap on queued deliveries per throttle window, across all types.
	 */
	const BUDGET_MAX = 20;

	/**
	 * Settings.
	 *
	 * @var Blt_Secure_Options
	 */
	private $options;

	/**
	 * Credential store (Slack webhook URL).
	 *
	 * @var Blt_Secure_Credential_Store
	 */
	private $credentials;

	/**
	 * Constructor.
	 *
	 * @param Blt_Secure_Options          $options     Settings access.
	 * @param Blt_Secure_Credential_Store $credentials Credential store.
	 */
	public function __construct( Blt_Secure_Options $options, Blt_Secure_Credential_Store $credentials ) {
		$this->options     = $options;
		$this->credentials = $credentials;
	}

	/**
	 * Module id.
	 *
	 * @return string
	 */
	public function id() {
		return 'alerts';
	}

	/**
	 * Defaults.
	 *
	 * @return array
	 */
	public function defaults() {
		return array(
			'email_enabled' => true,
			'email_to'      => '',
			'slack_enabled' => false,
		);
	}

	/**
	 * Always boots — the dispatch hook is cheap and self-gates on channels.
	 *
	 * @return bool
	 */
	public function is_enabled() {
		return true;
	}

	/**
	 * Register the dispatch hook.
	 *
	 * @return void
	 */
	public function boot() {
		add_action( 'blt_secure_alert', array( $this, 'dispatch' ), 10, 2 );
		add_action( self::DELIVER_HOOK, array( $this, 'deliver' ), 10, 2 );
	}

	/**
	 * Sanitize section.
	 *
	 * @param array $input   Raw input.
	 * @param array $current Current values.
	 * @return array
	 */
	public function sanitize( $input, $current ) {
		$email_to = isset( $input['email_to'] ) ? sanitize_email( $input['email_to'] ) : '';
		return array(
			'email_enabled' => ! empty( $input['email_enabled'] ),
			'email_to'      => $email_to ? $email_to : '',
			'slack_enabled' => ! empty( $input['slack_enabled'] ),
		);
	}

	// ---------------------------------------------------------------------
	// Pure helpers (unit-tested).
	// ---------------------------------------------------------------------

	/**
	 * Event types worth notifying on (high-signal; excludes routine activity
	 * like plugin activations that would otherwise be noisy).
	 *
	 * @return string[]
	 */
	public static function default_types() {
		return array(
			'lockout',
			'blocked_plugin_install',
			'blocked_plugin_deactivated',
			'blocked_upload',
			'malware_findings',
			'malware_file_deleted',
			'core_integrity_issues',
			'baseline_drift',
			'activity_admin_granted',
			'activity_user_registered',
			'activity_user_updated',
			'twofa_bruteforce',
			'twofa_disabled',
			'twofa_secret_lost',
			'twofa_recovery_used',
			'fleet_command',
		);
	}

	/**
	 * Event types that are deliberately NOT notified (routine activity). Every
	 * type any module emits must be in default_types() or here — the contract
	 * test in tests/test-alert-channels.php enforces it, so a new event slug
	 * is always classified rather than silently never alerted.
	 *
	 * @return string[]
	 */
	public static function routine_types() {
		return array(
			'activity_option_changed',
			'activity_plugin_activated',
			'activity_plugin_deactivated',
			'activity_theme_switched',
			'activity_plugin_deleted',
			'activity_user_deleted',
			'feed_updated',
			'ioc_sync',
			'twofa_enabled',
		);
	}

	/**
	 * Event types where each distinct occurrence matters (a second new
	 * administrator inside the throttle window must not be swallowed), so the
	 * throttle is keyed on the context as well as the type.
	 *
	 * @return string[]
	 */
	public static function per_context_types() {
		return array(
			'activity_admin_granted',
			'activity_user_registered',
			'activity_user_updated',
			'blocked_plugin_install',
			'twofa_disabled',
			'twofa_secret_lost',
			'malware_file_deleted',
		);
	}

	/**
	 * Throttle key for an event.
	 *
	 * @param string $type    Event type.
	 * @param array  $context Event context.
	 * @return string
	 */
	public static function throttle_key( $type, array $context ) {
		$basis = in_array( $type, self::per_context_types(), true )
			? $type . '|' . wp_json_encode( $context )
			: $type;
		return 'blt_sec_alert_' . md5( $basis );
	}

	/**
	 * Bound a context before it is persisted into the cron array (an
	 * autoloaded option): long strings are cut, big arrays truncated.
	 *
	 * @param mixed $value Context value.
	 * @param int   $depth Remaining nesting depth.
	 * @return mixed
	 */
	public static function trim_context( $value, $depth = 3 ) {
		if ( is_string( $value ) ) {
			return strlen( $value ) > 200 ? substr( $value, 0, 200 ) : $value;
		}
		if ( is_array( $value ) ) {
			if ( $depth <= 0 ) {
				return array();
			}
			$out = array();
			foreach ( array_slice( $value, 0, 20, true ) as $key => $item ) {
				$out[ $key ] = self::trim_context( $item, $depth - 1 );
			}
			return $out;
		}
		return is_scalar( $value ) || null === $value ? $value : '';
	}

	/**
	 * Whether a webhook URL may receive alerts: https only, host on the
	 * allowlist (hooks.slack.com by default; filterable for Mattermost etc.).
	 *
	 * @param string $url Webhook URL.
	 * @return bool
	 */
	public static function is_allowed_webhook( $url ) {
		$parts = wp_parse_url( (string) $url );
		if ( ! is_array( $parts ) || empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
			return false;
		}
		if ( 'https' !== strtolower( $parts['scheme'] ) || isset( $parts['user'] ) || isset( $parts['pass'] ) ) {
			return false;
		}
		/**
		 * Filter the hostnames an alert webhook may point at.
		 *
		 * @param string[] $hosts Allowed hostnames.
		 */
		$hosts = (array) apply_filters( 'blt_secure_alert_webhook_hosts', array( 'hooks.slack.com' ) );
		return in_array( strtolower( $parts['host'] ), array_map( 'strtolower', $hosts ), true );
	}

	/**
	 * Whether an event type is in the notify allowlist.
	 *
	 * @param string   $type      Event type.
	 * @param string[] $allowlist Allowed types.
	 * @return bool
	 */
	public static function should_notify( $type, array $allowlist ) {
		return in_array( $type, $allowlist, true );
	}

	/**
	 * A human label for an event type.
	 *
	 * @param string $type Event type.
	 * @return string
	 */
	public static function type_label( $type ) {
		$labels = array(
			'lockout'                    => __( 'Login lockout triggered', 'blt-secure' ),
			'blocked_plugin_install'     => __( 'Blocked a file-manager plugin install', 'blt-secure' ),
			'blocked_plugin_deactivated' => __( 'Deactivated a file-manager plugin', 'blt-secure' ),
			'activity_user_registered'   => __( 'A privileged account was created', 'blt-secure' ),
			'activity_user_updated'      => __( 'Email or password changed on a privileged account', 'blt-secure' ),
			'malware_file_deleted'       => __( 'A flagged file was deleted', 'blt-secure' ),
			'twofa_bruteforce'           => __( '2FA code brute force detected', 'blt-secure' ),
			'twofa_disabled'             => __( 'Two-factor authentication was disabled for a user', 'blt-secure' ),
			'twofa_secret_lost'          => __( 'A 2FA secret became undecryptable', 'blt-secure' ),
			'twofa_recovery_used'        => __( 'A 2FA recovery code was used', 'blt-secure' ),
			'fleet_command'              => __( 'A remote fleet command was executed', 'blt-secure' ),
			'blocked_upload'             => __( 'Blocked a dangerous upload', 'blt-secure' ),
			'malware_findings'           => __( 'Malware signatures found', 'blt-secure' ),
			'core_integrity_issues'      => __( 'Core files failed integrity check', 'blt-secure' ),
			'baseline_drift'             => __( 'Plugin/theme changed unexpectedly', 'blt-secure' ),
			'activity_admin_granted'     => __( 'A new administrator was granted', 'blt-secure' ),
		);
		return isset( $labels[ $type ] ) ? $labels[ $type ] : $type;
	}

	/**
	 * Build the notification subject and body.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string $type    Event type.
	 * @param array  $context Event context.
	 * @param string $site    Site name.
	 * @param string $url     Site URL.
	 * @return array{subject:string,body:string}
	 */
	public static function format( $type, array $context, $site, $url ) {
		$subject = sprintf(
			/* translators: 1: site name, 2: event label */
			__( '[BLT Secure] %1$s: %2$s', 'blt-secure' ),
			$site,
			self::type_label( $type )
		);

		$lines = array(
			self::type_label( $type ),
			'',
			/* translators: %s: site URL */
			sprintf( __( 'Site: %s', 'blt-secure' ), $url ),
			/* translators: %s: event type slug */
			sprintf( __( 'Event: %s', 'blt-secure' ), $type ),
		);
		if ( ! empty( $context ) ) {
			$lines[] = sprintf(
				/* translators: %s: JSON context */
				__( 'Details: %s', 'blt-secure' ),
				wp_json_encode( $context )
			);
		}

		return array(
			'subject' => $subject,
			'body'    => implode( "\n", $lines ),
		);
	}

	/**
	 * Build the Slack webhook payload.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string $text Message text.
	 * @return array
	 */
	public static function slack_payload( $text ) {
		return array( 'text' => (string) $text );
	}

	// ---------------------------------------------------------------------
	// Dispatch.
	// ---------------------------------------------------------------------

	/**
	 * Decide whether an event warrants a notification and, if so, QUEUE it.
	 *
	 * This runs inside the request that raised the event (a failed login, an
	 * upload, a role change), so it does no network or mail I/O: the throttle
	 * is claimed here, the delivery is a single WP-Cron event.
	 *
	 * @param string $type    Event type.
	 * @param array  $context Event context.
	 * @return void
	 */
	public function dispatch( $type, $context = array() ) {
		$context = is_array( $context ) ? $context : array();

		/**
		 * Filter the event types that trigger a channel notification.
		 *
		 * @param string[] $types Allowed event type slugs.
		 */
		$allowlist = apply_filters( 'blt_secure_alert_notify_types', self::default_types() );
		if ( ! self::should_notify( $type, (array) $allowlist ) ) {
			return;
		}

		$email_on = (bool) $this->options->get( 'alerts', 'email_enabled', true );
		$slack_on = (bool) $this->options->get( 'alerts', 'slack_enabled', false );
		if ( ! $email_on && ! $slack_on ) {
			return;
		}

		// Throttle per type (and per context for types where each occurrence
		// matters) to avoid floods.
		$throttle_key = self::throttle_key( $type, $context );
		if ( get_transient( $throttle_key ) ) {
			return;
		}

		// Global budget: varied contexts cannot bypass the throttle to flood.
		$budget = (int) get_transient( 'blt_sec_alert_budget' );
		if ( $budget >= self::BUDGET_MAX ) {
			return;
		}

		/** This filter is documented above. */
		$window = (int) apply_filters( 'blt_secure_alert_throttle', self::THROTTLE_SECONDS, $type );
		$window = max( 1, $window );
		set_transient( $throttle_key, 1, $window );
		set_transient( 'blt_sec_alert_budget', $budget + 1, $window );

		$this->enqueue( $type, self::trim_context( $context ) );
	}

	/**
	 * Schedule the delivery as a one-off cron event and nudge WP-Cron.
	 *
	 * @param string $type    Event type.
	 * @param array  $context Bounded event context.
	 * @return void
	 */
	private function enqueue( $type, array $context ) {
		wp_schedule_single_event( time(), self::DELIVER_HOOK, array( $type, $context ) );
		if ( function_exists( 'spawn_cron' ) ) {
			spawn_cron();
		}
	}

	/**
	 * Cron: send the notification (email and/or Slack).
	 *
	 * @param string $type    Event type.
	 * @param array  $context Event context.
	 * @return void
	 */
	public function deliver( $type, $context = array() ) {
		$context  = is_array( $context ) ? $context : array();
		$email_on = (bool) $this->options->get( 'alerts', 'email_enabled', true );
		$slack_on = (bool) $this->options->get( 'alerts', 'slack_enabled', false );

		$message = self::format(
			$type,
			$context,
			(string) get_bloginfo( 'name' ),
			(string) home_url()
		);

		if ( $email_on ) {
			$to = (string) $this->options->get( 'alerts', 'email_to', '' );
			if ( '' === $to ) {
				$to = (string) get_option( 'admin_email' );
			}
			if ( '' !== $to ) {
				wp_mail( $to, $message['subject'], $message['body'] );
			}
		}

		if ( $slack_on ) {
			$webhook = $this->credentials->get( 'slack_webhook' );
			if ( is_string( $webhook ) && self::is_allowed_webhook( $webhook ) ) {
				wp_safe_remote_post(
					$webhook,
					array(
						'timeout'     => 8,
						'redirection' => 0,
						'headers'     => array( 'Content-Type' => 'application/json' ),
						'body'        => wp_json_encode( self::slack_payload( $message['subject'] . "\n" . $message['body'] ) ),
					)
				);
			}
		}
	}
}
