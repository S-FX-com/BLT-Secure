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
			'blocked_plugin',
			'blocked_upload',
			'malware_findings',
			'core_integrity_issues',
			'baseline_drift',
			'activity_admin_granted',
		);
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
			'lockout'                => __( 'Login lockout triggered', 'blt-secure' ),
			'blocked_plugin'         => __( 'Blocked a file-manager plugin', 'blt-secure' ),
			'blocked_upload'         => __( 'Blocked a dangerous upload', 'blt-secure' ),
			'malware_findings'       => __( 'Malware signatures found', 'blt-secure' ),
			'core_integrity_issues'  => __( 'Core files failed integrity check', 'blt-secure' ),
			'baseline_drift'         => __( 'Plugin/theme changed unexpectedly', 'blt-secure' ),
			'activity_admin_granted' => __( 'A new administrator was granted', 'blt-secure' ),
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
	 * Deliver an event to the enabled channels, subject to the allowlist and
	 * the per-type throttle.
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

		// Throttle per type to avoid floods.
		$throttle_key = 'blt_sec_alert_' . md5( $type );
		if ( get_transient( $throttle_key ) ) {
			return;
		}
		/** This filter is documented above. */
		$window = (int) apply_filters( 'blt_secure_alert_throttle', self::THROTTLE_SECONDS, $type );
		set_transient( $throttle_key, 1, max( 1, $window ) );

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
			if ( is_string( $webhook ) && '' !== $webhook ) {
				wp_remote_post(
					$webhook,
					array(
						'timeout'  => 8,
						'blocking' => false,
						'headers'  => array( 'Content-Type' => 'application/json' ),
						'body'     => wp_json_encode( self::slack_payload( $message['subject'] . "\n" . $message['body'] ) ),
					)
				);
			}
		}
	}
}
