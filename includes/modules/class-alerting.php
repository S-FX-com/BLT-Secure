<?php
/**
 * Alerting stub (Phase 1: event ring buffer; Phase 3: Slack/email/dashboard).
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Collects security events into a bounded ring buffer option.
 *
 * Every module reports through notify(); Phase 3 channels (Slack webhook,
 * email digest, fleet dashboard push) subscribe to the blt_secure_alert
 * action without this class changing.
 */
class Blt_Secure_Alerting implements Blt_Secure_Module {

	const OPTION     = 'blt_secure_events';
	const MAX_EVENTS = 200;

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
		return 'alerting';
	}

	/**
	 * Defaults.
	 *
	 * @return array
	 */
	public function defaults() {
		return array(
			'log_events' => true,
		);
	}

	/**
	 * Always on — other modules depend on notify() existing.
	 *
	 * @return bool
	 */
	public function is_enabled() {
		return true;
	}

	/**
	 * No hooks of its own in Phase 1.
	 *
	 * @return void
	 */
	public function boot() {}

	/**
	 * Sanitize section.
	 *
	 * @param array $input Raw input.
	 * @param array $current Current values.
	 * @return array
	 */
	public function sanitize( $input, $current ) {
		return array(
			'log_events' => ! empty( $input['log_events'] ),
		);
	}

	/**
	 * Record a security event.
	 *
	 * @param string $type Event type slug (e.g. 'lockout', 'blocked_plugin').
	 * @param array  $context Structured context (no secrets!).
	 * @return void
	 */
	public function notify( $type, array $context = array() ) {
		// Record first, THEN fire the action: subscribers (the fleet snapshot,
		// alert channels) must see this event in the buffer. They only enqueue
		// their delivery work, so nothing slow runs on this request.
		if ( $this->options->get( 'alerting', 'log_events', true ) ) {
			$this->record( $type, $context );
		}

		/**
		 * Fires for every security event, after it has been recorded. Alert
		 * channels hook here; they must not do network or mail I/O inline.
		 *
		 * @param string $type Event type slug.
		 * @param array  $context Event context.
		 */
		do_action( 'blt_secure_alert', $type, $context );
	}

	/**
	 * Append one event to the bounded ring buffer (re-reading the option
	 * immediately before the write to keep the race window tiny).
	 *
	 * @param string $type    Event type slug.
	 * @param array  $context Structured context.
	 * @return void
	 */
	private function record( $type, array $context ) {
		$events = get_option( self::OPTION, array() );
		if ( ! is_array( $events ) ) {
			$events = array();
		}

		$events[] = array(
			'type'    => sanitize_key( $type ),
			'context' => $context,
			'time'    => time(),
		);

		if ( count( $events ) > self::MAX_EVENTS ) {
			$events = array_slice( $events, - self::MAX_EVENTS );
		}

		update_option( self::OPTION, $events, false );
	}

	/**
	 * Recent events, newest first.
	 *
	 * @param int $limit Max events.
	 * @return array
	 */
	public function recent( $limit = 20 ) {
		$events = get_option( self::OPTION, array() );
		if ( ! is_array( $events ) ) {
			return array();
		}
		return array_slice( array_reverse( $events ), 0, max( 1, (int) $limit ) );
	}
}
