<?php
/**
 * Alerting ring buffer: ordering and bounds.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure_Alerting.
 */
class Test_Alerting extends TestCase {

	protected function setUp(): void {
		$GLOBALS['blt_test_options'] = array();
		$GLOBALS['blt_test_actions'] = array();
		unset( $GLOBALS['blt_test_on_action'] );
	}

	protected function tearDown(): void {
		unset( $GLOBALS['blt_test_on_action'] );
	}

	private function alerting() {
		$options  = new Blt_Secure_Options();
		$alerting = new Blt_Secure_Alerting( $options );
		$options->register_defaults( 'alerting', $alerting->defaults() );
		return $alerting;
	}

	public function test_event_is_in_the_buffer_before_subscribers_run() {
		$seen = null;
		$GLOBALS['blt_test_on_action'] = static function ( $hook ) use ( &$seen ) {
			if ( 'blt_secure_alert' === $hook ) {
				$seen = array_column( (array) get_option( 'blt_secure_events', array() ), 'type' );
			}
		};

		$this->alerting()->notify( 'lockout', array( 'ip' => '203.0.113.1' ) );

		$this->assertSame( array( 'lockout' ), $seen, 'the fleet snapshot / channels must see the event that triggered them' );
	}

	public function test_subscribers_still_run_when_event_logging_is_off() {
		$GLOBALS['blt_test_options']['blt_secure_settings'] = array( 'alerting' => array( 'log_events' => false ) );
		$this->alerting()->notify( 'lockout' );

		$this->assertFalse( get_option( 'blt_secure_events', false ) );
		$this->assertSame( 'blt_secure_alert', $GLOBALS['blt_test_actions'][0][0] );
	}

	public function test_buffer_is_bounded_and_keeps_the_newest() {
		$alerting = $this->alerting();
		for ( $i = 0; $i < Blt_Secure_Alerting::MAX_EVENTS + 25; $i++ ) {
			$alerting->notify( 'activity_x', array( 'n' => $i ) );
		}
		$events = get_option( 'blt_secure_events' );
		$this->assertCount( Blt_Secure_Alerting::MAX_EVENTS, $events );
		$this->assertSame( Blt_Secure_Alerting::MAX_EVENTS + 24, end( $events )['context']['n'] );
		$this->assertSame( Blt_Secure_Alerting::MAX_EVENTS + 24, $alerting->recent( 1 )[0]['context']['n'] );
	}
}
