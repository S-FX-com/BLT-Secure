<?php
/**
 * Alert channel formatting / allowlist tests.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure_Alert_Channels pure helpers.
 */
class Test_Alert_Channels extends TestCase {

	public function test_should_notify_respects_allowlist() {
		$allow = Blt_Secure_Alert_Channels::default_types();
		$this->assertTrue( Blt_Secure_Alert_Channels::should_notify( 'malware_findings', $allow ) );
		$this->assertTrue( Blt_Secure_Alert_Channels::should_notify( 'lockout', $allow ) );
		// Routine activity is intentionally not in the default set.
		$this->assertFalse( Blt_Secure_Alert_Channels::should_notify( 'activity_plugin_activated', $allow ) );
		$this->assertFalse( Blt_Secure_Alert_Channels::should_notify( 'ioc_sync', $allow ) );
	}

	public function test_default_types_include_high_signal_events() {
		$types = Blt_Secure_Alert_Channels::default_types();
		foreach ( array( 'blocked_upload', 'core_integrity_issues', 'baseline_drift', 'activity_admin_granted' ) as $t ) {
			$this->assertContains( $t, $types );
		}
	}

	public function test_format_builds_subject_and_body() {
		$msg = Blt_Secure_Alert_Channels::format(
			'malware_findings',
			array( 'count' => 3 ),
			'My Site',
			'https://example.com'
		);
		$this->assertStringContainsString( 'My Site', $msg['subject'] );
		$this->assertStringContainsString( 'Malware signatures found', $msg['subject'] );
		$this->assertStringContainsString( 'https://example.com', $msg['body'] );
		$this->assertStringContainsString( 'malware_findings', $msg['body'] );
		$this->assertStringContainsString( '"count":3', $msg['body'] );
	}

	public function test_format_unknown_type_falls_back_to_slug() {
		$msg = Blt_Secure_Alert_Channels::format( 'some_new_event', array(), 'Site', 'https://x' );
		$this->assertStringContainsString( 'some_new_event', $msg['subject'] );
	}

	public function test_slack_payload_shape() {
		$this->assertSame( array( 'text' => 'hello' ), Blt_Secure_Alert_Channels::slack_payload( 'hello' ) );
	}

	public function test_type_label_known_and_unknown() {
		$this->assertSame( 'Login lockout triggered', Blt_Secure_Alert_Channels::type_label( 'lockout' ) );
		$this->assertSame( 'mystery', Blt_Secure_Alert_Channels::type_label( 'mystery' ) );
	}
}
