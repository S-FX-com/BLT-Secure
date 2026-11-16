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

	// ---------------------------------------------------------------------
	// Hardening pass.
	// ---------------------------------------------------------------------

	protected function setUp(): void {
		$GLOBALS['blt_test_options']    = array();
		$GLOBALS['blt_test_transients'] = array();
		$GLOBALS['blt_test_scheduled']  = array();
		$GLOBALS['blt_test_requests']   = array();
		$GLOBALS['blt_test_http']       = array();
		$GLOBALS['blt_test_mail']       = array();
	}

	/**
	 * Channels wired to in-memory options.
	 *
	 * @param array $alerts Settings for the 'alerts' section.
	 * @return Blt_Secure_Alert_Channels
	 */
	private function channels( array $alerts = array() ) {
		$GLOBALS['blt_test_options']['blt_secure_settings'] = array( 'alerts' => $alerts );
		$options = new Blt_Secure_Options();
		$store   = new Blt_Secure_Encrypted_Option_Store( new Blt_Secure_Crypto() );
		$store->set( 'slack_webhook', 'https://hooks.slack.com/services/T000/B000/XXXX' );
		$channels = new Blt_Secure_Alert_Channels( $options, $store );
		$options->register_defaults( 'alerts', $channels->defaults() );
		return $channels;
	}

	/**
	 * Every LITERAL event slug a module emits via notify( 'slug', ... ) under
	 * includes/. (Dynamic activity_<upgrader action> events are routine by
	 * construction and are not matched.)
	 *
	 * @return string[]
	 */
	private function emitted_types() {
		$types    = array();
		$iterator = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( BLT_SECURE_DIR . 'includes', FilesystemIterator::SKIP_DOTS ) );
		foreach ( $iterator as $file ) {
			$path = $file->getPathname();
			if ( '.php' !== substr( $path, -4 ) || false !== strpos( $path, '/includes/lib/' ) || false !== strpos( $path, '/includes/blt-family/' ) ) {
				continue;
			}
			if ( preg_match_all( '/->notify\(\s*\'([a-z0-9_]+)\'\s*,/', (string) file_get_contents( $path ), $m ) ) {
				$types = array_merge( $types, $m[1] );
			}
		}
		return array_values( array_unique( $types ) );
	}

	public function test_contract_every_notified_type_is_actually_emitted() {
		$emitted = $this->emitted_types();
		$this->assertNotEmpty( $emitted );
		foreach ( Blt_Secure_Alert_Channels::default_types() as $type ) {
			$this->assertContains( $type, $emitted, "'{$type}' is allowlisted for alerts but no module emits it (stale slug?)" );
		}
	}

	public function test_contract_every_emitted_type_is_classified() {
		$classified = array_merge( Blt_Secure_Alert_Channels::default_types(), Blt_Secure_Alert_Channels::routine_types() );
		foreach ( $this->emitted_types() as $type ) {
			$this->assertContains( $type, $classified, "'{$type}' is emitted but neither alerted nor listed as routine — classify it in Blt_Secure_Alert_Channels" );
		}
		$this->assertSame( array(), array_intersect( Blt_Secure_Alert_Channels::default_types(), Blt_Secure_Alert_Channels::routine_types() ), 'a type cannot be both' );
	}

	public function test_contract_high_signal_security_events_are_alerted() {
		foreach ( array( 'blocked_plugin_install', 'blocked_plugin_deactivated', 'twofa_bruteforce', 'twofa_disabled', 'twofa_secret_lost', 'twofa_recovery_used', 'malware_file_deleted', 'fleet_command' ) as $type ) {
			$this->assertContains( $type, Blt_Secure_Alert_Channels::default_types() );
			$this->assertNotSame( $type, Blt_Secure_Alert_Channels::type_label( $type ), "{$type} needs a label" );
		}
		$this->assertNotContains( 'blocked_plugin', Blt_Secure_Alert_Channels::default_types() );
	}

	public function test_dispatch_only_queues_and_does_no_io() {
		$channels = $this->channels( array( 'email_enabled' => true, 'slack_enabled' => true ) );
		$channels->dispatch( 'lockout', array( 'username' => 'bob', 'ip' => '203.0.113.9' ) );

		$this->assertSame( array(), $GLOBALS['blt_test_mail'], 'no wp_mail on the raising request' );
		$this->assertSame( array(), $GLOBALS['blt_test_requests'], 'no HTTP on the raising request' );
		$this->assertCount( 1, $GLOBALS['blt_test_scheduled'] );
		$this->assertSame( Blt_Secure_Alert_Channels::DELIVER_HOOK, $GLOBALS['blt_test_scheduled'][0]['hook'] );
		$this->assertSame( 'lockout', $GLOBALS['blt_test_scheduled'][0]['args'][0] );
	}

	public function test_deliver_sends_mail_and_slack_via_safe_transport() {
		$channels = $this->channels( array( 'email_enabled' => true, 'email_to' => 'ops@example.test', 'slack_enabled' => true ) );
		$channels->deliver( 'lockout', array( 'username' => 'bob' ) );

		$this->assertCount( 1, $GLOBALS['blt_test_mail'] );
		$this->assertSame( 'ops@example.test', $GLOBALS['blt_test_mail'][0][0] );
		$this->assertCount( 1, $GLOBALS['blt_test_requests'] );
		$this->assertSame( 0, $GLOBALS['blt_test_requests'][0]['args']['redirection'] );
	}

	public function test_deliver_refuses_a_non_slack_webhook() {
		$channels = $this->channels( array( 'email_enabled' => false, 'slack_enabled' => true ) );
		$store    = new Blt_Secure_Encrypted_Option_Store( new Blt_Secure_Crypto() );
		$store->set( 'slack_webhook', 'https://attacker.example/hook' );
		$channels->deliver( 'lockout', array() );
		$this->assertSame( array(), $GLOBALS['blt_test_requests'] );
	}

	public function test_a_second_admin_grant_inside_the_window_is_not_swallowed() {
		$channels = $this->channels( array( 'email_enabled' => true ) );
		$channels->dispatch( 'activity_admin_granted', array( 'user' => 'alice', 'actor' => 'root' ) );
		$channels->dispatch( 'activity_admin_granted', array( 'user' => 'mallory', 'actor' => 'alice' ) );
		$channels->dispatch( 'activity_admin_granted', array( 'user' => 'mallory', 'actor' => 'alice' ) ); // exact repeat: throttled.

		$this->assertCount( 2, $GLOBALS['blt_test_scheduled'] );
		$this->assertSame( 'mallory', $GLOBALS['blt_test_scheduled'][1]['args'][1]['user'] );
	}

	public function test_noisy_types_stay_throttled_per_type_even_with_varied_context() {
		$channels = $this->channels( array( 'email_enabled' => true ) );
		for ( $i = 0; $i < 10; $i++ ) {
			$channels->dispatch( 'lockout', array( 'username' => 'user' . $i ) );
		}
		$this->assertCount( 1, $GLOBALS['blt_test_scheduled'] );
	}

	public function test_global_budget_caps_per_context_floods() {
		$channels = $this->channels( array( 'email_enabled' => true ) );
		for ( $i = 0; $i < 60; $i++ ) {
			$channels->dispatch( 'activity_admin_granted', array( 'user' => 'u' . $i ) );
		}
		$this->assertCount( Blt_Secure_Alert_Channels::BUDGET_MAX, $GLOBALS['blt_test_scheduled'] );
	}

	public function test_dispatch_ignores_unlisted_types_and_disabled_channels() {
		$channels = $this->channels( array( 'email_enabled' => true ) );
		$channels->dispatch( 'activity_plugin_activated', array() );
		$off = $this->channels( array( 'email_enabled' => false, 'slack_enabled' => false ) );
		$off->dispatch( 'lockout', array() );
		$this->assertSame( array(), $GLOBALS['blt_test_scheduled'] );
	}

	public function test_trim_context_bounds_what_goes_into_the_cron_array() {
		$trimmed = Blt_Secure_Alert_Channels::trim_context(
			array(
				'file'  => str_repeat( 'A', 5000 ),
				'many'  => range( 1, 100 ),
				'deep'  => array( 'a' => array( 'b' => array( 'c' => array( 'd' => 1 ) ) ) ),
				'obj'   => new stdClass(),
				'n'     => 7,
			)
		);
		$this->assertSame( 200, strlen( $trimmed['file'] ) );
		$this->assertCount( 20, $trimmed['many'] );
		$this->assertSame( array(), $trimmed['deep']['a']['b'] );
		$this->assertSame( '', $trimmed['obj'] );
		$this->assertSame( 7, $trimmed['n'] );
	}

	public function test_webhook_allowlist() {
		$this->assertTrue( Blt_Secure_Alert_Channels::is_allowed_webhook( 'https://hooks.slack.com/services/T0/B0/x' ) );
		foreach ( array( 'http://hooks.slack.com/services/T0/B0/x', 'https://hooks.slack.com.evil.test/x', 'https://evil.test/hooks.slack.com', 'https://169.254.169.254/latest', 'https://localhost:8443/x', 'https://u:p@hooks.slack.com/x', 'ftp://hooks.slack.com/x', '' ) as $bad ) {
			$this->assertFalse( Blt_Secure_Alert_Channels::is_allowed_webhook( $bad ), $bad );
		}
	}
}
