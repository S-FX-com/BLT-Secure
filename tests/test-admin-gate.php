<?php
/**
 * Front-end loading gate, secret normalization, and settings-form carriers.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure::should_load_admin(), Blt_Secure_Admin::normalize_secret(), views.
 */
class Test_Admin_Gate extends TestCase {

	public static function setUpBeforeClass(): void {
		if ( ! class_exists( 'Blt_Secure' ) ) {
			require_once BLT_SECURE_DIR . 'includes/class-blt-secure.php';
		}
		if ( ! class_exists( 'Blt_Secure_Admin' ) ) {
			require_once BLT_SECURE_DIR . 'admin/class-admin.php';
		}
	}

	public function test_front_end_requests_never_load_the_admin_stack() {
		$this->assertFalse( Blt_Secure::should_load_admin( false, false, '', 'index.php' ) );
	}

	public function test_anonymous_admin_ajax_loads_admin_only_for_our_own_actions() {
		// is_admin() is TRUE for every admin-ajax.php hit, including anonymous front-end ones.
		$this->assertFalse( Blt_Secure::should_load_admin( true, true, 'heartbeat', 'admin-ajax.php' ) );
		$this->assertFalse( Blt_Secure::should_load_admin( true, true, 'some_theme_action', 'admin-ajax.php' ) );
		$this->assertFalse( Blt_Secure::should_load_admin( true, true, '', 'admin-ajax.php' ) );
		$this->assertFalse( Blt_Secure::should_load_admin( true, true, 'xblt_secure_cf_deploy', 'admin-ajax.php' ) );

		foreach ( array( 'blt_secure_cf_save_token', 'blt_secure_gh_save_token', 'blt_secure_slack_save', 'blt_secure_fleet_report', 'blt_secure_whitelist_add', 'blt_secure_health_run' ) as $action ) {
			$this->assertTrue( Blt_Secure::should_load_admin( true, true, $action, 'admin-ajax.php' ), $action );
		}
	}

	public function test_admin_post_does_not_load_it_but_settings_pages_do() {
		$this->assertFalse( Blt_Secure::should_load_admin( true, false, 'blt_secure_anything', 'admin-post.php' ) );
		// options.php POSTs need the Settings API sanitizer registered.
		$this->assertTrue( Blt_Secure::should_load_admin( true, false, '', 'options.php' ) );
		$this->assertTrue( Blt_Secure::should_load_admin( true, false, '', 'admin.php' ) );
		$this->assertTrue( Blt_Secure::should_load_admin( true, false, '', 'plugins.php' ) );
	}

	public function test_every_registered_ajax_action_is_covered_by_the_prefix_gate() {
		$source = (string) file_get_contents( BLT_SECURE_DIR . 'admin/class-admin.php' );
		preg_match_all( "/wp_ajax_([a-z_]+)'/", $source, $m );
		$this->assertNotEmpty( $m[1] );
		foreach ( $m[1] as $action ) {
			$this->assertTrue( Blt_Secure::should_load_admin( true, true, $action, 'admin-ajax.php' ), $action );
		}
	}

	public function test_secrets_are_kept_verbatim_not_mangled_by_text_sanitizing() {
		$cases = array(
			'github_pat_11ABCDEF0_abc%41def<x>' => 'github_pat_11ABCDEF0_abc%41def<x>', // sanitize_text_field would strip "%41" and "<x>".
			'  cf-token-0123456789abcdef  '     => 'cf-token-0123456789abcdef',
			str_repeat( 'a', 64 )               => str_repeat( 'a', 64 ),
		);
		foreach ( $cases as $in => $out ) {
			$this->assertSame( $out, Blt_Secure_Admin::normalize_secret( $in ) );
		}
		foreach ( array( '', 'short', 'has a space inside it', "tab\tinside-token-12345", "new\nline-token-123456", str_repeat( 'a', 513 ), 'caf' . "\xc3\xa9" . '-token-12345', array( 'x' ), null, 12345678 ) as $bad ) {
			$this->assertSame( '', Blt_Secure_Admin::normalize_secret( $bad ), 'rejected: ' . wp_json_encode( $bad ) );
		}
	}

	public function test_no_secret_handler_uses_sanitize_text_field() {
		$source = (string) file_get_contents( BLT_SECURE_DIR . 'admin/class-admin.php' );
		foreach ( array( 'ajax_save_token', 'ajax_gh_save_token', 'ajax_fleet_save' ) as $method ) {
			$start = strpos( $source, 'function ' . $method );
			$this->assertNotFalse( $start );
			$end  = strpos( $source, "\n	}\n", $start );
			$body = substr( $source, $start, $end - $start );
			$this->assertStringNotContainsString( 'sanitize_text_field', $body, $method );
			$this->assertStringContainsString( 'posted_secret', $body, $method );
		}
	}

	public function test_hidden_settings_fields_are_carried_so_a_save_cannot_clear_them() {
		$login = (string) file_get_contents( BLT_SECURE_DIR . 'admin/views/tab-login.php' );
		$this->assertMatchesRegularExpression( '/type="hidden" name="[^"]*\[login\]\[slug\]"/', $login, 'slug must be carried when the constant hides the input' );

		$hardening = (string) file_get_contents( BLT_SECURE_DIR . 'admin/views/tab-hardening.php' );
		$this->assertStringContainsString( "[fileguard][disallow_file_edit]' ) );", $hardening );
		$this->assertStringContainsString( 'type="hidden"', $hardening, 'a disabled DISALLOW_FILE_EDIT toggle must not post "off"' );
	}

	public function test_github_token_copy_does_not_recommend_a_classic_token() {
		$view = (string) file_get_contents( BLT_SECURE_DIR . 'admin/views/tab-advanced.php' );
		$this->assertStringNotContainsString( 'or a classic token with the repo scope', $view );
		$this->assertStringContainsString( 'fine-grained personal access token with read-only Contents', $view );
	}
}
