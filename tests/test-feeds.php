<?php
/**
 * Feed loader tests.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure_Feeds parsing/validation + the shipped feeds.json.
 */
class Test_Feeds extends TestCase {

	protected function setUp(): void {
		Blt_Secure_Feeds::flush();
	}

	public function test_valid_format() {
		$this->assertTrue( Blt_Secure_Feeds::valid_format( 'yara' ) );
		$this->assertTrue( Blt_Secure_Feeds::valid_format( 'ioc-json' ) );
		$this->assertTrue( Blt_Secure_Feeds::valid_format( 'ip-list' ) );
		$this->assertFalse( Blt_Secure_Feeds::valid_format( 'csv' ) );
		$this->assertFalse( Blt_Secure_Feeds::valid_format( '' ) );
	}

	public function test_normalize_valid_feed() {
		$feed = Blt_Secure_Feeds::normalize_feed(
			array(
				'id'             => 'threatfox-ip',
				'label'          => 'ThreatFox',
				'url'            => 'https://threatfox.abuse.ch/export/json/recent/',
				'format'         => 'ioc-json',
				'interval_hours' => 6,
				'enabled'        => true,
				'attribution'    => 'abuse.ch',
			)
		);
		$this->assertSame( 'threatfox-ip', $feed['id'] );
		$this->assertSame( 'ioc-json', $feed['format'] );
		$this->assertSame( 6, $feed['interval_hours'] );
		$this->assertTrue( $feed['enabled'] );
	}

	public function test_normalize_rejects_bad_url_format_or_id() {
		$this->assertNull( Blt_Secure_Feeds::normalize_feed( array( 'id' => 'x', 'url' => 'ftp://h/x', 'format' => 'ip-list' ) ) );
		$this->assertNull( Blt_Secure_Feeds::normalize_feed( array( 'id' => 'x', 'url' => 'https://h/x', 'format' => 'bogus' ) ) );
		$this->assertNull( Blt_Secure_Feeds::normalize_feed( array( 'url' => 'https://h/x', 'format' => 'yara' ) ) );
		$this->assertNull( Blt_Secure_Feeds::normalize_feed( 'not-an-array' ) );
	}

	public function test_normalize_defaults_bad_interval() {
		$feed = Blt_Secure_Feeds::normalize_feed(
			array( 'id' => 'a', 'url' => 'https://h/x', 'format' => 'yara', 'interval_hours' => 0 )
		);
		$this->assertSame( 24, $feed['interval_hours'] );
	}

	public function test_bundled_config_loads_three_feeds_all_disabled() {
		$all = Blt_Secure_Feeds::all();
		$this->assertCount( 3, $all );
		$this->assertArrayHasKey( 'threatfox-ip', $all );
		// Every shipped feed is opt-in (disabled) by default.
		$this->assertSame( array(), Blt_Secure_Feeds::enabled() );
	}

	public function test_by_format_filters_enabled_only() {
		// Nothing enabled in the shipped config → empty regardless of format.
		$this->assertSame( array(), Blt_Secure_Feeds::by_format( 'ip-list' ) );
	}

	public function test_get_returns_feed_or_null() {
		$this->assertNotNull( Blt_Secure_Feeds::get( 'spamhaus-drop' ) );
		$this->assertNull( Blt_Secure_Feeds::get( 'does-not-exist' ) );
	}
}
