<?php
/**
 * Privacy module helpers.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure_Privacy.
 */
class Test_Privacy extends TestCase {

	public function test_users_sitemap_provider_is_removed_and_others_kept() {
		$privacy  = new Blt_Secure_Privacy( new Blt_Secure_Options() );
		$provider = new stdClass();

		$this->assertFalse( $privacy->remove_users_sitemap( $provider, 'users' ) );
		$this->assertSame( $provider, $privacy->remove_users_sitemap( $provider, 'posts' ) );
	}
}
