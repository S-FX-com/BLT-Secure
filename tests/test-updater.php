<?php
/**
 * Updater token precedence, release-asset regex, and version-bump tests.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure_Updater pure logic.
 */
class Test_Updater extends TestCase {

	public function test_constant_wins_over_stored() {
		$this->assertSame( 'const_tok', Blt_Secure_Updater::pick_token( 'const_tok', 'stored_tok' ) );
	}

	public function test_stored_used_when_no_constant() {
		$this->assertSame( 'stored_tok', Blt_Secure_Updater::pick_token( null, 'stored_tok' ) );
		$this->assertSame( 'stored_tok', Blt_Secure_Updater::pick_token( '', 'stored_tok' ) );
		$this->assertSame( 'stored_tok', Blt_Secure_Updater::pick_token( false, 'stored_tok' ) );
	}

	public function test_null_when_nothing_configured() {
		$this->assertNull( Blt_Secure_Updater::pick_token( null, null ) );
		$this->assertNull( Blt_Secure_Updater::pick_token( '', '' ) );
		$this->assertNull( Blt_Secure_Updater::pick_token( false, 0 ) );
	}

	public function test_asset_regex_accepts_ci_zips() {
		$this->assertMatchesRegularExpression( Blt_Secure_Updater::ASSET_REGEX, 'blt-secure-0.2.3.zip' );
		$this->assertMatchesRegularExpression( Blt_Secure_Updater::ASSET_REGEX, 'blt-secure-10.0.12.zip' );
		$this->assertMatchesRegularExpression( Blt_Secure_Updater::ASSET_REGEX, 'blt-secure.zip' );
	}

	public function test_asset_regex_rejects_other_assets() {
		$this->assertDoesNotMatchRegularExpression( Blt_Secure_Updater::ASSET_REGEX, 'blt-secure-0.2.3.zip.sha256' );
		$this->assertDoesNotMatchRegularExpression( Blt_Secure_Updater::ASSET_REGEX, 'Source code (zip)' );
		$this->assertDoesNotMatchRegularExpression( Blt_Secure_Updater::ASSET_REGEX, 'blt-secure-pro.zip' );
		$this->assertDoesNotMatchRegularExpression( Blt_Secure_Updater::ASSET_REGEX, 'BLT-Secure-abc1234.tar.gz' );
	}

	public function test_repo_public_by_default() {
		// The canonical repository is public, so updates need no token.
		$this->assertTrue( Blt_Secure_Updater::repo_public() );
	}

	public function test_repo_url_points_at_the_public_org_repo() {
		$this->assertSame( 'https://github.com/S-FX-com/BLT-Secure/', Blt_Secure_Updater::REPO_URL );
	}
}

/**
 * .github/scripts/bump-version.php semver math + file rewriting.
 */
class Test_Version_Bump extends TestCase {

	public static function setUpBeforeClass(): void {
		require_once BLT_SECURE_DIR . '.github/scripts/bump-version.php';
	}

	public function test_patch_bump() {
		$this->assertSame( '0.1.1', blt_secure_next_version( '0.1.0', 'patch' ) );
		$this->assertSame( '0.1.10', blt_secure_next_version( '0.1.9', 'patch' ) );
	}

	public function test_minor_bump_resets_patch() {
		$this->assertSame( '0.2.0', blt_secure_next_version( '0.1.5', 'minor' ) );
	}

	public function test_major_bump_resets_minor_and_patch() {
		$this->assertSame( '2.0.0', blt_secure_next_version( '1.9.9', 'major' ) );
	}

	public function test_invalid_version_rejected() {
		$this->expectException( InvalidArgumentException::class );
		blt_secure_next_version( '1.2', 'patch' );
	}

	public function test_invalid_level_rejected() {
		$this->expectException( InvalidArgumentException::class );
		blt_secure_next_version( '1.2.3', 'huge' );
	}

	public function test_apply_bump_rewrites_all_three_locations() {
		$plugin = " * Version:           0.1.0\n"
			. "define( 'BLT_SECURE_VERSION', '0.1.0' );\n";
		$readme = "Stable tag: 0.1.0\n";

		$result = blt_secure_apply_bump( $plugin, $readme, 'minor' );

		$this->assertSame( '0.2.0', $result['version'] );
		$this->assertStringContainsString( ' * Version:           0.2.0', $result['plugin_file'] );
		$this->assertStringContainsString( "define( 'BLT_SECURE_VERSION', '0.2.0' );", $result['plugin_file'] );
		$this->assertStringContainsString( 'Stable tag: 0.2.0', $result['readme'] );
		$this->assertStringNotContainsString( '0.1.0', $result['plugin_file'] );
		$this->assertStringNotContainsString( '0.1.0', $result['readme'] );
	}

	public function test_apply_bump_fails_on_missing_marker() {
		$this->expectException( RuntimeException::class );
		blt_secure_apply_bump( "no version here\n", "Stable tag: 0.1.0\n", 'patch' );
	}

	public function test_apply_bump_works_on_real_files() {
		$plugin = (string) file_get_contents( BLT_SECURE_DIR . 'blt-secure.php' );
		$readme = (string) file_get_contents( BLT_SECURE_DIR . 'readme.txt' );

		$result = blt_secure_apply_bump( $plugin, $readme, 'patch' );

		$this->assertMatchesRegularExpression( '/^\d+\.\d+\.\d+$/', $result['version'] );
		$this->assertStringContainsString( 'Version:           ' . $result['version'], $result['plugin_file'] );
		$this->assertStringContainsString( "define( 'BLT_SECURE_VERSION', '" . $result['version'] . "' );", $result['plugin_file'] );
		$this->assertStringContainsString( 'Stable tag: ' . $result['version'], $result['readme'] );
	}
}
