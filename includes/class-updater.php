<?php
/**
 * Self-hosted plugin updates via plugin-update-checker + GitHub releases.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Wires the bundled plugin-update-checker (v5) to the GitHub release feed.
 *
 * Updates are served from GitHub release assets (the CI-built zip with a
 * stable blt-secure/ top-level folder) — never from source zipballs, whose
 * folder name includes the commit hash and would break the install path.
 *
 * The repository is public, so update checks work with no credentials at
 * all. A GitHub token is therefore optional; when present it is used only to
 * raise the GitHub API rate limit (60→5000 req/hr) and to keep working if
 * the repo is ever made private again.
 *
 * Token precedence: the BLT_SECURE_GITHUB_TOKEN wp-config constant wins
 * (fleet automation), else the encrypted credential store ('github_token',
 * managed on the Advanced tab), else the shared BLT family store (opt-in,
 * off by default).
 */
class Blt_Secure_Updater {

	const REPO_URL    = 'https://github.com/S-FX-com/BLT-Secure/';
	const TOKEN_KEY   = 'github_token';
	const ASSET_REGEX = '/^blt-secure(-[\d.]+)?\.zip$/i';

	/**
	 * Mirrors plugin-update-checker's Api::REQUIRE_RELEASE_ASSETS (the library
	 * default, PREFER_RELEASE_ASSETS, falls back to the auto-generated source
	 * zip, which ships dev files and a commit-hash folder name).
	 */
	const REQUIRE_RELEASE_ASSETS = 2;

	/**
	 * Credential store.
	 *
	 * @var Blt_Secure_Credential_Store
	 */
	private $store;

	/**
	 * The plugin-update-checker instance, once boot() has built it.
	 *
	 * @var object|null
	 */
	private $checker = null;

	/**
	 * Constructor.
	 *
	 * @param Blt_Secure_Credential_Store $store Credential store.
	 */
	public function __construct( Blt_Secure_Credential_Store $store ) {
		$this->store = $store;
	}

	/**
	 * Whether the update checker should load for this request. Front-end
	 * requests never need it: checks run from wp-admin, WP-Cron (PUC's
	 * 12-hour event — the path that matters on WP-Cron-only hosts), or
	 * WP-CLI, and previously injected update data persists in the
	 * update_plugins transient regardless.
	 *
	 * @return bool
	 */
	public static function should_load() {
		return is_admin()
			|| wp_doing_cron()
			|| ( defined( 'WP_CLI' ) && WP_CLI );
	}

	/**
	 * Build and configure the update checker.
	 *
	 * @return void
	 */
	public function boot() {
		require_once BLT_SECURE_DIR . 'includes/lib/plugin-update-checker/plugin-update-checker.php';

		$checker = \YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
			self::REPO_URL,
			BLT_SECURE_FILE,
			'blt-secure',
			24
		);

		$checker->setBranch( 'main' );

		$token = $this->token();
		if ( null !== $token ) {
			$checker->setAuthentication( $token );
		}

		// Only accept the CI-built zip asset; ignore checksums/source archives.
		$checker->getVcsApi()->enableReleaseAssets( self::ASSET_REGEX, self::REQUIRE_RELEASE_ASSETS );

		// REQUIRE alone is not enough: with no matching asset the library falls
		// through to its latest-tag / branch strategies, whose download is the
		// source archive. Drop any update that is not a CI-built release asset
		// and refuse to download one even if it slips through.
		$checker->addFilter(
			'request_info_result',
			static function ( $info ) {
				if ( is_object( $info ) && ! empty( $info->download_url ) && ! Blt_Secure_Updater::is_release_asset_url( $info->download_url ) ) {
					return null;
				}
				return $info;
			},
			10,
			2
		);
		add_filter( 'upgrader_pre_download', array( __CLASS__, 'guard_package' ), 10, 2 );

		/*
		 * Family update policy: at most one automatic check a day, anchored to
		 * 00:00 site time, with manual checks ("Check for Updates") always
		 * allowed. The 24-hour $checkPeriod above is required — a checker built
		 * with 0 registers no scheduler hooks at all and cannot be revived
		 * afterwards.
		 */
		BLT_Family_Updates::apply(
			$checker,
			array(
				'basename'  => plugin_basename( BLT_SECURE_FILE ),
				'icons_url' => BLT_SECURE_URL . 'assets/img/',
			)
		);

		$this->checker = $checker;
	}

	/**
	 * Whether a package URL is a CI-built release asset of this repository
	 * (never a source zipball/tarball/branch archive).
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string $url Package URL.
	 * @return bool
	 */
	public static function is_release_asset_url( $url ) {
		$parts = wp_parse_url( (string) $url );
		if ( ! is_array( $parts ) || empty( $parts['host'] ) || empty( $parts['path'] ) || 'https' !== strtolower( isset( $parts['scheme'] ) ? $parts['scheme'] : '' ) ) {
			return false;
		}
		$host = strtolower( $parts['host'] );
		$path = $parts['path'];
		if ( 'api.github.com' === $host ) {
			return 1 === preg_match( '#^/repos/S-FX-com/BLT-Secure/releases/assets/\d+$#i', $path );
		}
		if ( 'github.com' === $host ) {
			return 1 === preg_match( '#^/S-FX-com/BLT-Secure/releases/download/[^/]+/blt-secure(-[\d.]+)?\.zip$#i', $path );
		}
		return false;
	}

	/**
	 * upgrader_pre_download: refuse a source archive of this repository.
	 *
	 * @param mixed  $reply   Short-circuit value (false = proceed).
	 * @param string $package Package URL.
	 * @return mixed
	 */
	public static function guard_package( $reply, $package ) {
		$package = (string) $package;
		if ( false !== stripos( $package, 'S-FX-com/BLT-Secure' ) && ! self::is_release_asset_url( $package ) ) {
			return new WP_Error(
				'blt_secure_source_archive',
				__( 'BLT Secure only installs the CI-built release package, not a source archive. Update was not installed.', 'blt-secure' )
			);
		}
		return $reply;
	}

	/**
	 * The configured update checker, or null before boot() ran.
	 *
	 * Exposed so the settings screen can offer the same manual check the
	 * Plugins row does, and report when the last check ran.
	 *
	 * @return object|null
	 */
	public function checker() {
		return $this->checker;
	}

	/**
	 * Whether the plugin repository is publicly readable. When true, update
	 * checks succeed with no token and the "missing token" admin notice is
	 * suppressed. Filterable so a private fork can flip it back to false and
	 * restore the token-required behavior (and its notice).
	 *
	 * @return bool
	 */
	public static function repo_public() {
		/**
		 * Filter whether the update source repository is public.
		 *
		 * @param bool $public Default true (the canonical repo is public).
		 */
		return (bool) apply_filters( 'blt_secure_updates_repo_public', true );
	}

	/**
	 * The effective GitHub token for this site, or null when unconfigured.
	 *
	 * @return string|null
	 */
	public function token() {
		// Last rung only: the shared row is consulted after this plugin's own
		// resolution has failed, and BLT_Family::get() itself returns nothing
		// unless the site owner opted this plugin into the 'github' group.
		$shared = class_exists( 'BLT_Family' ) ? BLT_Family::get( 'blt-secure', 'github', 'token' ) : '';

		return self::pick_token(
			defined( 'BLT_SECURE_GITHUB_TOKEN' ) ? BLT_SECURE_GITHUB_TOKEN : null,
			$this->store->get( self::TOKEN_KEY ),
			$shared
		);
	}

	/**
	 * Token precedence — pure function (unit-tested): constant beats the
	 * stored token, which beats the shared BLT family store; empty/non-string
	 * values fall through.
	 *
	 * @param mixed $constant Value of the wp-config constant, if defined.
	 * @param mixed $stored Value from the credential store.
	 * @param mixed $shared Value from the shared BLT family store. Lowest
	 *                      precedence, and optional so existing two-argument
	 *                      callers keep their behavior.
	 * @return string|null
	 */
	public static function pick_token( $constant, $stored, $shared = null ) {
		if ( is_string( $constant ) && '' !== $constant ) {
			return $constant;
		}
		if ( is_string( $stored ) && '' !== $stored ) {
			return $stored;
		}
		if ( is_string( $shared ) && '' !== $shared ) {
			return $shared;
		}
		return null;
	}
}
