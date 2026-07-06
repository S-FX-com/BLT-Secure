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
 * Wires the bundled plugin-update-checker (v5) to the private GitHub repo.
 *
 * Updates are served from GitHub release assets (the CI-built zip with a
 * stable blt-secure/ top-level folder) — never from source zipballs, whose
 * folder name includes the commit hash and would break the install path.
 *
 * Token precedence: the BLT_SECURE_GITHUB_TOKEN wp-config constant wins
 * (fleet automation), else the encrypted credential store ('github_token',
 * managed on the Advanced tab). Without a token, private-repo API calls
 * 404 and PUC quietly finds no updates — the admin notice in
 * Blt_Secure_Admin makes that state visible instead of silent.
 */
class Blt_Secure_Updater {

	const REPO_URL    = 'https://github.com/sfxdotcom/BLT-Secure/';
	const TOKEN_KEY   = 'github_token';
	const ASSET_REGEX = '/^blt-secure(-[\d.]+)?\.zip$/i';

	/**
	 * Credential store.
	 *
	 * @var Blt_Secure_Credential_Store
	 */
	private $store;

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
			'blt-secure'
		);

		$checker->setBranch( 'main' );

		$token = $this->token();
		if ( null !== $token ) {
			$checker->setAuthentication( $token );
		}

		// Only accept the CI-built zip asset; ignore checksums/source archives.
		$checker->getVcsApi()->enableReleaseAssets( self::ASSET_REGEX );
	}

	/**
	 * The effective GitHub token for this site, or null when unconfigured.
	 *
	 * @return string|null
	 */
	public function token() {
		return self::pick_token(
			defined( 'BLT_SECURE_GITHUB_TOKEN' ) ? BLT_SECURE_GITHUB_TOKEN : null,
			$this->store->get( self::TOKEN_KEY )
		);
	}

	/**
	 * Token precedence — pure function (unit-tested): constant beats the
	 * stored token; empty/non-string values fall through.
	 *
	 * @param mixed $constant Value of the wp-config constant, if defined.
	 * @param mixed $stored Value from the credential store.
	 * @return string|null
	 */
	public static function pick_token( $constant, $stored ) {
		if ( is_string( $constant ) && '' !== $constant ) {
			return $constant;
		}
		if ( is_string( $stored ) && '' !== $stored ) {
			return $stored;
		}
		return null;
	}
}
