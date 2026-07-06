<?php
/**
 * Cloudflare rule payloads — pure data, unit-testable.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Builds the exact JSON-ready payloads the deployer sends. No HTTP, no WP
 * state — everything is parameterized so golden-file tests can pin the
 * bodies down.
 *
 * Every rule carries a "ref" (blt-secure-*) — the idempotency anchor the
 * reconciler matches on — and a "[BLT Secure]" description so rules are
 * recognizable in the Cloudflare dashboard.
 */
class Blt_Secure_Rule_Definitions {

	// Cloudflare-published managed ruleset IDs (stable, documented).
	const RULESET_CF_MANAGED  = 'efb7b8c949ac4650a09736fc376e9aee';
	const RULESET_OWASP       = '4814384a9e5d4991b9815dcfc25d2f1f';
	const RULESET_CF_FREE     = '77454fe2d30c4220b5701f6fdfb893ba';
	const OWASP_SCORE_RULE_ID = '6179ae15870a4bb7b2d480d4843b323c';

	const PHASE_MANAGED   = 'http_request_firewall_managed';
	const PHASE_CUSTOM    = 'http_request_firewall_custom';
	const PHASE_RATELIMIT = 'http_ratelimit';

	/**
	 * Curated ASNs to challenge (cloud providers & bulletproof hosts that
	 * legit browsers never originate from; challenged, not blocked, since
	 * legitimate services also live there).
	 *
	 * @return int[]
	 */
	public static function challenged_asns() {
		$asns = array(
			9009,   // M247 (VPN exit heavy).
			14061,  // DigitalOcean.
			16509,  // Amazon AWS.
			24940,  // Hetzner.
			45102,  // Alibaba Cloud.
			51167,  // Contabo.
			55286,  // B2 Net Solutions / Server Room.
			60068,  // Datacamp / CDN77 VPN exits.
			62904,  // Eonix.
			202425, // IP Volume (bulletproof).
			206264, // Amarutu (bulletproof).
			213371, // SQUITTER NETWORKS.
		);

		/**
		 * Filter the ASN challenge list.
		 *
		 * @param int[] $asns AS numbers.
		 */
		return apply_filters( 'blt_secure_challenged_asns', $asns );
	}

	/**
	 * Managed WAF execute-rules for the managed phase entrypoint.
	 *
	 * @param int $paranoia OWASP paranoia level 1-4.
	 * @param int $score_threshold OWASP anomaly threshold (25/40/60).
	 * @return array[] Rule payloads keyed by ref suffix.
	 */
	public static function managed_waf_rules( $paranoia = 2, $score_threshold = 40 ) {
		$paranoia = max( 1, min( 4, (int) $paranoia ) );

		// PL categories above the chosen level get disabled via overrides.
		$disabled_categories = array();
		for ( $level = $paranoia + 1; $level <= 4; $level++ ) {
			$disabled_categories[] = array(
				'category' => 'paranoia-level-' . $level,
				'enabled'  => false,
			);
		}

		return array(
			'managed' => array(
				'ref'               => 'blt-secure-waf-managed',
				'description'       => '[BLT Secure] Cloudflare Managed Ruleset (WordPress emphasis)',
				'expression'        => 'true',
				'action'            => 'execute',
				'action_parameters' => array(
					'id'        => self::RULESET_CF_MANAGED,
					'overrides' => array(
						'categories' => array(
							array(
								'category' => 'wordpress',
								'action'   => 'block',
								'enabled'  => true,
							),
						),
					),
				),
				'enabled'           => true,
			),
			'owasp'   => array(
				'ref'               => 'blt-secure-waf-owasp',
				'description'       => '[BLT Secure] OWASP Core Ruleset',
				'expression'        => 'true',
				'action'            => 'execute',
				'action_parameters' => array(
					'id'        => self::RULESET_OWASP,
					'overrides' => array_filter(
						array(
							'categories' => $disabled_categories ? $disabled_categories : null,
							'rules'      => array(
								array(
									'id'              => self::OWASP_SCORE_RULE_ID,
									'score_threshold' => (int) $score_threshold,
								),
							),
						)
					),
				),
				'enabled'           => true,
			),
		);
	}

	/**
	 * Free-plan fallback: the only managed ruleset free zones may execute.
	 *
	 * @return array[]
	 */
	public static function managed_waf_rules_free() {
		return array(
			'free' => array(
				'ref'               => 'blt-secure-waf-free',
				'description'       => '[BLT Secure] Cloudflare Free Managed Ruleset',
				'expression'        => 'true',
				'action'            => 'execute',
				'action_parameters' => array(
					'id' => self::RULESET_CF_FREE,
				),
				'enabled'           => true,
			),
		);
	}

	/**
	 * Curated custom-rules pack for the custom phase entrypoint.
	 *
	 * @return array[] Rule payloads keyed by ref suffix.
	 */
	public static function custom_pack_rules() {
		$asns = implode( ' ', array_map( 'intval', self::challenged_asns() ) );

		return array(
			'asn'   => array(
				'ref'         => 'blt-secure-custom-asn',
				'description' => '[BLT Secure] Challenge requests from high-abuse ASNs',
				'expression'  => '(ip.src.asnum in {' . $asns . '})',
				'action'      => 'managed_challenge',
				'enabled'     => true,
			),
			'tor'   => array(
				'ref'         => 'blt-secure-custom-tor',
				'description' => '[BLT Secure] Challenge TOR exit nodes',
				'expression'  => '(ip.src.country eq "T1")',
				'action'      => 'managed_challenge',
				'enabled'     => true,
			),
			'paths' => array(
				'ref'         => 'blt-secure-custom-paths',
				'description' => '[BLT Secure] Block sensitive path probes',
				'expression'  => '(http.request.uri.path contains "wp-config" or http.request.uri.path contains "/.env" or http.request.uri.path contains "/.git/")',
				'action'      => 'block',
				'enabled'     => true,
			),
		);
	}

	/**
	 * Rate-limit rule for login endpoints (one rule — free-plan budget).
	 *
	 * @param string $login_slug Custom login slug ('' when unset).
	 * @return array[] Rule payloads keyed by ref suffix.
	 */
	public static function rate_limit_rules( $login_slug = '' ) {
		$paths = array( '/wp-login.php', '/xmlrpc.php' );
		if ( '' !== $login_slug ) {
			$paths[] = '/' . ltrim( $login_slug, '/' );
		}

		$parts = array();
		foreach ( $paths as $path ) {
			$parts[] = 'http.request.uri.path eq "' . $path . '"';
		}

		return array(
			'login' => array(
				'ref'         => 'blt-secure-ratelimit-login',
				'description' => '[BLT Secure] Rate limit login and XML-RPC endpoints',
				'expression'  => '(' . implode( ' or ', $parts ) . ')',
				'action'      => 'block',
				'ratelimit'   => array(
					'characteristics'     => array( 'cf.colo.id', 'ip.src' ),
					'period'              => 60,
					'requests_per_period' => 5,
					'mitigation_timeout'  => 600,
				),
				'enabled'     => true,
			),
		);
	}

	/**
	 * Custom leaked-credential detection for the WP login form fields.
	 *
	 * @return array
	 */
	public static function leaked_creds_detection() {
		return array(
			'username' => 'lookup_json_string(http.request.body.form, "log")',
			'password' => 'lookup_json_string(http.request.body.form, "pwd")',
		);
	}

	/**
	 * Companion custom rule that challenges leaked-credential logins.
	 *
	 * @return array[] Rule payloads keyed by ref suffix.
	 */
	public static function leaked_creds_rules() {
		return array(
			'challenge' => array(
				'ref'         => 'blt-secure-leaked-creds',
				'description' => '[BLT Secure] Challenge logins using leaked credentials',
				'expression'  => '(cf.waf.credential_check.username_and_password_leaked)',
				'action'      => 'managed_challenge',
				'enabled'     => true,
			),
		);
	}

	/**
	 * Cloudflare Access application payload for wp-admin + the login slug.
	 *
	 * @param string $host Site host (no scheme).
	 * @param string $login_slug Custom login slug ('' = default wp-login.php).
	 * @return array
	 */
	public static function access_app( $host, $login_slug = '' ) {
		$login_path = '' !== $login_slug ? '/' . ltrim( $login_slug, '/' ) : '/wp-login.php';

		return array(
			'type'                 => 'self_hosted',
			'name'                 => '[BLT Secure] WordPress Admin',
			'domain'               => $host . '/wp-admin',
			'self_hosted_domains'  => array(
				$host . '/wp-admin',
				$host . $login_path,
			),
			'session_duration'     => '24h',
			'app_launcher_visible' => false,
		);
	}

	/**
	 * Access policies: allow listed emails; bypass for admin-ajax so
	 * anonymous front-end AJAX keeps working.
	 *
	 * @param string[] $emails Allowed emails.
	 * @return array[] Policy payloads keyed by ref suffix.
	 */
	public static function access_policies( array $emails ) {
		$includes = array();
		foreach ( $emails as $email ) {
			$includes[] = array( 'email' => array( 'email' => $email ) );
		}

		return array(
			'allow' => array(
				'name'     => '[BLT Secure] Allow administrators',
				'decision' => 'allow',
				'include'  => $includes,
			),
		);
	}

	/**
	 * Bypass application for admin-ajax.php / admin-post.php (created as a
	 * sibling app with an everyone-bypass policy).
	 *
	 * @param string $host Site host.
	 * @return array
	 */
	public static function access_bypass_app( $host ) {
		return array(
			'type'                 => 'self_hosted',
			'name'                 => '[BLT Secure] WordPress admin-ajax bypass',
			'domain'               => $host . '/wp-admin/admin-ajax.php',
			'self_hosted_domains'  => array(
				$host . '/wp-admin/admin-ajax.php',
				$host . '/wp-admin/admin-post.php',
			),
			'session_duration'     => '24h',
			'app_launcher_visible' => false,
		);
	}

	/**
	 * Everyone-bypass policy for the bypass app.
	 *
	 * @return array[]
	 */
	public static function access_bypass_policies() {
		return array(
			'bypass' => array(
				'name'     => '[BLT Secure] Bypass for front-end AJAX',
				'decision' => 'bypass',
				'include'  => array( array( 'everyone' => (object) array() ) ),
			),
		);
	}

	/**
	 * Stable hash of a config array — the deployer stores it to detect when
	 * settings drift from what is deployed ("update available" badge).
	 *
	 * @param array $config Any payload array.
	 * @return string
	 */
	public static function config_hash( array $config ) {
		return sha1( (string) wp_json_encode( $config ) );
	}
}
