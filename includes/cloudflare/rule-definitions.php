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

	// Legacy shared Account IP List name. Newer deployments use a host-scoped
	// name (see ioc_list_name()) so two sites in one Cloudflare account never
	// overwrite or delete each other's list. Names must be lowercase
	// alphanumeric + underscore.
	const IOC_LIST_NAME = 'blt_secure_iocs';

	/**
	 * Normalize a Cloudflare plan identifier ("free", "pro", "business",
	 * "enterprise", or the plan display name) to one of those four keys.
	 *
	 * @param mixed $raw legacy_id or plan name from the zone object.
	 * @return string One of free|pro|business|enterprise, or '' when unknown.
	 */
	public static function normalize_plan( $raw ) {
		$raw = strtolower( trim( (string) $raw ) );
		if ( '' === $raw ) {
			return '';
		}
		if ( false !== strpos( $raw, 'ent' ) ) {
			return 'enterprise';
		}
		if ( false !== strpos( $raw, 'business' ) || false !== strpos( $raw, 'biz' ) ) {
			return 'business';
		}
		if ( false !== strpos( $raw, 'pro' ) ) {
			return 'pro';
		}
		if ( false !== strpos( $raw, 'free' ) ) {
			return 'free';
		}
		return '';
	}

	/**
	 * Custom-rule budget per plan (0 = unknown plan, do not pre-check).
	 *
	 * @see https://developers.cloudflare.com/waf/custom-rules/
	 *
	 * @param string $plan Raw or normalized plan.
	 * @return int
	 */
	public static function custom_rule_limit( $plan ) {
		$limits = array(
			'free'       => 5,
			'pro'        => 20,
			'business'   => 100,
			'enterprise' => 1000,
		);
		$plan   = self::normalize_plan( $plan );
		return isset( $limits[ $plan ] ) ? $limits[ $plan ] : 0;
	}

	/**
	 * Rate-limiting-rule budget per plan (0 = unknown plan).
	 *
	 * @see https://developers.cloudflare.com/waf/rate-limiting-rules/#availability
	 *
	 * @param string $plan Raw or normalized plan.
	 * @return int
	 */
	public static function ratelimit_rule_limit( $plan ) {
		$limits = array(
			'free'       => 1,
			'pro'        => 2,
			'business'   => 5,
			'enterprise' => 100,
		);
		$plan   = self::normalize_plan( $plan );
		return isset( $limits[ $plan ] ) ? $limits[ $plan ] : 0;
	}

	/**
	 * Host-scoped IP-list name (lowercase alphanumeric + underscore, <= 50).
	 *
	 * @param string $host Site host.
	 * @return string
	 */
	public static function ioc_list_name( $host ) {
		$slug = trim( preg_replace( '/[^a-z0-9]+/', '_', strtolower( (string) $host ) ), '_' );
		$name = 'blt_secure_iocs_' . $slug;
		if ( '' === $slug || strlen( $name ) > 50 ) {
			$name = 'blt_secure_iocs_' . substr( md5( (string) $host ), 0, 12 );
		}
		return $name;
	}

	/**
	 * Every rule ref a feature can own, with the phase it lives in. Removal and
	 * tier transitions sweep ONLY these refs (all "blt-secure-*"), never
	 * anything else in the entrypoint.
	 *
	 * @param string $feature Feature key.
	 * @return array{phase:string,refs:string[]}|null
	 */
	public static function feature_refs( $feature ) {
		$map = array(
			'waf_managed'   => array(
				'phase' => self::PHASE_MANAGED,
				'refs'  => array( 'blt-secure-waf-managed', 'blt-secure-waf-owasp', 'blt-secure-waf-free' ),
			),
			'custom_pack'   => array(
				'phase' => self::PHASE_CUSTOM,
				// blt-secure-custom-tor is the pre-1.2 standalone TOR rule, now folded into the ASN rule.
				'refs'  => array( 'blt-secure-custom-asn', 'blt-secure-custom-paths', 'blt-secure-custom-tor' ),
			),
			'country_block' => array(
				'phase' => self::PHASE_CUSTOM,
				'refs'  => array( 'blt-secure-country-block' ),
			),
			'rate_limit'    => array(
				'phase' => self::PHASE_RATELIMIT,
				'refs'  => array( 'blt-secure-ratelimit-login' ),
			),
			'leaked_creds'  => array(
				'phase' => self::PHASE_CUSTOM,
				'refs'  => array( 'blt-secure-leaked-creds' ),
			),
			'ioc'           => array(
				'phase' => self::PHASE_CUSTOM,
				'refs'  => array( 'blt-secure-ioc-block' ),
			),
		);
		return isset( $map[ $feature ] ) ? $map[ $feature ] : null;
	}

	/**
	 * Normalize a site base path ("/blog" for a subdirectory install, '' for
	 * a root install) to lowercase with no trailing slash and a safe charset.
	 *
	 * @param string $path Path from home_url().
	 * @return string
	 */
	public static function normalize_base_path( $path ) {
		$path = strtolower( preg_replace( '/[^A-Za-z0-9_\-.\/]/', '', (string) $path ) );
		$path = trim( $path, '/' );
		return '' === $path ? '' : '/' . $path;
	}

	/**
	 * Expression fragment matching the login endpoints (wp-login.php,
	 * xmlrpc.php and the custom slug), case- and trailing-slash-insensitive,
	 * rooted at the site's base path for subdirectory installs. Uses
	 * starts_with()/lower(), which have no plan restriction.
	 *
	 * @see https://developers.cloudflare.com/ruleset-engine/rules-language/functions/
	 *
	 * @param string $login_slug Custom login slug ('' when unset).
	 * @param string $base_path  Site base path.
	 * @return string Parenthesised expression.
	 */
	public static function login_paths_expression( $login_slug = '', $base_path = '' ) {
		$base  = self::normalize_base_path( $base_path );
		$lower = 'lower(http.request.uri.path)';
		$parts = array(
			'starts_with(' . $lower . ', "' . $base . '/wp-login.php")',
			'starts_with(' . $lower . ', "' . $base . '/xmlrpc.php")',
		);

		$slug = trim( strtolower( preg_replace( '/[^A-Za-z0-9_\-.]/', '', (string) $login_slug ) ), '/' );
		if ( '' !== $slug ) {
			$parts[] = '(' . $lower . ' eq "' . $base . '/' . $slug . '" or starts_with(' . $lower . ', "' . $base . '/' . $slug . '/"))';
		}

		return '(' . implode( ' or ', $parts ) . ')';
	}

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
	 * Two rules, not three: TOR exits (Cloudflare's "T1" pseudo-country) are
	 * folded into the ASN challenge so the whole plugin fits Cloudflare's
	 * Free budget of 5 custom rules (pack 2 + country 1 + leaked-creds 1 + IOC
	 * 1). The challenge exempts /wp-json, /wp-cron.php and /xmlrpc.php so
	 * webhooks, REST clients, WP-Cron loopbacks and Jetpack from cloud ASNs are
	 * never challenged (they cannot solve a challenge).
	 *
	 * @param string $base_path Site base path (subdirectory installs).
	 * @return array[] Rule payloads keyed by ref suffix.
	 */
	public static function custom_pack_rules( $base_path = '' ) {
		$asns  = implode( ' ', array_map( 'intval', self::challenged_asns() ) );
		$base  = self::normalize_base_path( $base_path );
		$lower = 'lower(http.request.uri.path)';

		$exempt = array(
			'starts_with(' . $lower . ', "' . $base . '/wp-json")',
			'starts_with(' . $lower . ', "' . $base . '/wp-cron.php")',
			'starts_with(' . $lower . ', "' . $base . '/xmlrpc.php")',
		);

		return array(
			'asn'   => array(
				'ref'         => 'blt-secure-custom-asn',
				'description' => '[BLT Secure] Challenge high-abuse ASNs and TOR exits',
				'expression'  => '((ip.src.asnum in {' . $asns . '} or ip.src.country eq "T1") and not (' . implode( ' or ', $exempt ) . '))',
				'action'      => 'managed_challenge',
				'enabled'     => true,
			),
			'paths' => array(
				'ref'         => 'blt-secure-custom-paths',
				'description' => '[BLT Secure] Block sensitive path probes',
				'expression'  => '(' . $lower . ' contains "/wp-config." or ' . $lower . ' contains "/.env" or ' . $lower . ' contains "/.git/" or ends_with(' . $lower . ', "/.git"))',
				'action'      => 'block',
				'enabled'     => true,
			),
		);
	}

	/**
	 * Normalize a country selection to a sorted, deduped list of ISO 3166-1
	 * alpha-2 codes ("T1", Cloudflare's Tor pseudo-country, is also allowed).
	 * Accepts an array or a comma/space-separated string; anything that is
	 * not a valid code is dropped.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string|array $input Raw selection.
	 * @return string[] Uppercase codes, sorted.
	 */
	public static function sanitize_country_codes( $input ) {
		if ( is_string( $input ) ) {
			$input = preg_split( '/[\s,]+/', $input, -1, PREG_SPLIT_NO_EMPTY );
		}
		if ( ! is_array( $input ) ) {
			return array();
		}

		$codes = array();
		foreach ( $input as $code ) {
			if ( ! is_string( $code ) && ! is_numeric( $code ) ) {
				continue;
			}
			$code = strtoupper( trim( (string) $code ) );
			if ( preg_match( '/^(?:[A-Z]{2}|T1)$/', $code ) ) {
				$codes[ $code ] = true;
			}
		}

		$codes = array_keys( $codes );
		sort( $codes );
		return $codes;
	}

	/**
	 * Country-block rule for the custom phase: one rule blocking the selected
	 * countries site-wide, or (login-only mode) just on the login endpoints
	 * so visitors can still browse but never sign in.
	 *
	 * @param string[] $countries  ISO country codes (pre-sanitized).
	 * @param bool     $login_only Restrict the block to login endpoints.
	 * @param string   $login_slug Custom login slug ('' when unset).
	 * @param string   $base_path  Site base path (subdirectory installs).
	 * @return array[] Rule payloads keyed by ref suffix.
	 */
	public static function country_block_rules( array $countries, $login_only = false, $login_slug = '', $base_path = '' ) {
		$countries = self::sanitize_country_codes( $countries );

		$quoted = array();
		foreach ( $countries as $code ) {
			$quoted[] = '"' . $code . '"';
		}
		$expression = '(ip.src.country in {' . implode( ' ', $quoted ) . '})';

		if ( $login_only ) {
			$expression = '(' . $expression . ' and ' . self::login_paths_expression( $login_slug, $base_path ) . ')';
		}

		return array(
			'countries' => array(
				'ref'         => 'blt-secure-country-block',
				'description' => $login_only
					? '[BLT Secure] Block logins from selected countries'
					: '[BLT Secure] Block visits from selected countries',
				'expression'  => $expression,
				'action'      => 'block',
				'enabled'     => true,
			),
		);
	}

	/**
	 * Rate-limit rule for login endpoints (one rule — free-plan budget).
	 *
	 * Plan-aware, per
	 * https://developers.cloudflare.com/waf/rate-limiting-rules/#availability :
	 * Free zones may only count over 10 s and mitigate for 10 s; Pro and above
	 * accept 60 s / 600 s. An unknown plan gets the Free-safe values, which
	 * every plan accepts.
	 *
	 * @param string $login_slug Custom login slug ('' when unset).
	 * @param string $plan       Zone plan (raw or normalized).
	 * @param string $base_path  Site base path (subdirectory installs).
	 * @return array[] Rule payloads keyed by ref suffix.
	 */
	public static function rate_limit_rules( $login_slug = '', $plan = '', $base_path = '' ) {
		$plan = self::normalize_plan( $plan );
		if ( in_array( $plan, array( 'pro', 'business', 'enterprise' ), true ) ) {
			$ratelimit = array(
				'characteristics'     => array( 'cf.colo.id', 'ip.src' ),
				'period'              => 60,
				'requests_per_period' => 5,
				'mitigation_timeout'  => 600,
			);
		} else {
			$ratelimit = array(
				'characteristics'     => array( 'cf.colo.id', 'ip.src' ),
				'period'              => 10,
				'requests_per_period' => 5,
				'mitigation_timeout'  => 10,
			);
		}

		return array(
			'login' => array(
				'ref'         => 'blt-secure-ratelimit-login',
				'description' => '[BLT Secure] Rate limit login and XML-RPC endpoints',
				'expression'  => self::login_paths_expression( $login_slug, $base_path ),
				'action'      => 'block',
				'ratelimit'   => $ratelimit,
				'enabled'     => true,
			),
		);
	}

	/**
	 * Custom-phase rule that blocks any source IP present in the synced IOC
	 * list. The list is referenced by name ($blt_secure_iocs); one rule
	 * covers the whole list, so it scales to thousands of indicators.
	 *
	 * @param string $list_name Account IP-list name the rule references.
	 * @return array[] Rule payloads keyed by ref suffix.
	 */
	public static function ioc_block_rules( $list_name = self::IOC_LIST_NAME ) {
		return array(
			'block' => array(
				'ref'         => 'blt-secure-ioc-block',
				'description' => '[BLT Secure] Block IPs from synced threat-intel feeds',
				'expression'  => '(ip.src in $' . preg_replace( '/[^a-z0-9_]/', '', strtolower( (string) $list_name ) ) . ')',
				'action'      => 'block',
				'enabled'     => true,
			),
		);
	}

	/**
	 * Custom leaked-credential detection for the WP login form fields.
	 *
	 * Enterprise-only: custom detection locations are not available on other
	 * plans (WordPress is already covered by Cloudflare's default detection).
	 * WordPress posts application/x-www-form-urlencoded, so the expressions
	 * index the parsed form and url_decode() the first value.
	 *
	 * @see https://developers.cloudflare.com/waf/detections/leaked-credentials/
	 *
	 * @return array
	 */
	public static function leaked_creds_detection() {
		return array(
			'username' => 'url_decode(http.request.body.form["log"][0])',
			'password' => 'url_decode(http.request.body.form["pwd"][0])',
		);
	}

	/**
	 * Companion custom rule that challenges leaked-credential logins.
	 *
	 * Field availability: password_leaked is on every plan;
	 * username_and_password_leaked needs Pro or above. An unknown plan gets
	 * the all-plans field.
	 *
	 * @param string $plan Zone plan (raw or normalized).
	 * @return array[] Rule payloads keyed by ref suffix.
	 */
	public static function leaked_creds_rules( $plan = '' ) {
		$plan  = self::normalize_plan( $plan );
		$field = in_array( $plan, array( 'pro', 'business', 'enterprise' ), true )
			? 'cf.waf.credential_check.username_and_password_leaked'
			: 'cf.waf.credential_check.password_leaked';

		return array(
			'challenge' => array(
				'ref'         => 'blt-secure-leaked-creds',
				'description' => '[BLT Secure] Challenge logins using leaked credentials',
				'expression'  => '(' . $field . ')',
				'action'      => 'managed_challenge',
				'enabled'     => true,
			),
		);
	}

	/**
	 * Host-scoped Access application name. Apps are account-wide, so the host
	 * is part of the name: two sites in one account never adopt (or delete)
	 * each other's app.
	 *
	 * @param string $host Site host.
	 * @param bool   $bypass Whether this is the admin-ajax bypass app.
	 * @return string
	 */
	public static function access_app_name( $host, $bypass = false ) {
		return ( $bypass ? '[BLT Secure] admin-ajax bypass - ' : '[BLT Secure] WordPress Admin - ' ) . strtolower( (string) $host );
	}

	/**
	 * Cloudflare Access application payload for wp-admin + the login slug.
	 *
	 * Uses `destinations` (self_hosted_domains was deprecated, with support
	 * ending 2025-11-21) and creates the allow policy inline so the app can
	 * never exist without a policy (an Access app with no policy denies
	 * everyone).
	 *
	 * @see https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/methods/create/
	 *
	 * @param string   $host       Site host (no scheme).
	 * @param string   $login_slug Custom login slug ('' = default wp-login.php).
	 * @param string[] $emails     Allowed emails.
	 * @param string   $base_path  Site base path (subdirectory installs).
	 * @return array
	 */
	public static function access_app( $host, $login_slug = '', array $emails = array(), $base_path = '' ) {
		$base       = self::normalize_base_path( $base_path );
		$slug       = trim( preg_replace( '/[^A-Za-z0-9_\-.]/', '', (string) $login_slug ), '/' );
		$login_path = '' !== $slug ? '/' . $slug : '/wp-login.php';

		return array(
			'type'                 => 'self_hosted',
			'name'                 => self::access_app_name( $host ),
			'domain'               => $host . $base . '/wp-admin',
			'destinations'         => array(
				array(
					'type' => 'public',
					'uri'  => $host . $base . '/wp-admin',
				),
				array(
					'type' => 'public',
					'uri'  => $host . $base . $login_path,
				),
			),
			'session_duration'     => '24h',
			'app_launcher_visible' => false,
			'policies'             => array_values( self::access_policies( $emails ) ),
		);
	}

	/**
	 * Access policies: allow listed emails.
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
				'name'       => '[BLT Secure] Allow administrators',
				'decision'   => 'allow',
				'include'    => $includes,
				'precedence' => 1,
			),
		);
	}

	/**
	 * Bypass application for admin-ajax.php / admin-post.php (a sibling app
	 * with an everyone-bypass policy so anonymous front-end AJAX and form
	 * posts keep working behind the Access-protected /wp-admin).
	 *
	 * @param string $host      Site host.
	 * @param string $base_path Site base path (subdirectory installs).
	 * @return array
	 */
	public static function access_bypass_app( $host, $base_path = '' ) {
		$base = self::normalize_base_path( $base_path );

		return array(
			'type'                 => 'self_hosted',
			'name'                 => self::access_app_name( $host, true ),
			'domain'               => $host . $base . '/wp-admin/admin-ajax.php',
			'destinations'         => array(
				array(
					'type' => 'public',
					'uri'  => $host . $base . '/wp-admin/admin-ajax.php',
				),
				array(
					'type' => 'public',
					'uri'  => $host . $base . '/wp-admin/admin-post.php',
				),
			),
			'session_duration'     => '24h',
			'app_launcher_visible' => false,
			'policies'             => array_values( self::access_bypass_policies() ),
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
				'name'       => '[BLT Secure] Bypass for front-end AJAX',
				'decision'   => 'bypass',
				'include'    => array( array( 'everyone' => (object) array() ) ),
				'precedence' => 1,
			),
		);
	}

	/**
	 * Hash of the desired Access configuration (deployer stores it; the card
	 * recomputes it to show "update available").
	 *
	 * @param string   $host Site host.
	 * @param string   $login_slug Login slug.
	 * @param string[] $emails Allowed emails.
	 * @param string   $base_path Site base path.
	 * @return string
	 */
	public static function access_config_hash( $host, $login_slug, array $emails, $base_path = '' ) {
		$emails = array_values( array_unique( array_map( 'strtolower', $emails ) ) );
		sort( $emails );
		return self::config_hash( array( strtolower( (string) $host ), strtolower( (string) $login_slug ), $emails, self::normalize_base_path( $base_path ) ) );
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
