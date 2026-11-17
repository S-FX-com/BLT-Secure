<?php
/**
 * Golden assertions on Cloudflare payloads + API error mapping + deployer
 * reconciliation with a fake transport.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Rule definition payloads.
 */
class Test_Cf_Payloads extends TestCase {

	protected function setUp(): void {
		$GLOBALS['blt_test_options'] = array();
	}

	public function test_managed_waf_rules_paranoia_2() {
		$rules = Blt_Secure_Rule_Definitions::managed_waf_rules( 2, 40 );

		$this->assertSame( 'blt-secure-waf-managed', $rules['managed']['ref'] );
		$this->assertSame( 'execute', $rules['managed']['action'] );
		$this->assertSame( 'efb7b8c949ac4650a09736fc376e9aee', $rules['managed']['action_parameters']['id'] );
		$this->assertSame( 'wordpress', $rules['managed']['action_parameters']['overrides']['categories'][0]['category'] );

		$owasp = $rules['owasp'];
		$this->assertSame( '4814384a9e5d4991b9815dcfc25d2f1f', $owasp['action_parameters']['id'] );
		// PL2 → categories 3 and 4 disabled.
		$disabled = array_column( $owasp['action_parameters']['overrides']['categories'], 'category' );
		$this->assertSame( array( 'paranoia-level-3', 'paranoia-level-4' ), $disabled );
		$this->assertSame( 40, $owasp['action_parameters']['overrides']['rules'][0]['score_threshold'] );
	}

	public function test_managed_waf_paranoia_4_disables_nothing() {
		$rules = Blt_Secure_Rule_Definitions::managed_waf_rules( 4, 25 );
		$this->assertArrayNotHasKey( 'categories', $rules['owasp']['action_parameters']['overrides'] );
		$this->assertSame( 25, $rules['owasp']['action_parameters']['overrides']['rules'][0]['score_threshold'] );
	}

	public function test_custom_pack_expressions() {
		$rules = Blt_Secure_Rule_Definitions::custom_pack_rules();

		// TOR is folded into the ASN rule: the pack is 2 rules (Free budget).
		$this->assertSame( array( 'asn', 'paths' ), array_keys( $rules ) );
		$this->assertSame( 'managed_challenge', $rules['asn']['action'] );
		$this->assertStringContainsString( 'ip.src.asnum in {9009 ', $rules['asn']['expression'] );
		$this->assertStringContainsString( 'ip.src.country eq "T1"', $rules['asn']['expression'] );
		// Webhooks/REST/WP-Cron/XML-RPC callers cannot solve a challenge: exempt.
		foreach ( array( '/wp-json', '/wp-cron.php', '/xmlrpc.php' ) as $path ) {
			$this->assertStringContainsString( 'starts_with(lower(http.request.uri.path), "' . $path . '")', $rules['asn']['expression'] );
		}
		$this->assertStringContainsString( ' and not (', $rules['asn']['expression'] );

		$this->assertSame( 'block', $rules['paths']['action'] );
		$this->assertStringContainsString( '/wp-config.', $rules['paths']['expression'] );
		$this->assertStringNotContainsString( '"wp-config"', $rules['paths']['expression'], 'must not match /wp-config-guide style slugs' );
		$this->assertStringContainsString( '/.env', $rules['paths']['expression'] );
		$this->assertStringContainsString( '/.git/', $rules['paths']['expression'] );

		foreach ( $rules as $rule ) {
			$this->assertStringStartsWith( 'blt-secure-', $rule['ref'] );
			$this->assertStringStartsWith( '[BLT Secure]', $rule['description'] );
		}
	}

	public function test_custom_pack_subdirectory_install_prefixes_paths() {
		$rules = Blt_Secure_Rule_Definitions::custom_pack_rules( '/Blog/' );
		$this->assertStringContainsString( '"/blog/wp-json"', $rules['asn']['expression'] );
	}

	public function test_plan_normalization_and_limits() {
		$this->assertSame( 'free', Blt_Secure_Rule_Definitions::normalize_plan( 'free' ) );
		$this->assertSame( 'pro', Blt_Secure_Rule_Definitions::normalize_plan( 'Pro Website' ) );
		$this->assertSame( 'business', Blt_Secure_Rule_Definitions::normalize_plan( 'business' ) );
		$this->assertSame( 'enterprise', Blt_Secure_Rule_Definitions::normalize_plan( 'enterprise' ) );
		$this->assertSame( '', Blt_Secure_Rule_Definitions::normalize_plan( 'mystery' ) );

		// https://developers.cloudflare.com/waf/custom-rules/
		$this->assertSame( 5, Blt_Secure_Rule_Definitions::custom_rule_limit( 'free' ) );
		$this->assertSame( 20, Blt_Secure_Rule_Definitions::custom_rule_limit( 'pro' ) );
		$this->assertSame( 100, Blt_Secure_Rule_Definitions::custom_rule_limit( 'business' ) );
		$this->assertSame( 0, Blt_Secure_Rule_Definitions::custom_rule_limit( '' ) );
		// https://developers.cloudflare.com/waf/rate-limiting-rules/#availability
		$this->assertSame( 1, Blt_Secure_Rule_Definitions::ratelimit_rule_limit( 'free' ) );
		$this->assertSame( 2, Blt_Secure_Rule_Definitions::ratelimit_rule_limit( 'pro' ) );
		$this->assertSame( 5, Blt_Secure_Rule_Definitions::ratelimit_rule_limit( 'business' ) );
	}

	public function test_full_deploy_all_fits_the_free_custom_rule_budget() {
		$used = count( Blt_Secure_Rule_Definitions::custom_pack_rules() )
			+ count( Blt_Secure_Rule_Definitions::country_block_rules( array( 'CN' ) ) )
			+ count( Blt_Secure_Rule_Definitions::leaked_creds_rules( 'free' ) )
			+ count( Blt_Secure_Rule_Definitions::ioc_block_rules() );
		$this->assertLessThanOrEqual( Blt_Secure_Rule_Definitions::custom_rule_limit( 'free' ), $used );
	}

	public function test_ioc_list_name_is_host_scoped_and_valid() {
		$a = Blt_Secure_Rule_Definitions::ioc_list_name( 'www.Example.com' );
		$b = Blt_Secure_Rule_Definitions::ioc_list_name( 'other.example.org' );
		$this->assertSame( 'blt_secure_iocs_www_example_com', $a );
		$this->assertNotSame( $a, $b );
		$this->assertMatchesRegularExpression( '/^[a-z0-9_]{1,50}$/', Blt_Secure_Rule_Definitions::ioc_list_name( str_repeat( 'a-', 60 ) . '.com' ) );
		$rule = Blt_Secure_Rule_Definitions::ioc_block_rules( $a )['block'];
		$this->assertSame( '(ip.src in $' . $a . ')', $rule['expression'] );
	}

	public function test_rate_limit_rule() {
		// Pro and above: 5 / 60 s, blocked for 10 minutes.
		$rules = Blt_Secure_Rule_Definitions::rate_limit_rules( 'secret-door', 'pro' );
		$rule  = $rules['login'];

		$this->assertSame(
			'(starts_with(lower(http.request.uri.path), "/wp-login.php") or starts_with(lower(http.request.uri.path), "/xmlrpc.php") or (lower(http.request.uri.path) eq "/secret-door" or starts_with(lower(http.request.uri.path), "/secret-door/")))',
			$rule['expression']
		);
		$this->assertSame( array( 'cf.colo.id', 'ip.src' ), $rule['ratelimit']['characteristics'] );
		$this->assertSame( 60, $rule['ratelimit']['period'] );
		$this->assertSame( 5, $rule['ratelimit']['requests_per_period'] );
		$this->assertSame( 600, $rule['ratelimit']['mitigation_timeout'] );

		// Free: Cloudflare only accepts a 10 s period and a 10 s block.
		// https://developers.cloudflare.com/waf/rate-limiting-rules/#availability
		$free = Blt_Secure_Rule_Definitions::rate_limit_rules( '', 'free' )['login']['ratelimit'];
		$this->assertSame( 10, $free['period'] );
		$this->assertSame( 10, $free['mitigation_timeout'] );
		// An unknown plan gets the values every plan accepts.
		$this->assertSame( $free, Blt_Secure_Rule_Definitions::rate_limit_rules( '', '' )['login']['ratelimit'] );

		// Without a slug: only the two default endpoints.
		$default = Blt_Secure_Rule_Definitions::rate_limit_rules( '', 'pro' );
		$this->assertStringNotContainsString( 'secret-door', $default['login']['expression'] );
		$this->assertStringContainsString( '/wp-login.php', $default['login']['expression'] );
		$this->assertStringContainsString( '/xmlrpc.php', $default['login']['expression'] );

		// Subdirectory installs are rooted at the base path.
		$sub = Blt_Secure_Rule_Definitions::rate_limit_rules( 'door', 'pro', '/blog' );
		$this->assertStringContainsString( '"/blog/wp-login.php"', $sub['login']['expression'] );
		$this->assertStringContainsString( '"/blog/door/"', $sub['login']['expression'] );
	}

	public function test_leaked_creds_payloads() {
		// https://developers.cloudflare.com/waf/detections/leaked-credentials/ :
		// url-encoded form fields are read with url_decode(...form["name"][0]).
		$detection = Blt_Secure_Rule_Definitions::leaked_creds_detection();
		$this->assertSame( 'url_decode(http.request.body.form["log"][0])', $detection['username'] );
		$this->assertSame( 'url_decode(http.request.body.form["pwd"][0])', $detection['password'] );

		// Pro and above: user+password check; Free/unknown: password_leaked (all plans).
		$rules = Blt_Secure_Rule_Definitions::leaked_creds_rules( 'pro' );
		$this->assertSame( '(cf.waf.credential_check.username_and_password_leaked)', $rules['challenge']['expression'] );
		$this->assertSame( 'managed_challenge', $rules['challenge']['action'] );
		$this->assertSame( '(cf.waf.credential_check.password_leaked)', Blt_Secure_Rule_Definitions::leaked_creds_rules( 'free' )['challenge']['expression'] );
		$this->assertSame( '(cf.waf.credential_check.password_leaked)', Blt_Secure_Rule_Definitions::leaked_creds_rules()['challenge']['expression'] );
	}

	public function test_access_app_payloads() {
		$app = Blt_Secure_Rule_Definitions::access_app( 'example.org', 'secret-door', array( 'shane@s-fx.com' ) );
		$this->assertSame( 'self_hosted', $app['type'] );
		$this->assertSame( 'example.org/wp-admin', $app['domain'] );
		// self_hosted_domains is deprecated (sunset 2025-11-21): destinations only.
		$this->assertArrayNotHasKey( 'self_hosted_domains', $app );
		$uris = array_column( $app['destinations'], 'uri' );
		$this->assertSame( array( 'example.org/wp-admin', 'example.org/secret-door' ), $uris );
		$this->assertSame( 'public', $app['destinations'][0]['type'] );
		// Host-scoped name: two sites in one account never share an app.
		$this->assertSame( '[BLT Secure] WordPress Admin - example.org', $app['name'] );

		$default_app = Blt_Secure_Rule_Definitions::access_app( 'example.org', '', array( 'a@b.co' ) );
		$this->assertContains( 'example.org/wp-login.php', array_column( $default_app['destinations'], 'uri' ) );

		// The allow policy is created INLINE: the app can never exist without it.
		$this->assertCount( 1, $app['policies'] );
		$this->assertSame( 'allow', $app['policies'][0]['decision'] );
		$this->assertSame( 'shane@s-fx.com', $app['policies'][0]['include'][0]['email']['email'] );

		$bypass = Blt_Secure_Rule_Definitions::access_bypass_app( 'example.org' );
		$this->assertSame( 'example.org/wp-admin/admin-ajax.php', $bypass['domain'] );
		$this->assertSame(
			array( 'example.org/wp-admin/admin-ajax.php', 'example.org/wp-admin/admin-post.php' ),
			array_column( $bypass['destinations'], 'uri' )
		);
		$this->assertSame( '[BLT Secure] admin-ajax bypass - example.org', $bypass['name'] );
		$this->assertSame( 'bypass', $bypass['policies'][0]['decision'] );

		// Subdirectory installs are rooted at the base path.
		$sub = Blt_Secure_Rule_Definitions::access_app( 'example.org', '', array( 'a@b.co' ), '/blog' );
		$this->assertSame( 'example.org/blog/wp-admin', $sub['domain'] );
	}

	public function test_access_config_hash_tracks_inputs() {
		$h = Blt_Secure_Rule_Definitions::access_config_hash( 'example.org', 'door', array( 'a@b.co' ) );
		$this->assertSame( $h, Blt_Secure_Rule_Definitions::access_config_hash( 'EXAMPLE.org', 'door', array( 'A@b.co' ) ) );
		$this->assertNotSame( $h, Blt_Secure_Rule_Definitions::access_config_hash( 'example.org', 'other', array( 'a@b.co' ) ) );
		$this->assertNotSame( $h, Blt_Secure_Rule_Definitions::access_config_hash( 'example.org', 'door', array( 'x@y.co' ) ) );
	}

	public function test_config_hash_stability() {
		$a = Blt_Secure_Rule_Definitions::config_hash( array( 'x' => 1 ) );
		$this->assertSame( $a, Blt_Secure_Rule_Definitions::config_hash( array( 'x' => 1 ) ) );
		$this->assertNotSame( $a, Blt_Secure_Rule_Definitions::config_hash( array( 'x' => 2 ) ) );
	}

	public function test_sanitize_country_codes() {
		// String input: mixed case, mixed separators, dupes, invalid entries.
		$this->assertSame(
			array( 'CN', 'KP', 'RU' ),
			Blt_Secure_Rule_Definitions::sanitize_country_codes( 'cn, RU kp,ru,, xyz, 1' )
		);
		// Array input.
		$this->assertSame(
			array( 'DE', 'FR' ),
			Blt_Secure_Rule_Definitions::sanitize_country_codes( array( 'fr', 'DE', 'not-a-code', array( 'CN' ) ) )
		);
		// Cloudflare's Tor pseudo-country is a valid target.
		$this->assertSame( array( 'T1' ), Blt_Secure_Rule_Definitions::sanitize_country_codes( 't1' ) );
		// Junk in, nothing out.
		$this->assertSame( array(), Blt_Secure_Rule_Definitions::sanitize_country_codes( '<script>, USA, 12' ) );
		$this->assertSame( array(), Blt_Secure_Rule_Definitions::sanitize_country_codes( 42 ) );
	}

	public function test_country_block_rule_site_wide() {
		$rules = Blt_Secure_Rule_Definitions::country_block_rules( array( 'RU', 'CN' ) );
		$rule  = $rules['countries'];

		$this->assertSame( '(ip.src.country in {"CN" "RU"})', $rule['expression'] );
		$this->assertSame( 'block', $rule['action'] );
		$this->assertSame( 'blt-secure-country-block', $rule['ref'] );
		$this->assertStringStartsWith( '[BLT Secure]', $rule['description'] );
		$this->assertTrue( $rule['enabled'] );
	}

	public function test_country_block_rule_login_only() {
		$rules = Blt_Secure_Rule_Definitions::country_block_rules( array( 'CN' ), true, 'secret-door' );
		$rule  = $rules['countries'];

		$this->assertSame(
			'((ip.src.country in {"CN"}) and (starts_with(lower(http.request.uri.path), "/wp-login.php") or starts_with(lower(http.request.uri.path), "/xmlrpc.php") or (lower(http.request.uri.path) eq "/secret-door" or starts_with(lower(http.request.uri.path), "/secret-door/"))))',
			$rule['expression']
		);

		// Without a slug: only the two default endpoints.
		$default = Blt_Secure_Rule_Definitions::country_block_rules( array( 'CN' ), true );
		$this->assertStringNotContainsString( 'secret-door', $default['countries']['expression'] );
		$this->assertStringContainsString( '/xmlrpc.php', $default['countries']['expression'] );
	}

	public function test_country_block_rule_sanitizes_inline() {
		// Codes arriving unsanitized (e.g. straight from a filter) are cleaned.
		$rules = Blt_Secure_Rule_Definitions::country_block_rules( array( 'cn', '"});bad', 'RU' ) );
		$this->assertSame( '(ip.src.country in {"CN" "RU"})', $rules['countries']['expression'] );
	}
}

/**
 * API client error mapping via injected transport.
 */
class Test_Cf_Api extends TestCase {

	/**
	 * Build a client whose transport returns the given canned response.
	 *
	 * @param array|WP_Error $canned Response.
	 * @param array          $log Captured requests (by reference).
	 * @return Blt_Secure_Cloudflare_Api
	 */
	private function client( $canned, array &$log = array() ) {
		return new Blt_Secure_Cloudflare_Api(
			'tok_test',
			function ( $url, $args ) use ( $canned, &$log ) {
				$log[] = array(
					'url'  => $url,
					'args' => $args,
				);
				return $canned;
			}
		);
	}

	/**
	 * Canned CF response body.
	 *
	 * @param int   $status HTTP status.
	 * @param array $body Body array.
	 * @return array
	 */
	private function response( $status, array $body ) {
		return array(
			'response' => array( 'code' => $status ),
			'body'     => json_encode( $body ), // phpcs:ignore
		);
	}

	public function test_success_returns_result() {
		$log    = array();
		$client = $this->client(
			$this->response(
				200,
				array(
					'success' => true,
					'result'  => array( 'id' => 'abc' ),
				)
			),
			$log
		);

		$result = $client->get( '/zones', array( 'name' => 'example.org' ) );
		$this->assertSame( array( 'id' => 'abc' ), $result );
		$this->assertSame( 'https://api.cloudflare.com/client/v4/zones?name=example.org', $log[0]['url'] );
		$this->assertSame( 'Bearer tok_test', $log[0]['args']['headers']['Authorization'] );
	}

	public function test_auth_error_mapped() {
		$client = $this->client(
			$this->response(
				400,
				array(
					'success' => false,
					'errors'  => array(
						array(
							'code'    => 10000,
							'message' => 'Authentication error',
						),
					),
				)
			)
		);

		$result = $client->verify_token();
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'blt_cf_auth', $result->get_error_code() );
	}

	public function test_scope_error_mapped() {
		$client = $this->client(
			$this->response(
				403,
				array(
					'success' => false,
					'errors'  => array(
						array(
							'code'    => 10014,
							'message' => 'Access denied',
						),
					),
				)
			)
		);

		$result = $client->get( '/accounts/x/access/apps' );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'blt_cf_scope', $result->get_error_code() );
	}

	public function test_plan_error_mapped() {
		$client = $this->client(
			$this->response(
				400,
				array(
					'success' => false,
					'errors'  => array(
						array(
							'code'    => 20217,
							'message' => 'this ruleset is not available on your current plan',
						),
					),
				)
			)
		);

		$result = $client->post( '/zones/x/rulesets/y/rules', array() );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'blt_cf_plan', $result->get_error_code() );
	}

	public function test_validation_error_mapped() {
		$client = $this->client(
			$this->response(
				400,
				array(
					'success' => false,
					'errors'  => array(
						array(
							'code'    => 10021,
							'message' => 'invalid expression',
						),
					),
				)
			)
		);

		$result = $client->post( '/zones/x/rulesets/y/rules', array() );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'blt_cf_validation', $result->get_error_code() );
	}

	public function test_transport_failure_mapped() {
		$client = $this->client( new WP_Error( 'http_request_failed', 'timed out' ) );

		$result = $client->get( '/user/tokens/verify' );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'blt_cf_http', $result->get_error_code() );
	}

	public function test_zone_discovery_strips_subdomains() {
		$calls  = array();
		$client = new Blt_Secure_Cloudflare_Api(
			'tok',
			function ( $url ) use ( &$calls ) {
				$calls[] = $url;
				// Only the registrable domain resolves.
				$found = ( false !== strpos( $url, 'name=example.org' ) );
				return array(
					'response' => array( 'code' => 200 ),
					'body'     => json_encode( // phpcs:ignore
						array(
							'success' => true,
							'result'  => $found ? array( array( 'id' => 'zone123', 'name' => 'example.org' ) ) : array(),
						)
					),
				);
			}
		);

		$zone = $client->discover_zone( 'www.site.example.org' );
		$this->assertSame( 'zone123', $zone['id'] );
		$this->assertCount( 3, $calls ); // www.site.example.org → site.example.org → example.org.
	}
}

/**
 * Deployer reconciliation with a scripted transport.
 */
class Test_Cf_Deployer extends TestCase {

	protected function setUp(): void {
		$GLOBALS['blt_test_options'] = array();
	}

	/**
	 * Transport that answers by URL+method pattern and logs every call.
	 *
	 * @param array $script Ordered [method, url-substring, body-array] answers.
	 * @param array $log Captured calls.
	 * @return callable
	 */
	private function scripted_transport( array $script, array &$log ) {
		return function ( $url, $args ) use ( $script, &$log ) {
			$method = $args['method'];
			$log[]  = $method . ' ' . preg_replace( '#^https://api\.cloudflare\.com/client/v4#', '', $url );

			foreach ( $script as $entry ) {
				list( $m, $needle, $body ) = $entry;
				if ( $m === $method && false !== strpos( $url, $needle ) ) {
					return array(
						'response' => array( 'code' => 200 ),
						'body'     => json_encode( array( 'success' => true, 'result' => $body ) ), // phpcs:ignore
					);
				}
			}

			return array(
				'response' => array( 'code' => 404 ),
				'body'     => json_encode( array( 'success' => false, 'errors' => array( array( 'code' => 7003, 'message' => 'not found' ) ) ) ), // phpcs:ignore
			);
		};
	}

	private function connected_state() {
		$state = new Blt_Secure_Cloudflare_State();
		$state->set_zone(
			array(
				'zone_id'    => 'zone123',
				'zone_name'  => 'example.org',
				'account_id' => 'acct456',
				'plan'       => 'free',
				'host'       => 'example.org',
			)
		);
		return $state;
	}

	public function test_custom_pack_creates_missing_rules() {
		$log    = array();
		$script = array(
			// Entrypoint exists with one foreign rule and one of ours already present.
			array(
				'GET',
				'/phases/http_request_firewall_custom/entrypoint',
				array(
					'id'    => 'rs1',
					'rules' => array(
						array( 'id' => 'r-foreign', 'ref' => 'someone-elses-rule' ),
						array( 'id' => 'r-asn', 'ref' => 'blt-secure-custom-asn' ),
					),
				),
			),
			array(
				'PATCH',
				'/rulesets/rs1/rules/r-asn',
				array(
					'id'    => 'rs1',
					'rules' => array( array( 'id' => 'r-asn', 'ref' => 'blt-secure-custom-asn' ) ),
				),
			),
			array(
				'POST',
				'/rulesets/rs1/rules',
				array(
					'id'    => 'rs1',
					'rules' => array(
						array( 'id' => 'r-asn', 'ref' => 'blt-secure-custom-asn' ),
						array( 'id' => 'r-paths', 'ref' => 'blt-secure-custom-paths' ),
					),
				),
			),
		);

		$state    = $this->connected_state();
		$deployer = new Blt_Secure_Cloudflare_Deployer(
			new Blt_Secure_Cloudflare_Api( 'tok', $this->scripted_transport( $script, $log ) ),
			$state
		);

		$record = $deployer->deploy( 'custom_pack' );

		$this->assertIsArray( $record );
		$this->assertSame( 'rs1', $record['ruleset_id'] );
		// Existing rule was PATCHed (adopted), not duplicated.
		$this->assertContains( 'PATCH /zones/zone123/rulesets/rs1/rules/r-asn', $log );
		// The one missing rule was POSTed; the foreign rule was never touched.
		$this->assertSame( 1, count( array_keys( $log, 'POST /zones/zone123/rulesets/rs1/rules', true ) ) );
		$this->assertNotContains( 'PATCH /zones/zone123/rulesets/rs1/rules/r-foreign', $log );
		// State persisted with both ids.
		$this->assertSame( array( 'asn' => 'r-asn', 'paths' => 'r-paths' ), $record['rule_ids'] );
		$this->assertArrayNotHasKey( 'partial', $record );
		$this->assertNotNull( $state->deployment( 'custom_pack' ) );
	}

	public function test_country_block_requires_a_selection() {
		$log      = array();
		$deployer = new Blt_Secure_Cloudflare_Deployer(
			new Blt_Secure_Cloudflare_Api( 'tok', $this->scripted_transport( array(), $log ) ),
			$this->connected_state()
		);

		$result = $deployer->deploy( 'country_block', array( 'countries' => array() ) );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'blt_cf_validation', $result->get_error_code() );
		$this->assertSame( array(), $log, 'No HTTP calls should happen with an empty selection' );

		// Junk-only input degrades to empty and is refused the same way.
		$result = $deployer->deploy( 'country_block', array( 'countries' => array( 'USA', '12' ) ) );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'blt_cf_validation', $result->get_error_code() );
	}

	public function test_country_block_deploys_one_rule() {
		$log    = array();
		$script = array(
			array(
				'GET',
				'/phases/http_request_firewall_custom/entrypoint',
				array(
					'id'    => 'rs1',
					'rules' => array(),
				),
			),
			array(
				'POST',
				'/rulesets/rs1/rules',
				array(
					'id'    => 'rs1',
					'rules' => array( array( 'id' => 'r-cb', 'ref' => 'blt-secure-country-block' ) ),
				),
			),
		);

		$state    = $this->connected_state();
		$deployer = new Blt_Secure_Cloudflare_Deployer(
			new Blt_Secure_Cloudflare_Api( 'tok', $this->scripted_transport( $script, $log ) ),
			$state
		);

		$record = $deployer->deploy(
			'country_block',
			array(
				'countries'  => 'cn, ru',
				'login_only' => true,
				'login_slug' => 'secret-door',
			)
		);

		$this->assertIsArray( $record );
		$this->assertSame( array( 'countries' => 'r-cb' ), $record['rule_ids'] );
		$this->assertSame( array( 'CN', 'RU' ), $record['countries'] );
		$this->assertTrue( $record['login_only'] );
		$this->assertContains( 'POST /zones/zone123/rulesets/rs1/rules', $log );
		$this->assertNotNull( $state->deployment( 'country_block' ) );

		// Pin the deployed payload: the stored hash must match the rule built
		// with login_only + slug wired through, so silently dropping either in
		// the deployer would fail here (the transport does not log bodies).
		$this->assertSame(
			Blt_Secure_Rule_Definitions::config_hash( Blt_Secure_Rule_Definitions::country_block_rules( array( 'CN', 'RU' ), true, 'secret-door' ) ),
			$record['config_hash']
		);
	}

	public function test_deploy_without_connection_fails() {
		$log      = array();
		$deployer = new Blt_Secure_Cloudflare_Deployer(
			new Blt_Secure_Cloudflare_Api( 'tok', $this->scripted_transport( array(), $log ) ),
			new Blt_Secure_Cloudflare_State()
		);

		$result = $deployer->deploy( 'custom_pack' );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'blt_cf_not_connected', $result->get_error_code() );
		$this->assertSame( array(), $log, 'No HTTP calls should happen without a zone' );
	}

	public function test_remove_treats_404_as_success() {
		$state = $this->connected_state();
		$state->set_deployment(
			'custom_pack',
			array(
				'ruleset_id' => 'rs1',
				'rule_ids'   => array( 'asn' => 'r-gone' ),
			)
		);

		$log      = array(); // Empty script → all calls 404.
		$deployer = new Blt_Secure_Cloudflare_Deployer(
			new Blt_Secure_Cloudflare_Api( 'tok', $this->scripted_transport( array(), $log ) ),
			$state
		);

		$this->assertTrue( $deployer->remove( 'custom_pack' ) );
		$this->assertNull( $state->deployment( 'custom_pack' ) );
	}

	public function test_stale_detection() {
		$state = $this->connected_state();
		$state->set_deployment(
			'rate_limit',
			array(
				'ruleset_id'  => 'rs1',
				'rule_ids'    => array( 'login' => 'r1' ),
				'config_hash' => Blt_Secure_Rule_Definitions::config_hash( Blt_Secure_Rule_Definitions::rate_limit_rules( 'old-slug' ) ),
			)
		);

		$new_hash = Blt_Secure_Rule_Definitions::config_hash( Blt_Secure_Rule_Definitions::rate_limit_rules( 'new-slug' ) );
		$this->assertTrue( $state->is_stale( 'rate_limit', $new_hash ) );

		$same_hash = Blt_Secure_Rule_Definitions::config_hash( Blt_Secure_Rule_Definitions::rate_limit_rules( 'old-slug' ) );
		$this->assertFalse( $state->is_stale( 'rate_limit', $same_hash ) );
	}
}
