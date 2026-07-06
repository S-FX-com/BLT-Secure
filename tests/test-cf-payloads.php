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

		$this->assertSame( 'managed_challenge', $rules['asn']['action'] );
		$this->assertMatchesRegularExpression( '/^\(ip\.src\.asnum in \{[\d ]+\}\)$/', $rules['asn']['expression'] );
		$this->assertSame( '(ip.src.country eq "T1")', $rules['tor']['expression'] );
		$this->assertSame( 'managed_challenge', $rules['tor']['action'] );
		$this->assertSame( 'block', $rules['paths']['action'] );
		$this->assertStringContainsString( 'wp-config', $rules['paths']['expression'] );
		$this->assertStringContainsString( '/.env', $rules['paths']['expression'] );
		$this->assertStringContainsString( '/.git/', $rules['paths']['expression'] );

		foreach ( $rules as $rule ) {
			$this->assertStringStartsWith( 'blt-secure-', $rule['ref'] );
			$this->assertStringStartsWith( '[BLT Secure]', $rule['description'] );
		}
	}

	public function test_rate_limit_rule() {
		$rules = Blt_Secure_Rule_Definitions::rate_limit_rules( 'secret-door' );
		$rule  = $rules['login'];

		$this->assertSame(
			'(http.request.uri.path eq "/wp-login.php" or http.request.uri.path eq "/xmlrpc.php" or http.request.uri.path eq "/secret-door")',
			$rule['expression']
		);
		$this->assertSame( array( 'cf.colo.id', 'ip.src' ), $rule['ratelimit']['characteristics'] );
		$this->assertSame( 60, $rule['ratelimit']['period'] );
		$this->assertSame( 5, $rule['ratelimit']['requests_per_period'] );
		$this->assertSame( 600, $rule['ratelimit']['mitigation_timeout'] );

		// Without a slug: only the two default endpoints.
		$default = Blt_Secure_Rule_Definitions::rate_limit_rules();
		$this->assertStringNotContainsString( ' or http.request.uri.path eq "/"', $default['login']['expression'] );
		$this->assertSame(
			'(http.request.uri.path eq "/wp-login.php" or http.request.uri.path eq "/xmlrpc.php")',
			$default['login']['expression']
		);
	}

	public function test_leaked_creds_payloads() {
		$detection = Blt_Secure_Rule_Definitions::leaked_creds_detection();
		$this->assertSame( 'lookup_json_string(http.request.body.form, "log")', $detection['username'] );
		$this->assertSame( 'lookup_json_string(http.request.body.form, "pwd")', $detection['password'] );

		$rules = Blt_Secure_Rule_Definitions::leaked_creds_rules();
		$this->assertSame( '(cf.waf.credential_check.username_and_password_leaked)', $rules['challenge']['expression'] );
		$this->assertSame( 'managed_challenge', $rules['challenge']['action'] );
	}

	public function test_access_app_payloads() {
		$app = Blt_Secure_Rule_Definitions::access_app( 'example.org', 'secret-door' );
		$this->assertSame( 'self_hosted', $app['type'] );
		$this->assertSame( 'example.org/wp-admin', $app['domain'] );
		$this->assertSame( array( 'example.org/wp-admin', 'example.org/secret-door' ), $app['self_hosted_domains'] );

		$default_app = Blt_Secure_Rule_Definitions::access_app( 'example.org' );
		$this->assertContains( 'example.org/wp-login.php', $default_app['self_hosted_domains'] );

		$policies = Blt_Secure_Rule_Definitions::access_policies( array( 'shane@s-fx.com' ) );
		$this->assertSame( 'allow', $policies['allow']['decision'] );
		$this->assertSame( 'shane@s-fx.com', $policies['allow']['include'][0]['email']['email'] );

		$bypass = Blt_Secure_Rule_Definitions::access_bypass_app( 'example.org' );
		$this->assertSame( 'example.org/wp-admin/admin-ajax.php', $bypass['domain'] );
		$bypass_policies = Blt_Secure_Rule_Definitions::access_bypass_policies();
		$this->assertSame( 'bypass', $bypass_policies['bypass']['decision'] );
	}

	public function test_config_hash_stability() {
		$a = Blt_Secure_Rule_Definitions::config_hash( array( 'x' => 1 ) );
		$this->assertSame( $a, Blt_Secure_Rule_Definitions::config_hash( array( 'x' => 1 ) ) );
		$this->assertNotSame( $a, Blt_Secure_Rule_Definitions::config_hash( array( 'x' => 2 ) ) );
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
						array( 'id' => 'r-tor', 'ref' => 'blt-secure-custom-tor' ),
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
		// The two missing rules were POSTed.
		$this->assertSame( 2, count( array_keys( $log, 'POST /zones/zone123/rulesets/rs1/rules', true ) ) );
		// State persisted with all three ids.
		$this->assertSame( array( 'asn' => 'r-asn', 'tor' => 'r-tor', 'paths' => 'r-paths' ), $record['rule_ids'] );
		$this->assertNotNull( $state->deployment( 'custom_pack' ) );
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
