<?php
/**
 * Deployer safety tests against a stateful fake Cloudflare.
 *
 * The fake models rulesets (per-phase entrypoints), Access apps, IP lists with
 * async bulk operations and leaked-credential detections, logs every request,
 * and supports failure injection. It never touches the network.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Minimal stateful Cloudflare API double.
 */
class Blt_Test_Fake_Cf {

	/**
	 * Request log: "METHOD /path".
	 *
	 * @var string[]
	 */
	public $log = array();

	/**
	 * Zone plan returned by GET /zones/{id}.
	 *
	 * @var string
	 */
	public $plan = 'pro';

	/**
	 * Rulesets by phase: phase => array( id, rules[] ).
	 *
	 * @var array
	 */
	public $phases = array();

	/**
	 * Deleted rules: array( id, ref ).
	 *
	 * @var array[]
	 */
	public $deleted = array();

	/**
	 * Access apps.
	 *
	 * @var array[]
	 */
	public $apps = array();

	/**
	 * Lists, by id.
	 *
	 * @var array[]
	 */
	public $lists = array();

	/**
	 * Last PUT list items body, by list id.
	 *
	 * @var array
	 */
	public $items = array();

	/**
	 * Leaked-credential detections.
	 *
	 * @var array[]
	 */
	public $detections = array();

	/**
	 * Status the bulk operation reports.
	 *
	 * @var string
	 */
	public $op_status = 'completed';

	/**
	 * Failure injector: callable( method, path, body ) returning a response or null.
	 *
	 * @var callable|null
	 */
	public $fail = null;

	/**
	 * Id counter.
	 *
	 * @var int
	 */
	private $n = 0;

	/**
	 * Sleeper calls (seconds).
	 *
	 * @var int[]
	 */
	public $sleeps = array();

	/**
	 * Seed an entrypoint with foreign rules.
	 *
	 * @param string $phase Phase.
	 * @param int    $count Number of foreign rules.
	 * @return void
	 */
	public function seed_foreign( $phase, $count = 1 ) {
		$this->phases[ $phase ] = array(
			'id'    => 'rs-' . $phase,
			'rules' => array(),
		);
		for ( $i = 1; $i <= $count; $i++ ) {
			$this->phases[ $phase ]['rules'][] = array(
				'id'  => 'foreign-' . $phase . '-' . $i,
				'ref' => 'other-tool-' . $i,
			);
		}
	}

	/**
	 * API client wired to this fake.
	 *
	 * @return Blt_Secure_Cloudflare_Api
	 */
	public function api() {
		return new Blt_Secure_Cloudflare_Api(
			'tok',
			array( $this, 'handle' ),
			function ( $seconds ) {
				$this->sleeps[] = $seconds;
			}
		);
	}

	/**
	 * Names of the rules (refs) currently in a phase.
	 *
	 * @param string $phase Phase.
	 * @return string[]
	 */
	public function refs( $phase ) {
		return isset( $this->phases[ $phase ] ) ? array_column( $this->phases[ $phase ]['rules'], 'ref' ) : array();
	}

	/**
	 * Count of logged requests starting with a prefix.
	 *
	 * @param string $prefix e.g. "POST /accounts".
	 * @return int
	 */
	public function count( $prefix ) {
		$n = 0;
		foreach ( $this->log as $line ) {
			if ( 0 === strpos( $line, $prefix ) ) {
				++$n;
			}
		}
		return $n;
	}

	/**
	 * Success response.
	 *
	 * @param mixed $result Result.
	 * @param array $info result_info.
	 * @return array
	 */
	private function ok( $result, array $info = array() ) {
		$body = array(
			'success' => true,
			'result'  => $result,
		);
		if ( $info ) {
			$body['result_info'] = $info;
		}
		return array(
			'response' => array( 'code' => 200 ),
			'body'     => json_encode( $body ), // phpcs:ignore
		);
	}

	/**
	 * Error response.
	 *
	 * @param int    $status HTTP status.
	 * @param int    $code Cloudflare code.
	 * @param string $message Message.
	 * @return array
	 */
	public function err( $status, $code, $message ) {
		return array(
			'response' => array( 'code' => $status ),
			'body'     => json_encode( array( 'success' => false, 'errors' => array( array( 'code' => $code, 'message' => $message ) ) ) ), // phpcs:ignore
		);
	}

	/**
	 * A ruleset response for a phase.
	 *
	 * @param string $phase Phase.
	 * @return array
	 */
	private function ruleset( $phase ) {
		return array(
			'id'    => $this->phases[ $phase ]['id'],
			'phase' => $phase,
			'rules' => $this->phases[ $phase ]['rules'],
		);
	}

	/**
	 * Phase owning a ruleset id.
	 *
	 * @param string $ruleset_id Id.
	 * @return string|null
	 */
	private function phase_of( $ruleset_id ) {
		foreach ( $this->phases as $phase => $set ) {
			if ( $set['id'] === $ruleset_id ) {
				return $phase;
			}
		}
		return null;
	}

	/**
	 * Transport entry point.
	 *
	 * @param string $url Full URL.
	 * @param array  $args Request args.
	 * @return array
	 */
	public function handle( $url, $args ) {
		$path   = preg_replace( '#^https://api\.cloudflare\.com/client/v4#', '', $url );
		$path   = preg_replace( '#\?.*$#', '', $path );
		$method = $args['method'];
		$body   = isset( $args['body'] ) ? json_decode( $args['body'], true ) : null;

		$this->log[] = $method . ' ' . $path;

		if ( $this->fail ) {
			$injected = call_user_func( $this->fail, $method, $path, $body );
			if ( null !== $injected ) {
				return $injected;
			}
		}

		$m = array();

		if ( 'GET' === $method && preg_match( '#^/zones/([^/]+)$#', $path ) ) {
			return $this->ok( array( 'id' => 'zone123', 'name' => 'example.org', 'plan' => array( 'legacy_id' => $this->plan ) ) );
		}

		// Rulesets.
		if ( preg_match( '#^/zones/[^/]+/rulesets/phases/([^/]+)/entrypoint$#', $path, $m ) ) {
			if ( 'GET' === $method ) {
				return isset( $this->phases[ $m[1] ] ) ? $this->ok( $this->ruleset( $m[1] ) ) : $this->err( 404, 10003, 'could not find entrypoint ruleset' );
			}
			return $this->err( 400, 10021, 'unexpected ' . $method . ' on an entrypoint' );
		}
		if ( 'POST' === $method && preg_match( '#^/zones/[^/]+/rulesets$#', $path ) ) {
			$this->phases[ $body['phase'] ] = array(
				'id'    => 'rs-' . $body['phase'],
				'rules' => array(),
			);
			return $this->ok( $this->ruleset( $body['phase'] ) );
		}
		if ( preg_match( '#^/zones/[^/]+/rulesets/([^/]+)/rules(?:/([^/]+))?$#', $path, $m ) ) {
			$phase = $this->phase_of( $m[1] );
			if ( null === $phase ) {
				return $this->err( 404, 10003, 'no such ruleset' );
			}
			if ( 'POST' === $method && empty( $m[2] ) ) {
				$rule                                 = $body;
				$rule['id']                           = 'rule' . ( ++$this->n );
				$this->phases[ $phase ]['rules'][]    = $rule;
				return $this->ok( $this->ruleset( $phase ) );
			}
			foreach ( $this->phases[ $phase ]['rules'] as $i => $rule ) {
				if ( isset( $m[2] ) && $rule['id'] === $m[2] ) {
					if ( 'PATCH' === $method ) {
						$body['id']                              = $rule['id'];
						$this->phases[ $phase ]['rules'][ $i ]   = $body;
						return $this->ok( $this->ruleset( $phase ) );
					}
					if ( 'DELETE' === $method ) {
						$this->deleted[] = array(
							'id'  => $rule['id'],
							'ref' => isset( $rule['ref'] ) ? $rule['ref'] : '',
						);
						array_splice( $this->phases[ $phase ]['rules'], $i, 1 );
						return $this->ok( $this->ruleset( $phase ) );
					}
				}
			}
			return $this->err( 404, 10003, 'rule not found' );
		}

		// Access.
		if ( preg_match( '#^/accounts/[^/]+/access/apps(?:/([^/]+))?$#', $path, $m ) ) {
			if ( 'GET' === $method ) {
				return $this->ok( array_values( $this->apps ), array( 'page' => 1, 'total_pages' => 1 ) );
			}
			if ( 'POST' === $method ) {
				$id   = 'app' . ( ++$this->n );
				$app  = $body;
				$app['id'] = $id;
				$app['policies'] = array();
				foreach ( isset( $body['policies'] ) ? $body['policies'] : array() as $policy ) {
					$policy['id']      = 'pol' . ( ++$this->n );
					$app['policies'][] = $policy;
				}
				$this->apps[ $id ] = $app;
				return $this->ok( $app );
			}
			if ( 'PUT' === $method && isset( $this->apps[ $m[1] ] ) ) {
				$this->apps[ $m[1] ] = array_merge( $this->apps[ $m[1] ], $body, array( 'id' => $m[1] ) );
				return $this->ok( $this->apps[ $m[1] ] );
			}
			if ( 'DELETE' === $method ) {
				if ( ! isset( $this->apps[ $m[1] ] ) ) {
					return $this->err( 404, 12130, 'app not found' );
				}
				unset( $this->apps[ $m[1] ] );
				return $this->ok( array( 'id' => $m[1] ) );
			}
		}

		// Leaked credentials.
		if ( 'POST' === $method && preg_match( '#^/zones/[^/]+/leaked-credential-checks$#', $path ) ) {
			return $this->ok( array( 'enabled' => true ) );
		}
		if ( preg_match( '#^/zones/[^/]+/leaked-credential-checks/detections(?:/([^/]+))?$#', $path, $m ) ) {
			if ( 'GET' === $method ) {
				return $this->ok( array_values( $this->detections ) );
			}
			if ( 'POST' === $method ) {
				$id                      = 'det' . ( ++$this->n );
				$this->detections[ $id ] = array_merge( $body, array( 'id' => $id ) );
				return $this->ok( $this->detections[ $id ] );
			}
			if ( 'DELETE' === $method ) {
				unset( $this->detections[ $m[1] ] );
				return $this->ok( array( 'id' => $m[1] ) );
			}
		}

		// Lists.
		if ( preg_match( '#^/accounts/[^/]+/rules/lists/bulk_operations/([^/]+)$#', $path, $m ) ) {
			return $this->ok(
				array(
					'id'     => $m[1],
					'status' => $this->op_status,
					'error'  => 'failed' === $this->op_status ? 'item 3 is invalid' : '',
				)
			);
		}
		if ( preg_match( '#^/accounts/[^/]+/rules/lists/([^/]+)/items$#', $path, $m ) && 'PUT' === $method ) {
			$this->items[ $m[1] ] = $body;
			return $this->ok( array( 'operation_id' => 'op' . ( ++$this->n ) ) );
		}
		if ( preg_match( '#^/accounts/[^/]+/rules/lists(?:/([^/]+))?$#', $path, $m ) ) {
			if ( 'GET' === $method && empty( $m[1] ) ) {
				return $this->ok( array_values( $this->lists ) );
			}
			if ( 'GET' === $method ) {
				return isset( $this->lists[ $m[1] ] ) ? $this->ok( $this->lists[ $m[1] ] ) : $this->err( 404, 10006, 'list not found' );
			}
			if ( 'POST' === $method ) {
				$id                 = 'list' . ( ++$this->n );
				$this->lists[ $id ] = array_merge( $body, array( 'id' => $id ) );
				return $this->ok( $this->lists[ $id ] );
			}
			if ( 'DELETE' === $method ) {
				unset( $this->lists[ $m[1] ] );
				return $this->ok( array( 'id' => $m[1] ) );
			}
		}

		return $this->err( 404, 7003, 'no route for ' . $method . ' ' . $path );
	}
}

/**
 * Deployer behaviour: safety, plan-awareness, partial failure, ownership.
 */
class Test_Cf_Deployer_Safety extends TestCase {

	protected function setUp(): void {
		$GLOBALS['blt_test_options'] = array();
	}

	/**
	 * Connected state for a host/plan.
	 *
	 * @param string $host Host.
	 * @param string $plan Plan.
	 * @return Blt_Secure_Cloudflare_State
	 */
	private function state( $host = 'example.org', $plan = 'pro' ) {
		$state = new Blt_Secure_Cloudflare_State();
		$state->set_zone(
			array(
				'zone_id'    => 'zone123',
				'zone_name'  => 'example.org',
				'account_id' => 'acct456',
				'plan'       => $plan,
				'host'       => $host,
			)
		);
		return $state;
	}

	private function deployer( Blt_Test_Fake_Cf $cf, Blt_Secure_Cloudflare_State $state, $host = 'example.org' ) {
		return new Blt_Secure_Cloudflare_Deployer( $cf->api(), $state, $host );
	}

	// -------------------------------------------------------------------
	// Never PUT an entrypoint; only own refs are ever deleted.
	// -------------------------------------------------------------------

	public function test_no_put_ever_hits_a_ruleset_and_remove_only_deletes_own_refs() {
		$cf = new Blt_Test_Fake_Cf();
		$cf->plan = 'pro';
		foreach ( array( 'http_request_firewall_managed', 'http_request_firewall_custom' ) as $phase ) {
			$cf->seed_foreign( $phase, 2 );
		}
		$cf->seed_foreign( 'http_ratelimit', 1 ); // Pro allows 2 rate limiting rules.
		$state    = $this->state( 'example.org', 'pro' );
		$deployer = $this->deployer( $cf, $state );

		foreach ( array( 'waf_managed', 'custom_pack', 'rate_limit', 'leaked_creds' ) as $feature ) {
			$this->assertIsArray( $deployer->deploy( $feature, array( 'login_slug' => 'door' ) ), $feature );
		}
		$this->assertIsArray( $deployer->deploy( 'country_block', array( 'countries' => 'CN' ) ) );

		$this->assertTrue( $deployer->sync_ioc_list( array( '8.8.8.8' ) ) instanceof WP_Error === false );

		foreach ( array( 'waf_managed', 'custom_pack', 'country_block', 'rate_limit', 'leaked_creds' ) as $feature ) {
			$this->assertTrue( $deployer->remove( $feature ), $feature );
		}
		$this->assertTrue( $deployer->remove_ioc_list() );

		foreach ( $cf->log as $line ) {
			$this->assertDoesNotMatchRegularExpression( '#^PUT /zones/[^ ]*/rulesets#', $line, 'an entrypoint/ruleset must never be PUT' );
		}
		$this->assertGreaterThan( 5, count( $cf->deleted ) );
		foreach ( $cf->deleted as $gone ) {
			$this->assertStringStartsWith( 'blt-secure-', $gone['ref'], 'deleted a rule that is not ours: ' . $gone['id'] );
		}
		// The foreign rules are exactly what is left.
		$this->assertSame( array( 'other-tool-1', 'other-tool-2' ), $cf->refs( 'http_request_firewall_managed' ) );
		$this->assertSame( array( 'other-tool-1', 'other-tool-2' ), $cf->refs( 'http_request_firewall_custom' ) );
		$this->assertSame( array( 'other-tool-1' ), $cf->refs( 'http_ratelimit' ) );
	}

	public function test_remove_is_ref_based_so_orphans_without_a_record_are_removable() {
		$cf = new Blt_Test_Fake_Cf();
		$cf->seed_foreign( 'http_request_firewall_custom', 1 );
		// An orphan left by an interrupted older deploy (no state record at all).
		$cf->phases['http_request_firewall_custom']['rules'][] = array( 'id' => 'orphan1', 'ref' => 'blt-secure-custom-tor' );
		$cf->phases['http_request_firewall_custom']['rules'][] = array( 'id' => 'orphan2', 'ref' => 'blt-secure-custom-asn' );
		// Looks ours by description but not by ref: must survive.
		$cf->phases['http_request_firewall_custom']['rules'][] = array( 'id' => 'lookalike', 'ref' => 'someone', 'description' => '[BLT Secure] Block sensitive path probes' );

		$state    = $this->state();
		$deployer = $this->deployer( $cf, $state );
		$this->assertTrue( $deployer->remove( 'custom_pack' ) );

		$this->assertSame( array( 'other-tool-1', 'someone' ), $cf->refs( 'http_request_firewall_custom' ) );
	}

	public function test_redeploying_the_pack_retires_the_old_standalone_tor_rule() {
		$cf = new Blt_Test_Fake_Cf();
		$cf->plan = 'free';
		$cf->seed_foreign( 'http_request_firewall_custom', 1 );
		$cf->phases['http_request_firewall_custom']['rules'][] = array( 'id' => 'old-tor', 'ref' => 'blt-secure-custom-tor' );
		$state = $this->state( 'example.org', 'free' );

		$this->assertIsArray( $this->deployer( $cf, $state )->deploy( 'custom_pack' ) );
		$this->assertNotContains( 'blt-secure-custom-tor', $cf->refs( 'http_request_firewall_custom' ) );
		$this->assertContains( 'other-tool-1', $cf->refs( 'http_request_firewall_custom' ) );
	}

	// -------------------------------------------------------------------
	// Partial failure.
	// -------------------------------------------------------------------

	public function test_partial_failure_persists_progress_and_stays_removable() {
		$cf = new Blt_Test_Fake_Cf();
		$cf->plan = 'free';
		$cf->seed_foreign( 'http_request_firewall_custom', 1 );
		$cf->fail = function ( $method, $path, $body ) use ( $cf ) {
			if ( 'POST' === $method && is_array( $body ) && isset( $body['ref'] ) && 'blt-secure-custom-paths' === $body['ref'] ) {
				return $cf->err( 400, 20217, 'exceeded maximum number of rules' );
			}
			return null;
		};
		$state    = $this->state( 'example.org', 'free' );
		$deployer = $this->deployer( $cf, $state );

		$result = $deployer->deploy( 'custom_pack' );
		$this->assertInstanceOf( WP_Error::class, $result );

		$record = $state->deployment( 'custom_pack' );
		$this->assertIsArray( $record, 'progress must be recorded so the card can show and remove it' );
		$this->assertTrue( $record['partial'] );
		$this->assertArrayHasKey( 'asn', $record['rule_ids'] );
		$this->assertSame( array( 'other-tool-1', 'blt-secure-custom-asn' ), $cf->refs( 'http_request_firewall_custom' ) );

		// A retry completes the job and clears the partial flag.
		$cf->fail = null;
		$done     = $deployer->deploy( 'custom_pack' );
		$this->assertIsArray( $done );
		$this->assertArrayNotHasKey( 'partial', $state->deployment( 'custom_pack' ) );
		$this->assertSame( array( 'other-tool-1', 'blt-secure-custom-asn', 'blt-secure-custom-paths' ), $cf->refs( 'http_request_firewall_custom' ) );

		// And Remove deletes only ours.
		$this->assertTrue( $deployer->remove( 'custom_pack' ) );
		$this->assertSame( array( 'other-tool-1' ), $cf->refs( 'http_request_firewall_custom' ) );
	}

	// -------------------------------------------------------------------
	// WAF tier: chosen from the plan, never from an error.
	// -------------------------------------------------------------------

	public function test_waf_tier_follows_the_plan() {
		$cf       = new Blt_Test_Fake_Cf();
		$state    = $this->state( 'example.org', 'free' );
		$deployer = $this->deployer( $cf, $state );
		$cf->plan = 'free';

		$record = $deployer->deploy( 'waf_managed' );
		$this->assertSame( 'free', $record['tier'] );
		$this->assertSame( array( 'blt-secure-waf-free' ), $cf->refs( 'http_request_firewall_managed' ) );

		// Upgrade: full tier deployed, the free rule retired (no untracked leftovers).
		$cf->plan = 'pro';
		$state->update_plan( 'free' ); // Stale cache is refreshed after the TTL.
		$zone = $state->all();
		$zone['zone']['plan_checked'] = time() - 3600;
		update_option( Blt_Secure_Cloudflare_State::OPTION, $zone );
		$record = $this->deployer( $cf, $state )->deploy( 'waf_managed' );
		$this->assertSame( 'full', $record['tier'] );
		$this->assertSame( array( 'blt-secure-waf-managed', 'blt-secure-waf-owasp' ), $cf->refs( 'http_request_firewall_managed' ) );

		// Downgrade: the paid rules are retired.
		$cf->plan = 'free';
		$zone     = $state->all();
		$zone['zone']['plan_checked'] = time() - 3600;
		update_option( Blt_Secure_Cloudflare_State::OPTION, $zone );
		$record = $this->deployer( $cf, $state )->deploy( 'waf_managed' );
		$this->assertSame( 'free', $record['tier'] );
		$this->assertSame( array( 'blt-secure-waf-free' ), $cf->refs( 'http_request_firewall_managed' ) );
	}

	public function test_an_unreadable_plan_never_downgrades_a_paid_zone() {
		$cf       = new Blt_Test_Fake_Cf();
		$state    = $this->state( 'example.org', 'pro' );
		$deployer = $this->deployer( $cf, $state );
		$cf->plan = 'pro';
		$first    = $deployer->deploy( 'waf_managed' );
		$this->assertSame( 'full', $first['tier'] );
		$before = $cf->refs( 'http_request_firewall_managed' );
		$this->assertSame( array( 'blt-secure-waf-managed', 'blt-secure-waf-owasp' ), $before );

		// Upgrade path: state from an older version has no plan, and Cloudflare does not report one now.
		$zone                         = $state->all();
		$zone['zone']['plan']         = '';
		$zone['zone']['plan_checked'] = time() - 3600;
		update_option( Blt_Secure_Cloudflare_State::OPTION, $zone );
		$cf->plan = '';

		$result = $this->deployer( $cf, $state )->deploy( 'waf_managed' );

		$this->assertTrue( is_wp_error( $result ) );
		$this->assertSame( 'blt_cf_plan_unknown', $result->get_error_code() );
		$this->assertSame( $before, $cf->refs( 'http_request_firewall_managed' ), 'The paid rulesets must still be there.' );
		$this->assertSame( array(), $cf->deleted, 'Nothing may be deleted when the plan is unknown.' );
	}

	public function test_host_guard_accepts_upgraded_state_www_and_ignores_the_shared_store_host() {
		$cf = new Blt_Test_Fake_Cf();

		// v1.1.0 stored the plain home_url host, same derivation as today.
		$state = $this->state( 'example.org', 'pro' );
		$this->assertFalse( is_wp_error( $this->deployer( $cf, $state, 'example.org' )->deploy( 'custom_pack' ) ) );

		// www and the bare domain are one site.
		$this->assertFalse( is_wp_error( $this->deployer( $cf, $state, 'www.example.org' )->deploy( 'custom_pack' ) ) );
		$www = $this->state( 'www.example.org', 'pro' );
		$this->assertFalse( is_wp_error( $this->deployer( $cf, $www, 'example.org' )->deploy( 'custom_pack' ) ) );

		// A staging clone on a sibling subdomain is NOT.
		$clone = $this->deployer( $cf, $state, 'staging.example.org' )->deploy( 'custom_pack' );
		$this->assertTrue( is_wp_error( $clone ) );
		$this->assertSame( 'blt_cf_host_mismatch', $clone->get_error_code() );

		// A record from an older version with no stored host is never blocked by a host that came from
		// somewhere else (zone() gap-fills from the shared store; the guard reads only what this site stored).
		$old = new Blt_Secure_Cloudflare_State();
		$old->set_zone(
			array(
				'zone_id'    => 'zone123',
				'zone_name'  => 'example.org',
				'account_id' => 'acct456',
				'plan'       => 'pro',
			)
		);
		$this->assertSame( '', $old->stored_zone_host() );
		$this->assertFalse( is_wp_error( $this->deployer( $cf, $old, 'example.org' )->deploy( 'custom_pack' ) ) );
	}

	public function test_a_paid_plan_error_is_reported_not_silently_downgraded() {
		$cf       = new Blt_Test_Fake_Cf();
		$cf->plan = 'pro';
		$cf->fail = function ( $method, $path, $body ) use ( $cf ) {
			if ( 'POST' === $method && is_array( $body ) && isset( $body['ref'] ) && 'blt-secure-waf-owasp' === $body['ref'] ) {
				return $cf->err( 400, 20217, 'bad override' );
			}
			return null;
		};
		$state    = $this->state( 'example.org', 'pro' );
		$deployer = $this->deployer( $cf, $state );

		$result = $deployer->deploy( 'waf_managed' );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'blt_cf_validation', $result->get_error_code() );
		$this->assertNotContains( 'blt-secure-waf-free', $cf->refs( 'http_request_firewall_managed' ) );
		// The managed rule that did land is tracked, so Remove can clean it.
		$this->assertTrue( $state->deployment( 'waf_managed' )['partial'] );
		$this->assertTrue( $deployer->remove( 'waf_managed' ) );
		$this->assertSame( array(), $cf->refs( 'http_request_firewall_managed' ) );
	}

	// -------------------------------------------------------------------
	// Plan budget.
	// -------------------------------------------------------------------

	public function test_budget_check_skips_before_changing_anything() {
		$cf       = new Blt_Test_Fake_Cf();
		$cf->plan = 'free';
		$cf->seed_foreign( 'http_request_firewall_custom', 4 ); // 4 of 5 used; the pack needs 2.
		$state    = $this->state( 'example.org', 'free' );
		$deployer = $this->deployer( $cf, $state );

		$result = $deployer->deploy( 'custom_pack' );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'blt_cf_budget', $result->get_error_code() );
		$this->assertSame( array( 'skipped' => true ), $result->get_error_data() );
		$this->assertSame( 0, $cf->count( 'POST' ) );
		$this->assertSame( 0, $cf->count( 'PATCH' ) );
		$this->assertNull( $state->deployment( 'custom_pack' ) );

		// One rule still fits.
		$one = $deployer->deploy( 'country_block', array( 'countries' => 'CN' ) );
		$this->assertIsArray( $one );
	}

	public function test_whole_plugin_fits_a_clean_free_zone() {
		$cf       = new Blt_Test_Fake_Cf();
		$cf->plan = 'free';
		$state    = $this->state( 'example.org', 'free' );
		$deployer = $this->deployer( $cf, $state );

		foreach ( array( 'custom_pack', 'leaked_creds' ) as $feature ) {
			$this->assertIsArray( $deployer->deploy( $feature ), $feature );
		}
		$this->assertIsArray( $deployer->deploy( 'country_block', array( 'countries' => 'CN' ) ) );
		$this->assertIsArray( $deployer->deploy( 'rate_limit', array( 'login_slug' => '' ) ) );
		$this->assertIsArray( $deployer->sync_ioc_list( array( '8.8.8.8' ) ) );
		$this->assertCount( 5, $cf->phases['http_request_firewall_custom']['rules'] );

		// The user adds a rule of their own; re-adding a sixth is refused up front.
		$deployer = $this->deployer( $cf, $state );
		$this->assertTrue( $deployer->remove( 'country_block' ) );
		$cf->phases['http_request_firewall_custom']['rules'][] = array( 'id' => 'mine', 'ref' => 'mine' );
		$result = $deployer->deploy( 'country_block', array( 'countries' => 'CN' ) );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'blt_cf_budget', $result->get_error_code() );
	}

	public function test_rate_limit_payload_is_free_safe_on_free_and_full_on_pro() {
		$cf       = new Blt_Test_Fake_Cf();
		$cf->plan = 'free';
		$state    = $this->state( 'example.org', 'free' );
		$this->deployer( $cf, $state )->deploy( 'rate_limit' );
		$rule = $cf->phases['http_ratelimit']['rules'][0];
		$this->assertSame( 10, $rule['ratelimit']['period'] );
		$this->assertSame( 10, $rule['ratelimit']['mitigation_timeout'] );

		$cf2       = new Blt_Test_Fake_Cf();
		$cf2->plan = 'pro';
		$GLOBALS['blt_test_options'] = array();
		$state2    = $this->state( 'example.org', 'pro' );
		$this->deployer( $cf2, $state2 )->deploy( 'rate_limit' );
		$rule = $cf2->phases['http_ratelimit']['rules'][0];
		$this->assertSame( 60, $rule['ratelimit']['period'] );
		$this->assertSame( 600, $rule['ratelimit']['mitigation_timeout'] );
	}

	// -------------------------------------------------------------------
	// Leaked credentials by plan.
	// -------------------------------------------------------------------

	public function test_leaked_creds_by_plan() {
		foreach ( array(
			'free'       => array( 'password_leaked', false ),
			'pro'        => array( 'username_and_password_leaked', false ),
			'business'   => array( 'username_and_password_leaked', false ),
			'enterprise' => array( 'username_and_password_leaked', true ),
		) as $plan => $expect ) {
			$GLOBALS['blt_test_options'] = array();
			$cf       = new Blt_Test_Fake_Cf();
			$cf->plan = $plan;
			$state    = $this->state( 'example.org', $plan );
			$result   = $this->deployer( $cf, $state )->deploy( 'leaked_creds' );

			$this->assertIsArray( $result, $plan );
			$rule = $cf->phases['http_request_firewall_custom']['rules'][0];
			$this->assertStringContainsString( $expect[0], $rule['expression'], $plan );
			// Custom detections are Enterprise-only: no POST for anyone else.
			$this->assertSame( $expect[1] ? 1 : 0, $cf->count( 'POST /zones/zone123/leaked-credential-checks/detections' ), $plan );
		}
	}

	public function test_leaked_creds_detection_ownership() {
		$cf       = new Blt_Test_Fake_Cf();
		$cf->plan = 'enterprise';
		$state    = $this->state( 'example.org', 'enterprise' );
		$deployer = $this->deployer( $cf, $state );

		// Created by us: deleted on Remove.
		$deployer->deploy( 'leaked_creds' );
		$this->assertTrue( $state->deployment( 'leaked_creds' )['detection_owned'] );
		$this->assertCount( 1, $cf->detections );
		$deployer->remove( 'leaked_creds' );
		$this->assertCount( 0, $cf->detections );

		// Pre-existing identical detection: adopted, NEVER deleted.
		$desired = Blt_Secure_Rule_Definitions::leaked_creds_detection();
		$cf->detections['mine'] = array_merge( $desired, array( 'id' => 'mine' ) );
		$deployer->deploy( 'leaked_creds' );
		$this->assertFalse( $state->deployment( 'leaked_creds' )['detection_owned'] );
		$deployer->remove( 'leaked_creds' );
		$this->assertArrayHasKey( 'mine', $cf->detections );
		$this->assertNotEmpty( $deployer->notes() );
	}

	public function test_leaked_creds_rolls_back_a_detection_it_created_when_the_rule_fails() {
		$cf       = new Blt_Test_Fake_Cf();
		$cf->plan = 'enterprise';
		$cf->fail = function ( $method, $path, $body ) use ( $cf ) {
			if ( 'POST' === $method && is_array( $body ) && isset( $body['ref'] ) ) {
				return $cf->err( 500, 1000, 'boom' );
			}
			return null;
		};
		$state = $this->state( 'example.org', 'enterprise' );
		$this->assertInstanceOf( WP_Error::class, $this->deployer( $cf, $state )->deploy( 'leaked_creds' ) );
		$this->assertCount( 0, $cf->detections );
	}

	// -------------------------------------------------------------------
	// Access.
	// -------------------------------------------------------------------

	public function test_access_creates_bypass_first_with_inline_policies() {
		$cf       = new Blt_Test_Fake_Cf();
		$state    = $this->state();
		$deployer = $this->deployer( $cf, $state );

		$record = $deployer->deploy( 'access', array( 'emails' => array( 'admin@example.org' ), 'login_slug' => '' ) );
		$this->assertIsArray( $record );

		$posts = array_values( array_filter( $cf->log, static function ( $l ) {
			return 0 === strpos( $l, 'POST /accounts/acct456/access/apps' );
		} ) );
		$this->assertCount( 2, $posts );
		$names = array_column( array_values( $cf->apps ), 'name' );
		$this->assertSame( '[BLT Secure] admin-ajax bypass - example.org', $names[0], 'bypass app must be created first' );
		foreach ( $cf->apps as $app ) {
			$this->assertCount( 1, $app['policies'], 'an app must never exist without its policy' );
			$this->assertArrayNotHasKey( 'self_hosted_domains', $app );
		}
		$this->assertTrue( $record['app_owned'] );
		$this->assertTrue( $record['bypass_app_owned'] );
		$this->assertArrayNotHasKey( 'partial', $record );
	}

	public function test_access_scope_is_probed_before_anything_is_created() {
		$cf       = new Blt_Test_Fake_Cf();
		$cf->fail = function ( $method, $path ) use ( $cf ) {
			if ( false !== strpos( $path, '/access/apps' ) ) {
				return $cf->err( 403, 10000, 'Authentication error' );
			}
			return null;
		};
		$state  = $this->state();
		$result = $this->deployer( $cf, $state )->deploy( 'access', array( 'emails' => array( 'admin@example.org' ) ) );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'blt_cf_scope', $result->get_error_code() );
		$this->assertSame( 0, $cf->count( 'POST' ) );
		$this->assertSame( 0, $cf->count( 'PUT' ) );
		$this->assertNull( $state->deployment( 'access' ) );
	}

	public function test_access_main_app_failure_rolls_back_the_bypass_app() {
		$cf       = new Blt_Test_Fake_Cf();
		$cf->fail = function ( $method, $path, $body ) use ( $cf ) {
			if ( 'POST' === $method && is_array( $body ) && isset( $body['name'] ) && false !== strpos( $body['name'], 'WordPress Admin' ) ) {
				return $cf->err( 400, 12130, 'invalid policy' );
			}
			return null;
		};
		$state  = $this->state();
		$result = $this->deployer( $cf, $state )->deploy( 'access', array( 'emails' => array( 'admin@example.org' ) ) );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertCount( 0, $cf->apps, 'nothing this run created may be left behind' );
		$this->assertNull( $state->deployment( 'access' ) );
	}

	public function test_failed_access_redeploy_keeps_the_existing_record_and_ownership() {
		$cf       = new Blt_Test_Fake_Cf();
		$state    = $this->state();
		$deployer = $this->deployer( $cf, $state );
		$first    = $deployer->deploy( 'access', array( 'emails' => array( 'one@example.org' ) ) );
		$this->assertTrue( $first['app_owned'] );
		$this->assertCount( 2, $cf->apps );

		// Redeploy with a changed email; the MAIN app update is rejected while the bypass app
		// already exists (so nothing was created this run and the bypass step is a no-op/update).
		$main_id  = $first['app_id'];
		$cf->fail = function ( $method, $path ) use ( $cf, $main_id ) {
			if ( 'PUT' === $method && false !== strpos( $path, '/access/apps/' . $main_id ) ) {
				return $cf->err( 500, 0, 'transient failure' );
			}
			return null;
		};
		$result = $this->deployer( $cf, $state )->deploy( 'access', array( 'emails' => array( 'two@example.org' ) ) );
		$this->assertInstanceOf( WP_Error::class, $result );

		// The live main app must still be tracked, and still owned, exactly as before.
		$after = $state->deployment( 'access' );
		$this->assertSame( $main_id, $after['app_id'], 'The live main app must not become untracked.' );
		$this->assertTrue( $after['app_owned'], 'Ownership of the main app must not be lost.' );
		$this->assertSame( $first['bypass_app_id'], $after['bypass_app_id'] );

		// A later Remove deletes BOTH apps (nothing orphaned, nothing half-deleted).
		$cf->fail = null;
		$this->assertTrue( $this->deployer( $cf, $state )->remove( 'access' ) );
		$this->assertCount( 0, $cf->apps, 'Remove after a failed redeploy must clean up both apps.' );
	}

	public function test_two_sites_in_one_account_never_adopt_or_delete_each_others_apps() {
		$cf = new Blt_Test_Fake_Cf();

		// Site A.
		$GLOBALS['blt_test_options'] = array();
		$state_a = $this->state( 'a.example.org' );
		$dep_a   = $this->deployer( $cf, $state_a, 'a.example.org' );
		$rec_a   = $dep_a->deploy( 'access', array( 'emails' => array( 'a@example.org' ) ) );
		$saved_a = $GLOBALS['blt_test_options'];

		// Site B (separate WordPress options, same Cloudflare account).
		$GLOBALS['blt_test_options'] = array();
		$state_b = $this->state( 'b.example.org' );
		$dep_b   = $this->deployer( $cf, $state_b, 'b.example.org' );
		$rec_b   = $dep_b->deploy( 'access', array( 'emails' => array( 'b@example.org' ) ) );

		$this->assertNotSame( $rec_a['app_id'], $rec_b['app_id'] );
		$this->assertCount( 4, $cf->apps );

		// B removes: only B's apps go.
		$this->assertTrue( $dep_b->remove( 'access' ) );
		$this->assertArrayHasKey( $rec_a['app_id'], $cf->apps );
		$this->assertArrayHasKey( $rec_a['bypass_app_id'], $cf->apps );
		$this->assertCount( 2, $cf->apps );

		unset( $saved_a );
	}

	public function test_adopted_access_app_is_updated_but_never_deleted() {
		$cf = new Blt_Test_Fake_Cf();
		// An app with this site's host-scoped name that this plugin did not create.
		$cf->apps['preexisting'] = array(
			'id'       => 'preexisting',
			'name'     => '[BLT Secure] WordPress Admin - example.org',
			'domain'   => 'example.org/old',
			'policies' => array(),
		);
		$state    = $this->state();
		$deployer = $this->deployer( $cf, $state );

		$record = $deployer->deploy( 'access', array( 'emails' => array( 'admin@example.org' ) ) );
		$this->assertSame( 'preexisting', $record['app_id'] );
		$this->assertFalse( $record['app_owned'] );
		// Adopted app is rewritten to the desired config (not returned stale).
		$this->assertSame( 'example.org/wp-admin', $cf->apps['preexisting']['domain'] );
		$this->assertSame( 1, $cf->count( 'PUT /accounts/acct456/access/apps/preexisting' ) );

		// Redeploy with unchanged config: no extra rewrite.
		$deployer->deploy( 'access', array( 'emails' => array( 'admin@example.org' ) ) );
		$this->assertSame( 1, $cf->count( 'PUT /accounts/acct456/access/apps/preexisting' ) );

		// Remove: the bypass app we created goes, the adopted app stays.
		$this->assertTrue( $deployer->remove( 'access' ) );
		$this->assertArrayHasKey( 'preexisting', $cf->apps );
		$this->assertCount( 1, $cf->apps );
		$this->assertNotEmpty( $deployer->notes() );
	}

	public function test_access_email_change_updates_the_deployed_app() {
		$cf       = new Blt_Test_Fake_Cf();
		$state    = $this->state();
		$deployer = $this->deployer( $cf, $state );
		$first    = $deployer->deploy( 'access', array( 'emails' => array( 'one@example.org' ) ) );
		$deployer->deploy( 'access', array( 'emails' => array( 'two@example.org' ) ) );

		$this->assertSame( 1, $cf->count( 'PUT /accounts/acct456/access/apps/' . $first['app_id'] ) );
		$this->assertSame(
			'two@example.org',
			$cf->apps[ $first['app_id'] ]['policies'][0]['include'][0]['email']['email']
		);
	}

	// -------------------------------------------------------------------
	// Zone / host drift.
	// -------------------------------------------------------------------

	public function test_mutations_refuse_when_the_site_host_drifted() {
		$cf       = new Blt_Test_Fake_Cf();
		$state    = $this->state( 'example.org' );
		$deployer = $this->deployer( $cf, $state, 'staging.example.net' );

		foreach ( array( $deployer->deploy( 'custom_pack' ), $deployer->remove( 'custom_pack' ), $deployer->sync_ioc_list( array( '8.8.8.8' ) ) ) as $result ) {
			$this->assertInstanceOf( WP_Error::class, $result );
			$this->assertSame( 'blt_cf_host_mismatch', $result->get_error_code() );
		}
		$this->assertSame( array(), $cf->log, 'a drifted site must not make a single API call' );
	}

	public function test_connecting_to_a_different_zone_forgets_old_deployments() {
		$state = $this->state();
		$state->set_deployment( 'custom_pack', array( 'ruleset_id' => 'rs-old', 'rule_ids' => array( 'asn' => 'x' ) ) );

		$same = $state->zone();
		$same['plan'] = 'business';
		$state->set_zone( $same );
		$this->assertNotNull( $state->deployment( 'custom_pack' ), 'same zone keeps its records' );

		$state->set_zone( array( 'zone_id' => 'other-zone', 'account_id' => 'a2', 'host' => 'example.org', 'plan' => 'free' ) );
		$this->assertNull( $state->deployment( 'custom_pack' ) );
	}

	public function test_connect_can_verify_without_persisting() {
		$cf = new Blt_Test_Fake_Cf();
		$cf->fail = function ( $method, $path ) use ( $cf ) {
			if ( '/user/tokens/verify' === $path ) {
				return $cf->err( 400, 1000, 'Invalid API Token' ); // Account-owned token.
			}
			if ( '/zones' === $path ) {
				return array(
					'response' => array( 'code' => 200 ),
					'body'     => json_encode( array( 'success' => true, 'result' => array( array( 'id' => 'zone123', 'name' => 'example.org', 'account' => array( 'id' => 'acct456' ), 'plan' => array( 'legacy_id' => 'free' ), 'status' => 'active' ) ) ) ), // phpcs:ignore
				);
			}
			return null;
		};
		$state    = new Blt_Secure_Cloudflare_State();
		$deployer = new Blt_Secure_Cloudflare_Deployer( $cf->api(), $state );

		$zone = $deployer->connect( 'example.org', false );
		$this->assertIsArray( $zone, 'verify falls back to a zone read when /user/tokens/verify rejects the token' );
		$this->assertSame( 'zone123', $zone['zone_id'] );
		$this->assertSame( array(), $state->zone(), 'nothing is stored until the caller stores the token first' );
	}

	// -------------------------------------------------------------------
	// IOC list sync.
	// -------------------------------------------------------------------

	public function test_ioc_sync_uses_a_host_scoped_list_filters_items_and_polls_the_operation() {
		$cf       = new Blt_Test_Fake_Cf();
		$state    = $this->state();
		$deployer = $this->deployer( $cf, $state );

		$record = $deployer->sync_ioc_list( array( '8.8.8.8', '1.2.0.0/16', '9.0.0.0/7', '0.0.0.0/0' ) );
		$this->assertIsArray( $record );

		$list = reset( $cf->lists );
		$this->assertSame( 'blt_secure_iocs_example_org', $list['name'] );
		$this->assertSame( array( array( 'ip' => '8.8.8.8' ), array( 'ip' => '1.2.0.0/16' ) ), $cf->items[ $list['id'] ], 'prefixes outside IPv4 /8-/32 are never sent' );
		$this->assertSame( '(ip.src in $blt_secure_iocs_example_org)', $cf->phases['http_request_firewall_custom']['rules'][0]['expression'] );
		$this->assertTrue( $record['list_owned'] );
		$this->assertFalse( $record['list_pending'] );
		$this->assertSame( 1, $cf->count( 'GET /accounts/acct456/rules/lists/bulk_operations/' ) );

		// Remove: rule first, then the list we created.
		$this->assertTrue( $deployer->remove_ioc_list() );
		$this->assertCount( 0, $cf->lists );
		$this->assertSame( array(), $cf->refs( 'http_request_firewall_custom' ) );
	}

	public function test_ioc_sync_reports_a_failed_bulk_operation() {
		$cf            = new Blt_Test_Fake_Cf();
		$cf->op_status = 'failed';
		$state         = $this->state();

		$result = $this->deployer( $cf, $state )->sync_ioc_list( array( '8.8.8.8' ) );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'blt_cf_list_failed', $result->get_error_code() );
		$this->assertStringContainsString( 'item 3 is invalid', $result->get_error_message() );
		$this->assertSame( array(), $cf->refs( 'http_request_firewall_custom' ), 'no block rule is attached to a list that failed to load' );
	}

	public function test_ioc_sync_polling_is_bounded_and_reports_pending() {
		$cf            = new Blt_Test_Fake_Cf();
		$cf->op_status = 'running';
		$state         = $this->state();

		$record = $this->deployer( $cf, $state )->sync_ioc_list( array( '8.8.8.8' ) );
		$this->assertIsArray( $record );
		$this->assertTrue( $record['list_pending'] );
		$this->assertSame( 5, $cf->count( 'GET /accounts/acct456/rules/lists/bulk_operations/' ) );
		$this->assertLessThanOrEqual( 15, array_sum( $cf->sleeps ) );
	}

	public function test_ioc_sync_checks_the_budget_before_creating_or_filling_the_list() {
		$cf       = new Blt_Test_Fake_Cf();
		$cf->plan = 'free';
		$cf->seed_foreign( 'http_request_firewall_custom', 5 );
		$state = $this->state( 'example.org', 'free' );

		$result = $this->deployer( $cf, $state )->sync_ioc_list( array( '8.8.8.8' ) );
		$this->assertSame( 'blt_cf_budget', $result->get_error_code() );
		$this->assertSame( 0, $cf->count( 'POST /accounts' ) );
		$this->assertSame( 0, $cf->count( 'PUT' ) );
		$this->assertCount( 0, $cf->lists );
	}

	public function test_ioc_adopted_legacy_list_is_reused_and_never_deleted() {
		$cf                  = new Blt_Test_Fake_Cf();
		$cf->lists['legacy'] = array( 'id' => 'legacy', 'name' => 'blt_secure_iocs', 'kind' => 'ip' );
		$state               = $this->state();
		// Record written by an older version: list id, no ownership flag.
		$state->set_deployment( 'ioc', array( 'list_id' => 'legacy', 'rule_ids' => array() ) );
		$deployer = $this->deployer( $cf, $state );

		$record = $deployer->sync_ioc_list( array( '8.8.8.8' ) );
		$this->assertSame( 'legacy', $record['list_id'] );
		$this->assertSame( 'blt_secure_iocs', $record['list_name'] );
		$this->assertFalse( $record['list_owned'] );
		$this->assertSame( 0, $cf->count( 'POST /accounts/acct456/rules/lists' ) );

		$this->assertTrue( $deployer->remove_ioc_list() );
		$this->assertArrayHasKey( 'legacy', $cf->lists );
		$this->assertNotEmpty( $deployer->notes() );
	}
}

/**
 * API client: error mapping, retry, redirects, pagination, id encoding.
 */
class Test_Cf_Api_Resilience extends TestCase {

	private function api_with( array $responses, array &$log, array &$sleeps ) {
		return new Blt_Secure_Cloudflare_Api(
			'tok',
			function ( $url, $args ) use ( &$responses, &$log ) {
				$log[] = array( $url, $args );
				return array_shift( $responses );
			},
			function ( $seconds ) use ( &$sleeps ) {
				$sleeps[] = $seconds;
			}
		);
	}

	private function resp( $status, array $body, array $headers = array() ) {
		return array(
			'response' => array( 'code' => $status ),
			'headers'  => $headers,
			'body'     => json_encode( $body ), // phpcs:ignore
		);
	}

	public function test_403_with_code_10000_is_a_permission_problem() {
		$log    = array();
		$sleeps = array();
		$api    = $this->api_with( array( $this->resp( 403, array( 'success' => false, 'errors' => array( array( 'code' => 10000, 'message' => 'Authentication error' ) ) ) ) ), $log, $sleeps );

		$error = $api->get( '/zones/x/rulesets' );
		$this->assertSame( 'blt_cf_scope', $error->get_error_code() );
	}

	public function test_401_and_non_403_10000_stay_auth_errors() {
		$log    = array();
		$sleeps = array();
		$api    = $this->api_with( array( $this->resp( 401, array( 'success' => false, 'errors' => array( array( 'code' => 10000, 'message' => 'Authentication error' ) ) ) ) ), $log, $sleeps );
		$this->assertSame( 'blt_cf_auth', $api->get( '/x' )->get_error_code() );
	}

	public function test_a_403_plan_refusal_is_a_plan_error_not_a_scope_error() {
		$log    = array();
		$sleeps = array();
		$api    = $this->api_with( array( $this->resp( 403, array( 'success' => false, 'errors' => array( array( 'code' => 1, 'message' => 'This feature is not available on your plan' ) ) ) ) ), $log, $sleeps );
		$this->assertSame( 'blt_cf_plan', $api->get( '/x' )->get_error_code() );

		// "explanation" contains the letters "plan" but is not a plan error.
		$api = $this->api_with( array( $this->resp( 400, array( 'success' => false, 'errors' => array( array( 'code' => 5, 'message' => 'see explanation' ) ) ) ) ), $log, $sleeps );
		$this->assertSame( 'blt_cf_validation', $api->get( '/x' )->get_error_code() );
	}

	public function test_429_is_retried_with_retry_after_then_succeeds() {
		$log    = array();
		$sleeps = array();
		$api    = $this->api_with(
			array(
				$this->resp( 429, array( 'success' => false, 'errors' => array( array( 'code' => 971, 'message' => 'slow down' ) ) ), array( 'Retry-After' => '3' ) ),
				$this->resp( 200, array( 'success' => true, 'result' => array( 'ok' => 1 ) ) ),
			),
			$log,
			$sleeps
		);

		$this->assertSame( array( 'ok' => 1 ), $api->get( '/x' ) );
		$this->assertCount( 2, $log );
		$this->assertSame( array( 3 ), $sleeps );
	}

	public function test_429_retries_are_bounded_and_clamped() {
		$log    = array();
		$sleeps = array();
		$limited = $this->resp( 429, array( 'success' => false, 'errors' => array( array( 'code' => 971, 'message' => 'slow down' ) ) ), array( 'retry-after' => '9999' ) );
		$api     = $this->api_with( array( $limited, $limited, $limited, $limited ), $log, $sleeps );

		$error = $api->get( '/x' );
		$this->assertSame( 'blt_cf_rate_limited', $error->get_error_code() );
		$this->assertCount( 3, $log, 'one attempt plus two retries, never more' );
		$this->assertSame( array( 5, 5 ), $sleeps, 'a hostile Retry-After is clamped' );
	}

	public function test_requests_never_follow_redirects_and_carry_the_bearer_only_to_cloudflare() {
		$log    = array();
		$sleeps = array();
		$api    = $this->api_with( array( $this->resp( 200, array( 'success' => true, 'result' => array() ) ) ), $log, $sleeps );
		$api->get( '/zones' );

		$this->assertSame( 0, $log[0][1]['redirection'] );
		$this->assertStringStartsWith( 'https://api.cloudflare.com/client/v4/', $log[0][0] );
		$this->assertArrayHasKey( 'limit_response_size', $log[0][1] );
	}

	public function test_ids_are_url_encoded() {
		$this->assertSame( 'a%2Fb%3F', Blt_Secure_Cloudflare_Api::seg( 'a/b?' ) );
	}

	public function test_get_all_follows_result_info_pages() {
		$log    = array();
		$sleeps = array();
		$api    = $this->api_with(
			array(
				array(
					'response' => array( 'code' => 200 ),
					'body'     => json_encode( array( 'success' => true, 'result' => array( array( 'id' => 1 ), array( 'id' => 2 ) ), 'result_info' => array( 'page' => 1, 'total_pages' => 2 ) ) ), // phpcs:ignore
				),
				array(
					'response' => array( 'code' => 200 ),
					'body'     => json_encode( array( 'success' => true, 'result' => array( array( 'id' => 3 ) ), 'result_info' => array( 'page' => 2, 'total_pages' => 2 ) ) ), // phpcs:ignore
				),
			),
			$log,
			$sleeps
		);

		$all = $api->get_all( '/accounts/a/access/apps' );
		$this->assertSame( array( 1, 2, 3 ), array_column( $all, 'id' ) );
		$this->assertStringContainsString( 'page=2', $log[1][0] );
	}
}

/**
 * IOC feed fetch folding: a failed feed must never shrink the list.
 */
class Test_Ioc_Collect extends TestCase {

	public function test_failed_feeds_are_reported_not_merged_silently() {
		require_once BLT_SECURE_DIR . 'includes/modules/class-ioc.php';

		$good = "8.8.8.0/24\n1.2.3.4\n";
		$out  = Blt_Secure_Ioc::collect(
			array(
				array( 'id' => 'a', 'format' => 'ip-list', 'code' => 200, 'body' => $good, 'error' => '' ),
				array( 'id' => 'b', 'format' => 'ip-list', 'code' => 0, 'body' => '', 'error' => 'timed out' ),
				array( 'id' => 'c', 'format' => 'ip-list', 'code' => 503, 'body' => 'oops', 'error' => '' ),
				array( 'id' => 'd', 'format' => 'ip-list', 'code' => 200, 'body' => '<html>moved</html>', 'error' => '' ),
			)
		);

		$this->assertSame( array( 'b', 'c', 'd' ), array_keys( $out['failed'] ) );
		$this->assertSame( 'timed out', $out['failed']['b'] );
		$this->assertSame( 'HTTP 503', $out['failed']['c'] );
		$this->assertSame( 'no usable entries', $out['failed']['d'] );
		$this->assertSame( array( 'a' => 2 ), $out['per_feed'] );
	}

	public function test_all_good_feeds_merge_and_dedupe() {
		require_once BLT_SECURE_DIR . 'includes/modules/class-ioc.php';

		$out = Blt_Secure_Ioc::collect(
			array(
				array( 'id' => 'a', 'format' => 'ip-list', 'code' => 200, 'body' => "8.8.8.8\n", 'error' => '' ),
				array( 'id' => 'b', 'format' => 'ip-list', 'code' => 200, 'body' => "8.8.8.8\n1.2.3.4\n", 'error' => '' ),
			)
		);
		$this->assertSame( array(), $out['failed'] );
		$this->assertSame( array( '8.8.8.8', '1.2.3.4' ), $out['ips'] );
	}

	public function test_feeds_must_be_https() {
		$this->assertNull( Blt_Secure_Feeds::normalize_feed( array( 'id' => 'x', 'url' => 'http://insecure.example/feed.txt', 'format' => 'ip-list' ) ) );
		$this->assertNotNull( Blt_Secure_Feeds::normalize_feed( array( 'id' => 'x', 'url' => 'https://secure.example/feed.txt', 'format' => 'ip-list' ) ) );
	}
}
