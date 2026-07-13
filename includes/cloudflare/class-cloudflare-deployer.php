<?php
/**
 * Cloudflare deployment orchestrator.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Deploys/removes the five Phase-1 Cloudflare features idempotently.
 *
 * Deploy = reconcile: fetch the phase entrypoint ruleset, index existing
 * rules by our "ref", PATCH matches and POST the missing — never PUT the
 * whole entrypoint (other tools' rules live there too). Removal deletes by
 * stored ID and treats 404 as success.
 */
class Blt_Secure_Cloudflare_Deployer {

	const FEATURES = array( 'waf_managed', 'custom_pack', 'country_block', 'rate_limit', 'leaked_creds', 'access' );

	/**
	 * API client.
	 *
	 * @var Blt_Secure_Cloudflare_Api
	 */
	private $api;

	/**
	 * State store.
	 *
	 * @var Blt_Secure_Cloudflare_State
	 */
	private $state;

	/**
	 * Constructor.
	 *
	 * @param Blt_Secure_Cloudflare_Api   $api API client.
	 * @param Blt_Secure_Cloudflare_State $state State store.
	 */
	public function __construct( Blt_Secure_Cloudflare_Api $api, Blt_Secure_Cloudflare_State $state ) {
		$this->api   = $api;
		$this->state = $state;
	}

	/**
	 * Verify token and (re)discover the zone; persists identity.
	 *
	 * @param string $host Site host.
	 * @return array|WP_Error Zone summary.
	 */
	public function connect( $host ) {
		$verify = $this->api->verify_token();
		if ( is_wp_error( $verify ) ) {
			return $verify;
		}

		$zone = $this->api->discover_zone( $host );
		if ( is_wp_error( $zone ) ) {
			return $zone;
		}

		$summary = array(
			'zone_id'    => isset( $zone['id'] ) ? $zone['id'] : '',
			'zone_name'  => isset( $zone['name'] ) ? $zone['name'] : '',
			'account_id' => isset( $zone['account']['id'] ) ? $zone['account']['id'] : '',
			'plan'       => isset( $zone['plan']['legacy_id'] ) ? $zone['plan']['legacy_id'] : ( isset( $zone['plan']['name'] ) ? strtolower( $zone['plan']['name'] ) : '' ),
			'host'       => $host,
		);
		$this->state->set_zone( $summary );

		return $summary;
	}

	/**
	 * Deploy one feature.
	 *
	 * @param string $feature Feature key.
	 * @param array  $config Feature-specific config (paranoia, slug, emails...).
	 * @return array|WP_Error Deployment record.
	 */
	public function deploy( $feature, array $config = array() ) {
		$zone = $this->state->zone();
		if ( empty( $zone['zone_id'] ) ) {
			return new WP_Error( 'blt_cf_not_connected', __( 'Cloudflare is not connected yet — verify your token first.', 'blt-secure' ) );
		}

		switch ( $feature ) {
			case 'waf_managed':
				return $this->deploy_waf_managed( $zone, $config );
			case 'custom_pack':
				return $this->deploy_ruleset_feature( $zone, 'custom_pack', Blt_Secure_Rule_Definitions::PHASE_CUSTOM, Blt_Secure_Rule_Definitions::custom_pack_rules() );
			case 'country_block':
				return $this->deploy_country_block( $zone, $config );
			case 'rate_limit':
				$slug = isset( $config['login_slug'] ) ? (string) $config['login_slug'] : '';
				return $this->deploy_ruleset_feature( $zone, 'rate_limit', Blt_Secure_Rule_Definitions::PHASE_RATELIMIT, Blt_Secure_Rule_Definitions::rate_limit_rules( $slug ) );
			case 'leaked_creds':
				return $this->deploy_leaked_creds( $zone );
			case 'access':
				return $this->deploy_access( $zone, $config );
		}

		return new WP_Error( 'blt_cf_unknown_feature', __( 'Unknown Cloudflare feature.', 'blt-secure' ) );
	}

	/**
	 * Remove one feature's deployment.
	 *
	 * @param string $feature Feature key.
	 * @return true|WP_Error
	 */
	public function remove( $feature ) {
		$zone   = $this->state->zone();
		$record = $this->state->deployment( $feature );

		if ( null === $record ) {
			return true; // Nothing deployed.
		}

		switch ( $feature ) {
			case 'waf_managed':
			case 'custom_pack':
			case 'country_block':
			case 'rate_limit':
				$result = $this->remove_rules( $zone, $record );
				break;

			case 'leaked_creds':
				$result = $this->remove_leaked_creds( $zone, $record );
				break;

			case 'access':
				$result = $this->remove_access( $zone, $record );
				break;

			default:
				return new WP_Error( 'blt_cf_unknown_feature', __( 'Unknown Cloudflare feature.', 'blt-secure' ) );
		}

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$this->state->clear_deployment( $feature );
		return true;
	}

	/**
	 * Remove everything (uninstall opt-in path). Best-effort.
	 *
	 * @return void
	 */
	public function remove_all() {
		foreach ( self::FEATURES as $feature ) {
			$this->remove( $feature );
		}
		$this->remove_ioc_list();
	}

	// -------------------------------------------------------------------
	// IOC blocklist (account IP List + one referencing custom rule).
	// -------------------------------------------------------------------

	/**
	 * Push a set of IP/CIDR indicators to the account IP List and ensure the
	 * custom-phase rule that blocks them exists. Idempotent: the list is
	 * reused by name and the rule reconciled by ref.
	 *
	 * @param string[] $ips Validated IP/CIDR strings.
	 * @return array|WP_Error Deployment record (list_id, rule_ids, count).
	 */
	public function sync_ioc_list( array $ips ) {
		$zone = $this->state->zone();
		if ( empty( $zone['zone_id'] ) || empty( $zone['account_id'] ) ) {
			return new WP_Error( 'blt_cf_not_connected', __( 'Cloudflare is not connected yet — verify your token first.', 'blt-secure' ) );
		}

		$list = $this->find_or_create_ioc_list( $zone['account_id'] );
		if ( is_wp_error( $list ) ) {
			return $list;
		}
		$list_id = isset( $list['id'] ) ? $list['id'] : '';
		if ( '' === $list_id ) {
			return new WP_Error( 'blt_cf_validation', __( 'Cloudflare did not return an IP List id.', 'blt-secure' ) );
		}

		// Bulk-replace the list contents (Cloudflare expects [{ip:…}, …]).
		$items = array();
		foreach ( $ips as $ip ) {
			$items[] = array( 'ip' => $ip );
		}
		$replaced = $this->api->put( '/accounts/' . $zone['account_id'] . '/rules/lists/' . $list_id . '/items', $items );
		if ( is_wp_error( $replaced ) ) {
			return $replaced;
		}

		// Ensure the referencing block rule (custom phase).
		return $this->deploy_ruleset_feature(
			$zone,
			'ioc',
			Blt_Secure_Rule_Definitions::PHASE_CUSTOM,
			Blt_Secure_Rule_Definitions::ioc_block_rules(),
			array(
				'list_id' => $list_id,
				'count'   => count( $ips ),
			)
		);
	}

	/**
	 * Delete the IOC block rule and the account IP List. 404 = already gone.
	 *
	 * @return true|WP_Error
	 */
	public function remove_ioc_list() {
		$zone   = $this->state->zone();
		$record = $this->state->deployment( 'ioc' );
		if ( null === $record ) {
			return true;
		}

		// Rule must go first — a list cannot be deleted while referenced.
		$removed = $this->remove_rules( $zone, $record );
		if ( is_wp_error( $removed ) ) {
			return $removed;
		}

		if ( ! empty( $record['list_id'] ) && ! empty( $zone['account_id'] ) ) {
			$deleted = $this->api->delete( '/accounts/' . $zone['account_id'] . '/rules/lists/' . $record['list_id'] );
			if ( is_wp_error( $deleted ) && ! $this->is_not_found( $deleted ) ) {
				return $deleted;
			}
		}

		$this->state->clear_deployment( 'ioc' );
		return true;
	}

	/**
	 * Adopt the account IP List by name, or create it.
	 *
	 * @param string $account_id Account id.
	 * @return array|WP_Error List object.
	 */
	private function find_or_create_ioc_list( $account_id ) {
		$lists = $this->api->get( '/accounts/' . $account_id . '/rules/lists' );
		if ( ! is_wp_error( $lists ) ) {
			foreach ( $lists as $list ) {
				if ( isset( $list['name'], $list['id'] ) && Blt_Secure_Rule_Definitions::IOC_LIST_NAME === $list['name'] ) {
					return $list;
				}
			}
		} elseif ( in_array( $lists->get_error_code(), array( 'blt_cf_auth', 'blt_cf_scope' ), true ) ) {
			// Missing Account Filter Lists permission must surface, not create.
			return $lists;
		}

		return $this->api->post(
			'/accounts/' . $account_id . '/rules/lists',
			array(
				'name'        => Blt_Secure_Rule_Definitions::IOC_LIST_NAME,
				'kind'        => 'ip',
				'description' => '[BLT Secure] Synced threat-intel indicators',
			)
		);
	}

	// -------------------------------------------------------------------
	// Feature: managed WAF.
	// -------------------------------------------------------------------

	/**
	 * Deploy managed rulesets, degrading to the free ruleset when the plan
	 * refuses the paid ones.
	 *
	 * @param array $zone Zone identity.
	 * @param array $config paranoia / score_threshold.
	 * @return array|WP_Error
	 */
	private function deploy_waf_managed( array $zone, array $config ) {
		$paranoia  = isset( $config['paranoia'] ) ? (int) $config['paranoia'] : 2;
		$threshold = isset( $config['score_threshold'] ) ? (int) $config['score_threshold'] : 40;

		$rules  = Blt_Secure_Rule_Definitions::managed_waf_rules( $paranoia, $threshold );
		$result = $this->deploy_ruleset_feature( $zone, 'waf_managed', Blt_Secure_Rule_Definitions::PHASE_MANAGED, $rules, array( 'tier' => 'full' ) );

		if ( is_wp_error( $result ) && in_array( $result->get_error_code(), array( 'blt_cf_plan', 'blt_cf_validation' ), true ) ) {
			// Free-plan fallback.
			$free = Blt_Secure_Rule_Definitions::managed_waf_rules_free();
			return $this->deploy_ruleset_feature( $zone, 'waf_managed', Blt_Secure_Rule_Definitions::PHASE_MANAGED, $free, array( 'tier' => 'free' ) );
		}

		return $result;
	}

	// -------------------------------------------------------------------
	// Feature: country block.
	// -------------------------------------------------------------------

	/**
	 * Deploy the country-block rule. Refuses an empty selection so a bad
	 * request can never deploy a rule with an always-false (or malformed)
	 * expression.
	 *
	 * @param array $zone Zone identity.
	 * @param array $config countries / login_only / login_slug.
	 * @return array|WP_Error
	 */
	private function deploy_country_block( array $zone, array $config ) {
		$countries = isset( $config['countries'] ) ? Blt_Secure_Rule_Definitions::sanitize_country_codes( $config['countries'] ) : array();
		if ( empty( $countries ) ) {
			return new WP_Error( 'blt_cf_validation', __( 'Choose at least one country to block first.', 'blt-secure' ) );
		}

		$login_only = ! empty( $config['login_only'] );
		$slug       = isset( $config['login_slug'] ) ? (string) $config['login_slug'] : '';

		return $this->deploy_ruleset_feature(
			$zone,
			'country_block',
			Blt_Secure_Rule_Definitions::PHASE_CUSTOM,
			Blt_Secure_Rule_Definitions::country_block_rules( $countries, $login_only, $slug ),
			array(
				'countries'  => $countries,
				'login_only' => $login_only,
			)
		);
	}

	// -------------------------------------------------------------------
	// Ruleset-engine plumbing (shared by waf_managed / custom_pack / rate_limit).
	// -------------------------------------------------------------------

	/**
	 * Reconcile a set of desired rules into a phase entrypoint.
	 *
	 * @param array  $zone Zone identity.
	 * @param string $feature Feature key for state.
	 * @param string $phase Ruleset phase.
	 * @param array  $rules Desired rules keyed by ref suffix.
	 * @param array  $extra Extra fields to store in the record.
	 * @return array|WP_Error Deployment record.
	 */
	private function deploy_ruleset_feature( array $zone, $feature, $phase, array $rules, array $extra = array() ) {
		$entrypoint = $this->ensure_entrypoint( $zone['zone_id'], $phase );
		if ( is_wp_error( $entrypoint ) ) {
			return $entrypoint;
		}

		$ruleset_id = $entrypoint['id'];
		$existing   = array();
		if ( ! empty( $entrypoint['rules'] ) && is_array( $entrypoint['rules'] ) ) {
			foreach ( $entrypoint['rules'] as $rule ) {
				if ( ! empty( $rule['ref'] ) && ! empty( $rule['id'] ) ) {
					$existing[ $rule['ref'] ] = $rule['id'];
				}
			}
		}

		$rule_ids = array();
		foreach ( $rules as $key => $payload ) {
			$ref = $payload['ref'];

			if ( isset( $existing[ $ref ] ) ) {
				$result = $this->api->patch(
					'/zones/' . $zone['zone_id'] . '/rulesets/' . $ruleset_id . '/rules/' . $existing[ $ref ],
					$payload
				);
			} else {
				$result = $this->api->post(
					'/zones/' . $zone['zone_id'] . '/rulesets/' . $ruleset_id . '/rules',
					$payload
				);
			}

			if ( is_wp_error( $result ) ) {
				return $result;
			}

			// Rule mutation endpoints return the updated ruleset; find our rule.
			$rule_ids[ $key ] = $this->find_rule_id_by_ref( $result, $ref, isset( $existing[ $ref ] ) ? $existing[ $ref ] : '' );
		}

		$record = array_merge(
			$extra,
			array(
				'ruleset_id'  => $ruleset_id,
				'phase'       => $phase,
				'rule_ids'    => $rule_ids,
				'config_hash' => Blt_Secure_Rule_Definitions::config_hash( $rules ),
			)
		);
		$this->state->set_deployment( $feature, $record );

		return $record;
	}

	/**
	 * Get the phase entrypoint ruleset (with rules), creating it if absent.
	 *
	 * @param string $zone_id Zone id.
	 * @param string $phase Phase name.
	 * @return array|WP_Error Ruleset object.
	 */
	private function ensure_entrypoint( $zone_id, $phase ) {
		$entrypoint = $this->api->get( '/zones/' . $zone_id . '/rulesets/phases/' . $phase . '/entrypoint' );

		if ( ! is_wp_error( $entrypoint ) && ! empty( $entrypoint['id'] ) ) {
			return $entrypoint;
		}

		// Scope problems must surface, not trigger a create attempt.
		if ( is_wp_error( $entrypoint ) && in_array( $entrypoint->get_error_code(), array( 'blt_cf_auth', 'blt_cf_scope' ), true ) ) {
			return $entrypoint;
		}

		return $this->api->post(
			'/zones/' . $zone_id . '/rulesets',
			array(
				'name'        => 'default',
				'kind'        => 'zone',
				'phase'       => $phase,
				'description' => '',
				'rules'       => array(),
			)
		);
	}

	/**
	 * Locate a rule id by ref in a returned ruleset.
	 *
	 * @param array  $ruleset Ruleset response.
	 * @param string $ref Rule ref.
	 * @param string $fallback Previous id when known.
	 * @return string
	 */
	private function find_rule_id_by_ref( array $ruleset, $ref, $fallback = '' ) {
		if ( ! empty( $ruleset['rules'] ) && is_array( $ruleset['rules'] ) ) {
			foreach ( $ruleset['rules'] as $rule ) {
				if ( isset( $rule['ref'] ) && $rule['ref'] === $ref && ! empty( $rule['id'] ) ) {
					return $rule['id'];
				}
			}
		}
		return $fallback;
	}

	/**
	 * Delete a feature's rules by stored id; 404 = already gone = success.
	 *
	 * @param array $zone Zone identity.
	 * @param array $record Deployment record.
	 * @return true|WP_Error
	 */
	private function remove_rules( array $zone, array $record ) {
		if ( empty( $record['ruleset_id'] ) || empty( $record['rule_ids'] ) ) {
			return true;
		}

		foreach ( (array) $record['rule_ids'] as $rule_id ) {
			if ( '' === (string) $rule_id ) {
				continue;
			}
			$result = $this->api->delete( '/zones/' . $zone['zone_id'] . '/rulesets/' . $record['ruleset_id'] . '/rules/' . $rule_id );
			if ( is_wp_error( $result ) && ! $this->is_not_found( $result ) ) {
				return $result;
			}
		}

		return true;
	}

	// -------------------------------------------------------------------
	// Feature: leaked credentials.
	// -------------------------------------------------------------------

	/**
	 * Enable leaked-credential checks, add the WP-form detection, and the
	 * companion challenge rule.
	 *
	 * @param array $zone Zone identity.
	 * @return array|WP_Error
	 */
	private function deploy_leaked_creds( array $zone ) {
		$enable = $this->api->post( '/zones/' . $zone['zone_id'] . '/leaked-credential-checks', array( 'enabled' => true ) );
		if ( is_wp_error( $enable ) ) {
			return $enable;
		}

		// Custom detection for wp-login.php form fields. Duplicate
		// detections error; reuse an existing identical one.
		$detection_id = '';
		$desired      = Blt_Secure_Rule_Definitions::leaked_creds_detection();
		$existing     = $this->api->get( '/zones/' . $zone['zone_id'] . '/leaked-credential-checks/detections' );
		if ( ! is_wp_error( $existing ) ) {
			foreach ( $existing as $detection ) {
				if ( isset( $detection['username'], $detection['password'] )
					&& $detection['username'] === $desired['username']
					&& $detection['password'] === $desired['password'] ) {
					$detection_id = isset( $detection['id'] ) ? $detection['id'] : '';
					break;
				}
			}
		}
		if ( '' === $detection_id ) {
			$created = $this->api->post( '/zones/' . $zone['zone_id'] . '/leaked-credential-checks/detections', $desired );
			if ( is_wp_error( $created ) ) {
				return $created;
			}
			$detection_id = isset( $created['id'] ) ? $created['id'] : '';
		}

		// Companion challenge rule lives in the custom phase.
		$rules_result = $this->deploy_ruleset_feature( $zone, 'leaked_creds', Blt_Secure_Rule_Definitions::PHASE_CUSTOM, Blt_Secure_Rule_Definitions::leaked_creds_rules(), array( 'detection_id' => $detection_id ) );
		if ( is_wp_error( $rules_result ) ) {
			return $rules_result;
		}

		return $rules_result;
	}

	/**
	 * Remove the leaked-creds detection + rule (leaves the zone-level
	 * enabled flag on — it is harmless and may predate us).
	 *
	 * @param array $zone Zone identity.
	 * @param array $record Deployment record.
	 * @return true|WP_Error
	 */
	private function remove_leaked_creds( array $zone, array $record ) {
		if ( ! empty( $record['detection_id'] ) ) {
			$result = $this->api->delete( '/zones/' . $zone['zone_id'] . '/leaked-credential-checks/detections/' . $record['detection_id'] );
			if ( is_wp_error( $result ) && ! $this->is_not_found( $result ) ) {
				return $result;
			}
		}

		return $this->remove_rules( $zone, $record );
	}

	// -------------------------------------------------------------------
	// Feature: Cloudflare Access.
	// -------------------------------------------------------------------

	/**
	 * Probe whether the token can manage Access apps at all.
	 *
	 * @return true|WP_Error
	 */
	public function probe_access() {
		$zone = $this->state->zone();
		if ( empty( $zone['account_id'] ) ) {
			return new WP_Error( 'blt_cf_not_connected', __( 'Cloudflare is not connected yet.', 'blt-secure' ) );
		}
		$result = $this->api->get( '/accounts/' . $zone['account_id'] . '/access/apps' );
		return is_wp_error( $result ) ? $result : true;
	}

	/**
	 * Create the Access app + allow policy + admin-ajax bypass app.
	 *
	 * @param array $zone Zone identity.
	 * @param array $config emails / login_slug.
	 * @return array|WP_Error
	 */
	private function deploy_access( array $zone, array $config ) {
		if ( empty( $zone['account_id'] ) ) {
			return new WP_Error( 'blt_cf_not_connected', __( 'No Cloudflare account id is known for this zone.', 'blt-secure' ) );
		}

		$emails = isset( $config['emails'] ) && is_array( $config['emails'] ) ? array_filter( array_map( 'sanitize_email', $config['emails'] ) ) : array();
		if ( empty( $emails ) ) {
			return new WP_Error( 'blt_cf_validation', __( 'At least one administrator email is required for the Access policy.', 'blt-secure' ) );
		}

		$host = $zone['host'];
		$slug = isset( $config['login_slug'] ) ? (string) $config['login_slug'] : '';
		$base = '/accounts/' . $zone['account_id'] . '/access/apps';

		$record = array(
			'app_id'        => '',
			'bypass_app_id' => '',
			'policy_ids'    => array(),
		);

		// Bypass app FIRST — the moment the main app exists, admin-ajax is
		// gated; creating the bypass first avoids a broken window.
		$bypass_app = $this->find_or_create_app( $base, Blt_Secure_Rule_Definitions::access_bypass_app( $host ) );
		if ( is_wp_error( $bypass_app ) ) {
			return $bypass_app;
		}
		$record['bypass_app_id'] = $bypass_app['id'];

		foreach ( Blt_Secure_Rule_Definitions::access_bypass_policies() as $policy ) {
			$created = $this->find_or_create_policy( $base . '/' . $bypass_app['id'] . '/policies', $policy );
			if ( is_wp_error( $created ) ) {
				return $created;
			}
			$record['policy_ids'][] = $created['id'];
		}

		$app = $this->find_or_create_app( $base, Blt_Secure_Rule_Definitions::access_app( $host, $slug ) );
		if ( is_wp_error( $app ) ) {
			return $app;
		}
		$record['app_id'] = $app['id'];

		foreach ( Blt_Secure_Rule_Definitions::access_policies( $emails ) as $policy ) {
			$created = $this->find_or_create_policy( $base . '/' . $app['id'] . '/policies', $policy );
			if ( is_wp_error( $created ) ) {
				return $created;
			}
			$record['policy_ids'][] = $created['id'];
		}

		$record['config_hash'] = Blt_Secure_Rule_Definitions::config_hash( array( $emails, $slug, $host ) );
		$this->state->set_deployment( 'access', $record );

		return $record;
	}

	/**
	 * Adopt an existing app by name or create it.
	 *
	 * @param string $base Apps endpoint.
	 * @param array  $payload App payload.
	 * @return array|WP_Error App object.
	 */
	private function find_or_create_app( $base, array $payload ) {
		$apps = $this->api->get( $base );
		if ( ! is_wp_error( $apps ) ) {
			foreach ( $apps as $app ) {
				if ( isset( $app['name'], $app['id'] ) && $app['name'] === $payload['name'] ) {
					return $app;
				}
			}
		}
		return $this->api->post( $base, $payload );
	}

	/**
	 * Adopt an existing policy by name or create it.
	 *
	 * @param string $base Policies endpoint.
	 * @param array  $payload Policy payload.
	 * @return array|WP_Error Policy object.
	 */
	private function find_or_create_policy( $base, array $payload ) {
		$policies = $this->api->get( $base );
		if ( ! is_wp_error( $policies ) ) {
			foreach ( $policies as $policy ) {
				if ( isset( $policy['name'], $policy['id'] ) && $policy['name'] === $payload['name'] ) {
					return $policy;
				}
			}
		}
		return $this->api->post( $base, $payload );
	}

	/**
	 * Delete Access apps (policies cascade with the app).
	 *
	 * @param array $zone Zone identity.
	 * @param array $record Deployment record.
	 * @return true|WP_Error
	 */
	private function remove_access( array $zone, array $record ) {
		$base = '/accounts/' . $zone['account_id'] . '/access/apps';

		foreach ( array( 'app_id', 'bypass_app_id' ) as $key ) {
			if ( ! empty( $record[ $key ] ) ) {
				$result = $this->api->delete( $base . '/' . $record[ $key ] );
				if ( is_wp_error( $result ) && ! $this->is_not_found( $result ) ) {
					return $result;
				}
			}
		}

		return true;
	}

	/**
	 * Whether an error is a 404 (treated as success on delete).
	 *
	 * @param WP_Error $error Error.
	 * @return bool
	 */
	private function is_not_found( WP_Error $error ) {
		$data = $error->get_error_data();
		return is_array( $data ) && isset( $data['status'] ) && 404 === (int) $data['status'];
	}
}
