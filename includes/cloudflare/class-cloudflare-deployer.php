<?php
/**
 * Cloudflare deployment orchestrator.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once dirname( __DIR__ ) . '/feeds/class-ioc-parser.php';

/**
 * Deploys/removes the Cloudflare features idempotently.
 *
 * Deploy = reconcile: fetch the phase entrypoint ruleset, index existing
 * rules by our "ref", PATCH matches and POST the missing — never PUT the
 * whole entrypoint (other tools' rules live there too). Removal is ref-based
 * too: it deletes only rules in the entrypoint whose ref is one of this
 * feature's own "blt-secure-*" refs, so orphans from a half-finished deploy
 * stay removable and nothing else in the ruleset can be touched.
 *
 * Objects that are account-wide rather than ref-addressable (Access apps, the
 * IP list, leaked-credential detections) carry a host-scoped name, and the
 * deployment record remembers whether this plugin created them or merely
 * adopted an existing one. Adopted objects are never deleted.
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
	 * This site's host (from home_url) for the zone-drift guard; null skips it.
	 *
	 * @var string|null
	 */
	private $site_host;

	/**
	 * Human-readable notes from the last operation (e.g. adopted objects left in place).
	 *
	 * @var string[]
	 */
	private $notes = array();

	/**
	 * Constructor.
	 *
	 * @param Blt_Secure_Cloudflare_Api   $api API client.
	 * @param Blt_Secure_Cloudflare_State $state State store.
	 * @param string|null                 $site_host This site's host; when given, every mutation refuses to run if the stored zone was connected for a different host.
	 */
	public function __construct( Blt_Secure_Cloudflare_Api $api, Blt_Secure_Cloudflare_State $state, $site_host = null ) {
		$this->api       = $api;
		$this->state     = $state;
		$this->site_host = null === $site_host ? null : strtolower( (string) $site_host );
	}

	/**
	 * Notes produced by the last remove()/deploy() call.
	 *
	 * @return string[]
	 */
	public function notes() {
		return $this->notes;
	}

	/**
	 * Verify token and (re)discover the zone.
	 *
	 * @param string $host Site host.
	 * @param bool   $persist Persist the zone identity (false lets the caller store the token first).
	 * @return array|WP_Error Zone summary.
	 */
	public function connect( $host, $persist = true ) {
		$verify = $this->api->verify_token();
		if ( is_wp_error( $verify ) ) {
			return $verify;
		}

		$zone = $this->api->discover_zone( $host );
		if ( is_wp_error( $zone ) ) {
			return $zone;
		}

		$summary = array(
			'zone_id'      => isset( $zone['id'] ) ? $zone['id'] : '',
			'zone_name'    => isset( $zone['name'] ) ? $zone['name'] : '',
			'account_id'   => isset( $zone['account']['id'] ) ? $zone['account']['id'] : '',
			'plan'         => self::extract_plan( $zone ),
			'plan_checked' => time(),
			'host'         => $host,
		);
		if ( $persist ) {
			$this->state->set_zone( $summary );
		}

		return $summary;
	}

	/**
	 * Raw plan id/name from a zone object.
	 *
	 * @param array $zone Zone object.
	 * @return string
	 */
	private static function extract_plan( array $zone ) {
		if ( isset( $zone['plan']['legacy_id'] ) && '' !== $zone['plan']['legacy_id'] ) {
			return (string) $zone['plan']['legacy_id'];
		}
		return isset( $zone['plan']['name'] ) ? strtolower( (string) $zone['plan']['name'] ) : '';
	}

	/**
	 * Refuse to mutate when this site's host is not the host the zone was
	 * connected for (site migrated, domain changed, staging clone sharing the
	 * production token and state).
	 *
	 * @param array $zone Zone identity.
	 * @return true|WP_Error
	 */
	private function guard_host( array $zone ) {
		unset( $zone ); // Deliberately not used: zone() is gap-filled from the shared store.
		$stored = $this->state->stored_zone_host();
		if ( null === $this->site_host || '' === $stored ) {
			return true; // Nothing recorded to compare with (records from older versions).
		}
		// www and the bare domain are the same site; a different subdomain (a staging clone) is not.
		if ( self::bare_host( $stored ) === self::bare_host( $this->site_host ) ) {
			return true;
		}
		return new WP_Error(
			'blt_cf_host_mismatch',
			sprintf(
				/* translators: 1: host the Cloudflare zone was connected for, 2: this site's current host */
				__( 'Cloudflare was connected for %1$s but this site is now %2$s (site moved, domain changed, or this is a clone). Nothing was changed — disconnect and reconnect your token on this site first.', 'blt-secure' ),
				$stored,
				$this->site_host
			)
		);
	}

	/**
	 * A host without a leading "www.".
	 *
	 * @param string $host Host.
	 * @return string
	 */
	private static function bare_host( $host ) {
		$host = strtolower( (string) $host );
		return 0 === strpos( $host, 'www.' ) ? substr( $host, 4 ) : $host;
	}

	/**
	 * The zone's plan, normalized (free|pro|business|enterprise|''). Refreshed
	 * from Cloudflare at most every 5 minutes; falls back to the stored value.
	 *
	 * @param array $zone Zone identity.
	 * @return string
	 */
	private function current_plan( array $zone ) {
		$stored  = isset( $zone['plan'] ) ? (string) $zone['plan'] : '';
		$checked = isset( $zone['plan_checked'] ) ? (int) $zone['plan_checked'] : 0;

		if ( $checked < time() - 300 ) {
			$fresh = $this->api->get( '/zones/' . Blt_Secure_Cloudflare_Api::seg( $zone['zone_id'] ) );
			if ( ! is_wp_error( $fresh ) ) {
				$raw = self::extract_plan( $fresh );
				if ( '' !== $raw ) {
					$stored = $raw;
					$this->state->update_plan( $raw );
				}
			}
		}

		return Blt_Secure_Rule_Definitions::normalize_plan( $stored );
	}

	/**
	 * Deploy one feature.
	 *
	 * @param string $feature Feature key.
	 * @param array  $config Feature-specific config (paranoia, slug, emails...).
	 * @return array|WP_Error Deployment record.
	 */
	public function deploy( $feature, array $config = array() ) {
		$this->notes = array();

		$zone = $this->state->zone();
		if ( empty( $zone['zone_id'] ) ) {
			return new WP_Error( 'blt_cf_not_connected', __( 'Cloudflare is not connected yet — verify your token first.', 'blt-secure' ) );
		}
		if ( ! in_array( $feature, self::FEATURES, true ) ) {
			return new WP_Error( 'blt_cf_unknown_feature', __( 'Unknown Cloudflare feature.', 'blt-secure' ) );
		}

		$guard = $this->guard_host( $zone );
		if ( is_wp_error( $guard ) ) {
			return $guard;
		}

		// Cheap input validation first: a bad request makes no API calls at all.
		if ( 'country_block' === $feature ) {
			$wanted = isset( $config['countries'] ) ? Blt_Secure_Rule_Definitions::sanitize_country_codes( $config['countries'] ) : array();
			if ( empty( $wanted ) ) {
				return new WP_Error( 'blt_cf_validation', __( 'Choose at least one country to block first.', 'blt-secure' ) );
			}
		}

		$plan = $this->current_plan( $zone );
		$slug = isset( $config['login_slug'] ) ? (string) $config['login_slug'] : '';
		$base = isset( $config['base_path'] ) ? (string) $config['base_path'] : '';

		switch ( $feature ) {
			case 'waf_managed':
				return $this->deploy_waf_managed( $zone, $config, $plan );
			case 'custom_pack':
				return $this->deploy_ruleset_feature( $zone, 'custom_pack', Blt_Secure_Rule_Definitions::PHASE_CUSTOM, Blt_Secure_Rule_Definitions::custom_pack_rules( $base ), array(), $plan, array( 'blt-secure-custom-tor' ) );
			case 'country_block':
				return $this->deploy_country_block( $zone, $config, $plan );
			case 'rate_limit':
				return $this->deploy_ruleset_feature( $zone, 'rate_limit', Blt_Secure_Rule_Definitions::PHASE_RATELIMIT, Blt_Secure_Rule_Definitions::rate_limit_rules( $slug, $plan, $base ), array(), $plan );
			case 'leaked_creds':
				return $this->deploy_leaked_creds( $zone, $plan );
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
		$this->notes = array();

		$zone   = $this->state->zone();
		$record = $this->state->deployment( $feature );

		if ( ! in_array( $feature, self::FEATURES, true ) ) {
			return new WP_Error( 'blt_cf_unknown_feature', __( 'Unknown Cloudflare feature.', 'blt-secure' ) );
		}
		if ( empty( $zone['zone_id'] ) ) {
			// Nothing can be reached; just forget any stale record.
			$this->state->clear_deployment( $feature );
			return true;
		}

		$guard = $this->guard_host( $zone );
		if ( is_wp_error( $guard ) ) {
			return $guard;
		}

		switch ( $feature ) {
			case 'waf_managed':
			case 'custom_pack':
			case 'country_block':
			case 'rate_limit':
				$result = $this->remove_rules( $zone, $feature );
				break;

			case 'leaked_creds':
				$result = $this->remove_leaked_creds( $zone, is_array( $record ) ? $record : array() );
				break;

			default: // access.
				if ( null === $record ) {
					return true; // Nothing deployed.
				}
				$result = $this->remove_access( $zone, $record );
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
	 * reused (by stored id, then by host-scoped name) and the rule reconciled
	 * by ref. The custom-rule budget is checked BEFORE any list is created or
	 * filled, the bulk operation is polled (bounded) so a failed update is
	 * reported instead of read as success.
	 *
	 * @param string[] $ips Validated IP/CIDR strings.
	 * @return array|WP_Error Deployment record (list_id, rule_ids, count).
	 */
	public function sync_ioc_list( array $ips ) {
		$this->notes = array();

		$zone = $this->state->zone();
		if ( empty( $zone['zone_id'] ) || empty( $zone['account_id'] ) ) {
			return new WP_Error( 'blt_cf_not_connected', __( 'Cloudflare is not connected yet — verify your token first.', 'blt-secure' ) );
		}
		$guard = $this->guard_host( $zone );
		if ( is_wp_error( $guard ) ) {
			return $guard;
		}

		// Defensive: only entries Cloudflare accepts (IPv4 /8-/32, IPv6 /12-/128).
		$items = array();
		foreach ( $ips as $ip ) {
			if ( Blt_Secure_Ioc_Parser::is_cf_list_item( $ip ) ) {
				$items[] = array( 'ip' => $ip );
			}
		}
		if ( empty( $items ) ) {
			return new WP_Error( 'blt_cf_validation', __( 'No indicators were valid for a Cloudflare IP list.', 'blt-secure' ) );
		}

		$plan   = $this->current_plan( $zone );
		$record = $this->state->deployment( 'ioc' );
		$record = is_array( $record ) ? $record : array();
		$name   = ! empty( $record['list_name'] ) ? (string) $record['list_name'] : Blt_Secure_Rule_Definitions::ioc_list_name( isset( $zone['host'] ) ? $zone['host'] : '' );
		$rules  = Blt_Secure_Rule_Definitions::ioc_block_rules( $name );

		$budget = $this->preflight_budget( $zone, Blt_Secure_Rule_Definitions::PHASE_CUSTOM, $rules, $plan );
		if ( is_wp_error( $budget ) ) {
			return $budget;
		}

		$list = $this->find_or_create_ioc_list( $zone['account_id'], $name, $record );
		if ( is_wp_error( $list ) ) {
			return $list;
		}
		$list_id = isset( $list['id'] ) ? (string) $list['id'] : '';
		if ( '' === $list_id ) {
			return new WP_Error( 'blt_cf_validation', __( 'Cloudflare did not return an IP List id.', 'blt-secure' ) );
		}
		// An adopted list keeps its own name (e.g. the pre-1.2 shared name), and
		// the block rule must reference the name of the list actually used.
		if ( ! empty( $list['name'] ) ) {
			$name  = (string) $list['name'];
			$rules = Blt_Secure_Rule_Definitions::ioc_block_rules( $name );
		}

		$account = Blt_Secure_Cloudflare_Api::seg( $zone['account_id'] );

		// Bulk-replace the list contents (Cloudflare expects [{ip:…}, …]); the
		// call is asynchronous and returns an operation id.
		$replaced = $this->api->put( '/accounts/' . $account . '/rules/lists/' . Blt_Secure_Cloudflare_Api::seg( $list_id ) . '/items', $items );
		if ( is_wp_error( $replaced ) ) {
			return $replaced;
		}

		$pending = false;
		if ( ! empty( $replaced['operation_id'] ) ) {
			$op = $this->await_bulk_operation( $account, (string) $replaced['operation_id'] );
			if ( is_wp_error( $op ) ) {
				return $op;
			}
			$pending = 'pending' === $op;
		}

		$owned = ! empty( $list['__created'] ) || ( ! empty( $record['list_owned'] ) && isset( $record['list_id'] ) && (string) $record['list_id'] === $list_id );

		// Ensure the referencing block rule (custom phase).
		return $this->deploy_ruleset_feature(
			$zone,
			'ioc',
			Blt_Secure_Rule_Definitions::PHASE_CUSTOM,
			$rules,
			array(
				'list_id'      => $list_id,
				'list_name'    => $name,
				'list_owned'   => (bool) $owned,
				'list_pending' => $pending,
				'count'        => count( $items ),
			),
			$plan
		);
	}

	/**
	 * Poll a list bulk operation, bounded (about 10 s worst case).
	 *
	 * @param string $account Account id path segment.
	 * @param string $operation_id Operation id.
	 * @return true|string|WP_Error true when completed, 'pending' when still running, WP_Error on failure.
	 */
	private function await_bulk_operation( $account, $operation_id ) {
		for ( $i = 0; $i < 5; $i++ ) {
			$status = $this->api->get( '/accounts/' . $account . '/rules/lists/bulk_operations/' . Blt_Secure_Cloudflare_Api::seg( $operation_id ) );
			if ( is_wp_error( $status ) ) {
				return $status;
			}
			$state = isset( $status['status'] ) ? strtolower( (string) $status['status'] ) : '';
			if ( 'completed' === $state ) {
				return true;
			}
			if ( 'failed' === $state ) {
				$detail = isset( $status['error'] ) && is_string( $status['error'] ) && '' !== $status['error'] ? $status['error'] : __( 'unspecified error', 'blt-secure' );
				return new WP_Error(
					'blt_cf_list_failed',
					sprintf(
						/* translators: %s: Cloudflare's error text */
						__( 'Cloudflare could not apply the IP list update: %s', 'blt-secure' ),
						$detail
					)
				);
			}
			$this->api->pause( $i + 1 );
		}
		return 'pending';
	}

	/**
	 * Delete the IOC block rule and, when this plugin created it, the account
	 * IP List. 404 = already gone. An adopted list is left in place.
	 *
	 * @return true|WP_Error
	 */
	public function remove_ioc_list() {
		$this->notes = array();

		$zone   = $this->state->zone();
		$record = $this->state->deployment( 'ioc' );
		if ( null === $record || empty( $zone['zone_id'] ) ) {
			return true;
		}
		$guard = $this->guard_host( $zone );
		if ( is_wp_error( $guard ) ) {
			return $guard;
		}

		// Rule must go first — a list cannot be deleted while referenced.
		$removed = $this->remove_rules( $zone, 'ioc' );
		if ( is_wp_error( $removed ) ) {
			return $removed;
		}

		if ( ! empty( $record['list_id'] ) && ! empty( $zone['account_id'] ) ) {
			if ( ! empty( $record['list_owned'] ) ) {
				$deleted = $this->api->delete( '/accounts/' . Blt_Secure_Cloudflare_Api::seg( $zone['account_id'] ) . '/rules/lists/' . Blt_Secure_Cloudflare_Api::seg( $record['list_id'] ) );
				if ( is_wp_error( $deleted ) && ! $this->is_not_found( $deleted ) ) {
					return $deleted;
				}
			} else {
				$this->notes[] = __( 'The Cloudflare IP list was adopted rather than created by this plugin, so it was left in place.', 'blt-secure' );
			}
		}

		$this->state->clear_deployment( 'ioc' );
		return true;
	}

	/**
	 * Adopt the account IP List (stored id, then host-scoped name) or create it.
	 * A list created by this call carries a transient `__created` marker.
	 *
	 * @param string $account_id Account id.
	 * @param string $name       List name.
	 * @param array  $record     Previous IOC deployment record.
	 * @return array|WP_Error List object.
	 */
	private function find_or_create_ioc_list( $account_id, $name, array $record ) {
		$base = '/accounts/' . Blt_Secure_Cloudflare_Api::seg( $account_id ) . '/rules/lists';

		if ( ! empty( $record['list_id'] ) ) {
			$known = $this->api->get( $base . '/' . Blt_Secure_Cloudflare_Api::seg( $record['list_id'] ) );
			if ( ! is_wp_error( $known ) && ! empty( $known['id'] ) ) {
				return $known;
			}
			if ( is_wp_error( $known ) && in_array( $known->get_error_code(), array( 'blt_cf_auth', 'blt_cf_scope', 'blt_cf_rate_limited' ), true ) ) {
				return $known;
			}
		}

		$lists = $this->api->get( $base );
		if ( ! is_wp_error( $lists ) ) {
			foreach ( $lists as $list ) {
				if ( isset( $list['name'], $list['id'] ) && $name === $list['name'] ) {
					return $list;
				}
			}
		} elseif ( in_array( $lists->get_error_code(), array( 'blt_cf_auth', 'blt_cf_scope', 'blt_cf_rate_limited' ), true ) ) {
			// Missing Account Filter Lists permission must surface, not create.
			return $lists;
		}

		$created = $this->api->post(
			$base,
			array(
				'name'        => $name,
				'kind'        => 'ip',
				'description' => '[BLT Secure] Synced threat-intel indicators',
			)
		);
		if ( is_wp_error( $created ) ) {
			return $created;
		}
		$created['__created'] = true;
		return $created;
	}

	// -------------------------------------------------------------------
	// Feature: managed WAF.
	// -------------------------------------------------------------------

	/**
	 * Deploy managed rulesets. The tier comes from the zone's KNOWN plan, never
	 * from an error: Pro and above get the Cloudflare Managed + OWASP rulesets,
	 * everything else the Free Managed Ruleset. The other tier's rules are
	 * retired after a successful deploy so a plan change never leaves an
	 * untracked rule behind.
	 *
	 * @see https://developers.cloudflare.com/waf/managed-rules/
	 *
	 * @param array  $zone Zone identity.
	 * @param array  $config paranoia / score_threshold.
	 * @param string $plan Normalized plan.
	 * @return array|WP_Error
	 */
	private function deploy_waf_managed( array $zone, array $config, $plan ) {
		$paranoia  = isset( $config['paranoia'] ) ? (int) $config['paranoia'] : 2;
		$threshold = isset( $config['score_threshold'] ) ? (int) $config['score_threshold'] : 40;
		if ( ! in_array( $threshold, array( 25, 40, 60 ), true ) ) {
			$threshold = 40;
		}

		// An unreadable plan must never be treated as Free: that would deploy the Free ruleset and
		// then retire the Managed + OWASP rules of a paid zone on a transient API error.
		if ( '' === $plan ) {
			return new WP_Error(
				'blt_cf_plan_unknown',
				__( 'Cloudflare did not report this zone\'s plan, so the managed rulesets were left exactly as they are. Try again in a minute.', 'blt-secure' )
			);
		}

		if ( in_array( $plan, array( 'pro', 'business', 'enterprise' ), true ) ) {
			return $this->deploy_ruleset_feature(
				$zone,
				'waf_managed',
				Blt_Secure_Rule_Definitions::PHASE_MANAGED,
				Blt_Secure_Rule_Definitions::managed_waf_rules( $paranoia, $threshold ),
				array( 'tier' => 'full' ),
				$plan,
				array( 'blt-secure-waf-free' )
			);
		}

		return $this->deploy_ruleset_feature(
			$zone,
			'waf_managed',
			Blt_Secure_Rule_Definitions::PHASE_MANAGED,
			Blt_Secure_Rule_Definitions::managed_waf_rules_free(),
			array( 'tier' => 'free' ),
			$plan,
			array( 'blt-secure-waf-managed', 'blt-secure-waf-owasp' )
		);
	}

	// -------------------------------------------------------------------
	// Feature: country block.
	// -------------------------------------------------------------------

	/**
	 * Deploy the country-block rule. Refuses an empty selection so a bad
	 * request can never deploy a rule with an always-false (or malformed)
	 * expression.
	 *
	 * @param array  $zone Zone identity.
	 * @param array  $config countries / login_only / login_slug / base_path.
	 * @param string $plan Normalized plan.
	 * @return array|WP_Error
	 */
	private function deploy_country_block( array $zone, array $config, $plan ) {
		$countries = isset( $config['countries'] ) ? Blt_Secure_Rule_Definitions::sanitize_country_codes( $config['countries'] ) : array();
		if ( empty( $countries ) ) {
			return new WP_Error( 'blt_cf_validation', __( 'Choose at least one country to block first.', 'blt-secure' ) );
		}

		$login_only = ! empty( $config['login_only'] );
		$slug       = isset( $config['login_slug'] ) ? (string) $config['login_slug'] : '';
		$base       = isset( $config['base_path'] ) ? (string) $config['base_path'] : '';

		return $this->deploy_ruleset_feature(
			$zone,
			'country_block',
			Blt_Secure_Rule_Definitions::PHASE_CUSTOM,
			Blt_Secure_Rule_Definitions::country_block_rules( $countries, $login_only, $slug, $base ),
			array(
				'countries'  => $countries,
				'login_only' => $login_only,
			),
			$plan
		);
	}

	// -------------------------------------------------------------------
	// Ruleset-engine plumbing (shared by every rule-based feature).
	// -------------------------------------------------------------------

	/**
	 * Read a phase entrypoint without creating it.
	 *
	 * @param string $zone_id Zone id.
	 * @param string $phase Phase name.
	 * @return array|null|WP_Error Ruleset, null when the phase has no entrypoint yet, WP_Error otherwise.
	 */
	private function get_entrypoint( $zone_id, $phase ) {
		$entrypoint = $this->api->get( '/zones/' . Blt_Secure_Cloudflare_Api::seg( $zone_id ) . '/rulesets/phases/' . $phase . '/entrypoint' );

		if ( ! is_wp_error( $entrypoint ) ) {
			return ! empty( $entrypoint['id'] ) ? $entrypoint : null;
		}

		$missing = $this->is_not_found( $entrypoint ) || 1 === preg_match( '/could not find|not found|no such/i', $entrypoint->get_error_message() );
		if ( $missing ) {
			return null;
		}

		// Auth, scope, throttling and transport problems must surface, never
		// trigger a create attempt.
		return $entrypoint;
	}

	/**
	 * Check the per-plan rule budget for a phase before anything is created.
	 *
	 * @see https://developers.cloudflare.com/waf/custom-rules/
	 * @see https://developers.cloudflare.com/waf/rate-limiting-rules/#availability
	 *
	 * @param array    $zone Zone identity.
	 * @param string   $phase Phase.
	 * @param array    $rules Desired rules.
	 * @param string   $plan Normalized plan.
	 * @param string[] $retire_refs Refs that will be deleted by this deploy (free up budget).
	 * @param array    $entrypoint Already-read entrypoint (skips the GET), or null.
	 * @return true|WP_Error blt_cf_budget when the plan cannot hold the rules.
	 */
	private function preflight_budget( array $zone, $phase, array $rules, $plan, array $retire_refs = array(), $entrypoint = null ) {
		$limit = 0;
		$label = '';
		if ( Blt_Secure_Rule_Definitions::PHASE_CUSTOM === $phase ) {
			$limit = Blt_Secure_Rule_Definitions::custom_rule_limit( $plan );
			$label = __( 'custom rules', 'blt-secure' );
		} elseif ( Blt_Secure_Rule_Definitions::PHASE_RATELIMIT === $phase ) {
			$limit = Blt_Secure_Rule_Definitions::ratelimit_rule_limit( $plan );
			$label = __( 'rate limiting rules', 'blt-secure' );
		}
		if ( $limit < 1 ) {
			return true; // Unknown plan or an unmetered phase.
		}

		if ( null === $entrypoint ) {
			$entrypoint = $this->get_entrypoint( $zone['zone_id'], $phase );
			if ( is_wp_error( $entrypoint ) ) {
				return $entrypoint;
			}
		}

		$existing = array();
		$current  = 0;
		if ( is_array( $entrypoint ) && ! empty( $entrypoint['rules'] ) && is_array( $entrypoint['rules'] ) ) {
			$current = count( $entrypoint['rules'] );
			foreach ( $entrypoint['rules'] as $rule ) {
				if ( ! empty( $rule['ref'] ) ) {
					$existing[ $rule['ref'] ] = true;
				}
			}
		}

		$needed = 0;
		foreach ( $rules as $payload ) {
			if ( ! isset( $existing[ $payload['ref'] ] ) ) {
				++$needed;
			}
		}
		$freed = 0;
		foreach ( $retire_refs as $ref ) {
			if ( isset( $existing[ $ref ] ) ) {
				++$freed;
			}
		}

		if ( $current + $needed - $freed > $limit ) {
			return new WP_Error(
				'blt_cf_budget',
				sprintf(
					/* translators: 1: plan name, 2: plan limit, 3: label (custom rules / rate limiting rules), 4: rules already in the zone, 5: rules this feature still needs */
					__( 'Skipped: your Cloudflare %1$s plan allows %2$d %3$s per zone, this zone already has %4$d and this feature needs %5$d more. Remove a rule you do not need or upgrade the plan, then redeploy.', 'blt-secure' ),
					'' !== $plan ? $plan : __( 'current', 'blt-secure' ),
					$limit,
					$label,
					$current,
					$needed
				),
				array( 'skipped' => true )
			);
		}

		return true;
	}

	/**
	 * Reconcile a set of desired rules into a phase entrypoint.
	 *
	 * Progress is persisted after EVERY rule (flagged "partial" until the last
	 * one lands), so a failure midway never leaves live rules the UI cannot see
	 * or remove.
	 *
	 * @param array    $zone Zone identity.
	 * @param string   $feature Feature key for state.
	 * @param string   $phase Ruleset phase.
	 * @param array    $rules Desired rules keyed by ref suffix.
	 * @param array    $extra Extra fields to store in the record.
	 * @param string   $plan Normalized plan (budget check).
	 * @param string[] $retire_refs Own refs to delete once the deploy succeeded (tier change / folded rules).
	 * @return array|WP_Error Deployment record.
	 */
	private function deploy_ruleset_feature( array $zone, $feature, $phase, array $rules, array $extra = array(), $plan = '', array $retire_refs = array() ) {
		$zone_seg   = Blt_Secure_Cloudflare_Api::seg( $zone['zone_id'] );
		$entrypoint = $this->get_entrypoint( $zone['zone_id'], $phase );
		if ( is_wp_error( $entrypoint ) ) {
			return $entrypoint;
		}

		$budget = $this->preflight_budget( $zone, $phase, $rules, $plan, $retire_refs, null === $entrypoint ? array() : $entrypoint );
		if ( is_wp_error( $budget ) ) {
			return $budget;
		}

		if ( null === $entrypoint ) {
			$entrypoint = $this->api->post(
				'/zones/' . $zone_seg . '/rulesets',
				array(
					'name'        => 'default',
					'kind'        => 'zone',
					'phase'       => $phase,
					'description' => '',
					'rules'       => array(),
				)
			);
			if ( is_wp_error( $entrypoint ) ) {
				return $entrypoint;
			}
		}

		$ruleset_id = isset( $entrypoint['id'] ) ? (string) $entrypoint['id'] : '';
		if ( '' === $ruleset_id ) {
			return new WP_Error( 'blt_cf_validation', __( 'Cloudflare did not return a ruleset id.', 'blt-secure' ) );
		}
		$ruleset_seg = Blt_Secure_Cloudflare_Api::seg( $ruleset_id );

		$existing = array();
		if ( ! empty( $entrypoint['rules'] ) && is_array( $entrypoint['rules'] ) ) {
			foreach ( $entrypoint['rules'] as $rule ) {
				if ( ! empty( $rule['ref'] ) && ! empty( $rule['id'] ) ) {
					$existing[ $rule['ref'] ] = $rule['id'];
				}
			}
		}

		// Ids already known to exist at the edge (re-adopted by ref).
		$rule_ids = array();
		foreach ( $rules as $key => $payload ) {
			if ( isset( $existing[ $payload['ref'] ] ) ) {
				$rule_ids[ $key ] = $existing[ $payload['ref'] ];
			}
		}

		foreach ( $rules as $key => $payload ) {
			$ref = $payload['ref'];

			if ( isset( $existing[ $ref ] ) ) {
				$result = $this->api->patch(
					'/zones/' . $zone_seg . '/rulesets/' . $ruleset_seg . '/rules/' . Blt_Secure_Cloudflare_Api::seg( $existing[ $ref ] ),
					$payload
				);
			} else {
				$result = $this->api->post(
					'/zones/' . $zone_seg . '/rulesets/' . $ruleset_seg . '/rules',
					$payload
				);
			}

			if ( is_wp_error( $result ) ) {
				return $result;
			}

			// Rule mutation endpoints return the updated ruleset; find our rule.
			$rule_ids[ $key ] = $this->find_rule_id_by_ref( $result, $ref, isset( $existing[ $ref ] ) ? $existing[ $ref ] : '' );

			// Persist progress so an interrupted deploy stays visible/removable.
			$this->state->set_deployment(
				$feature,
				array_merge(
					$extra,
					array(
						'ruleset_id' => $ruleset_id,
						'phase'      => $phase,
						'rule_ids'   => $rule_ids,
						'partial'    => true,
					)
				)
			);
		}

		// Retire superseded own refs (other WAF tier, folded TOR rule).
		foreach ( $retire_refs as $ref ) {
			if ( 0 !== strpos( $ref, 'blt-secure-' ) || ! isset( $existing[ $ref ] ) ) {
				continue;
			}
			$gone = $this->api->delete( '/zones/' . $zone_seg . '/rulesets/' . $ruleset_seg . '/rules/' . Blt_Secure_Cloudflare_Api::seg( $existing[ $ref ] ) );
			if ( is_wp_error( $gone ) && ! $this->is_not_found( $gone ) ) {
				$this->notes[] = sprintf(
					/* translators: %s: rule ref */
					__( 'Could not remove the superseded rule %s; remove it in the Cloudflare dashboard.', 'blt-secure' ),
					$ref
				);
			}
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
	 * Delete a feature's rules BY REF: read the live entrypoint and delete only
	 * rules whose ref is one of this feature's own "blt-secure-*" refs. Works
	 * for orphans (no deployment record) and can never touch a foreign rule.
	 * 404 = already gone = success.
	 *
	 * @param array  $zone Zone identity.
	 * @param string $feature Feature key (incl. 'ioc').
	 * @return true|WP_Error
	 */
	private function remove_rules( array $zone, $feature ) {
		$def = Blt_Secure_Rule_Definitions::feature_refs( $feature );
		if ( null === $def ) {
			return true;
		}

		$entrypoint = $this->get_entrypoint( $zone['zone_id'], $def['phase'] );
		if ( is_wp_error( $entrypoint ) ) {
			return $entrypoint;
		}
		if ( null === $entrypoint || empty( $entrypoint['rules'] ) || ! is_array( $entrypoint['rules'] ) ) {
			return true;
		}

		$zone_seg    = Blt_Secure_Cloudflare_Api::seg( $zone['zone_id'] );
		$ruleset_seg = Blt_Secure_Cloudflare_Api::seg( $entrypoint['id'] );

		foreach ( $entrypoint['rules'] as $rule ) {
			$ref = isset( $rule['ref'] ) ? (string) $rule['ref'] : '';
			if ( '' === $ref || empty( $rule['id'] ) || 0 !== strpos( $ref, 'blt-secure-' ) || ! in_array( $ref, $def['refs'], true ) ) {
				continue;
			}
			$result = $this->api->delete( '/zones/' . $zone_seg . '/rulesets/' . $ruleset_seg . '/rules/' . Blt_Secure_Cloudflare_Api::seg( $rule['id'] ) );
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
	 * Enable leaked-credential checks and add the companion challenge rule.
	 * Custom detection locations are Enterprise-only; every other plan relies
	 * on Cloudflare's default detection (which already covers WordPress).
	 *
	 * @see https://developers.cloudflare.com/waf/detections/leaked-credentials/
	 *
	 * @param array  $zone Zone identity.
	 * @param string $plan Normalized plan.
	 * @return array|WP_Error
	 */
	private function deploy_leaked_creds( array $zone, $plan ) {
		$zone_seg = Blt_Secure_Cloudflare_Api::seg( $zone['zone_id'] );
		$rules    = Blt_Secure_Rule_Definitions::leaked_creds_rules( $plan );

		// Budget first: nothing is enabled or created when the rule cannot fit.
		$budget = $this->preflight_budget( $zone, Blt_Secure_Rule_Definitions::PHASE_CUSTOM, $rules, $plan );
		if ( is_wp_error( $budget ) ) {
			return $budget;
		}

		$enable = $this->api->post( '/zones/' . $zone_seg . '/leaked-credential-checks', array( 'enabled' => true ) );
		if ( is_wp_error( $enable ) ) {
			return $enable;
		}

		$extra = array( 'plan_tier' => 'enterprise' === $plan ? 'custom' : 'default' );

		if ( 'enterprise' === $plan ) {
			$desired      = Blt_Secure_Rule_Definitions::leaked_creds_detection();
			$detection_id = '';
			$created_now  = false;

			$existing = $this->api->get( '/zones/' . $zone_seg . '/leaked-credential-checks/detections' );
			if ( ! is_wp_error( $existing ) ) {
				foreach ( $existing as $detection ) {
					if ( isset( $detection['username'], $detection['password'] )
						&& $detection['username'] === $desired['username']
						&& $detection['password'] === $desired['password'] ) {
						$detection_id = isset( $detection['id'] ) ? (string) $detection['id'] : '';
						break;
					}
				}
			}
			if ( '' === $detection_id ) {
				$created = $this->api->post( '/zones/' . $zone_seg . '/leaked-credential-checks/detections', $desired );
				if ( is_wp_error( $created ) ) {
					return $created;
				}
				$detection_id = isset( $created['id'] ) ? (string) $created['id'] : '';
				$created_now  = '' !== $detection_id;
			}

			$previous = $this->state->deployment( 'leaked_creds' );
			$owned    = $created_now || ( is_array( $previous ) && ! empty( $previous['detection_owned'] ) && isset( $previous['detection_id'] ) && (string) $previous['detection_id'] === $detection_id );

			$extra['detection_id']    = $detection_id;
			$extra['detection_owned'] = (bool) $owned;

			$result = $this->deploy_ruleset_feature( $zone, 'leaked_creds', Blt_Secure_Rule_Definitions::PHASE_CUSTOM, $rules, $extra, $plan );
			if ( is_wp_error( $result ) && $created_now && '' !== $detection_id ) {
				// Roll back what this run created.
				$this->api->delete( '/zones/' . $zone_seg . '/leaked-credential-checks/detections/' . Blt_Secure_Cloudflare_Api::seg( $detection_id ) );
			}
			return $result;
		}

		return $this->deploy_ruleset_feature( $zone, 'leaked_creds', Blt_Secure_Rule_Definitions::PHASE_CUSTOM, $rules, $extra, $plan );
	}

	/**
	 * Remove the leaked-creds rule (by ref) and, only when this plugin created
	 * it, the custom detection. The zone-level enabled flag stays on — it is
	 * harmless and may predate us.
	 *
	 * @param array $zone Zone identity.
	 * @param array $record Deployment record.
	 * @return true|WP_Error
	 */
	private function remove_leaked_creds( array $zone, array $record ) {
		if ( ! empty( $record['detection_id'] ) ) {
			if ( ! empty( $record['detection_owned'] ) ) {
				$result = $this->api->delete( '/zones/' . Blt_Secure_Cloudflare_Api::seg( $zone['zone_id'] ) . '/leaked-credential-checks/detections/' . Blt_Secure_Cloudflare_Api::seg( $record['detection_id'] ) );
				if ( is_wp_error( $result ) && ! $this->is_not_found( $result ) ) {
					return $result;
				}
			} else {
				$this->notes[] = __( 'The leaked-credential detection was adopted rather than created by this plugin, so it was left in place.', 'blt-secure' );
			}
		}

		return $this->remove_rules( $zone, 'leaked_creds' );
	}

	// -------------------------------------------------------------------
	// Feature: Cloudflare Access.
	// -------------------------------------------------------------------

	/**
	 * Probe whether the token can manage Access apps at all (read-only).
	 *
	 * @return true|WP_Error
	 */
	public function probe_access() {
		$zone = $this->state->zone();
		if ( empty( $zone['account_id'] ) ) {
			return new WP_Error( 'blt_cf_not_connected', __( 'Cloudflare is not connected yet.', 'blt-secure' ) );
		}
		$result = $this->api->get( '/accounts/' . Blt_Secure_Cloudflare_Api::seg( $zone['account_id'] ) . '/access/apps', array( 'per_page' => 1 ) );
		return is_wp_error( $result ) ? $result : true;
	}

	/**
	 * Create/update the Access apps. Each app is created WITH its policy in
	 * one request (an Access app without a policy denies everyone, so there is
	 * never a window where wp-admin is locked), the admin-ajax bypass app goes
	 * first, and anything this run created is rolled back if a later step
	 * fails. The scope is probed before anything is touched.
	 *
	 * @param array $zone Zone identity.
	 * @param array $config emails / login_slug / base_path.
	 * @return array|WP_Error
	 */
	private function deploy_access( array $zone, array $config ) {
		if ( empty( $zone['account_id'] ) ) {
			return new WP_Error( 'blt_cf_not_connected', __( 'No Cloudflare account id is known for this zone.', 'blt-secure' ) );
		}

		$emails = isset( $config['emails'] ) && is_array( $config['emails'] ) ? array_values( array_filter( array_map( 'sanitize_email', $config['emails'] ) ) ) : array();
		if ( empty( $emails ) ) {
			return new WP_Error( 'blt_cf_validation', __( 'At least one administrator email is required for the Access policy.', 'blt-secure' ) );
		}
		sort( $emails );

		$host = isset( $zone['host'] ) ? (string) $zone['host'] : '';
		if ( '' === $host ) {
			return new WP_Error( 'blt_cf_validation', __( 'The site host is unknown; reconnect the Cloudflare token first.', 'blt-secure' ) );
		}
		$slug = isset( $config['login_slug'] ) ? (string) $config['login_slug'] : '';
		$base = Blt_Secure_Rule_Definitions::normalize_base_path( isset( $config['base_path'] ) ? $config['base_path'] : '' );

		// Scope/entitlement preflight: fail BEFORE anything is created.
		$probe = $this->probe_access();
		if ( is_wp_error( $probe ) ) {
			return $probe;
		}

		$apps_url = '/accounts/' . Blt_Secure_Cloudflare_Api::seg( $zone['account_id'] ) . '/access/apps';
		$apps     = $this->api->get_all( $apps_url );
		if ( is_wp_error( $apps ) ) {
			return $apps; // Cannot tell what exists; creating blind would duplicate.
		}

		$previous = $this->state->deployment( 'access' );
		$previous = is_array( $previous ) ? $previous : array();
		$hash     = Blt_Secure_Rule_Definitions::access_config_hash( $host, $slug, $emails, $base );
		$changed  = ! isset( $previous['config_hash'] ) || $previous['config_hash'] !== $hash;

		$record = array(
			'app_id'           => '',
			'bypass_app_id'    => '',
			'app_owned'        => false,
			'bypass_app_owned' => false,
			'policy_ids'       => array(),
			'host'             => $host,
			'partial'          => true,
		);

		// Bypass app FIRST — the moment the main app exists, admin-ajax is gated.
		$bypass = $this->upsert_app(
			$apps_url,
			$apps,
			Blt_Secure_Rule_Definitions::access_bypass_app( $host, $base ),
			isset( $previous['bypass_app_id'] ) ? (string) $previous['bypass_app_id'] : '',
			! empty( $previous['bypass_app_owned'] ),
			$changed
		);
		if ( is_wp_error( $bypass ) ) {
			return $bypass;
		}
		$record['bypass_app_id']    = $bypass['id'];
		$record['bypass_app_owned'] = $bypass['owned'];
		$record['policy_ids']       = array_merge( $record['policy_ids'], $bypass['policy_ids'] );
		$this->state->set_deployment( 'access', $record );

		$main = $this->upsert_app(
			$apps_url,
			$apps,
			Blt_Secure_Rule_Definitions::access_app( $host, $slug, $emails, $base ),
			isset( $previous['app_id'] ) ? (string) $previous['app_id'] : '',
			! empty( $previous['app_owned'] ),
			$changed
		);
		if ( is_wp_error( $main ) ) {
			// Roll back what this run created (a pre-existing app is untouched).
			if ( $bypass['created'] ) {
				$this->api->delete( $apps_url . '/' . Blt_Secure_Cloudflare_Api::seg( $bypass['id'] ) );
				if ( empty( $previous ) ) {
					$this->state->clear_deployment( 'access' );
				} else {
					$this->state->set_deployment( 'access', $previous );
				}
			}
			return $main;
		}
		$record['app_id']     = $main['id'];
		$record['app_owned']  = $main['owned'];
		$record['policy_ids'] = array_merge( $record['policy_ids'], $main['policy_ids'] );

		unset( $record['partial'] );
		$record['config_hash'] = $hash;
		$this->state->set_deployment( 'access', $record );

		return $record;
	}

	/**
	 * Adopt-and-update, or create, one Access application (with its inline
	 * policy). An existing app is matched by its host-scoped name, or by the id
	 * this site stored earlier (migrating an older shared-name app). It is only
	 * rewritten when the desired config changed.
	 *
	 * @param string $apps_url   Apps endpoint.
	 * @param array  $apps       Existing apps.
	 * @param array  $payload    Desired app (incl. inline policies).
	 * @param string $stored_id  App id stored by this site, or ''.
	 * @param bool   $stored_owned Whether this plugin created that stored app.
	 * @param bool   $changed    Whether the desired config differs from what was deployed.
	 * @return array|WP_Error {id, owned, created, policy_ids}
	 */
	private function upsert_app( $apps_url, array $apps, array $payload, $stored_id, $stored_owned, $changed ) {
		$found = null;
		foreach ( $apps as $app ) {
			if ( isset( $app['name'], $app['id'] ) && $app['name'] === $payload['name'] ) {
				$found = $app;
				break;
			}
		}
		if ( null === $found && '' !== $stored_id ) {
			foreach ( $apps as $app ) {
				if ( isset( $app['id'] ) && (string) $app['id'] === $stored_id ) {
					$found = $app;
					break;
				}
			}
		}

		if ( null !== $found ) {
			$id    = (string) $found['id'];
			$owned = $stored_owned && $stored_id === $id;
			$ids   = self::policy_ids( $found );

			if ( $changed || ( isset( $found['name'] ) && $found['name'] !== $payload['name'] ) ) {
				$updated = $this->api->put( $apps_url . '/' . Blt_Secure_Cloudflare_Api::seg( $id ), $payload );
				if ( is_wp_error( $updated ) ) {
					return $updated;
				}
				$ids = array_merge( $ids, self::policy_ids( $updated ) );
			}

			return array(
				'id'         => $id,
				'owned'      => $owned,
				'created'    => false,
				'policy_ids' => array_values( array_unique( $ids ) ),
			);
		}

		$created = $this->api->post( $apps_url, $payload );
		if ( is_wp_error( $created ) ) {
			return $created;
		}
		if ( empty( $created['id'] ) ) {
			return new WP_Error( 'blt_cf_validation', __( 'Cloudflare did not return an Access application id.', 'blt-secure' ) );
		}

		return array(
			'id'         => (string) $created['id'],
			'owned'      => true,
			'created'    => true,
			'policy_ids' => self::policy_ids( $created ),
		);
	}

	/**
	 * Policy ids carried by an app object (inline policy objects or id strings).
	 *
	 * @param array $app App object.
	 * @return string[]
	 */
	private static function policy_ids( array $app ) {
		$ids = array();
		if ( ! empty( $app['policies'] ) && is_array( $app['policies'] ) ) {
			foreach ( $app['policies'] as $policy ) {
				if ( is_array( $policy ) && ! empty( $policy['id'] ) ) {
					$ids[] = (string) $policy['id'];
				} elseif ( is_string( $policy ) && '' !== $policy ) {
					$ids[] = $policy;
				}
			}
		}
		return $ids;
	}

	/**
	 * Delete the Access apps this plugin created (policies go with the app).
	 * Apps it merely adopted are left in place and reported.
	 *
	 * @param array $zone Zone identity.
	 * @param array $record Deployment record.
	 * @return true|WP_Error
	 */
	private function remove_access( array $zone, array $record ) {
		if ( empty( $zone['account_id'] ) ) {
			return true;
		}
		$base = '/accounts/' . Blt_Secure_Cloudflare_Api::seg( $zone['account_id'] ) . '/access/apps';

		$targets = array(
			'app_id'        => 'app_owned',
			'bypass_app_id' => 'bypass_app_owned',
		);
		foreach ( $targets as $id_key => $owned_key ) {
			if ( empty( $record[ $id_key ] ) ) {
				continue;
			}
			if ( empty( $record[ $owned_key ] ) ) {
				$this->notes[] = __( 'An Access application was adopted (or created by an older version) rather than created by this plugin, so it was left in place — delete it in Cloudflare Zero Trust if you no longer want it.', 'blt-secure' );
				continue;
			}
			$result = $this->api->delete( $base . '/' . Blt_Secure_Cloudflare_Api::seg( $record[ $id_key ] ) );
			if ( is_wp_error( $result ) && ! $this->is_not_found( $result ) ) {
				return $result;
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
