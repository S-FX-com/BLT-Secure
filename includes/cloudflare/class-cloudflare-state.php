<?php
/**
 * Deployment state tracking.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Persists zone identity and per-feature deployment records
 * (rule/ruleset/app IDs + a hash of the config that produced them) in a
 * non-autoloaded option.
 *
 * IDs are a cache, not the source of truth — the deployer reconciles by
 * "ref" against what actually exists at Cloudflare, so lost or stale state
 * (site migration, option wipe) heals on the next deploy instead of
 * duplicating rules.
 */
class Blt_Secure_Cloudflare_State {

	const OPTION = 'blt_secure_cf_state';

	/**
	 * Read the full state.
	 *
	 * @return array
	 */
	public function all() {
		$state = get_option( self::OPTION, array() );
		return is_array( $state ) ? $state : array();
	}

	/**
	 * Zone identity (zone_id, account_id, plan, host).
	 *
	 * The account id and host may be borrowed from the shared BLT family
	 * store when this site has not discovered them yet — see the comment
	 * below for why that borrow is strictly read-only.
	 *
	 * @return array
	 */
	public function zone() {
		$state = $this->all();
		$zone  = isset( $state['zone'] ) && is_array( $state['zone'] ) ? $state['zone'] : array();

		/*
		 * Shared-store fallback, READ-ONLY and gap-filling only: the borrowed
		 * values exist in the array we hand back and nowhere else.
		 *
		 * NEVER call set_zone() with a shared value. Zone discovery —
		 * Blt_Secure_Cloudflare_Deployer::connect(), over
		 * Blt_Secure_Cloudflare_Api::discover_zone() — is the sole writer of
		 * this state, and it writes only what Cloudflare itself reported for
		 * this site's own zone. Injecting a shared account_id into the stored
		 * state could make the IOC deployer PUT list items into the WRONG
		 * Cloudflare account.
		 *
		 * zone_id is deliberately never borrowed: it is what every
		 * "is Cloudflare connected?" gate keys on, and it is only ever real
		 * if this site discovered it.
		 */
		if ( class_exists( 'BLT_Family' ) ) {
			if ( empty( $zone['account_id'] ) ) {
				$shared_account = BLT_Family::get( 'blt-secure', 'cloudflare', 'account_id' );
				if ( '' !== $shared_account ) {
					$zone['account_id'] = $shared_account;
				}
			}
			if ( empty( $zone['host'] ) ) {
				$shared_host = BLT_Family::get( 'blt-secure', 'cloudflare', 'zone_host' );
				if ( '' !== $shared_host ) {
					$zone['host'] = $shared_host;
				}
			}
		}

		return $zone;
	}

	/**
	 * Persist zone identity.
	 *
	 * @param array $zone zone_id/account_id/plan/host.
	 * @return void
	 */
	public function set_zone( array $zone ) {
		$state         = $this->all();
		$state['zone'] = $zone;
		update_option( self::OPTION, $state, false );
	}

	/**
	 * A feature's deployment record.
	 *
	 * @param string $feature Feature key (waf_managed, custom_pack, ...).
	 * @return array|null
	 */
	public function deployment( $feature ) {
		$state = $this->all();
		return isset( $state['deployments'][ $feature ] ) && is_array( $state['deployments'][ $feature ] )
			? $state['deployments'][ $feature ]
			: null;
	}

	/**
	 * Record a deployment.
	 *
	 * @param string $feature Feature key.
	 * @param array  $record IDs + config_hash.
	 * @return void
	 */
	public function set_deployment( $feature, array $record ) {
		$state = $this->all();
		if ( ! isset( $state['deployments'] ) || ! is_array( $state['deployments'] ) ) {
			$state['deployments'] = array();
		}
		$record['deployed_at']            = time();
		$state['deployments'][ $feature ] = $record;
		update_option( self::OPTION, $state, false );
	}

	/**
	 * Forget a deployment (after removal).
	 *
	 * @param string $feature Feature key.
	 * @return void
	 */
	public function clear_deployment( $feature ) {
		$state = $this->all();
		unset( $state['deployments'][ $feature ] );
		update_option( self::OPTION, $state, false );
	}

	/**
	 * Whether the stored config hash for a feature differs from the current
	 * desired config ("update available").
	 *
	 * @param string $feature Feature key.
	 * @param string $current_hash Hash of the config we would deploy now.
	 * @return bool
	 */
	public function is_stale( $feature, $current_hash ) {
		$record = $this->deployment( $feature );
		return null !== $record && isset( $record['config_hash'] ) && $record['config_hash'] !== $current_hash;
	}

	/**
	 * Drop everything (token removed / zone changed).
	 *
	 * @return void
	 */
	public function reset() {
		delete_option( self::OPTION );
	}
}
