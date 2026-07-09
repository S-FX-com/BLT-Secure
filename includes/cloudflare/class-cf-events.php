<?php
/**
 * Cloudflare firewall-event query + response normalization.
 *
 * Pure helpers around the GraphQL `firewallEventsAdaptive` dataset: build the
 * query/variables and turn the response into flat, storable event rows. No
 * HTTP or WP state, so the query shape and parsing are unit-testable.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Firewall-event GraphQL helpers.
 */
class Blt_Secure_Cf_Events {

	/**
	 * The GraphQL query document (stable; variables carry the specifics).
	 *
	 * @return string
	 */
	public static function query() {
		return 'query BltFirewallEvents($zoneTag: string!, $since: Time!, $limit: uint64!) {'
			. ' viewer { zones(filter: {zoneTag: $zoneTag}) {'
			. ' firewallEventsAdaptive(filter: {datetime_geq: $since}, limit: $limit, orderBy: [datetime_DESC]) {'
			. ' action datetime clientIP clientCountryName clientRequestHTTPHost clientRequestPath source ruleId userAgent'
			. ' } } } }';
	}

	/**
	 * Build the variables for a lookback window.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string $zone_tag Zone id.
	 * @param int    $since_ts Unix timestamp of the window start.
	 * @param int    $limit    Max rows (1-1000).
	 * @return array
	 */
	public static function variables( $zone_tag, $since_ts, $limit = 100 ) {
		return array(
			'zoneTag' => (string) $zone_tag,
			'since'   => gmdate( 'Y-m-d\TH:i:s\Z', (int) $since_ts ),
			'limit'   => max( 1, min( 1000, (int) $limit ) ),
		);
	}

	/**
	 * Normalize a GraphQL `data` payload into flat event rows.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param array $data GraphQL `data` member.
	 * @return array[] Rows: [ time, source, action, ip, country, host, path, rule, ua ].
	 */
	public static function parse( array $data ) {
		$zones = array();
		if ( isset( $data['viewer']['zones'] ) && is_array( $data['viewer']['zones'] ) ) {
			$zones = $data['viewer']['zones'];
		}

		$rows = array();
		foreach ( $zones as $zone ) {
			if ( empty( $zone['firewallEventsAdaptive'] ) || ! is_array( $zone['firewallEventsAdaptive'] ) ) {
				continue;
			}
			foreach ( $zone['firewallEventsAdaptive'] as $event ) {
				if ( ! is_array( $event ) ) {
					continue;
				}
				$datetime = isset( $event['datetime'] ) ? (string) $event['datetime'] : '';
				$ts       = '' !== $datetime ? strtotime( $datetime ) : false;

				$rows[] = array(
					'time'    => $ts ? (int) $ts : 0,
					'source'  => 'cloudflare',
					'action'  => isset( $event['action'] ) ? (string) $event['action'] : '',
					'ip'      => isset( $event['clientIP'] ) ? (string) $event['clientIP'] : '',
					'country' => isset( $event['clientCountryName'] ) ? (string) $event['clientCountryName'] : '',
					'host'    => isset( $event['clientRequestHTTPHost'] ) ? (string) $event['clientRequestHTTPHost'] : '',
					'path'    => isset( $event['clientRequestPath'] ) ? (string) $event['clientRequestPath'] : '',
					'rule'    => isset( $event['source'] ) ? (string) $event['source'] : '',
					'ua'      => isset( $event['userAgent'] ) ? (string) $event['userAgent'] : '',
				);
			}
		}
		return $rows;
	}

	/**
	 * Merge local security events and Cloudflare edge events into one
	 * newest-first timeline.
	 *
	 * Pure function (unit-tested). Local events arrive in the alerting
	 * ring-buffer shape ({type, context, time}); they are normalized to the
	 * same row shape with source 'local'.
	 *
	 * @param array[] $local Local events (alerting shape).
	 * @param array[] $cf    Cloudflare rows (parse() shape).
	 * @param int     $limit Max rows to keep.
	 * @return array[]
	 */
	public static function merge( array $local, array $cf, $limit = 100 ) {
		$rows = $cf;
		foreach ( $local as $event ) {
			$rows[] = array(
				'time'    => isset( $event['time'] ) ? (int) $event['time'] : 0,
				'source'  => 'local',
				'action'  => isset( $event['type'] ) ? (string) $event['type'] : '',
				'context' => isset( $event['context'] ) && is_array( $event['context'] ) ? $event['context'] : array(),
			);
		}

		usort(
			$rows,
			static function ( $a, $b ) {
				$ta = isset( $a['time'] ) ? (int) $a['time'] : 0;
				$tb = isset( $b['time'] ) ? (int) $b['time'] : 0;
				if ( $ta === $tb ) {
					return 0;
				}
				return $ta < $tb ? 1 : -1;
			}
		);

		return array_slice( $rows, 0, max( 1, (int) $limit ) );
	}
}
