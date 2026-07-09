<?php
/**
 * Pluggable feed-source loader.
 *
 * Parses feeds/feeds.json into a validated, filterable list of feed
 * descriptors that Phase 2/3 consumers (the malware signature loader, the
 * IOC → Cloudflare sync) read to know what to fetch and how often. This
 * class only loads and validates configuration; it never performs network
 * I/O itself, so it is cheap to construct and safe to unit-test.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Loads and validates the feed catalogue.
 */
class Blt_Secure_Feeds {

	const CONFIG = 'feeds/feeds.json';

	/**
	 * Formats a consumer knows how to handle.
	 */
	const FORMATS = array( 'yara', 'ioc-json', 'ip-list' );

	/**
	 * Memoized normalized feeds for this request.
	 *
	 * @var array[]|null
	 */
	private static $cache = null;

	/**
	 * Whether a format string is one we support.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string $format Candidate format.
	 * @return bool
	 */
	public static function valid_format( $format ) {
		return in_array( $format, self::FORMATS, true );
	}

	/**
	 * Normalize one raw feed entry, or null when it is unusable.
	 *
	 * Pure function (unit-tested). Requires a non-empty id, a valid http(s)
	 * url, and a supported format; other fields get sane defaults.
	 *
	 * @param mixed $raw Raw entry from JSON.
	 * @return array|null
	 */
	public static function normalize_feed( $raw ) {
		if ( ! is_array( $raw ) ) {
			return null;
		}

		$id     = isset( $raw['id'] ) ? sanitize_key( $raw['id'] ) : '';
		$url    = isset( $raw['url'] ) ? trim( (string) $raw['url'] ) : '';
		$format = isset( $raw['format'] ) ? (string) $raw['format'] : '';

		if ( '' === $id || ! self::valid_format( $format ) ) {
			return null;
		}
		if ( ! preg_match( '#^https?://#i', $url ) ) {
			return null;
		}

		$interval = isset( $raw['interval_hours'] ) ? (int) $raw['interval_hours'] : 24;
		if ( $interval < 1 ) {
			$interval = 24;
		}

		return array(
			'id'             => $id,
			'label'          => isset( $raw['label'] ) ? (string) $raw['label'] : $id,
			'url'            => $url,
			'format'         => $format,
			'interval_hours' => $interval,
			'enabled'        => ! empty( $raw['enabled'] ),
			'attribution'    => isset( $raw['attribution'] ) ? (string) $raw['attribution'] : '',
		);
	}

	/**
	 * All configured feeds (valid entries only), filterable.
	 *
	 * @return array[] Keyed by feed id.
	 */
	public static function all() {
		if ( null === self::$cache ) {
			self::$cache = self::read_config();
		}

		/**
		 * Filter the loaded feed catalogue (e.g. to add or disable a feed
		 * fleet-wide without shipping a plugin update).
		 *
		 * @param array[] $feeds Normalized feeds keyed by id.
		 */
		$feeds = apply_filters( 'blt_secure_feeds', self::$cache );
		return is_array( $feeds ) ? $feeds : array();
	}

	/**
	 * Only the enabled feeds.
	 *
	 * @return array[]
	 */
	public static function enabled() {
		return array_filter(
			self::all(),
			static function ( $feed ) {
				return ! empty( $feed['enabled'] );
			}
		);
	}

	/**
	 * Enabled feeds of a given format.
	 *
	 * @param string $format One of self::FORMATS.
	 * @return array[]
	 */
	public static function by_format( $format ) {
		return array_filter(
			self::enabled(),
			static function ( $feed ) use ( $format ) {
				return $feed['format'] === $format;
			}
		);
	}

	/**
	 * A single feed by id, or null.
	 *
	 * @param string $id Feed id.
	 * @return array|null
	 */
	public static function get( $id ) {
		$all = self::all();
		return isset( $all[ $id ] ) ? $all[ $id ] : null;
	}

	/**
	 * Clear the request cache (used in tests / after a config change).
	 *
	 * @return void
	 */
	public static function flush() {
		self::$cache = null;
	}

	/**
	 * Read and normalize the bundled config file.
	 *
	 * @return array[] Keyed by id.
	 */
	private static function read_config() {
		$path = BLT_SECURE_DIR . self::CONFIG;
		if ( ! is_readable( $path ) ) {
			return array();
		}

		$data = json_decode( (string) file_get_contents( $path ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		if ( ! is_array( $data ) || empty( $data['feeds'] ) || ! is_array( $data['feeds'] ) ) {
			return array();
		}

		$feeds = array();
		foreach ( $data['feeds'] as $raw ) {
			$feed = self::normalize_feed( $raw );
			if ( null !== $feed ) {
				$feeds[ $feed['id'] ] = $feed;
			}
		}
		return $feeds;
	}
}
