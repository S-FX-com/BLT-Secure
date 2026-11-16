<?php
/**
 * Baseline module: plugin/theme file-integrity monitoring.
 *
 * Records a hash baseline of every installed plugin and theme (keyed by
 * slug + version) and, on a weekly scan, reports files that changed without
 * a version bump — the signature of a tampered or backdoored extension.
 *
 * A version change re-baselines only when it is confirmed (see
 * Blt_Secure_Baseline_Scanner::rebaseline_decision()): the upgrader reported
 * an install/update for that extension, wp.org's published checksums match
 * the files on disk, or the admin acknowledged the finding. A version bump
 * with no such confirmation keeps the old baseline and is reported — editing
 * the Version header must not be a way to launder a modification.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Enumerates extensions, maintains baselines, and reports drift.
 */
class Blt_Secure_Baseline implements Blt_Secure_Module {

	/**
	 * Index of baselines: key => [ version, trust, time, checked, store ].
	 * File hashes live in one non-autoloaded option PER extension (see
	 * store_name()) so no single row grows past max_allowed_packet.
	 */
	const BASELINE_OPTION = 'blt_secure_baselines';
	const RESULTS_OPTION  = 'blt_secure_baseline_results';
	const EVENTS_OPTION   = 'blt_secure_baseline_events';
	const CRON_HOOK       = 'blt_secure_baseline_scan';
	const AJAX_RUN        = 'blt_secure_baseline_scan_run';

	const MAX_FINDINGS = 100;
	const MAX_REMOTE   = 5;       // wp.org checksum fetches per scan.
	const EVENT_TTL    = 2592000; // 30 days.
	const MAX_EVENTS   = 300;

	/**
	 * Settings.
	 *
	 * @var Blt_Secure_Options
	 */
	private $options;

	/**
	 * Alerting sink.
	 *
	 * @var Blt_Secure_Alerting|null
	 */
	private $alerting;

	/**
	 * Finding whitelist.
	 *
	 * @var Blt_Secure_Scan_Whitelist
	 */
	private $whitelist;

	/**
	 * wp.org checksum fetches made during the current scan.
	 *
	 * @var int
	 */
	private $remote_calls = 0;

	/**
	 * Constructor.
	 *
	 * @param Blt_Secure_Options             $options   Settings access.
	 * @param Blt_Secure_Alerting|null       $alerting  Alerting sink.
	 * @param Blt_Secure_Scan_Whitelist|null $whitelist Finding whitelist.
	 */
	public function __construct( Blt_Secure_Options $options, $alerting = null, $whitelist = null ) {
		$this->options   = $options;
		$this->alerting  = $alerting;
		$this->whitelist = $whitelist instanceof Blt_Secure_Scan_Whitelist ? $whitelist : new Blt_Secure_Scan_Whitelist();
	}

	/**
	 * The shared finding whitelist.
	 *
	 * @return Blt_Secure_Scan_Whitelist
	 */
	public function whitelist() {
		return $this->whitelist;
	}

	/**
	 * Module id.
	 *
	 * @return string
	 */
	public function id() {
		return 'baseline';
	}

	/**
	 * Defaults.
	 *
	 * @return array
	 */
	public function defaults() {
		return array(
			'enabled'  => true,
			'schedule' => true,
		);
	}

	/**
	 * Enabled?
	 *
	 * @return bool
	 */
	public function is_enabled() {
		return (bool) $this->options->get( 'baseline', 'enabled', true );
	}

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function boot() {
		add_action( self::CRON_HOOK, array( $this, 'run_scan' ) );
		add_filter( 'blt_secure_health_checks', array( $this, 'register_health_check' ) );

		// Cheap (a hook that only fires during installs/updates): remember which
		// extensions the upgrader touched, so a later version change can be
		// recognized as legitimate.
		add_action( 'upgrader_process_complete', array( $this, 'record_update' ), 10, 2 );

		if ( $this->options->get( 'baseline', 'schedule', true ) ) {
			add_action( 'admin_init', array( $this, 'ensure_scheduled' ) );
		}

		if ( is_admin() ) {
			add_action( 'wp_ajax_' . self::AJAX_RUN, array( $this, 'ajax_run' ) );
		}
	}

	/**
	 * Sanitize section.
	 *
	 * @param array $input   Raw input.
	 * @param array $current Current values.
	 * @return array
	 */
	public function sanitize( $input, $current ) {
		return array(
			'enabled'  => ! empty( $input['enabled'] ),
			'schedule' => ! empty( $input['schedule'] ),
		);
	}

	/**
	 * Ensure the weekly scan is scheduled.
	 *
	 * @return void
	 */
	public function ensure_scheduled() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + ( 5 * HOUR_IN_SECONDS ), 'weekly', self::CRON_HOOK );
		}
	}

	// -------------------------------------------------------------------
	// Update events.
	// -------------------------------------------------------------------

	/**
	 * Baseline keys touched by an upgrader run.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param array $hook_extra Context from upgrader_process_complete.
	 * @param array $installed  Extra plugin files / theme slugs the upgrader reported (install case).
	 * @return string[]
	 */
	public static function keys_from_upgrade( array $hook_extra, array $installed = array() ) {
		$type   = isset( $hook_extra['type'] ) ? (string) $hook_extra['type'] : '';
		$action = isset( $hook_extra['action'] ) ? (string) $hook_extra['action'] : '';
		if ( ! in_array( $action, array( 'update', 'install' ), true ) ) {
			return array();
		}

		$keys = array();
		if ( 'plugin' === $type ) {
			$files = array();
			if ( ! empty( $hook_extra['plugins'] ) && is_array( $hook_extra['plugins'] ) ) {
				$files = $hook_extra['plugins'];
			} elseif ( ! empty( $hook_extra['plugin'] ) ) {
				$files = array( $hook_extra['plugin'] );
			}
			foreach ( array_merge( $files, $installed ) as $file ) {
				$file = (string) $file;
				if ( '' === $file ) {
					continue;
				}
				$dir    = dirname( $file );
				$keys[] = 'plugin/' . ( '.' === $dir ? $file : $dir );
			}
		} elseif ( 'theme' === $type ) {
			$slugs = array();
			if ( ! empty( $hook_extra['themes'] ) && is_array( $hook_extra['themes'] ) ) {
				$slugs = $hook_extra['themes'];
			} elseif ( ! empty( $hook_extra['theme'] ) ) {
				$slugs = array( $hook_extra['theme'] );
			}
			foreach ( array_merge( $slugs, $installed ) as $slug ) {
				if ( '' !== (string) $slug ) {
					$keys[] = 'theme/' . (string) $slug;
				}
			}
		}
		return array_values( array_unique( $keys ) );
	}

	/**
	 * Remember that the upgrader installed/updated these extensions.
	 *
	 * @param mixed $upgrader   Upgrader instance.
	 * @param array $hook_extra Context from core.
	 * @return void
	 */
	public function record_update( $upgrader, $hook_extra ) {
		if ( ! is_array( $hook_extra ) ) {
			return;
		}

		$installed = array();
		if ( is_object( $upgrader ) && isset( $hook_extra['action'], $hook_extra['type'] ) && 'install' === $hook_extra['action'] ) {
			if ( 'plugin' === $hook_extra['type'] && method_exists( $upgrader, 'plugin_info' ) ) {
				$installed[] = (string) $upgrader->plugin_info();
			} elseif ( 'theme' === $hook_extra['type'] && method_exists( $upgrader, 'theme_info' ) ) {
				$theme = $upgrader->theme_info();
				if ( is_object( $theme ) && method_exists( $theme, 'get_stylesheet' ) ) {
					$installed[] = (string) $theme->get_stylesheet();
				}
			}
		}

		$keys = self::keys_from_upgrade( $hook_extra, $installed );
		if ( empty( $keys ) ) {
			return;
		}

		$events = get_option( self::EVENTS_OPTION, array() );
		$events = is_array( $events ) ? $events : array();
		$now    = time();
		foreach ( $keys as $key ) {
			$events[ $key ] = $now;
		}
		update_option( self::EVENTS_OPTION, self::prune_events( $events, $now ), false );
	}

	/**
	 * Drop expired events and cap the list.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param array $events key => timestamp.
	 * @param int   $now    Current time.
	 * @return array
	 */
	public static function prune_events( array $events, $now ) {
		foreach ( $events as $key => $time ) {
			if ( ! is_int( $time ) || ( $now - $time ) > self::EVENT_TTL ) {
				unset( $events[ $key ] );
			}
		}
		if ( count( $events ) > self::MAX_EVENTS ) {
			asort( $events );
			$events = array_slice( $events, count( $events ) - self::MAX_EVENTS, null, true );
		}
		return $events;
	}

	// -------------------------------------------------------------------
	// Targets and storage.
	// -------------------------------------------------------------------

	/**
	 * Enumerate installed plugins and themes as baseline targets.
	 *
	 * @return array[] Each: [ key, label, dir, version, single (bool), file, slug ].
	 */
	protected function targets() {
		foreach ( array( 'plugin.php', 'theme.php' ) as $file ) {
			$path = ABSPATH . 'wp-admin/includes/' . $file;
			if ( is_readable( $path ) ) {
				require_once $path;
			}
		}

		$targets = array();

		if ( function_exists( 'get_plugins' ) ) {
			$plugin_dir = defined( 'WP_PLUGIN_DIR' ) ? WP_PLUGIN_DIR : WP_CONTENT_DIR . '/plugins';
			foreach ( get_plugins() as $file => $data ) {
				$dirname   = dirname( $file );
				$single    = ( '.' === $dirname );
				$targets[] = array(
					'key'     => 'plugin/' . ( $single ? $file : $dirname ),
					'label'   => isset( $data['Name'] ) ? $data['Name'] : $file,
					'dir'     => $single ? $plugin_dir . '/' . $file : $plugin_dir . '/' . $dirname,
					'version' => isset( $data['Version'] ) ? (string) $data['Version'] : '',
					'single'  => $single,
					'file'    => $file,
					'slug'    => $single ? '' : $dirname,
				);
			}
		}

		if ( function_exists( 'wp_get_themes' ) ) {
			foreach ( wp_get_themes() as $slug => $theme ) {
				$targets[] = array(
					'key'     => 'theme/' . $slug,
					'label'   => $theme->get( 'Name' ) ? $theme->get( 'Name' ) : $slug,
					'dir'     => $theme->get_stylesheet_directory(),
					'version' => (string) $theme->get( 'Version' ),
					'single'  => false,
					'file'    => '',
					'slug'    => '',
				);
			}
		}

		return $targets;
	}

	/**
	 * Option name that holds one extension's file hashes.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string $key Baseline key.
	 * @return string
	 */
	public static function store_name( $key ) {
		return 'blt_secure_bl_' . substr( md5( (string) $key ), 0, 20 );
	}

	/**
	 * Write an option and confirm it stuck. update_option() returns false both
	 * for "unchanged" and for a failed write (e.g. a row over max_allowed_packet),
	 * so a false result is verified by reading the value back.
	 *
	 * @param string $name  Option name.
	 * @param mixed  $value Value.
	 * @return bool
	 */
	private function store( $name, $value ) {
		if ( update_option( $name, $value, false ) ) {
			return true;
		}
		return get_option( $name, null ) === $value;
	}

	/**
	 * Hash a target (directory tree, or a single-file plugin).
	 *
	 * @param Blt_Secure_Baseline_Scanner $engine Engine.
	 * @param array                       $target Target descriptor.
	 * @return array|null path => hash, or null when unhashable/too large.
	 */
	private function hash_target( Blt_Secure_Baseline_Scanner $engine, array $target ) {
		if ( empty( $target['single'] ) ) {
			return $engine->hash_dir( $target['dir'] );
		}
		if ( ! is_readable( $target['dir'] ) ) {
			$engine->last_reason = 'unreadable';
			return null;
		}
		$md5 = md5_file( $target['dir'] );
		if ( false === $md5 ) {
			$engine->last_reason = 'unreadable';
			return null;
		}
		$engine->last_reason = '';
		return array( basename( $target['dir'] ) => $md5 );
	}

	/**
	 * Load an extension's stored file hashes (migrating the legacy inline form).
	 *
	 * @param string     $key   Baseline key.
	 * @param array|null $entry Index entry.
	 * @return array
	 */
	private function stored_hashes( $key, $entry ) {
		if ( is_array( $entry ) && isset( $entry['hashes'] ) && is_array( $entry['hashes'] ) ) {
			return $entry['hashes']; // Legacy inline storage (pre-split).
		}
		$hashes = get_option( self::store_name( $key ), array() );
		return is_array( $hashes ) ? $hashes : array();
	}

	/**
	 * Whether wp.org's published checksums vouch for the files on disk.
	 *
	 * Only repository-hosted plugins are checkable (themes have no checksum
	 * endpoint). Network calls are capped per scan; a failed fetch is simply
	 * "not confirmed".
	 *
	 * @param array $target Target descriptor.
	 * @param array $hashes Current hashes.
	 * @return bool
	 */
	private function wporg_confirms( array $target, array $hashes ) {
		if ( 0 !== strpos( $target['key'], 'plugin/' ) || '' === $target['slug'] || '' === $target['version'] || $this->remote_calls >= self::MAX_REMOTE ) {
			return false;
		}
		$updates = get_site_transient( 'update_plugins' );
		$info    = null;
		foreach ( array( 'response', 'no_update' ) as $bucket ) {
			if ( is_object( $updates ) && isset( $updates->{$bucket}[ $target['file'] ] ) ) {
				$info = $updates->{$bucket}[ $target['file'] ];
				break;
			}
		}
		$id = is_object( $info ) && isset( $info->id ) ? (string) $info->id : '';
		if ( 0 !== strpos( $id, 'w.org/plugins/' ) ) {
			return false;
		}

		++$this->remote_calls;
		$response = wp_remote_get(
			'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode( $target['slug'] ) . '/' . rawurlencode( $target['version'] ) . '.json',
			array(
				'timeout'             => 8,
				'limit_response_size' => 5242880,
			)
		);
		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}
		$manifest = Blt_Secure_Baseline_Scanner::parse_manifest( wp_remote_retrieve_body( $response ) );
		return null !== $manifest && Blt_Secure_Baseline_Scanner::matches_manifest( $hashes, $manifest );
	}

	/**
	 * Wall-clock budget for one scan, in seconds.
	 *
	 * @return float
	 */
	private function time_budget() {
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 120 ); // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged, WordPress.PHP.NoSilencedErrors.Discouraged
		}
		$max    = (int) ini_get( 'max_execution_time' );
		$budget = $max > 0 ? max( 10, $max - 8 ) : 90;
		return (float) apply_filters( 'blt_secure_scan_time_budget', min( 90, $budget ) );
	}

	// -------------------------------------------------------------------
	// Scan.
	// -------------------------------------------------------------------

	/**
	 * Run the baseline scan: baseline new extensions, re-baseline CONFIRMED
	 * version changes, and report drift, unconfirmed version bumps and
	 * extensions that cannot be monitored.
	 *
	 * @return array Stored results payload.
	 */
	public function run_scan() {
		require_once BLT_SECURE_DIR . 'includes/scanner/class-baseline-scanner.php';

		$engine  = new Blt_Secure_Baseline_Scanner();
		$targets = $this->targets();
		$started = microtime( true );
		$budget  = $this->time_budget();

		$index = get_option( self::BASELINE_OPTION, array() );
		$index = is_array( $index ) ? $index : array();

		$events = get_option( self::EVENTS_OPTION, array() );
		$events = is_array( $events ) ? $events : array();

		// Least-recently-checked first, so a time-limited run cannot starve the
		// same targets forever.
		usort(
			$targets,
			static function ( $a, $b ) use ( $index ) {
				$ta = isset( $index[ $a['key'] ]['checked'] ) ? (int) $index[ $a['key'] ]['checked'] : 0;
				$tb = isset( $index[ $b['key'] ]['checked'] ) ? (int) $index[ $b['key'] ]['checked'] : 0;
				return $ta <=> $tb;
			}
		);

		$this->remote_calls = 0;
		$findings           = array();
		$partial            = false;
		$errors             = 0;
		$events_dirty       = false;
		$now                = time();
		$next               = array();

		foreach ( $targets as $target ) {
			$key   = $target['key'];
			$entry = isset( $index[ $key ] ) && is_array( $index[ $key ] ) ? $index[ $key ] : null;
			if ( null !== $entry ) {
				$next[ $key ] = $entry;
			}

			if ( ( microtime( true ) - $started ) > $budget ) {
				$partial = true;
				continue; // Keep the stored entry; checked next run, first.
			}

			$hashes = $this->hash_target( $engine, $target );
			if ( null === $hashes ) {
				// Cannot monitor it — say so instead of silently passing. The
				// previous baseline (if any) is kept untouched.
				$reason = $engine->last_reason;
				if ( count( $findings ) < self::MAX_FINDINGS ) {
					$findings[] = array(
						'key'         => $key,
						'kind'        => 'unmonitored',
						'label'       => sprintf(
							/* translators: 1: plugin/theme name, 2: reason */
							__( '%1$s — not monitored (%2$s)', 'blt-secure' ),
							$target['label'],
							'too_large' === $reason ? __( 'too many files to hash', 'blt-secure' ) : __( 'files could not be read', 'blt-secure' )
						),
						'version'     => $target['version'],
						'added'       => 0,
						'modified'    => 0,
						'removed'     => 0,
						'files'       => array(),
						'fingerprint' => Blt_Secure_Baseline_Scanner::drift_fingerprint( $key, $target['version'], array( 'unmonitored:' . $reason ), array() ),
					);
				}
				continue;
			}

			$old_hashes = null === $entry ? array() : $this->stored_hashes( $key, $entry );
			$diff       = Blt_Secure_Baseline_Scanner::diff( $old_hashes, $hashes );
			$changed    = array_merge( $diff['modified'], $diff['added'], $diff['removed'] );

			// Decide what a differing version means.
			$bump_fp   = '';
			$confirmed = false;
			$trust     = '';
			$ack       = false;
			if ( null !== $entry && isset( $entry['version'] ) && (string) $entry['version'] !== $target['version'] ) {
				$bump_fp = Blt_Secure_Baseline_Scanner::drift_fingerprint(
					$key,
					$target['version'],
					array_merge( $changed, array( 'version:' . (string) $entry['version'] . '>' . $target['version'] ) ),
					$hashes
				);
				$ack     = $this->whitelist->is_whitelisted( $bump_fp );
				if ( isset( $events[ $key ] ) && (int) $events[ $key ] >= (int) ( isset( $entry['time'] ) ? $entry['time'] : 0 ) ) {
					$confirmed = true;
					$trust     = 'update_event';
				} elseif ( ! $ack && $this->wporg_confirms( $target, $hashes ) ) {
					$confirmed = true;
					$trust     = 'wporg_checksums';
				}
				if ( $ack && ! $confirmed ) {
					$trust = 'acknowledged';
				}
			}

			$decision = Blt_Secure_Baseline_Scanner::rebaseline_decision( $entry, $target['version'], $confirmed, $ack );

			if ( 'baseline' === $decision || 'accept' === $decision ) {
				$new_trust = 'baseline' === $decision ? 'first_seen' : $trust; // first_seen = trust on first use.
				$saved     = $this->store( self::store_name( $key ), $hashes );
				if ( $saved ) {
					$next[ $key ] = array(
						'version' => $target['version'],
						'trust'   => $new_trust,
						'time'    => $now,
						'checked' => $now,
						'count'   => count( $hashes ),
					);
					if ( 'accept' === $decision && isset( $events[ $key ] ) ) {
						unset( $events[ $key ] );
						$events_dirty = true;
					}
				} else {
					++$errors; // Could not persist: keep whatever was stored before.
				}
				continue;
			}

			if ( null !== $entry ) {
				$next[ $key ]            = $entry;
				$next[ $key ]['checked'] = $now;
				unset( $next[ $key ]['hashes'] );
				if ( isset( $entry['hashes'] ) && is_array( $entry['hashes'] ) ) {
					// Legacy inline hashes: move them into their own option now.
					if ( ! $this->store( self::store_name( $key ), $entry['hashes'] ) ) {
						$next[ $key ]['hashes'] = $entry['hashes'];
						++$errors;
					}
				}
			}

			if ( 'flag' === $decision ) {
				if ( count( $findings ) < self::MAX_FINDINGS ) {
					$findings[] = array(
						'key'         => $key,
						'kind'        => 'version_bump',
						'label'       => sprintf(
							/* translators: 1: plugin/theme name, 2: old version, 3: new version */
							__( '%1$s — version changed %2$s → %3$s with no update event', 'blt-secure' ),
							$target['label'],
							(string) $entry['version'],
							$target['version']
						),
						'version'     => $target['version'],
						'added'       => count( $diff['added'] ),
						'modified'    => count( $diff['modified'] ),
						'removed'     => count( $diff['removed'] ),
						'files'       => array_slice( $changed, 0, 10 ),
						'fingerprint' => $bump_fp,
					);
				}
				continue;
			}

			// 'compare': same version — any change is unexpected.
			if ( Blt_Secure_Baseline_Scanner::has_changes( $diff ) && count( $findings ) < self::MAX_FINDINGS ) {
				$findings[] = array(
					'key'         => $key,
					'kind'        => 'drift',
					'label'       => $target['label'],
					'version'     => $target['version'],
					'added'       => count( $diff['added'] ),
					'modified'    => count( $diff['modified'] ),
					'removed'     => count( $diff['removed'] ),
					'files'       => array_slice( $changed, 0, 10 ),
					// Content-sensitive over the FULL changed set so a later edit re-flags.
					'fingerprint' => Blt_Secure_Baseline_Scanner::drift_fingerprint( $key, $target['version'], $changed, $hashes ),
				);
			}
		}

		// Forget baselines (and their hash options) of extensions that are gone.
		$present = array();
		foreach ( $targets as $target ) {
			$present[ $target['key'] ] = true;
		}
		foreach ( array_keys( $next ) as $key ) {
			if ( ! isset( $present[ $key ] ) ) {
				delete_option( self::store_name( $key ) );
				unset( $next[ $key ] );
			}
		}

		if ( ! $this->store( self::BASELINE_OPTION, $next ) ) {
			++$errors;
		}
		if ( $events_dirty ) {
			update_option( self::EVENTS_OPTION, self::prune_events( $events, $now ), false );
		}

		$payload = array(
			'time'      => $now,
			'targets'   => count( $targets ),
			'findings'  => $findings,
			'truncated' => count( $findings ) >= self::MAX_FINDINGS,
			'partial'   => $partial,
			'errors'    => $errors,
		);
		update_option( self::RESULTS_OPTION, $payload, false );

		$active = $this->whitelist->active( $findings );
		if ( $this->alerting && ! empty( $active ) ) {
			$this->alerting->notify( 'baseline_drift', array( 'count' => count( $active ) ) );
		}

		return $payload;
	}

	/**
	 * The most recent stored results, or null.
	 *
	 * @return array|null
	 */
	public function latest() {
		$payload = get_option( self::RESULTS_OPTION, null );
		return is_array( $payload ) ? $payload : null;
	}

	/**
	 * Contribute a summary check to the Health Check catalogue.
	 *
	 * @param array[] $checks Existing checks.
	 * @return array[]
	 */
	public function register_health_check( $checks ) {
		$checks[] = array(
			'id'       => 'plugin_theme_integrity',
			'label'    => __( 'Installed plugins and themes match their baseline', 'blt-secure' ),
			'category' => 'files',
			'callback' => array( $this, 'health_check' ),
		);
		return $checks;
	}

	/**
	 * Whether every active finding is an "unmonitored" notice (advisory only).
	 *
	 * Pure function (unit-tested).
	 *
	 * @param array[] $findings Active findings.
	 * @return bool
	 */
	public static function only_unmonitored( array $findings ) {
		foreach ( $findings as $finding ) {
			if ( ! is_array( $finding ) || ! isset( $finding['kind'] ) || 'unmonitored' !== $finding['kind'] ) {
				return false;
			}
		}
		return ! empty( $findings );
	}

	/**
	 * Health-check callback.
	 *
	 * @return array
	 */
	public function health_check() {
		$payload = $this->latest();
		if ( null === $payload ) {
			return array(
				'status'  => Blt_Secure_Health_Result::SKIP,
				'message' => __( 'No baseline scan has run yet — open the Scanner tab and run one.', 'blt-secure' ),
			);
		}

		$active = isset( $payload['findings'] ) ? $this->whitelist->active( (array) $payload['findings'] ) : array();
		$count  = count( $active );

		if ( $count > 0 ) {
			if ( self::only_unmonitored( $active ) ) {
				return array(
					'status'  => Blt_Secure_Health_Result::WARN,
					'message' => sprintf(
						/* translators: %d: number of extensions */
						_n( '%d plugin/theme could not be monitored for file changes.', '%d plugins/themes could not be monitored for file changes.', $count, 'blt-secure' ),
						$count
					),
					'details' => __( 'Too many files to hash, or the files were unreadable. Ignore the finding on the Scanner tab if this is expected.', 'blt-secure' ),
				);
			}
			return array(
				'status'  => Blt_Secure_Health_Result::FAIL,
				'message' => sprintf(
					/* translators: %d: number of extensions */
					_n( '%d plugin/theme changed without a verified update.', '%d plugins/themes changed without a verified update.', $count, 'blt-secure' ),
					$count
				),
				'details' => __( 'Files changed without a version update, or the version was changed without an install/update event. That can mean a compromised extension. Review it on the Scanner tab; reinstall the plugin/theme from a trusted source if you did not make the change.', 'blt-secure' ),
			);
		}

		if ( ! empty( $payload['errors'] ) ) {
			return array(
				'status'  => Blt_Secure_Health_Result::WARN,
				'message' => __( 'The file baseline could not be saved (database write failed), so changes may go unnoticed.', 'blt-secure' ),
			);
		}
		if ( ! empty( $payload['partial'] ) ) {
			return array(
				'status'  => Blt_Secure_Health_Result::WARN,
				'message' => __( 'The last baseline scan ran out of time before checking every plugin/theme. The rest are checked first next run.', 'blt-secure' ),
			);
		}

		return array(
			'status'  => Blt_Secure_Health_Result::PASS,
			'message' => sprintf(
				/* translators: %d: number of extensions */
				__( 'All %d installed plugins/themes match their recorded baseline.', 'blt-secure' ),
				isset( $payload['targets'] ) ? (int) $payload['targets'] : 0
			),
		);
	}

	/**
	 * AJAX: run a scan now.
	 *
	 * @return void
	 */
	public function ajax_run() {
		check_ajax_referer( 'blt_secure_cf' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'blt-secure' ) ), 403 );
		}

		$payload = $this->run_scan();
		wp_send_json_success( $payload );
	}
}
