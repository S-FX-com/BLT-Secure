<?php
/**
 * Buoy bridge: the local, read-only surface BLT Connect (the Buoy fleet agent)
 * reads BLT Secure through.
 *
 * BLT Connect is the ONLY transport between a site and Buoy (Ed25519-signed
 * envelopes, a fixed command vocabulary). This class adds no network code, no
 * credentials and no inbound route: it only answers a filter the agent applies
 * while serving an already-authenticated `inventory.read`. When BLT Connect is
 * absent or the site is not enrolled, nothing ever calls it.
 *
 * Contract (mirrored by Buoy's `ingestMalwareFindings`, DECISIONS
 * D-2026-11-16-01):
 *  - Each finding is exactly `{ severity, signature, path }`.
 *  - At most 199 real findings, most severe first, so the agent's own
 *    200-item slice never cuts a real finding. When more existed, or any
 *    scanner's result is missing/partial, a sentinel finding with signature
 *    `blt_secure:truncated` is appended. Buoy treats a list WITH the sentinel
 *    as incomplete and resolves nothing from it.
 *  - Findings the site owner ignored (the scan whitelist) are excluded, so Buoy
 *    mirrors what the site itself shows as active.
 *  - Severity is capped at `high` unless the `blt_secure_buoy_allow_critical`
 *    filter says otherwise. In Buoy, `critical` opens an incident, marks
 *    backups suspect and blocks automated updates until a person triages it,
 *    and Buoy has no triage UI yet. Heuristic signatures must not be able to
 *    freeze updates on a client site.
 *  - Paths are relative (as the scanners store them); no file contents, no
 *    snippets, no secrets leave the site.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Builds and serves the `blt_secure_findings` payload.
 */
class Blt_Secure_Buoy_Bridge {

	/**
	 * Signature of the "this list is incomplete" marker. Keep in sync with
	 * FINDINGS_TRUNCATED_SIGNATURE in Buoy's services/inventory.ts.
	 */
	const TRUNCATED_SIGNATURE = 'blt_secure:truncated';

	/**
	 * Real findings per payload. The agent slices to 200; one slot is kept for
	 * the sentinel so it can never be the item that gets cut.
	 */
	const MAX_FINDINGS = 199;

	/**
	 * Severity rank, most severe first.
	 *
	 * @var array<string,int>
	 */
	private static $rank = array(
		'critical' => 4,
		'high'     => 3,
		'medium'   => 2,
		'low'      => 1,
	);

	/**
	 * Scan whitelist (ignored findings).
	 *
	 * @var Blt_Secure_Scan_Whitelist
	 */
	private $whitelist;

	/**
	 * Constructor.
	 *
	 * @param Blt_Secure_Scan_Whitelist $whitelist Finding whitelist.
	 */
	public function __construct( Blt_Secure_Scan_Whitelist $whitelist ) {
		$this->whitelist = $whitelist;
	}

	/**
	 * Hook the provider. Cheap: a single filter registration, no I/O.
	 *
	 * @return void
	 */
	public function boot() {
		add_filter( 'blt_secure_findings', array( $this, 'provide' ), 10, 1 );
	}

	/**
	 * Filter callback: answer BLT Connect's `apply_filters( 'blt_secure_findings', null )`.
	 *
	 * Runs only while the agent serves an authenticated inventory.read (cron or
	 * REST), never on a front-end page view, and only reads three options.
	 *
	 * @param mixed $current Value from earlier callbacks (null from the agent).
	 * @return mixed Findings array, or $current when sharing is switched off.
	 */
	public function provide( $current ) {
		/**
		 * Switch off sharing findings with Buoy for this site.
		 *
		 * @param bool $enabled Default true.
		 */
		if ( ! apply_filters( 'blt_secure_buoy_findings_enabled', true ) ) {
			return $current;
		}

		/**
		 * Allow `critical` to pass through to Buoy unchanged. Leave false until Buoy
		 * has a findings triage workflow (see the class docblock).
		 *
		 * @param bool $allow Default false.
		 */
		$allow_critical = (bool) apply_filters( 'blt_secure_buoy_allow_critical', false );

		return self::build(
			get_option( 'blt_secure_core_scan_results', array() ),
			get_option( 'blt_secure_malware_results', array() ),
			get_option( 'blt_secure_baseline_results', array() ),
			$this->whitelist,
			$allow_critical
		);
	}

	/**
	 * Assemble the payload from the three stored scan results.
	 *
	 * Pure apart from the whitelist lookup; unit-tested.
	 *
	 * @param mixed                     $core           Core scan payload.
	 * @param mixed                     $malware        Malware scan payload.
	 * @param mixed                     $baseline       Baseline scan payload.
	 * @param Blt_Secure_Scan_Whitelist $whitelist      Finding whitelist.
	 * @param bool                      $allow_critical Pass `critical` through.
	 * @return array<int,array{severity:string,signature:string,path:string}>
	 */
	public static function build( $core, $malware, $baseline, Blt_Secure_Scan_Whitelist $whitelist, $allow_critical = false ) {
		$rows       = array();
		$incomplete = false;

		$sources = array(
			array( $core, 'issues', 'core' ),
			array( $malware, 'findings', 'malware' ),
			array( $baseline, 'findings', 'baseline' ),
		);

		foreach ( $sources as $source ) {
			list( $payload, $key, $scanner ) = $source;

			// A scanner that never ran, errored, or stopped early says nothing
			// about the files it did not reach: the list is not the whole truth.
			if ( ! is_array( $payload ) || empty( $payload ) || ! empty( $payload['error'] ) || ! empty( $payload['partial'] ) || ! empty( $payload['truncated'] ) ) {
				$incomplete = true;
			}
			if ( ! is_array( $payload ) || empty( $payload[ $key ] ) || ! is_array( $payload[ $key ] ) ) {
				continue;
			}

			foreach ( $whitelist->active( $payload[ $key ] ) as $finding ) {
				if ( ! is_array( $finding ) ) {
					continue;
				}
				$row = self::normalize( $scanner, $finding, $allow_critical );
				if ( null !== $row ) {
					$rows[] = $row;
				}
			}
		}

		usort(
			$rows,
			static function ( $a, $b ) {
				$by_severity = self::$rank[ $b['severity'] ] - self::$rank[ $a['severity'] ];
				if ( 0 !== $by_severity ) {
					return $by_severity;
				}
				$by_path = strcmp( $a['path'], $b['path'] );
				return 0 !== $by_path ? $by_path : strcmp( $a['signature'], $b['signature'] );
			}
		);

		if ( count( $rows ) > self::MAX_FINDINGS ) {
			$rows       = array_slice( $rows, 0, self::MAX_FINDINGS );
			$incomplete = true;
		}

		if ( $incomplete ) {
			$rows[] = array(
				'severity'  => 'low',
				'signature' => self::TRUNCATED_SIGNATURE,
				'path'      => '',
			);
		}

		return $rows;
	}

	/**
	 * Map one scanner finding to `{ severity, signature, path }`.
	 *
	 * The signature is built only from parts that do not change with the admin
	 * language, because Buoy de-duplicates on signature + path and a changed
	 * signature would resolve and reopen every finding. For malware that is the
	 * finding type plus a hash of path, content hash and line (the stored
	 * fingerprint also hashes the translated description, so it is not used).
	 * Core and baseline fingerprints contain no translated text and are used.
	 *
	 * @param string $scanner        'core' | 'malware' | 'baseline'.
	 * @param array  $finding        Stored finding.
	 * @param bool   $allow_critical Pass `critical` through.
	 * @return array{severity:string,signature:string,path:string}|null
	 */
	private static function normalize( $scanner, array $finding, $allow_critical ) {
		$fingerprint = isset( $finding['fingerprint'] ) ? preg_replace( '/[^a-f0-9]/', '', strtolower( (string) $finding['fingerprint'] ) ) : '';
		$short       = substr( (string) $fingerprint, 0, 12 );

		if ( 'core' === $scanner ) {
			$status    = isset( $finding['status'] ) ? preg_replace( '/[^a-z_]/', '', strtolower( (string) $finding['status'] ) ) : 'issue';
			$path      = isset( $finding['path'] ) ? (string) $finding['path'] : '';
			$severity  = 'modified' === $status ? 'high' : 'medium';
			$signature = 'core_' . $status;
		} elseif ( 'malware' === $scanner ) {
			$type     = isset( $finding['type'] ) ? preg_replace( '/[^a-z0-9_]/', '', strtolower( (string) $finding['type'] ) ) : 'finding';
			$path     = isset( $finding['path'] ) ? (string) $finding['path'] : '';
			$severity = isset( $finding['severity'] ) ? strtolower( (string) $finding['severity'] ) : 'medium';
			// The stored fingerprint also hashes the translated description, so it changes when the
			// admin language does. Build the signature from the stable parts instead.
			$stable    = isset( $finding['hash'] ) ? sha1( $type . '|' . $path . '|' . (string) $finding['hash'] . '|' . ( isset( $finding['line'] ) ? (int) $finding['line'] : 0 ) ) : $short;
			$signature = 'malware_' . $type . ( '' !== $stable ? ':' . substr( $stable, 0, 12 ) : '' );
		} else {
			$kind      = isset( $finding['kind'] ) ? preg_replace( '/[^a-z_]/', '', strtolower( (string) $finding['kind'] ) ) : 'drift';
			$path      = isset( $finding['key'] ) ? (string) $finding['key'] : '';
			$signature = 'baseline_' . $kind . ( '' !== $short ? ':' . $short : '' );
			if ( 'unmonitored' === $kind ) {
				$severity = 'low';
			} elseif ( 'version_bump' === $kind ) {
				// A version change nobody installed, with files that differ, is
				// what a tampered plugin looks like.
				$severity = ( ! empty( $finding['modified'] ) || ! empty( $finding['added'] ) ) ? 'high' : 'medium';
			} else {
				$severity = 'medium';
			}
		}

		if ( '' === $path ) {
			return null;
		}
		if ( ! isset( self::$rank[ $severity ] ) ) {
			$severity = 'medium';
		}
		if ( 'critical' === $severity && ! $allow_critical ) {
			$severity = 'high';
		}

		return array(
			'severity'  => $severity,
			'signature' => substr( $signature, 0, 190 ),
			'path'      => substr( $path, 0, 300 ),
		);
	}
}
