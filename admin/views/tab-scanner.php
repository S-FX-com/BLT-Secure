<?php
/**
 * Scanner tab: core file integrity + malware signature results.
 *
 * @var Blt_Secure_Scanner|null       $scanner   Core scanner module (null if disabled).
 * @var Blt_Secure_Malware|null       $malware   Malware module (null if disabled).
 * @var Blt_Secure_Baseline|null      $baseline  Baseline module (null if disabled).
 * @var Blt_Secure_Scan_Whitelist     $whitelist Shared finding whitelist.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$blt_secure_scan = $scanner ? $scanner->latest() : null;
$blt_secure_mw   = $malware ? $malware->latest() : null;

$blt_secure_core_issues  = ( $blt_secure_scan && ! empty( $blt_secure_scan['issues'] ) ) ? $blt_secure_scan['issues'] : array();
$blt_secure_core_active  = $whitelist->active( $blt_secure_core_issues );
$blt_secure_core_ignored = $whitelist->ignored( $blt_secure_core_issues );
$blt_secure_mw_findings  = ( $blt_secure_mw && ! empty( $blt_secure_mw['findings'] ) ) ? $blt_secure_mw['findings'] : array();
$blt_secure_mw_active    = $whitelist->active( $blt_secure_mw_findings );
$blt_secure_mw_ignored   = $whitelist->ignored( $blt_secure_mw_findings );

$blt_secure_core_meta = array(
	Blt_Secure_Core_Scanner::STATUS_MODIFIED => __( 'Modified', 'blt-secure' ),
	Blt_Secure_Core_Scanner::STATUS_MISSING  => __( 'Missing', 'blt-secure' ),
	Blt_Secure_Core_Scanner::STATUS_UNKNOWN  => __( 'Unexpected', 'blt-secure' ),
);

$blt_secure_sev_class = array(
	'critical' => 'blt-hc-fail',
	'high'     => 'blt-hc-fail',
	'medium'   => 'blt-hc-warn',
	'low'      => 'blt-hc-warn',
);
?>
<div class="blt-hc">

	<h2 class="blt-hc-cat"><?php esc_html_e( 'Core file integrity', 'blt-secure' ); ?></h2>
	<p class="description">
		<?php esc_html_e( 'Verifies your WordPress core files against the official md5 checksums published by WordPress.org. Modified, missing, or unexpected files in wp-admin and wp-includes can indicate a compromise. Runs automatically once a day.', 'blt-secure' ); ?>
	</p>

	<?php if ( null === $scanner ) : ?>
		<div class="notice notice-warning inline"><p><?php esc_html_e( 'The core scanner is disabled.', 'blt-secure' ); ?></p></div>
	<?php else : ?>

		<?php if ( $blt_secure_scan && empty( $blt_secure_scan['error'] ) ) : ?>
			<?php
			$blt_secure_issue_count = count( $blt_secure_core_active );
			$blt_secure_clean       = ( 0 === $blt_secure_issue_count );
			?>
			<div class="blt-hc-scoreboard">
				<div class="blt-hc-score <?php echo $blt_secure_clean ? 'blt-hc-score-good' : 'blt-hc-score-bad'; ?>">
					<span class="blt-hc-score-num"><?php echo $blt_secure_clean ? '✓' : esc_html( $blt_secure_issue_count ); ?></span>
					<span class="blt-hc-score-label"><?php echo $blt_secure_clean ? esc_html__( 'Core intact', 'blt-secure' ) : esc_html__( 'Issues', 'blt-secure' ); ?></span>
				</div>
				<ul class="blt-hc-tallies">
					<li><strong><?php echo esc_html( isset( $blt_secure_scan['checked'] ) ? (int) $blt_secure_scan['checked'] : 0 ); ?></strong> <?php esc_html_e( 'Core files verified', 'blt-secure' ); ?></li>
					<li><strong><?php echo esc_html( isset( $blt_secure_scan['version'] ) ? $blt_secure_scan['version'] : '' ); ?></strong> <?php esc_html_e( 'WordPress version', 'blt-secure' ); ?></li>
				</ul>
			</div>
			<p class="blt-hc-meta">
				<?php
				printf(
					/* translators: %s: human-readable time difference */
					esc_html__( 'Last scanned %s ago.', 'blt-secure' ),
					esc_html( human_time_diff( (int) $blt_secure_scan['time'], time() ) )
				);
				?>
			</p>
		<?php elseif ( $blt_secure_scan && ! empty( $blt_secure_scan['error'] ) ) : ?>
			<div class="notice notice-warning inline"><p><?php echo esc_html( $blt_secure_scan['error'] ); ?></p></div>
		<?php else : ?>
			<div class="blt-hc-scoreboard blt-hc-empty">
				<p><?php esc_html_e( 'No scan has run yet. Run a scan to verify your core files.', 'blt-secure' ); ?></p>
			</div>
		<?php endif; ?>

		<p>
			<button type="button" class="button button-primary" id="blt-scan-run"><?php esc_html_e( 'Scan core files now', 'blt-secure' ); ?></button>
			<span id="blt-scan-status" class="blt-card-message"></span>
		</p>

		<?php if ( ! empty( $blt_secure_core_active ) ) : ?>
			<ul class="blt-hc-list">
				<?php foreach ( $blt_secure_core_active as $blt_secure_issue ) : ?>
					<?php
					$blt_secure_st    = isset( $blt_secure_issue['status'] ) ? $blt_secure_issue['status'] : Blt_Secure_Core_Scanner::STATUS_MODIFIED;
					$blt_secure_label = isset( $blt_secure_core_meta[ $blt_secure_st ] ) ? $blt_secure_core_meta[ $blt_secure_st ] : $blt_secure_st;
					$blt_secure_cls   = Blt_Secure_Core_Scanner::STATUS_MISSING === $blt_secure_st ? 'blt-hc-warn' : 'blt-hc-fail';
					$blt_secure_path  = isset( $blt_secure_issue['path'] ) ? $blt_secure_issue['path'] : '';
					?>
					<li class="blt-hc-item <?php echo esc_attr( $blt_secure_cls ); ?>">
						<span class="blt-hc-icon" aria-hidden="true">!</span>
						<span class="blt-hc-body">
							<span class="blt-hc-title"><code><?php echo esc_html( $blt_secure_path ); ?></code></span>
							<span class="blt-hc-msg"><?php echo esc_html( $blt_secure_label ); ?></span>
						</span>
						<?php blt_secure_ignore_button( 'core', isset( $blt_secure_issue['fingerprint'] ) ? $blt_secure_issue['fingerprint'] : '', $blt_secure_label . ' — ' . $blt_secure_path ); ?>
					</li>
				<?php endforeach; ?>
			</ul>
			<?php if ( ! empty( $blt_secure_scan['truncated'] ) ) : ?>
				<p class="description"><?php esc_html_e( 'The list was truncated — fix these and re-scan to see any remaining issues.', 'blt-secure' ); ?></p>
			<?php endif; ?>
			<p class="description"><?php esc_html_e( 'To restore modified or missing core files, go to Dashboard → Updates and click “Re-install version”. Investigate any “unexpected” files before deleting them.', 'blt-secure' ); ?></p>
		<?php elseif ( $blt_secure_scan && empty( $blt_secure_scan['error'] ) ) : ?>
			<div class="notice notice-success inline"><p><?php esc_html_e( 'Every core file matches the official WordPress checksums.', 'blt-secure' ); ?></p></div>
		<?php endif; ?>

		<?php
		if ( ! empty( $blt_secure_core_ignored ) ) {
			$blt_secure_items = array();
			foreach ( $blt_secure_core_ignored as $blt_secure_issue ) {
				$blt_secure_st      = isset( $blt_secure_issue['status'] ) ? $blt_secure_issue['status'] : Blt_Secure_Core_Scanner::STATUS_MODIFIED;
				$blt_secure_items[] = array(
					'title'       => isset( $blt_secure_issue['path'] ) ? $blt_secure_issue['path'] : '',
					'meta'        => isset( $blt_secure_core_meta[ $blt_secure_st ] ) ? $blt_secure_core_meta[ $blt_secure_st ] : $blt_secure_st,
					'fingerprint' => isset( $blt_secure_issue['fingerprint'] ) ? $blt_secure_issue['fingerprint'] : '',
				);
			}
			blt_secure_ignored_details( $blt_secure_items );
		}
		?>

	<?php endif; ?>

	<hr style="margin:32px 0;" />

	<h2 class="blt-hc-cat"><?php esc_html_e( 'Malware scan', 'blt-secure' ); ?></h2>
	<p class="description">
		<?php esc_html_e( 'Scans wp-content (uploads, plugins, themes, mu-plugins) for known malware and webshell signatures, and specifically flags any executable or script file (PHP, HTML, JS, SVG, server scripts, config overrides) found in the uploads directory — where only media and documents belong. Signature matches are occasionally false positives — inspect each flagged file before acting. Runs automatically once a week.', 'blt-secure' ); ?>
	</p>

	<?php if ( null === $malware ) : ?>
		<div class="notice notice-warning inline"><p><?php esc_html_e( 'The malware scanner is disabled.', 'blt-secure' ); ?></p></div>
	<?php else : ?>

		<?php if ( $blt_secure_mw && empty( $blt_secure_mw['error'] ) ) : ?>
			<?php
			$blt_secure_mw_count = count( $blt_secure_mw_active );
			$blt_secure_mw_clean = ( 0 === $blt_secure_mw_count );
			?>
			<div class="blt-hc-scoreboard">
				<div class="blt-hc-score <?php echo $blt_secure_mw_clean ? 'blt-hc-score-good' : 'blt-hc-score-bad'; ?>">
					<span class="blt-hc-score-num"><?php echo $blt_secure_mw_clean ? '✓' : esc_html( $blt_secure_mw_count ); ?></span>
					<span class="blt-hc-score-label"><?php echo $blt_secure_mw_clean ? esc_html__( 'Clean', 'blt-secure' ) : esc_html__( 'Findings', 'blt-secure' ); ?></span>
				</div>
				<ul class="blt-hc-tallies">
					<li><strong><?php echo esc_html( isset( $blt_secure_mw['scanned'] ) ? (int) $blt_secure_mw['scanned'] : 0 ); ?></strong> <?php esc_html_e( 'Files scanned', 'blt-secure' ); ?></li>
				</ul>
			</div>
			<p class="blt-hc-meta">
				<?php
				printf(
					/* translators: %s: human-readable time difference */
					esc_html__( 'Last scanned %s ago.', 'blt-secure' ),
					esc_html( human_time_diff( (int) $blt_secure_mw['time'], time() ) )
				);
				?>
			</p>
		<?php elseif ( $blt_secure_mw && ! empty( $blt_secure_mw['error'] ) ) : ?>
			<div class="notice notice-warning inline"><p><?php echo esc_html( $blt_secure_mw['error'] ); ?></p></div>
		<?php else : ?>
			<div class="blt-hc-scoreboard blt-hc-empty">
				<p><?php esc_html_e( 'No malware scan has run yet. Run a scan to check wp-content.', 'blt-secure' ); ?></p>
			</div>
		<?php endif; ?>

		<p>
			<button type="button" class="button button-primary" id="blt-mw-run"><?php esc_html_e( 'Scan for malware now', 'blt-secure' ); ?></button>
			<span id="blt-mw-status" class="blt-card-message"></span>
		</p>

		<?php if ( ! empty( $blt_secure_mw_active ) ) : ?>
			<ul class="blt-hc-list">
				<?php foreach ( $blt_secure_mw_active as $blt_secure_find ) : ?>
					<?php
					$blt_secure_sev  = isset( $blt_secure_find['severity'] ) ? $blt_secure_find['severity'] : 'medium';
					$blt_secure_cls  = isset( $blt_secure_sev_class[ $blt_secure_sev ] ) ? $blt_secure_sev_class[ $blt_secure_sev ] : 'blt-hc-warn';
					$blt_secure_ln   = isset( $blt_secure_find['line'] ) ? (int) $blt_secure_find['line'] : 0;
					$blt_secure_path = isset( $blt_secure_find['path'] ) ? $blt_secure_find['path'] : '';
					$blt_secure_desc = isset( $blt_secure_find['description'] ) ? $blt_secure_find['description'] : '';
					?>
					<li class="blt-hc-item <?php echo esc_attr( $blt_secure_cls ); ?>">
						<span class="blt-hc-icon" aria-hidden="true">!</span>
						<span class="blt-hc-body">
							<span class="blt-hc-title"><code><?php echo esc_html( $blt_secure_path ); ?></code>
								<?php if ( $blt_secure_ln > 0 ) : ?>
									<?php
									printf(
										/* translators: %d: line number */
										' <span class="blt-hc-details">' . esc_html__( 'line %d', 'blt-secure' ) . '</span>',
										(int) $blt_secure_ln
									);
									?>
								<?php endif; ?>
							</span>
							<span class="blt-hc-msg">
								<strong><?php echo esc_html( ucfirst( $blt_secure_sev ) ); ?>:</strong>
								<?php echo esc_html( $blt_secure_desc ); ?>
							</span>
							<?php if ( ! empty( $blt_secure_find['snippet'] ) ) : ?>
								<span class="blt-hc-details"><code><?php echo esc_html( $blt_secure_find['snippet'] ); ?></code></span>
							<?php endif; ?>
						</span>
						<?php blt_secure_ignore_button( 'malware', isset( $blt_secure_find['fingerprint'] ) ? $blt_secure_find['fingerprint'] : '', $blt_secure_path . ' — ' . $blt_secure_desc ); ?>
					</li>
				<?php endforeach; ?>
			</ul>
			<?php if ( ! empty( $blt_secure_mw['truncated'] ) ) : ?>
				<p class="description"><?php esc_html_e( 'The findings list was truncated — clean these up and re-scan to see the rest.', 'blt-secure' ); ?></p>
			<?php endif; ?>
		<?php elseif ( $blt_secure_mw && empty( $blt_secure_mw['error'] ) ) : ?>
			<div class="notice notice-success inline"><p><?php esc_html_e( 'No files in wp-content matched the malware signatures.', 'blt-secure' ); ?></p></div>
		<?php endif; ?>

		<?php
		if ( ! empty( $blt_secure_mw_ignored ) ) {
			$blt_secure_items = array();
			foreach ( $blt_secure_mw_ignored as $blt_secure_find ) {
				$blt_secure_items[] = array(
					'title'       => isset( $blt_secure_find['path'] ) ? $blt_secure_find['path'] : '',
					'meta'        => isset( $blt_secure_find['description'] ) ? $blt_secure_find['description'] : '',
					'fingerprint' => isset( $blt_secure_find['fingerprint'] ) ? $blt_secure_find['fingerprint'] : '',
				);
			}
			blt_secure_ignored_details( $blt_secure_items );
		}
		?>

	<?php endif; ?>

	<hr style="margin:32px 0;" />

	<h2 class="blt-hc-cat"><?php esc_html_e( 'Plugin & theme integrity', 'blt-secure' ); ?></h2>
	<p class="description">
		<?php esc_html_e( 'Records a hash baseline of each installed plugin and theme and flags files that change without a version update — a sign of tampering. A normal update re-baselines automatically. Runs automatically once a week.', 'blt-secure' ); ?>
	</p>

	<?php if ( null === $baseline ) : ?>
		<div class="notice notice-warning inline"><p><?php esc_html_e( 'The baseline monitor is disabled.', 'blt-secure' ); ?></p></div>
	<?php else : ?>
		<?php
		$blt_secure_bl          = $baseline->latest();
		$blt_secure_bl_findings = ( $blt_secure_bl && ! empty( $blt_secure_bl['findings'] ) ) ? $blt_secure_bl['findings'] : array();
		$blt_secure_bl_active   = $whitelist->active( $blt_secure_bl_findings );
		$blt_secure_bl_ignored  = $whitelist->ignored( $blt_secure_bl_findings );
		?>

		<?php if ( $blt_secure_bl ) : ?>
			<?php
			$blt_secure_bl_count = count( $blt_secure_bl_active );
			$blt_secure_bl_clean = ( 0 === $blt_secure_bl_count );
			?>
			<div class="blt-hc-scoreboard">
				<div class="blt-hc-score <?php echo $blt_secure_bl_clean ? 'blt-hc-score-good' : 'blt-hc-score-bad'; ?>">
					<span class="blt-hc-score-num"><?php echo $blt_secure_bl_clean ? '✓' : esc_html( $blt_secure_bl_count ); ?></span>
					<span class="blt-hc-score-label"><?php echo $blt_secure_bl_clean ? esc_html__( 'Unchanged', 'blt-secure' ) : esc_html__( 'Changed', 'blt-secure' ); ?></span>
				</div>
				<ul class="blt-hc-tallies">
					<li><strong><?php echo esc_html( isset( $blt_secure_bl['targets'] ) ? (int) $blt_secure_bl['targets'] : 0 ); ?></strong> <?php esc_html_e( 'Extensions tracked', 'blt-secure' ); ?></li>
				</ul>
			</div>
			<p class="blt-hc-meta">
				<?php
				printf(
					/* translators: %s: human-readable time difference */
					esc_html__( 'Last checked %s ago.', 'blt-secure' ),
					esc_html( human_time_diff( (int) $blt_secure_bl['time'], time() ) )
				);
				?>
			</p>
		<?php else : ?>
			<div class="blt-hc-scoreboard blt-hc-empty">
				<p><?php esc_html_e( 'No baseline check has run yet. The first run records the baseline.', 'blt-secure' ); ?></p>
			</div>
		<?php endif; ?>

		<p>
			<button type="button" class="button button-primary" id="blt-bl-run"><?php esc_html_e( 'Check integrity now', 'blt-secure' ); ?></button>
			<span id="blt-bl-status" class="blt-card-message"></span>
		</p>

		<?php if ( ! empty( $blt_secure_bl_active ) ) : ?>
			<ul class="blt-hc-list">
				<?php foreach ( $blt_secure_bl_active as $blt_secure_bf ) : ?>
					<?php $blt_secure_bf_label = isset( $blt_secure_bf['label'] ) ? $blt_secure_bf['label'] : $blt_secure_bf['key']; ?>
					<li class="blt-hc-item blt-hc-fail">
						<span class="blt-hc-icon" aria-hidden="true">!</span>
						<span class="blt-hc-body">
							<span class="blt-hc-title"><?php echo esc_html( $blt_secure_bf_label ); ?></span>
							<span class="blt-hc-msg">
								<?php
								printf(
									/* translators: 1: modified count, 2: added count, 3: removed count */
									esc_html__( '%1$d modified, %2$d added, %3$d removed at the same version', 'blt-secure' ),
									(int) $blt_secure_bf['modified'],
									(int) $blt_secure_bf['added'],
									(int) $blt_secure_bf['removed']
								);
								?>
							</span>
							<?php if ( ! empty( $blt_secure_bf['files'] ) ) : ?>
								<span class="blt-hc-details"><code><?php echo esc_html( implode( ', ', $blt_secure_bf['files'] ) ); ?></code></span>
							<?php endif; ?>
						</span>
						<?php blt_secure_ignore_button( 'baseline', isset( $blt_secure_bf['fingerprint'] ) ? $blt_secure_bf['fingerprint'] : '', $blt_secure_bf_label ); ?>
					</li>
				<?php endforeach; ?>
			</ul>
		<?php elseif ( $blt_secure_bl ) : ?>
			<div class="notice notice-success inline"><p><?php esc_html_e( 'Every tracked plugin and theme matches its baseline.', 'blt-secure' ); ?></p></div>
		<?php endif; ?>

		<?php
		if ( ! empty( $blt_secure_bl_ignored ) ) {
			$blt_secure_items = array();
			foreach ( $blt_secure_bl_ignored as $blt_secure_bf ) {
				$blt_secure_items[] = array(
					'title'       => isset( $blt_secure_bf['label'] ) ? $blt_secure_bf['label'] : ( isset( $blt_secure_bf['key'] ) ? $blt_secure_bf['key'] : '' ),
					'meta'        => __( 'Changed without a version update', 'blt-secure' ),
					'fingerprint' => isset( $blt_secure_bf['fingerprint'] ) ? $blt_secure_bf['fingerprint'] : '',
				);
			}
			blt_secure_ignored_details( $blt_secure_items );
		}
		?>

	<?php endif; ?>
</div>
