<?php
/**
 * Scanner tab: core file integrity results.
 *
 * @var Blt_Secure_Scanner|null $scanner Scanner module (null if disabled).
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$blt_secure_scan = $scanner ? $scanner->latest() : null;

$blt_secure_status_meta = array(
	Blt_Secure_Core_Scanner::STATUS_MODIFIED => array( 'blt-hc-fail', __( 'Modified', 'blt-secure' ) ),
	Blt_Secure_Core_Scanner::STATUS_MISSING  => array( 'blt-hc-warn', __( 'Missing', 'blt-secure' ) ),
	Blt_Secure_Core_Scanner::STATUS_UNKNOWN  => array( 'blt-hc-fail', __( 'Unexpected', 'blt-secure' ) ),
);
?>
<div class="blt-hc">
	<p class="description">
		<?php esc_html_e( 'Verifies your WordPress core files against the official md5 checksums published by WordPress.org. Modified, missing, or unexpected files in wp-admin and wp-includes can indicate a compromise. Runs automatically once a day.', 'blt-secure' ); ?>
	</p>

	<?php if ( null === $scanner ) : ?>
		<div class="notice notice-warning inline"><p><?php esc_html_e( 'The Scanner module is disabled.', 'blt-secure' ); ?></p></div>
	<?php else : ?>

		<?php if ( $blt_secure_scan && empty( $blt_secure_scan['error'] ) ) : ?>
			<?php
			$blt_secure_issue_count = isset( $blt_secure_scan['issues'] ) ? count( $blt_secure_scan['issues'] ) : 0;
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

		<?php if ( $blt_secure_scan && empty( $blt_secure_scan['error'] ) && ! empty( $blt_secure_scan['issues'] ) ) : ?>
			<h2 class="blt-hc-cat"><?php esc_html_e( 'Flagged files', 'blt-secure' ); ?></h2>
			<ul class="blt-hc-list">
				<?php foreach ( $blt_secure_scan['issues'] as $blt_secure_issue ) : ?>
					<?php
					$blt_secure_st   = isset( $blt_secure_issue['status'] ) ? $blt_secure_issue['status'] : Blt_Secure_Core_Scanner::STATUS_MODIFIED;
					$blt_secure_meta = isset( $blt_secure_status_meta[ $blt_secure_st ] ) ? $blt_secure_status_meta[ $blt_secure_st ] : array( 'blt-hc-fail', $blt_secure_st );
					?>
					<li class="blt-hc-item <?php echo esc_attr( $blt_secure_meta[0] ); ?>">
						<span class="blt-hc-icon" aria-hidden="true"><?php echo '!'; ?></span>
						<span class="blt-hc-body">
							<span class="blt-hc-title"><code><?php echo esc_html( isset( $blt_secure_issue['path'] ) ? $blt_secure_issue['path'] : '' ); ?></code></span>
							<span class="blt-hc-msg"><?php echo esc_html( $blt_secure_meta[1] ); ?></span>
						</span>
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

	<?php endif; ?>
</div>
