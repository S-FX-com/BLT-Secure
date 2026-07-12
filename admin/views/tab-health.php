<?php
/**
 * Health Check tab: security self-assessment with a score and grouped results.
 *
 * @var Blt_Secure_Health|null $health Health module (null if disabled).
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$blt_secure_payload = $health ? $health->latest() : null;
$blt_secure_cats    = Blt_Secure_Health_Checks::categories();

$blt_secure_status_meta = array(
	Blt_Secure_Health_Result::PASS => array( 'blt-hc-pass', '✓' ),
	Blt_Secure_Health_Result::WARN => array( 'blt-hc-warn', '!' ),
	Blt_Secure_Health_Result::FAIL => array( 'blt-hc-fail', '✕' ),
	Blt_Secure_Health_Result::SKIP => array( 'blt-hc-skip', '–' ),
);
?>
<div class="blt-hc">
	<p class="description">
		<?php esc_html_e( 'Run a comprehensive check of this site’s security configuration. Checks also run automatically once a day; the results below are the most recent scan.', 'blt-secure' ); ?>
	</p>

	<?php if ( null === $health ) : ?>
		<div class="notice notice-warning inline"><p><?php esc_html_e( 'The Health Check module is disabled.', 'blt-secure' ); ?></p></div>
	<?php else : ?>

		<?php if ( $blt_secure_payload && isset( $blt_secure_payload['summary'] ) ) : ?>
			<?php
			$blt_secure_summary = $blt_secure_payload['summary'];
			$blt_secure_score   = isset( $blt_secure_summary['score'] ) ? (int) $blt_secure_summary['score'] : 0;
			$blt_secure_grade   = $blt_secure_score >= 80 ? 'good' : ( $blt_secure_score >= 50 ? 'ok' : 'bad' );
			?>
			<div class="blt-hc-scoreboard">
				<div class="blt-hc-score blt-hc-score-<?php echo esc_attr( $blt_secure_grade ); ?>">
					<span class="blt-hc-score-num"><?php echo esc_html( $blt_secure_score ); ?>%</span>
					<span class="blt-hc-score-label"><?php esc_html_e( 'Security score', 'blt-secure' ); ?></span>
				</div>
				<ul class="blt-hc-tallies">
					<?php
					$blt_secure_tallies = array(
						Blt_Secure_Health_Result::PASS => __( 'Passed', 'blt-secure' ),
						Blt_Secure_Health_Result::WARN => __( 'Warnings', 'blt-secure' ),
						Blt_Secure_Health_Result::FAIL => __( 'Failed', 'blt-secure' ),
						Blt_Secure_Health_Result::SKIP => __( 'Skipped', 'blt-secure' ),
					);
					foreach ( $blt_secure_tallies as $blt_secure_tk => $blt_secure_tlabel ) :
						$blt_secure_meta = $blt_secure_status_meta[ $blt_secure_tk ];
						?>
						<li class="<?php echo esc_attr( $blt_secure_meta[0] ); ?> blt-hc-filter" data-filter="<?php echo esc_attr( $blt_secure_tk ); ?>" role="button" tabindex="0" aria-pressed="false" title="<?php esc_attr_e( 'Click to show only these; click again to show all.', 'blt-secure' ); ?>">
							<strong><?php echo esc_html( (int) $blt_secure_summary[ $blt_secure_tk ] ); ?></strong> <?php echo esc_html( $blt_secure_tlabel ); ?>
						</li>
					<?php endforeach; ?>
				</ul>
			</div>
			<p class="blt-hc-meta">
				<?php
				printf(
					/* translators: %s: human-readable time difference */
					esc_html__( 'Last scanned %s ago.', 'blt-secure' ),
					esc_html( human_time_diff( (int) $blt_secure_payload['time'], time() ) )
				);
				?>
			</p>
		<?php else : ?>
			<div class="blt-hc-scoreboard blt-hc-empty">
				<p><?php esc_html_e( 'No scan has run yet. Run the checks to see your security score.', 'blt-secure' ); ?></p>
			</div>
		<?php endif; ?>

		<p>
			<button type="button" class="button button-primary" id="blt-hc-run"><?php esc_html_e( 'Run checks now', 'blt-secure' ); ?></button>
			<span id="blt-hc-status" class="blt-card-message"></span>
		</p>

		<?php if ( $blt_secure_payload && ! empty( $blt_secure_payload['results'] ) ) : ?>
			<?php
			// Group results by category, preserving the catalogue's category order.
			$blt_secure_grouped = array();
			foreach ( $blt_secure_payload['results'] as $blt_secure_row ) {
				$blt_secure_key                          = isset( $blt_secure_row['category'] ) ? $blt_secure_row['category'] : 'core';
				$blt_secure_grouped[ $blt_secure_key ][] = $blt_secure_row;
			}
			?>
			<?php foreach ( $blt_secure_cats as $blt_secure_cat_key => $blt_secure_cat_label ) : ?>
				<?php if ( empty( $blt_secure_grouped[ $blt_secure_cat_key ] ) ) : ?>
					<?php continue; ?>
				<?php endif; ?>
				<h2 class="blt-hc-cat"><?php echo esc_html( $blt_secure_cat_label ); ?></h2>
				<ul class="blt-hc-list">
					<?php foreach ( $blt_secure_grouped[ $blt_secure_cat_key ] as $blt_secure_row ) : ?>
						<?php
						$blt_secure_st   = isset( $blt_secure_row['status'] ) ? $blt_secure_row['status'] : Blt_Secure_Health_Result::SKIP;
						$blt_secure_meta = isset( $blt_secure_status_meta[ $blt_secure_st ] ) ? $blt_secure_status_meta[ $blt_secure_st ] : $blt_secure_status_meta[ Blt_Secure_Health_Result::SKIP ];
						$blt_secure_cid  = isset( $blt_secure_row['id'] ) ? $blt_secure_row['id'] : '';
						$blt_secure_can  = in_array( $blt_secure_st, array( Blt_Secure_Health_Result::WARN, Blt_Secure_Health_Result::FAIL ), true )
							&& Blt_Secure_Health_Fixes::is_fixable( $blt_secure_cid );
						?>
						<li class="blt-hc-item <?php echo esc_attr( $blt_secure_meta[0] ); ?>" data-status="<?php echo esc_attr( $blt_secure_st ); ?>">
							<span class="blt-hc-icon" aria-hidden="true"><?php echo esc_html( $blt_secure_meta[1] ); ?></span>
							<span class="blt-hc-body">
								<span class="blt-hc-title"><?php echo esc_html( isset( $blt_secure_row['label'] ) ? $blt_secure_row['label'] : '' ); ?></span>
								<span class="blt-hc-msg"><?php echo esc_html( isset( $blt_secure_row['message'] ) ? $blt_secure_row['message'] : '' ); ?></span>
								<?php if ( ! empty( $blt_secure_row['details'] ) ) : ?>
									<span class="blt-hc-details"><?php echo esc_html( $blt_secure_row['details'] ); ?></span>
								<?php endif; ?>
							</span>
							<?php if ( $blt_secure_can ) : ?>
								<button type="button" class="button blt-hc-fix" data-check="<?php echo esc_attr( $blt_secure_cid ); ?>">
									<?php echo esc_html( Blt_Secure_Health_Fixes::label( $blt_secure_cid ) ); ?>
								</button>
							<?php endif; ?>
						</li>
					<?php endforeach; ?>
				</ul>
			<?php endforeach; ?>
			<p class="blt-hc-noresults" hidden><?php esc_html_e( 'No checks match this filter.', 'blt-secure' ); ?></p>
		<?php endif; ?>

	<?php endif; ?>
</div>
