<?php
/**
 * Timeline tab: unified local + Cloudflare-edge security events.
 *
 * @var Blt_Secure_Timeline|null $timeline Timeline module (null if disabled).
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$blt_secure_status = $timeline ? $timeline->latest() : null;
$blt_secure_rows   = $timeline ? $timeline->timeline( 100 ) : array();
?>
<div class="blt-hc">
	<p class="description">
		<?php esc_html_e( 'A single chronological view of security events — actions blocked or challenged at the Cloudflare edge, merged with events recorded on this site. Cloudflare events are polled hourly.', 'blt-secure' ); ?>
	</p>

	<?php if ( null === $timeline ) : ?>
		<div class="notice notice-warning inline"><p><?php esc_html_e( 'The Timeline module is disabled.', 'blt-secure' ); ?></p></div>
	<?php else : ?>

		<?php
		$blt_secure_tl_status = is_array( $blt_secure_status ) && isset( $blt_secure_status['status'] ) ? $blt_secure_status['status'] : '';
		$blt_secure_tl_note   = '';
		switch ( $blt_secure_tl_status ) {
			case 'ok':
				$blt_secure_tl_note = sprintf(
					/* translators: %s: human time diff */
					__( 'Cloudflare events last polled %s ago.', 'blt-secure' ),
					human_time_diff( (int) $blt_secure_status['time'], time() )
				);
				break;
			case 'no_token':
				$blt_secure_tl_note = __( 'Connect a Cloudflare token on the Cloudflare tab to include edge events.', 'blt-secure' );
				break;
			case 'no_zone':
				$blt_secure_tl_note = __( 'Cloudflare is not connected to a zone yet.', 'blt-secure' );
				break;
			case 'error':
				$blt_secure_tl_note = isset( $blt_secure_status['error'] ) ? $blt_secure_status['error'] : __( 'The last Cloudflare poll failed.', 'blt-secure' );
				break;
			default:
				$blt_secure_tl_note = __( 'Cloudflare events have not been polled yet.', 'blt-secure' );
		}
		?>
		<p class="blt-hc-meta"><?php echo esc_html( $blt_secure_tl_note ); ?></p>

		<p>
			<button type="button" class="button" id="blt-tl-run"><?php esc_html_e( 'Refresh from Cloudflare', 'blt-secure' ); ?></button>
			<span id="blt-tl-status" class="blt-card-message"></span>
		</p>

		<?php if ( empty( $blt_secure_rows ) ) : ?>
			<p class="description"><?php esc_html_e( 'No events yet.', 'blt-secure' ); ?></p>
		<?php else : ?>
			<table class="widefat striped" style="max-width:1000px;">
				<thead>
					<tr>
						<th style="width:150px;"><?php esc_html_e( 'When', 'blt-secure' ); ?></th>
						<th style="width:80px;"><?php esc_html_e( 'Source', 'blt-secure' ); ?></th>
						<th><?php esc_html_e( 'Event', 'blt-secure' ); ?></th>
						<th><?php esc_html_e( 'Detail', 'blt-secure' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $blt_secure_rows as $blt_secure_row ) : ?>
						<?php
						$blt_secure_is_cf = isset( $blt_secure_row['source'] ) && 'cloudflare' === $blt_secure_row['source'];
						$blt_secure_when  = isset( $blt_secure_row['time'] ) && $blt_secure_row['time'] ? wp_date( 'Y-m-d H:i', (int) $blt_secure_row['time'] ) : '—';

						if ( $blt_secure_is_cf ) {
							$blt_secure_event  = isset( $blt_secure_row['action'] ) ? $blt_secure_row['action'] : '';
							$blt_secure_detail = trim(
								( isset( $blt_secure_row['ip'] ) ? $blt_secure_row['ip'] : '' )
								. ( ! empty( $blt_secure_row['country'] ) ? ' (' . $blt_secure_row['country'] . ')' : '' )
								. ( ! empty( $blt_secure_row['path'] ) ? ' → ' . $blt_secure_row['path'] : '' )
								. ( ! empty( $blt_secure_row['rule'] ) ? ' [' . $blt_secure_row['rule'] . ']' : '' )
							);
						} else {
							$blt_secure_event  = isset( $blt_secure_row['action'] ) ? $blt_secure_row['action'] : '';
							$blt_secure_detail = isset( $blt_secure_row['context'] ) ? wp_json_encode( $blt_secure_row['context'] ) : '';
						}
						?>
						<tr>
							<td><?php echo esc_html( $blt_secure_when ); ?></td>
							<td>
								<span class="blt-badge <?php echo $blt_secure_is_cf ? 'blt-badge-ok' : ''; ?>">
									<?php echo $blt_secure_is_cf ? esc_html__( 'Edge', 'blt-secure' ) : esc_html__( 'Site', 'blt-secure' ); ?>
								</span>
							</td>
							<td><code><?php echo esc_html( $blt_secure_event ); ?></code></td>
							<td><span class="blt-hc-details"><?php echo esc_html( $blt_secure_detail ); ?></span></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>

	<?php endif; ?>
</div>
