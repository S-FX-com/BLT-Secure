<?php
/**
 * Cloudflare tab: token + deploy cards (AJAX).
 *
 * @var Blt_Secure_Options          $options  Settings.
 * @var Blt_Secure_Cloudflare_State $cf_state CF state.
 * @var Blt_Secure_Credential_Store $store    Credential store.
 * @var Blt_Secure_Admin            $admin    Controller.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$blt_secure_zone      = $cf_state->zone();
$blt_secure_has_token = is_string( $store->get( 'cf_token' ) );
$blt_secure_connected = $blt_secure_has_token && ! empty( $blt_secure_zone['zone_id'] );
?>
<div class="blt-cf">

	<h2><?php esc_html_e( 'Connection', 'blt-secure' ); ?></h2>

	<?php if ( ! $store->is_available() ) : ?>
		<div class="notice notice-error inline"><p>
			<?php esc_html_e( 'This server has no authenticated-encryption support (libsodium or OpenSSL AES-GCM). A Cloudflare token cannot be stored safely, so edge features are unavailable.', 'blt-secure' ); ?>
		</p></div>
	<?php else : ?>

		<p class="description" style="max-width:720px;">
			<?php esc_html_e( 'Create a custom API token at dash.cloudflare.com → My Profile → API Tokens with: Zone → Zone: Read, Zone → Zone WAF: Edit (scoped to this site’s zone). Add Account → Access: Apps and Policies: Edit only if you want the Cloudflare Access feature.', 'blt-secure' ); ?>
		</p>

		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="blt-cf-token"><?php esc_html_e( 'API token', 'blt-secure' ); ?></label></th>
				<td>
					<?php if ( $blt_secure_connected ) : ?>
						<p id="blt-cf-status">
							<span class="blt-badge blt-badge-ok">✓</span>
							<?php
							printf(
								/* translators: 1: zone name, 2: plan name */
								esc_html__( 'Connected to zone %1$s (%2$s plan). The token is stored encrypted.', 'blt-secure' ),
								'<strong>' . esc_html( $blt_secure_zone['zone_name'] ) . '</strong>',
								esc_html( $blt_secure_zone['plan'] ? $blt_secure_zone['plan'] : 'unknown' )
							);
							?>
						</p>
						<button type="button" class="button" id="blt-cf-disconnect"><?php esc_html_e( 'Disconnect (forget token)', 'blt-secure' ); ?></button>
					<?php else : ?>
						<input type="password" id="blt-cf-token" class="regular-text" autocomplete="off" placeholder="<?php esc_attr_e( 'Paste your zone-scoped API token', 'blt-secure' ); ?>" />
						<button type="button" class="button button-primary" id="blt-cf-connect"><?php esc_html_e( 'Verify & save', 'blt-secure' ); ?></button>
						<p id="blt-cf-status" class="description"></p>
					<?php endif; ?>
				</td>
			</tr>
		</table>

		<h2><?php esc_html_e( 'Edge protections', 'blt-secure' ); ?></h2>
		<?php if ( ! $blt_secure_connected ) : ?>
			<p class="description"><?php esc_html_e( 'Connect a token above to enable one-click deployment.', 'blt-secure' ); ?></p>
		<?php endif; ?>

		<div class="blt-cards">
			<?php
			$blt_secure_login_slug = (string) $options->get( 'login', 'slug', '' );
			foreach ( $admin->cf_cards() as $blt_secure_feature => $blt_secure_card ) :
				$blt_secure_record   = $cf_state->deployment( $blt_secure_feature );
				$blt_secure_deployed = null !== $blt_secure_record;
				$blt_secure_stale    = false;
				if ( $blt_secure_deployed && 'rate_limit' === $blt_secure_feature ) {
					$blt_secure_stale = $cf_state->is_stale( 'rate_limit', Blt_Secure_Rule_Definitions::config_hash( Blt_Secure_Rule_Definitions::rate_limit_rules( $blt_secure_login_slug ) ) );
				}
				?>
				<div class="blt-card" data-feature="<?php echo esc_attr( $blt_secure_feature ); ?>">
					<h3><?php echo esc_html( $blt_secure_card['title'] ); ?></h3>
					<p><?php echo esc_html( $blt_secure_card['desc'] ); ?></p>

					<?php if ( 'waf_managed' === $blt_secure_feature ) : ?>
						<p class="blt-waf-controls">
							<label><?php esc_html_e( 'OWASP paranoia:', 'blt-secure' ); ?>
								<select class="blt-paranoia">
									<?php for ( $blt_secure_pl = 1; $blt_secure_pl <= 4; $blt_secure_pl++ ) : ?>
										<option value="<?php echo esc_attr( $blt_secure_pl ); ?>" <?php selected( 2, $blt_secure_pl ); ?>>PL<?php echo esc_html( $blt_secure_pl ); ?></option>
									<?php endfor; ?>
								</select>
							</label>
							<label><?php esc_html_e( 'Sensitivity:', 'blt-secure' ); ?>
								<select class="blt-threshold">
									<option value="60"><?php esc_html_e( 'Low (threshold 60)', 'blt-secure' ); ?></option>
									<option value="40" selected><?php esc_html_e( 'Medium (threshold 40)', 'blt-secure' ); ?></option>
									<option value="25"><?php esc_html_e( 'High (threshold 25)', 'blt-secure' ); ?></option>
								</select>
							</label>
						</p>
					<?php endif; ?>

					<p class="blt-card-status">
						<?php if ( $blt_secure_stale ) : ?>
							<span class="blt-badge blt-badge-warn"><?php esc_html_e( 'Update available', 'blt-secure' ); ?></span>
							<em><?php esc_html_e( 'Your login slug changed since this rule was deployed — redeploy to update it.', 'blt-secure' ); ?></em>
						<?php elseif ( $blt_secure_deployed ) : ?>
							<span class="blt-badge blt-badge-ok"><?php esc_html_e( 'Deployed', 'blt-secure' ); ?></span>
							<?php if ( isset( $blt_secure_record['tier'] ) && 'free' === $blt_secure_record['tier'] ) : ?>
								<em><?php esc_html_e( 'Free plan: the limited Free Managed Ruleset was deployed (paid managed rulesets need Pro or higher).', 'blt-secure' ); ?></em>
							<?php endif; ?>
						<?php else : ?>
							<span class="blt-badge"><?php esc_html_e( 'Not deployed', 'blt-secure' ); ?></span>
						<?php endif; ?>
					</p>

					<p class="blt-card-actions">
						<button type="button" class="button button-primary blt-deploy" <?php disabled( ! $blt_secure_connected ); ?>>
							<?php echo $blt_secure_deployed ? esc_html__( 'Redeploy', 'blt-secure' ) : esc_html__( 'Deploy', 'blt-secure' ); ?>
						</button>
						<button type="button" class="button blt-remove" <?php disabled( ! $blt_secure_connected || ! $blt_secure_deployed ); ?>>
							<?php esc_html_e( 'Remove', 'blt-secure' ); ?>
						</button>
						<span class="blt-card-message description"></span>
					</p>
				</div>
			<?php endforeach; ?>
		</div>

	<?php endif; ?>
</div>
