<?php
/**
 * Trust badge (Phase 3).
 *
 * A client-facing "Protected by BLT Secure" badge exposed as the
 * `[blt_secure_badge]` shortcode. Badge-only by design: it never discloses
 * scores, findings, versions, or any other security specifics — a padlock and
 * a label, nothing an attacker could fingerprint the site from.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Registers the trust-badge shortcode.
 */
class Blt_Secure_Badge implements Blt_Secure_Module {

	const SHORTCODE = 'blt_secure_badge';

	/**
	 * Settings.
	 *
	 * @var Blt_Secure_Options
	 */
	private $options;

	/**
	 * Constructor.
	 *
	 * @param Blt_Secure_Options $options Settings access.
	 */
	public function __construct( Blt_Secure_Options $options ) {
		$this->options = $options;
	}

	/**
	 * Module id.
	 *
	 * @return string
	 */
	public function id() {
		return 'badge';
	}

	/**
	 * Defaults. Off by default; the site owner opts in and places the
	 * shortcode where they want it.
	 *
	 * @return array
	 */
	public function defaults() {
		return array(
			'enabled' => false,
		);
	}

	/**
	 * Enabled?
	 *
	 * @return bool
	 */
	public function is_enabled() {
		return (bool) $this->options->get( 'badge', 'enabled', false );
	}

	/**
	 * Register the shortcode.
	 *
	 * @return void
	 */
	public function boot() {
		add_shortcode( self::SHORTCODE, array( $this, 'shortcode' ) );
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
			'enabled' => ! empty( $input['enabled'] ),
		);
	}

	/**
	 * Shortcode callback.
	 *
	 * @param array $atts Shortcode attributes.
	 * @return string
	 */
	public function shortcode( $atts ) {
		$atts = shortcode_atts(
			array(
				'label' => __( 'Protected by BLT Secure', 'blt-secure' ),
				'style' => 'light',
			),
			$atts,
			self::SHORTCODE
		);

		return self::render( $atts['label'], $atts['style'] );
	}

	/**
	 * Build the badge markup. Self-contained (inline SVG, no external assets)
	 * and free of any security specifics.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string $label Badge text.
	 * @param string $style 'light' or 'dark'.
	 * @return string
	 */
	public static function render( $label, $style = 'light' ) {
		$label = trim( (string) $label );
		if ( '' === $label ) {
			$label = 'Protected by BLT Secure';
		}
		$dark = ( 'dark' === $style );

		$bg     = $dark ? '#1e1e2e' : '#f6f7fb';
		$fg     = $dark ? '#e6e6f0' : '#1d2327';
		$accent = '#2f6f4f';

		$shield = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" '
			. 'fill="' . esc_attr( $accent ) . '" aria-hidden="true" focusable="false">'
			. '<path d="M12 2 4 5v6c0 5 3.4 9 8 11 4.6-2 8-6 8-11V5l-8-3zm-1.2 13.2-3-3 1.4-1.4 1.6 1.6 4.2-4.2 1.4 1.4-5.6 5.6z"/>'
			. '</svg>';

		return '<span class="blt-secure-badge" role="img" aria-label="' . esc_attr( $label ) . '" '
			. 'style="display:inline-flex;align-items:center;gap:6px;padding:6px 10px;border-radius:6px;'
			. 'font:600 12px/1 -apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,sans-serif;'
			. 'background:' . esc_attr( $bg ) . ';color:' . esc_attr( $fg ) . ';border:1px solid rgba(47,111,79,.35);">'
			. $shield
			. '<span>' . esc_html( $label ) . '</span>'
			. '</span>';
	}
}
