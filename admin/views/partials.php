<?php
/**
 * Shared settings-view partials: the toggle switch and setting-row helpers
 * used across the Hardening / Login / Advanced tabs so every control shares
 * one layout and one escaping path.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! function_exists( 'blt_secure_toggle' ) ) {
	/**
	 * Echo a toggle switch that wraps a real checkbox (so the Settings API
	 * still receives the field).
	 *
	 * @param string $name    Full input name attribute.
	 * @param bool   $checked Whether it is on.
	 * @param array  $args    Optional: 'value' (default '1'), 'id', 'disabled'.
	 * @return void
	 */
	function blt_secure_toggle( $name, $checked, $args = array() ) {
		$value    = isset( $args['value'] ) ? $args['value'] : '1';
		$id       = isset( $args['id'] ) ? $args['id'] : '';
		$disabled = ! empty( $args['disabled'] );

		printf(
			'<label class="blt-switch"><input type="checkbox" %1$s name="%2$s" value="%3$s" %4$s %5$s /><span class="blt-slider"></span></label>',
			$id ? 'id="' . esc_attr( $id ) . '"' : '',
			esc_attr( $name ),
			esc_attr( $value ),
			checked( (bool) $checked, true, false ),
			disabled( $disabled, true, false )
		);
	}
}

if ( ! function_exists( 'blt_secure_setting_open' ) ) {
	/**
	 * Open a setting row and print its title + description. Caller then prints
	 * the control markup and closes with blt_secure_setting_close().
	 *
	 * @param string $title Row title.
	 * @param string $desc  Description (already-translated plain text).
	 * @return void
	 */
	function blt_secure_setting_open( $title, $desc = '' ) {
		echo '<div class="blt-setting"><div class="blt-setting-info">';
		echo '<div class="blt-setting-title">' . esc_html( $title ) . '</div>';
		if ( '' !== $desc ) {
			echo '<p class="blt-setting-desc">' . esc_html( $desc ) . '</p>';
		}
	}
}

if ( ! function_exists( 'blt_secure_setting_control' ) ) {
	/**
	 * Close the info column and open the control column.
	 *
	 * @return void
	 */
	function blt_secure_setting_control() {
		echo '</div><div class="blt-setting-control">';
	}
}

if ( ! function_exists( 'blt_secure_setting_close' ) ) {
	/**
	 * Close the control column and the row.
	 *
	 * @return void
	 */
	function blt_secure_setting_close() {
		echo '</div></div>';
	}
}
