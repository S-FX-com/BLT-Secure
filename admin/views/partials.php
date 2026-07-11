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

if ( ! function_exists( 'blt_secure_ignore_button' ) ) {
	/**
	 * Echo an "Ignore" button for a scanner finding. The JS handler reads the
	 * data attributes to whitelist the finding by fingerprint.
	 *
	 * @param string $scanner     Scanner id (core|malware|baseline).
	 * @param string $fingerprint Finding fingerprint.
	 * @param string $label       Short human label stored for the ignore list.
	 * @return void
	 */
	function blt_secure_ignore_button( $scanner, $fingerprint, $label ) {
		if ( '' === (string) $fingerprint ) {
			return;
		}
		printf(
			'<button type="button" class="button-link blt-wl-ignore" data-fp="%1$s" data-scanner="%2$s" data-label="%3$s">%4$s</button>',
			esc_attr( $fingerprint ),
			esc_attr( $scanner ),
			esc_attr( $label ),
			esc_html__( 'Ignore', 'blt-secure' )
		);
	}
}

if ( ! function_exists( 'blt_secure_ignored_details' ) ) {
	/**
	 * Echo a collapsed "Ignored findings" panel with a Restore button per item.
	 * No-op when there is nothing ignored.
	 *
	 * @param array[] $items Each: [ 'title' => string, 'meta' => string, 'fingerprint' => string, 'code' => bool ].
	 *                       'code' (default true) renders the title in a <code> tag (for file paths).
	 * @return void
	 */
	function blt_secure_ignored_details( array $items ) {
		if ( empty( $items ) ) {
			return;
		}
		$count = count( $items );
		echo '<details class="blt-wl-ignored">';
		printf(
			'<summary>%s</summary>',
			esc_html(
				sprintf(
					/* translators: %d: number of ignored findings */
					_n( '%d ignored finding', '%d ignored findings', $count, 'blt-secure' ),
					$count
				)
			)
		);
		echo '<ul class="blt-hc-list">';
		foreach ( $items as $item ) {
			$title    = isset( $item['title'] ) ? $item['title'] : '';
			$use_code = ! isset( $item['code'] ) || $item['code'];
			echo '<li class="blt-hc-item blt-wl-item">';
			echo '<span class="blt-hc-icon" aria-hidden="true">&ndash;</span>';
			echo '<span class="blt-hc-body">';
			if ( $use_code ) {
				echo '<span class="blt-hc-title"><code>' . esc_html( $title ) . '</code></span>';
			} else {
				echo '<span class="blt-hc-title">' . esc_html( $title ) . '</span>';
			}
			if ( ! empty( $item['meta'] ) ) {
				echo '<span class="blt-hc-msg">' . esc_html( $item['meta'] ) . '</span>';
			}
			echo '</span>';
			printf(
				'<button type="button" class="button-link blt-wl-restore" data-fp="%1$s">%2$s</button>',
				esc_attr( isset( $item['fingerprint'] ) ? $item['fingerprint'] : '' ),
				esc_html__( 'Restore', 'blt-secure' )
			);
			echo '</li>';
		}
		echo '</ul></details>';
	}
}
