<?php
/**
 * Settings access layer.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Wraps the single autoloaded blt_secure_settings option.
 *
 * One option row keeps per-request DB cost at a single read on shared
 * hosting. Sections map 1:1 to module ids; defaults are collected from the
 * registered modules so a missing key always resolves to something sane.
 */
class Blt_Secure_Options {

	const OPTION = 'blt_secure_settings';

	/**
	 * Cached settings array for this request.
	 *
	 * @var array|null
	 */
	private $settings = null;

	/**
	 * Section defaults, keyed by section id.
	 *
	 * @var array
	 */
	private $defaults = array();

	/**
	 * Register a section's defaults (called by the loader per module).
	 *
	 * @param string $section Section id.
	 * @param array  $defaults Default values.
	 * @return void
	 */
	public function register_defaults( $section, array $defaults ) {
		$this->defaults[ $section ] = $defaults;
	}

	/**
	 * All registered defaults.
	 *
	 * @return array
	 */
	public function get_defaults() {
		return $this->defaults;
	}

	/**
	 * Full settings array, defaults merged in.
	 *
	 * @return array
	 */
	public function all() {
		if ( null === $this->settings ) {
			$saved = get_option( self::OPTION, array() );
			if ( ! is_array( $saved ) ) {
				$saved = array();
			}
			$this->settings = $saved;
		}

		$merged = $this->settings;
		foreach ( $this->defaults as $section => $defaults ) {
			$saved_section      = isset( $merged[ $section ] ) && is_array( $merged[ $section ] ) ? $merged[ $section ] : array();
			$merged[ $section ] = array_merge( $defaults, $saved_section );
		}

		return $merged;
	}

	/**
	 * Read one value.
	 *
	 * @param string $section Section id.
	 * @param string $key Key within the section.
	 * @param mixed  $fallback Value when neither saved nor defaulted.
	 * @return mixed
	 */
	public function get( $section, $key, $fallback = null ) {
		$all = $this->all();
		if ( isset( $all[ $section ] ) && array_key_exists( $key, $all[ $section ] ) ) {
			return $all[ $section ][ $key ];
		}
		return $fallback;
	}

	/**
	 * Read a whole section.
	 *
	 * @param string $section Section id.
	 * @return array
	 */
	public function section( $section ) {
		$all = $this->all();
		return isset( $all[ $section ] ) && is_array( $all[ $section ] ) ? $all[ $section ] : array();
	}

	/**
	 * Persist one section (merging into the stored array, not replacing it —
	 * saving one settings tab must never wipe another).
	 *
	 * @param string $section Section id.
	 * @param array  $values Sanitized values.
	 * @return void
	 */
	public function update_section( $section, array $values ) {
		$saved = get_option( self::OPTION, array() );
		if ( ! is_array( $saved ) ) {
			$saved = array();
		}
		$saved[ $section ]        = $values;
		$saved['schema_version']  = 1;
		update_option( self::OPTION, $saved );
		$this->settings = $saved;
	}
}
