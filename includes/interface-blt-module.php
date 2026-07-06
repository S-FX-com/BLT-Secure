<?php
/**
 * Module contract.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * A BLT Secure feature module.
 *
 * Modules are instantiated on every request but only boot() (i.e. register
 * hooks) when enabled, so construction must stay trivial.
 */
interface Blt_Secure_Module {

	/**
	 * Unique module id — doubles as the settings section key.
	 *
	 * @return string
	 */
	public function id();

	/**
	 * Default settings for this module's section.
	 *
	 * @return array
	 */
	public function defaults();

	/**
	 * Whether the module should register its hooks for this request.
	 *
	 * @return bool
	 */
	public function is_enabled();

	/**
	 * Register hooks. Called on plugins_loaded (priority 1) when enabled.
	 *
	 * @return void
	 */
	public function boot();

	/**
	 * Sanitize this module's settings section on save.
	 *
	 * @param array $input Raw section input.
	 * @param array $current Current (saved) section values.
	 * @return array Sanitized section.
	 */
	public function sanitize( $input, $current );
}
