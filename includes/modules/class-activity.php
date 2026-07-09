<?php
/**
 * Activity monitor: logs high-signal wp-admin changes as security events.
 *
 * Records the actions attackers take once they have a foothold — creating an
 * admin, installing a plugin, switching the theme, or repointing siteurl —
 * into the shared event log (surfaced on the Advanced tab and available to
 * Phase 3 alert channels via the blt_secure_alert action). Deliberately does
 * not log routine content edits; only account, code, and critical-option
 * changes.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hooks a curated set of WordPress actions and forwards them to alerting.
 */
class Blt_Secure_Activity implements Blt_Secure_Module {

	/**
	 * Settings.
	 *
	 * @var Blt_Secure_Options
	 */
	private $options;

	/**
	 * Event sink.
	 *
	 * @var Blt_Secure_Alerting
	 */
	private $alerting;

	/**
	 * Constructor.
	 *
	 * @param Blt_Secure_Options  $options  Settings access.
	 * @param Blt_Secure_Alerting $alerting Event sink.
	 */
	public function __construct( Blt_Secure_Options $options, Blt_Secure_Alerting $alerting ) {
		$this->options  = $options;
		$this->alerting = $alerting;
	}

	/**
	 * Module id.
	 *
	 * @return string
	 */
	public function id() {
		return 'activity';
	}

	/**
	 * Defaults.
	 *
	 * @return array
	 */
	public function defaults() {
		return array( 'enabled' => true );
	}

	/**
	 * Enabled?
	 *
	 * @return bool
	 */
	public function is_enabled() {
		return (bool) $this->options->get( 'activity', 'enabled', true );
	}

	/**
	 * Sanitize section.
	 *
	 * @param array $input   Raw input.
	 * @param array $current Current values.
	 * @return array
	 */
	public function sanitize( $input, $current ) {
		return array( 'enabled' => ! empty( $input['enabled'] ) );
	}

	/**
	 * Register hooks. The high-frequency updated_option listener is admin-only
	 * so front-end transient writes never pay for it; the rest are discrete
	 * backend actions and are cheap to observe everywhere (incl. WP-CLI).
	 *
	 * @return void
	 */
	public function boot() {
		add_action( 'set_user_role', array( $this, 'on_set_user_role' ), 10, 3 );
		add_action( 'deleted_user', array( $this, 'on_deleted_user' ), 10, 1 );
		add_action( 'activated_plugin', array( $this, 'on_activated_plugin' ), 10, 1 );
		add_action( 'deactivated_plugin', array( $this, 'on_deactivated_plugin' ), 10, 1 );
		add_action( 'switch_theme', array( $this, 'on_switch_theme' ), 10, 1 );
		add_action( 'upgrader_process_complete', array( $this, 'on_upgrader_complete' ), 10, 2 );

		if ( is_admin() ) {
			add_action( 'updated_option', array( $this, 'on_updated_option' ), 10, 3 );
		}
	}

	// ---------------------------------------------------------------------
	// Pure helpers (unit-tested).
	// ---------------------------------------------------------------------

	/**
	 * Whether a role change grants administrator that the user did not have.
	 *
	 * @param string $role      New primary role.
	 * @param array  $old_roles Prior roles.
	 * @return bool
	 */
	public static function is_admin_grant( $role, $old_roles ) {
		return 'administrator' === $role && ! in_array( 'administrator', (array) $old_roles, true );
	}

	/**
	 * Options whose changes are security-relevant enough to log.
	 *
	 * @return string[]
	 */
	public static function watched_options() {
		return array( 'siteurl', 'home', 'admin_email', 'users_can_register', 'default_role', 'template', 'stylesheet' );
	}

	/**
	 * Whether an option name is on the watch list.
	 *
	 * @param string $name Option name.
	 * @return bool
	 */
	public static function is_watched_option( $name ) {
		return in_array( $name, self::watched_options(), true );
	}

	// ---------------------------------------------------------------------
	// Handlers.
	// ---------------------------------------------------------------------

	/**
	 * Actor login for attribution, or 'system' outside a user session.
	 *
	 * @return string
	 */
	private function actor() {
		if ( function_exists( 'wp_get_current_user' ) ) {
			$user = wp_get_current_user();
			if ( $user && $user->exists() ) {
				return $user->user_login;
			}
		}
		return 'system';
	}

	/**
	 * Log an administrator grant.
	 *
	 * @param int    $user_id   Affected user.
	 * @param string $role      New role.
	 * @param array  $old_roles Prior roles.
	 * @return void
	 */
	public function on_set_user_role( $user_id, $role, $old_roles ) {
		if ( ! self::is_admin_grant( $role, $old_roles ) ) {
			return;
		}
		$user = get_userdata( $user_id );
		$this->alerting->notify(
			'activity_admin_granted',
			array(
				'user'  => $user ? $user->user_login : (int) $user_id,
				'actor' => $this->actor(),
			)
		);
	}

	/**
	 * Log a user deletion.
	 *
	 * @param int $user_id Deleted user.
	 * @return void
	 */
	public function on_deleted_user( $user_id ) {
		$this->alerting->notify(
			'activity_user_deleted',
			array(
				'user_id' => (int) $user_id,
				'actor'   => $this->actor(),
			)
		);
	}

	/**
	 * Log a plugin activation.
	 *
	 * @param string $plugin Plugin file.
	 * @return void
	 */
	public function on_activated_plugin( $plugin ) {
		$this->alerting->notify(
			'activity_plugin_activated',
			array(
				'plugin' => (string) $plugin,
				'actor'  => $this->actor(),
			)
		);
	}

	/**
	 * Log a plugin deactivation.
	 *
	 * @param string $plugin Plugin file.
	 * @return void
	 */
	public function on_deactivated_plugin( $plugin ) {
		$this->alerting->notify(
			'activity_plugin_deactivated',
			array(
				'plugin' => (string) $plugin,
				'actor'  => $this->actor(),
			)
		);
	}

	/**
	 * Log a theme switch.
	 *
	 * @param string $new_name New theme name.
	 * @return void
	 */
	public function on_switch_theme( $new_name ) {
		$this->alerting->notify(
			'activity_theme_switched',
			array(
				'theme' => (string) $new_name,
				'actor' => $this->actor(),
			)
		);
	}

	/**
	 * Log a plugin/theme/core install or update.
	 *
	 * @param mixed $upgrader   Upgrader instance (unused).
	 * @param array $hook_extra Context from core.
	 * @return void
	 */
	public function on_upgrader_complete( $upgrader, $hook_extra ) {
		if ( ! is_array( $hook_extra ) || empty( $hook_extra['type'] ) ) {
			return;
		}
		$this->alerting->notify(
			'activity_' . sanitize_key( isset( $hook_extra['action'] ) ? $hook_extra['action'] : 'install' ),
			array(
				'type'  => sanitize_key( $hook_extra['type'] ),
				'items' => $this->upgrade_items( $hook_extra ),
				'actor' => $this->actor(),
			)
		);
	}

	/**
	 * Extract the affected slugs from upgrader context.
	 *
	 * @param array $hook_extra Context.
	 * @return array
	 */
	private function upgrade_items( array $hook_extra ) {
		foreach ( array( 'plugins', 'themes' ) as $key ) {
			if ( ! empty( $hook_extra[ $key ] ) && is_array( $hook_extra[ $key ] ) ) {
				return array_map( 'strval', $hook_extra[ $key ] );
			}
		}
		if ( ! empty( $hook_extra['plugin'] ) ) {
			return array( (string) $hook_extra['plugin'] );
		}
		if ( ! empty( $hook_extra['theme'] ) ) {
			return array( (string) $hook_extra['theme'] );
		}
		return array();
	}

	/**
	 * Log a change to a watched option.
	 *
	 * @param string $option Option name.
	 * @param mixed  $old    Old value.
	 * @param mixed  $value  New value.
	 * @return void
	 */
	public function on_updated_option( $option, $old, $value ) {
		if ( ! self::is_watched_option( $option ) ) {
			return;
		}
		$this->alerting->notify(
			'activity_option_changed',
			array(
				'option' => (string) $option,
				'from'   => is_scalar( $old ) ? (string) $old : '',
				'to'     => is_scalar( $value ) ? (string) $value : '',
				'actor'  => $this->actor(),
			)
		);
	}
}
