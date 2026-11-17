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
		add_action( 'add_user_role', array( $this, 'on_add_user_role' ), 10, 2 );
		add_action( 'user_register', array( $this, 'on_user_register' ), 10, 1 );
		add_action( 'profile_update', array( $this, 'on_profile_update' ), 10, 2 );
		add_action( 'delete_plugin', array( $this, 'on_delete_plugin' ), 10, 1 );

		// Per-option hooks instead of the global updated_option listener: each
		// fires only for that one option (zero cost for every other write), so
		// they can run in EVERY context — front end, REST, cron, WP-CLI — which
		// is where an exploited plugin endpoint would change siteurl or the
		// default role. A listener gated on is_admin() would miss exactly that.
		foreach ( self::watched_options() as $option ) {
			add_action( 'update_option_' . $option, array( $this, 'on_watched_option' ), 10, 3 );
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
	 * Whether a role list includes a role that can change the site or its
	 * content (so a new account / credential change on it is worth an alert).
	 * Subscriber-level churn on a membership site is deliberately not logged.
	 *
	 * @param array $roles Role slugs.
	 * @return bool
	 */
	public static function is_privileged_roles( $roles ) {
		return ! empty( array_intersect( array( 'administrator', 'editor', 'shop_manager' ), (array) $roles ) );
	}

	/**
	 * Which sensitive credentials differ between a user's old and new record.
	 *
	 * @param string $old_email Old email.
	 * @param string $new_email New email.
	 * @param string $old_pass  Old password hash.
	 * @param string $new_pass  New password hash.
	 * @return string[] Subset of 'email', 'password'.
	 */
	public static function changed_credentials( $old_email, $new_email, $old_pass, $new_pass ) {
		$changed = array();
		if ( (string) $old_email !== (string) $new_email ) {
			$changed[] = 'email';
		}
		if ( (string) $old_pass !== (string) $new_pass ) {
			$changed[] = 'password';
		}
		return $changed;
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
		$this->log_admin_grant( $user_id );
	}

	/**
	 * Users already reported as granted admin during this request. set_role()
	 * fires both set_user_role and add_user_role, so without this one grant
	 * would be logged twice.
	 *
	 * @var array<int,bool>
	 */
	private $granted = array();

	/**
	 * Notify an administrator grant once per user per request.
	 *
	 * @param int $user_id Affected user.
	 * @return void
	 */
	private function log_admin_grant( $user_id ) {
		$user_id = (int) $user_id;
		if ( isset( $this->granted[ $user_id ] ) ) {
			return;
		}
		$this->granted[ $user_id ] = true;
		$user                      = get_userdata( $user_id );
		$this->alerting->notify(
			'activity_admin_granted',
			array(
				'user'  => $user ? $user->user_login : $user_id,
				'actor' => $this->actor(),
			)
		);
	}

	/**
	 * Log an administrator role ADDED as a secondary role (WP_User::add_role()
	 * fires add_user_role, not set_user_role).
	 *
	 * @param int    $user_id User id.
	 * @param string $role    Role added.
	 * @return void
	 */
	public function on_add_user_role( $user_id, $role ) {
		if ( 'administrator' !== $role ) {
			return;
		}
		$this->log_admin_grant( $user_id );
	}

	/**
	 * Log creation of an account with an elevated role.
	 *
	 * @param int $user_id New user.
	 * @return void
	 */
	public function on_user_register( $user_id ) {
		$user = get_userdata( $user_id );
		if ( ! $user || ! self::is_privileged_roles( $user->roles ) ) {
			return;
		}
		$this->alerting->notify(
			'activity_user_registered',
			array(
				'user'  => $user->user_login,
				'roles' => implode( ',', array_map( 'sanitize_key', (array) $user->roles ) ),
				'actor' => $this->actor(),
			)
		);
	}

	/**
	 * Log an email or password change on a privileged account — the account
	 * takeover step.
	 *
	 * @param int     $user_id       User id.
	 * @param WP_User $old_user_data User before the update.
	 * @return void
	 */
	public function on_profile_update( $user_id, $old_user_data = null ) {
		if ( ! is_object( $old_user_data ) ) {
			return;
		}
		$user = get_userdata( $user_id );
		if ( ! $user || ! self::is_privileged_roles( $user->roles ) ) {
			return;
		}
		$changed = self::changed_credentials(
			isset( $old_user_data->user_email ) ? $old_user_data->user_email : '',
			$user->user_email,
			isset( $old_user_data->user_pass ) ? $old_user_data->user_pass : '',
			$user->user_pass
		);
		if ( empty( $changed ) ) {
			return;
		}
		$this->alerting->notify(
			'activity_user_updated',
			array(
				'user'    => $user->user_login,
				'changed' => implode( ',', $changed ),
				'actor'   => $this->actor(),
			)
		);
	}

	/**
	 * Log a plugin being deleted from disk.
	 *
	 * @param string $plugin Plugin file.
	 * @return void
	 */
	public function on_delete_plugin( $plugin ) {
		$this->alerting->notify(
			'activity_plugin_deleted',
			array(
				'plugin' => (string) $plugin,
				'actor'  => $this->actor(),
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
	 * Per-option hook adapter (update_option_{$option} passes old, new, name).
	 *
	 * @param mixed  $old    Old value.
	 * @param mixed  $value  New value.
	 * @param string $option Option name.
	 * @return void
	 */
	public function on_watched_option( $old, $value, $option = '' ) {
		$this->on_updated_option( (string) $option, $old, $value );
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
