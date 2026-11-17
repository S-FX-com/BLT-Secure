<?php
/**
 * File guard: editor lockdown + file-manager plugin blocker.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Two protections:
 *
 * 1. Disables the wp-admin theme/plugin file editors via the
 *    file_mod_allowed filter when DISALLOW_FILE_EDIT isn't already set.
 * 2. Blocks installation/activation of file-manager plugins (the recurring
 *    compromise vector across the client fleet) — formalizing the old
 *    mu-plugin blocker as a built-in module with a filterable slug list.
 */
class Blt_Secure_File_Guard implements Blt_Secure_Module {

	/**
	 * Settings.
	 *
	 * @var Blt_Secure_Options
	 */
	private $options;

	/**
	 * Alerting.
	 *
	 * @var Blt_Secure_Alerting
	 */
	private $alerting;

	/**
	 * Constructor.
	 *
	 * @param Blt_Secure_Options  $options Settings access.
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
		return 'fileguard';
	}

	/**
	 * Defaults.
	 *
	 * @return array
	 */
	public function defaults() {
		return array(
			'disallow_file_edit'  => true,
			'block_file_managers' => true,
		);
	}

	/**
	 * Enabled when either protection is on.
	 *
	 * @return bool
	 */
	public function is_enabled() {
		return $this->options->get( 'fileguard', 'disallow_file_edit', true )
			|| $this->options->get( 'fileguard', 'block_file_managers', true );
	}

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function boot() {
		if ( $this->options->get( 'fileguard', 'disallow_file_edit', true ) && ! ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) ) {
			add_filter( 'file_mod_allowed', array( $this, 'block_file_edit' ), 10, 2 );
		}

		if ( $this->options->get( 'fileguard', 'block_file_managers', true ) ) {
			add_filter( 'upgrader_pre_install', array( $this, 'block_install' ), 10, 2 );
			// Fresh installs carry no slug in hook_extra, so also check the unpacked directory name.
			add_filter( 'upgrader_source_selection', array( $this, 'block_source' ), 10, 4 );
			add_action( 'activate_plugin', array( $this, 'block_activation' ), 10, 1 );
			add_filter( 'plugin_action_links', array( $this, 'strip_activate_link' ), 10, 2 );
			add_action( 'admin_init', array( $this, 'deactivate_blocked' ) );
		}
	}

	/**
	 * Sanitize section.
	 *
	 * @param array $input Raw input.
	 * @param array $current Current values.
	 * @return array
	 */
	public function sanitize( $input, $current ) {
		return array(
			'disallow_file_edit'  => ! empty( $input['disallow_file_edit'] ),
			'block_file_managers' => ! empty( $input['block_file_managers'] ),
		);
	}

	/**
	 * Default blocked slugs, filterable for fleet-specific additions.
	 *
	 * @return string[]
	 */
	public function blocked_slugs() {
		$slugs = array(
			'wp-file-manager',
			'wp-file-manager-pro',
			'filester',
			'file-manager-advanced',
			'bit-file-manager',
			'advanced-file-manager',
			'wp-filebrowser',
			'file-manager',
		);

		/**
		 * Filter the list of blocked plugin slugs.
		 *
		 * @param string[] $slugs Plugin slugs (directory names).
		 */
		return apply_filters( 'blt_secure_blocked_plugins', $slugs );
	}

	/**
	 * Whether a plugin directory name is on the blocked list. Tolerates the
	 * casual renames that would otherwise defeat an exact match: case, a
	 * trailing version / copy suffix ("wp-file-manager-6.9", "-1") and ".zip".
	 * Pure given the list (unit-tested).
	 *
	 * @param string   $slug    Directory name.
	 * @param string[] $blocked Blocked slugs.
	 * @return bool
	 */
	public static function slug_matches( $slug, array $blocked ) {
		$slug = strtolower( trim( (string) $slug ) );
		$slug = (string) preg_replace( '/\.zip$/', '', $slug );
		if ( '' === $slug || '.' === $slug ) {
			return false;
		}
		$base = (string) preg_replace( '/[-_.]v?\d+(?:\.\d+)*$/', '', $slug );

		foreach ( $blocked as $candidate ) {
			$candidate = strtolower( (string) $candidate );
			if ( $slug === $candidate || $base === $candidate ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Convenience: is this slug blocked right now?
	 *
	 * @param string $slug Directory name.
	 * @return bool
	 */
	private function is_blocked( $slug ) {
		return self::slug_matches( $slug, $this->blocked_slugs() );
	}

	/**
	 * Refuse a plugin whose unpacked directory is a blocked slug. This is the
	 * check that actually stops fresh installs: Plugin_Upgrader::install()
	 * passes only type/action in hook_extra, so upgrader_pre_install cannot
	 * tell which plugin is arriving.
	 *
	 * @param string|WP_Error $source        Unpacked source directory.
	 * @param string          $remote_source Remote source.
	 * @param object          $upgrader      Upgrader instance.
	 * @param array           $hook_extra    Install context.
	 * @return string|WP_Error
	 */
	public function block_source( $source, $remote_source = '', $upgrader = null, $hook_extra = array() ) {
		if ( is_wp_error( $source ) || ! is_string( $source ) ) {
			return $source;
		}
		if ( is_array( $hook_extra ) && isset( $hook_extra['type'] ) && 'plugin' !== $hook_extra['type'] ) {
			return $source;
		}

		$slug = basename( untrailingslashit( $source ) );
		if ( $this->is_blocked( $slug ) ) {
			$this->alerting->notify(
				'blocked_plugin_install',
				array(
					'slug' => $slug,
					'user' => get_current_user_id(),
				)
			);
			return new WP_Error(
				'blt_secure_blocked_plugin',
				__( 'BLT Secure blocks file-manager plugins: they are a common compromise vector. Contact your site administrator if you need file access.', 'blt-secure' )
			);
		}

		return $source;
	}

	/**
	 * Refuse to activate a blocked plugin that is already on disk.
	 *
	 * @param string $plugin Plugin basename (dir/file.php).
	 * @return void
	 */
	public function block_activation( $plugin ) {
		if ( $this->is_blocked( dirname( (string) $plugin ) ) ) {
			$this->alerting->notify(
				'blocked_plugin_install',
				array(
					'slug' => dirname( (string) $plugin ),
					'user' => get_current_user_id(),
				)
			);
			wp_die(
				esc_html__( 'BLT Secure blocks file-manager plugins: they are a common compromise vector. Contact your site administrator if you need file access.', 'blt-secure' ),
				'',
				array( 'back_link' => true )
			);
		}
	}

	/**
	 * Kill the theme/plugin editors (same effect as DISALLOW_FILE_EDIT).
	 *
	 * @param bool   $allowed Whether file mods are allowed.
	 * @param string $context Capability context.
	 * @return bool
	 */
	public function block_file_edit( $allowed, $context ) {
		if ( 'capability_edit_themes' === $context ) {
			return false;
		}
		return $allowed;
	}

	/**
	 * Refuse installation of blocked plugins.
	 *
	 * @param bool|WP_Error $response Pre-install response.
	 * @param array         $hook_extra Install context.
	 * @return bool|WP_Error
	 */
	public function block_install( $response, $hook_extra ) {
		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$slug = '';
		if ( ! empty( $hook_extra['plugin'] ) ) {
			$slug = dirname( plugin_basename( $hook_extra['plugin'] ) );
		} elseif ( ! empty( $hook_extra['slug'] ) ) {
			$slug = $hook_extra['slug'];
		}

		if ( $slug && $this->is_blocked( $slug ) ) {
			$this->alerting->notify(
				'blocked_plugin_install',
				array(
					'slug' => $slug,
					'user' => get_current_user_id(),
				)
			);
			return new WP_Error(
				'blt_secure_blocked_plugin',
				__( 'BLT Secure blocks file-manager plugins: they are a common compromise vector. Contact your site administrator if you need file access.', 'blt-secure' )
			);
		}

		return $response;
	}

	/**
	 * Remove the Activate link for blocked plugins in the list table.
	 *
	 * @param array  $actions Action links.
	 * @param string $plugin_file Plugin basename.
	 * @return array
	 */
	public function strip_activate_link( $actions, $plugin_file ) {
		$slug = dirname( $plugin_file );
		if ( $this->is_blocked( $slug ) ) {
			unset( $actions['activate'] );
			$actions['blt_secure_blocked'] = '<span style="color:#b32d2e;">' . esc_html__( 'Blocked by BLT Secure', 'blt-secure' ) . '</span>';
		}
		return $actions;
	}

	/**
	 * If a blocked plugin is somehow active, deactivate it and say so.
	 *
	 * @return void
	 */
	public function deactivate_blocked() {
		if ( ! current_user_can( 'activate_plugins' ) ) {
			return;
		}

		$deactivated = array();
		foreach ( (array) get_option( 'active_plugins', array() ) as $plugin_file ) {
			$slug = dirname( $plugin_file );
			if ( $this->is_blocked( $slug ) ) {
				deactivate_plugins( $plugin_file );
				$deactivated[] = $slug;
			}
		}

		// Network-activated plugins live in a separate site option (keys = basenames).
		if ( is_multisite() && current_user_can( 'manage_network_plugins' ) ) {
			foreach ( array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) as $plugin_file ) {
				$slug = dirname( (string) $plugin_file );
				if ( $this->is_blocked( $slug ) ) {
					deactivate_plugins( $plugin_file, false, true );
					$deactivated[] = $slug;
				}
			}
		}

		if ( $deactivated ) {
			$this->alerting->notify(
				'blocked_plugin_deactivated',
				array(
					'slugs' => $deactivated,
					'user'  => get_current_user_id(),
				)
			);
			add_action(
				'admin_notices',
				static function () use ( $deactivated ) {
					printf(
						'<div class="notice notice-error"><p>%s <code>%s</code></p></div>',
						esc_html__( 'BLT Secure deactivated blocked file-manager plugin(s):', 'blt-secure' ),
						esc_html( implode( ', ', $deactivated ) )
					);
				}
			);
		}
	}
}
