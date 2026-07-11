<?php
/**
 * One-click remediations for health-check findings.
 *
 * Only findings that BLT Secure can safely and reversibly fix *from the
 * plugin* are listed here — the ones driven by our own module settings, plus a
 * couple of safe WordPress/filesystem actions. Findings that need a wp-config
 * constant, a server ini change, a core/plugin update, a user rename, or the
 * deletion of files are deliberately left to the guidance text; there is no
 * Fix button for those.
 *
 * Fixes are keyed by the check id they resolve. Each callback receives the
 * shared Blt_Secure_Options and returns true on success or a WP_Error.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Registry of automatic remediations, keyed by health-check id.
 */
class Blt_Secure_Health_Fixes {

	/**
	 * The fix catalogue: check id => [ label, callback ].
	 *
	 * `label` is the short action shown on the Fix button. `callback` is
	 * `function( Blt_Secure_Options $options ): true|WP_Error`.
	 *
	 * @return array<string,array{label:string,callback:callable}>
	 */
	public static function all() {
		$c = __CLASS__;

		$fixes = array(
			'enumeration_blocked'   => array(
				'label'    => __( 'Block enumeration', 'blt-secure' ),
				'callback' => array( $c, 'fix_enumeration_blocked' ),
			),
			'login_lockout'         => array(
				'label'    => __( 'Enable lockout', 'blt-secure' ),
				'callback' => array( $c, 'fix_login_lockout' ),
			),
			'two_factor'            => array(
				'label'    => __( 'Require 2FA for admins', 'blt-secure' ),
				'callback' => array( $c, 'fix_two_factor' ),
			),
			'xmlrpc_disabled'       => array(
				'label'    => __( 'Disable XML-RPC', 'blt-secure' ),
				'callback' => array( $c, 'fix_xmlrpc_disabled' ),
			),
			'file_edit_disabled'    => array(
				'label'    => __( 'Disable file editor', 'blt-secure' ),
				'callback' => array( $c, 'fix_file_edit_disabled' ),
			),
			'file_managers_blocked' => array(
				'label'    => __( 'Block file managers', 'blt-secure' ),
				'callback' => array( $c, 'fix_file_managers_blocked' ),
			),
			'registration_off'      => array(
				'label'    => __( 'Disable registration', 'blt-secure' ),
				'callback' => array( $c, 'fix_registration_off' ),
			),
			'uploads_index'         => array(
				'label'    => __( 'Add index.php', 'blt-secure' ),
				'callback' => array( $c, 'fix_uploads_index' ),
			),
			'header_nosniff'        => array(
				'label'    => __( 'Send header', 'blt-secure' ),
				'callback' => array( $c, 'fix_header_nosniff' ),
			),
			'header_xframe'         => array(
				'label'    => __( 'Send header', 'blt-secure' ),
				'callback' => array( $c, 'fix_header_xframe' ),
			),
			'header_referrer'       => array(
				'label'    => __( 'Send header', 'blt-secure' ),
				'callback' => array( $c, 'fix_header_referrer' ),
			),
			'header_hsts'           => array(
				'label'    => __( 'Enable HSTS', 'blt-secure' ),
				'callback' => array( $c, 'fix_header_hsts' ),
			),
			'header_csp'            => array(
				'label'    => __( 'Enable CSP', 'blt-secure' ),
				'callback' => array( $c, 'fix_header_csp' ),
			),
		);

		/**
		 * Filter the automatic-fix catalogue. Modules that add their own health
		 * checks can register matching fixes here.
		 *
		 * @param array $fixes check id => [ label, callback ].
		 */
		return apply_filters( 'blt_secure_health_fixes', $fixes );
	}

	/**
	 * Whether a check id has an automatic fix.
	 *
	 * @param string $check_id Check id.
	 * @return bool
	 */
	public static function is_fixable( $check_id ) {
		$all = self::all();
		return isset( $all[ (string) $check_id ] );
	}

	/**
	 * The Fix-button label for a check id, or '' when not fixable.
	 *
	 * @param string $check_id Check id.
	 * @return string
	 */
	public static function label( $check_id ) {
		$all = self::all();
		return isset( $all[ (string) $check_id ]['label'] ) ? (string) $all[ (string) $check_id ]['label'] : '';
	}

	/**
	 * Apply the fix for a check id.
	 *
	 * @param string             $check_id Check id.
	 * @param Blt_Secure_Options $options  Settings access.
	 * @return true|WP_Error
	 */
	public static function apply( $check_id, Blt_Secure_Options $options ) {
		$all = self::all();
		$id  = (string) $check_id;

		if ( ! isset( $all[ $id ] ) || ! is_callable( $all[ $id ]['callback'] ) ) {
			return new WP_Error( 'blt_unknown_fix', __( 'This finding has no automatic fix.', 'blt-secure' ) );
		}

		$result = call_user_func( $all[ $id ]['callback'], $options );
		return is_wp_error( $result ) ? $result : true;
	}

	// ---------------------------------------------------------------------
	// Fix callbacks.
	// ---------------------------------------------------------------------

	/**
	 * Merge changes into a settings section without wiping its other keys.
	 *
	 * @param Blt_Secure_Options $options Settings access.
	 * @param string             $section Section id.
	 * @param array              $changes key => value to set.
	 * @return true
	 */
	private static function set_section( Blt_Secure_Options $options, $section, array $changes ) {
		$current = $options->section( $section );
		foreach ( $changes as $key => $value ) {
			$current[ $key ] = $value;
		}
		$options->update_section( $section, $current );
		return true;
	}

	/**
	 * @param Blt_Secure_Options $options Settings.
	 * @return true
	 */
	public static function fix_enumeration_blocked( $options ) {
		return self::set_section( $options, 'privacy', array( 'block_enum' => true ) );
	}

	/**
	 * @param Blt_Secure_Options $options Settings.
	 * @return true
	 */
	public static function fix_login_lockout( $options ) {
		return self::set_section( $options, 'login', array( 'lockout_enabled' => true ) );
	}

	/**
	 * @param Blt_Secure_Options $options Settings.
	 * @return true
	 */
	public static function fix_two_factor( $options ) {
		return self::set_section( $options, 'twofa', array( 'policy' => 'required_admins' ) );
	}

	/**
	 * @param Blt_Secure_Options $options Settings.
	 * @return true
	 */
	public static function fix_xmlrpc_disabled( $options ) {
		return self::set_section( $options, 'xmlrpc', array( 'enabled' => false ) );
	}

	/**
	 * @param Blt_Secure_Options $options Settings.
	 * @return true
	 */
	public static function fix_file_edit_disabled( $options ) {
		return self::set_section( $options, 'fileguard', array( 'disallow_file_edit' => true ) );
	}

	/**
	 * @param Blt_Secure_Options $options Settings.
	 * @return true
	 */
	public static function fix_file_managers_blocked( $options ) {
		return self::set_section( $options, 'fileguard', array( 'block_file_managers' => true ) );
	}

	/**
	 * @param Blt_Secure_Options $options Settings.
	 * @return true
	 */
	public static function fix_header_nosniff( $options ) {
		return self::set_section(
			$options,
			'headers',
			array(
				'enabled' => true,
				'nosniff' => true,
			)
		);
	}

	/**
	 * @param Blt_Secure_Options $options Settings.
	 * @return true
	 */
	public static function fix_header_xframe( $options ) {
		return self::set_section(
			$options,
			'headers',
			array(
				'enabled' => true,
				'x_frame' => 'SAMEORIGIN',
			)
		);
	}

	/**
	 * @param Blt_Secure_Options $options Settings.
	 * @return true
	 */
	public static function fix_header_referrer( $options ) {
		return self::set_section(
			$options,
			'headers',
			array(
				'enabled'         => true,
				'referrer_policy' => 'strict-origin-when-cross-origin',
			)
		);
	}

	/**
	 * @param Blt_Secure_Options $options Settings.
	 * @return true
	 */
	public static function fix_header_hsts( $options ) {
		return self::set_section(
			$options,
			'headers',
			array(
				'enabled' => true,
				'hsts'    => true,
			)
		);
	}

	/**
	 * @param Blt_Secure_Options $options Settings.
	 * @return true
	 */
	public static function fix_header_csp( $options ) {
		return self::set_section(
			$options,
			'headers',
			array(
				'enabled'         => true,
				'csp_enabled'     => true,
				'csp_report_only' => true,
			)
		);
	}

	/**
	 * Turn off open user registration (core option).
	 *
	 * @param Blt_Secure_Options $options Settings (unused).
	 * @return true
	 */
	public static function fix_registration_off( $options ) {
		unset( $options );
		update_option( 'users_can_register', 0 );
		return true;
	}

	/**
	 * Drop a silent index.php into the uploads directory to block listing.
	 *
	 * @param Blt_Secure_Options $options Settings (unused).
	 * @return true|WP_Error
	 */
	public static function fix_uploads_index( $options ) {
		unset( $options );
		$uploads = function_exists( 'wp_upload_dir' ) ? wp_upload_dir() : array();
		if ( empty( $uploads['basedir'] ) || ! is_dir( $uploads['basedir'] ) ) {
			return new WP_Error( 'blt_no_uploads', __( 'The uploads directory could not be located.', 'blt-secure' ) );
		}
		$file = trailingslashit( $uploads['basedir'] ) . 'index.php';
		if ( file_exists( $file ) ) {
			return true;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, WordPress.PHP.NoSilencedErrors.Discouraged
		$written = @file_put_contents( $file, "<?php\n// Silence is golden.\n" );
		if ( false === $written ) {
			return new WP_Error( 'blt_write_failed', __( 'Could not write index.php to the uploads directory — check its permissions.', 'blt-secure' ) );
		}
		return true;
	}
}
