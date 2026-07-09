<?php
/**
 * Upload guard: blocks executable PHP from entering the media library.
 *
 * Runs at upload time (wp_handle_upload_prefilter) and rejects files that
 * are PHP by extension or that carry a PHP open tag anywhere in their bytes
 * (the disguised-image / polyglot trick). This is deliberately narrow and
 * false-positive-safe — it does not run the full signature set against
 * binary media; the scheduled malware scan covers deeper analysis of the
 * whole tree.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Rejects dangerous uploads before WordPress stores them.
 */
class Blt_Secure_Upload_Guard implements Blt_Secure_Module {

	/**
	 * Read at most this many bytes when sniffing for a PHP tag.
	 */
	const SNIFF_BYTES = 8388608; // 8 MB.

	/**
	 * Settings.
	 *
	 * @var Blt_Secure_Options
	 */
	private $options;

	/**
	 * Event sink.
	 *
	 * @var Blt_Secure_Alerting|null
	 */
	private $alerting;

	/**
	 * Constructor.
	 *
	 * @param Blt_Secure_Options       $options  Settings access.
	 * @param Blt_Secure_Alerting|null $alerting Event sink.
	 */
	public function __construct( Blt_Secure_Options $options, $alerting = null ) {
		$this->options  = $options;
		$this->alerting = $alerting;
	}

	/**
	 * Module id.
	 *
	 * @return string
	 */
	public function id() {
		return 'upload_guard';
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
		return (bool) $this->options->get( 'upload_guard', 'enabled', true );
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
	 * Register hooks.
	 *
	 * @return void
	 */
	public function boot() {
		add_filter( 'wp_handle_upload_prefilter', array( $this, 'inspect' ) );
	}

	// ---------------------------------------------------------------------
	// Pure helpers (unit-tested).
	// ---------------------------------------------------------------------

	/**
	 * Whether a filename has a PHP-executable extension (including the
	 * double-extension trick, e.g. shell.php.jpg).
	 *
	 * @param string $name Filename.
	 * @return bool
	 */
	public static function dangerous_extension( $name ) {
		$name = strtolower( (string) $name );
		return (bool) preg_match( '#\.(?:php|php3|php4|php5|php7|phtml|pht|phps|phar)(?:\.|$)#', $name );
	}

	/**
	 * Whether a blob contains a PHP open tag (php, echo, or short tag) but not
	 * a mere XML declaration.
	 *
	 * @param string $content File bytes.
	 * @return bool
	 */
	public static function has_php_open_tag( $content ) {
		return (bool) preg_match( '#<\?(?:php|=|\s)#i', (string) $content );
	}

	/**
	 * The reason an upload is dangerous, or '' if it is allowed.
	 *
	 * Pure function (unit-tested).
	 *
	 * @param string $name    Filename.
	 * @param string $content File bytes (may be a bounded prefix).
	 * @return string
	 */
	public static function danger_reason( $name, $content ) {
		if ( self::dangerous_extension( $name ) ) {
			return 'php_extension';
		}
		if ( self::has_php_open_tag( $content ) ) {
			return 'php_tag_in_file';
		}
		return '';
	}

	// ---------------------------------------------------------------------
	// Hook.
	// ---------------------------------------------------------------------

	/**
	 * Inspect a pending upload and reject it if it can execute as PHP.
	 *
	 * @param array $file Upload array (name, type, tmp_name, error, size).
	 * @return array
	 */
	public function inspect( $file ) {
		if ( ! is_array( $file ) || ! empty( $file['error'] ) ) {
			return $file;
		}

		$name    = isset( $file['name'] ) ? (string) $file['name'] : '';
		$tmp     = isset( $file['tmp_name'] ) ? (string) $file['tmp_name'] : '';
		$content = '';
		if ( '' !== $tmp && is_readable( $tmp ) ) {
			$content = (string) @file_get_contents( $tmp, false, null, 0, self::SNIFF_BYTES ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents, WordPress.PHP.NoSilencedErrors.Discouraged
		}

		$reason = self::danger_reason( $name, $content );
		if ( '' === $reason ) {
			return $file;
		}

		if ( $this->alerting ) {
			$this->alerting->notify(
				'blocked_upload',
				array(
					'file'   => $name,
					'reason' => $reason,
				)
			);
		}

		$file['error'] = __( 'BLT Secure blocked this upload because it can execute as PHP. If you believe this is a mistake, contact your site administrator.', 'blt-secure' );
		return $file;
	}
}
