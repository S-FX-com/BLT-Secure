<?php
/**
 * A single health-check result.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Immutable value object describing the outcome of one health check.
 *
 * Status semantics:
 *  - PASS  the site is configured the recommended way.
 *  - WARN  advisory — not a vulnerability by itself, worth reviewing.
 *  - FAIL  a real hardening gap the admin should close.
 *  - SKIP  could not be determined on this host (never affects the score).
 */
class Blt_Secure_Health_Result {

	const PASS = 'pass';
	const WARN = 'warn';
	const FAIL = 'fail';
	const SKIP = 'skip';

	/**
	 * Stable check id.
	 *
	 * @var string
	 */
	public $id;

	/**
	 * Human-readable check title.
	 *
	 * @var string
	 */
	public $label;

	/**
	 * Category key (see Blt_Secure_Health_Checks::categories()).
	 *
	 * @var string
	 */
	public $category;

	/**
	 * One of the status constants.
	 *
	 * @var string
	 */
	public $status;

	/**
	 * Short result sentence shown under the title.
	 *
	 * @var string
	 */
	public $message;

	/**
	 * Optional longer guidance shown on demand.
	 *
	 * @var string
	 */
	public $details;

	/**
	 * Constructor.
	 *
	 * @param string $id       Check id.
	 * @param string $label    Title.
	 * @param string $category Category key.
	 * @param string $status   Status constant.
	 * @param string $message  Result sentence.
	 * @param string $details  Optional guidance.
	 */
	public function __construct( $id, $label, $category, $status, $message, $details = '' ) {
		$this->id       = (string) $id;
		$this->label    = (string) $label;
		$this->category = (string) $category;
		$this->status   = self::normalize_status( $status );
		$this->message  = (string) $message;
		$this->details  = (string) $details;
	}

	/**
	 * Coerce an arbitrary value to a known status (unknown → SKIP).
	 *
	 * @param mixed $status Candidate status.
	 * @return string
	 */
	public static function normalize_status( $status ) {
		$known = array( self::PASS, self::WARN, self::FAIL, self::SKIP );
		return in_array( $status, $known, true ) ? $status : self::SKIP;
	}

	/**
	 * Serialize for storage in the results option.
	 *
	 * @return array
	 */
	public function to_array() {
		return array(
			'id'       => $this->id,
			'label'    => $this->label,
			'category' => $this->category,
			'status'   => $this->status,
			'message'  => $this->message,
			'details'  => $this->details,
		);
	}

	/**
	 * Rehydrate from a stored array.
	 *
	 * @param array $data Stored result.
	 * @return Blt_Secure_Health_Result
	 */
	public static function from_array( array $data ) {
		return new self(
			isset( $data['id'] ) ? $data['id'] : '',
			isset( $data['label'] ) ? $data['label'] : '',
			isset( $data['category'] ) ? $data['category'] : '',
			isset( $data['status'] ) ? $data['status'] : self::SKIP,
			isset( $data['message'] ) ? $data['message'] : '',
			isset( $data['details'] ) ? $data['details'] : ''
		);
	}
}
