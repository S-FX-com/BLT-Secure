<?php
/**
 * Runs the registered health checks and summarizes the outcome.
 *
 * @package Blt_Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Executes each check definition against a shared context and aggregates the
 * results. A check that throws is downgraded to SKIP so one broken probe can
 * never abort the whole scan.
 */
class Blt_Secure_Health_Runner {

	/**
	 * Check definitions: [ id, label, category, callback ].
	 *
	 * @var array[]
	 */
	private $checks;

	/**
	 * Constructor.
	 *
	 * @param array[] $checks Check definitions.
	 */
	public function __construct( array $checks ) {
		$this->checks = $checks;
	}

	/**
	 * Run all checks against the context.
	 *
	 * @param Blt_Secure_Health_Context $context Shared scan context.
	 * @return Blt_Secure_Health_Result[]
	 */
	public function run( Blt_Secure_Health_Context $context ) {
		$results = array();

		foreach ( $this->checks as $check ) {
			$id       = isset( $check['id'] ) ? $check['id'] : '';
			$label    = isset( $check['label'] ) ? $check['label'] : $id;
			$category = isset( $check['category'] ) ? $check['category'] : 'core';
			$callback = isset( $check['callback'] ) ? $check['callback'] : null;

			if ( ! is_callable( $callback ) ) {
				continue;
			}

			try {
				$outcome = call_user_func( $callback, $context );
			} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement
				$outcome = array(
					'status'  => Blt_Secure_Health_Result::SKIP,
					'message' => __( 'This check could not run on your server.', 'blt-secure' ),
				);
			}

			$results[] = new Blt_Secure_Health_Result(
				$id,
				$label,
				$category,
				isset( $outcome['status'] ) ? $outcome['status'] : Blt_Secure_Health_Result::SKIP,
				isset( $outcome['message'] ) ? $outcome['message'] : '',
				isset( $outcome['details'] ) ? $outcome['details'] : ''
			);
		}

		return $results;
	}

	/**
	 * Aggregate results into counts and a percentage score.
	 *
	 * Pure function (unit-tested). The score is passed / (passed + failed):
	 * warnings are advisory and skips are not applicable, so neither moves
	 * the denominator. An all-clear (or nothing scorable) site is 100%.
	 *
	 * @param Blt_Secure_Health_Result[]|array[] $results Result objects or arrays.
	 * @return array{pass:int,warn:int,fail:int,skip:int,total:int,score:int}
	 */
	public static function summarize( array $results ) {
		$counts = array(
			Blt_Secure_Health_Result::PASS => 0,
			Blt_Secure_Health_Result::WARN => 0,
			Blt_Secure_Health_Result::FAIL => 0,
			Blt_Secure_Health_Result::SKIP => 0,
		);

		foreach ( $results as $result ) {
			$status = is_object( $result ) ? $result->status : ( isset( $result['status'] ) ? $result['status'] : Blt_Secure_Health_Result::SKIP );
			$status = Blt_Secure_Health_Result::normalize_status( $status );
			++$counts[ $status ];
		}

		$scorable = $counts[ Blt_Secure_Health_Result::PASS ] + $counts[ Blt_Secure_Health_Result::FAIL ];
		$score    = $scorable > 0
			? (int) round( ( $counts[ Blt_Secure_Health_Result::PASS ] / $scorable ) * 100 )
			: 100;

		return array(
			'pass'  => $counts[ Blt_Secure_Health_Result::PASS ],
			'warn'  => $counts[ Blt_Secure_Health_Result::WARN ],
			'fail'  => $counts[ Blt_Secure_Health_Result::FAIL ],
			'skip'  => $counts[ Blt_Secure_Health_Result::SKIP ],
			'total' => count( $results ),
			'score' => $score,
		);
	}
}
