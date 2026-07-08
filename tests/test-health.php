<?php
/**
 * Health-check scoring and result value-object tests.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure_Health_Runner::summarize() pure logic + the result VO.
 */
class Test_Health extends TestCase {

	/**
	 * Build a result with the given status.
	 *
	 * @param string $status Status constant.
	 * @return Blt_Secure_Health_Result
	 */
	private function r( $status ) {
		return new Blt_Secure_Health_Result( 'id', 'Label', 'core', $status, 'msg' );
	}

	public function test_score_is_pass_over_pass_plus_fail() {
		// 38 pass, 4 warn, 11 fail → warnings excluded → 38/49 = 77.55% → 78.
		$results = array_merge(
			array_fill( 0, 38, $this->r( Blt_Secure_Health_Result::PASS ) ),
			array_fill( 0, 4, $this->r( Blt_Secure_Health_Result::WARN ) ),
			array_fill( 0, 11, $this->r( Blt_Secure_Health_Result::FAIL ) )
		);
		$summary = Blt_Secure_Health_Runner::summarize( $results );

		$this->assertSame( 38, $summary['pass'] );
		$this->assertSame( 4, $summary['warn'] );
		$this->assertSame( 11, $summary['fail'] );
		$this->assertSame( 53, $summary['total'] );
		$this->assertSame( 78, $summary['score'] );
	}

	public function test_warnings_and_skips_do_not_lower_the_score() {
		$results = array_merge(
			array_fill( 0, 5, $this->r( Blt_Secure_Health_Result::PASS ) ),
			array_fill( 0, 10, $this->r( Blt_Secure_Health_Result::WARN ) ),
			array_fill( 0, 10, $this->r( Blt_Secure_Health_Result::SKIP ) )
		);
		$summary = Blt_Secure_Health_Runner::summarize( $results );

		// No failures → 100% regardless of warnings/skips.
		$this->assertSame( 100, $summary['score'] );
		$this->assertSame( 10, $summary['skip'] );
	}

	public function test_empty_run_scores_100() {
		$summary = Blt_Secure_Health_Runner::summarize( array() );
		$this->assertSame( 100, $summary['score'] );
		$this->assertSame( 0, $summary['total'] );
	}

	public function test_all_failing_scores_zero() {
		$summary = Blt_Secure_Health_Runner::summarize( array_fill( 0, 4, $this->r( Blt_Secure_Health_Result::FAIL ) ) );
		$this->assertSame( 0, $summary['score'] );
	}

	public function test_summarize_accepts_stored_arrays() {
		$results = array(
			array( 'status' => Blt_Secure_Health_Result::PASS ),
			array( 'status' => Blt_Secure_Health_Result::FAIL ),
			array( 'status' => 'bogus' ), // Normalizes to SKIP.
		);
		$summary = Blt_Secure_Health_Runner::summarize( $results );

		$this->assertSame( 1, $summary['pass'] );
		$this->assertSame( 1, $summary['fail'] );
		$this->assertSame( 1, $summary['skip'] );
		$this->assertSame( 50, $summary['score'] );
	}

	public function test_unknown_status_normalizes_to_skip() {
		$this->assertSame( Blt_Secure_Health_Result::SKIP, Blt_Secure_Health_Result::normalize_status( 'nonsense' ) );
		$this->assertSame( Blt_Secure_Health_Result::PASS, Blt_Secure_Health_Result::normalize_status( 'pass' ) );
	}

	public function test_result_round_trips_through_array() {
		$original = new Blt_Secure_Health_Result( 'x', 'Title', 'files', Blt_Secure_Health_Result::WARN, 'message', 'details' );
		$restored = Blt_Secure_Health_Result::from_array( $original->to_array() );

		$this->assertSame( $original->id, $restored->id );
		$this->assertSame( $original->category, $restored->category );
		$this->assertSame( $original->status, $restored->status );
		$this->assertSame( $original->details, $restored->details );
	}

	public function test_catalogue_is_well_formed() {
		$checks     = Blt_Secure_Health_Checks::all();
		$categories = Blt_Secure_Health_Checks::categories();

		// Aiming for scanner-parity breadth.
		$this->assertGreaterThanOrEqual( 45, count( $checks ) );

		$ids = array();
		foreach ( $checks as $check ) {
			$this->assertArrayHasKey( 'id', $check );
			$this->assertArrayHasKey( 'label', $check );
			$this->assertArrayHasKey( 'category', $check );
			$this->assertArrayHasKey( 'callback', $check );
			$this->assertNotSame( '', $check['id'] );
			$this->assertArrayHasKey( $check['category'], $categories, "Unknown category for {$check['id']}" );
			$this->assertTrue( is_callable( $check['callback'] ), "Uncallable check {$check['id']}" );
			$ids[] = $check['id'];
		}

		// Every check id is unique.
		$this->assertSame( count( $ids ), count( array_unique( $ids ) ) );
	}

	public function test_runner_downgrades_a_throwing_check_to_skip() {
		$runner = new Blt_Secure_Health_Runner(
			array(
				array(
					'id'       => 'boom',
					'label'    => 'Boom',
					'category' => 'core',
					'callback' => static function () {
						throw new RuntimeException( 'kaboom' );
					},
				),
				array(
					'id'       => 'ok',
					'label'    => 'OK',
					'category' => 'core',
					'callback' => static function () {
						return array( 'status' => Blt_Secure_Health_Result::PASS, 'message' => 'fine' );
					},
				),
			)
		);

		$options = new Blt_Secure_Options();
		$results = $runner->run( new Blt_Secure_Health_Context( $options ) );

		$this->assertCount( 2, $results );
		$this->assertSame( Blt_Secure_Health_Result::SKIP, $results[0]->status );
		$this->assertSame( Blt_Secure_Health_Result::PASS, $results[1]->status );
	}
}
