<?php
/**
 * Upload guard pure-logic tests.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Blt_Secure_Upload_Guard static helpers.
 */
class Test_Upload_Guard extends TestCase {

	/**
	 * @dataProvider dangerous_names
	 * @param string $name Filename.
	 */
	public function test_dangerous_extensions( $name ) {
		$this->assertTrue( Blt_Secure_Upload_Guard::dangerous_extension( $name ), $name );
	}

	/**
	 * @return array[]
	 */
	public function dangerous_names() {
		return array(
			array( 'shell.php' ),
			array( 'SHELL.PHP' ),
			array( 'x.phtml' ),
			array( 'x.php5' ),
			array( 'x.phar' ),
			array( 'evil.php.jpg' ),
			array( 'a.pht' ),
			// .php anywhere in the extension chain can execute on misconfigured Apache.
			array( 'my.php.document.txt' ),
		);
	}

	/**
	 * @dataProvider safe_names
	 * @param string $name Filename.
	 */
	public function test_safe_extensions( $name ) {
		$this->assertFalse( Blt_Secure_Upload_Guard::dangerous_extension( $name ), $name );
	}

	/**
	 * @return array[]
	 */
	public function safe_names() {
		return array(
			array( 'photo.jpg' ),
			array( 'document.pdf' ),
			array( 'archive.zip' ),
			array( 'notphp.phpx' ),
			array( 'sheet.csv' ),
		);
	}

	public function test_php_open_tag_detected() {
		$this->assertTrue( Blt_Secure_Upload_Guard::has_php_open_tag( '<?php system($_GET["c"]); ?>' ) );
		$this->assertTrue( Blt_Secure_Upload_Guard::has_php_open_tag( 'GIF89a<?=`id`?>' ) );
		$this->assertTrue( Blt_Secure_Upload_Guard::has_php_open_tag( "<?php\n" ) );
		$this->assertTrue( Blt_Secure_Upload_Guard::has_php_open_tag( 'x<?PHP eval($_POST[1]);' ) );
		$this->assertTrue( Blt_Secure_Upload_Guard::has_php_open_tag( '<?=$x' ) );
		$this->assertTrue( Blt_Secure_Upload_Guard::has_php_open_tag( '<?= system("id") ?>' ) );
		$this->assertTrue( Blt_Secure_Upload_Guard::has_php_open_tag( '<?=(system)("id")?>' ) );
	}

	/**
	 * Deterministic high-entropy bytes (a SHA-256 stream). A test on random_bytes() can fail by
	 * chance on any CI run no matter how low the real false-positive rate is; a fixed corpus
	 * either always passes or always fails.
	 *
	 * @param int $seed  Corpus number.
	 * @param int $bytes Length.
	 * @return string
	 */
	private static function entropy( $seed, $bytes ) {
		$out = '';
		for ( $i = 0; strlen( $out ) < $bytes; $i++ ) {
			$out .= hash( 'sha256', 'blt-secure-corpus-' . $seed . '-' . $i, true );
		}
		return substr( $out, 0, $bytes );
	}

	public function test_high_entropy_binary_is_not_flagged() {
		// Regression: the first fix flagged ~100% of random 8 MB buffers, and its successor (a bare
		// `<?=` + one punctuation byte) still flagged ~1.3% — about one large JPEG/ZIP in 75.
		for ( $seed = 0; $seed < 6; $seed++ ) {
			$this->assertFalse( Blt_Secure_Upload_Guard::has_php_open_tag( self::entropy( $seed, 8 * 1024 * 1024 ) ), "Deterministic 8 MB corpus #$seed was flagged" );
		}
	}

	public function test_short_echo_tag_needs_an_expression_not_just_punctuation() {
		// Each of these is what random bytes produce by chance: `<?=` plus one lone character.
		foreach ( array( '<?=$', '<?=(', '<?=@', '<?=`', '<?=a(', '<?=$1', '<?=$-', '<?=ab(x' ) as $noise ) {
			$this->assertFalse( Blt_Secure_Upload_Guard::has_php_open_tag( "\x00\x01" . $noise . "\xff\xfe" ), 'Chance bytes must not count as a PHP tag: ' . bin2hex( $noise ) );
		}
		// ...whereas every real echo-tag payload shape still does.
		$payloads = array(
			'<?=$_GET[1]?>',
			'<?=$f($_POST[0]);',
			'<?=system($_GET[0]);',
			'<?=@eval($_POST[1])',
			"<?=exec('id')?>",
			'<?=phpinfo()?>',
			'<?=@$_GET[0]($_POST[1])?>',
			'<?= $a . $b',
			"<?=\n  \$x\n;",
			'GIF89a<?=`id`',
			'<?=(system)("id")?>',
		);
		foreach ( $payloads as $payload ) {
			$this->assertTrue( Blt_Secure_Upload_Guard::has_php_open_tag( $payload ), 'Real payload must still be detected: ' . $payload );
		}
	}

	public function test_inspect_blocks_polyglot_appended_after_sniff_window() {
		$tmp = tempnam( sys_get_temp_dir(), 'blt' );
		file_put_contents( $tmp, str_repeat( "\0", Blt_Secure_Upload_Guard::SNIFF_BYTES + 1024 ) . '<?php evil();' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		$guard  = new Blt_Secure_Upload_Guard( new Blt_Secure_Options() );
		$result = $guard->inspect(
			array(
				'name'     => 'photo.jpg',
				'tmp_name' => $tmp,
				'error'    => 0,
			)
		);
		unlink( $tmp ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
		$this->assertNotEmpty( $result['error'] );
	}

	public function test_inspect_allows_clean_file() {
		$tmp = tempnam( sys_get_temp_dir(), 'blt' );
		file_put_contents( $tmp, self::entropy( 99, 4096 ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		$guard  = new Blt_Secure_Upload_Guard( new Blt_Secure_Options() );
		$result = $guard->inspect(
			array(
				'name'     => 'photo.jpg',
				'tmp_name' => $tmp,
				'error'    => 0,
			)
		);
		unlink( $tmp ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
		$this->assertSame( 0, $result['error'] );
	}

	/**
	 * @dataProvider sneaky_names
	 * @param string $name Filename.
	 */
	public function test_extension_variants_flagged( $name ) {
		$this->assertTrue( Blt_Secure_Upload_Guard::dangerous_extension( $name ), $name );
	}

	/**
	 * @return array[]
	 */
	public function sneaky_names() {
		return array(
			array( 'x.php8' ),
			array( 'x.php6' ),
			array( 'x.phpt' ),
			array( 'x.php ' ),
			array( "x.php\0.jpg" ),
			array( 'x.php .jpg' ),
			array( 'x.PhP.' ),
		);
	}

	public function test_php_open_tag_not_flagged_for_xml_declaration() {
		$this->assertFalse( Blt_Secure_Upload_Guard::has_php_open_tag( '<?xml version="1.0"?><svg></svg>' ) );
		$this->assertFalse( Blt_Secure_Upload_Guard::has_php_open_tag( 'plain text with no tags' ) );
	}

	public function test_danger_reason_prioritizes_extension_then_content() {
		$this->assertSame( 'php_extension', Blt_Secure_Upload_Guard::danger_reason( 'x.php', 'harmless' ) );
		$this->assertSame( 'php_tag_in_file', Blt_Secure_Upload_Guard::danger_reason( 'image.jpg', 'GIF<?php evil();' ) );
		$this->assertSame( '', Blt_Secure_Upload_Guard::danger_reason( 'image.jpg', 'just pixels' ) );
	}
}
