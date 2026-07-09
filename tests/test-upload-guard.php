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
		$this->assertTrue( Blt_Secure_Upload_Guard::has_php_open_tag( "text\n<?  echo 1;" ) );
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
