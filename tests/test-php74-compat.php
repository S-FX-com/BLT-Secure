<?php
/**
 * PHP 7.4 compatibility gate.
 *
 * The plugin promises PHP 7.4+, but development and CI hosts run newer PHP, so
 * `php -l` and the rest of the suite cannot catch 8.0+ syntax. The usual tool
 * (PHPCompatibility) cannot help here: 9.x predates PHP 8 and 10.x needs
 * PHP_CodeSniffer 4, which WPCS does not support yet. This test reads the token
 * stream instead — no dependencies, runs wherever the suite runs.
 *
 * It fails the build on syntax and functions that do not exist on 7.4. A second
 * group of tests feeds it known-bad snippets so the detectors cannot silently
 * check nothing.
 *
 * @package Blt_Secure
 */

use PHPUnit\Framework\TestCase;

/**
 * Token-level PHP 7.4 compatibility scan.
 */
class Test_Php74_Compat extends TestCase {

	/**
	 * Functions that do not exist on PHP 7.4.
	 *
	 * str_contains / str_starts_with / str_ends_with are included even though WordPress 5.9+
	 * polyfills them in production: the unit-test bootstrap has no WordPress, so a plugin class
	 * or test that calls one passes on 8.x and fatals on the 7.4 CI leg. Use strpos() or guard
	 * the call with function_exists().
	 *
	 * @var string[]
	 */
	private static $new_functions = array(
		'str_contains',
		'str_starts_with',
		'str_ends_with',
		'get_debug_type',
		'get_resource_id',
		'fdiv',
		'preg_last_error_msg',
		'array_is_list',
		'enum_exists',
		'fsync',
		'fdatasync',
		'mb_str_pad',
		'json_validate',
		'array_find',
		'array_any',
		'array_all',
	);

	/**
	 * Classes/interfaces added after 7.4.
	 *
	 * @var string[]
	 */
	private static $new_classes = array(
		'ValueError',
		'UnhandledMatchError',
		'Stringable',
		'WeakMap',
		'Attribute',
		'ReturnTypeWillChange',
		'AllowDynamicProperties',
		'SensitiveParameter',
		'Override',
	);

	/**
	 * PHP files that must stay 7.4-compatible: the plugin AND its tests (CI runs both on 7.4).
	 *
	 * @return string[]
	 */
	private static function plugin_files() {
		$root  = dirname( __DIR__ );
		$files = array();
		$skip  = array( '/vendor/', '/node_modules/', '/includes/lib/', '/dashboard/', '/.git/' );

		$iterator = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ) );
		foreach ( $iterator as $file ) {
			$path = str_replace( '\\', '/', $file->getPathname() );
			if ( '.php' !== substr( $path, -4 ) ) {
				continue;
			}
			$relative = substr( $path, strlen( str_replace( '\\', '/', $root ) ) );
			foreach ( $skip as $needle ) {
				if ( false !== strpos( $relative . '/', $needle ) ) {
					continue 2;
				}
			}
			$files[] = $path;
		}
		sort( $files );
		return $files;
	}

	/**
	 * Significant tokens only, as [ id|char, text, line ].
	 *
	 * @param string $code PHP source.
	 * @return array<int,array{0:int|string,1:string,2:int}>
	 */
	private static function tokens( $code ) {
		$out  = array();
		$line = 1;
		foreach ( token_get_all( $code ) as $token ) {
			if ( is_array( $token ) ) {
				$line = $token[2];
				if ( in_array( $token[0], array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true ) ) {
					continue;
				}
				$out[] = array( $token[0], $token[1], $token[2] );
			} else {
				$out[] = array( $token, $token, $line );
			}
		}
		return $out;
	}

	/**
	 * A token constant that only exists on newer PHP, or null.
	 *
	 * @param string $name Constant name.
	 * @return int|null
	 */
	private static function const_id( $name ) {
		return defined( $name ) ? constant( $name ) : null;
	}

	/**
	 * Scan one source string for post-7.4 constructs.
	 *
	 * @param string $code PHP source.
	 * @return string[] Human-readable problems ("line N: ...").
	 */
	public static function problems( $code ) {
		$t        = self::tokens( $code );
		$n        = count( $t );
		$problems = array();

		$simple = array(
			'T_MATCH'                    => 'match expression (PHP 8.0)',
			'T_NULLSAFE_OBJECT_OPERATOR' => 'nullsafe operator ?-> (PHP 8.0)',
			'T_ATTRIBUTE'                => 'attribute #[ ] (PHP 8.0)',
			'T_READONLY'                 => 'readonly (PHP 8.1)',
			'T_ENUM'                     => 'enum (PHP 8.1)',
		);
		$ids    = array();
		foreach ( $simple as $name => $label ) {
			$id = self::const_id( $name );
			if ( null !== $id ) {
				$ids[ $id ] = $label;
			}
		}

		$guarded = array();
		if ( preg_match_all( '/function_exists\(\s*[\'"]([a-z0-9_]+)[\'"]\s*\)/i', $code, $m ) ) {
			$guarded = array_map( 'strtolower', $m[1] );
		}

		for ( $i = 0; $i < $n; $i++ ) {
			$id   = $t[ $i ][0];
			$text = $t[ $i ][1];
			$line = $t[ $i ][2];

			if ( isset( $ids[ $id ] ) ) {
				$problems[] = "line {$line}: {$ids[ $id ]}";
			}

			// Non-capturing catch: catch ( Exception ) with no variable (PHP 8.0).
			if ( T_CATCH === $id && isset( $t[ $i + 1 ] ) && '(' === $t[ $i + 1 ][0] ) {
				$has_var = false;
				for ( $k = $i + 2; $k < $n && ')' !== $t[ $k ][0]; $k++ ) {
					if ( T_VARIABLE === $t[ $k ][0] ) {
						$has_var = true;
					}
				}
				if ( ! $has_var ) {
					$problems[] = "line {$line}: catch without a variable (PHP 8.0)";
				}
			}

			// Functions added after 7.4.
			if ( T_STRING === $id && isset( $t[ $i + 1 ] ) && '(' === $t[ $i + 1 ][0] ) {
				$lower = strtolower( $text );
				$prev  = $i > 0 ? $t[ $i - 1 ][0] : null;
				if ( in_array( $lower, self::$new_functions, true )
					&& ! in_array( $lower, $guarded, true )
					&& ! in_array( $prev, array( T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NEW ), true ) ) {
					$problems[] = "line {$line}: function {$text}() does not exist before its PHP 8 release";
				}
			}

			// Classes added after 7.4.
			if ( T_STRING === $id && in_array( $text, self::$new_classes, true ) ) {
				$prev = $i > 0 ? $t[ $i - 1 ][0] : null;
				if ( ! in_array( $prev, array( T_OBJECT_OPERATOR, T_FUNCTION, T_CONST, T_DOUBLE_COLON ), true ) ) {
					$problems[] = "line {$line}: class {$text} does not exist on PHP 7.4";
				}
			}

			// Function / closure / arrow-function declarations.
			if ( T_FUNCTION === $id || T_FN === $id ) {
				$j = $i + 1;
				if ( isset( $t[ $j ] ) && '&' === $t[ $j ][0] ) {
					++$j;
				}
				if ( T_FUNCTION === $id && isset( $t[ $j ] ) && T_STRING === $t[ $j ][0] ) {
					++$j;
				}
				if ( ! isset( $t[ $j ] ) || '(' !== $t[ $j ][0] ) {
					continue;
				}
				$end       = self::check_parameters( $t, $j, $problems );
				$after     = $end + 1;
				$scan_from = $after;

				// Closure use ( $a, $b, ) — trailing comma is 8.0.
				if ( isset( $t[ $after ] ) && T_USE === $t[ $after ][0] && isset( $t[ $after + 1 ] ) && '(' === $t[ $after + 1 ][0] ) {
					$depth = 0;
					for ( $k = $after + 1; $k < $n; $k++ ) {
						if ( '(' === $t[ $k ][0] ) {
							++$depth;
						} elseif ( ')' === $t[ $k ][0] ) {
							--$depth;
							if ( 0 === $depth ) {
								if ( ',' === $t[ $k - 1 ][0] ) {
									$problems[] = "line {$t[ $k ][2]}: trailing comma in closure use() (PHP 8.0)";
								}
								$scan_from = $k + 1;
								break;
							}
						}
					}
				}

				// Return type: union, mixed, never, static (all 8.0+).
				if ( isset( $t[ $scan_from ] ) && ':' === $t[ $scan_from ][0] ) {
					for ( $k = $scan_from + 1; $k < $n; $k++ ) {
						$c = $t[ $k ][0];
						if ( '{' === $c || ';' === $c || T_DOUBLE_ARROW === $c ) {
							break;
						}
						self::check_type_token( $t[ $k ], 'return type', $problems );
					}
				}
			}
		}

		return array_values( array_unique( $problems ) );
	}

	/**
	 * Inspect one parameter list. Returns the index of its closing parenthesis.
	 *
	 * @param array    $t        Tokens.
	 * @param int      $open     Index of the opening parenthesis.
	 * @param string[] $problems Collected problems (by reference).
	 * @return int
	 */
	private static function check_parameters( array $t, $open, array &$problems ) {
		$n          = count( $t );
		$depth      = 0;
		$in_default = false;

		for ( $k = $open; $k < $n; $k++ ) {
			$c    = $t[ $k ][0];
			$line = $t[ $k ][2];

			if ( '(' === $c || '[' === $c ) {
				++$depth;
				continue;
			}
			if ( ')' === $c || ']' === $c ) {
				--$depth;
				if ( 0 === $depth ) {
					return $k;
				}
				continue;
			}
			if ( 1 !== $depth ) {
				continue;
			}

			if ( ',' === $c ) {
				$in_default = false;
				if ( isset( $t[ $k + 1 ] ) && ')' === $t[ $k + 1 ][0] ) {
					$problems[] = "line {$line}: trailing comma in a parameter list (PHP 8.0)";
				}
				continue;
			}
			if ( '=' === $c ) {
				$in_default = true;
				continue;
			}
			if ( $in_default ) {
				continue;
			}

			if ( in_array( $c, array( T_PUBLIC, T_PROTECTED, T_PRIVATE ), true ) ) {
				$problems[] = "line {$line}: constructor property promotion (PHP 8.0)";
			}
			self::check_type_token( $t[ $k ], 'parameter type', $problems );
		}

		return $n - 1;
	}

	/**
	 * Flag a token that is only legal in a type position from PHP 8.0.
	 *
	 * @param array    $token    [ id, text, line ].
	 * @param string   $where    Label.
	 * @param string[] $problems Collected problems (by reference).
	 * @return void
	 */
	private static function check_type_token( array $token, $where, array &$problems ) {
		list( $id, $text, $line ) = $token;
		if ( '|' === $id ) {
			$problems[] = "line {$line}: union type in a {$where} (PHP 8.0)";
		} elseif ( T_STRING === $id && in_array( strtolower( $text ), array( 'mixed', 'never' ), true ) ) {
			$problems[] = "line {$line}: '{$text}' type in a {$where} (PHP 8.0/8.1)";
		} elseif ( T_STATIC === $id && 'return type' === $where ) {
			$problems[] = "line {$line}: 'static' return type (PHP 8.0)";
		}
	}

	/**
	 * Every plugin file is 7.4-compatible.
	 *
	 * @return void
	 */
	public function test_plugin_and_test_code_use_nothing_newer_than_php_74() {
		$files = self::plugin_files();
		$this->assertGreaterThan( 50, count( $files ), 'The scan found suspiciously few files; the gate may be pointing at the wrong directory.' );

		$found = array();
		foreach ( $files as $file ) {
			foreach ( self::problems( (string) file_get_contents( $file ) ) as $problem ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
				$found[] = substr( $file, strlen( dirname( __DIR__ ) ) + 1 ) . ': ' . $problem;
			}
		}

		$this->assertSame( array(), $found, "PHP 8+ constructs found in code that must run on PHP 7.4:\n" . implode( "\n", $found ) );
	}

	/**
	 * Known-bad snippets: the detectors must fire, or the test above proves nothing.
	 *
	 * @return array<string,array{0:string,1:string}>
	 */
	public function bad_snippets() {
		return array(
			'match'                 => array( '<?php $a = match ( $x ) { 1 => 2, default => 3 };', 'match' ),
			'nullsafe'              => array( '<?php $a = $o?->p;', 'nullsafe' ),
			'attribute'             => array( "<?php\n#[Foo]\nclass A {}", 'attribute' ),
			'union param'           => array( '<?php function f( int|string $a ) {}', 'union type' ),
			'union return'          => array( '<?php function f(): int|string { return 1; }', 'union type' ),
			'arrow fn union'        => array( '<?php $f = fn( int|string $v ) => $v;', 'union type' ),
			'mixed param'           => array( '<?php function f( mixed $a ) {}', 'mixed' ),
			'never return'          => array( '<?php function f(): never { exit; }', 'never' ),
			'static return'         => array( '<?php class A { function f(): static { return $this; } }', 'static' ),
			'promotion'             => array( '<?php class A { function __construct( private int $a ) {} }', 'promotion' ),
			'param trailing comma'  => array( '<?php function f( $a, $b, ) {}', 'trailing comma' ),
			'closure use comma'     => array( '<?php $f = function () use ( $a, $b, ) {};', 'trailing comma' ),
			'catch without var'     => array( '<?php try {} catch ( Exception ) {}', 'catch without' ),
			'get_debug_type'        => array( '<?php $a = get_debug_type( $x );', 'get_debug_type' ),
			'array_is_list'         => array( '<?php $a = array_is_list( $x );', 'array_is_list' ),
			'fdiv'                  => array( '<?php $a = fdiv( 1, 2 );', 'fdiv' ),
			'ValueError'            => array( '<?php throw new ValueError( "x" );', 'ValueError' ),
			'str_contains'          => array( '<?php $a = str_contains( "ab", "a" );', 'str_contains' ),
			'str_starts_with'       => array( '<?php $a = str_starts_with( "ab", "a" );', 'str_starts_with' ),
			'readonly property'     => array( '<?php class A { public readonly int $a; }', 'readonly' ),
			'enum'                  => array( "<?php enum Suit: string { case H = 'h'; }", 'enum' ),
		);
	}

	/**
	 * Each detector fires on its construct.
	 *
	 * @dataProvider bad_snippets
	 *
	 * @param string $code   Snippet.
	 * @param string $needle Text expected in a reported problem.
	 * @return void
	 */
	public function test_detector_fires( $code, $needle ) {
		if ( in_array( $needle, array( 'match', 'nullsafe', 'attribute' ), true ) && PHP_VERSION_ID < 80000 || in_array( $needle, array( 'readonly', 'enum' ), true ) && PHP_VERSION_ID < 80100 ) {
			$this->markTestSkipped( 'These tokens only exist on PHP 8+; on 7.4 the file would not lex and php -l fails first.' );
		}
		$problems = self::problems( $code );
		$this->assertNotEmpty( $problems, "Expected a problem for: {$code}" );
		$this->assertStringContainsString( $needle, implode( ' | ', $problems ) );
	}

	/**
	 * Valid 7.4 code is not flagged — including `|` and `static` in places that are not types.
	 *
	 * @return void
	 */
	public function test_valid_php74_is_not_flagged() {
		$ok = array(
			'<?php function f( int $flags = E_ALL | E_STRICT, ?string $s = null ): ?array { return null; }',
			'<?php $x = $a | $b; $y = static function () { return 1; }; $z = fn( $v ) => $v | 1;',
			'<?php class A { public static function make(): self { return new static(); } private $p; }',
			'<?php try { f(); } catch ( Exception $e ) {} catch ( TypeError | Error $e ) {}',
			'<?php if ( function_exists( "fdiv" ) ) { $a = fdiv( 1, 2 ); }',
			'<?php $s = strpos( "ab", "a" ); $t = $o->fdiv( 1 ); $u = A::get_debug_type( 1 );',
			'<?php if ( function_exists( "str_contains" ) ) { $s = str_contains( "ab", "a" ); }',
			'<?php function f( array $a = array( 1, 2 ), $b = [ 3, 4 ] ) { return f( 1, 2, ); }',
			'<?php class A { public function fdiv( $a ) {} public function get_debug_type() {} }',
		);
		foreach ( $ok as $code ) {
			$this->assertSame( array(), self::problems( $code ), "False positive on: {$code}" );
		}
	}
}
