<?php
/**
 * Curve25519
 * 
 * Assembled from:
 *  - https://godoc.org/code.google.com/p/go.crypto/curve25519
 *  - https://github.com/agl/curve25519-donna
 *
 * @author Devi Mandiri <devi.mandiri@gmail.com>
 * @link   https://github.com/devi/Salt
 * 
 */
class Curve25519 {

	/* Lazy load */
	private static $instance;

	public static function instance() {
		if (!isset(static::$instance)) {
			static::$instance = new Curve25519();
		}
		return static::$instance;
	}

	function feAdd($dst, $a, $b) {
		for ($i = 0;$i < 10;++$i) {
			$dst[$i] = $a[$i] + $b[$i];
		}
	}

	function feSub($dst, $a, $b) {
		for ($i = 0;$i < 10;++$i) {
			$dst[$i] = $a[$i] - $b[$i];
		}
	}

	function feCSwap($f, $g, $b) {
		$swap = -$b;
		for ($i = 0;$i < 10; ++$i) {
			$x = $swap & ($f[$i] ^ $g[$i]);
			$f[$i] = $f[$i] ^ $x;
			$g[$i] = $g[$i] ^ $x;
		}
	}

	function feLoad($out, $in, $offset, $start, $shift, $mask) {
		$out[$offset] = ((
				$in[$start+0] |
				$in[$start+1] << 8 |
				$in[$start+2] << 16 |
				$in[$start+3] << 24) >> $shift) & $mask;
	}

	function feFromBytes($output, $input) {
		$this->feLoad($output, $input, 0, 0, 0, 0x3ffffff);
		$this->feLoad($output, $input, 1, 3, 2, 0x1ffffff);
		$this->feLoad($output, $input, 2, 6, 3, 0x3ffffff);
		$this->feLoad($output, $input, 3, 9, 5, 0x1ffffff);
		$this->feLoad($output, $input, 4, 12, 6, 0x3ffffff);
		$this->feLoad($output, $input, 5, 16, 0, 0x1ffffff);
		$this->feLoad($output, $input, 6, 19, 1, 0x3ffffff);
		$this->feLoad($output, $input, 7, 22, 3, 0x1ffffff);
		$this->feLoad($output, $input, 8, 25, 4, 0x3ffffff);
		$this->feLoad($output, $input, 9, 28, 6, 0x3ffffff);
	}

	function feStore($out, $in, $i, $s) {
		$out[$s+0] |= $in[$i] & 0xff;
		$out[$s+1] = ($in[$i] >> 8) & 0xff;
		$out[$s+2] = ($in[$i] >> 16) & 0xff;
		$out[$s+3] = ($in[$i] >> 24) & 0xff;
	}

	function feTobytes($output, $input) {
		for ($j = 0; $j < 2; ++$j) {
			for ($i = 0;$i < 9; ++$i) {
				if (($i & 1) === 1) {
					$mask = $input[$i] >> 31;
					$carry = -(($input[$i] & $mask) >> 25);
					$input[$i] += $carry << 25;
					$input[$i+1] -= $carry;
				} else {
					$mask = $input[$i] >> 31;
					$carry = -(($input[$i] & $mask) >> 26);
					$input[$i] += $carry << 26;
					$input[$i+1] -= $carry;
				}
			}
			$mask = $input[9] >> 31;
			$carry = -(($input[9] & $mask) >> 25);
			$input[9] += $carry << 25;
			$input[0] -= $carry * 19;
		}

		$mask = $input[0] >> 31;
		$carry = -(($input[0] & $mask) >> 26);
		$input[0] += $carry << 26;
		$input[1] -= $carry;

		$input[1] <<= 2;
		$input[2] <<= 3;
		$input[3] <<= 5;
		$input[4] <<= 6;
		$input[6] <<= 1;
		$input[7] <<= 3;
		$input[8] <<= 4;
		$input[9] <<= 6;

		$output[0] = 0;
		$output[16] = 0;

		$this->feStore($output, $input, 0,0);
		$this->feStore($output, $input, 1,3);
		$this->feStore($output, $input, 2,6);
		$this->feStore($output, $input, 3,9);
		$this->feStore($output, $input, 4,12);
		$this->feStore($output, $input, 5,16);
		$this->feStore($output, $input, 6,19);
		$this->feStore($output, $input, 7,22);
		$this->feStore($output, $input, 8,25);
		$this->feStore($output, $input, 9,28);
	}

	function feCarry19(&$x, &$y) { 
		$c = ($x + (1 << 24)) >> 25;
		$y += $c * 19;
		$x -= $c << 25;
	}

	function feCarry25(&$x, &$y) { 
		$c = ($x + (1 << 24)) >> 25;
		$y += $c;
		$x -= $c << 25;
	}

	function feCarry26(&$x, &$y) { 
		$c = ($x + (1 << 25)) >> 26;
		$y += $c;
		$x -= $c << 26;
	}

	function feMul($h, $f, $g) {
		$f0 = $f[0];
		$f1 = $f[1];
		$f2 = $f[2];
		$f3 = $f[3];
		$f4 = $f[4];
		$f5 = $f[5];
		$f6 = $f[6];
		$f7 = $f[7];
		$f8 = $f[8];
		$f9 = $f[9];
		$g0 = $g[0];
		$g1 = $g[1];
		$g2 = $g[2];
		$g3 = $g[3];
		$g4 = $g[4];
		$g5 = $g[5];
		$g6 = $g[6];
		$g7 = $g[7];
		$g8 = $g[8];
		$g9 = $g[9];

		$g1_19 = 19 * $g1;
		$g2_19 = 19 * $g2;
		$g3_19 = 19 * $g3;
		$g4_19 = 19 * $g4;
		$g5_19 = 19 * $g5;
		$g6_19 = 19 * $g6;
		$g7_19 = 19 * $g7;
		$g8_19 = 19 * $g8;
		$g9_19 = 19 * $g9;
		$f1_2 = 2 * $f1;
		$f3_2 = 2 * $f3;
		$f5_2 = 2 * $f5;
		$f7_2 = 2 * $f7;
		$f9_2 = 2 * $f9;
		$f0g0 = $f0 * $g0;
		$f0g1 = $f0 * $g1;
		$f0g2 = $f0 * $g2;
		$f0g3 = $f0 * $g3;
		$f0g4 = $f0 * $g4;
		$f0g5 = $f0 * $g5;
		$f0g6 = $f0 * $g6;
		$f0g7 = $f0 * $g7;
		$f0g8 = $f0 * $g8;
		$f0g9 = $f0 * $g9;
		$f1g0 = $f1 * $g0;
		$f1g1_2 = $f1_2 * $g1;
		$f1g2 = $f1 * $g2;
		$f1g3_2 = $f1_2 * $g3;
		$f1g4 = $f1 * $g4;
		$f1g5_2 = $f1_2 * $g5;
		$f1g6 = $f1 * $g6;
		$f1g7_2 = $f1_2 * $g7;
		$f1g8 = $f1 * $g8;
		$f1g9_38 = $f1_2 * $g9_19;
		$f2g0 = $f2 * $g0;
		$f2g1 = $f2 * $g1;
		$f2g2 = $f2 * $g2;
		$f2g3 = $f2 * $g3;
		$f2g4 = $f2 * $g4;
		$f2g5 = $f2 * $g5;
		$f2g6 = $f2 * $g6;
		$f2g7 = $f2 * $g7;
		$f2g8_19 = $f2 * $g8_19;
		$f2g9_19 = $f2 * $g9_19;
		$f3g0 = $f3 * $g0;
		$f3g1_2 = $f3_2 * $g1;
		$f3g2 = $f3 * $g2;
		$f3g3_2 = $f3_2 * $g3;
		$f3g4 = $f3 * $g4;
		$f3g5_2 = $f3_2 * $g5;
		$f3g6 = $f3 * $g6;
		$f3g7_38 = $f3_2 * $g7_19;
		$f3g8_19 = $f3 * $g8_19;
		$f3g9_38 = $f3_2 * $g9_19;
		$f4g0 = $f4 * $g0;
		$f4g1 = $f4 * $g1;
		$f4g2 = $f4 * $g2;
		$f4g3 = $f4 * $g3;
		$f4g4 = $f4 * $g4;
		$f4g5 = $f4 * $g5;
		$f4g6_19 = $f4 * $g6_19;
		$f4g7_19 = $f4 * $g7_19;
		$f4g8_19 = $f4 * $g8_19;
		$f4g9_19 = $f4 * $g9_19;
		$f5g0 = $f5 * $g0;
		$f5g1_2 = $f5_2 * $g1;
		$f5g2 = $f5 * $g2;
		$f5g3_2 = $f5_2 * $g3;
		$f5g4 = $f5 * $g4;
		$f5g5_38 = $f5_2 * $g5_19;
		$f5g6_19 = $f5 * $g6_19;
		$f5g7_38 = $f5_2 * $g7_19;
		$f5g8_19 = $f5 * $g8_19;
		$f5g9_38 = $f5_2 * $g9_19;
		$f6g0 = $f6 * $g0;
		$f6g1 = $f6 * $g1;
		$f6g2 = $f6 * $g2;
		$f6g3 = $f6 * $g3;
		$f6g4_19 = $f6 * $g4_19;
		$f6g5_19 = $f6 * $g5_19;
		$f6g6_19 = $f6 * $g6_19;
		$f6g7_19 = $f6 * $g7_19;
		$f6g8_19 = $f6 * $g8_19;
		$f6g9_19 = $f6 * $g9_19;
		$f7g0 = $f7 * $g0;
		$f7g1_2 = $f7_2 * $g1;
		$f7g2 = $f7 * $g2;
		$f7g3_38 = $f7_2 * $g3_19;
		$f7g4_19 = $f7 * $g4_19;
		$f7g5_38 = $f7_2 * $g5_19;
		$f7g6_19 = $f7 * $g6_19;
		$f7g7_38 = $f7_2 * $g7_19;
		$f7g8_19 = $f7 * $g8_19;
		$f7g9_38 = $f7_2 * $g9_19;
		$f8g0 = $f8 * $g0;
		$f8g1 = $f8 * $g1;
		$f8g2_19 = $f8 * $g2_19;
		$f8g3_19 = $f8 * $g3_19;
		$f8g4_19 = $f8 * $g4_19;
		$f8g5_19 = $f8 * $g5_19;
		$f8g6_19 = $f8 * $g6_19;
		$f8g7_19 = $f8 * $g7_19;
		$f8g8_19 = $f8 * $g8_19;
		$f8g9_19 = $f8 * $g9_19;
		$f9g0 = $f9 * $g0;
		$f9g1_38 = $f9_2 * $g1_19;
		$f9g2_19 = $f9 * $g2_19;
		$f9g3_38 = $f9_2 * $g3_19;
		$f9g4_19 = $f9 * $g4_19;
		$f9g5_38 = $f9_2 * $g5_19;
		$f9g6_19 = $f9 * $g6_19;
		$f9g7_38 = $f9_2 * $g7_19;
		$f9g8_19 = $f9 * $g8_19;
		$f9g9_38 = $f9_2 * $g9_19;
		$h0 = $f0g0 + $f1g9_38 + $f2g8_19 + $f3g7_38 + $f4g6_19 + $f5g5_38 + $f6g4_19 + $f7g3_38 + $f8g2_19 + $f9g1_38;
		$h1 = $f0g1 + $f1g0 + $f2g9_19 + $f3g8_19 + $f4g7_19 + $f5g6_19 + $f6g5_19 + $f7g4_19 + $f8g3_19 + $f9g2_19;
		$h2 = $f0g2 + $f1g1_2 + $f2g0 + $f3g9_38 + $f4g8_19 + $f5g7_38 + $f6g6_19 + $f7g5_38 + $f8g4_19 + $f9g3_38;
		$h3 = $f0g3 + $f1g2 + $f2g1 + $f3g0 + $f4g9_19 + $f5g8_19 + $f6g7_19 + $f7g6_19 + $f8g5_19 + $f9g4_19;
		$h4 = $f0g4 + $f1g3_2 + $f2g2 + $f3g1_2 + $f4g0 + $f5g9_38 + $f6g8_19 + $f7g7_38 + $f8g6_19 + $f9g5_38;
		$h5 = $f0g5 + $f1g4 + $f2g3 + $f3g2 + $f4g1 + $f5g0 + $f6g9_19 + $f7g8_19 + $f8g7_19 + $f9g6_19;
		$h6 = $f0g6 + $f1g5_2 + $f2g4 + $f3g3_2 + $f4g2 + $f5g1_2 + $f6g0 + $f7g9_38 + $f8g8_19 + $f9g7_38;
		$h7 = $f0g7 + $f1g6 + $f2g5 + $f3g4 + $f4g3 + $f5g2 + $f6g1 + $f7g0 + $f8g9_19 + $f9g8_19;
		$h8 = $f0g8 + $f1g7_2 + $f2g6 + $f3g5_2 + $f4g4 + $f5g3_2 + $f6g2 + $f7g1_2 + $f8g0 + $f9g9_38;
		$h9 = $f0g9 + $f1g8 + $f2g7 + $f3g6 + $f4g5 + $f5g4 + $f6g3 + $f7g2 + $f8g1 + $f9g0;

		$this->feCarry26($h0, $h1); 
		$this->feCarry26($h4, $h5);
		$this->feCarry25($h1, $h2);
		$this->feCarry25($h5, $h6);
		$this->feCarry26($h2, $h3);
		$this->feCarry26($h6, $h7);
		$this->feCarry25($h3, $h4);
		$this->feCarry25($h7, $h8);
		$this->feCarry26($h4, $h5);
		$this->feCarry26($h8, $h9);
		$this->feCarry19($h9, $h0);
		$this->feCarry26($h0, $h1);

		$h[0] = $h0;
		$h[1] = $h1;
		$h[2] = $h2;
		$h[3] = $h3;
		$h[4] = $h4;
		$h[5] = $h5;
		$h[6] = $h6;
		$h[7] = $h7;
		$h[8] = $h8;
		$h[9] = $h9;
	}

	function feSquare($h, $f) {
		$f0 = $f[0];
		$f1 = $f[1];
		$f2 = $f[2];
		$f3 = $f[3];
		$f4 = $f[4];
		$f5 = $f[5];
		$f6 = $f[6];
		$f7 = $f[7];
		$f8 = $f[8];
		$f9 = $f[9];
		$f0_2 = 2 * $f0;
		$f1_2 = 2 * $f1;
		$f2_2 = 2 * $f2;
		$f3_2 = 2 * $f3;
		$f4_2 = 2 * $f4;
		$f5_2 = 2 * $f5;
		$f6_2 = 2 * $f6;
		$f7_2 = 2 * $f7;
		$f5_38 = 38 * $f5;
		$f6_19 = 19 * $f6;
		$f7_38 = 38 * $f7;
		$f8_19 = 19 * $f8;
		$f9_38 = 38 * $f9;
		$f0f0 = $f0 * $f0;
		$f0f1_2 = $f0_2 * $f1;
		$f0f2_2 = $f0_2 * $f2;
		$f0f3_2 = $f0_2 * $f3;
		$f0f4_2 = $f0_2 * $f4;
		$f0f5_2 = $f0_2 * $f5;
		$f0f6_2 = $f0_2 * $f6;
		$f0f7_2 = $f0_2 * $f7;
		$f0f8_2 = $f0_2 * $f8;
		$f0f9_2 = $f0_2 * $f9;
		$f1f1_2 = $f1_2 * $f1;
		$f1f2_2 = $f1_2 * $f2;
		$f1f3_4 = $f1_2 * $f3_2;
		$f1f4_2 = $f1_2 * $f4;
		$f1f5_4 = $f1_2 * $f5_2;
		$f1f6_2 = $f1_2 * $f6;
		$f1f7_4 = $f1_2 * $f7_2;
		$f1f8_2 = $f1_2 * $f8;
		$f1f9_76 = $f1_2 * $f9_38;
		$f2f2 = $f2 * $f2;
		$f2f3_2 = $f2_2 * $f3;
		$f2f4_2 = $f2_2 * $f4;
		$f2f5_2 = $f2_2 * $f5;
		$f2f6_2 = $f2_2 * $f6;
		$f2f7_2 = $f2_2 * $f7;
		$f2f8_38 = $f2_2 * $f8_19;
		$f2f9_38 = $f2 * $f9_38;
		$f3f3_2 = $f3_2 * $f3;
		$f3f4_2 = $f3_2 * $f4;
		$f3f5_4 = $f3_2 * $f5_2;
		$f3f6_2 = $f3_2 * $f6;
		$f3f7_76 = $f3_2 * $f7_38;
		$f3f8_38 = $f3_2 * $f8_19;
		$f3f9_76 = $f3_2 * $f9_38;
		$f4f4 = $f4 * $f4;
		$f4f5_2 = $f4_2 * $f5;
		$f4f6_38 = $f4_2 * $f6_19;
		$f4f7_38 = $f4 * $f7_38;
		$f4f8_38 = $f4_2 * $f8_19;
		$f4f9_38 = $f4 * $f9_38;
		$f5f5_38 = $f5 * $f5_38;
		$f5f6_38 = $f5_2 * $f6_19;
		$f5f7_76 = $f5_2 * $f7_38;
		$f5f8_38 = $f5_2 * $f8_19;
		$f5f9_76 = $f5_2 * $f9_38;
		$f6f6_19 = $f6 * $f6_19;
		$f6f7_38 = $f6 * $f7_38;
		$f6f8_38 = $f6_2 * $f8_19;
		$f6f9_38 = $f6 * $f9_38;
		$f7f7_38 = $f7 * $f7_38;
		$f7f8_38 = $f7_2 * $f8_19;
		$f7f9_76 = $f7_2 * $f9_38;
		$f8f8_19 = $f8 * $f8_19;
		$f8f9_38 = $f8 * $f9_38;
		$f9f9_38 = $f9 * $f9_38;
		$h0 = $f0f0 + $f1f9_76 + $f2f8_38 + $f3f7_76 + $f4f6_38 + $f5f5_38;
		$h1 = $f0f1_2 + $f2f9_38 + $f3f8_38 + $f4f7_38 + $f5f6_38;
		$h2 = $f0f2_2 + $f1f1_2 + $f3f9_76 + $f4f8_38 + $f5f7_76 + $f6f6_19;
		$h3 = $f0f3_2 + $f1f2_2 + $f4f9_38 + $f5f8_38 + $f6f7_38;
		$h4 = $f0f4_2 + $f1f3_4 + $f2f2 + $f5f9_76 + $f6f8_38 + $f7f7_38;
		$h5 = $f0f5_2 + $f1f4_2 + $f2f3_2 + $f6f9_38 + $f7f8_38;
		$h6 = $f0f6_2 + $f1f5_4 + $f2f4_2 + $f3f3_2 + $f7f9_76 + $f8f8_19;
		$h7 = $f0f7_2 + $f1f6_2 + $f2f5_2 + $f3f4_2 + $f8f9_38;
		$h8 = $f0f8_2 + $f1f7_4 + $f2f6_2 + $f3f5_4 + $f4f4 + $f9f9_38;
		$h9 = $f0f9_2 + $f1f8_2 + $f2f7_2 + $f3f6_2 + $f4f5_2;

		$this->feCarry26($h0, $h1);
		$this->feCarry26($h4, $h5);
		$this->feCarry25($h1, $h2);
		$this->feCarry25($h5, $h6);
		$this->feCarry26($h2, $h3);
		$this->feCarry26($h6, $h7);
		$this->feCarry25($h3, $h4);
		$this->feCarry25($h7, $h8);
		$this->feCarry26($h4, $h5);
		$this->feCarry26($h8, $h9);
		$this->feCarry19($h9, $h0);
		$this->feCarry26($h0, $h1);

		$h[0] = $h0;
		$h[1] = $h1;
		$h[2] = $h2;
		$h[3] = $h3;
		$h[4] = $h4;
		$h[5] = $h5;
		$h[6] = $h6;
		$h[7] = $h7;
		$h[8] = $h8;
		$h[9] = $h9;
	}

	function feMul121666($h, $f) {
		$h0 = $f[0] * 121666;
		$h1 = $f[1] * 121666;
		$h2 = $f[2] * 121666;
		$h3 = $f[3] * 121666;
		$h4 = $f[4] * 121666;
		$h5 = $f[5] * 121666;
		$h6 = $f[6] * 121666;
		$h7 = $f[7] * 121666;
		$h8 = $f[8] * 121666;
		$h9 = $f[9] * 121666;

		$this->feCarry19($h9, $h0);
		$this->feCarry25($h1, $h2);
		$this->feCarry25($h3, $h4);
		$this->feCarry25($h5, $h6);
		$this->feCarry25($h7, $h8);
		$this->feCarry26($h0, $h1);
		$this->feCarry26($h2, $h3);
		$this->feCarry26($h4, $h5);
		$this->feCarry26($h6, $h7);
		$this->feCarry26($h8, $h9);

		$h[0] = $h0;
		$h[1] = $h1;
		$h[2] = $h2;
		$h[3] = $h3;
		$h[4] = $h4;
		$h[5] = $h5;
		$h[6] = $h6;
		$h[7] = $h7;
		$h[8] = $h8;
		$h[9] = $h9;
	}

	function feInvert($out, $z) {
		$t0 = new SplFixedArray(10);
		$t1 = new SplFixedArray(10);
		$t2 = new SplFixedArray(10);
		$t3 = new SplFixedArray(10);

		$this->feSquare($t0, $z);
		$this->feSquare($t1, $t0);
		for ($i = 1;$i < 2;++$i) {
			$this->feSquare($t1, $t1);
		}
		$this->feMul($t1, $z, $t1);
		$this->feMul($t0, $t0, $t1);
		$this->feSquare($t2, $t0);
		$this->feMul($t1, $t1, $t2);
		$this->feSquare($t2, $t1);
		for ($i = 1;$i < 5;++$i) {
			$this->feSquare($t2, $t2);
		}
		$this->feMul($t1, $t2, $t1);
		$this->feSquare($t2, $t1);
		for ($i = 1;$i < 10;++$i) {
			$this->feSquare($t2, $t2);
		}
		$this->feMul($t2, $t2, $t1);
		$this->feSquare($t3, $t2);
		for ($i = 1;$i < 20;++$i) {
			$this->feSquare($t3, $t3);
		}
		$this->feMul($t2, $t3, $t2);
		$this->feSquare($t2, $t2);
		for ($i = 1;$i < 10;++$i) {
			$this->feSquare($t2, $t2);
		}
		$this->feMul($t1, $t2, $t1);
		$this->feSquare($t2, $t1);
		for ($i = 1;$i < 50;++$i) {
			$this->feSquare($t2, $t2);
		}
		$this->feMul($t2, $t2, $t1);
		$this->feSquare($t3, $t2);
		for ($i = 1;$i < 100;++$i) {
			$this->feSquare($t3, $t3);
		}
		$this->feMul($t2, $t3, $t2);
		$this->feSquare($t2, $t2);
		for ($i = 1;$i < 50;++$i) {
			$this->feSquare($t2, $t2);
		}
		$this->feMul($t1, $t2, $t1);
		$this->feSquare($t1, $t1);
		for ($i = 1;$i < 5;++$i) {
			$this->feSquare($t1, $t1);
		}
		$this->feMul($out, $t1, $t0);
	}

	function scalarmult(&$out, $in, $scalar) {
		$x1 = new SplFixedArray(10);
		$x2 = new SplFixedArray(10); $x2[0] = 1;
		$z2 = new SplFixedArray(10);
		$x3 = new SplFixedArray(10);
		$z3 = new SplFixedArray(10); $z3[0] = 1;
		$tmp0  = new SplFixedArray(10);
		$tmp1 = new SplFixedArray(10);
		$e = new SplFixedArray(32);

		for ($i = 0;$i < 32;++$i) $e[$i] = $in[$i];
		$e[0] &= 248;
		$e[31] &= 127;
		$e[31] |= 64;

		$this->feFromBytes($x1, $scalar);

		for ($i = 0;$i < 10;++$i) $x3[$i] = $x1[$i];

		$swap = 0;
		for ($pos = 254; $pos >= 0; $pos--) {
			$b = ($e[$pos/8] >> ($pos&7));
			$b &= 1;
			$swap ^= $b;
			$this->feCSwap($x2, $x3, $swap);
			$this->feCSwap($z2, $z3, $swap);
			$swap = $b;

			$this->feSub($tmp0, $x3, $z3);
			$this->feSub($tmp1, $x2, $z2);
			$this->feAdd($x2, $x2, $z2);
			$this->feAdd($z2, $x3, $z3);
			$this->feMul($z3, $tmp0, $x2);
			$this->feMul($z2, $z2, $tmp1);
			$this->feSquare($tmp0, $tmp1);
			$this->feSquare($tmp1, $x2);
			$this->feAdd($x3, $z3, $z2);
			$this->feSub($z2, $z3, $z2);
			$this->feMul($x2, $tmp1, $tmp0);
			$this->feSub($tmp1, $tmp1, $tmp0);
			$this->feSquare($z2, $z2);
			$this->feMul121666($z3, $tmp1);
			$this->feSquare($x3, $x3);
			$this->feAdd($tmp0, $tmp0, $z3);
			$this->feMul($z3, $x1, $z2);
			$this->feMul($z2, $tmp1, $tmp0);
		}

		$this->feCSwap($x2, $x3, $swap);
		$this->feCSwap($z2, $z3, $swap);

		$this->feInvert($z2, $z2);
		$this->feMul($x2, $x2, $z2);
		$this->feToBytes($out, $x2);
	}

}
