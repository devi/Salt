<?php
/**
 * Poly1305
 *
 * Assembled from:
 *   https://github.com/floodyberry/poly1305-donna
 *
 * 
 * @author Devi Mandiri <devi.mandiri@gmail.com>
 * @link   https://github.com/devi/Salt
 * 
 */
class Poly1305 {

	/* Lazy load */
	private static $instance;

	public static function instance() {
		if (!isset(static::$instance)) {
			static::$instance = new Poly1305();
		}
		return static::$instance;
	}

	function context() {
		$ctx = new SplFixedArray(6);
		$ctx[0] = new SplFixedArray(5);  // r
		$ctx[1] = new SplFixedArray(5);  // h
		$ctx[2] = new SplFixedArray(4);  // pad
		$ctx[3] = 0;                     // leftover
		$ctx[4] = new SplFixedArray(16); // buffer
		$ctx[5] = 0;                     // final
		return $ctx;
	}

	function load($x, $offset = 0) {
		return
			$x[$offset] |
			($x[1+$offset] << 8) |
			($x[2+$offset] << 16) |
			($x[3+$offset] << 24);
	}

	function store($x, $offset = 0, $u) {
		$x[$offset]   = $u & 0xff; $u >>= 8;
		$x[1+$offset] = $u & 0xff; $u >>= 8;
		$x[2+$offset] = $u & 0xff; $u >>= 8;
		$x[3+$offset] = $u & 0xff;
	}

	function init($key) {
		$ctx = $this->context();

		// r
		$ctx[0][0] = ($this->load($key, 0)     ) & 0x3ffffff;
		$ctx[0][1] = ($this->load($key, 3) >> 2) & 0x3ffff03;
		$ctx[0][2] = ($this->load($key, 6) >> 4) & 0x3ffc0ff;
		$ctx[0][3] = ($this->load($key, 9) >> 6) & 0x3f03fff;
		$ctx[0][4] = ($this->load($key,12) >> 8) & 0x00fffff;

		// h
		$ctx[1][0] = 0;
		$ctx[1][1] = 0;
		$ctx[1][2] = 0;
		$ctx[1][3] = 0;
		$ctx[1][4] = 0;

		// pad
		$ctx[2][0] = $this->load($key, 16);
		$ctx[2][1] = $this->load($key, 20);
		$ctx[2][2] = $this->load($key, 24);
		$ctx[2][3] = $this->load($key, 28);

		// leftover
		$ctx[3] = 0;

		// final
		$ctx[5] = 0;


		return $ctx;
	}

	function blocks($ctx, $m, $mOffset = 0, $mlen) {
		$hibit = $ctx[5] ? 0 : (1 << 24);

		// r
		$r0 = $ctx[0][0];
		$r1 = $ctx[0][1];
		$r2 = $ctx[0][2];
		$r3 = $ctx[0][3];
		$r4 = $ctx[0][4];

		$s1 = $r1 * 5;
		$s2 = $r2 * 5;
		$s3 = $r3 * 5;
		$s4 = $r4 * 5;

		// h
		$h0 = $ctx[1][0];
		$h1 = $ctx[1][1];
		$h2 = $ctx[1][2];
		$h3 = $ctx[1][3];
		$h4 = $ctx[1][4];

		while ($mlen >= 16) {
			$h0 += ($this->load($m,   $mOffset)     ) & 0x3ffffff;
			$h1 += ($this->load($m, 3+$mOffset) >> 2) & 0x3ffffff;
			$h2 += ($this->load($m, 6+$mOffset) >> 4) & 0x3ffffff;
			$h3 += ($this->load($m, 9+$mOffset) >> 6) & 0x3ffffff;
			$h4 += ($this->load($m,12+$mOffset) >> 8) | $hibit;

			$d0 = ($h0 * $r0) + ($h1 * $s4) + ($h2 * $s3) + ($h3 * $s2) + ($h4 * $s1);
			$d1 = ($h0 * $r1) + ($h1 * $r0) + ($h2 * $s4) + ($h3 * $s3) + ($h4 * $s2);
			$d2 = ($h0 * $r2) + ($h1 * $r1) + ($h2 * $r0) + ($h3 * $s4) + ($h4 * $s3);
			$d3 = ($h0 * $r3) + ($h1 * $r2) + ($h2 * $r1) + ($h3 * $r0) + ($h4 * $s4);
			$d4 = ($h0 * $r4) + ($h1 * $r3) + ($h2 * $r2) + ($h3 * $r1) + ($h4 * $r0);

			                $c = ($d0 >> 26); $h0 = $d0 & 0x3ffffff;
			$d1 += $c;      $c = ($d1 >> 26); $h1 = $d1 & 0x3ffffff;
			$d2 += $c;      $c = ($d2 >> 26); $h2 = $d2 & 0x3ffffff;
			$d3 += $c;      $c = ($d3 >> 26); $h3 = $d3 & 0x3ffffff;
			$d4 += $c;      $c = ($d4 >> 26); $h4 = $d4 & 0x3ffffff;
			$h0 += $c * 5;  $c = ($h0 >> 26); $h0 = $h0 & 0x3ffffff;
			$h1 += $c;

			$mOffset += 16;
			$mlen -= 16;
		}

		// h
		$ctx[1][0] = $h0;
		$ctx[1][1] = $h1;
		$ctx[1][2] = $h2;
		$ctx[1][3] = $h3;
		$ctx[1][4] = $h4;

	}

	function update($ctx, $m, $mlen) {
		$mOffset = 0;
		/* handle leftover */
		if ($ctx[3]) {
			
			$want = (16 - $ctx[3]);
			if ($want > $mlen) {
				$want = $mlen;
			}
			for ($i = 0; $i < $want;++$i) {
				// buffer
				$ctx[4][$ctx[3] + $i] = $m[$i+$mOffset];
			}
			$mlen -= $want;
			$mOffset += $want;
			
			$ctx[3] += $want;
			if ($ctx[3] < 16) {
				return;
			}
			$this->blocks($ctx, $ctx[4], 0, 16);
			$ctx[3] = 0;
		}

		/* process full blocks */
		if ($mlen >= 16) {
			$want = ($mlen & ~(16 - 1));
			$this->blocks($ctx, $m, $mOffset, $want);
			$mOffset += $want;
			$mlen -= $want;
		}

		/* store leftover */
		if ($mlen) {
			for ($i = 0; $i < $mlen; ++$i) {
				$ctx[4][$ctx[3] + $i] = $m[$i+$mOffset];
			}
			$ctx[3] += $mlen;
		}

	}

	function finish($ctx, $out) {
		if ($ctx[3]) {
			$i = $ctx[3];
			$ctx[4][$i++] = 1;
			for ($j = $i; $j < 16; ++$j) {
				$ctx[4][$j] = 0;
			}
			$ctx[5] = 1;
			$this->blocks($ctx, $ctx[4], 0, 16);
		}

		$h0 = $ctx[1][0];
		$h1 = $ctx[1][1];
		$h2 = $ctx[1][2];
		$h3 = $ctx[1][3];
		$h4 = $ctx[1][4];

		               $c = $h1 >> 26; $h1 = $h1 & 0x3ffffff;
		$h2 +=     $c; $c = $h2 >> 26; $h2 = $h2 & 0x3ffffff;
		$h3 +=     $c; $c = $h3 >> 26; $h3 = $h3 & 0x3ffffff;
		$h4 +=     $c; $c = $h4 >> 26; $h4 = $h4 & 0x3ffffff;
		$h0 += $c * 5; $c = $h0 >> 26; $h0 = $h0 & 0x3ffffff;
		$h1 +=     $c;

		$g0 = $h0 + 5;  $c = $g0 >> 26; $g0 &= 0x3ffffff;
		$g1 = $h1 + $c; $c = $g1 >> 26; $g1 &= 0x3ffffff;
		$g2 = $h2 + $c; $c = $g2 >> 26; $g2 &= 0x3ffffff;
		$g3 = $h3 + $c; $c = $g3 >> 26; $g3 &= 0x3ffffff;
		$g4 = $h4 + $c - (1 << 26);

		// mask = (g4 >> ((sizeof(unsigned long) * 8) - 1)) - 1;
		// is this correct ?
		$mask = (1 & ($g4 >> 0x3f)) - 1;
		$g0 &= $mask;
		$g1 &= $mask;
		$g2 &= $mask;
		$g3 &= $mask;
		$g4 &= $mask;
		$mask = ~$mask;
		$h0 = ($h0 & $mask) | $g0;
		$h1 = ($h1 & $mask) | $g1;
		$h2 = ($h2 & $mask) | $g2;
		$h3 = ($h3 & $mask) | $g3;
		$h4 = ($h4 & $mask) | $g4;

		$h0 = (($h0      ) | ($h1 << 26)) & 0xffffffff;
		$h1 = (($h1 >>  6) | ($h2 << 20)) & 0xffffffff;
		$h2 = (($h2 >> 12) | ($h3 << 14)) & 0xffffffff;
		$h3 = (($h3 >> 18) | ($h4 <<  8)) & 0xffffffff;

		$f = $h0 + $ctx[2][0]             ; $h0 = $f;
		$f = $h1 + $ctx[2][1] + ($f >> 32); $h1 = $f;
		$f = $h2 + $ctx[2][2] + ($f >> 32); $h2 = $f;
		$f = $h3 + $ctx[2][3] + ($f >> 32); $h3 = $f;

		$this->store($out,  0, $h0);
		$this->store($out,  4, $h1);
		$this->store($out,  8, $h2);
		$this->store($out, 12, $h3);

		$ctx[0][0] = 0;
		$ctx[0][1] = 0;
		$ctx[0][2] = 0;
		$ctx[0][3] = 0;
		$ctx[0][4] = 0;
		$ctx[1][0] = 0;
		$ctx[1][1] = 0;
		$ctx[1][2] = 0;
		$ctx[1][3] = 0;
		$ctx[1][4] = 0;
		$ctx[2][0] = 0;
		$ctx[2][1] = 0;
		$ctx[2][2] = 0;
		$ctx[2][3] = 0;
	}

}
