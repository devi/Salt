<?php
/**
 * Blake2s
 *
 * 
 * PHP implementation of BLAKE2s cryptographic hash function.
 * 
 * Assembled from:
 *  - https://blake2.net
 *
 * @author Devi Mandiri <devi.mandiri@gmail.com>
 */
class Blake2s {

	const BLOCKBYTES =   64; // digest length
	const OUTBYTES   =   32; // maximum output length
	const KEYBYTES   =   32; // maximum length of key

	protected static $IV = array(
		0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
		0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
	);

	protected static $sigma = array(
		array( 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15),
		array(14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3),
		array(11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4),
		array( 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8),
		array( 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13),
		array( 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9),
		array(12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11),
		array(13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10),
		array( 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5),
		array(10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0)
	);

	protected function load32($x, $offset = 0) {
		return
			$x[$offset] |
			($x[1+$offset] << 8) |
			($x[2+$offset] << 16) |
			($x[3+$offset] << 24);
	}

	protected function store32($x, $offset = 0, $u) {
		$x[$offset]   = $u & 0xff; $u >>= 8;
		$x[1+$offset] = $u & 0xff; $u >>= 8;
		$x[2+$offset] = $u & 0xff; $u >>= 8;
		$x[3+$offset] = $u & 0xff;
	}

	protected function rotr32($x, $y) {
		return ($x >> $y) | ($x << (32 - $y));
	}

	protected function context($p) {
		$ctx = new SplFixedArray(6);
		$ctx[0] = new SplFixedArray(8); // h
		$ctx[1] = new SplFixedArray(2); // t
		$ctx[2] = new SplFixedArray(2); // f
		$ctx[3] = new SplFixedArray(2*Blake2s::BLOCKBYTES); // buf
		$ctx[4] = 0; // buflen

		for ($i = 0;$i < 8;++$i) {
			$ctx[0][$i] = static::$IV[$i] ^ $this->load32($p, $i*4);
		}

		return $ctx;
	}

	/**
	 * Initialize Blake2s context.
	 *
	 * @param  string
	 * @param  int
	 * @return array   Blake2s context
	 */
	public function init($key = null) {
		$keylen = strlen($key);
		if ($keylen > Blake2s::KEYBYTES) {
			$keylen = Blake2s::KEYBYTES;
		}

		$p = new SplFixedArray(32);
		$p[0] = Blake2s::OUTBYTES; // digest_length 
		$p[1] = $keylen;           // key_length
		$p[2] = 1;                 // fanout
		$p[3] = 1;                 // depth

		$ctx = $this->context($p);

		if ($key) {
			$block = SplFixedArray::fromArray(
				unpack("C*", substr($key, 0, $keylen)),
				false
			);
			$block->setSize(Blake2s::BLOCKBYTES);
			$this->update($ctx, $block, Blake2s::BLOCKBYTES);
		}

		return $ctx;
	}

	/**
	 * G function of BLAKE2s
	 */
	protected function blocks($v, $m, $r, $i, $a, $b, $c, $d) {
		$v[$a] = ($v[$a] + $v[$b] + $m[static::$sigma[$r][2*$i]]) & 0xffffffff;
		$v[$d] = $this->rotr32($v[$d] ^ $v[$a], 16) & 0xffffffff;
		$v[$c] = ($v[$c] + $v[$d]) & 0xffffffff;
		$v[$b] = $this->rotr32($v[$b] ^ $v[$c], 12) & 0xffffffff;
		$v[$a] = ($v[$a] + $v[$b] + $m[static::$sigma[$r][2*$i+1]]) & 0xffffffff;
		$v[$d] = $this->rotr32($v[$d] ^ $v[$a], 8) & 0xffffffff;
		$v[$c] = ($v[$c] + $v[$d]) & 0xffffffff;
		$v[$b] = $this->rotr32($v[$b] ^ $v[$c], 7) & 0xffffffff;
	}

	protected function compress($ctx, $block) {
		$m = new SplFixedArray(16);
		$v = new SplFixedArray(16);

		for ($i = 0;$i < 16;++$i) {
			$m[$i] = $this->load32($block, $i*4);
		}

		for ($i = 0;$i < 8;++$i) {
			$v[$i] = $ctx[0][$i];
		}

		$v[ 8] = static::$IV[0];
		$v[ 9] = static::$IV[1];
		$v[10] = static::$IV[2];
		$v[11] = static::$IV[3];
		$v[12] = ($ctx[1][0] ^ static::$IV[4]) & 0xffffffff;
		$v[13] = ($ctx[1][1] ^ static::$IV[5]) & 0xffffffff;
		$v[14] = ($ctx[2][0] ^ static::$IV[6]) & 0xffffffff;
		$v[15] = ($ctx[2][1] ^ static::$IV[7]) & 0xffffffff;

		for ($i = 0;$i < 10;++$i) {
			$this->blocks($v, $m, $i, 0, 0, 4,  8, 12);
			$this->blocks($v, $m, $i, 1, 1, 5,  9, 13);
			$this->blocks($v, $m, $i, 2, 2, 6, 10, 14);
			$this->blocks($v, $m, $i, 3, 3, 7, 11, 15);
			$this->blocks($v, $m, $i, 4, 0, 5, 10, 15);
			$this->blocks($v, $m, $i, 5, 1, 6, 11, 12);
			$this->blocks($v, $m, $i, 6, 2, 7,  8, 13);
			$this->blocks($v, $m, $i, 7, 3, 4,  9, 14);
		}

		for ($i = 0;$i < 8;++$i) {
			$ctx[0][$i] = $ctx[0][$i] ^ $v[$i] ^ $v[$i+8];
		}
	}

	protected function incrementCounter($ctx, $inc) {
		$ctx[1][0] = $ctx[1][0] + $inc;
		$ctx[1][1] = $ctx[1][1] + ($ctx[1][0] < $inc);
	}

	/**
	 * Fill context with data
	 *
	 * @param  array  Blake2s context
	 * @param  array  byte array int presentation
	 * @param  int    data length
	 * @return void
	 */
	public function update($ctx, $in, $inlen) {
		$offset = 0;
		while ($inlen > 0) {
			$left = $ctx[4];
			$fill = 2 * Blake2s::BLOCKBYTES - $left;

			if ($inlen > $fill) {
				for ($i = 0;$i < $fill;++$i) {
					$ctx[3][$i+$left] = $in[$i+$offset];
				}

				$ctx[4] += $fill;

				$this->incrementCounter($ctx, Blake2s::BLOCKBYTES);
				$this->compress($ctx, $ctx[3]);

				for ($i = 0;$i < Blake2s::BLOCKBYTES;++$i) {
					$ctx[3][$i] = $ctx[3][$i+Blake2s::BLOCKBYTES];
				}

				$ctx[4] -= Blake2s::BLOCKBYTES;
				$offset += $fill;
				$inlen -= $fill;
			} else {
				for ($i = 0;$i < $inlen;++$i) {
					$ctx[3][$i+$left] = $in[$i+$offset];
				}
				$ctx[4] += $inlen;
				$offset += $inlen;
				$inlen -= $inlen;
			}
		}
	}

	/**
	 * Pack available data from context.
	 * 
	 * @param  array  Blake2s context
	 * @param  int    output length
	 * @param  bool   When set to TRUE, outputs raw byte array
	 * @return mixed
	 */
	public function finish($ctx, $raw = false) {
		if ($ctx[4] > Blake2s::BLOCKBYTES) {
			$this->incrementCounter($ctx, Blake2s::BLOCKBYTES);
			$this->compress($ctx, $ctx[3]);
			$ctx[4] -= Blake2s::BLOCKBYTES;
			for ($i = 0;$i < $ctx[4];++$i) {
				$ctx[3][$i] = $ctx[3][$i+Blake2s::BLOCKBYTES];
			}
		}

		$this->incrementCounter($ctx, $ctx[4]);
		$ctx[2][0] = 0xffffffff;

		$j = (2*Blake2s::BLOCKBYTES) - $ctx[4];
		for ($i = 0;$i < $j;++$i) {
			$ctx[3][$i+$ctx[4]] = 0;
		}

		$this->compress($ctx, $ctx[3]);

		$buffer = new SplFixedArray(Blake2s::OUTBYTES);
		for ($i = 0;$i < 8;++$i) {
			$this->store32($buffer, $i*4, $ctx[0][$i]);
		}

		if ($raw) $buffer;

		$out = "";
		$hextable = "0123456789abcdef";
		for ($i = 0;$i < Blake2s::OUTBYTES;++$i) {
			$c = $buffer[$i];
			$out .= $hextable[$c>>4];
			$out .= $hextable[$c&0x0f];
		}
		return $out;
	}

}
