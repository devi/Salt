<?php
/**
 * Salt
 *
 * A collections of [NaCl](http://nacl.cr.yp.to/) cryptography library for PHP.
 *
 * 
 * @link   https://github.com/devi/Salt
 *
 */
class Salt {

	/* Salsa20, HSalsa20, XSalsa20 */
	const salsa20_KEY    = 32;
	const salsa20_NONCE  =  8;
	const salsa20_INPUT  = 16;
	const salsa20_OUTPUT = 64;
	const salsa20_CONST  = 16;

	const hsalsa20_KEY    = 32;
	const hsalsa20_INPUT  = 16;
	const hsalsa20_OUTPUT = 32;
	const hsalsa20_CONST  = 16;

	const xsalsa20_KEY   = 32;
	const xsalsa20_NONCE = 24;

	/* Stream salsa20, salsa20_xor */
	const stream_salsa20_KEY   = 32;
	const stream_salsa20_NONCE = 24;

	/* Poly1305 */
	const poly1305_KEY    = 32;
	const poly1305_OUTPUT = 16;

	/* Onetimeauth */
	const onetimeauth_KEY    = 32;
	const onetimeauth_OUTPUT = 16;

	/* Secretbox */
	const secretbox_KEY     = 32;
	const secretbox_NONCE   = 24;
	const secretbox_ZERO    = 32;
	const secretbox_BOXZERO = 16;

	/* Scalarmult */
	const scalarmult_INPUT  = 32;
	const scalarmult_SCALAR = 32;

	/* Box */
	const box_PRIVATEKEY = 32;
	const box_PUBLICKEY  = 32;
	const box_NONCE      = 24;

	/* Sign */
	const sign_PRIVATEKEY = 64;
	const sign_PUBLICKEY  = 32;
	const sign_SIGNATURE  = 64;

	protected static $instance;

	public static function instance() {
		if (!isset(static::$instance)) {
			static::$instance = new Salt();
		}
		return static::$instance;
	}

	/**
	 * Helper function to generate random string.
	 *
	 * @param  int
	 * @return mixed
	 */
	public function randombytes($length = 32) {
		$raw = "";
		if (is_readable('/dev/urandom')) {
			$fp = true;
			if ($fp === true) {
				$fp = @fopen('/dev/urandom', 'rb');
			}
			if ($fp !== true && $fp !== false) {
				$raw = fread($fp, $length);
			}
		} else if (function_exists('mcrypt_create_iv')) {
			$raw = mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
		} else if (function_exists('openssl_random_pseudo_bytes')) {
			$raw = openssl_random_pseudo_bytes($length);
		}
		return $raw ? $raw : false;
	}

	/**
	 * Returns 1 if $x === $y
	 *
	 * @param array
	 * @param array
	 * @return int
	 */
	public function compare($x, $y) {
		$l = count($x);
		if ($l !== count($y)) return false;
		$v = 0;
		for ($i = 0; $i < $l; ++$i) {
			$v |= $x[$i] ^ $y[$i];
		}
		return $this->compareByte($v, 0);
	}

	/**
	 * Returns 1 if $x === $y and 0 otherwise.
	 * 
	 * source:
	 *   http://golang.org/pkg/crypto/subtle#ConstantTimeByteEq
	 *
	 * @param int
	 * @param int
	 * @return int
	 */
	public function compareByte($x, $y) {
		$z = ($x ^ $y) ^ 0xff;
		$z &= $z >> 4;
		$z &= $z >> 2;
		$z &= $z >> 1;
		return $z;
	}

	public function crypto_core_salsa20($in, $key, $const) {
		$out = new FieldElement(32);
		Salsa20::instance()->core($out, $in, $key, $const);
		return $out;
	}

	public function crypto_core_hsalsa20($in, $key, $const) {
		$out = new FieldElement(32);
		Salsa20::instance()->core($out, $in, $key, $const, false);
		return $out;
	}

	public function crypto_onetimeauth($in, $length, $key) {
		$p = Poly1305::instance();
		$mac = new FieldElement(16);
		$ctx = $p->init($key);
		$p->update($ctx, $in, $length);
		$p->finish($ctx, $mac);
		return $mac;
	}

	public function crypto_onetimeauth_verify($mac, $in, $length, $key) {
		$correct = $this->crypto_onetimeauth($in, $length, $key);
		return ($this->compare($correct, $mac->slice(0,16)) === 1);
	}

	public function crypto_stream_salsa20($length, $nonce, $key) {
		$out = new FieldElement($length);
		Salsa20::instance()->stream($out, false, $length, $nonce, $key);
		return $out;
	}

	public function crypto_stream_salsa20_xor($in, $length, $nonce, $key) {
		$out = new FieldElement($length);
		Salsa20::instance()->stream($out, $in, $length, $nonce, $key);
		return $out;
	}

	public function crypto_stream_xsalsa20($length, $nonce, $key) {
		$subkey = $this->crypto_core_hsalsa20($nonce, $key, Salsa20::$sigma);
		return $this->crypto_stream_salsa20($length, $nonce->slice(16), $subkey);
	}

	public function crypto_stream_xsalsa20_xor($in, $length, $nonce, $key) {
		$subkey = $this->crypto_core_hsalsa20($nonce, $key, Salsa20::$sigma);
		return $this->crypto_stream_salsa20_xor($in, $length, $nonce->slice(16), $subkey);
	}

	public function crypto_stream($length, $nonce, $key) {
		return $this->crypo_stream_xsalsa20($length, $nonce, $key);
	}

	public function crypto_stream_xor($in, $length, $nonce, $key) {
		return $this->crypo_stream_xsalsa20_xor($in, $length, $nonce, $key);
	}

	public function crypto_secretbox($message, $length, $nonce, $key) {
		if ($length < 32) return false;
		$out = $this->crypto_stream_xsalsa20_xor($message, $length, $nonce, $key);
		$mac = $this->crypto_onetimeauth($out->slice(32), $length-32, $out);
		for ($i = 0; $i < 16;++$i) {
			$out[$i] = 0;
			$out[$i+16] = $mac[$i];
		}
		return $out;
	}

	public function crypto_secretbox_open($chipertext, $length, $nonce, $key) {
		if ($length < 32) return false;
		$subkey = $this->crypto_stream_xsalsa20(32, $nonce, $key);
		if (!$this->crypto_onetimeauth_verify(
				$chipertext->slice(16),
				$chipertext->slice(32),
				$length - 32,
				$subkey
			)) return false;
		$out = $this->crypto_stream_xsalsa20_xor($chipertext, $length, $nonce, $key);
		for ($i = 0;$i < 32;++$i) $out[$i] = 0;
		return $out;
	}

	public function crypto_scalarmult($in, $scalar) {
		$out = FieldElement::fromArray(
				Curve25519::instance()->scalarmult($in, $scalar)
			);
		return $out;
	}

	public function crypto_scalarmult_base($in) {
		$out = FieldElement::fromArray(
				Curve25519::instance()->scalarbase($in)
			);
		return $out;
	}

	public function crypto_box_keypair() {
		$sk = FieldElement::fromString($this->randombytes(32));
		$pk = $this->crypto_scalarmult_base($sk);
		$ret = new SplFixedArray(2);
		$ret[0] = $sk; $ret[1] = $pk;
		return $ret;
	}

	public function crypto_box_beforenm($publickey, $privatekey) {
		$s = $this->crypto_scalarmult($privatekey, $publickey);
		return $this->crypto_core_hsalsa20(new FieldElement(16), $s, Salsa20::$sigma);
	}

	public function crypto_box_afternm($input, $length, $nonce, $key) {
		return $this->crypto_secretbox($input, $length, $nonce, $key);
	}

	public function crypto_box($input, $length, $nonce, $publickey, $privatekey) {
		$subkey = $this->crypto_box_beforenm($publickey, $privatekey);
		// pad 32 byte
		$inlen = count($input);
		$in = new FieldElement($inlen+32);
		for ($i = 0;$i < $inlen;++$i) $in[$i+32] = $input[$i];
		return $this->crypto_box_afternm($in, $length+32, $nonce, $subkey);
	}

	public function crypto_box_open_afternm($chipertext, $length, $nonce, $key) {
		return $this->crypto_secretbox_open($chipertext, $length, $nonce, $key);
	}

	public function crypto_box_open($chipertext, $length, $nonce, $publickey, $privatekey) {
		$subkey = $this->crypto_box_beforenm($publickey, $privatekey);
		return $this->crypto_box_open_afternm($chipertext, $length, $nonce, $subkey);
	}

	/**
	 * Generate private and public key.
	 *
	 * @param  string  32 byte random string
	 * @param  string
	 * @return array   private key, public key
	 */
	public function crypto_sign_keypair($seed=null, $hashAlgo="sha512") {
		if ($seed && strlen($seed) < 32) {
			throw new Exception("crypto_sign_keypair: seed must be 32 byte");
		}

		$seed = $seed ? substr($seed, 0 ,32) : $this->randombytes();

		$sk = FieldElement::fromString($seed);
		$sk->setSize(64);

		$azDigest = hash($hashAlgo, $seed, true);
		$az = FieldElement::fromString($azDigest);
		$az[0] &= 248;
		$az[31] &= 63;
		$az[31] |= 64;

		$ed = Ed25519::instance();
		$A = new GeExtended();
		$pk = new FieldElement(32);
		$ed->geScalarmultBase($A, $az);
		$ed->GeExtendedtoBytes($pk, $A);

		$sk->copy($pk, 32, 32);

		$ret = new SplFixedArray(2);
		$ret[0] = $sk; $ret[1] = $pk;
		return $ret;
	}

	/**
	 * Signs a message using the signer's private key and returns
	 * the signed message.
	 *
	 * @param  string        the message
	 * @param  int           message length
	 * @param  FieldElement  private key
	 * @param  string        hash algo, default to sha512
	 * @return FieldElement  signed message
	 */
	public function crypto_sign(
			$m, $mlen = null, FieldElement $sk, $hashAlgo = "sha512"
	){
		if (count($sk) < 64) {
			throw new Exception("crypto_sign: private key must be 64 byte");
		}

		$pk = $sk->slice(32, 32);

		$azDigest = hash($hashAlgo, $sk->slice(0,32)->toString(), true);
		$az = FieldElement::fromString($azDigest);
		$az[0] &= 248;
		$az[31] &= 63;
		$az[31] |= 64;

		$mlen = $mlen ? $mlen : strlen($m);
		$smlen = $mlen + 64;

		$sm = new FieldElement($smlen);
		$sm1 = FieldElement::fromString(substr($m, 0, $mlen));
		$sm->copy($sm1, $mlen, 64);
		$sm->copy($az, 32, 32, 32);

		$nonceDigest = hash($hashAlgo, $sm->slice(32, $mlen+32)->toString(), true);
		$nonce = FieldElement::fromString($nonceDigest);

		$sm->copy($pk, 32, 32);

		$ed = Ed25519::instance();
		$R = new GeExtended();
		$ed->scReduce($nonce);
		$ed->geScalarmultBase($R, $nonce);
		$ed->GeExtendedtoBytes($sm, $R);

		$hramDigest = hash($hashAlgo, $sm->toString(), true);
		$hram = FieldElement::fromString($hramDigest);
		$ed->scReduce($hram);

		$rest = new FieldElement(32);
		$ed->scMulAdd($rest, $hram, $az, $nonce);
		$sm->copy($rest, 32, 32);

		return $sm;
	}

	/**
	 * Validate and open signed message using signer's publickey.
	 *
	 * @param  string        signed message
	 * @param  int           signed message length
	 * @param  FieldElement  signer's public key
	 * @param  string        hash algo
	 * @return mixed
	 */
	public function crypto_sign_open(
			FieldElement $sm, $smlen,
			FieldElement $pk, $hashAlgo = "sha512"
	){
		$ed = Ed25519::instance();
		$A = new GeExtended();

		if ($smlen < 64) return false;
		if ($sm[63] & 224) return false;
		if (!$ed->geFromBytesNegateVartime($A, $pk)) return false;

		$d = 0;
		for ($i = 0;$i < 32;++$i) $d |= $pk[$i];
		if ($d === 0) return false;

		$hs = hash_init($hashAlgo);
		hash_update($hs, $sm->slice(0, 32)->toString());
		hash_update($hs, $pk->toString());
		hash_update($hs, $sm->slice(64, $smlen-64)->toString());
		$hDigest = hash_final($hs, true);

		$h = FieldElement::fromString($hDigest);
		$ed->scReduce($h);

		$R = new GeProjective();
		$rcheck = new FieldElement(32);
		$ed->geDoubleScalarmultVartime($R, $h, $A, $sm->slice(32));
		$ed->geToBytes($rcheck, $R);

		if ($ed->cryptoVerify32($rcheck, $sm) === 0) {
			$m = $sm->slice(64, $smlen-64);
			return $m->toString();
		}

		return false;
	}

	/**
	 * Generate hash value using Blake2s.
	 *
	 * @param  string
	 * @param  bool    When set to TRUE, outputs raw byte array
	 * @return mixed
	 */
	public function hash($str, $raw = false) {
		$s = SplFixedArray::fromArray(unpack("C*", $str), false);
		$b2s = new Blake2s();
		$ctx = $b2s->init();
		$b2s->update($ctx, $s, count($s));
		return $b2s->finish($ctx, $raw);
	}
}
