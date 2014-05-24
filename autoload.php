<?php

spl_autoload_register(
	function($class) {
		static $classes = null;
		if ($classes === null) {
			$classes = array(
				'curve25519' => '/Curve25519/Curve25519.php',
				'ed25519' => '/Ed25519/Ed25519.php',
				'fieldelement' => '/FieldElement.php',
				'gecached' => '/Ed25519/GeCached.php',
				'gecompleted' => '/Ed25519/GeCompleted.php',
				'geextended' => '/Ed25519/GeExtended.php',
				'geprecomp' => '/Ed25519/GePrecomp.php',
				'geprojective' => '/Ed25519/GeProjective.php',
				'salt' => '/Salt.php',
				'poly1305' => '/Poly1305/Poly1305.php',
				'salsa20' => '/Salsa20/Salsa20.php',
			);
		}
		$cn = strtolower($class);
		if (isset($classes[$cn])) {
			require __DIR__ . $classes[$cn];
		}
	}
);
