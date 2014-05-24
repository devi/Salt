<?php

include "../autoload.php";

$salt = Salt::instance();

$keys = $salt->crypto_sign_keypair();

$sk = $keys[0];
$pk = $keys[1];

$msg = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

$sm = $salt->crypto_sign($msg, strlen($msg), $sk);

$plaintext = $salt->crypto_sign_open($sm, count($sm), $pk);

if ($salt->compare($msg, $plaintext) !== 1) {
	echo "invalid signature";
} else {
	echo $plaintext;
}

echo "\nmemory peak: ".memory_get_peak_usage(true)."\n";
