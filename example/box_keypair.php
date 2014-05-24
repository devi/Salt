<?php

include "../autoload.php";

$keys = Salt::instance()->crypto_box_keypair();

echo "secret key:\n";
echo $keys[0]->toHex()."\n";

echo "public key:\n";
echo $keys[1]->toHex()."\n";
