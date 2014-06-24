<?php

include "../autoload.php";

$salt = Salt::instance();

// alice generate key pair
$alice = $salt->crypto_box_keypair();

$alice_privatekey = $alice[0];
$alice_publickey = $alice[1];

// bob generate key pair
$bob = $salt->crypto_box_keypair();

$bob_privatekey = $bob[0];
$bob_publickey = $bob[1];

// alice generate 24 bytes nonce
$nonce = FieldElement::fromString($salt->randombytes(24));

// alice write the message
$msg = FieldElement::fromString("Lorem ipsum dolor sit amet, consectetur adipiscing elit.");

// alice encrypt the message using her private key and bob publickey
$chipertext = $salt->crypto_box($msg, $msg->getSize(), $nonce, $bob_publickey, $alice_privatekey);

// bob decrypt the encrypted message from alice using his private key and alice public key
$plaintext = $salt->crypto_box_open($chipertext, $chipertext->getSize(), $nonce, $alice_publickey, $bob_privatekey);

// bob read the the message
echo $plaintext->toString()."\n";
