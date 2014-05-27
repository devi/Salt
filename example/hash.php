<?php

include "../autoload.php";

$data = "BLAKE2s is optimized for 8- to 32-bit platforms and produces digests of any size between 1 and 32 bytes";

echo Salt::hash($data);
