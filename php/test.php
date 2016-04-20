<?php
$s = hash_hmac('sha256', 'Message', 'secret', true);
echo bin2hex($s); // aa747c502a898200f9e4fa21bac68136f886a0e27aec70ba06daf2e2a5cb5597
?>

