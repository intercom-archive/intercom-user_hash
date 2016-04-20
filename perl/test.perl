use Digest::SHA qw(hmac_sha256_hex);
$digest = hmac_sha256_hex("Message", "secret");
print $digest; # aa747c502a898200f9e4fa21bac68136f886a0e27aec70ba06daf2e2a5cb5597

