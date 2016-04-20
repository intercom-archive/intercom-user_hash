require 'openssl'

print OpenSSL::HMAC.hexdigest('sha256', "secret", "Message") # aa747c502a898200f9e4fa21bac68136f886a0e27aec70ba06daf2e2a5cb5597
