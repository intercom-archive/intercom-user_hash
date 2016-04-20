import hashlib
import hmac

KEY = "secret"
MESSAGE = "Message"
result = hmac.new(KEY, MESSAGE, hashlib.sha256).hexdigest()
print result # aa747c502a898200f9e4fa21bac68136f886a0e27aec70ba06daf2e2a5cb5597

