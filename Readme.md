Intercom user_hash
==================
- Code for generating the user_hash value for [Intercom's Secure mode](https://docs.intercom.io/configuring-intercom/enable-secure-mode)
- Based on http://www.jokecamp.com/blog/examples-of-creating-base64-hashes-using-hmac-sha256-in-different-languages/


Remember that your secret key should never be exposed to the public
===================================================================
So Javascript (or any front end) code below should only be used for testing unless modified and used to run on the server side

Javascript
==========
```
<script src="http://crypto-js.googlecode.com/svn/tags/3.0.2/build/rollups/hmac-sha256.js"></script>
<script src="http://crypto-js.googlecode.com/svn/tags/3.0.2/build/components/enc-base64-min.js"></script>

<script>
  var hash = CryptoJS.HmacSHA256("Message", "secret");
  var hashInHex = CryptoJS.enc.Hex.stringify(hash);
  document.write(hashInHex); // aa747c502a898200f9e4fa21bac68136f886a0e27aec70ba06daf2e2a5cb5597
</script>
```

Node
====
```
const crypto = require('crypto');
const hmac = crypto.createHmac('sha256', 'secret');
hmac.update('Message');
console.log(hmac.digest('hex')); // aa747c502a898200f9e4fa21bac68136f886a0e27aec70ba06daf2e2a5cb5597
```

PHP
===
```
<?php
$s = hash_hmac('sha256', 'Message', 'secret', true);
echo bin2hex($s); // aa747c502a898200f9e4fa21bac68136f886a0e27aec70ba06daf2e2a5cb5597
?>
```

Java
====
```
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Test {
  public static void main(String[] args) {
  try {
      String secret = "secret";
      String message = "Message";

      Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
      SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
      sha256_HMAC.init(secret_key);

      byte[] hash = (sha256_HMAC.doFinal(message.getBytes()));
      StringBuffer result = new StringBuffer();
      for (byte b : hash) {
        result.append(String.format("%02X", b));
      }
      System.out.println(result.toString()); // AA747C502A898200F9E4FA21BAC68136F886A0E27AEC70BA06DAF2E2A5CB5597
    }
    catch (Exception e){
      System.out.println("Error");
    }
  }
}
```

Groovy
======
```
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;

def hmac_sha256(String secretKey, String data) {
 try {
    Mac mac = Mac.getInstance("HmacSHA256")
    SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256")
    mac.init(secretKeySpec)
    byte[] digest = mac.doFinal(data.getBytes())
    return digest
   } catch (InvalidKeyException e) {
    throw new RuntimeException("Invalid key exception while converting to HMac SHA256")
  }
}

def hash = hmac_sha256("secret", "Message")
StringBuffer result = new StringBuffer();
for (byte b : hash) {
result.append(String.format("%02X", b));
}
print(result.toString()); // AA747C502A898200F9E4FA21BAC68136F886A0E27AEC70BA06DAF2E2A5CB5597
```


C#
==
```
using System.Security.Cryptography;

namespace Test
{
	public class MyHmac
	{
		public static void Main(string[] args){
			var hmac = new MyHmac ();
			System.Console.WriteLine(hmac.CreateToken ("Message", "secret")); // AA747C502A898200F9E4FA21BAC68136F886A0E27AEC70BA06DAF2E2A5CB5597
		}
		private string CreateToken(string message, string secret)
		{
			secret = secret ?? "";
			var encoding = new System.Text.ASCIIEncoding();
			byte[] keyByte = encoding.GetBytes(secret);
			byte[] messageBytes = encoding.GetBytes(message);
			using (var hmacsha256 = new HMACSHA256(keyByte))
			{
				byte[] hashmessage = hmacsha256.ComputeHash(messageBytes);

				var sb = new System.Text.StringBuilder();
				for (var i = 0; i <= hashmessage.Length - 1; i++)
				{
					sb.Append(hashmessage[i].ToString("X2"));
				}
				return sb.ToString();
			}
		}
	}
}
```

Objective C
===========
```
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonHMAC.h>

NSData *hmacForKeyAndData(NSString *key, NSString *data)
{
    const char *cKey  = [key cStringUsingEncoding:NSASCIIStringEncoding];
    const char *cData = [data cStringUsingEncoding:NSASCIIStringEncoding];
    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, cKey, strlen(cKey), cData, strlen(cData), cHMAC);
    return [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)];
}

// http://stackoverflow.com/a/9084784
NSString *hexadecimalString(NSData *data){
    /* Returns hexadecimal string of NSData. Empty string if data is empty.   */

    const unsigned char *dataBuffer = (const unsigned char *)[data bytes];

    if (!dataBuffer)
        return [NSString string];

    NSUInteger          dataLength  = [data length];
    NSMutableString     *hexString  = [NSMutableString stringWithCapacity:(dataLength * 2)];

    for (int i = 0; i < dataLength; ++i)
        [hexString appendString:[NSString stringWithFormat:@"%02lx", (unsigned long)dataBuffer[i]]];

    return [NSString stringWithString:hexString];
}
int main (int argc, const char * argv[])
{
    @autoreleasepool {
        NSLog(@"%@", hexadecimalString(hmacForKeyAndData(@"secret", @"Message")));
    }
    return 0;
}
```

Go
==
```
package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
)

func ComputeHmac256(message string, secret string) string {
    key := []byte(secret)
    h := hmac.New(sha256.New, key)
    h.Write([]byte(message))
    return hex.EncodeToString(h.Sum(nil))
}

func main() {
    fmt.Println(ComputeHmac256("Message", "secret")) // aa747c502a898200f9e4fa21bac68136f886a0e27aec70ba06daf2e2a5cb5597
}
```


Ruby
====
```
require 'openssl'

OpenSSL::HMAC.hexdigest('sha256', "secret", "Message") # aa747c502a898200f9e4fa21bac68136f886a0e27aec70ba06daf2e2a5cb5597
```

Python (2.x)
============
```
import hashlib
import hmac

KEY = "secret"
MESSAGE = "Message"
result = hmac.new(KEY, MESSAGE, hashlib.sha256).hexdigest()
print result # aa747c502a898200f9e4fa21bac68136f886a0e27aec70ba06daf2e2a5cb5597
```

Python (3.x)
============
```
import hashlib
import hmac

KEY = "secret"
KEY_BYTES=KEY.encode('ascii')
MESSAGE = "Message"
MESSAGE_BYTES=MESSAGE.encode('ascii')
result = hmac.new(KEY_BYTES, MESSAGE_BYTES, hashlib.sha256).hexdigest()

print (result) # aa747c502a898200f9e4fa21bac68136f886a0e27aec70ba06daf2e2a5cb5597
```

Perl
====
```
use Digest::SHA qw(hmac_sha256_hex);
$digest = hmac_sha256_hex("Message", "secret");
print $digest; # aa747c502a898200f9e4fa21bac68136f886a0e27aec70ba06daf2e2a5cb5597
```

Swift
=====
```
// Add
// #import <CommonCrypto/CommonHMAC.h>
// to the bridging Objective-C bridging header.

import Foundation

enum CryptoAlgorithm {
    case MD5, SHA1, SHA224, SHA256, SHA384, SHA512

    var HMACAlgorithm: CCHmacAlgorithm {
        var result: Int = 0
        switch self {
        case .MD5:      result = kCCHmacAlgMD5
        case .SHA1:     result = kCCHmacAlgSHA1
        case .SHA224:   result = kCCHmacAlgSHA224
        case .SHA256:   result = kCCHmacAlgSHA256
        case .SHA384:   result = kCCHmacAlgSHA384
        case .SHA512:   result = kCCHmacAlgSHA512
        }
        return CCHmacAlgorithm(result)
    }

    var digestLength: Int {
        var result: Int32 = 0
        switch self {
        case .MD5:      result = CC_MD5_DIGEST_LENGTH
        case .SHA1:     result = CC_SHA1_DIGEST_LENGTH
        case .SHA224:   result = CC_SHA224_DIGEST_LENGTH
        case .SHA256:   result = CC_SHA256_DIGEST_LENGTH
        case .SHA384:   result = CC_SHA384_DIGEST_LENGTH
        case .SHA512:   result = CC_SHA512_DIGEST_LENGTH
        }
        return Int(result)
    }
}

extension String {

    func hmac(algorithm: CryptoAlgorithm, key: String) -> String {
        let str = self.cStringUsingEncoding(NSUTF8StringEncoding)
        let strLen = Int(self.lengthOfBytesUsingEncoding(NSUTF8StringEncoding))
        let digestLen = algorithm.digestLength
        let result = UnsafeMutablePointer<CUnsignedChar>.alloc(digestLen)
        let keyStr = key.cStringUsingEncoding(NSUTF8StringEncoding)
        let keyLen = Int(key.lengthOfBytesUsingEncoding(NSUTF8StringEncoding))

        CCHmac(algorithm.HMACAlgorithm, keyStr!, keyLen, str!, strLen, result)

        let digest = stringFromResult(result, length: digestLen)

        result.dealloc(digestLen)

        return digest
    }

    private func stringFromResult(result: UnsafeMutablePointer<CUnsignedChar>, length: Int) -> String {
        var hash = NSMutableString()
        for i in 0..<length {
            hash.appendFormat("%02x", result[i])
        }
        return String(hash)
    }

}


print("Message".hmac(CryptoAlgorithm.SHA256, key: "secret")) //aa747c502a898200f9e4fa21bac68136f886a0e27aec70ba06daf2e2a5cb5597
```
