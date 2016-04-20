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

