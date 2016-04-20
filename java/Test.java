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

