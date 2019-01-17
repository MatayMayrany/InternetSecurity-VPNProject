import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

public class SessionKey {

    SecretKey secretKey;

    public SessionKey(int keyLength) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keyLength);
        secretKey = keyGenerator.generateKey();
    }

    public SessionKey (byte[] keyBytes){
        secretKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
    }

    public String encodeKey(){
        String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        return encodedKey;
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

}
