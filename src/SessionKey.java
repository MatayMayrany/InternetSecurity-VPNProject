import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;

public class SessionKey {

    SecretKey secretKey;
    String secretKeyString;
    KeyGenerator keyGenerator = null;

    public SessionKey(int keyLength){
        try{
            keyGenerator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException noSuchAlgorithmException){
            noSuchAlgorithmException.printStackTrace();
        }
        keyGenerator.init(keyLength);

        secretKey = keyGenerator.generateKey();
    }

    public SessionKey (String encodedKey){
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    public String encodeKey(){
        String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        return encodedKey;
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

}
