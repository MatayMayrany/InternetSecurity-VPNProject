import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SessionDecrypter {
    byte[] secretKey;
    byte[] iv;

    public SessionDecrypter(String encodedKey, String encodediv){
        secretKey = Base64.getDecoder().decode(encodedKey);
        iv = Base64.getDecoder().decode(encodediv);
    }

    public CipherInputStream openCipherInputStream(InputStream inputStream) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            SecretKeySpec keySpec = new SecretKeySpec(secretKey, "AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            CipherInputStream cryptoin = new CipherInputStream(inputStream, cipher);
            return cryptoin;
    }
}
