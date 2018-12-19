
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

public class SessionEncrypter {
    private SessionKey sessionKey;
    private Cipher cipher;
    private SessionIV sessionIV;

    public SessionEncrypter(SessionKey sessionKeyCons, SessionIV sessionIVCons) throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
        this.sessionKey = sessionKeyCons;
        this.sessionIV = sessionIVCons;
        //System.out.println(sessionIVCons.encodeIV() + "\n" + sessionKeyCons.encodeKey());
    }
    public CipherOutputStream openCipherOutputStream(OutputStream outputStream) throws InvalidAlgorithmParameterException, InvalidKeyException {
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey.getSecretKey(), this.sessionIV.getIvSpec());
            return new CipherOutputStream(outputStream, cipher);
    }

//    public String encodeKey(){
//        return sessionKey.encodeKey();
//    }
//
//    public String encodeIV(){
//        return Base64.getEncoder().encodeToString(iv);
//    }

}
