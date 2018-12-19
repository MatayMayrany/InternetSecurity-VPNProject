
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


public class SessionEncrypter {
    private SessionKey sessionKey;
    private Cipher cipher;
    private SessionIV sessionIV;

    public SessionEncrypter(SessionKey sessionKeyCons, SessionIV sessionIVCons) throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
        this.sessionKey = sessionKeyCons;
        this.sessionIV = sessionIVCons;
    }
    public CipherOutputStream openCipherOutputStream(OutputStream outputStream) throws InvalidAlgorithmParameterException, InvalidKeyException {
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey.getSecretKey(), this.sessionIV.getIvSpec());
            return new CipherOutputStream(outputStream, cipher);
    }

}
