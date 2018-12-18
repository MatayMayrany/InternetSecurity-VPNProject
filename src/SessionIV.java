import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;

public class SessionIV {
    byte[] iv = new byte[16];
    public SessionIV(){
        Random random = new SecureRandom();
        random.nextBytes(iv);
    }

    public String encodeIV(){
        return Base64.getEncoder().encodeToString(iv);
    }

    public byte[] decodeIV(byte[] iv){
        return Base64.getDecoder().decode(iv);
    }

}
