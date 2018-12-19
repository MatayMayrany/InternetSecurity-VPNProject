import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;

public class SessionIV {
    private static byte[] iv = new byte[16];
    public SessionIV(){
        Random random = new SecureRandom();
        random.nextBytes(iv);
    }

    public SessionIV (byte[] iv){
        this.iv = Base64.getDecoder().decode(iv);
    }

    public IvParameterSpec getIvSpec(){
        return new IvParameterSpec(iv);
    }

    public  String encodeIV(){
        return Base64.getEncoder().encodeToString(iv);
    }

//    public byte[] decodeIV(byte[] iv){
//        return Base64.getDecoder().decode(iv);
//    }

}
