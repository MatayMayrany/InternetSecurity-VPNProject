
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class HandshakeCrypto {
    public static CertificateFactory fact;
    public static X509Certificate certificate;
    public static FileInputStream certifcateFile;
    public static FileInputStream privateKeyFile;
    // encrypts data given text and key to return cipher
    public static byte[] encrypt(byte[] plainText, Key key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedData = cipher.doFinal(plainText);
        return encryptedData;
    }
    // decrypts data given cipher text and key to return plain text
    public static byte[] decrypt(byte[] cipherText, Key key) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plainData = cipher.doFinal(cipherText);
        return plainData;
    }
    //extracts public key from a certificate file
    public static PublicKey getPublicKeyFromCertFile(String certFile) throws CertificateException, FileNotFoundException {
        fact = CertificateFactory.getInstance("X.509");
        certifcateFile = new FileInputStream(certFile);
        certificate = (X509Certificate) fact.generateCertificate(certifcateFile);
        return certificate.getPublicKey();
    }

    //extracts private key from a Private Key file
    public static PrivateKey getPrivateKeyFromKeyFile(String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, NoSuchProviderException {
        Path path = Paths.get(filePath);
        byte[] privKeyBytes = Files.readAllBytes(path);
        // Change pem files to der encoding so we can make a java object
        String type = getFileExtension(filePath);
        if (type.equals("pem")){
            String temp = new String(privKeyBytes);
            String privKeyPEM = temp.replace("-----BEGIN PRIVATE KEY-----\n", "");
            privKeyPEM = privKeyPEM.replace("-----END PRIVATE KEY-----", "");
            Base64 b64 = new Base64();
            privKeyBytes = b64.decode(privKeyPEM);

        }
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    public static String getFileExtension(String fullName) {
        String fileName = new File(fullName).getName();
        int dotIndex = fileName.lastIndexOf('.');
        return (dotIndex == -1) ? "" : fileName.substring(dotIndex + 1);
    }



}
