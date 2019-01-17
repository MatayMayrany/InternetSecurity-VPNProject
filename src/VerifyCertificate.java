import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.*;
import java.util.Base64;

public class VerifyCertificate {
    public static CertificateFactory fact;
    public static FileInputStream caFile;
    public static X509Certificate caCer;
    public static PublicKey caCerPublicKey;
    public static Arguments arguments;
    public static String LINE_SEPARATOR = System.getProperty("line.separator");
    public static String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static String END_CERT = "-----END CERTIFICATE-----";
    public static String currentDirectory = System.getProperty("user.dir");


    public static boolean verifyCertificates(X509Certificate verifyCer, String caPath) throws FileNotFoundException, CertificateException {
        // check dates
        fact = CertificateFactory.getInstance("X.509");
        caFile = new FileInputStream(currentDirectory + "/" + caPath);
        //caFile = new FileInputStream(arguments.get("cacert"));
        caCer = (X509Certificate) fact.generateCertificate(caFile);
        caCerPublicKey = caCer.getPublicKey();
        try{
            verifyCer.checkValidity();
            verifyCer.verify(caCerPublicKey);
            return true;
        } catch (Exception e){
            System.err.println(e);
        }
        return false;
    }
    /*get encoded string certificate from path argument*/
    public static String getEncodedCertificate(String certPath) throws Exception {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        FileInputStream CAIs = new FileInputStream(certPath);
        X509Certificate certificate = (X509Certificate) fact.generateCertificate(CAIs);

//        String LINE_SEPARATOR = System.getProperty("line.separator");
//        String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
//        String END_CERT = "-----END CERTIFICATE-----";

        //Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes());

        byte[] rawCrtText = certificate.getEncoded();
        return new String(Base64.getEncoder().encode(rawCrtText));
       // return BEGIN_CERT + LINE_SEPARATOR + encodedCertText + LINE_SEPARATOR + END_CERT;
    }
    /*get encoded string certificate from path argument*/
    public static X509Certificate getCertificateFromEncodedString(String cert) throws CertificateException {
        byte[] derCert = Base64.getDecoder().decode(cert);
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        InputStream is = new ByteArrayInputStream(derCert);
        X509Certificate certificate = (X509Certificate) fact.generateCertificate(is);
        return certificate;
    }


}
