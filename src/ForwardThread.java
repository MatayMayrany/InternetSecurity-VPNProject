/**
 * ForwardThread handles the TCP forwarding between a socket input stream (source)
 * and a socket output stream (destination). It reads the input stream and forwards
 * everything to the output stream. If some of the streams fails, the forwarding
 * is stopped and the parent thread is notified to close all its connections.
 */

import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class ForwardThread extends Thread
{
    private static final int READ_BUFFER_SIZE = 8192;

    InputStream mInputStream;
    OutputStream mOutputStream;
    ForwardServerClientThread mParent;
    private int cryptoFlag = 0;

    private SessionEncrypter sessionEncrypter;
    private SessionDecrypter sessionDecrypter;
    /**
     * Creates a new traffic forward thread specifying its input stream,
     * output stream and parent thread
     */
    public ForwardThread(ForwardServerClientThread aParent, InputStream aInputStream, OutputStream aOutputStream, SessionKey sessionKey, SessionIV sessionIV, int crypto) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        mInputStream = aInputStream;
        mOutputStream =  aOutputStream;
        mParent = aParent;
        this.cryptoFlag = crypto;
        this.sessionEncrypter = new SessionEncrypter(sessionKey, sessionIV);
        this.sessionDecrypter = new SessionDecrypter(sessionKey.encodeKey(), sessionIV.encodeIV());
    }

    /**
     * Runs the thread. Until it is possible, reads the input stream and puts read
     * data in the output stream. If reading can not be done (due to exception or
     * when the stream is at his end) or writing is failed, exits the thread.
     */
    public void run()
    {
        byte[] buffer = new byte[READ_BUFFER_SIZE];
        try {
            /* See whether we are encrypting or decrypting*/
            if (cryptoFlag == 1){
                while (true) {
                    System.out.println("ENCRYPTING");
                    int bytesRead = mInputStream.read(buffer);
                    if (bytesRead == -1)
                        break;
                    CipherOutputStream cryptOut =  this.sessionEncrypter.openCipherOutputStream(mOutputStream);
                    System.out.println(new String(buffer, "UTF-8"));
                    cryptOut.write(buffer, 0, bytesRead);
                }
            } else if (cryptoFlag == 2){
                while (true) {
                    CipherInputStream cryptIn = this.sessionDecrypter.openCipherInputStream(mInputStream);
                    System.out.println("Decrypting");
                    int bytesRead = cryptIn.read(buffer);
                    if (bytesRead == -1)
                        break;
                    System.out.println(new String(buffer, "UTF-8"));
                    mOutputStream.write(buffer, 0, bytesRead);
                }
            }else {
                System.out.println("False CryptoMode!!!");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("we are done");

        // Notify parent thread that the connection is broken and forwarding should stop
        mParent.connectionBroken();
    }
}
