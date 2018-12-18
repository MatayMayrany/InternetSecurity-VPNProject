/**
 * Port forwarding client. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server
 * and adapted for IK2206.
 *
 * See original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */


import java.io.*;
import java.lang.AssertionError;
import java.lang.IllegalArgumentException;
import java.lang.Integer;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Base64;

public class ForwardClient
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardClient";
    private static Arguments arguments;
    public static HandshakeMessage handshakeMessage;
    private static int serverPort;
    private static String serverHost;
    private static PrivateKey clientPrivateKey;
    static String ENCODING = "UTF-8";


    private static final String MESSAGETYPE = "MessageType";
    private static final String CERTIFCATE = "Certificate";
    private static final String CLIENTHELLO = "ClientHello";
    private static final String SERVERTHELLO = "ServerHello";
    private static final String FORWARD = "Forward";
    private static final String SESSION = "Session";
    private static final String SESSION_KEY = "SessionKey";
    private static final String SESSION_IV = "SessionIV";
    private static final String TARGET_HOST = "TargetHost";
    private static final String TARGET_PORT = "TargetPort";


    private static void doHandshake() throws Exception {

        /* Connect to forward server server */
        System.out.println("Connect to " +  arguments.get("handshakehost") + ":" + Integer.parseInt(arguments.get("handshakeport")));
        Socket socket = new Socket(arguments.get("handshakehost"), Integer.parseInt(arguments.get("handshakeport")));

        /* This is where the handshake should take place */

        /*send ClientHello Message consisting of type identifier and clients certificate*/
        HandshakeMessage clientHello = sendClientHelloMessage();
        if(clientHello!=null){
            clientHello.send(socket);
        } else {
            System.err.println("Failed to send ClientHello, Closing Connection...");
            socket.close();
        }
//        HandshakeMessage clientHello = new HandshakeMessage();
//        clientHello.putParameter("MessageType", "ClientHello");
//        //get encoded certificate and add it as parameter
//        String encodedUserCertificate = VerifyCertificate.getEncodedCertificate(arguments.get("usercert"));
//        if(encodedUserCertificate!=null){
//            clientHello.putParameter("Certificate", encodedUserCertificate);
//            clientHello.send(socket);
//        }else {
//            System.err.println("Couldn't get the certificate!");
//            socket.close();
//        }

        /*Wait for the server to respond with their own ServerHello message*/

        System.out.println("Waiting for serverHello msg...");
        HandshakeMessage serverHello = new HandshakeMessage();
        serverHello.recv(socket);
        boolean serverHelloDone = validateServerHello(serverHello);
        /*Check the message parameters and verify the servers certificate*/
//        boolean verified = false;
//        if(serverHello.getParameter("MessageType").equals("ServerHello")){
//            if (VerifyCertificate.verifyCertificates(VerifyCertificate.getCertificateFromEncodedString(serverHello.getParameter("Certificate")))){
//                System.out.println("The server certificate is verified and signed by the CA");
//                verified = true;
//            }else{
//                System.err.println("BAD Certificate, Closing Connection..");
//                socket.close();
//            }
//        }else {
//            System.err.println("message type wasn't ServerHello, Closing Connection..");
//            socket.close();
//        }
//        System.out.println("Client and server Hello done");

        /*if we verified successfully we move on to the ForwardMessage*/
        if(serverHelloDone){
            HandshakeMessage forwardMessage = sendForwardMessage();
//            HandshakeMessage forwardMessage = new HandshakeMessage();
//            forwardMessage.putParameter(MESSAGETYPE, 	FORWARD);
//            forwardMessage.putParameter(TARGET_HOST	, Handshake.targetHost);
//            forwardMessage.putParameter(TARGET_PORT, Integer.toString(Handshake.targetPort));
            if (handshakeMessage!=null){
                forwardMessage.send(socket);
                System.out.println("sent The ForwardMessage...");
            }else {
                System.err.println("Failed to send ForwardMessage, Closing Connection...");
                socket.close();
            }

        }else {
            System.err.println("Failed to validate Server, Closing Connection...");
            socket.close();
        }
        /*Wait for the final server to respond with their SessionMessage and check the parameters*/
        System.out.println("Waiting for serverHello msg...");
        HandshakeMessage sessionMessage = new HandshakeMessage();
        sessionMessage.recv(socket);
        if(sessionMessage.getParameter(MESSAGETYPE).equals(SESSION)){
            System.out.println("Recieved The SessionMessage...");
            //get the encrypted session key and iv and decode + decrypt them
            clientPrivateKey = HandshakeCrypto.getPrivateKeyFromKeyFile(arguments.get("key"));

            /* we need to do this to recieved key and iv
             decode with base64 to string -> decrypt with our private Key -> decode the SessionIv.encodeIV() */
            String messageKey = sessionMessage.getParameter(SESSION_KEY);
            byte[] sessionKeybytes = HandshakeCrypto.decrypt(Base64.getDecoder().decode(messageKey), clientPrivateKey);
            String sessionKeyEncodedString = new String(sessionKeybytes, ENCODING);
            SessionKey sessionKey = new SessionKey(sessionKeyEncodedString); // gets a session key from it's encoded version

            /* we get encrypted bytes and decrypt them*/
            String messageIV = sessionMessage.getParameter(SESSION_IV);
            System.out.println(messageIV);
            byte[] encodedMessageBytes = Base64.getEncoder().encode(messageIV.getBytes());
            byte[] decodedMessageBytes = Base64.getDecoder().decode(encodedMessageBytes);
            byte[] DecryptedsessionIVbytes = HandshakeCrypto.decrypt(Base64.getDecoder().decode(decodedMessageBytes), clientPrivateKey);
            SessionIV sessionIV = new SessionIV(DecryptedsessionIVbytes);

            //Start the session
            System.out.println("Handshake complete! Closing this connection and Starting session...");
            socket.close();
            startSession(sessionKey, sessionIV);
        } else {
            System.out.println("Wrong messageType, Should be Session, closing connection...");
            socket.close();
        }

        socket.close();

        /*
         * Fake the handshake result with static parameters.
         */

        /* This is to where the ForwardClient should connect.
         * The ForwardServer creates a socket
         * dynamically and communicates the address (hostname and port number)
         * to ForwardClient during the handshake (ServerHost, ServerPort parameters).
         * Here, we use a static address instead.
         */
        serverHost = Handshake.serverHost;
        serverPort = Handshake.serverPort;
    }
    /*method for creating the first message in the Handshake Protocol*/

    public static HandshakeMessage sendClientHelloMessage(){
        handshakeMessage = new HandshakeMessage();
        handshakeMessage.putParameter(MESSAGETYPE, CLIENTHELLO);
        //get encoded certificate and add it as parameter
        String encodedUserCertificate = null;
        try {
            encodedUserCertificate = VerifyCertificate.getEncodedCertificate(arguments.get("usercert"));
        } catch (Exception e) {
            System.err.println(e);
        }
        if(encodedUserCertificate!=null){
            handshakeMessage.putParameter(CERTIFCATE, encodedUserCertificate);
            return handshakeMessage;
        }else {
            System.err.println("Couldn't get the certificate!");
            return null;
        }
    }

    /* method for Validating the serverHello message */

    public static boolean validateServerHello(HandshakeMessage serverHello){
        /*Check the message parameters and verify the servers certificate*/
        boolean verified = false;
        if(serverHello.getParameter(MESSAGETYPE).equals(SERVERTHELLO)){
            try {
                if (VerifyCertificate.verifyCertificates(VerifyCertificate.getCertificateFromEncodedString(serverHello.getParameter(CERTIFCATE)))){
                    System.out.println("The server certificate is verified and signed by the CA");
                    return true;
                }else{
                    System.err.println("BAD Certificate!!");
                }
            } catch (Exception e) {
                System.err.println(e);
            }
        }else {
            System.err.println("message type wasn't ServerHello!");
        }
        return false;
    }

    /* Method for 3rd step, creates the ForwardMessage to send */

    public static HandshakeMessage sendForwardMessage(){
        handshakeMessage = new HandshakeMessage();
        handshakeMessage.putParameter(MESSAGETYPE, 	FORWARD);
        handshakeMessage.putParameter(TARGET_HOST	, Handshake.targetHost);
        handshakeMessage.putParameter(TARGET_PORT, Integer.toString(Handshake.targetPort));
        return handshakeMessage;
    }



    /*
     * Let user know that we are waiting
     */
    private static void tellUser(ServerSocket listensocket) throws UnknownHostException {
        System.out.println("Client forwarder to target " + arguments.get("targethost") + ":" + arguments.get("targetport"));
        System.out.println("Waiting for incoming connections at " +
                InetAddress.getLocalHost().getHostAddress() + ":" + listensocket.getLocalPort());
    }

    public static void startSession(SessionKey sessionKey, SessionIV sessionIV){

    }
    /*
     * Set up client forwarder.
     * Run handshake negotiation, then set up a listening socket and wait for user.
     * When user has connected, start port forwarder thread.
     */
    static public void startForwardClient() throws Exception {

        doHandshake();

        // Wait for client. Accept one connection.

        ForwardServerClientThread forwardThread;
        ServerSocket listensocket;

        try {
            /* Create a new socket. This is to where the user should connect.
             * ForwardClient sets up port forwarding between this socket
             * and the ServerHost/ServerPort learned from the handshake */
            listensocket = new ServerSocket();
            /* Let the system pick a port number */
            listensocket.bind(null);
            /* Tell the user, so the user knows where to connect */
            tellUser(listensocket);

            Socket clientSocket = listensocket.accept();
            String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
            log("Accepted client from " + clientHostPort);

            forwardThread = new ForwardServerClientThread(clientSocket, serverHost, serverPort);
            forwardThread.start();

        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(e);
            throw e;
        }
    }

    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public static void log(String aMessage)
    {
        if (ENABLE_LOGGING)
            System.out.println(aMessage);
    }

    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--targethost=<hostname>");
        System.err.println(indent + "--targetport=<portnumber>");
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");
    }

    /**
     * Program entry point. Reads arguments and run
     * the forward server
     */
    public static void main(String[] args)
    {
        try {
            arguments = new Arguments();
            arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
            arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
            arguments.loadArguments(args);
            if (arguments.get("targetport") == null || arguments.get("targethost") == null) {
                throw new IllegalArgumentException("Target not specified");
            }
        } catch(IllegalArgumentException ex) {
            System.out.println(ex);
            usage();
            System.exit(1);
        }
        try {
            startForwardClient();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
