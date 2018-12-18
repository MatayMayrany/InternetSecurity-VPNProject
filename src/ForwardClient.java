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
    private static int serverPort;
    private static String serverHost;
    private static PrivateKey clientPrivateKey;
    static String ENCODING = "UTF-8";


    private static void doHandshake() throws Exception {

        /* Connect to forward server server */
        System.out.println("Connect to " +  arguments.get("handshakehost") + ":" + Integer.parseInt(arguments.get("handshakeport")));
        Socket socket = new Socket(arguments.get("handshakehost"), Integer.parseInt(arguments.get("handshakeport")));

        /* This is where the handshake should take place */

        /*send HelloMessage consisting of type identifier and clients certificate*/
        HandshakeMessage clientHello = new HandshakeMessage();
        clientHello.putParameter("MessageType", "ClientHello");
        //get encoded certificate and add it as parameter
        String encodedUserCertificate = VerifyCertificate.getEncodedCertificate(arguments.get("usercert"));
        if(encodedUserCertificate!=null){
            System.out.println(encodedUserCertificate);
            clientHello.putParameter("Certificate", encodedUserCertificate);
            clientHello.send(socket);
        }else {
            System.err.println("Couldn't get the certificate!");
            socket.close();
        }

        /*Wait for the server to respond with their own ServerHello message*/

        System.out.println("Waiting for serverHello msg...");
        HandshakeMessage serverHello = new HandshakeMessage();
        serverHello.recv(socket);
        /*Check the message parameters and verify the servers certificate*/
        boolean verified = false;
        if(serverHello.getParameter("MessageType").equals("ServerHello")){
            if (VerifyCertificate.verifyCertificates(VerifyCertificate.getCertificateFromEncodedString(clientHello.getParameter("Certificate")))){
                System.out.println("The server certificate is verified and signed by the CA");
                verified = true;
            }else{
                System.err.println("BAD Certificate, Closing Connection..");
                socket.close();
            }
        }else {
            System.err.println("message type wasn't ServerHello, Closing Connection..");
            socket.close();
        }
        System.out.println("Client and server Hello done");

        /*if we verified successfully we move on to the ForwardMessage*/
        if(verified){
            HandshakeMessage forwardMessage = new HandshakeMessage();
            forwardMessage.putParameter("MessageType", 	"Forward");
            forwardMessage.putParameter("TargetHost"	, Handshake.targetHost);
            forwardMessage.putParameter("TargetPort", Integer.toString(Handshake.targetPort));
            forwardMessage.send(socket);
            System.out.println("sent The ForwardMessage...");
        }
        /*Wait for the final server to respond with their SessionMessage and check the parameters*/
        System.out.println("Waiting for serverHello msg...");
        HandshakeMessage sessionMessage = new HandshakeMessage();
        sessionMessage.recv(socket);
        if(sessionMessage.getParameter("MessageType").equals("Session")){
            System.out.println("Recieved The SessionMessage...");
            //get the encrypted session key and iv and decode + decrypt them
            clientPrivateKey = HandshakeCrypto.getPrivateKeyFromKeyFile(arguments.get("key"));
            byte[] sessionKeybytes = HandshakeCrypto.decrypt(Base64.getDecoder().decode(sessionMessage.getParameter("SessionKey")), clientPrivateKey);
            byte[] sessionIV = HandshakeCrypto.decrypt(Base64.getDecoder().decode(sessionMessage.getParameter("SessionIV")), clientPrivateKey);
            //get the java object from the bytes for the key
            String sessionKeyEncodedString = new String(sessionKeybytes, ENCODING);
            SessionKey sessionKey = new SessionKey(sessionKeyEncodedString); // gets a session key from it's encoded version
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


    /*
     * Let user know that we are waiting
     */
    private static void tellUser(ServerSocket listensocket) throws UnknownHostException {
        System.out.println("Client forwarder to target " + arguments.get("targethost") + ":" + arguments.get("targetport"));
        System.out.println("Waiting for incoming connections at " +
                InetAddress.getLocalHost().getHostAddress() + ":" + listensocket.getLocalPort());
    }

    public static void startSession(SessionKey sessionKey, byte[] sessionIV){

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
