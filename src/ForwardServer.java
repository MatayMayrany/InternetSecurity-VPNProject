/**
 * Port forwarding server. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server 
 * and adapted for IK2206.
 *
 * Original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */

import java.io.*;
import java.lang.AssertionError;
import java.lang.Integer;
import java.security.cert.*;
import java.util.ArrayList;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Base64;
import java.util.Properties;
import java.util.StringTokenizer;

import static java.lang.Integer.parseInt;

public class ForwardServer
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardServer";
    private static Arguments arguments;
    static String ENCODING = "UTF-8";
    private ServerSocket handshakeSocket;

    private static SessionIV sessionIV;
    private static SessionKey sessionKey;

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
    private ServerSocket listenSocket;
    private String targetHost;
    private int targetPort;

    /**
     * Do handshake negotiation with client to authenticate, learn 
     * target host/port, etc.
     */
    private void doHandshake() throws UnknownHostException, IOException, Exception {

        Socket clientSocket = handshakeSocket.accept();
        String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
        X509Certificate clientCertificate = null;
        Logger.log("Incoming handshake . from " + clientHostPort);

        /* This is where the handshake should take place */

        /*Recieve the clientHello and verify it*/
        System.out.println("Waiting for clientHello msg...");
        HandshakeMessage clientHello = new HandshakeMessage();
        clientHello.recv(clientSocket);
        if(clientHello.getParameter(MESSAGETYPE).equals(CLIENTHELLO)){
            clientCertificate = VerifyCertificate.getCertificateFromEncodedString(clientHello.getParameter(CERTIFCATE));
            if (VerifyCertificate.verifyCertificates(clientCertificate)){
                System.out.println("The client certificate is verified and signed by the CA");
            }else{
                System.out.println("BAD Certificate, Closing Connection");
                clientSocket.close();
            }
        }else {
            System.out.println("message type wasn't ClientHello, Closing Connection");
            clientSocket.close();
        }
        /*Send back the server hello if the connection still exists*/
        if (clientSocket.isConnected()){
            HandshakeMessage serverHello = new HandshakeMessage();
            serverHello.putParameter(MESSAGETYPE, SERVERTHELLO);
            //get encoded certificate and add it as parameter
            serverHello.putParameter(CERTIFCATE, VerifyCertificate.getEncodedCertificate(arguments.get("usercert")));
            serverHello.send(clientSocket);
            System.out.println("Client and server Hello done");
        }

        /*wait for the Forward Message and examine it */
        HandshakeMessage forwardMessage = new HandshakeMessage();
        forwardMessage.recv(clientSocket);
        boolean forwardDone = false;
        //This is static for this project but for generality
        if(forwardMessage.getParameter(MESSAGETYPE).equals(FORWARD)){
            System.out.println("Recieved Forward Message!");
            Handshake.targetHost = forwardMessage.getParameter(TARGET_HOST);
            Handshake.targetPort = parseInt(forwardMessage.getParameter(TARGET_PORT));
            forwardDone = true;
        }else{
            System.out.println("Message type incorrect, Should be Forward!, closing connection...");
            clientSocket.close();
        }

        /*if we accept the forwardMessage we send back the final SessionMessage */
        if (forwardDone){
            HandshakeMessage sessionMessage = new HandshakeMessage();
            sessionMessage.putParameter(MESSAGETYPE, 	SESSION);
            //create session key and iv
            sessionKey = new SessionKey(128);
            String sessionKeyB64 = sessionKey.encodeKey();

            sessionIV = new SessionIV();
            String sessionIVB64 = sessionIV.encodeIV();
          // System.out.println(sessionIV.encodeIV() + "    \n" + sessionKey.encodeKey());

            //encrypt key and IV with client public key
            byte[] encryptedSessionKey = HandshakeCrypto.encrypt(sessionKeyB64.getBytes(ENCODING), clientCertificate.getPublicKey());

            byte[] encryptedSessionIV = HandshakeCrypto.encrypt(sessionIVB64.getBytes(ENCODING), clientCertificate.getPublicKey());

            sessionMessage.putParameter(SESSION_KEY	, Base64.getEncoder().encodeToString(encryptedSessionKey));
            sessionMessage.putParameter(SESSION_IV	, Base64.getEncoder().encodeToString(encryptedSessionIV));
            sessionMessage.putParameter("ServerHost", Handshake.serverHost);
            sessionMessage.putParameter("ServerPort", Integer.toString(Handshake.serverPort));
            sessionMessage.send(clientSocket);
            System.out.println("Sent Session Message!");
        }

        clientSocket.close();

        /*
         * Fake the handshake result with static parameters.
         */

        /* listenSocket is a new socket where the ForwardServer waits for the
         * client to connect. The ForwardServer creates this socket and communicates
         * the socket's address to the ForwardClient during the handshake, so that the
         * ForwardClient knows to where it should connect (ServerHost/ServerPort parameters).
         * Here, we use a static address instead (serverHost/serverPort).
         * (This may give "Address already in use" errors, but that's OK for now.)
         */
        listenSocket = new ServerSocket();
        listenSocket.bind(new InetSocketAddress(Handshake.serverHost, Handshake.serverPort));
        /* The final destination. The ForwardServer sets up port forwarding
         * between the listensocket (ie., ServerHost/ServerPort) and the target.
         */
        targetHost = Handshake.targetHost;
        targetPort = Handshake.targetPort;

    }

    /**
     * Starts the forward server - binds on a given port and starts serving
     */
    public void startForwardServer() throws Exception {
        // Bind server on given TCP port
        int port = parseInt(arguments.get("handshakeport"));
        try {
            handshakeSocket = new ServerSocket(port);
        } catch (IOException ioe) {
            throw new IOException("Unable to bind to port " + port);
        }

        log("Nakov Forward Server started on TCP port " + port);

        // Accept client connections and process them until stopped
        while(true) {
            ForwardServerClientThread forwardThread;
            try {
                doHandshake();
                //send the threads that will be handling the forwarding of data the Key and IV for encryption
                forwardThread = new ForwardServerClientThread(this.listenSocket, this.targetHost, this.targetPort, sessionKey, sessionIV);
                forwardThread.start();
            } catch (IOException e) {
                throw e;
            }
        }
    }

    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public void log(String aMessage)
    {
        if (ENABLE_LOGGING)
            System.out.println(aMessage);
    }

    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");
    }

    /**
     * Program entry point. Reads settings, starts check-alive thread and
     * the forward server
     */
    public static void main(String[] args)
            throws Exception
    {
        arguments = new Arguments();
        arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
        arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
        arguments.loadArguments(args);

        ForwardServer srv = new ForwardServer();
        try {
            srv.startForwardServer();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


}
