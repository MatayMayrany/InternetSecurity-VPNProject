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

public class ForwardServer
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardServer";
    private static Arguments arguments;


    private ServerSocket handshakeSocket;

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
        Logger.log("Incoming handshake . from " + clientHostPort);

        /* This is where the handshake should take place */

        /*Recieve the clientHello and verify it*/
        System.out.println("Waiting for clientHello msg...");
        HandshakeMessage clientHello = new HandshakeMessage();
        clientHello.recv(clientSocket);
        if(clientHello.getParameter("MessageType").equals("ClientHello")){
            VerifyCertificate verifyCertificate = new VerifyCertificate();
            if (verifyCertificate.verifyCertificates(getCertificateFromEncodedString(clientHello.getParameter("Certificate")))){
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
            serverHello.putParameter("MessageType", "ServerHello");
            //get encoded certificate and add it as parameter
            serverHello.putParameter("Certificate", getEncodedServerCertificate("usercert"));
            serverHello.send(clientSocket);
            System.out.println("GOOD SO FAR");
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
    public String getEncodedServerCertificate(String cert) throws CertificateException, FileNotFoundException {
        try {
            FileInputStream is = new FileInputStream(arguments.get(cert));
            String encodedCert = Base64.getEncoder().encodeToString(is.toString().getBytes());
            return encodedCert;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

    public X509Certificate getCertificateFromEncodedString(String certB64) throws CertificateException {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        InputStream is = new ByteArrayInputStream(certB64.getBytes());
        return (X509Certificate) fact.generateCertificate(is);
    }


    /**
     * Starts the forward server - binds on a given port and starts serving
     */
    public void startForwardServer() throws Exception {
        // Bind server on given TCP port
        int port = Integer.parseInt(arguments.get("handshakeport"));
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

                forwardThread = new ForwardServerClientThread(this.listenSocket, this.targetHost, this.targetPort);
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

//    public String encodeCertificate(Certificate X509Certifacte) throws CertificateEncodingException {
//        String encodedCertificate = X509Certifacte.getEncoded().toString();
//        return encodedCertificate;
//    }

}
