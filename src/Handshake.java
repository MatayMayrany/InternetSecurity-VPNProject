public class Handshake {
    /* Static data -- replace with handshake! */

    /* Where the client forwarder forwards data from  */
    public static final String serverHost = "localhost";
    public static final int serverPort = 2206;

    /* The final destination */
    public static String targetHost = "localhost";
    public static int targetPort = 6789;

    public SessionKey sessionKey;
    public SessionIV sessionIV;

    public Handshake(SessionKey sessionKey, SessionIV sessionIV){
        this.sessionKey = sessionKey;
        this.sessionIV = sessionIV;
    }
}
