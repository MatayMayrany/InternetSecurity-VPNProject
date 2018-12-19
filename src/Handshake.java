public class Handshake {
    /* Static data -- replace with handshake! */

    /* Where the client forwarder forwards data from  */
    public static final String serverHost = "localhost";
    public static final int serverPort = 4412;

    /* The final destination */
    public static String targetHost = "localhost";
    public static int targetPort = 6789;

    private SessionKey sessionKey;
    private SessionIV sessionIV;

    public Handshake(SessionKey sessionKey, SessionIV sessionIV){
        this.sessionKey = sessionKey;
        this.sessionIV = sessionIV;
    }
}
