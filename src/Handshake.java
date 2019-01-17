public class Handshake {
    /* Static data -- replace with handshake! */

    /* Where the client forwarder forwards data from  */
    public static final String serverHost = "130.229.130.21";
    public static final int serverPort = 4000;

    /* The final destination */
    public static String targetHost = "130.229.130.21";
    public static int targetPort = 6789;

    public SessionKey sessionKey;
    public SessionIV sessionIV;

    public Handshake(SessionKey sessionKey, SessionIV sessionIV){
        this.sessionKey = sessionKey;
        this.sessionIV = sessionIV;
    }
}
