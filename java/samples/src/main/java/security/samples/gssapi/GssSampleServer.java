package security.samples.gssapi;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.MessageProp;
import security.samples.SampleServer;
import security.samples.Transport;

import java.io.IOException;

public class GssSampleServer extends SampleServer {
    private GSSManager manager;

    public GssSampleServer(String[] args) throws IOException {
        super(args);
        this.manager = GSSManager.getInstance();
    }

    @Override
    protected void onConnection(Transport.Connection conn) throws Exception {
        GSSContext context = manager.createContext((GSSCredential)null);
        byte[] token = null;

        System.out.print("Starting negotiating security context");
        while (!context.isEstablished()) {
            token = conn.recvToken();
            token = context.acceptSecContext(token, 0, token.length);
            if (token != null) {
                conn.sendToken(token);
            }
        }

        System.out.print("Context Established! ");
        System.out.println("Client is " + context.getSrcName());
        System.out.println("Server is " + context.getTargName());

        doWith(context, conn);

        context.dispose();
    }

    protected void doWith(GSSContext context, Transport.Connection conn) throws Exception {
        byte[] token = null;

        if (context.getMutualAuthState())
            System.out.println("Mutual authentication took place!");

        MessageProp prop = new MessageProp(0, false);

        token = conn.recvToken();
        byte[] bytes = context.unwrap(token, 0, token.length, prop);
        String str = new String(bytes);
        System.out.println("Received data \""
                + str + "\" of length " + str.length());

        System.out.println("Confidentiality applied: "
                + prop.getPrivacy());

        prop.setQOP(0);
        token = context.getMIC(bytes, 0, bytes.length, prop);
        System.out.println("Will send MIC token of size "
                + token.length);
        conn.sendToken(token);
    }

    public static void main(String[] args) throws Exception {
        new GssSampleServer(args).run();
    }
}
