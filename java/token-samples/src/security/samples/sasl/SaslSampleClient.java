package security.samples.sasl;

import security.samples.SampleClient;
import security.samples.Transport;

import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class SaslSampleClient extends SampleClient {
    private SaslClient saslClient;

    @Override
    protected void usage(String[] args) {
        if (args.length < 4) {
            System.err.println("Usage: java <options> TokenSaslSampleClient "
                    + "<server-host> <server-port> <service-protocol> <server-fqdn>");
            System.exit(-1);
        }
    }

    public SaslSampleClient(String[] args) throws Exception {
        super(args);

        String protocol = args[2];
        String serverFqdn = args[3];
        Map<String, String> props = new HashMap<String, String>();
        props.put(Sasl.QOP, "auth");

        this.saslClient = Sasl.createSaslClient(new String[]{"GSSAPI"}, null,
                protocol, serverFqdn, props, null);
    }

    @Override
    protected void onConnection(Transport.Connection conn) throws Exception {
        byte[] token = saslClient.hasInitialResponse() ? new byte[0] : null;
        token = saslClient.evaluateChallenge(token);
        conn.sendMessage("CONT", token);

        Transport.Message msg = conn.recvMessage();
        while (!saslClient.isComplete() && (isContinue(msg) || isOK(msg))) {
            byte[] respToken = saslClient.evaluateChallenge(msg.body);

            if (isOK(msg)) {
                if (respToken != null) {
                    throw new IOException("Attempting to send response after completion");
                }
                break;
            } else {
                conn.sendMessage("CONT", respToken);
                msg = conn.recvMessage();
            }
        }

        System.out.println("Context Established! ");

        token = "Hello There!\0".getBytes();
        System.out.println("Will send wrap token of size " + token.length);

        conn.sendToken(token);

        saslClient.dispose();
    }

    protected boolean isOK(Transport.Message msg) {
        if (msg.header != null) {
            return new String(msg.header).equals("OK");
        }
        return false;
    }

    protected boolean isContinue(Transport.Message msg) {
        if (msg.header != null) {
            return new String(msg.header).equals("CONT");
        }
        return false;
    }

    public static void main(String[] args) throws Exception  {
        new SaslSampleClient(args).run();
    }
}
