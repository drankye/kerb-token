package token.samples.sasl;

import kerb.token.sasl.gsskrb5ext.GssKrb5ExtProvider;
import kerb.token.sasl.gsskrb5ext.GssKrb5ServerExt;
import org.ietf.jgss.GSSContext;
import security.samples.Transport;
import security.samples.sasl.SaslSampleServer;
import token.samples.AuthzDataDumper;

import javax.security.sasl.SaslServer;
import java.security.Security;
import java.util.Map;

public class TokenSaslSampleServer extends SaslSampleServer {
    static {
        Security.addProvider(new GssKrb5ExtProvider());
    }

    @Override
    protected void usage(String[] args) {
        if (args.length < 3) {
            System.err.println("Usage: java <options> TokenSaslSampleServer "
                    + "<ListenPort> <service-protocol> <server-fqdn>");
            System.exit(-1);
        }
    }

    public TokenSaslSampleServer(String[] args) throws Exception {
        super(args);
        this.mechanism = "GSSAPIEXT";
    }

    @Override
    protected void doWith(SaslServer ss, Map<String, Object> props,
                          Transport.Connection conn) throws Exception {

        super.doWith(ss, props, conn);

        GSSContext context = (GSSContext) ss.getNegotiatedProperty(GssKrb5ServerExt.GSSCONTEXT_KEY);
        doWith(context, conn);
        ss.getNegotiatedProperty(GssKrb5ServerExt.GSSCONTEXT_KEY);
    }

    protected void doWith(GSSContext context, Transport.Connection conn) throws Exception {
        AuthzDataDumper.checkAuthzData(context);
    }

    public static void main(String[] args) throws Exception {
        new TokenSaslSampleServer(args).run();
    }
}
