package token.samples.sasl;

import org.ietf.jgss.GSSContext;
import security.samples.Transport;
import security.samples.sasl.SaslSampleServer;
import token.samples.AuthzDataDumper;
import token.samples.sasl.gsskrb5ext.GssKrb5ServerExt;

import javax.security.sasl.SaslServer;
import java.util.Map;

public class TokenSaslSampleServer extends SaslSampleServer {
    static {
        GssKrb5ServerExt.init();
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

    protected void doWith(SaslServer ss, Map<String, Object> props,
                          Transport.Connection conn) throws Exception {
        GSSContext context = (GSSContext) props.get(GssKrb5ServerExt.GSSCONTEXT_KEY);
        doWith(context, conn);
    }

    protected void doWith(GSSContext context, Transport.Connection conn) throws Exception {
        AuthzDataDumper.checkAuthzData(context);
    }
}
