package token.samples.gssapi;

import org.ietf.jgss.GSSContext;
import security.samples.Transport;
import security.samples.gssapi.GssSampleServer;
import token.samples.AuthzDataDumper;

import java.io.IOException;

public class TokenGssSampleServer extends GssSampleServer {
    public TokenGssSampleServer(String[] args) throws IOException {
        super(args);
    }

    public static void main(String[] args) throws Exception {
        new TokenGssSampleServer(args).run();
    }

    protected void doWith(GSSContext context, Transport.Connection conn) throws Exception {
        super.doWith(context, conn);

        AuthzDataDumper.checkAuthzData(context);
    }
}
