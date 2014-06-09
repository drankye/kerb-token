package token.samples.sasl;

import kerb.token.sasl.gsskrb5ext.GssKrb5ExtProvider;

import java.security.Security;

public class TokenSaslSampleClient extends TokenSaslSampleServer {
    static {
        Security.addProvider(new GssKrb5ExtProvider());
    }

    public TokenSaslSampleClient(String[] args) throws Exception {
        super(args);
    }
}
