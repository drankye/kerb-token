package token.samples.sasl;

import kerb.token.sasl.gsskrb5ext.GssKrb5ClientExt;

public class TokenSaslSampleClient extends TokenSaslSampleServer {
    static {
        GssKrb5ClientExt.init();
    }

    public TokenSaslSampleClient(String[] args) throws Exception {
        super(args);
    }
}
