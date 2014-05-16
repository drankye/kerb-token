package token.samples.sasl;

import token.samples.sasl.gsskrb5ext.GssKrb5ClientExt;


public class TokenSaslSampleClient extends TokenSaslSampleServer {
    static {
        GssKrb5ClientExt.init();
    }

}
