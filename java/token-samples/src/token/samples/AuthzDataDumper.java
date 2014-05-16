package token.samples;

import com.sun.security.jgss.AuthorizationDataEntry;
import com.sun.security.jgss.ExtendedGSSContext;
import com.sun.security.jgss.InquireType;
import org.haox.asn1.EncodingOption;
import org.haox.asn1.type.*;
import org.ietf.jgss.GSSContext;

public class AuthzDataDumper {
    static final int JWT_AUTHZ_DATA_TYPE = 81;
    public static final int AD_IF_RELEVANT_TYPE = 1;

    /**
     AuthorizationData       ::= SEQUENCE OF SEQUENCE {
     ad-type         [0] Int32,
     ad-data         [1] OCTET STRING
     }
     */
    static int AD_TYPE = 0;
    static int AD_DATA = 1;

    static class AuthzDataEntry extends Asn1SequenceType {

        public AuthzDataEntry() {
            super(new Asn1FieldInfo[] {
                    new Asn1FieldInfo(AD_TYPE, 0, Asn1Integer.class),
                    new Asn1FieldInfo(AD_DATA, 1, Asn1OctetString.class)
            });
            setEncodingOption(EncodingOption.EXPLICIT);
        }

        public int getAuthzType() {
            Integer value = getFieldAsInteger(AD_TYPE);
            return value;
        }

        public byte[] getAuthzData() {
            return getFieldAsOctetBytes(AD_DATA);
        }
    }

    public static void checkAuthzData(GSSContext context) throws Exception {
        System.out.println("Looking for token from authorization data in GSSContext");

        Object authzData = null;
        if (context instanceof ExtendedGSSContext) {
            ExtendedGSSContext ex = (ExtendedGSSContext)context;
            authzData = ex.inquireSecContext(
                    InquireType.KRB5_GET_AUTHZ_DATA);
        }

        if (authzData != null) {
            AuthorizationDataEntry[] authzEntries = (AuthorizationDataEntry[]) authzData;
            System.out.println("Got authzData entries: " + authzEntries.length);
            for (int i = 0; i < authzEntries.length; ++i) {
                AuthzDataDumper.dumpAuthzData(authzEntries[i]);
            }
        }
    }

    public static void dumpAuthzData(AuthorizationDataEntry authzDataEntry) throws Exception {
        if (authzDataEntry.getType() == AuthzDataDumper.AD_IF_RELEVANT_TYPE) {
            return;
        }

        byte[] authzData = authzDataEntry.getData();
        // let's first remove the wrapper first
        Asn1Sequence wrapper = new Asn1Sequence();
        wrapper.decode(authzData);
        Asn1Item item = wrapper.getValue().get(0);

        // then decode the content and populate the fields into ad object
        AuthzDataEntry ad = new AuthzDataEntry();
        item.decodeValueWith(ad);
        if (ad.getAuthzType() == JWT_AUTHZ_DATA_TYPE) {
            String token = new String(ad.getAuthzData());
            System.out.println("========== Extracted a token: " + token + " ==========");
        }
    }
}
