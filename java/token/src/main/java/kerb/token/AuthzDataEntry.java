package kerb.token;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1Integer;
import org.haox.asn1.type.Asn1OctetString;
import org.haox.asn1.type.Asn1SequenceType;

public class AuthzDataEntry extends Asn1SequenceType {
    static int AD_TYPE = 0;
    static int AD_DATA = 1;

    public AuthzDataEntry() {
        super(new Asn1FieldInfo[] {
                new Asn1FieldInfo(AD_TYPE, 0, Asn1Integer.class),
                new Asn1FieldInfo(AD_DATA, 1, Asn1OctetString.class)
        });
    }

    public int getAuthzType() {
        Integer value = getFieldAsInteger(AD_TYPE);
        return value;
    }

    public byte[] getAuthzData() {
        return getFieldAsOctetBytes(AD_DATA);
    }
}
