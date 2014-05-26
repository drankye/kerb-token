package kerb.token;

import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class TokenTool {

    public static JWT issueToken() {
        // must have for kerb-token
        String krbPrincipal = "drankye@SH.INTEL.COM";

        PlainHeader header = new PlainHeader();
        header.setCustomParameter("krbPrincipal", krbPrincipal);

        JWTClaimsSet jwtClaims = new JWTClaimsSet();

        String iss = "token-service";
        jwtClaims.setIssuer(iss);

        String sub = "drankye";
        jwtClaims.setSubject(sub);

        // must have for kerb-token
        jwtClaims.setSubject(krbPrincipal);

        List<String> aud = new ArrayList<String>();
        aud.add("krb5kdc-with-token-extension");
        jwtClaims.setAudience(aud);

        // Set expiration in 60 minutes
        final Date NOW =  new Date(new Date().getTime() / 1000 * 1000);
        Date exp = new Date(NOW.getTime() + 1000 * 60 * 60);
        jwtClaims.setExpirationTime(exp);

        Date nbf = NOW;
        jwtClaims.setNotBeforeTime(nbf);

        Date iat = NOW;
        jwtClaims.setIssueTime(iat);

        String jti = UUID.randomUUID().toString();
        jwtClaims.setJWTID(jti);

        PlainJWT jwt = new PlainJWT(header, jwtClaims);
        return jwt;
    }

    public static JWT decodeToken(String token) throws ParseException {
        PlainJWT jwt = PlainJWT.parse(token);

        return jwt;
    }

    public static void main(String[] args) throws ParseException {
        JWT jwt = issueToken();
        String token = jwt.serialize();
        System.out.println("Issued token: " + token);

        JWT jwt2 = decodeToken(token);
        String krbPrincipal = (String) jwt2.getHeader().getCustomParameter("krbPrincipal");
        System.out.println("Decoded token with krbprincipal: " + krbPrincipal);
    }
}
