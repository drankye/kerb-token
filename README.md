==== Kerberos Token-preauth ====

== Kerberos token-preauth
This extension allows 3rd party token(jwt) can be used to authenticate to Kerberos and obtain a ticket granting ticket.
It bases on Kerberos preauth framework(FAST tunnel) and provides another preauthent method similar to OTP and PKINIT. 
It allows token can be used as credential to authenticate to KDC for a normal principal instead of user password or key. 
When using the token to request a tgt, the user name claimed in the token must match the specified Kerberos principal.
PKI is used to establish the trust relationship between 3rd party token issuer and KDC.

1. Deployment

1) This assumes you have a jwt token authority or provider.
  
2) It provides jwt-token module(so file) and implements both client side and kdc side corresponding plugins to make it work.
To deploy, on both KDC host and client hosts:

cp jwt.so /usr/local/lib/krb5/plugins/preauth/
jwt-token.so  otp.so  pkinit.so

2. Configuration

1) In KDC side, in kdc.conf:

In token-preauth section,

This configures the token signature verification key file

token-authority-cert: <TOKEN-AUTHORITY-VERIFICATON_KEY_FILE>

This configures the mapping between token atrribute(s) and krb principal account

token-principal-mapping: <TOKEN-ATTRIBUTE_FOR_USERNAME>

2 Optionally, PKINIT

You can deploy and configure PKINIT to meet the armor key requirements for client. Like other preauthenticaton method e.g. OTP, 
token should be protected from leakage in the FAST tunnel between client and KDC, which requres an armor ticket or key. 
The options to get a FAST armor key:
1) Sticking a srvtab in etc
2) Use PKINIT, supposedly anonymous PKINIT
3) Get a TGT for an "ordinary" user with a long-term shared secret

We suggest PKINIT since PKINIT itself can be employed for end users to authenticate to KDC and it's convenient in some scenarioes.

4. How to use

1) Assumes you have a token;

2) Get an armor tgt assuming you use anonymous PKINIT option

kinit -c /tmp/krb5cc_armor -n @<YOUR_REALM>

3) Get tgt using your token, like

kinit -T /tmp/krb5cc_armor_token -c /tmp/krb5cc_my -X token=<YOUR-JWT-TOKEN> <YOUR-PRINCIPAL>

We provide a shell command ktinit.sh to wraps all the above steps:

ktinit.sh -h
This tool uses token to authenticate to KDC and obtains tgt for you.
ktinit [-t token | -T token-cache-file] [-c kerb-ccache-file]
      when no token specified, ~/.tokenauth.token will be used by default


4) With the credential cached tgt, you can access services as normal.

== JAVA 

1. How to extract tokens in application server side
 
There're two APIs provided by JRE to utilize Kerberos mechanism. In both, we need to hook and extract the token from
service ticket so that
a. authenticate client with the token
b. extract identity attributes and labels from token for fine-grained  authorization.

1) GSSAPI

It's very simple, since JRE GSSAPI has already support to query info like authorization data from tickets. What we need
is to query and extract the authorization data from tickets, then decoding it(ASN.1) and get the token from it.

2) SASL

SASL GSSAPI mechanism wraps GSSAPI level but it doesn't support for now to expose the GSSContext outside thus we won't
able to do above using the mechanism. We need to come up our own SASL mechanism like GSSAPI but allow application to 
access the needed GSSContext to do above for querying and extracting tokens.

2. A new JAAS login module: Krb5TokenAuthnLoginModule

This module can be configured and get token from token cache, then does the whole work the following:

1) Get needed armor ticket/key;
2) kinit with the armor ticket and token, gets tgt and puts it in specified credentail cache;
3) Wraps and exectues Krb5LoginModule with above credential cache;
4) As a result of 3), all necessary credential is validated and put in JAVA authorization context.

== Project layout

|--java
|   |
|   |---samples: java security samples to show how to write GSSAPI and SASL applications
|   |
|   |---token:  Krb5TokenAuthnLoginModule module, SASL GSSAPIExt mechanism for token, and samples to show how token can be
|                extracted from tickets
|
|--krb5
|   |
|   |--src/plugins/preauth/jwt: token-preauth plugin for KDC and clients
|   |
|   |--krb5/src/lib/jwttoken: token library for facilities to process and verify tokens

== Notes

This effort is still on the going, and not completely finished yet. Particularly, the token decryption and verification is
to be done.

== License

Apache License V2