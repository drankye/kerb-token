package kerb.token.login;

import com.sun.security.auth.module.Krb5LoginModule;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.util.HashMap;
import java.util.Map;

public class TokenAuthnLoginModule implements LoginModule {
    Krb5LoginModule krb5LoginModule;

    // initial state
    private Subject subject;
    private CallbackHandler callbackHandler;
    private Map sharedState;
    private Map<String, ?> options;

    // configurable option
    private boolean debug = false;
    private boolean doNotPrompt = false;
    private boolean useTokenCache = false;
    private String ticketCacheName = null;

    private boolean storePass = false;
    private boolean clearPass = false;

    // the authentication status
    private boolean succeeded = false;
    private boolean commitSucceeded = false;
    private String username;

    private char[] password = null;

    private String token = null;

    private static final String TOKEN = "tokenauth.token";

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler,
                           Map<String, ?> sharedState, Map<String, ?> options) {

        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = sharedState;
        this.options = options;

        // initialize any configured options

        debug = "true".equalsIgnoreCase((String)options.get("debug"));
        doNotPrompt = "true".equalsIgnoreCase((String)options.get
                ("doNotPrompt"));
        useTokenCache = "true".equalsIgnoreCase((String)options.get
                ("useTokenCache"));
        storePass =
                "true".equalsIgnoreCase((String)options.get("storePass"));
        clearPass =
                "true".equalsIgnoreCase((String)options.get("clearPass"));

        if (debug) {
            System.out.print("Debug is  " + debug
                    + " useTokenCache " + useTokenCache
                    + " doNotPrompt " + doNotPrompt
                    + " ticketCache is " + ticketCacheName
                    + "\n");
        }
    }

    @Override
    public boolean login() throws LoginException {
        validateConfiguration();

        boolean myLoginResult = doMyLogin();
        if (myLoginResult) {
            Map krbSharedState = new HashMap();
            Map<String, ?> krbOptions = new HashMap<String, Object>();

            krb5LoginModule = new Krb5LoginModule();
            krb5LoginModule.initialize(subject, null, krbSharedState, krbOptions);
            return krb5LoginModule.login();
        }
        return false;
    }

    private boolean doMyLogin() throws LoginException {
        try {
            attemptAuthentication(true);
            if (debug)
                System.out.println("\t\t[TokenAuthnLoginModule] " +
                        "authentication succeeded");
            succeeded = true;
            cleanState();
            return true;
        } catch (LoginException le) {
            // authentication failed -- try again below by prompting
            cleanState();
            if (debug) {
                System.out.println("\t\t[TokenAuthnLoginModule] " +
                        "failed with:" +
                        le.getMessage());
            }
        }

        // attempt the authentication by getting the username and pwd
        // by prompting or configuration i.e. not from shared state

        try {
            attemptAuthentication(false);
            succeeded = true;
            cleanState();
            return true;
        } catch (LoginException e) {
            // authentication failed -- clean out state
            if (debug) {
                System.out.println("\t\t[Krb5LoginModule] " +
                        "authentication failed \n" +
                        e.getMessage());
            }
            succeeded = false;
            cleanState();
            throw e;
        }
    }

    @Override
    public boolean commit() throws LoginException {
        return krb5LoginModule.commit();
    }

    @Override
    public boolean abort() throws LoginException {
        return krb5LoginModule.abort();
    }

    @Override
    public boolean logout() throws LoginException {
        return krb5LoginModule.logout();
    }

    private void attemptAuthentication(boolean getPasswdFromSharedState)
            throws LoginException {

        if (useTokenCache) {
            // ticketCacheName == null implies the default cache
            if (debug)
                System.out.println("Acquire TGT from Cache");
            token = TokenCache.readToken(ticketCacheName);

            if (debug) {
                if (token == null) {
                    System.out.println
                            ("No token from Token Cache");
                }
            }
        }

        if (token == null) {
            promptForPass(getPasswdFromSharedState);
        }
    }

    private void promptForPass(boolean getPasswdFromSharedState)
            throws LoginException {

        if (getPasswdFromSharedState) {
            // use the password saved by the first module in the stack
            token = (String)sharedState.get(TOKEN);
            if (token == null) {
                if (debug) {
                    System.out.println
                            ("Token from shared state is null");
                }
                throw new LoginException
                        ("Token can not be obtained from sharedstate ");
            }
            if (debug) {
                System.out.println
                        ("Token is " + token);
            }
            return;
        }

        if (doNotPrompt) {
            throw new LoginException
                    ("Unable to obtain token from user\n");
        } else {
            if (callbackHandler == null)
                throw new LoginException("No CallbackHandler "
                        + "available "
                        + "to garner authentication "
                        + "information from the user");
            try {
                Callback[] callbacks = new Callback[1];
                callbacks[0] = new NameCallback("Please specify your token", null);
                callbackHandler.handle(callbacks);
                String tmpToken = ((NameCallback)
                        callbacks[0]).getName();
                if (tmpToken != null) {
                    token = tmpToken;
                }
                if (debug) {
                    System.out.println("\t\t[TokenAuthnLoginModule] " +
                            "user entered token: " +
                            token);
                    System.out.println();
                }
            } catch (java.io.IOException ioe) {
                throw new LoginException(ioe.getMessage());
            } catch (UnsupportedCallbackException uce) {
                throw new LoginException(uce.getMessage()
                        +" not available to garner "
                        +" authentication information "
                        + "from the user");
            }
        }
    }

    private void validateConfiguration() throws LoginException {
        if (doNotPrompt && !useTokenCache)
            throw new LoginException
                    ("Configuration Error"
                            + " - either doNotPrompt should be "
                            + " false or useTokenCache "
                            + " should be true");
        if (ticketCacheName != null && !useTokenCache)
            throw new LoginException
                    ("Configuration Error "
                            + " - useTokenCache should be set "
                            + "to true to use the ticket cache"
                            + ticketCacheName);
    }

    private void cleanState() {

        // save input as shared state only if
        // authentication succeeded
        if (succeeded) {
            if (storePass &&
                    !sharedState.containsKey(TOKEN)) {
                sharedState.put(TOKEN, token);
            }
        }
        if (clearPass) {
            sharedState.remove(TOKEN);
        }
    }

}
