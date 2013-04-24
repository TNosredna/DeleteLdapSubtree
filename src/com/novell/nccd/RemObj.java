package com.novell.nccd;

import javax.naming.*;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.InitialLdapContext;
import javax.net.ssl.SSLHandshakeException;
import java.io.File;
import java.security.Provider;
import java.security.Security;
import java.util.Hashtable;

/**
 * Description: Recursively remove objects from directory via LDAP
 */
public class RemObj {
    static int DEFAULT_PORT = 389;
    static boolean DEFAULT_USE_SSL = false;
    static String DEFAULT_KEYSTORE_PASSWORD = "changeit";
    static String BASE_CONTAINER = "";
    static boolean BASE_CONTAINER_DELETE = false;
    static String LDAP_HOST = "localhost";
    static int LDAP_PORT = DEFAULT_PORT;
    static boolean USE_SSL = DEFAULT_USE_SSL;
    static String LDAP_FILTER = "(objectClass=*)";
    static String USER_DN;
    static String USER_PASSWORD;
    static LdapContext ctx;
    static int ldapSearchTimeout = 3000;
    static long ldapSearchCountLimit = 0;
    static SearchControls constraints = new SearchControls();
    static private Provider provider = null;

    public static void main(String[] args) {
        if (processParameters(args)) {
            try {
                constraints.setCountLimit(ldapSearchCountLimit);
                constraints.setTimeLimit(ldapSearchTimeout);
                constraints.setReturningAttributes(new String[]{});
                constraints.setSearchScope(SearchControls.ONELEVEL_SCOPE);
                ctx = createLdapContext(USER_DN, USER_PASSWORD);
                pruneSubTree(LDAP_FILTER, BASE_CONTAINER);
            } catch (Exception e) {
                System.out.println(e.getLocalizedMessage());
            }
        }
    }

    private static void printUsage() {
        System.out.println("USAGE \"RemObj (v1.01) - Recursively remove objects from directory using LDAP\"");
        System.out.println("Copyright (c) 2012, Novell Consulting Custom Development");
        System.out.println("");
        System.out.println("Usage: remobj -h ldap_host -u admin -p password -b base-container [-f filter] [-port port] [-ssl useSSL?]");
        System.out.println("");
        System.out.println("       Recursively removes all objects from specified container");
        System.out.println("       which satisfy optional filter (default: objectclass=*).");
        System.out.println("       The base-container is also removed.");
        System.out.println("");
        System.out.println("       Admin and Container must be in LDAP DN form,");
        System.out.println("       e.g. cn=admin,o=novell");
        System.out.println("");
        System.out.println("       Filter may be specified in LDAP filter form:");
        System.out.println("       e.g. The simplest form is: attribute=value");
        System.out.println("");
        System.out.println("       LDAP Port may be overridden, but defaults to 389.");
        System.out.println("       If a secure port is configured, -ssl must be set to the boolean 'true'.");
        System.out.println("");
    }

    private static boolean processParameters(String[] args) {
        if (args.length == 0 ||
                args[0].equalsIgnoreCase("-?") || args[0].equalsIgnoreCase("--?") || args[0].equalsIgnoreCase("/?") ||
                args[0].equalsIgnoreCase("-help") || args[0].equalsIgnoreCase("--help") || args[0].equalsIgnoreCase("/help"))  {
            printUsage();
            return false;
        } else {
            for (int ctr = 0; ctr < args.length; ctr++) {
                if (args[ctr].equalsIgnoreCase("-h")) {
                    if (args.length > ctr) {
                        LDAP_HOST = args[ctr + 1];
                    }
                } else if (args[ctr].equalsIgnoreCase("-u")) {
                    if (args.length > ctr) {
                        USER_DN = args[ctr + 1];
                    }
                } else if (args[ctr].equalsIgnoreCase("-p")) {
                    if (args.length > ctr) {
                        USER_PASSWORD = args[ctr + 1];
                    }
                } else if (args[ctr].equalsIgnoreCase("-b")) {
                    if (args.length > ctr) {
                        BASE_CONTAINER = args[ctr + 1];
                    }
                } else if (args[ctr].equalsIgnoreCase("-d")) {
                    BASE_CONTAINER_DELETE = true;
                } else if (args[ctr].equalsIgnoreCase("-f")) {
                    if (args.length > ctr) {
                        LDAP_FILTER = args[ctr + 1];
                    }
                } else if (args[ctr].equalsIgnoreCase("-port")) {
                    if (args.length > ctr) {
                        LDAP_PORT = (Integer.valueOf(args[ctr + 1])).intValue();
                    }
                } else if (args[ctr].equalsIgnoreCase("-ssl")) {
                    if (args.length > ctr) {
                        USE_SSL = args[ctr + 1].equalsIgnoreCase("true");
                    }
                }
            }
        }
        return true;
    }

    static void pruneSubTree(String ldapFilter, String searchBaseFdn) throws Exception {
        NamingEnumeration objects = ctx.search(searchBaseFdn, ldapFilter, constraints);
        while (objects.hasMore()) {
            SearchResult searchResult = (SearchResult)objects.next();
            String objectFdn;
            if (searchResult.isRelative()) {
                objectFdn = searchResult.getName() + (searchBaseFdn.equals("") ? "" : "," + searchBaseFdn);
            } else {
                objectFdn = searchResult.getName();

                // This can happen if the object returned is an eDir Alias object type
                if (objectFdn.startsWith("ldap://") || objectFdn.startsWith("ldaps://") ) {
                    objectFdn = objectFdn.substring(objectFdn.lastIndexOf("/") + 1);
                }
            }
            pruneSubTree(ldapFilter, objectFdn);
        }
        ctx.destroySubcontext(searchBaseFdn);
    }

    /** Create and return an LdapContext object.
     *
     * @param loginFdn  Fdn of object to use for authentication
     * @param loginPassword Password to use for object authenticating
     * @return LdapContext
     * @throws Exception
     */
    static LdapContext createLdapContext(String loginFdn, String loginPassword) throws Exception {
        if (loginPassword.length() == 0) {
            throw new Exception("Empty password provided");
        }
        String ldapHost = LDAP_HOST;
        int ldapPort = LDAP_PORT;
        boolean useSSL = USE_SSL;

        Hashtable contextParameters = new Hashtable();
        contextParameters.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        contextParameters.put(Context.PROVIDER_URL, "ldap://" + ldapHost + ":" + ldapPort + "/");
        contextParameters.put(Context.SECURITY_AUTHENTICATION, "simple");
        if (useSSL) {
            Security.addProvider(getProvider());
            contextParameters.put("java.naming.ldap.factory.socket",
                    "com.novell.nccd.JsseSSLSocketFactory");
            contextParameters.put(Context.SECURITY_PROTOCOL, "ssl");

            //use default keystore based on JAVA_HOME
            String java_home = System.getenv("JAVA_HOME");
            String keystorePath;
            String libSecCacerts = "lib" + File.separator + "security" + File.separator + "cacerts";
            String pathWithoutJre = java_home + File.separator + libSecCacerts;
            String pathWithJre = java_home + File.separator + "jre" + File.separator + libSecCacerts;
            if (new File(pathWithJre).exists()) {
                keystorePath = pathWithJre;
            } else if (new File(pathWithoutJre).exists()) {
                keystorePath = pathWithoutJre;
            } else {
                throw new Exception("Can't find the java keystore based on JAVA_HOME at " + pathWithoutJre + " or " + pathWithJre);
            }
            String keystorePassword = DEFAULT_KEYSTORE_PASSWORD;
            JsseSSLSocketFactory.loadKeystore(keystorePath, keystorePassword);
        }
        contextParameters.put(Context.SECURITY_PRINCIPAL, loginFdn);
        contextParameters.put(Context.SECURITY_CREDENTIALS, loginPassword);

        LdapContext ldapCtx;
        try {
            ldapCtx = new InitialLdapContext(contextParameters, null);
        } catch (CommunicationException e) {
            if (e.getCause() instanceof SSLHandshakeException) {
                throw new Exception("Error creating SSL connection", e);
            }
            throw e;
        } catch (OperationNotSupportedException onse) {
            if (onse.getMessage().indexOf("-197") > 0) {
                throw new Exception(onse.getLocalizedMessage(), onse);
            } else {
                throw new Exception(onse.getLocalizedMessage(), onse);
            }
        } catch (NamingException ne) {
            throw new Exception(ne.getLocalizedMessage(), ne);
        }
        return (ldapCtx);
    }

    static private Provider getProvider() throws Exception {
        if (provider == null) {
            try {
                Class providerClass = Class.forName("com.sun.net.ssl.internal.ssl.Provider");
                System.out.println("The Sun JSSE Provider was successfully loaded");
                provider = (Provider) providerClass.newInstance();
                return provider;
            } catch (Exception e) {
                System.out.println("Unable to load the Sun JSSE Provider");
            }

            try {
                Class providerClass = Class.forName("com.ibm.jsse.IBMJSSEProvider");
                System.out.println("The IBM JSSE Provider was successfully loaded.");
                System.out.println("WARNING: The IBM JSSE Provider('com.ibm.jsse.IBMJSSEProvider') may not be compatible with NMAS Challenge/Response authentication. If you are using NMAS Challenge/Response authentication and are having issues, try removing the IBM version of JAVA and replacing it with Sun's version.  If that isn't possible, you can try adding 'sunjce_provider.jar' to the '../WEB-INF/lib' directory and restart the webserver.");
                provider = (Provider) providerClass.newInstance();
                return provider;
            } catch (Exception e) {
                System.out.println("Unable to load the IBM JSSE Provider");
            }
        } else {
            return provider;
        }

        throw new Exception("A suitable JSSE Provider could not be located.");
    }

}
