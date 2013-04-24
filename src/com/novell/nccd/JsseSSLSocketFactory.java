package com.novell.nccd;

import javax.net.SocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.*;
import java.net.Socket;
import java.net.InetAddress;
import java.io.IOException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.KeyStoreException;
import java.security.KeyManagementException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.util.Enumeration;

public class JsseSSLSocketFactory extends SocketFactory {
    private static KeyStore ks=null;
    private static String keyStorePath;
    private static String keyStorePassword;

    private static JsseSSLSocketFactory default_factory = null;
    private SocketFactory sslSocketFactory= null;

    private static class AllCertsTrustManager implements X509TrustManager {
        X509TrustManager manager;

        AllCertsTrustManager(X509TrustManager manager) {
            this.manager = manager;
        }

        public X509Certificate[] getAcceptedIssuers() {
            X509Certificate[] X509Certs = null;
            try {
                // See how many certificates are in the keystore.
                int numberOfEntry = ks.size();

                // If there are any certificates in the keystore.
                if (numberOfEntry > 0) {
                    // Create an array of X509Certificates
                    X509Certs = new X509Certificate[numberOfEntry];
                    // Get all of the certificate alias out of the keystore.
                    Enumeration aliases = ks.aliases();
                    // Retrieve all of the certificates out of the keystore
                    // via the alias name.

                    int i = 0;
                    while (aliases.hasMoreElements()) {
                        X509Certs[i] = (X509Certificate) ks.getCertificate((String)aliases.nextElement());
                        i++;
                    }
                }
            } catch (Exception e) {
                System.out.println("AllCertsTrustManager: getAcceptedIssuers Exception: " + e.toString());
                X509Certs = null;
            }
            return X509Certs;
        }

        // isChainTrusted searches the keyStore for any certificate in the certificate chain.
        private boolean isChainTrusted(X509Certificate[] chain) {
            boolean trusted = true;
            try {
                // Start with the root and see if it is in the Keystore.
                // The root is at the end of the chain.
                for (int i = chain.length - 1; i >= 0; i--) {
                    X509Certificate chainCert = chain[i];
                    String ksAlias = ks.getCertificateAlias(chainCert);
                    if (ksAlias != null) {
                        X509Certificate ksCert = (X509Certificate)ks.getCertificate(ksAlias);
                        try {
                            chainCert.checkValidity();
                        } catch (Exception e) {  // caught if the cert is not valid (thrown by checkValidity())
                            trusted = false;
                            System.out.println("AllCertsTrustManager: Error: Exception in isChainTrusted: Server cert is invalid. "+e);
                        }
                        try {
                            ksCert.checkValidity();
                        } catch (Exception e) {   // caught if the cert is not valid (thrown by checkValidity())
                            trusted = false;
                            System.out.println("AllCertsTrustManager: Error: Exception in isChainTrusted: Server cert in keystore is invalid. "+e);
                        }
                    } else {
                        trusted = false;
                    }
                    // if anything is not trusted, exit now
                    if (!trusted) {
                        break;
                    }
                }
            } catch (Exception e) {
                trusted = false;
                System.out.println("AllCertsTrustManager: Error: Exception in isChainTrusted: " + e.toString());
            }
            return trusted;
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException { }

        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            try {
                // If certificate is untrusted
                if (!isChainTrusted(chain)) {
                    // Add Chain to the keyStore.
                    for (int i = 0; (chain != null && i < chain.length); i++) {
                        X509Certificate certificate = chain[i];
                        try {
                            certificate.checkValidity();
                            String alias = certificate.getSubjectDN().toString();
                            if (ks.containsAlias(alias)) {
                                System.out.println("AllCertsTrustManager: Deleting existing cert in cached keystore: "+alias);
                                ks.deleteEntry(alias);
                            }
                            System.out.println("AllCertsTrustManager: Adding chain cert to cached keystore: "+alias);
                            ks.setCertificateEntry(alias, certificate);
                        } catch (Exception e) {
                            System.out.println("AllCertsTrustManager: Error: Exception in checkServerTrusted: Server cert is invalid. "+e);
                        }
                    }
                    // Save keystore to file.
                    OutputStream keyStoreOStream = new FileOutputStream(keyStorePath);
                    ks.store(keyStoreOStream, keyStorePassword.toCharArray());
                    keyStoreOStream.close();
                    System.out.println("AllCertsTrustManager: Cached keystore saved to " + keyStorePath);
                }
            } catch (Exception e) {
                System.out.println("AllCertsTrustManager: Error: Exception in isServerTrusted: " + e.toString());
            }
        }
    }

    public static void setKeystore(KeyStore ks) {
        if (JsseSSLSocketFactory.ks != null) {
            return;
        }

        JsseSSLSocketFactory.ks = ks;
    }

    public static void loadKeystore(String truststore) throws Exception {
        loadKeystore(truststore,  null);
    }

    public static void loadKeystore(String truststore, String truststorePassword) throws Exception {
        if (ks != null) {
            return;
        }

        keyStorePath = truststore;
        keyStorePassword = truststorePassword;

        KeyStore store;
        try {
            store = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            throw new Exception("Error creating KeyStore", e);
        }

        try {
            if (truststorePassword == null) {
                store.load(new FileInputStream(truststore), null);
            } else {
                store.load(new FileInputStream(truststore), truststorePassword.toCharArray());
            }
        } catch (IOException e) {
            throw new Exception("Error loading KeyStore", e);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("Error loading KeyStore", e);
        } catch (CertificateException e) {
            throw new Exception("Error loading KeyStore", e);
        }

        ks = store;
    }

    public static void loadCertAsKeystore(String caCert) throws Exception {
        if (ks != null) {
            return;
        }

        // Load CA Chain file
        CertificateFactory cf;
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new Exception("Error creating CertificateFactory", e);
        }
        X509Certificate cert;
        try {
            cert = (X509Certificate) cf.generateCertificate(new FileInputStream(caCert));
        } catch (CertificateException e) {
            throw new Exception("Error with certificate", e);
        } catch (FileNotFoundException e) {
            throw new Exception("Unable to find certificate file", e);
        }

        KeyStore store;
        try {
            store = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            throw new Exception("Error creating KeyStore", e);
        }

        try {
            store.load(null, null);
        } catch (IOException e) {
            throw new Exception("Error initializing KeyStore", e);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("Error initializing KeyStore", e);
        } catch (CertificateException e) {
            throw new Exception("Error initializing KeyStore", e);
        }

        try {
            store.setCertificateEntry("caCert", cert);
        } catch (KeyStoreException e) {
            throw new Exception("Error adding certificate to KeyStore", e);
        }

        ks = store;
    }

    private void init() throws IOException {
        if (sslSocketFactory != null) {
            return;
        }

        TrustManagerFactory tmf;
        try {
            tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new IOException(e.getMessage());
        }

        try {
            tmf.init(ks);
        } catch (KeyStoreException e) {
            throw new IOException(e.getMessage());
        }

        TrustManager[] managers = tmf.getTrustManagers();
        for (int i=0; i<managers.length; ++i) {
            if (managers[i] instanceof X509TrustManager) {
                managers[i] = new AllCertsTrustManager((X509TrustManager)managers[i]);
            }
        }

        SSLContext ctx;
        try {
            ctx = SSLContext.getInstance("SSL");
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IOException(e.getMessage());
        }

        try {
            ctx.init(null, managers, null);
        } catch (KeyManagementException e) {
            throw new IOException(e.getMessage());
        }

        sslSocketFactory = ctx.getSocketFactory();
    }

    public static SocketFactory getDefault() {
        synchronized(JsseSSLSocketFactory.class) {
            if (default_factory == null) {
                default_factory = new JsseSSLSocketFactory();
            }
        }

        return default_factory;
    }

    public Socket createSocket(String host, int port) throws IOException  {
        if (sslSocketFactory == null) {
            init();
        }

        return sslSocketFactory.createSocket(host, port);
    }

    public Socket createSocket(InetAddress host, int port) throws IOException {
        if (sslSocketFactory == null) {
            init();
        }

        return sslSocketFactory.createSocket(host, port);
    }

    public Socket createSocket(InetAddress host, int port, InetAddress client_host, int client_port) throws IOException {
        if (sslSocketFactory == null) {
            init();
        }

        return sslSocketFactory.createSocket(host, port, client_host, client_port);
    }

    public Socket createSocket(String host, int port, InetAddress client_host, int client_port) throws IOException {
        if (sslSocketFactory == null) {
            init();
        }

        return sslSocketFactory.createSocket(host, port, client_host, client_port);
    }
}