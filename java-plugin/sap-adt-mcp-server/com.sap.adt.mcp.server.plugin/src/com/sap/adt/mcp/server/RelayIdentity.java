package com.sap.adt.mcp.server;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.SSLEngine;
import java.net.Socket;
import javax.security.auth.x500.X500Principal;
import javax.naming.ldap.Rdn;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/** Company relay client identity as issued by the registration service. */
public final class RelayIdentity {
    private final JsonObject profile;
    final URI bridge;
    final HttpClient client;

    private RelayIdentity(JsonObject profile, URI bridge, HttpClient client) {
        this.profile = profile;
        this.bridge = bridge;
        this.client = client;
    }

    static RelayIdentity fromProfile(JsonObject profile) throws IOException, GeneralSecurityException {
        URI bridge = checkEndpoint(string(profile, "bridge"), "wss", "/bridge");
        X509Certificate ca = authority(string(profile, "ca_pem"));
        X509Certificate leaf = certificate(string(profile, "client_cert_pem"));
        leaf.checkValidity();
        List<String> usages = leaf.getExtendedKeyUsage();
        boolean[] keyUsage = leaf.getKeyUsage();
        X500Principal expected = new X500Principal("CN=" + Rdn.escapeValue("eclipse:" + string(profile, "label")));
        if (leaf.getBasicConstraints() != -1 || !leaf.getIssuerX500Principal().equals(ca.getSubjectX500Principal())
                || !leaf.getSubjectX500Principal().equals(expected) || keyUsage == null || !keyUsage[0]
                || usages == null || !usages.contains("1.3.6.1.5.5.7.3.2")) {
            throw new GeneralSecurityException("Invalid relay client certificate.");
        }
        leaf.verify(ca.getPublicKey());
        byte[] encoded = der(string(profile, "client_key_pem"), "PRIVATE KEY");
        PrivateKey key;
        try {
            key = KeyFactory.getInstance(leaf.getPublicKey().getAlgorithm())
                    .generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
        String algorithm = switch (key.getAlgorithm()) {
            case "EC" -> "SHA256withECDSA";
            case "RSA" -> "SHA256withRSA";
            case "EdDSA", "Ed25519" -> "Ed25519";
            default -> throw new GeneralSecurityException("Unsupported relay client key.");
        };
        Signature proof = Signature.getInstance(algorithm);
        byte[] challenge = "SAP ADT relay client key check".getBytes(StandardCharsets.US_ASCII);
        proof.initSign(key);
        proof.update(challenge);
        byte[] signed = proof.sign();
        proof.initVerify(leaf.getPublicKey());
        proof.update(challenge);
        if (!proof.verify(signed)) {
            throw new GeneralSecurityException("Mismatched relay client key.");
        }
        KeyStore identity = KeyStore.getInstance("PKCS12");
        identity.load(null, null);
        char[] password = new char[0];
        identity.setKeyEntry("eclipse", key, password, new Certificate[] {leaf, ca});
        KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(identity, password);
        return new RelayIdentity(profile, bridge, httpClient(ca, keys.getKeyManagers()));
    }

    static HttpClient httpClient(X509Certificate ca, KeyManager[] keys) throws GeneralSecurityException, IOException {
        return httpClient(keys, new TrustManager[] {trustManager(ca)});
    }

    private static X509ExtendedTrustManager trustManager(X509Certificate ca) throws GeneralSecurityException, IOException {
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry("relay-ca", ca);
        TrustManagerFactory trustManagers = TrustManagerFactory.getInstance("PKIX");
        trustManagers.init(trust);
        for (TrustManager manager : trustManagers.getTrustManagers()) {
            if (manager instanceof X509ExtendedTrustManager pkix) return pkix;
        }
        throw new GeneralSecurityException("An endpoint-aware PKIX trust manager is required.");
    }

    /** Only for the public registration request. No token or identity can be attached here. */
    static HttpClient registrationClient() throws GeneralSecurityException {
        return httpClient(null, new TrustManager[] {new PresentedAuthority()});
    }

    private static HttpClient httpClient(KeyManager[] keys, TrustManager[] trust) throws GeneralSecurityException {
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        // An explicitly empty key manager list prevents ambient client certificates on registration.
        context.init(keys == null ? new KeyManager[0] : keys, trust, null);
        SSLParameters parameters = context.getDefaultSSLParameters();
        parameters.setProtocols(new String[] {"TLSv1.3"});
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        return HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).sslContext(context)
                .sslParameters(parameters).connectTimeout(Duration.ofSeconds(15))
                .followRedirects(HttpClient.Redirect.NEVER).build();
    }

    /** Public bootstrap trusts the presented root for this handshake only. Standard PKIX checks
     * signatures, validity, and the endpoint hostname using the actual socket or engine. */
    private static final class PresentedAuthority extends X509ExtendedTrustManager {
        private static X509ExtendedTrustManager provisional(X509Certificate[] chain) throws CertificateException {
            if (chain == null || chain.length < 2) throw new CertificateException("Missing registration CA.");
            X509Certificate ca = chain[chain.length - 1];
            try {
                ca.checkValidity();
                if (ca.getBasicConstraints() < 0 || !ca.getSubjectX500Principal().equals(ca.getIssuerX500Principal())) {
                    throw new CertificateException("Invalid registration CA.");
                }
                ca.verify(ca.getPublicKey());
                return trustManager(ca);
            } catch (GeneralSecurityException | IOException e) {
                throw new CertificateException("Could not validate the registration CA.", e);
            }
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String auth, SSLEngine engine) throws CertificateException {
            provisional(chain).checkServerTrusted(chain, auth, engine);
        }
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String auth, Socket socket) throws CertificateException {
            provisional(chain).checkServerTrusted(chain, auth, socket);
        }
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String auth) throws CertificateException {
            throw new CertificateException("Endpoint identification is required.");
        }
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String auth) throws CertificateException {
            throw new CertificateException("This is a registration client.");
        }
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String auth, Socket socket) throws CertificateException {
            throw new CertificateException("This is a registration client.");
        }
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String auth, SSLEngine engine) throws CertificateException {
            throw new CertificateException("This is a registration client.");
        }
        @Override
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    static URI checkEndpoint(String value, String scheme, String path) {
        URI uri = URI.create(value);
        if (!scheme.equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getPort() == 0
                || uri.getPort() > 65535 || uri.getRawUserInfo() != null || uri.getRawQuery() != null
                || uri.getRawFragment() != null || !(path.equals(uri.getRawPath())
                    || (path.isEmpty() && "/".equals(uri.getRawPath())))) {
            throw new IllegalArgumentException("Invalid relay endpoint.");
        }
        return uri;
    }

    static String string(JsonObject object, String key) throws IOException {
        JsonElement value = object.get(key);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()
                || value.getAsString().isEmpty()) {
            throw new IOException("Missing registration field.");
        }
        return value.getAsString();
    }

    static X509Certificate authority(String pem) throws GeneralSecurityException {
        X509Certificate ca = certificate(pem);
        ca.checkValidity();
        if (ca.getBasicConstraints() < 0) {
            throw new GeneralSecurityException("Invalid relay CA.");
        }
        return ca;
    }

    static byte[] fingerprint(X509Certificate certificate) throws GeneralSecurityException {
        return MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
    }

    private static X509Certificate certificate(String pem) throws GeneralSecurityException {
        byte[] encoded = der(pem, "CERTIFICATE");
        ByteArrayInputStream input = new ByteArrayInputStream(encoded);
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
        if (input.available() != 0 || !Arrays.equals(encoded, cert.getEncoded())) {
            throw new GeneralSecurityException("Unexpected certificate data.");
        }
        return cert;
    }

    private static byte[] der(String pem, String type) throws GeneralSecurityException {
        String begin = "-----BEGIN " + type + "-----";
        String end = "-----END " + type + "-----";
        String text = pem.strip();
        if (!text.startsWith(begin) || !text.endsWith(end)) {
            throw new GeneralSecurityException("Incorrect PEM type.");
        }
        return Base64.getDecoder().decode(text.substring(begin.length(), text.length() - end.length())
                .replace("\r", "").replace("\n", "").strip());
    }

    JsonObject profile() {
        return profile;
    }
}
