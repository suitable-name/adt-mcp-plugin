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
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
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

    /**
     * Only for the enrollment claim. No identity can be attached here, and the handshake fails
     * unless the relay presents the CA the link's token pins.
     */
    static HttpClient registrationClient(PinnedAuthority pinned) throws GeneralSecurityException {
        return httpClient(null, new TrustManager[] {pinned});
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

    /** The presented chain holds no certificate with the fingerprint the enrollment link pins. */
    static final class PinMismatch extends CertificateException {
        private static final long serialVersionUID = 1L;

        PinMismatch() {
            super("The relay did not present the pinned CA.");
        }
    }

    /**
     * Enrollment trust: during the handshake, and so before the claim secret is sent, requires a
     * certificate in the presented chain whose SHA-256 equals the fingerprint pinned by the link's
     * token, then validates the chain with PKIX using that certificate as the only trust anchor.
     * Standard PKIX checks signatures, validity, and the endpoint hostname using the actual socket
     * or engine.
     */
    static final class PinnedAuthority extends X509ExtendedTrustManager {
        private final byte[] pinned;
        private volatile boolean mismatched;

        PinnedAuthority(byte[] pinnedFingerprint) {
            this.pinned = pinnedFingerprint.clone();
        }

        /** True once a handshake was refused because the pinned CA was not presented. */
        boolean mismatched() { return mismatched; }

        private X509ExtendedTrustManager anchored(X509Certificate[] chain) throws CertificateException {
            if (chain == null || chain.length == 0) {
                mismatched = true;
                throw new PinMismatch();
            }
            try {
                // The enrollment listener sends the CA last, so search from the end.
                for (int i = chain.length - 1; i >= 0; i--) {
                    if (MessageDigest.isEqual(pinned, fingerprint(chain[i]))) {
                        X509Certificate ca = chain[i];
                        if (ca.getBasicConstraints() < 0) break;
                        ca.checkValidity();
                        return trustManager(ca);
                    }
                }
            } catch (GeneralSecurityException | IOException e) {
                throw new CertificateException("Could not validate the registration CA.", e);
            }
            mismatched = true;
            throw new PinMismatch();
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String auth, SSLEngine engine) throws CertificateException {
            anchored(chain).checkServerTrusted(chain, auth, engine);
        }
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String auth, Socket socket) throws CertificateException {
            anchored(chain).checkServerTrusted(chain, auth, socket);
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

    /**
     * The label the relay put into an issued Eclipse certificate (subject CN {@code eclipse:<label>}).
     * The relay's stored label wins over the link's optional one, so the profile takes it from here.
     */
    static String certificateLabel(String certificatePem) throws GeneralSecurityException {
        X509Certificate leaf = certificate(certificatePem);
        try {
            for (Rdn rdn : new LdapName(leaf.getSubjectX500Principal().getName(X500Principal.RFC2253)).getRdns()) {
                if (rdn.getType().equalsIgnoreCase("CN") && rdn.getValue() instanceof String cn
                        && cn.startsWith("eclipse:") && cn.length() > "eclipse:".length()) {
                    return cn.substring("eclipse:".length());
                }
            }
        } catch (InvalidNameException e) {
            throw new GeneralSecurityException("Invalid relay client certificate.", e);
        }
        throw new GeneralSecurityException("Invalid relay client certificate.");
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

    /** This Eclipse's label as the relay certificate names it. */
    public String label() throws IOException {
        return string(profile, "label");
    }

    /**
     * This Eclipse's relay fingerprint, the endpoint ID: lowercase hex SHA-256 of its relay client certificate.
     *
     * @throws GeneralSecurityException if the stored certificate is unusable
     */
    public String relayFingerprint() throws GeneralSecurityException, IOException {
        byte[] digest = fingerprint(certificate(string(profile, "client_cert_pem")));
        StringBuilder hex = new StringBuilder(64);
        for (byte b : digest) {
            hex.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return hex.toString();
    }
}
