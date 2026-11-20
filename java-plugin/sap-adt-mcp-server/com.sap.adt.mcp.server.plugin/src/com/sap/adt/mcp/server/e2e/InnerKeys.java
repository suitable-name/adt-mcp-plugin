package com.sap.adt.mcp.server.e2e;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * The plugin's long-term inner identity: an ECDSA P-256 key (plan D1) and a minimal self-signed X.509 v3
 * certificate for it. The pin is the SHA-256 of the key's SubjectPublicKeyInfo DER, not of the certificate;
 * the certificate's names and dates carry no meaning, so it is simply regenerated if it ever changes.
 *
 * <p>The JDK has no public X.509 builder and the plugin ships no BouncyCastle, so {@link #selfSignedCertificate}
 * writes the DER by hand from a fixed template.</p>
 */
public final class InnerKeys {
    private static final byte[] OID_ECDSA_SHA256 = {0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x04, 0x03, 0x02};
    private static final byte[] OID_COMMON_NAME = {0x06, 0x03, 0x55, 0x04, 0x03};
    private static final byte[] OID_BASIC_CONSTRAINTS = {0x06, 0x03, 0x55, 0x1D, 0x13};
    private static final byte[] OID_KEY_USAGE = {0x06, 0x03, 0x55, 0x1D, 0x0F};
    private static final byte[] OID_EXT_KEY_USAGE = {0x06, 0x03, 0x55, 0x1D, 0x25};
    private static final byte[] OID_SERVER_AUTH = {0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01};
    private static final byte[] OID_CLIENT_AUTH = {0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02};
    private static final String COMMON_NAME = "SAP ADT MCP Eclipse";
    private static final String NOT_BEFORE = "200101000000Z";
    private static final String NOT_AFTER = "99991231235959Z";
    private static final byte[] PROOF = "SAP ADT inner key check".getBytes(StandardCharsets.US_ASCII);
    private static final int BLOB_VERSION = 1;
    private static final int MAX_BLOB_PART = 16 * 1024;

    private final PrivateKey privateKey;
    private final X509Certificate certificate;
    private final String fingerprint;

    private InnerKeys(PrivateKey privateKey, X509Certificate certificate) {
        this.privateKey = privateKey;
        this.certificate = certificate;
        this.fingerprint = fingerprint(certificate.getPublicKey());
    }

    /** Loads the stored identity, or creates and stores one when the storage is empty. */
    public static InnerKeys loadOrCreate(KeyStorage storage) throws GeneralSecurityException, IOException {
        byte[] blob = storage.read();
        if (blob != null) {
            // A damaged identity is an error, never a silent rotation: a new key would unpair every desktop.
            return fromBlob(blob);
        }
        KeyPair pair = newKeyPair();
        InnerKeys keys = new InnerKeys(pair.getPrivate(), parse(selfSignedCertificate(pair)));
        storage.write(keys.toBlob());
        return keys;
    }

    /** A fresh identity that is not stored (tests, throw-away clients). */
    public static InnerKeys generate() throws GeneralSecurityException {
        KeyPair pair = newKeyPair();
        return new InnerKeys(pair.getPrivate(), parse(selfSignedCertificate(pair)));
    }

    public PrivateKey privateKey() {
        return privateKey;
    }

    public X509Certificate certificate() {
        return certificate;
    }

    public PublicKey publicKey() {
        return certificate.getPublicKey();
    }

    /** Lowercase hex SHA-256 of the SubjectPublicKeyInfo DER. */
    public String fingerprint() {
        return fingerprint;
    }

    /** The 32-byte SHA-256 of the SubjectPublicKeyInfo DER. */
    public byte[] fingerprintBytes() {
        return HexFormat.of().parseHex(fingerprint);
    }

    /** Lowercase hex SHA-256 of {@code key}'s SubjectPublicKeyInfo DER. */
    public static String fingerprint(PublicKey key) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(key.getEncoded()));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 is unavailable.", e);
        }
    }

    /** True for an EC key on secp256r1 (P-256). */
    public static boolean isP256(PublicKey key) {
        return key instanceof ECPublicKey ec && ec.getParams().getCurve().getField().getFieldSize() == 256
                && ec.getParams().getOrder().bitLength() == 256;
    }

    private static KeyPair newKeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        return generator.generateKeyPair();
    }

    // ------------------------------------------------------------------ storage blob

    private byte[] toBlob() throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            byte[] key = privateKey.getEncoded();
            byte[] cert;
            try {
                cert = certificate.getEncoded();
            } catch (GeneralSecurityException e) {
                throw new IOException("Invalid inner certificate.");
            }
            out.writeByte(BLOB_VERSION);
            out.writeInt(key.length);
            out.write(key);
            out.writeInt(cert.length);
            out.write(cert);
            Arrays.fill(key, (byte) 0);
        }
        return bytes.toByteArray();
    }

    private static InnerKeys fromBlob(byte[] blob) throws GeneralSecurityException, IOException {
        byte[] key = null;
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(blob))) {
            if (in.readUnsignedByte() != BLOB_VERSION) {
                throw new IOException("Unsupported inner key storage.");
            }
            key = part(in);
            byte[] cert = part(in);
            if (in.available() != 0) {
                throw new IOException("Invalid inner key storage.");
            }
            X509Certificate certificate = parse(cert);
            if (!isP256(certificate.getPublicKey())) {
                throw new GeneralSecurityException("The inner key is not a P-256 key.");
            }
            PrivateKey privateKey = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(key));
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(privateKey);
            signer.update(PROOF);
            byte[] signed = signer.sign();
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(certificate.getPublicKey());
            verifier.update(PROOF);
            if (!verifier.verify(signed)) {
                throw new GeneralSecurityException("The inner key and certificate do not match.");
            }
            return new InnerKeys(privateKey, certificate);
        } finally {
            if (key != null) {
                Arrays.fill(key, (byte) 0);
            }
        }
    }

    private static byte[] part(DataInputStream in) throws IOException {
        int length = in.readInt();
        if (length <= 0 || length > MAX_BLOB_PART) {
            throw new IOException("Invalid inner key storage.");
        }
        byte[] data = new byte[length];
        in.readFully(data);
        return data;
    }

    private static X509Certificate parse(byte[] der) throws GeneralSecurityException {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
    }

    // ------------------------------------------------------------------ DER certificate writer

    /**
     * A self-signed X.509 v3 certificate for the pair, DER encoded, from this fixed template:
     * <pre>
     * Certificate  ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }
     * tbsCertificate ::= SEQUENCE {
     *   [0] version 2 (v3),
     *   serialNumber   16 random bytes, positive (first byte 0x40..0x7F),
     *   signature      ecdsa-with-SHA256 (1.2.840.10045.4.3.2, no parameters),
     *   issuer         CN=SAP ADT MCP Eclipse,
     *   validity       UTCTime 200101000000Z .. GeneralizedTime 99991231235959Z,
     *   subject        CN=SAP ADT MCP Eclipse (same as the issuer),
     *   subjectPublicKeyInfo  the key's own X.509 encoding (P-256),
     *   [3] extensions basicConstraints (critical, CA false), keyUsage (critical, digitalSignature),
     *                  extendedKeyUsage (serverAuth, clientAuth) }
     * </pre>
     * The signature is {@code SHA256withECDSA} over the DER of {@code tbsCertificate}.
     */
    static byte[] selfSignedCertificate(KeyPair pair) throws GeneralSecurityException {
        byte[] signatureAlgorithm = der(0x30, OID_ECDSA_SHA256);
        byte[] name = der(0x30, der(0x31, der(0x30, OID_COMMON_NAME,
                der(0x0C, COMMON_NAME.getBytes(StandardCharsets.UTF_8)))));
        byte[] serial = new byte[16];
        new SecureRandom().nextBytes(serial);
        serial[0] = (byte) ((serial[0] & 0x3F) | 0x40);
        byte[] validity = der(0x30, der(0x17, NOT_BEFORE.getBytes(StandardCharsets.US_ASCII)),
                der(0x18, NOT_AFTER.getBytes(StandardCharsets.US_ASCII)));
        byte[] basicConstraints = der(0x30, OID_BASIC_CONSTRAINTS, new byte[] {0x01, 0x01, (byte) 0xFF},
                der(0x04, der(0x30)));
        byte[] keyUsage = der(0x30, OID_KEY_USAGE, new byte[] {0x01, 0x01, (byte) 0xFF},
                der(0x04, new byte[] {0x03, 0x02, 0x07, (byte) 0x80}));
        byte[] extendedKeyUsage = der(0x30, OID_EXT_KEY_USAGE, der(0x04, der(0x30, OID_SERVER_AUTH, OID_CLIENT_AUTH)));
        byte[] tbs = der(0x30,
                der(0xA0, der(0x02, new byte[] {0x02})),
                der(0x02, serial),
                signatureAlgorithm,
                name,
                validity,
                name,
                pair.getPublic().getEncoded(),
                der(0xA3, der(0x30, basicConstraints, keyUsage, extendedKeyUsage)));
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(pair.getPrivate());
        signer.update(tbs);
        byte[] signature = signer.sign();
        byte[] bits = new byte[signature.length + 1];
        System.arraycopy(signature, 0, bits, 1, signature.length);
        return der(0x30, tbs, signatureAlgorithm, der(0x03, bits));
    }

    /** One DER TLV whose value is the concatenation of {@code parts}. */
    private static byte[] der(int tag, byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(length + 4);
        out.write(tag);
        if (length < 0x80) {
            out.write(length);
        } else if (length < 0x100) {
            out.write(0x81);
            out.write(length);
        } else if (length < 0x10000) {
            out.write(0x82);
            out.write(length >>> 8);
            out.write(length);
        } else {
            throw new IllegalArgumentException("DER element too long.");
        }
        for (byte[] part : parts) {
            out.write(part, 0, part.length);
        }
        return out.toByteArray();
    }
}
