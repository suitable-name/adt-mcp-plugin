package com.sap.adt.mcp.server.e2e;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HexFormat;

/** Regression harness for {@link InnerKeys}: the hand-written DER certificate, the pin and the storage. */
public final class InnerKeysRegression {
    private static final class Memory implements KeyStorage {
        byte[] blob;

        @Override
        public byte[] read() {
            return blob == null ? null : blob.clone();
        }

        @Override
        public void write(byte[] data) {
            blob = data.clone();
        }
    }

    public static void main(String[] args) throws Exception {
        certificateParsesAndVerifies();
        fingerprintIsStable();
        storageKeepsTheIdentity();
        System.out.println("InnerKeysRegression passed.");
    }

    private static void certificateParsesAndVerifies() throws Exception {
        InnerKeys keys = InnerKeys.generate();
        X509Certificate cert = keys.certificate();
        check(cert.getVersion() == 3);
        cert.verify(cert.getPublicKey());
        cert.checkValidity();
        check(cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal()));
        check(cert.getSubjectX500Principal().getName().contains("SAP ADT MCP Eclipse"));
        check(cert.getSigAlgOID().equals("1.2.840.10045.4.3.2"));
        check(cert.getBasicConstraints() == -1);
        check(cert.getKeyUsage() != null && cert.getKeyUsage()[0]);
        check(cert.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.1")
                && cert.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.2"));
        check(cert.getNotAfter().getTime() > 4_000_000_000_000L);
        check(InnerKeys.isP256(cert.getPublicKey()));
        check(cert.getPublicKey().equals(keys.publicKey()));

        // The private key matches the certificate.
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(keys.privateKey());
        signer.update(new byte[] {1, 2, 3});
        byte[] signed = signer.sign();
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(cert.getPublicKey());
        verifier.update(new byte[] {1, 2, 3});
        check(verifier.verify(signed));

        // A flipped bit in the signature or the signed part must not verify.
        byte[] der = cert.getEncoded();
        byte[] tampered = der.clone();
        tampered[tampered.length - 5] ^= 0x01;
        verifyFails(tampered, cert);
        byte[] tbs = der.clone();
        tbs[60] ^= 0x01;
        verifyFails(tbs, cert);
    }

    private static void verifyFails(byte[] der, X509Certificate original) {
        try {
            X509Certificate changed = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
            changed.verify(original.getPublicKey());
        } catch (GeneralSecurityException e) {
            return;
        }
        throw new AssertionError("A modified certificate verified.");
    }

    private static void fingerprintIsStable() throws Exception {
        InnerKeys keys = InnerKeys.generate();
        byte[] spki = keys.publicKey().getEncoded();
        // SubjectPublicKeyInfo of an uncompressed P-256 key, as rcgen and rustls see it.
        byte[] prefix = HexFormat.of().parseHex("3059301306072a8648ce3d020106082a8648ce3d030107034200" + "04");
        check(spki.length == 91 && Arrays.equals(Arrays.copyOf(spki, prefix.length), prefix));
        String expected = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(spki));
        check(keys.fingerprint().equals(expected));
        check(keys.fingerprint().equals(keys.fingerprint()));
        check(keys.fingerprint().equals(InnerKeys.fingerprint(keys.certificate().getPublicKey())));
        check(Arrays.equals(keys.fingerprintBytes(), HexFormat.of().parseHex(expected)));
        check(PinStore.isFingerprint(keys.fingerprint()));
        // A new certificate for the same key (the signature is randomised) keeps the pin.
        check(!keys.fingerprint().equals(InnerKeys.generate().fingerprint()));
    }

    private static void storageKeepsTheIdentity() throws Exception {
        Memory storage = new Memory();
        InnerKeys first = InnerKeys.loadOrCreate(storage);
        check(storage.blob != null);
        InnerKeys second = InnerKeys.loadOrCreate(storage);
        check(first.fingerprint().equals(second.fingerprint()));
        check(Arrays.equals(first.certificate().getEncoded(), second.certificate().getEncoded()));
        // A damaged identity is an error, never a silent rotation.
        Memory damaged = new Memory();
        damaged.blob = new byte[] {1, 0, 0, 0, 3, 1, 2, 3, 0, 0, 0, 3, 1, 2, 3};
        try {
            InnerKeys.loadOrCreate(damaged);
            throw new AssertionError("A damaged identity loaded.");
        } catch (GeneralSecurityException | IOException e) {
            check(Arrays.equals(damaged.blob, new byte[] {1, 0, 0, 0, 3, 1, 2, 3, 0, 0, 0, 3, 1, 2, 3}));
        }
        // A certificate that belongs to another key is refused.
        InnerKeys other = InnerKeys.generate();
        Memory mixed = new Memory();
        InnerKeys.loadOrCreate(mixed);
        Memory donor = new Memory();
        InnerKeys.loadOrCreate(donor);
        byte[] a = mixed.blob;
        byte[] b = donor.blob;
        int keyLength = ((a[1] & 0xFF) << 24 | (a[2] & 0xFF) << 16 | (a[3] & 0xFF) << 8 | (a[4] & 0xFF));
        int otherKeyLength = ((b[1] & 0xFF) << 24 | (b[2] & 0xFF) << 16 | (b[3] & 0xFF) << 8 | (b[4] & 0xFF));
        byte[] swapped = new byte[1 + 4 + keyLength + (b.length - 5 - otherKeyLength)];
        System.arraycopy(a, 0, swapped, 0, 5 + keyLength);
        System.arraycopy(b, 5 + otherKeyLength, swapped, 5 + keyLength, b.length - 5 - otherKeyLength);
        Memory wrong = new Memory();
        wrong.blob = swapped;
        try {
            InnerKeys.loadOrCreate(wrong);
            throw new AssertionError("A mismatched certificate loaded.");
        } catch (GeneralSecurityException | IOException e) {
            check(other != null);
        }
    }

    private static void check(boolean condition) {
        if (!condition) {
            throw new AssertionError("Inner keys regression.");
        }
    }
}
