package com.sap.adt.mcp.server;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLEngine;

/**
 * Regression harness for enrollment by link: the pinning trust manager and the mapping from an
 * enrollment link to the bridge URL and registration origin. The certificates are fixed test
 * certificates (two unrelated P-256 CAs, each with a leaf for relay.test, valid to 2126).
 */
public final class RelayEnrollmentRegression {
    private static final String CA_A = """
            -----BEGIN CERTIFICATE-----
            MIIBmjCCAUGgAwIBAgIUDoHW8e14LhMbSxCCgJ7gRVtvq9gwCgYIKoZIzj0EAwIw
            GjEYMBYGA1UEAwwPVGVzdCBSZWxheSBDQSBBMCAXDTI2MTEyMDEyNDY0NFoYDzIx
            MjYxMDI3MTI0NjQ0WjAaMRgwFgYDVQQDDA9UZXN0IFJlbGF5IENBIEEwWTATBgcq
            hkjOPQIBBggqhkjOPQMBBwNCAAS/l+rTLdlt8XMUac7XoSR8DW+rmhjumf08Boqn
            Z6oKpKNCV3iLUMqDEHw5rWBdX5SpVhlK8d3HSoI9K6BGLPqao2MwYTAdBgNVHQ4E
            FgQUHi/XPGH7a+mEyD8b6vKMi4FwaIgwHwYDVR0jBBgwFoAUHi/XPGH7a+mEyD8b
            6vKMi4FwaIgwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZI
            zj0EAwIDRwAwRAIgBPXKiCYRGB+sRuAdCEisHlOFX/v9E+BTvtHkfBtNL38CIHQW
            OCey2BNlqwnnSMF/27Btq07ROKQ/UUqYgurij0+k
            -----END CERTIFICATE-----
            """;
    private static final String LEAF_A = """
            -----BEGIN CERTIFICATE-----
            MIIBwTCCAWegAwIBAgIUEmZjrI7BZTwFhUsHoOInGMitOF0wCgYIKoZIzj0EAwIw
            GjEYMBYGA1UEAwwPVGVzdCBSZWxheSBDQSBBMCAXDTI2MTEyMDEyNDY0NFoYDzIx
            MjYxMDI3MTI0NjQ0WjAVMRMwEQYDVQQDDApyZWxheS50ZXN0MFkwEwYHKoZIzj0C
            AQYIKoZIzj0DAQcDQgAEc7Euo9lUQb/bKy4mIo/24IGgdHsa8hSxEtEk0cPD5Bxt
            ZVMoMQbwHzcyHwXT2W1tZPhKDLuRK5M/3akz1HXKvKOBjTCBijAMBgNVHRMBAf8E
            AjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAVBgNVHREE
            DjAMggpyZWxheS50ZXN0MB0GA1UdDgQWBBQG/xiBvE70O0wq/5KRRBEvREEI0jAf
            BgNVHSMEGDAWgBQeL9c8Yftr6YTIPxvq8oyLgXBoiDAKBggqhkjOPQQDAgNIADBF
            AiEA3GCZ12X4PfvX3N/oMFLTycKuj0YWOf63YJJH7WmpZ/ECIHaFdd3BNLUbDDLz
            asx1vF7GfAqa2PZJSPIkrgkCo3VZ
            -----END CERTIFICATE-----
            """;
    private static final String CA_B = """
            -----BEGIN CERTIFICATE-----
            MIIBnDCCAUGgAwIBAgIUcVDiOyz8IJK2jSNkhf2fGFYDa6EwCgYIKoZIzj0EAwIw
            GjEYMBYGA1UEAwwPVGVzdCBSZWxheSBDQSBCMCAXDTI2MTEyMDEyNDY0NFoYDzIx
            MjYxMDI3MTI0NjQ0WjAaMRgwFgYDVQQDDA9UZXN0IFJlbGF5IENBIEIwWTATBgcq
            hkjOPQIBBggqhkjOPQMBBwNCAAT7VJqOn8dx9Z1nX7Y3IGnLyTLMc9SKPhgZh7Mk
            TZvwYMcRuhWAF/cW/q3EBf1AWi5P3faHPQnh4tPOLAncJR/2o2MwYTAdBgNVHQ4E
            FgQUoawKOc9BNeKfExE2B1K7m3Cq8rMwHwYDVR0jBBgwFoAUoawKOc9BNeKfExE2
            B1K7m3Cq8rMwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZI
            zj0EAwIDSQAwRgIhAN8OYu3kkl3kYGf5XLp4UPrCZVsWe6ZQDZuLiLE4Q/OkAiEA
            kTNyfcXDIrvX5MfGTKYIt5QCqm5mrdulmy2ffvnpewU=
            -----END CERTIFICATE-----
            """;
    private static final String LEAF_B = """
            -----BEGIN CERTIFICATE-----
            MIIBwjCCAWegAwIBAgIUXKteUq+8LVX7TRN/cjAIkiDuQbUwCgYIKoZIzj0EAwIw
            GjEYMBYGA1UEAwwPVGVzdCBSZWxheSBDQSBCMCAXDTI2MTEyMDEyNDY0NFoYDzIx
            MjYxMDI3MTI0NjQ0WjAVMRMwEQYDVQQDDApyZWxheS50ZXN0MFkwEwYHKoZIzj0C
            AQYIKoZIzj0DAQcDQgAECRPaoqLJSzqYzrfElV+CXKzD85pM+0QziBvaKgCtONrR
            KVPHVrsFRMYImfIx5cOKQ4D3Sd/CoqoByIQBqFnbUKOBjTCBijAMBgNVHRMBAf8E
            AjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAVBgNVHREE
            DjAMggpyZWxheS50ZXN0MB0GA1UdDgQWBBRPUHIbcSBl5E2q6oiBR68S9NszqDAf
            BgNVHSMEGDAWgBShrAo5z0E14p8TETYHUrubcKryszAKBggqhkjOPQQDAgNJADBG
            AiEAsRWCcuuZepBzSmZ/TfOHohNeNgGAtZhQpCYFdg+ihdsCIQDzVV9A3erIdbJo
            /w7FAo0kwmU/vbuek5b+PA2pNEemiA==
            -----END CERTIFICATE-----
            """;
    private static final String CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    public static void main(String[] args) throws Exception {
        X509Certificate caA = cert(CA_A);
        X509Certificate leafA = cert(LEAF_A);
        X509Certificate caB = cert(CA_B);
        X509Certificate leafB = cert(LEAF_B);
        byte[] pinA = sha256(caA);
        check(!MessageDigest.isEqual(pinA, sha256(caB)));

        // The chain contains the pinned CA (sent last): accepted.
        RelayIdentity.PinnedAuthority pinned = new RelayIdentity.PinnedAuthority(pinA);
        pinned.checkServerTrusted(new X509Certificate[] {leafA, caA}, "ECDHE_ECDSA", (SSLEngine) null);
        check(!pinned.mismatched());

        // No pinned CA in the chain: another relay's chain, a bare leaf, an empty chain.
        mismatch(pinA, new X509Certificate[] {leafB, caB});
        mismatch(pinA, new X509Certificate[] {leafA});
        mismatch(pinA, new X509Certificate[0]);
        mismatch(pinA, null);

        // The pinned CA is present but did not sign the leaf: refused by PKIX, not accepted.
        RelayIdentity.PinnedAuthority wrongLeaf = new RelayIdentity.PinnedAuthority(pinA);
        try {
            wrongLeaf.checkServerTrusted(new X509Certificate[] {leafB, caA}, "ECDHE_ECDSA", (SSLEngine) null);
            throw new AssertionError("Accepted a leaf the pinned CA did not issue");
        } catch (CertificateException e) {
            check(!(e instanceof RelayIdentity.PinMismatch));
        }

        // The legacy two-argument form has no endpoint identification and is refused.
        try {
            new RelayIdentity.PinnedAuthority(pinA).checkServerTrusted(new X509Certificate[] {leafA, caA}, "ECDHE_ECDSA");
            throw new AssertionError("Accepted without endpoint identification");
        } catch (CertificateException expected) {
            // refused
        }

        // Link to enrollment mapping.
        String token = token(pinA);
        RelayLink link = RelayLink.parse("sap-adt://enroll?v=1&r=eclipse&n=Gussek+Relay&s=relay.example.com:8787"
                + "&e=relay.example.com:8788&t=" + token);
        check(RelayLink.tokenFingerprint(token) != null
                && MessageDigest.isEqual(RelayLink.tokenFingerprint(token), pinA));
        RelayEnrollment enrollment = new RelayEnrollment(link);
        check(enrollment.bridgeUrl().equals("wss://relay.example.com:8787/bridge"));
        check(enrollment.registrationOrigin().equals("https://relay.example.com:8788"));
        RelayEnrollment v6 = new RelayEnrollment(RelayLink.parse("sap-adt://enroll?v=1&r=eclipse&n=x&s=[::1]:8787"
                + "&e=[::1]:8788&t=" + token));
        check(v6.bridgeUrl().equals("wss://[::1]:8787/bridge"));
        check(v6.registrationOrigin().equals("https://[::1]:8788"));

        // Only an eclipse enrollment link is accepted.
        refused(RelayLink.parse("sap-adt://enroll?v=1&r=desktop&n=x&s=h.test:1&e=h.test:2&t=" + token));
        refused(RelayLink.parse("sap-adt://pair?v=1&p=" + "ab".repeat(32) + "&t=" + token));

        // The two failure texts are fixed.
        check(RelayEnrollment.PIN_MISMATCH.equals("The relay did not present the CA this link belongs to. "
                + "This is either the wrong relay or an attacker in the middle."));
        check(RelayEnrollment.CLAIM_REFUSED.equals("The link was invalid, expired, cancelled or already used. "
                + "Ask the relay operator for a new link."));
        System.out.println("RelayEnrollmentRegression passed.");
    }

    private static void mismatch(byte[] pin, X509Certificate[] chain) {
        RelayIdentity.PinnedAuthority pinned = new RelayIdentity.PinnedAuthority(pin);
        try {
            pinned.checkServerTrusted(chain, "ECDHE_ECDSA", (SSLEngine) null);
            throw new AssertionError("Accepted a chain without the pinned CA");
        } catch (CertificateException e) {
            check(e instanceof RelayIdentity.PinMismatch);
            check(pinned.mismatched());
        }
    }

    private static void refused(RelayLink link) {
        try {
            new RelayEnrollment(link);
            throw new AssertionError("Accepted a link that is not an eclipse enrollment link");
        } catch (IllegalArgumentException expected) {
            // refused
        }
    }

    private static X509Certificate cert(String pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
    }

    private static byte[] sha256(X509Certificate certificate) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
    }

    /** GW1- plus Crockford Base32 of a 32-byte secret followed by the fingerprint. */
    private static String token(byte[] fingerprint) {
        byte[] payload = new byte[64];
        for (int i = 0; i < 32; i++) payload[i] = (byte) (i * 5 + 1);
        System.arraycopy(fingerprint, 0, payload, 32, 32);
        StringBuilder out = new StringBuilder("GW1-");
        int accumulator = 0;
        int bits = 0;
        for (byte b : payload) {
            accumulator = (accumulator << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                out.append(CROCKFORD.charAt((accumulator >> bits) & 31));
            }
            accumulator &= (1 << bits) - 1;
        }
        if (bits > 0) out.append(CROCKFORD.charAt((accumulator << (5 - bits)) & 31));
        return out.toString();
    }

    private static void check(boolean condition) {
        if (!condition) throw new AssertionError();
    }
}
