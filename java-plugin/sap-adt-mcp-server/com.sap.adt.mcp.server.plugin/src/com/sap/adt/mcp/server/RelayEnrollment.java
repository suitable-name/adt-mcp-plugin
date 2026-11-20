package com.sap.adt.mcp.server;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.Strictness;

/**
 * Enrolls this Eclipse with the relay from an {@code sap-adt://enroll} link (role eclipse). The
 * claim pins the relay CA during the TLS handshake, before the secret is sent.
 */
public final class RelayEnrollment {
    public static final String PIN_MISMATCH = "The relay did not present the CA this link belongs to. "
            + "This is either the wrong relay or an attacker in the middle.";
    public static final String CLAIM_REFUSED = "The link was invalid, expired, cancelled or already used. "
            + "Ask the relay operator for a new link.";
    private static final int MAX_BYTES = 64 * 1024;
    private static final Gson JSON = new GsonBuilder().setStrictness(Strictness.STRICT).create();
    private final URI registration;
    private final URI bridge;
    private final RelayLink link;

    /**
     * @param link an enrollment link for the {@code eclipse} role. The link is used as is; the
     *             caller should {@link RelayLink#wipe() wipe} it after {@link #enroll()} returns.
     * @throws IllegalArgumentException when the link is not an enrollment link for Eclipse
     */
    public RelayEnrollment(RelayLink link) {
        if (link == null || link.kind() != RelayLink.Kind.ENROLL || link.role() != RelayLink.Role.ECLIPSE) {
            throw new IllegalArgumentException("Use an enrollment link for the eclipse role.");
        }
        this.registration = RelayIdentity.checkEndpoint(link.registrationUrl(), "https", "");
        this.bridge = RelayIdentity.checkEndpoint(link.bridgeUrl(), "wss", "/bridge");
        this.link = link;
    }

    /** The data (mTLS) bridge URL the profile will use: {@code wss://<s>/bridge}. */
    public String bridgeUrl() { return bridge.toASCIIString(); }

    /** The enrollment origin the claim goes to: {@code https://<e>}. */
    public String registrationOrigin() {
        return registration.getScheme() + "://" + registration.getRawAuthority();
    }

    /** All messages from this exception are generated locally and safe to display. */
    public static final class Failure extends Exception {
        private static final long serialVersionUID = 1L;

        private Failure(String message) {
            super(message);
        }
    }

    public RelayIdentity enroll() throws InterruptedException, Failure {
        String stage = "Could not reach the relay's enrollment address. Check the link and your network.";
        byte[] fingerprint = RelayLink.tokenFingerprint(new String(link.token()));
        if (fingerprint == null) throw new Failure("The link's code is not valid.");
        RelayIdentity.PinnedAuthority pinned = new RelayIdentity.PinnedAuthority(fingerprint);
        char[] secret = link.token();
        try {
            JsonObject claim = new JsonObject();
            claim.addProperty("token", new String(secret));
            JsonObject bundle = post(RelayIdentity.registrationClient(pinned), "/claim", claim, 30);
            stage = "The relay returned an invalid credential bundle.";
            String caPem = RelayIdentity.string(bundle, "ca_pem");
            X509Certificate issuedCa = RelayIdentity.authority(caPem);
            if (!MessageDigest.isEqual(fingerprint, RelayIdentity.fingerprint(issuedCa))) {
                throw new Failure("The claimed certificate bundle uses a different relay CA.");
            }
            String certificate = RelayIdentity.string(bundle, "client_cert_pem");
            JsonObject profile = new JsonObject();
            profile.addProperty("ca_pem", caPem);
            profile.addProperty("bridge", bridge.toASCIIString());
            profile.addProperty("label", RelayIdentity.certificateLabel(certificate));
            profile.addProperty("client_cert_pem", certificate);
            profile.addProperty("client_key_pem", RelayIdentity.string(bundle, "client_key_pem"));
            return RelayIdentity.fromProfile(profile);
        } catch (InterruptedException | Failure e) {
            throw e;
        } catch (Exception e) {
            if (pinned.mismatched() || causedByPinMismatch(e)) throw new Failure(PIN_MISMATCH);
            throw new Failure(stage);
        } finally {
            Arrays.fill(secret, '\0');
            Arrays.fill(fingerprint, (byte) 0);
            link.wipe(); // a link is single use; this enrollment cannot be run twice
        }
    }

    private static boolean causedByPinMismatch(Throwable failure) {
        Throwable cause = failure;
        for (int depth = 0; cause != null && depth < 16; depth++, cause = cause.getCause()) {
            if (cause instanceof RelayIdentity.PinMismatch) return true;
        }
        return false;
    }

    private JsonObject post(HttpClient client, String path, JsonObject json, int seconds) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(registration.resolve(path))
                .timeout(Duration.ofSeconds(seconds)).header("Content-Type", "application/json")
                .header("Accept", "application/json").POST(HttpRequest.BodyPublishers.ofString(json.toString())).build();
        var exchange = client.sendAsync(request, info -> new LimitedReply());
        HttpResponse<byte[]> response;
        try {
            response = exchange.get(seconds, TimeUnit.SECONDS);
        } finally {
            exchange.cancel(true);
        }
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new Failure(CLAIM_REFUSED);
        }
        byte[] bytes = response.body();
        try {
            return JSON.fromJson(new String(bytes, StandardCharsets.UTF_8), JsonObject.class);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /** Whether {@code token} is a well-formed {@code GW1-} token. */
    public static boolean validTokenFormat(String token) {
        byte[] fingerprint = RelayLink.tokenFingerprint(token.strip());
        if (fingerprint == null) return false;
        Arrays.fill(fingerprint, (byte) 0);
        return true;
    }

    private static final class LimitedReply implements HttpResponse.BodySubscriber<byte[]> {
        private final HttpResponse.BodySubscriber<byte[]> body = HttpResponse.BodySubscribers.ofByteArray();
        private Flow.Subscription subscription;
        private int remaining = MAX_BYTES;

        @Override
        public CompletionStage<byte[]> getBody() { return body.getBody(); }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            this.subscription = subscription;
            body.onSubscribe(subscription);
        }

        @Override
        public void onNext(List<ByteBuffer> buffers) {
            for (ByteBuffer buffer : buffers) {
                if (buffer.remaining() > remaining) {
                    subscription.cancel();
                    body.onError(new IOException("Registration response is too large."));
                    return;
                }
                remaining -= buffer.remaining();
            }
            body.onNext(buffers);
        }

        @Override
        public void onError(Throwable failure) { body.onError(failure); }

        @Override
        public void onComplete() { body.onComplete(); }
    }
}
