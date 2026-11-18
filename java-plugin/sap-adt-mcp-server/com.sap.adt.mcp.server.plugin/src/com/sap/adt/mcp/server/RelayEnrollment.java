package com.sap.adt.mcp.server;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.Strictness;

public final class RelayEnrollment {
    private static final int MAX_BYTES = 64 * 1024;
    private static final String CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    private static final Gson JSON = new GsonBuilder().setStrictness(Strictness.STRICT).create();
    private final URI registration;
    private final URI bridge;
    private final String label;
    private final String id;

    public RelayEnrollment(String label, String registrationUrl, String bridgeUrl) {
        this.registration = RelayIdentity.checkEndpoint(registrationUrl, "https", "");
        this.bridge = RelayIdentity.checkEndpoint(bridgeUrl, "wss", "/bridge");
        if (label.isBlank() || label.length() > 64 || !label.chars().allMatch(c -> c >= 32 && c <= 126)) {
            throw new IllegalArgumentException("Invalid registration label.");
        }
        this.label = label;
        byte[] random = new byte[16];
        new SecureRandom().nextBytes(random);
        this.id = HexFormat.of().formatHex(random);
    }

    public String requestId() {
        return id;
    }

    /** All messages from this exception are generated locally and safe to display. */
    public static final class Failure extends Exception {
        private static final long serialVersionUID = 1L;

        private Failure(String message) {
            super(message);
        }
    }

    @FunctionalInterface
    public interface TokenPrompt {
        String read() throws InterruptedException;
    }

    public RelayIdentity enroll(TokenPrompt prompt) throws InterruptedException, Failure {
        String stage = "Registration failed or timed out. Check the registration URL and operator approval.";
        try {
            JsonObject request = new JsonObject();
            request.addProperty("id", id);
            request.addProperty("label", label);
            request.addProperty("role", "eclipse");
            Reply approval = post(RelayIdentity.registrationClient(), "/request", request, 190);
            if (!id.equals(RelayIdentity.string(approval.json(), "id"))) {
                throw new Failure("The approval does not match this registration request.");
            }
            String caPem = RelayIdentity.string(approval.json(), "ca_pem");
            X509Certificate ca = RelayIdentity.authority(caPem);
            byte[] fingerprint = RelayIdentity.fingerprint(ca);
            if (!MessageDigest.isEqual(fingerprint, RelayIdentity.fingerprint(approval.peerCa()))) {
                throw new Failure("The approval CA differs from the CA presented by the registration endpoint.");
            }
            String token = prompt.read();
            if (token == null) throw new Failure("Registration canceled before claiming a certificate.");
            if (!MessageDigest.isEqual(fingerprint, tokenFingerprint(token))) {
                throw new Failure("The approval token identifies a different relay CA.");
            }
            JsonObject claim = new JsonObject();
            claim.addProperty("token", token);
            stage = "Could not claim the approved certificate. Start a new registration.";
            JsonObject bundle = post(RelayIdentity.httpClient(ca, null), "/claim", claim, 30).json();
            stage = "The relay returned an invalid credential bundle.";
            X509Certificate issuedCa = RelayIdentity.authority(RelayIdentity.string(bundle, "ca_pem"));
            if (!MessageDigest.isEqual(fingerprint, RelayIdentity.fingerprint(issuedCa))) {
                throw new Failure("The claimed certificate bundle uses a different relay CA.");
            }
            JsonObject profile = new JsonObject();
            profile.addProperty("ca_pem", caPem);
            profile.addProperty("bridge", bridge.toASCIIString());
            profile.addProperty("label", label);
            profile.addProperty("client_cert_pem", RelayIdentity.string(bundle, "client_cert_pem"));
            profile.addProperty("client_key_pem", RelayIdentity.string(bundle, "client_key_pem"));
            return RelayIdentity.fromProfile(profile);
        } catch (InterruptedException | Failure e) {
            throw e;
        } catch (Exception e) {
            throw new Failure(stage);
        }
    }

    private record Reply(JsonObject json, X509Certificate peerCa) {}

    private Reply post(HttpClient client, String path, JsonObject json, int seconds) throws Exception {
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
            throw new Failure("The relay refused " + path + " (HTTP " + response.statusCode() + ").");
        }
        byte[] bytes = response.body();
        try {
            JsonObject parsed = JSON.fromJson(new String(bytes, StandardCharsets.UTF_8), JsonObject.class);
            Certificate[] chain = response.sslSession().orElseThrow().getPeerCertificates();
            return new Reply(parsed, (X509Certificate) chain[chain.length - 1]);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /** The GW1 payload holds a 32-byte secret followed by the SHA-256 digest of the CA DER. */
    private static byte[] tokenFingerprint(String token) throws Failure {
        if (token.length() > 1024 || !token.regionMatches(true, 0, "GW1", 0, 3)) {
            throw new Failure("Enter a valid approval token.");
        }
        byte[] fingerprint = new byte[32];
        int accumulator = 0;
        int bits = 0;
        int length = 0;
        for (int i = 3; i < token.length(); i++) {
            char symbol = token.charAt(i);
            if (symbol == '-' || symbol == ' ' || symbol == '\t' || symbol == '\n' || symbol == '\r' || symbol == '\f') {
                continue;
            }
            int value = switch (symbol) {
                case 'O', 'o' -> 0;
                case 'I', 'i', 'L', 'l' -> 1;
                default -> symbol > 127 ? -1 : CROCKFORD.indexOf(Character.toUpperCase(symbol));
            };
            if (value < 0) {
                throw new Failure("Enter a valid approval token.");
            }
            accumulator = (accumulator << 5) | value;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                if (length >= 64) {
                    throw new Failure("Enter a valid approval token.");
                }
                if (length >= 32) {
                    fingerprint[length - 32] = (byte) (accumulator >> bits);
                }
                length++;
            }
        }
        if (length != 64 || bits != 3 || (accumulator & 7) != 0) {
            throw new Failure("Enter a valid approval token.");
        }
        return fingerprint;
    }

    public static boolean validTokenFormat(String token) {
        try {
            tokenFingerprint(token.strip());
            return true;
        } catch (Failure e) {
            return false;
        }
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
