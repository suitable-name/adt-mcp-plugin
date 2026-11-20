package com.sap.adt.mcp.server.e2e;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import java.util.function.Supplier;

import com.sap.adt.mcp.server.RelayLink;

/**
 * The plugin side of pairing (plan section 1). {@link #mint()} creates a one-time link, {@link #claim} checks the
 * secret a desktop sends inside the pinned inner session, asks the user, and pins the desktop's key.
 *
 * <p>The secret is single use and burns as soon as it is presented correctly (a refused or unanswered dialog does
 * not leave it usable). After {@value #MAX_WRONG_ATTEMPTS} wrong secrets the link burns too. Every failure is
 * generic to the caller; the real reason goes to the local log only. No secret is ever logged.</p>
 */
public final class Pairing implements PairingGate {
    /** Lifetime of a link (D10). */
    public static final Duration LIFETIME = Duration.ofMinutes(5);
    /** How long the dialog may stay unanswered (D12). */
    public static final Duration CONFIRM_TIMEOUT = Duration.ofMinutes(2);
    /** The one JSON-RPC error code for every failed claim. */
    public static final int REFUSED_CODE = -32_004;
    public static final String REFUSED_MESSAGE = "Pairing refused.";
    static final int MAX_WRONG_ATTEMPTS = 5;
    private static final int SECRET_BYTES = 32;
    private static final int MAX_LABEL_CODE_POINTS = 64;

    /** Where a confirmed pairing is stored; production passes {@code PinStore::add}. */
    @FunctionalInterface
    public interface Pins {
        void add(String keyFingerprint, String relayFingerprint, String label);
    }

    private final String endpointId;
    private final String eclipseLabel;
    private final Supplier<byte[]> innerKeyFingerprint;
    private final Pins pins;
    private final PairingConfirmer confirmer;
    private final Clock clock;
    private final Duration confirmTimeout;
    private final Consumer<String> log;
    private final SecureRandom random = new SecureRandom();

    private byte[] secret;
    private Instant expiresAt;
    private int wrongAttempts;

    /**
     * @param endpointId this Eclipse's relay fingerprint (64 lowercase hex)
     * @param eclipseLabel this Eclipse's label, shown in the link
     * @param innerKeyFingerprint the 32 raw bytes of {@code InnerKeys.fingerprintBytes()}
     */
    public Pairing(String endpointId, String eclipseLabel, Supplier<byte[]> innerKeyFingerprint, Pins pins,
            PairingConfirmer confirmer, Consumer<String> log) {
        this(endpointId, eclipseLabel, innerKeyFingerprint, pins, confirmer, Clock.systemUTC(), CONFIRM_TIMEOUT, log);
    }

    /** With an injectable clock and dialog timeout, for tests. */
    public Pairing(String endpointId, String eclipseLabel, Supplier<byte[]> innerKeyFingerprint, Pins pins,
            PairingConfirmer confirmer, Clock clock, Duration confirmTimeout, Consumer<String> log) {
        this.endpointId = endpointId;
        this.eclipseLabel = eclipseLabel;
        this.innerKeyFingerprint = innerKeyFingerprint;
        this.pins = pins;
        this.confirmer = confirmer;
        this.clock = clock;
        this.confirmTimeout = confirmTimeout;
        this.log = log;
    }

    /**
     * Creates a new link and cancels the previous one. The text contains the secret: show it to the user, keep it
     * out of logs.
     *
     * @throws IllegalStateException if the link cannot be built
     */
    public synchronized String mint() {
        byte[] fingerprint = innerKeyFingerprint.get();
        if (fingerprint == null || fingerprint.length != 32) {
            throw new IllegalStateException("The inner key is not available.");
        }
        burn();
        byte[] fresh = new byte[SECRET_BYTES];
        random.nextBytes(fresh);
        byte[] payload = new byte[64];
        System.arraycopy(fresh, 0, payload, 0, SECRET_BYTES);
        System.arraycopy(fingerprint, 0, payload, SECRET_BYTES, 32);
        char[] token = RelayLink.encodeToken(payload);
        Arrays.fill(payload, (byte) 0);
        RelayLink link = null;
        try {
            link = RelayLink.pair(endpointId, linkName(eclipseLabel), token);
            String text = link.build();
            secret = fresh;
            expiresAt = clock.instant().plus(LIFETIME);
            wrongAttempts = 0;
            return text;
        } catch (RelayLink.LinkException e) {
            Arrays.fill(fresh, (byte) 0);
            throw new IllegalStateException("The pairing link could not be built.");
        } finally {
            Arrays.fill(token, '\0');
            if (link != null) link.wipe();
        }
    }

    /** Cancels the outstanding link, if any. */
    public synchronized void cancel() {
        burn();
    }

    /** When the outstanding link expires, or null if none is outstanding. */
    public synchronized Instant expiresAt() {
        return pairingOpenLocked() ? expiresAt : null;
    }

    @Override
    public synchronized boolean pairingOpen() {
        return pairingOpenLocked();
    }

    private boolean pairingOpenLocked() {
        return secret != null && clock.instant().isBefore(expiresAt);
    }

    private void burn() {
        if (secret != null) Arrays.fill(secret, (byte) 0);
        secret = null;
        expiresAt = null;
        wrongAttempts = 0;
    }

    /**
     * Handles {@code pair/claim}. Blocks the calling thread until the user answers or
     * {@link #CONFIRM_TIMEOUT} passes.
     *
     * @param secretHex the secret as 64 hex characters, as the desktop sent it
     * @return true if the desktop is now pinned; false for every failure (the reason is logged, never returned)
     */
    public boolean claim(StreamContext context, String secretHex) {
        String peer = normalizedHex(context.peerKeyFingerprint());
        if (peer == null) return refuse("the desktop key fingerprint is malformed");
        byte[] presented = hex(secretHex);
        String failure = null;
        synchronized (this) {
            if (secret == null) {
                failure = "no pairing link is outstanding";
            } else if (!clock.instant().isBefore(expiresAt)) {
                burn();
                failure = "the pairing link expired";
            } else {
                // Compare in constant time even when the presented value is malformed.
                boolean equal = MessageDigest.isEqual(presented == null ? new byte[SECRET_BYTES] : presented, secret);
                if (presented == null || !equal) {
                    if (++wrongAttempts >= MAX_WRONG_ATTEMPTS) burn();
                    failure = "the secret was wrong";
                } else {
                    burn(); // single use, whatever the user answers
                }
            }
        }
        if (presented != null) Arrays.fill(presented, (byte) 0);
        if (failure != null) return refuse(failure);

        String label = cleanLabel(context.assertedLabel());
        String shortFingerprint = shortFingerprint(peer);
        CompletableFuture<Boolean> answer;
        try {
            answer = confirmer.confirm(label, shortFingerprint);
        } catch (RuntimeException e) {
            return refuse("the confirmation could not be shown");
        }
        boolean confirmed;
        try {
            confirmed = Boolean.TRUE.equals(answer.get(confirmTimeout.toMillis(), TimeUnit.MILLISECONDS));
        } catch (TimeoutException e) {
            answer.cancel(true);
            return refuse("the user did not answer in time");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            answer.cancel(true);
            return refuse("the pairing was interrupted");
        } catch (ExecutionException | CancellationException e) {
            return refuse("the confirmation failed");
        }
        if (!confirmed) return refuse("the user refused");
        try {
            String relay = normalizedHex(context.assertedDesktopFingerprint());
            pins.add(peer, relay == null ? "" : relay, label);
        } catch (RuntimeException e) {
            return refuse("the key could not be stored");
        }
        log.accept("Paired desktop \"" + label + "\" (key " + shortFingerprint + ").");
        return true;
    }

    private boolean refuse(String reason) {
        log.accept("Pairing refused: " + reason + ".");
        return false;
    }

    /** The first 16 hex characters in groups of four, for example {@code 3fa9 01bc 77d2 e45a}. */
    public static String shortFingerprint(String hexFingerprint) {
        String lower = hexFingerprint.toLowerCase(Locale.ROOT);
        String head = lower.length() > 16 ? lower.substring(0, 16) : lower;
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < head.length(); i += 4) {
            if (i > 0) out.append(' ');
            out.append(head, i, Math.min(i + 4, head.length()));
        }
        return out.toString();
    }

    /** A label safe to show and store: no control characters, at most 64 code points, never empty. */
    static String cleanLabel(String label) {
        StringBuilder out = new StringBuilder();
        if (label != null) {
            int count = 0;
            for (int i = 0; i < label.length() && count < MAX_LABEL_CODE_POINTS;) {
                int cp = label.codePointAt(i);
                i += Character.charCount(cp);
                int type = Character.getType(cp);
                if (type == Character.CONTROL || type == Character.FORMAT || type == Character.LINE_SEPARATOR
                        || type == Character.PARAGRAPH_SEPARATOR) {
                    continue;
                }
                out.appendCodePoint(cp);
                count++;
            }
        }
        String text = out.toString().strip();
        return text.isEmpty() ? "unnamed desktop" : text;
    }

    /** The link's name field allows 64 UTF-8 bytes. */
    private static String linkName(String label) {
        String name = cleanLabel(label);
        while (name.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > RelayLink.MAX_NAME_BYTES) {
            name = name.substring(0, name.offsetByCodePoints(name.length(), -1));
        }
        return name;
    }

    /** Lowercase hex of exactly 64 characters, or null. */
    private static String normalizedHex(String value) {
        if (value == null || value.length() != 64) return null;
        String lower = value.toLowerCase(Locale.ROOT);
        return lower.chars().allMatch(c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) ? lower : null;
    }

    /** 64 hex characters to 32 bytes, or null. */
    private static byte[] hex(String value) {
        String lower = normalizedHex(value);
        if (lower == null) return null;
        byte[] out = new byte[SECRET_BYTES];
        for (int i = 0; i < SECRET_BYTES; i++) {
            out[i] = (byte) ((Character.digit(lower.charAt(2 * i), 16) << 4) | Character.digit(lower.charAt(2 * i + 1), 16));
        }
        return out;
    }
}
