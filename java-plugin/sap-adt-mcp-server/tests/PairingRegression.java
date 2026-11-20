package com.sap.adt.mcp.server;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import com.sap.adt.mcp.server.e2e.Pairing;
import com.sap.adt.mcp.server.e2e.PairingConfirmer;
import com.sap.adt.mcp.server.e2e.StreamContext;

/**
 * Source-level regression harness for the plugin side of pairing: mint and claim (single use, lifetime, one
 * outstanding link), the generic refusal, the confirmation dialog (refused, unanswered), and the link's token.
 */
public final class PairingRegression {
    private static final String ENDPOINT = "d".repeat(64);
    private static final String DESKTOP_KEY = "ab".repeat(32);
    private static final String DESKTOP_RELAY = "cd".repeat(32);

    private record Ctx(int streamId, String peerKeyFingerprint, boolean peerPinned, String assertedDesktopFingerprint,
            String assertedLabel) implements StreamContext {
    }

    private static final class TestClock extends Clock {
        Instant now = Instant.parse("2026-11-20T10:00:00Z");

        @Override public ZoneId getZone() { return ZoneOffset.UTC; }

        @Override public Clock withZone(ZoneId zone) { return this; }

        @Override public Instant instant() { return now; }
    }

    private static final class Fixture {
        final TestClock clock = new TestClock();
        final List<String> pins = new ArrayList<>();
        final List<String> log = new ArrayList<>();
        final List<String> asked = new ArrayList<>();
        final byte[] innerKey = new byte[32];
        PairingConfirmer confirmer = (label, shortFingerprint) -> {
            asked.add(label + "|" + shortFingerprint);
            return CompletableFuture.completedFuture(true);
        };
        Pairing pairing;

        Fixture() {
            this(Duration.ofSeconds(5));
        }

        Fixture(Duration timeout) {
            for (int i = 0; i < innerKey.length; i++) innerKey[i] = (byte) (0x40 + i);
            pairing = new Pairing(ENDPOINT, "Eclipse Laptop", () -> innerKey,
                    (key, relay, label) -> pins.add(key + "|" + relay + "|" + label),
                    (label, shortFingerprint) -> confirmer.confirm(label, shortFingerprint), clock, timeout, log::add);
        }

        /** Mints a link and returns the secret as 64 hex characters (decoded from the link's token). */
        String mintSecret() {
            return secretOf(pairing.mint());
        }
    }

    public static void main(String[] args) throws Exception {
        mintAndClaimOnce();
        linkHasTheEndpointAndTheKeyFingerprint();
        expiry();
        oneOutstandingLink();
        wrongSecretIsRefusedGenerically();
        refusedOrUnansweredDialogRefuses();
        malformedInputIsRefused();
        labelsAreCleaned();
        shortFingerprintGroupsOfFour();
    }

    private static void mintAndClaimOnce() {
        Fixture f = new Fixture();
        check(!f.pairing.pairingOpen() && f.pairing.expiresAt() == null);
        String secret = f.mintSecret();
        check(f.pairing.pairingOpen());
        check(f.pairing.expiresAt().equals(f.clock.now.plus(Duration.ofMinutes(5))));
        Ctx desktop = new Ctx(1, DESKTOP_KEY, false, DESKTOP_RELAY, "Anna Laptop");
        check(f.pairing.claim(desktop, secret));
        check(f.pins.equals(List.of(DESKTOP_KEY + "|" + DESKTOP_RELAY + "|Anna Laptop")));
        // The user saw the relay's label and the short form of the desktop key.
        check(f.asked.equals(List.of("Anna Laptop|" + Pairing.shortFingerprint(DESKTOP_KEY))));
        check(Pairing.shortFingerprint(DESKTOP_KEY).equals("abab abab abab abab"));
        // Single use: the same secret never works again, and no link is outstanding.
        check(!f.pairing.pairingOpen());
        check(!f.pairing.claim(desktop, secret));
        check(f.pins.size() == 1);
        // A new link can be minted and used afterwards.
        check(f.pairing.claim(new Ctx(2, "12".repeat(32), false, DESKTOP_RELAY, "Second"), f.mintSecret()));
        check(f.pins.size() == 2);
        noSecretInLog(f, secret);
    }

    private static void linkHasTheEndpointAndTheKeyFingerprint() throws Exception {
        Fixture f = new Fixture();
        String text = f.pairing.mint();
        check(text.startsWith("sap-adt://pair?"));
        RelayLink link = RelayLink.parse(text);
        check(link.kind() == RelayLink.Kind.PAIR);
        check(link.endpoint().equals(ENDPOINT) && link.name().equals("Eclipse Laptop"));
        byte[] payload = RelayLink.decodeToken(new String(link.token()));
        check(payload != null);
        // The token's second half is the fingerprint of this plugin's inner key.
        check(Arrays.equals(Arrays.copyOfRange(payload, 32, 64), f.innerKey));
        check(Arrays.equals(RelayLink.tokenFingerprint(new String(link.token())), f.innerKey));
        // The first half is a fresh random secret, different for every link.
        byte[] first = Arrays.copyOfRange(payload, 0, 32);
        check(!Arrays.equals(first, new byte[32]));
        byte[] second = RelayLink.decodeToken(new String(RelayLink.parse(f.pairing.mint()).token()));
        check(!Arrays.equals(first, Arrays.copyOfRange(second, 0, 32)));
        // A long label is cut to the link's 64 bytes instead of failing.
        Pairing longLabel = new Pairing(ENDPOINT, "x".repeat(200), () -> f.innerKey, (k, r, l) -> { },
                (l, s) -> CompletableFuture.completedFuture(true), f.clock, Duration.ofSeconds(1), f.log::add);
        check(RelayLink.parse(longLabel.mint()).name().length() == 64);
    }

    private static void expiry() {
        Fixture f = new Fixture();
        String secret = f.mintSecret();
        f.clock.now = f.clock.now.plus(Duration.ofMinutes(4)).plusSeconds(59);
        check(f.pairing.pairingOpen());
        f.clock.now = f.clock.now.plusSeconds(1);
        check(!f.pairing.pairingOpen() && f.pairing.expiresAt() == null);
        check(!f.pairing.claim(new Ctx(1, DESKTOP_KEY, false, DESKTOP_RELAY, "Late"), secret));
        check(f.pins.isEmpty() && f.asked.isEmpty());
        // Even the right secret fails the minute it expires, and a fresh link works.
        String fresh = f.mintSecret();
        check(f.pairing.claim(new Ctx(2, DESKTOP_KEY, false, DESKTOP_RELAY, "Prompt"), fresh));
    }

    private static void oneOutstandingLink() {
        Fixture f = new Fixture();
        String first = f.mintSecret();
        String second = f.mintSecret();
        Ctx desktop = new Ctx(1, DESKTOP_KEY, false, DESKTOP_RELAY, "Anna");
        check(!first.equals(second));
        // The new link cancelled the old one.
        check(!f.pairing.claim(desktop, first));
        check(f.pairing.claim(desktop, second));
        // Cancel closes the gate.
        f.mintSecret();
        check(f.pairing.pairingOpen());
        f.pairing.cancel();
        check(!f.pairing.pairingOpen());
    }

    private static void wrongSecretIsRefusedGenerically() {
        Fixture f = new Fixture();
        String secret = f.mintSecret();
        Ctx desktop = new Ctx(1, DESKTOP_KEY, false, DESKTOP_RELAY, "Anna");
        String wrong = flip(secret);
        check(!f.pairing.claim(desktop, wrong));
        check(f.pins.isEmpty() && f.asked.isEmpty());
        // A wrong guess does not burn the link ...
        check(f.pairing.pairingOpen());
        // ... but after five wrong guesses it is gone, even for the right secret.
        for (int i = 0; i < 4; i++) check(!f.pairing.claim(desktop, wrong));
        check(!f.pairing.pairingOpen());
        check(!f.pairing.claim(desktop, secret));
        check(f.pins.isEmpty());
        // The log names the real reason locally and holds no secret.
        check(f.log.stream().anyMatch(line -> line.contains("secret was wrong")));
        noSecretInLog(f, secret);
        noSecretInLog(f, wrong);
        // The right secret still works for a link that had fewer wrong guesses.
        Fixture g = new Fixture();
        String good = g.mintSecret();
        check(!g.pairing.claim(desktop, flip(good)));
        check(g.pairing.claim(desktop, good));
    }

    private static void refusedOrUnansweredDialogRefuses() {
        Ctx desktop = new Ctx(1, DESKTOP_KEY, false, DESKTOP_RELAY, "Anna");
        // The user clicks Refuse: nothing is pinned, and the secret is burned (the link cannot be retried).
        Fixture refused = new Fixture();
        refused.confirmer = (label, shortFingerprint) -> CompletableFuture.completedFuture(false);
        String secret = refused.mintSecret();
        check(!refused.pairing.claim(desktop, secret));
        check(refused.pins.isEmpty() && !refused.pairing.pairingOpen());
        refused.confirmer = (label, shortFingerprint) -> CompletableFuture.completedFuture(true);
        check(!refused.pairing.claim(desktop, secret));
        check(refused.pins.isEmpty());

        // No answer in time: refused, and the future is cancelled so the dialog can close.
        Fixture silent = new Fixture(Duration.ofMillis(100));
        AtomicReference<CompletableFuture<Boolean>> pending = new AtomicReference<>();
        silent.confirmer = (label, shortFingerprint) -> {
            pending.set(new CompletableFuture<>());
            return pending.get();
        };
        String silentSecret = silent.mintSecret();
        check(!silent.pairing.claim(desktop, silentSecret));
        check(pending.get().isCancelled());
        check(silent.pins.isEmpty() && !silent.pairing.pairingOpen());
        check(silent.log.stream().anyMatch(line -> line.contains("did not answer")));

        // A confirmation that fails to show, or a future that fails, also refuses.
        Fixture broken = new Fixture();
        broken.confirmer = (label, shortFingerprint) -> { throw new IllegalStateException("no display"); };
        check(!broken.pairing.claim(desktop, broken.mintSecret()));
        broken.confirmer = (label, shortFingerprint) -> CompletableFuture.failedFuture(new IllegalStateException("x"));
        check(!broken.pairing.claim(desktop, broken.mintSecret()));
        check(broken.pins.isEmpty());

        // A pin store that fails refuses too.
        Fixture failing = new Fixture();
        Pairing store = new Pairing(ENDPOINT, "E", () -> failing.innerKey,
                (key, relay, label) -> { throw new IllegalStateException("disk"); },
                (label, shortFingerprint) -> CompletableFuture.completedFuture(true), failing.clock,
                Duration.ofSeconds(1), failing.log::add);
        check(!store.claim(desktop, secretOf(store.mint())));
    }

    private static void malformedInputIsRefused() {
        Fixture f = new Fixture();
        String secret = f.mintSecret();
        Ctx desktop = new Ctx(1, DESKTOP_KEY, false, DESKTOP_RELAY, "Anna");
        for (String bad : new String[] {"", "zz".repeat(32), secret.substring(2), secret + "00", null}) {
            check(!f.pairing.claim(desktop, bad));
        }
        // A malformed desktop key fingerprint is refused without burning the link.
        Fixture g = new Fixture();
        String good = g.mintSecret();
        check(!g.pairing.claim(new Ctx(1, "not hex", false, DESKTOP_RELAY, "Anna"), good));
        check(g.pairing.pairingOpen());
        check(g.pairing.claim(new Ctx(1, DESKTOP_KEY.toUpperCase(), false, DESKTOP_RELAY, "Anna"), good.toUpperCase()));
        // Fingerprints are stored in lowercase.
        check(g.pins.get(0).startsWith(DESKTOP_KEY + "|"));
    }

    private static void labelsAreCleaned() {
        Fixture f = new Fixture();
        String secret = f.mintSecret();
        String evil = "Anna\u0007\n Laptop‮" + "y".repeat(100);
        check(f.pairing.claim(new Ctx(1, DESKTOP_KEY, false, DESKTOP_RELAY, evil), secret));
        String stored = f.pins.get(0).split("\\|")[2];
        check(stored.startsWith("Anna Laptop") && stored.length() <= 64);
        check(stored.chars().noneMatch(c -> Character.isISOControl(c) || c == 0x202e));
        Fixture g = new Fixture();
        check(g.pairing.claim(new Ctx(1, DESKTOP_KEY, false, DESKTOP_RELAY, null), g.mintSecret()));
        check(g.pins.get(0).endsWith("|unnamed desktop"));
    }

    private static void shortFingerprintGroupsOfFour() {
        check(Pairing.shortFingerprint("0123456789ABCDEF0123456789ABCDEF").equals("0123 4567 89ab cdef"));
        check(Pairing.shortFingerprint("abc").equals("abc"));
    }

    /** The secret of a link as 64 hex characters. */
    private static String secretOf(String link) {
        try {
            byte[] payload = RelayLink.decodeToken(new String(RelayLink.parse(link).token()));
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < 32; i++) hex.append(String.format("%02x", payload[i] & 0xFF));
            return hex.toString();
        } catch (RelayLink.LinkException e) {
            throw new AssertionError("The minted link did not parse.", e);
        }
    }

    private static String flip(String hex) {
        char first = hex.charAt(0);
        return (first == '0' ? '1' : '0') + hex.substring(1);
    }

    private static void noSecretInLog(Fixture f, String secret) {
        for (String line : f.log) check(!line.contains(secret) && !line.contains("GW1-"));
    }

    private static void check(boolean condition) {
        if (!condition) throw new AssertionError("Pairing regression.");
    }
}
