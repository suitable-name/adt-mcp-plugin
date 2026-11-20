package com.sap.adt.mcp.server.e2e;

import java.util.concurrent.CompletableFuture;

/**
 * Asks the user whether to pair a desktop. The UI implements it with a non-blocking dialog.
 *
 * <p>The returned future completes with {@code true} for Pair and {@code false} for Refuse. {@link Pairing} cancels
 * it when the answer takes too long, so the dialog can close itself ({@code whenComplete} sees a
 * {@code CancellationException}).</p>
 */
@FunctionalInterface
public interface PairingConfirmer {
    /**
     * @param relaySuppliedLabel the desktop's label as the relay asserted it; it is not verified
     * @param shortFingerprint the first 16 hex characters of the desktop key's fingerprint, in groups of four
     */
    CompletableFuture<Boolean> confirm(String relaySuppliedLabel, String shortFingerprint);
}
