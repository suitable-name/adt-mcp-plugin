package com.sap.adt.mcp.server;

import java.io.IOException;
import java.security.GeneralSecurityException;

import com.sap.adt.mcp.server.e2e.InnerKeys;
import com.sap.adt.mcp.server.e2e.PairingGate;
import com.sap.adt.mcp.server.e2e.PinStore;
import com.sap.adt.mcp.server.e2e.StreamHandler;

/**
 * Process-wide wiring of the end-to-end tunnel. The request/pairing code registers its {@link StreamHandler}
 * and {@link PairingGate} at startup; {@link RelayBridge} reads them when it is created. A bridge created while
 * no handler is registered does not serve the tunnel.
 */
public final class E2eServices {
    private static volatile StreamHandler handler;
    private static volatile PairingGate pairingGate;
    private static PinStore pinStore;
    private static InnerKeys innerKeys;

    private E2eServices() {
    }

    public static void setHandler(StreamHandler streamHandler) {
        handler = streamHandler;
    }

    public static void setPairingGate(PairingGate gate) {
        pairingGate = gate;
    }

    /** The registered handler, or null. */
    public static StreamHandler handler() {
        return handler;
    }

    /** The registered gate; with none registered pairing is never open. */
    public static PairingGate pairingGate() {
        PairingGate gate = pairingGate;
        return gate != null ? gate : () -> false;
    }

    /** The paired desktops, kept in Eclipse secure storage. */
    public static synchronized PinStore pinStore() {
        if (pinStore == null) {
            pinStore = new PinStore(new SecureBlobStorage("innerPins"));
        }
        return pinStore;
    }

    /**
     * The plugin's inner identity, created on first use and kept in Eclipse secure storage.
     *
     * @throws IllegalStateException when the identity cannot be read or created; the message never has key material
     */
    public static synchronized InnerKeys innerKeys() {
        if (innerKeys == null) {
            try {
                innerKeys = InnerKeys.loadOrCreate(new SecureBlobStorage("innerKey"));
            } catch (GeneralSecurityException | IOException e) {
                throw new IllegalStateException("The inner identity key is unavailable.", e);
            }
        }
        return innerKeys;
    }

    /** For tests and alternative storage: replaces the pin store. */
    public static synchronized void setPinStore(PinStore store) {
        pinStore = store;
    }

    /** For tests and alternative storage: replaces the inner identity. */
    public static synchronized void setInnerKeys(InnerKeys keys) {
        innerKeys = keys;
    }
}
