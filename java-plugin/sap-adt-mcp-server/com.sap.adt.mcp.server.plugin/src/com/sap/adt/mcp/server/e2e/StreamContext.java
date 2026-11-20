package com.sap.adt.mcp.server.e2e;

/** What the plugin knows about one tunnel stream. */
public interface StreamContext {
    int streamId();

    /** Lowercase hex SHA-256 of the client's SubjectPublicKeyInfo, proven by the inner handshake. */
    String peerKeyFingerprint();

    boolean peerPinned();

    /** From the relay's open frame, an assertion only. May be null. */
    String assertedDesktopFingerprint();

    /** From the relay's open frame, an assertion only. May be null. */
    String assertedLabel();
}
