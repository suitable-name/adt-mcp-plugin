package com.sap.adt.mcp.server.e2e;

/** Whether a pairing link is outstanding, so that an unknown client key may be accepted for {@code pair/claim}. */
public interface PairingGate {
    boolean pairingOpen();
}
