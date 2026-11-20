package com.sap.adt.mcp.server.e2e;

import java.io.IOException;

/** Where the pins are persisted (one opaque blob; the format belongs to {@link PinStore}). */
public interface PinStorage {
    /** The stored blob, or null when nothing has been stored yet. */
    byte[] read() throws IOException;

    /** Replaces the stored blob. */
    void write(byte[] blob) throws IOException;
}
