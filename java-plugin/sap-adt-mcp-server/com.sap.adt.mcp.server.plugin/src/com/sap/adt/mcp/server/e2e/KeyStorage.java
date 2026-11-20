package com.sap.adt.mcp.server.e2e;

import java.io.IOException;

/** Where the inner identity (private key and certificate, as one opaque blob) is kept. */
public interface KeyStorage {
    /** The stored blob, or null when nothing has been stored yet. */
    byte[] read() throws IOException;

    /** Replaces the stored blob. */
    void write(byte[] blob) throws IOException;
}
