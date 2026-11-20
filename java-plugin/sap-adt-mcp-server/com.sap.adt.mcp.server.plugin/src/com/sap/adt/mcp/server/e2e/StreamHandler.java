package com.sap.adt.mcp.server.e2e;

import com.google.gson.JsonObject;

/** Serves the inner JSON-RPC messages of the end-to-end tunnel. Implemented by the request/pairing lane. */
public interface StreamHandler {
    /**
     * A decrypted inner JSON-RPC message whose envelope matched.
     *
     * @return the JSON-RPC response text, or null for a notification
     */
    String handle(StreamContext context, JsonObject message, RelayPolicyView policy);

    /** The stream ended for any reason; free per-stream state. May be called from any thread. */
    default void closed(int streamId) {
    }
}
