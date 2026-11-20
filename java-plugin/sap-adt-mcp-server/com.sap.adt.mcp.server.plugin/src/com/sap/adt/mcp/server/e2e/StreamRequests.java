package com.sap.adt.mcp.server.e2e;

import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.sap.adt.mcp.server.LocalPolicy;
import com.sap.adt.mcp.server.PolicyDenials;
import com.sap.adt.mcp.server.ToolExecutor;

/**
 * One MCP session per encrypted stream. Answers {@code initialize}, {@code ping}, {@code tools/list},
 * {@code tools/call} (through the {@link ToolExecutor} that the legacy bridge path shares) and {@code pair/claim}.
 *
 * <p>The relay layer of every call is the {@link RelayPolicyView} the transport hands in. The local layer is the
 * global permissions combined with the desktop's own, looked up by the key fingerprint the inner handshake proved.
 * Notifications get no response. An unpinned peer can only {@code pair/claim}.</p>
 */
public final class StreamRequests implements StreamHandler {
    /** The caller must pair first. */
    public static final int NOT_PAIRED = -32_004;
    private static final String LATEST = "2025-11-25";
    private static final int MAX_SESSIONS = 1024;

    private final ToolExecutor executor;
    private final Pairing pairing;
    private final Function<String, LocalPolicy> localPolicy;
    private final String serverVersion;
    private final Map<Integer, Session> sessions = Collections.synchronizedMap(new LinkedHashMap<Integer, Session>() {
        private static final long serialVersionUID = 1L;

        @Override
        protected boolean removeEldestEntry(Map.Entry<Integer, Session> eldest) {
            return size() > MAX_SESSIONS;
        }
    });

    private static final class Session {
        final String peer;
        volatile boolean initialized;

        Session(String peer) {
            this.peer = peer;
        }
    }

    /**
     * @param localPolicy the effective local policy for a desktop key fingerprint: the global permissions combined
     *        with that desktop's own (see {@code PermissionsModel#effectiveFor})
     * @param serverVersion the plugin version reported in {@code serverInfo}
     */
    public StreamRequests(ToolExecutor executor, Pairing pairing, Function<String, LocalPolicy> localPolicy,
            String serverVersion) {
        this.executor = executor;
        this.pairing = pairing;
        this.localPolicy = localPolicy;
        this.serverVersion = serverVersion;
    }

    /** The transport calls this when a stream closes, so its session state goes away. */
    public void closed(int streamId) {
        sessions.remove(streamId);
    }

    @Override
    public String handle(StreamContext context, JsonObject message, RelayPolicyView policy) {
        JsonElement id = message.get("id");
        String method = ToolExecutor.string(message.get("method"));
        if (!"2.0".equals(ToolExecutor.string(message.get("jsonrpc"))) || method == null || !validId(id)) {
            return id == null ? null : text(JsonNull.INSTANCE, ToolExecutor.error(JsonNull.INSTANCE, -32600,
                    "Invalid JSON-RPC request."));
        }
        JsonElement params = message.get("params");
        if (params != null && !params.isJsonObject()) {
            return id == null ? null : text(id, ToolExecutor.error(id, -32602, "Expected a parameters object."));
        }
        JsonObject arguments = params == null ? new JsonObject() : params.getAsJsonObject();
        if (id == null) {
            // A notification never gets a response. Its only effect here is none: initialization is complete once
            // the initialize request was answered.
            return null;
        }
        return text(id, dispatch(context, id, method, arguments, policy));
    }

    private JsonObject dispatch(StreamContext context, JsonElement id, String method, JsonObject params,
            RelayPolicyView policy) {
        if ("pair/claim".equals(method)) {
            return claim(context, id, params);
        }
        if (!context.peerPinned()) {
            PolicyDenials.report("Refused " + method + " on stream " + context.streamId() + ": the desktop is not paired.");
            return ToolExecutor.error(id, NOT_PAIRED, "This desktop is not paired.");
        }
        Session session = session(context);
        return switch (method) {
            case "initialize" -> initialize(session, id, params);
            case "ping" -> ToolExecutor.success(id, new JsonObject());
            case "tools/list", "tools/call" -> {
                if (!session.initialized) {
                    yield ToolExecutor.error(id, -32600, "Send initialize first.");
                }
                yield tools(context, id, method, params, policy);
            }
            default -> ToolExecutor.error(id, -32601, "Unknown method.");
        };
    }

    private JsonObject claim(StreamContext context, JsonElement id, JsonObject params) {
        String secret = ToolExecutor.string(params.get("secret"));
        if (secret != null && pairing.claim(context, secret)) {
            JsonObject result = new JsonObject();
            result.addProperty("paired", true);
            return ToolExecutor.success(id, result);
        }
        if (secret == null) {
            PolicyDenials.report("Pairing refused: the claim carried no secret.");
        }
        return ToolExecutor.error(id, Pairing.REFUSED_CODE, Pairing.REFUSED_MESSAGE);
    }

    private JsonObject initialize(Session session, JsonElement id, JsonObject params) {
        String requested = ToolExecutor.string(params.get("protocolVersion"));
        if (requested == null) {
            return ToolExecutor.error(id, -32602, "Missing protocol version.");
        }
        String version = switch (requested) {
            case "2024-11-05", "2025-03-26", "2025-06-18" -> requested;
            default -> LATEST;
        };
        session.initialized = true;
        JsonObject listChanged = new JsonObject();
        listChanged.addProperty("listChanged", false);
        JsonObject capabilities = new JsonObject();
        capabilities.add("tools", listChanged);
        JsonObject info = new JsonObject();
        info.addProperty("name", "sap-adt-eclipse");
        info.addProperty("version", serverVersion);
        JsonObject result = new JsonObject();
        result.addProperty("protocolVersion", version);
        result.add("capabilities", capabilities);
        result.add("serverInfo", info);
        return ToolExecutor.success(id, result);
    }

    private JsonObject tools(StreamContext context, JsonElement id, String method, JsonObject params,
            RelayPolicyView policy) {
        if (policy == null || policy.allowedTools() == null) {
            return ToolExecutor.error(id, -32602, "Missing or invalid relay tool list.");
        }
        Set<String> relayAllowed = new HashSet<>(policy.allowedTools());
        LocalPolicy local;
        try {
            local = localPolicy.apply(context.peerKeyFingerprint());
        } catch (RuntimeException e) {
            local = LocalPolicy.blocked(false);
        }
        if ("tools/list".equals(method)) {
            return executor.list(id, relayAllowed, local);
        }
        return executor.call(id, params, relayAllowed, policy.packageScopes(), local);
    }

    private Session session(StreamContext context) {
        synchronized (sessions) {
            Session existing = sessions.get(context.streamId());
            if (existing != null && existing.peer.equals(context.peerKeyFingerprint())) return existing;
            Session fresh = new Session(context.peerKeyFingerprint());
            sessions.put(context.streamId(), fresh);
            return fresh;
        }
    }

    /** A JSON-RPC id is absent (a notification), a string or an integer. */
    private static boolean validId(JsonElement id) {
        if (id == null) return true;
        if (!id.isJsonPrimitive()) return false;
        if (id.getAsJsonPrimitive().isString()) return true;
        return id.getAsJsonPrimitive().isNumber() && id.getAsString().matches("-?[0-9]{1,19}");
    }

    private static String text(JsonElement id, JsonObject response) {
        return ToolExecutor.limited(id, response);
    }
}
