package com.sap.adt.mcp.server;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.Strictness;
import com.sap.adt.mcp.tools.McpTool;
import com.sap.adt.mcp.tools.ToolCatalog;
import com.sap.adt.mcp.sap.AdtRestClient;

/**
 * The legacy (unencrypted) bridge path: discovers and dispatches the tools attached to this Eclipse SAP session.
 *
 * <p>This class is the authority for what runs. A tool executes only if the relay listed it in
 * {@code relayAllowedTools} and this Eclipse's local permissions allow it, and a package-aware tool's
 * target must pass the relay's package scopes and the local patterns. The checks and the execution live in
 * {@link ToolExecutor}, which the encrypted stream path shares.</p>
 */
final class RelayRequests {
    /** The relay refused or did not list the tool. */
    static final int RELAY_DENIED = ToolExecutor.RELAY_DENIED;
    /** This Eclipse's local permissions refused the call. */
    static final int LOCAL_DENIED = ToolExecutor.LOCAL_DENIED;
    static final int POLICY_VERSION = 2;
    /** Advertised in {@code relay/hello}: this plugin can serve encrypted streams. */
    static final int E2E_VERSION = 1;
    /** The message of the {@link #LOCAL_DENIED} error for a refused legacy call. */
    static final String UNENCRYPTED_REFUSED =
            "This Eclipse accepts only end-to-end encrypted calls. Pair this desktop with Pair Desktop in the MCP view.";
    private static final int MAX_RELAY_TOOLS = 256;
    private static final Gson JSON = new GsonBuilder().setStrictness(Strictness.STRICT).create();
    private final ToolExecutor executor;
    private final Supplier<LocalPolicy> localPolicy;
    private final BooleanSupplier allowUnencrypted;
    /** Set once the relay's hello advertised policy version 2. After that every call must carry its tool list. */
    private volatile boolean relaySendsToolList;

    /** Production constructor: the bundled tool table and the Eclipse preferences, read again on every call. */
    RelayRequests(List<McpTool> registeredTools, AdtRestClient sapSession) {
        this(registeredTools, sapSession, ToolCatalog.bundled(), LocalPolicySource::current);
    }

    RelayRequests(List<McpTool> registeredTools, AdtRestClient sapSession, ToolCatalog catalog,
            Supplier<LocalPolicy> localPolicy) {
        this(registeredTools, sapSession, catalog, localPolicy, LegacyCalls::allowed);
    }

    /** @param allowUnencrypted read on every legacy list and call; false refuses them with {@link #LOCAL_DENIED} */
    RelayRequests(List<McpTool> registeredTools, AdtRestClient sapSession, ToolCatalog catalog,
            Supplier<LocalPolicy> localPolicy, BooleanSupplier allowUnencrypted) {
        this.executor = new ToolExecutor(registeredTools, sapSession, catalog);
        this.localPolicy = localPolicy;
        this.allowUnencrypted = allowUnencrypted;
    }

    String reply(String message) {
        JsonElement parsed;
        try {
            parsed = JSON.fromJson(message, JsonElement.class);
        } catch (JsonParseException e) {
            return error(JsonNull.INSTANCE, -32700, "Invalid JSON.").toString();
        }
        if (parsed == null || !parsed.isJsonObject()) {
            return error(JsonNull.INSTANCE, -32600, "Expected a request object.").toString();
        }
        JsonObject request = parsed.getAsJsonObject();
        JsonElement id = request.get("id");
        if (id == null || !id.isJsonPrimitive() || !id.getAsJsonPrimitive().isNumber()
                || !id.getAsString().matches("[1-9][0-9]{0,19}")) {
            return error(JsonNull.INSTANCE, -32600, "Expected a positive integer request ID.").toString();
        }
        String method = string(request.get("method"));
        if (!"2.0".equals(string(request.get("jsonrpc"))) || method == null) {
            return error(id, -32600, "Invalid JSON-RPC request.").toString();
        }
        JsonElement params = request.get("params");
        if (params != null && !params.isJsonObject()) {
            return error(id, -32602, "Expected a parameters object.").toString();
        }

        JsonObject response = switch (method) {
            case "relay/hello" -> {
                // A relay that does not advertise policy version 2 is an old relay: it sends no tool list.
                JsonObject offered = params == null ? new JsonObject() : params.getAsJsonObject();
                JsonElement version = offered.get("policyVersion");
                if (version != null && version.isJsonPrimitive() && version.getAsJsonPrimitive().isNumber()
                        && version.getAsString().equals(Integer.toString(POLICY_VERSION))) {
                    relaySendsToolList = true;
                }
                JsonObject hello = new JsonObject();
                hello.addProperty("policyVersion", POLICY_VERSION);
                hello.addProperty("e2e", E2E_VERSION);
                yield success(id, hello);
            }
            case "ping" -> success(id, new JsonObject());
            case "tools/list" -> list(id, method, params == null ? new JsonObject() : params.getAsJsonObject());
            case "tools/call" -> call(id, method, params == null ? new JsonObject() : params.getAsJsonObject());
            default -> error(id, -32601, "Unknown bridge method.");
        };
        return ToolExecutor.limited(id, response);
    }

    /**
     * The tool names the relay allows for this call, or null from an old relay that never sent policy version 2.
     *
     * @throws IllegalArgumentException if the list is missing from a version 2 relay or is malformed
     */
    private Set<String> relayAllowed(JsonObject params) {
        JsonElement value = params.get("relayAllowedTools");
        if (value == null) {
            if (relaySendsToolList) throw new IllegalArgumentException("Missing relay tool list.");
            return null;
        }
        if (!value.isJsonArray() || value.getAsJsonArray().size() > MAX_RELAY_TOOLS) {
            throw new IllegalArgumentException("Invalid relay tool list.");
        }
        Set<String> names = new HashSet<>();
        for (JsonElement entry : value.getAsJsonArray()) {
            String name = string(entry);
            if (name == null || name.length() > 64) throw new IllegalArgumentException("Invalid relay tool list.");
            names.add(name);
        }
        return names;
    }

    /** The refusal for a legacy call when this Eclipse accepts only encrypted calls; otherwise null. */
    private JsonObject refuseUnencrypted(JsonElement id, String method) {
        if (allowUnencrypted.getAsBoolean()) return null;
        LegacyCalls.refused(method);
        return error(id, LOCAL_DENIED, UNENCRYPTED_REFUSED);
    }

    private JsonObject list(JsonElement id, String method, JsonObject params) {
        JsonObject refused = refuseUnencrypted(id, method);
        if (refused != null) return refused;
        Set<String> relayAllowed;
        try {
            relayAllowed = relayAllowed(params);
        } catch (IllegalArgumentException e) {
            return error(id, -32602, "Missing or invalid relay tool list.");
        }
        return executor.list(id, relayAllowed, localPolicy.get());
    }

    private JsonObject call(JsonElement id, String method, JsonObject params) {
        JsonObject refused = refuseUnencrypted(id, method);
        if (refused != null) return refused;
        Set<String> relayAllowed;
        try {
            relayAllowed = relayAllowed(params);
        } catch (IllegalArgumentException e) {
            return error(id, -32602, "Missing or invalid relay tool list.");
        }
        // The legacy path applies the global local policy only.
        return executor.call(id, params, relayAllowed, params.get("relayPackageScopes"), localPolicy.get());
    }

    private static String string(JsonElement value) {
        return ToolExecutor.string(value);
    }

    private static JsonObject error(JsonElement id, int code, String message) {
        return ToolExecutor.error(id, code, message);
    }

    private static JsonObject success(JsonElement id, JsonObject result) {
        return ToolExecutor.success(id, result);
    }
}
