package com.sap.adt.mcp.server;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.sap.adt.mcp.sap.AdtRestClient;
import com.sap.adt.mcp.tools.McpTool;
import com.sap.adt.mcp.tools.SearchObjectTool;
import com.sap.adt.mcp.tools.ToolCatalog;

/**
 * Tool listing and tool calls, shared by the legacy bridge path ({@link RelayRequests}) and the encrypted stream
 * path ({@code StreamRequests}). Both apply the relay's allowed tools, the relay's package scopes, a local policy,
 * schema validation, {@code synchronized (sapSession)} and the response limit.
 *
 * <p>The caller supplies the relay layer and the local policy, so the legacy path passes the global local policy
 * and a stream passes global and per-desktop permissions combined.</p>
 */
public final class ToolExecutor {
    /** The relay refused or did not list the tool. */
    public static final int RELAY_DENIED = -32_001;
    /** This Eclipse's local permissions refused the call. */
    public static final int LOCAL_DENIED = -32_002;
    public static final int MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

    private final Map<String, McpTool> tools = new LinkedHashMap<>();
    private final AdtRestClient sapSession;
    private final ToolCatalog catalog;

    /** Production constructor: the bundled tool table. */
    public ToolExecutor(List<McpTool> registeredTools, AdtRestClient sapSession) {
        this(registeredTools, sapSession, ToolCatalog.bundled());
    }

    public ToolExecutor(List<McpTool> registeredTools, AdtRestClient sapSession, ToolCatalog catalog) {
        this.sapSession = sapSession;
        this.catalog = catalog;
        for (McpTool tool : registeredTools) {
            if (tools.putIfAbsent(tool.getName(), tool) != null) {
                throw new IllegalArgumentException("Duplicate SAP tool.");
            }
        }
        // Every registered tool must be listed in the shared table with the class its code declares.
        catalog.verifyAgainst(registeredTools);
    }

    /**
     * The tools the relay and the local policy both allow.
     *
     * @param relayAllowed the relay's allowed tool names, or null from an old relay that sends no list
     */
    public JsonObject list(JsonElement id, Set<String> relayAllowed, LocalPolicy local) {
        JsonArray definitions = new JsonArray();
        for (McpTool tool : tools.values()) {
            if (relayAllowed != null && !relayAllowed.contains(tool.getName())
                    || local.refusal(catalog, tool.getName()) != null) {
                continue;
            }
            JsonObject definition = new JsonObject();
            definition.addProperty("name", tool.getName());
            definition.addProperty("description", tool.getDescription());
            definition.add("inputSchema", tool.getInputSchema());
            definitions.add(definition);
        }
        JsonObject result = new JsonObject();
        result.add("tools", definitions);
        return success(id, result);
    }

    /**
     * @param relayAllowed the relay's allowed tool names, or null from an old relay that sends no list
     * @param relayPackageScopes the relay's package scope layers (a JSON array of arrays); null or malformed fails closed
     */
    public JsonObject call(JsonElement id, JsonObject params, Set<String> relayAllowed, JsonElement relayPackageScopes,
            LocalPolicy local) {
        RelayPackageScopes scopes;
        try {
            scopes = RelayPackageScopes.parse(relayPackageScopes);
        } catch (IllegalArgumentException e) {
            return error(id, -32602, "Missing or invalid relay package restrictions.");
        }
        McpTool tool = tools.get(string(params.get("name")));
        if (tool == null) {
            return error(id, -32602, "Unknown relay tool.");
        }
        String name = tool.getName();
        if (relayAllowed != null && !relayAllowed.contains(name)) {
            PolicyDenials.report("Denied " + name + " (relay layer): the relay did not list this tool as allowed.");
            return error(id, RELAY_DENIED, "Denied by the relay's permissions: the relay did not allow this tool.");
        }
        String refusal = local.refusal(catalog, name);
        if (refusal != null) {
            PolicyDenials.report("Denied " + name + " (this Eclipse's permissions): " + refusal + ".");
            return error(id, LOCAL_DENIED, "Denied by this Eclipse's permissions: " + refusal + ".");
        }
        JsonElement args = params.get("arguments");
        if (args != null && !args.isJsonObject()) {
            return error(id, -32602, "Expected a tool arguments object.");
        }
        JsonObject arguments = args == null ? new JsonObject() : args.getAsJsonObject();
        if (!validArguments(tool.getInputSchema(), arguments)) {
            return error(id, -32602, "The arguments do not match the SAP tool schema.");
        }
        if (SearchObjectTool.NAME.equals(tool.getName()) && string(arguments.get("query")).isBlank()) {
            return error(id, -32602, "Enter a search query.");
        }
        try {
            synchronized (sapSession) {
                if (Thread.currentThread().isInterrupted()) {
                    return error(id, -32000, "The call was canceled before dispatch.");
                }
                String result = scopes.unrestricted() && local.scopes().unrestricted() ? tool.execute(arguments)
                        : new ScopedSapCall(sapSession, scopes, local.scopes()).execute(tool, arguments);
                return success(id, toolResult(result, false));
            }
        } catch (ScopedSapCall.Denied e) {
            if (e.local) {
                PolicyDenials.report("Denied " + name + " (this Eclipse's permissions): the target is outside the local package patterns.");
                return error(id, LOCAL_DENIED,
                        "Denied by this Eclipse's permissions: the target is outside the local package patterns.");
            }
            PolicyDenials.report("Denied " + name + " (relay layer): SAP package access could not be verified.");
            return error(id, RELAY_DENIED, "SAP package access could not be verified for this call.");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return success(id, toolResult("The call was interrupted. Check SAP for changes before retrying.", true));
        } catch (Exception e) {
            // SAP exceptions can include the request URI and the entire SAP response body.
            return success(id, toolResult("The SAP tool failed. Its outcome is unknown. Check SAP before retrying.", true));
        }
    }

    /** The response text, or the standard error when it exceeds the response limit. */
    public static String limited(JsonElement id, JsonObject response) {
        String text = response.toString();
        if (text.length() > MAX_RESPONSE_BYTES || text.getBytes(StandardCharsets.UTF_8).length > MAX_RESPONSE_BYTES) {
            return error(id, -32000, "The tool response exceeded the bridge limit. Check SAP before retrying an operation.")
                    .toString();
        }
        return text;
    }

    private static boolean validArguments(JsonObject schema, JsonObject args) {
        if (schema.has("required")) {
            for (JsonElement required : schema.getAsJsonArray("required")) {
                if (!args.has(required.getAsString())) return false;
            }
        }
        JsonObject properties = schema.getAsJsonObject("properties");
        for (String name : args.keySet()) {
            if (!properties.has(name)) return false;
            JsonObject spec = properties.getAsJsonObject(name);
            JsonElement value = args.get(name);
            if (spec.has("enum") && !spec.getAsJsonArray("enum").contains(value)) return false;
            switch (spec.get("type").getAsString()) {
                case "string" -> { if (string(value) == null) return false; }
                case "integer" -> { if (!validInteger(value, spec)) return false; }
                default -> { return false; }
            }
        }
        return true;
    }

    private static boolean validInteger(JsonElement value, JsonObject spec) {
        if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isNumber()) return false;
        try {
            int count = value.getAsBigDecimal().intValueExact();
            return (!spec.has("minimum") || count >= spec.get("minimum").getAsInt())
                    && (!spec.has("maximum") || count <= spec.get("maximum").getAsInt());
        } catch (NumberFormatException | ArithmeticException e) {
            return false;
        }
    }

    /** The string value, or null when the element is missing or not a JSON string. */
    public static String string(JsonElement value) {
        return value != null && value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()
                ? value.getAsString() : null;
    }

    private static JsonObject toolResult(String text, boolean isError) {
        JsonObject item = new JsonObject();
        item.addProperty("type", "text");
        item.addProperty("text", text);
        JsonArray content = new JsonArray();
        content.add(item);
        JsonObject result = new JsonObject();
        result.add("content", content);
        result.addProperty("isError", isError);
        return result;
    }

    private static JsonObject envelope(JsonElement id) {
        JsonObject response = new JsonObject();
        response.addProperty("jsonrpc", "2.0");
        response.add("id", id);
        return response;
    }

    public static JsonObject error(JsonElement id, int code, String message) {
        JsonObject detail = new JsonObject();
        detail.addProperty("code", code);
        detail.addProperty("message", message);
        JsonObject response = envelope(id);
        response.add("error", detail);
        return response;
    }

    public static JsonObject success(JsonElement id, JsonObject result) {
        JsonObject response = envelope(id);
        response.add("result", result);
        return response;
    }
}
