package com.sap.adt.mcp.server;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.Strictness;
import com.sap.adt.mcp.tools.McpTool;
import com.sap.adt.mcp.tools.SearchObjectTool;
import com.sap.adt.mcp.sap.AdtRestClient;

/** Discovers and dispatches the tools attached to this Eclipse SAP session. */
final class RelayRequests {
    private static final int MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
    private static final Gson JSON = new GsonBuilder().setStrictness(Strictness.STRICT).create();
    private final Map<String, McpTool> tools = new LinkedHashMap<>();
    private final AdtRestClient sapSession;

    RelayRequests(List<McpTool> registeredTools, AdtRestClient sapSession) {
        this.sapSession = sapSession;
        for (McpTool tool : registeredTools) {
            if (tools.putIfAbsent(tool.getName(), tool) != null) {
                throw new IllegalArgumentException("Duplicate SAP tool.");
            }
        }
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
                JsonObject hello = new JsonObject();
                hello.addProperty("policyVersion", 1);
                yield success(id, hello);
            }
            case "ping" -> success(id, new JsonObject());
            case "tools/list" -> success(id, list());
            case "tools/call" -> call(id, params == null ? new JsonObject() : params.getAsJsonObject());
            default -> error(id, -32601, "Unknown bridge method.");
        };
        String text = response.toString();
        if (text.length() > MAX_RESPONSE_BYTES || text.getBytes(StandardCharsets.UTF_8).length > MAX_RESPONSE_BYTES) {
            return error(id, -32000, "The tool response exceeded the bridge limit. Check SAP before retrying an operation.").toString();
        }
        return text;
    }

    private JsonObject list() {
        JsonArray definitions = new JsonArray();
        for (McpTool tool : tools.values()) {
            JsonObject definition = new JsonObject();
            definition.addProperty("name", tool.getName());
            definition.addProperty("description", tool.getDescription());
            definition.add("inputSchema", tool.getInputSchema());
            definitions.add(definition);
        }
        JsonObject result = new JsonObject();
        result.add("tools", definitions);
        return result;
    }

    private JsonObject call(JsonElement id, JsonObject params) {
        RelayPackageScopes scopes;
        try {
            scopes = RelayPackageScopes.parse(params.get("relayPackageScopes"));
        } catch (IllegalArgumentException e) {
            return error(id, -32602, "Missing or invalid relay package restrictions.");
        }
        McpTool tool = tools.get(string(params.get("name")));
        if (tool == null) {
            return error(id, -32602, "Unknown relay tool.");
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
                String result = scopes.unrestricted() ? tool.execute(arguments)
                        : new ScopedSapCall(sapSession, scopes).execute(tool, arguments);
                return success(id, toolResult(result, false));
            }
        } catch (ScopedSapCall.Denied e) {
            return error(id, -32001, "SAP package access could not be verified for this call.");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return success(id, toolResult("The call was interrupted. Check SAP for changes before retrying.", true));
        } catch (Exception e) {
            // SAP exceptions can include the request URI and the entire SAP response body.
            return success(id, toolResult("The SAP tool failed. Its outcome is unknown. Check SAP before retrying.", true));
        }
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

    private static String string(JsonElement value) {
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

    private static JsonObject error(JsonElement id, int code, String message) {
        JsonObject detail = new JsonObject();
        detail.addProperty("code", code);
        detail.addProperty("message", message);
        JsonObject response = envelope(id);
        response.add("error", detail);
        return response;
    }

    private static JsonObject success(JsonElement id, JsonObject result) {
        JsonObject response = envelope(id);
        response.add("result", result);
        return response;
    }
}
