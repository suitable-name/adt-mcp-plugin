package com.sap.adt.mcp.server;

import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLSession;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sap.adt.mcp.preferences.PermissionsModel;
import com.sap.adt.mcp.sap.AdtRestClient;
import com.sap.adt.mcp.tools.*;

/**
 * Source-level regression harness for the "Allow unencrypted relay calls" switch (key relay.allowUnencrypted).
 * Run from the checkout root, like LocalPolicyRegression.
 */
public final class LegacySwitchRegression {
    private static final String TARGET = "{\"objectType\":\"CLAS\",\"objectName\":\"/NS/CL_DEMO\"}";
    private static final String ALL = "[\"sap_get_source\",\"sap_search_object\"]";
    private static final int LOCAL = -32_002;
    private static final String REFUSAL =
            "This Eclipse accepts only end-to-end encrypted calls. Pair this desktop with Pair Desktop in the MCP view.";

    public static void main(String[] args) {
        ToolCatalog catalog = loadCatalog();
        switchOffRefusesLegacyListAndCall(catalog);
        switchOnBehavesAsBefore(catalog);
        preferenceDefaultsAndPerCallRead(catalog);
        lockedAdministratorValueWins();
        unreadableValueFailsClosed();
    }

    private static void switchOffRefusesLegacyListAndCall(ToolCatalog catalog) {
        FakeSap sap = new FakeSap();
        List<String> logged = new ArrayList<>();
        LegacyCalls.onRefusal(logged::add);
        RelayRequests relay = relay(sap, catalog, () -> false);
        // relay/hello and ping still answer, so the relay can keep the bridge.
        JsonObject hello = hello(relay);
        check(hello.getAsJsonObject("result").get("policyVersion").getAsInt() == 2);
        check(hello.getAsJsonObject("result").get("e2e").getAsInt() == 1);
        check(!request(relay, "ping", new JsonObject()).has("error"));
        for (JsonObject reply : new JsonObject[] {list(relay), call(relay)}) {
            check(code(reply) == LOCAL);
            check(reply.getAsJsonObject("error").get("message").getAsString().equals(REFUSAL));
        }
        check(sap.paths.isEmpty());
        check(logged.size() == 2 && logged.get(0).contains("tools/list") && logged.get(1).contains("tools/call"));
        check(logged.stream().allMatch(line -> line.contains("this Eclipse's encryption setting")));
        LegacyCalls.onRefusal(null);
    }

    private static void switchOnBehavesAsBefore(ToolCatalog catalog) {
        FakeSap sap = new FakeSap();
        List<String> logged = new ArrayList<>();
        LegacyCalls.onRefusal(logged::add);
        RelayRequests relay = relay(sap, catalog, () -> true);
        hello(relay);
        check(!list(relay).has("error"));
        check(!call(relay).has("error"));
        check(!sap.paths.isEmpty());
        check(logged.isEmpty());
        LegacyCalls.onRefusal(null);
    }

    private static void preferenceDefaultsAndPerCallRead(ToolCatalog catalog) {
        MapBackend backend = new MapBackend();
        PermissionsModel model = new PermissionsModel(backend);
        check(PermissionsModel.KEY_ALLOW_UNENCRYPTED.equals("relay.allowUnencrypted"));
        check(model.allowUnencrypted()); // default in this version
        FakeSap sap = new FakeSap();
        RelayRequests relay = relay(sap, catalog, model::allowUnencrypted);
        hello(relay);
        check(!call(relay).has("error"));
        // A change applies to the next call, with the same RelayRequests instance.
        model.saveAllowUnencrypted(false);
        check(!model.allowUnencrypted());
        check(code(call(relay)) == LOCAL);
        check(code(list(relay)) == LOCAL);
        model.resetAllowUnencrypted();
        check(model.allowUnencrypted());
        check(!list(relay).has("error"));
        // An administrator preset without a lock is a default the user can override.
        backend.admin.put(PermissionsModel.KEY_ALLOW_UNENCRYPTED, "false");
        check(!model.allowUnencrypted());
        model.saveAllowUnencrypted(true);
        check(model.allowUnencrypted());
    }

    private static void lockedAdministratorValueWins() {
        MapBackend backend = new MapBackend();
        PermissionsModel model = new PermissionsModel(backend);
        backend.admin.put(PermissionsModel.KEY_LOCKED, "true");
        backend.admin.put(PermissionsModel.KEY_ALLOW_UNENCRYPTED, "false");
        backend.user.put(PermissionsModel.KEY_ALLOW_UNENCRYPTED, "true");
        check(!model.allowUnencrypted());
        Map<String, String> before = new HashMap<>(backend.user);
        try {
            model.saveAllowUnencrypted(true);
            throw new AssertionError("A locked store accepted a save.");
        } catch (IllegalStateException expected) {
            check(backend.user.equals(before));
        }
        try {
            model.resetAllowUnencrypted();
            throw new AssertionError("A locked store accepted a reset.");
        } catch (IllegalStateException expected) {
            check(backend.user.equals(before));
        }
        // Locked and no administrator value: the default (allowed) applies, the user's "false" is ignored too.
        backend.admin.remove(PermissionsModel.KEY_ALLOW_UNENCRYPTED);
        backend.user.put(PermissionsModel.KEY_ALLOW_UNENCRYPTED, "false");
        check(model.allowUnencrypted());
        // Locked with an administrator "true" beats a user "false".
        backend.admin.put(PermissionsModel.KEY_ALLOW_UNENCRYPTED, "true");
        check(model.allowUnencrypted());
    }

    private static void unreadableValueFailsClosed() {
        MapBackend backend = new MapBackend();
        PermissionsModel model = new PermissionsModel(backend);
        backend.user.put(PermissionsModel.KEY_ALLOW_UNENCRYPTED, "maybe");
        check(!model.allowUnencrypted());
        PermissionsModel broken = new PermissionsModel(new PermissionsModel.Backend() {
            @Override public String admin(String key) { throw new IllegalStateException("unreadable"); }
            @Override public String user(String key) { return null; }
            @Override public void putUser(String key, String value) { }
            @Override public void removeUser(String key) { }
        });
        check(!broken.allowUnencrypted());
    }

    private static RelayRequests relay(FakeSap sap, ToolCatalog catalog, java.util.function.BooleanSupplier allow) {
        return new RelayRequests(List.of(new SearchObjectTool(sap), new GetSourceTool(sap)), sap, catalog,
                LocalPolicy::unrestricted, allow::getAsBoolean);
    }

    private static JsonObject hello(RelayRequests relay) {
        return json(relay.reply("{\"jsonrpc\":\"2.0\",\"method\":\"relay/hello\",\"id\":1,"
                + "\"params\":{\"policyVersion\":2}}"));
    }

    private static JsonObject call(RelayRequests relay) {
        JsonObject params = new JsonObject();
        params.addProperty("name", "sap_get_source");
        params.add("arguments", json(TARGET));
        params.add("relayPackageScopes", JsonParser.parseString("[]"));
        params.add("relayAllowedTools", JsonParser.parseString(ALL));
        return request(relay, "tools/call", params);
    }

    private static JsonObject list(RelayRequests relay) {
        JsonObject params = new JsonObject();
        params.add("relayAllowedTools", JsonParser.parseString(ALL));
        return request(relay, "tools/list", params);
    }

    private static JsonObject request(RelayRequests relay, String method, JsonObject params) {
        JsonObject request = new JsonObject();
        request.addProperty("id", 1);
        request.addProperty("jsonrpc", "2.0");
        request.addProperty("method", method);
        request.add("params", params);
        return json(relay.reply(request.toString()));
    }

    private static int code(JsonObject reply) {
        check(reply.has("error"));
        return reply.getAsJsonObject("error").get("code").getAsInt();
    }

    private static JsonObject json(String value) { return JsonParser.parseString(value).getAsJsonObject(); }

    private static ToolCatalog loadCatalog() {
        String path = System.getProperty("tools.json",
                "java-plugin/sap-adt-mcp-server/com.sap.adt.mcp.server.plugin/resources/tools.json");
        try (java.io.Reader reader = java.nio.file.Files.newBufferedReader(java.nio.file.Path.of(path))) {
            return ToolCatalog.load(reader);
        } catch (java.io.IOException e) {
            throw new AssertionError("Cannot read " + path, e);
        }
    }

    private static void check(boolean condition) {
        if (!condition) throw new AssertionError("Legacy switch regression.");
    }

    private static final class MapBackend implements PermissionsModel.Backend {
        final Map<String, String> admin = new HashMap<>();
        final Map<String, String> user = new HashMap<>();

        @Override public String admin(String key) { return admin.get(key); }
        @Override public String user(String key) { return user.get(key); }
        @Override public void putUser(String key, String value) { user.put(key, value); }
        @Override public void removeUser(String key) { user.remove(key); }
    }

    private static final class FakeSap extends AdtRestClient {
        final List<String> paths = new ArrayList<>();

        @Override public void login() { }

        @Override public boolean isLoggedIn() { return true; }

        @Override public String getUsername() { return "TEST"; }

        @Override
        public HttpResponse<String> get(String path, String accept) {
            paths.add(path);
            String uri = "/sap/bc/adt/oo/classes/%2fns%2fcl_demo";
            String core = "http://www.sap.com/adt/core";
            if (path.startsWith("/sap/bc/adt/repository/informationsystem/search?")) {
                return response("<a:objectReferences xmlns:a='" + core + "'><a:objectReference a:name='CL_DEMO' "
                        + "a:type='CLAS/OC' a:uri='" + uri + "' a:packageName='/NS/ZAPP'/></a:objectReferences>");
            }
            if (path.equals(uri + "/source/main")) return response("CLASS /NS/CL_DEMO.");
            return response("<c:abapClass xmlns:c='http://www.sap.com/adt/oo/classes' xmlns:a='" + core
                    + "' a:name='/NS/CL_DEMO' a:type='CLAS/OC' a:uri='" + uri + "'><a:packageRef a:name='/NS/ZAPP'/>"
                    + "</c:abapClass>");
        }

        @Override
        public HttpResponse<String> delete(String path) { throw new AssertionError("Unexpected delete."); }

        @Override
        public HttpResponse<String> postWithHeaders(String path, String body, String type, String accept, Map<String, String> headers) {
            throw new AssertionError("Unexpected post.");
        }

        @Override
        public HttpResponse<String> putWithHeaders(String path, String body, String type, Map<String, String> headers) {
            throw new AssertionError("Unexpected write.");
        }

        @Override
        public HttpResponse<String> post(String path, String body, String type, String accept) {
            throw new AssertionError("Unexpected post.");
        }
    }

    private static HttpResponse<String> response(String body) { return new Reply(body); }

    private record Reply(String body) implements HttpResponse<String> {
        public int statusCode() { return 200; }
        public HttpRequest request() { throw new AssertionError(); }
        public HttpHeaders headers() { return HttpHeaders.of(Map.of(), (name, value) -> true); }
        public java.net.URI uri() { return java.net.URI.create("https://unused.invalid"); }
        public HttpClient.Version version() { return HttpClient.Version.HTTP_1_1; }
        public Optional<SSLSession> sslSession() { return Optional.empty(); }
        public Optional<HttpResponse<String>> previousResponse() { return Optional.empty(); }
    }
}
