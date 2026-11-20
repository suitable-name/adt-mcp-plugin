package com.sap.adt.mcp.server;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLSession;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sap.adt.mcp.preferences.PermissionsModel;
import com.sap.adt.mcp.sap.AdtRestClient;
import com.sap.adt.mcp.tools.*;

/** Source-level regression harness for the local Eclipse permissions and for the plugin acting as the authority. */
public final class LocalPolicyRegression {
    private static final String CORE = "http://www.sap.com/adt/core";
    private static final String URI = "/sap/bc/adt/oo/classes/%2fns%2fcl_demo";
    private static final String TARGET = "{\"objectType\":\"CLAS\",\"objectName\":\"/NS/CL_DEMO\"}";
    private static final String ALL = "[\"sap_activate\",\"sap_create_object\",\"sap_get_source\",\"sap_lock\","
            + "\"sap_object_structure\",\"sap_search_object\",\"sap_set_source\",\"sap_sql_query\",\"sap_unlock\"]";
    private static final String OPEN_SCOPE = "[]";
    private static final int RELAY = -32_001;
    private static final int LOCAL = -32_002;

    public static void main(String[] args) {
        ToolCatalog catalog = loadCatalog();
        localReadOnlyBlocksAWriteTheRelayAllows(catalog);
        compromisedRelayStub(catalog);
        localPatternsIntersectWithRelayScopes(catalog);
        compatibilityWithOldRelays(catalog);
        lockFlagMakesTheStoreReadOnly();
        catalogVerificationIsWired(catalog);
        patternRulesMatchTheRelay();
    }

    private static void localReadOnlyBlocksAWriteTheRelayAllows(ToolCatalog catalog) {
        FakeSap sap = new FakeSap();
        AtomicReference<LocalPolicy> policy = new AtomicReference<>(LocalPolicy.of(true, null, List.of(), false));
        RelayRequests relay = relay(sap, catalog, policy::get);
        hello(relay, true);
        String write = TARGET.substring(0, TARGET.length() - 1) + ",\"source\":\"test\"}";
        JsonObject denied = call(relay, "sap_set_source", write, ALL, OPEN_SCOPE);
        check(code(denied) == LOCAL);
        check(denied.getAsJsonObject("error").get("message").getAsString()
                .startsWith("Denied by this Eclipse's permissions: "));
        check(sap.paths.isEmpty());
        // Read tools still work, and a SQL (execute) tool is refused too.
        check(!call(relay, "sap_get_source", TARGET, ALL, OPEN_SCOPE).has("error"));
        check(code(call(relay, "sap_sql_query", "{\"query\":\"SELECT 1\"}", ALL, OPEN_SCOPE)) == LOCAL);
        List<String> listed = names(list(relay, ALL));
        check(listed.contains("sap_get_source") && listed.contains("sap_search_object"));
        check(!listed.contains("sap_set_source") && !listed.contains("sap_sql_query"));
        // A change applies to the next call without recreating anything.
        policy.set(LocalPolicy.unrestricted());
        check(names(list(relay, ALL)).contains("sap_set_source"));
        // A tool allow-list that omits a component refuses the composite writer.
        policy.set(LocalPolicy.of(false, Set.of("sap_set_source", "sap_lock"), List.of(), false));
        check(code(call(relay, "sap_set_source", write, ALL, OPEN_SCOPE)) == LOCAL);
        check(!names(list(relay, ALL)).contains("sap_set_source"));
        // A store that cannot be read refuses everything.
        policy.set(LocalPolicy.blocked(false));
        check(names(list(relay, ALL)).isEmpty());
    }

    private static void compromisedRelayStub(ToolCatalog catalog) {
        FakeSap sap = new FakeSap();
        RelayRequests relay = relay(sap, catalog, LocalPolicy::unrestricted);
        hello(relay, true);
        // The stub forwards a call for a tool that its own allowed list omits.
        String withoutSource = "[\"sap_search_object\"]";
        JsonObject denied = call(relay, "sap_get_source", TARGET, withoutSource, OPEN_SCOPE);
        check(code(denied) == RELAY);
        check(sap.paths.isEmpty());
        check(names(list(relay, withoutSource)).equals(List.of("sap_search_object")));
        // Malformed lists are refused, with or without version 2.
        for (String bad : new String[] {"\"sap_get_source\"", "[1]", "[null]", "{}"}) {
            check(code(call(relay, "sap_get_source", TARGET, bad, OPEN_SCOPE)) == -32602);
            check(list(relay, bad).has("error"));
        }
        check(sap.paths.isEmpty());
        // Version 2 relay with no list at all: fail closed.
        check(code(call(relay, "sap_get_source", TARGET, null, OPEN_SCOPE)) == -32602);
        check(list(relay, null).has("error"));
        check(sap.paths.isEmpty());
    }

    private static void localPatternsIntersectWithRelayScopes(ToolCatalog catalog) {
        FakeSap sap = new FakeSap();
        LocalPolicy local = LocalPolicy.of(false, null, LocalPolicy.parsePatterns("/ns/zapp"), false);
        RelayRequests relay = relay(sap, catalog, () -> local);
        hello(relay, true);
        String relayScope = "[[\"/NS/*\"]]";
        sap.owner = "/NS/ZAPP";
        check(!call(relay, "sap_get_source", TARGET, ALL, relayScope).has("error"));
        // The relay allows /NS/*, but the local patterns do not allow this package.
        sap.owner = "/NS/OTHER";
        check(code(call(relay, "sap_get_source", TARGET, ALL, relayScope)) == LOCAL);
        // Outside the relay's scope the relay layer refuses, even though it is not a local denial.
        sap.owner = "/OTHER/PKG";
        check(code(call(relay, "sap_get_source", TARGET, ALL, relayScope)) == RELAY);
        // Local patterns apply even when the relay sends no package restriction.
        sap.owner = "/NS/OTHER";
        check(code(call(relay, "sap_get_source", TARGET, ALL, OPEN_SCOPE)) == LOCAL);
        sap.owner = "/NS/ZAPP";
        check(!call(relay, "sap_get_source", TARGET, ALL, OPEN_SCOPE).has("error"));
        // With local patterns a tool that cannot be limited to a package is refused outright.
        sap.paths.clear();
        check(code(call(relay, "sap_sql_query", "{\"query\":\"SELECT 1\"}", ALL, OPEN_SCOPE)) == LOCAL);
        check(sap.paths.isEmpty());
        check(!names(list(relay, ALL)).contains("sap_sql_query"));
        // Search results are filtered by both layers.
        JsonObject search = json(resultText(call(relay, "sap_search_object", "{\"query\":\"*\"}", ALL, relayScope)));
        check(search.get("totalResults").getAsInt() == 1 && !search.toString().contains("EXCLUDED"));
    }

    private static void compatibilityWithOldRelays(ToolCatalog catalog) {
        FakeSap sap = new FakeSap();
        // A hello without policy version 2 (an old relay, which sends no tool list) accepts a missing list.
        RelayRequests old = relay(sap, catalog, LocalPolicy::unrestricted);
        hello(old, false);
        check(!call(old, "sap_get_source", TARGET, null, OPEN_SCOPE).has("error"));
        check(names(list(old, null)).contains("sap_get_source"));
        // The local policy still applies to an old relay.
        RelayRequests oldLocal = relay(sap, catalog, () -> LocalPolicy.of(true, null, List.of(), false));
        check(code(call(oldLocal, "sap_set_source", TARGET, null, OPEN_SCOPE)) == LOCAL);
        // A relay that never said hello at all is treated as old, as before this change.
        RelayRequests silent = relay(sap, catalog, LocalPolicy::unrestricted);
        check(!call(silent, "sap_get_source", TARGET, null, OPEN_SCOPE).has("error"));
        // Once a relay has advertised version 2 it cannot go back.
        hello(silent, true);
        check(code(call(silent, "sap_get_source", TARGET, null, OPEN_SCOPE)) == -32602);
        hello(silent, false);
        check(code(call(silent, "sap_get_source", TARGET, null, OPEN_SCOPE)) == -32602);
    }

    private static void lockFlagMakesTheStoreReadOnly() {
        MapBackend backend = new MapBackend();
        PermissionsModel store = new PermissionsModel(backend);
        check(store.load().summary().equals("Local permissions: no restrictions"));
        store.save(true, Set.of("sap_get_source"), List.of("Z*"));
        LocalPolicy saved = store.load();
        check(saved.readOnly() && saved.allowedTools().equals(Set.of("sap_get_source"))
                && saved.packagePatterns().equals(List.of("Z*")) && !saved.locked());
        check(saved.summary().equals("Local permissions: read-only, 1 tool, 1 package pattern"));
        // An invalid pattern writes nothing.
        try {
            store.save(false, null, List.of("not valid"));
            throw new AssertionError("Invalid pattern accepted.");
        } catch (IllegalArgumentException expected) {
            check(store.load().readOnly());
        }
        // The administrator sets the lock and presets a value. User values are ignored and cannot be saved.
        backend.admin.put(PermissionsModel.KEY_LOCKED, "true");
        backend.admin.put(PermissionsModel.KEY_READ_ONLY, "true");
        backend.admin.put(PermissionsModel.KEY_PACKAGE_PATTERNS, "Z*,/NS/*");
        backend.user.put(PermissionsModel.KEY_READ_ONLY, "false");
        backend.user.put(PermissionsModel.KEY_PACKAGE_PATTERNS, "*");
        check(store.locked());
        LocalPolicy locked = store.load();
        check(locked.locked() && locked.readOnly() && locked.allowedTools() == null
                && locked.packagePatterns().equals(List.of("/NS/*", "Z*"))); // parsePatterns sorts
        check(locked.summary().endsWith("(locked by your administrator)"));
        Map<String, String> before = new HashMap<>(backend.user);
        try {
            store.save(false, null, List.of());
            throw new AssertionError("A locked store accepted a save.");
        } catch (IllegalStateException expected) {
            check(backend.user.equals(before));
        }
        try {
            store.reset();
            throw new AssertionError("A locked store accepted a reset.");
        } catch (IllegalStateException expected) {
            check(backend.user.equals(before));
        }
        // Unreadable stored values fail closed.
        // ("no good" would split into the two valid patterns NO and GOOD.)
        backend.admin.put(PermissionsModel.KEY_PACKAGE_PATTERNS, "Z*,%BAD%");
        check(store.load().allowedTools().isEmpty());
    }

    private static void catalogVerificationIsWired(ToolCatalog catalog) {
        FakeSap sap = new FakeSap();
        // An empty table lists none of the registered tools, so the constructor must refuse them.
        ToolCatalog empty = ToolCatalog.load(new java.io.StringReader("{\"version\":1,\"tools\":[]}"));
        try {
            new RelayRequests(List.of(new SearchObjectTool(sap)), sap, empty, LocalPolicy::unrestricted);
            throw new AssertionError("The constructor did not verify the tool table.");
        } catch (IllegalStateException expected) {
            // Expected.
        }
    }

    private static void patternRulesMatchTheRelay() {
        check(LocalPolicy.parsePatterns(" z*, /ns/zapp;Z*\n*").equals(List.of("*", "/NS/ZAPP", "Z*")));
        check(LocalPolicy.parsePatterns("").isEmpty());
        for (String bad : new String[] {"Z*X", "/NS/", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", "A B-C"}) {
            try {
                LocalPolicy.parsePatterns(bad);
                throw new AssertionError("Accepted " + bad);
            } catch (IllegalArgumentException expected) {
                // Expected.
            }
        }
        StringBuilder many = new StringBuilder();
        for (int i = 0; i < 65; i++) many.append("Z").append(i).append(',');
        try {
            LocalPolicy.parsePatterns(many.toString());
            throw new AssertionError("Accepted more than 64 patterns.");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
    }

    private static RelayRequests relay(FakeSap sap, ToolCatalog catalog, java.util.function.Supplier<LocalPolicy> policy) {
        return new RelayRequests(List.of(new SearchObjectTool(sap), new GetSourceTool(sap),
                new ObjectStructureTool(sap), new LockTool(sap), new UnlockTool(sap), new SqlQueryTool(sap),
                new SetSourceTool(sap), new CreateObjectTool(sap), new ActivateTool(sap)), sap, catalog, policy);
    }

    private static void hello(RelayRequests relay, boolean versionTwo) {
        String params = versionTwo ? ",\"params\":{\"policyVersion\":2}" : "";
        JsonObject reply = json(relay.reply("{\"jsonrpc\":\"2.0\",\"method\":\"relay/hello\",\"id\":1" + params + "}"));
        check(reply.getAsJsonObject("result").get("policyVersion").getAsInt() == 2);
    }

    private static JsonObject call(RelayRequests relay, String tool, String args, String allowed, String scopes) {
        JsonObject params = new JsonObject();
        params.addProperty("name", tool);
        params.add("arguments", json(args));
        params.add("relayPackageScopes", JsonParser.parseString(scopes));
        if (allowed != null) params.add("relayAllowedTools", JsonParser.parseString(allowed));
        return request(relay, "tools/call", params);
    }

    private static JsonObject list(RelayRequests relay, String allowed) {
        JsonObject params = new JsonObject();
        if (allowed != null) params.add("relayAllowedTools", JsonParser.parseString(allowed));
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

    private static List<String> names(JsonObject listReply) {
        check(!listReply.has("error"));
        List<String> names = new ArrayList<>();
        JsonArray tools = listReply.getAsJsonObject("result").getAsJsonArray("tools");
        tools.forEach(tool -> names.add(tool.getAsJsonObject().get("name").getAsString()));
        return names;
    }

    private static int code(JsonObject reply) {
        check(reply.has("error"));
        return reply.getAsJsonObject("error").get("code").getAsInt();
    }

    private static JsonObject json(String value) { return JsonParser.parseString(value).getAsJsonObject(); }

    private static String resultText(JsonObject reply) {
        check(!reply.has("error"));
        JsonObject result = reply.getAsJsonObject("result");
        check(!result.get("isError").getAsBoolean());
        return result.getAsJsonArray("content").get(0).getAsJsonObject().get("text").getAsString();
    }

    /** Loads the shared tool table from the source tree. Run the harness from the checkout root. */
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
        if (!condition) throw new AssertionError("Local policy regression.");
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
        String owner = "/NS/ZAPP";

        @Override public void login() { }

        @Override public boolean isLoggedIn() { return true; }

        @Override public String getUsername() { return "TEST"; }

        @Override
        public HttpResponse<String> delete(String path) {
            throw new AssertionError("Unexpected delete in local policy regression.");
        }

        @Override
        public HttpResponse<String> get(String path, String accept) {
            paths.add(path);
            if (path.startsWith("/sap/bc/adt/repository/informationsystem/search?")) {
                String ref = "<a:objectReference a:name='CL_DEMO' a:type='CLAS/OC' a:uri='" + URI + "' a:packageName='/NS/ZAPP'/>";
                return response("<a:objectReferences xmlns:a='" + CORE + "'>" + ref
                        + ref.replace("CL_DEMO", "EXCLUDED_ONE").replace("/NS/ZAPP", "/NS/EXCLUDED") + "</a:objectReferences>");
            }
            if (path.equals(URI + "/source/main")) return response("CLASS /NS/CL_DEMO.");
            check(path.equals(URI));
            return response("<c:abapClass xmlns:c='http://www.sap.com/adt/oo/classes' xmlns:a='" + CORE
                    + "' a:name='/NS/CL_DEMO' a:type='CLAS/OC' a:uri='" + URI + "'><a:packageRef a:name='" + owner
                    + "'/></c:abapClass>");
        }

        @Override
        public HttpResponse<String> postWithHeaders(String path, String body, String type, String accept, Map<String, String> headers) {
            throw new AssertionError("Unexpected post in local policy regression.");
        }

        @Override
        public HttpResponse<String> putWithHeaders(String path, String body, String type, Map<String, String> headers) {
            throw new AssertionError("Unexpected write in local policy regression.");
        }

        @Override
        public HttpResponse<String> post(String path, String body, String type, String accept) {
            throw new AssertionError("Unexpected post in local policy regression.");
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
