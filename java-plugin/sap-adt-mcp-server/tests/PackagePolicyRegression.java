package com.sap.adt.mcp.server;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.net.ssl.SSLSession;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sap.adt.mcp.sap.AdtRestClient;
import com.sap.adt.mcp.tools.*;

/** Source-level regression harness for package enforcement. All SAP responses are supplied in memory. */
public final class PackagePolicyRegression {
    private static final String CORE = "http://www.sap.com/adt/core";
    private static final String URI = "/sap/bc/adt/oo/classes/%2fns%2fcl_demo";
    private static final String SCOPE = "[[\"/NS/*\"],[\"/NS/Z*\"]]";
    private static final String TARGET = "{\"objectType\":\"CLAS\",\"objectName\":\"/NS/CL_DEMO\"}";

    public static void main(String[] args) {
        FakeSap sap = new FakeSap();
        ToolCatalog catalog = loadCatalog();
        // The local policy is unrestricted here, so this harness exercises the relay's package scopes only.
        RelayRequests relay = new RelayRequests(List.of(new SearchObjectTool(sap), new GetSourceTool(sap),
                new ObjectStructureTool(sap), new LockTool(sap), new UnlockTool(sap), new SqlQueryTool(sap),
                new SetSourceTool(sap), new CreateObjectTool(sap), new ActivateTool(sap)), sap, catalog,
                LocalPolicy::unrestricted);
        JsonObject hello = json(relay.reply(
                "{\"jsonrpc\":\"2.0\",\"method\":\"relay/hello\",\"id\":1,\"params\":{\"policyVersion\":2}}"));
        check(hello.getAsJsonObject("result").get("policyVersion").getAsInt() == 2);
        for (String invalid : new String[] {null, "null", "[\"/NS/*\"]", "[[\"Z*X\"]]", "[[\"/ns/*\"]]",
                "[[\"*\"],[],[]]", "[[true]]", "[[]]"}) {
            check(call(relay, "sap_get_source", TARGET, invalid).has("error"));
        }
        check(sap.paths.isEmpty());
        String scopeEscape = "{\"objectType\":\"CLAS\",\"objectName\":\"../outside?version=inactive\"}";
        check(call(relay, "sap_get_source", scopeEscape, SCOPE).has("error"));
        call(relay, "sap_get_source", scopeEscape, "[]");
        check(sap.paths.isEmpty());
        check(!resultText(call(relay, "sap_get_source", TARGET, SCOPE)).isEmpty());
        check(sap.paths.equals(List.of(URI, URI + "/source/main", URI)));
        sap.paths.clear();
        sap.afterSource = "/NS/OUTSIDE";
        check(call(relay, "sap_get_source", TARGET, SCOPE).has("error"));
        sap.afterSource = null;
        sap.owner = "/NS/ZAPP";
        sap.nestedOwnerOnly = true;
        sap.paths.clear();
        check(call(relay, "sap_get_source", TARGET, SCOPE).has("error"));
        check(sap.paths.equals(List.of(URI)));
        sap.nestedOwnerOnly = false;
        sap.wrongUri = true;
        check(call(relay, "sap_object_structure", TARGET, SCOPE).has("error"));
        sap.wrongUri = false;
        check(json(resultText(call(relay, "sap_object_structure", TARGET, SCOPE)))
                .get("packageName").getAsString().equals("/NS/ZAPP"));
        JsonObject search = json(resultText(call(relay, "sap_search_object", "{\"query\":\"*\"}", SCOPE)));
        check(search.get("totalResults").getAsInt() == 1 && !search.toString().contains("FORBIDDEN"));
        sap.paths.clear();
        check(call(relay, "sap_sql_query", "{\"query\":\"SELECT * FROM secret\"}", SCOPE).has("error"));
        check(sap.paths.isEmpty());
        String unlock = TARGET.substring(0, TARGET.length() - 1) + ",\"lockHandle\":\"h1\"}";
        check(call(relay, "sap_unlock", unlock, SCOPE).has("error"));
        check(resultText(call(relay, "sap_lock", TARGET, SCOPE)).contains("h1"));
        check(!call(relay, "sap_unlock", unlock, SCOPE).has("error"));
        check(call(relay, "sap_unlock", unlock, SCOPE).has("error"));
        sap.paths.clear();
        sap.moveAfterLock = true;
        String write = TARGET.substring(0, TARGET.length() - 1) + ",\"source\":\"test\"}";
        check(call(relay, "sap_set_source", write, SCOPE).has("error"));
        check(sap.paths.equals(List.of(URI, URI + "?_action=LOCK&accessMode=MODIFY", URI,
                URI + "?_action=UNLOCK&lockHandle=h1")));
        String create = "{\"objtype\":\"CLAS/OC\",\"name\":\"/NS/CL_NEW\",\"parentName\":\"/NS/ZAPP\",\"description\":\"test\"}";
        sap.paths.clear();
        check(call(relay, "sap_create_object", create.replace("ZAPP", "OUTSIDE"), SCOPE).has("error"));
        check(sap.paths.isEmpty());
        check(resultText(call(relay, "sap_create_object", create, SCOPE)).contains("created"));
        check(sap.posted.contains("<adtcore:packageRef adtcore:name=\"/NS/ZAPP\""));
        checkLockOwnership();
    }

    private static void checkLockOwnership() {
        FakeSap first = new FakeSap();
        FakeSap second = new FakeSap();
        first.rememberLock("shared-handle", URI);
        check(first.ownsLock("shared-handle", URI));
        check(!second.ownsLock("shared-handle", URI));
        first.forgetLock("shared-handle", URI + "/other");
        check(first.ownsLock("shared-handle", URI));
        first.logout();
        check(!first.ownsLock("shared-handle", URI));
    }

    private static JsonObject call(RelayRequests relay, String tool, String args, String layers) {
        JsonObject params = new JsonObject();
        params.addProperty("name", tool);
        params.add("arguments", json(args));
        if (layers != null) params.add("relayPackageScopes", JsonParser.parseString(layers));
        // The relay allows every tool here; the package scopes are what these checks vary.
        params.add("relayAllowedTools", JsonParser.parseString(
                "[\"sap_activate\",\"sap_create_object\",\"sap_get_source\",\"sap_lock\",\"sap_object_structure\","
                + "\"sap_search_object\",\"sap_set_source\",\"sap_sql_query\",\"sap_unlock\"]"));
        JsonObject request = new JsonObject();
        request.addProperty("id", 1);
        request.addProperty("jsonrpc", "2.0");
        request.addProperty("method", "tools/call");
        request.add("params", params);
        return json(relay.reply(request.toString()));
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

    private static JsonObject json(String value) { return JsonParser.parseString(value).getAsJsonObject(); }

    private static String resultText(JsonObject reply) {
        JsonObject result = reply.getAsJsonObject("result");
        check(!result.get("isError").getAsBoolean());
        return result.getAsJsonArray("content").get(0).getAsJsonObject().get("text").getAsString();
    }

    private static void check(boolean condition) {
        if (!condition) throw new AssertionError("Package policy regression.");
    }

    private static final class FakeSap extends AdtRestClient {
        final List<String> paths = new ArrayList<>();
        String owner = "/NS/ZAPP";
        boolean nestedOwnerOnly;
        boolean wrongUri;
        boolean moveAfterLock;
        String afterSource;
        String posted;

        @Override
        public void login() { }

        @Override
        public boolean isLoggedIn() { return true; }

        @Override
        public String getUsername() { return "TEST"; }

        @Override
        public HttpResponse<String> delete(String path) {
            throw new AssertionError("Unexpected delete in package policy regression.");
        }

        @Override
        public HttpResponse<String> get(String path, String accept) {
            paths.add(path);
            if (path.startsWith("/sap/bc/adt/repository/informationsystem/search?")) {
                String ref = "<a:objectReference a:name='CL_DEMO' a:type='CLAS/OC' a:uri='" + URI + "' a:packageName='/NS/ZAPP'/>";
                return response("<a:objectReferences xmlns:a='" + CORE + "'>" + ref
                        + ref.replace("CL_DEMO", "FORBIDDEN").replace("/NS/ZAPP", "/NS/EXCLUDED") + "</a:objectReferences>");
            }
            if (path.equals(URI + "/source/main")) {
                if (afterSource != null) owner = afterSource;
                return response("CLASS /NS/CL_DEMO.");
            }
            check(path.equals(URI));
            String ref = "<a:packageRef a:name='" + owner + "'/>";
            return response("<c:abapClass xmlns:c='http://www.sap.com/adt/oo/classes' xmlns:a='" + CORE
                    + "' a:name='/NS/CL_DEMO' a:type='CLAS/OC' a:uri='" + (wrongUri ? URI + "/other" : URI) + "'>"
                    + (nestedOwnerOnly ? "<related>" + ref + "</related>" : ref) + "</c:abapClass>");
        }

        @Override
        public HttpResponse<String> postWithHeaders(String path, String body, String type, String accept, Map<String, String> headers) {
            paths.add(path);
            if (path.contains("_action=LOCK")) {
                if (moveAfterLock) owner = "/NS/OUTSIDE";
                return response("<lock><LOCK_HANDLE>h1</LOCK_HANDLE></lock>");
            }
            check(path.equals(URI + "?_action=UNLOCK&lockHandle=h1"));
            return response("");
        }

        @Override
        public HttpResponse<String> putWithHeaders(String path, String body, String type, Map<String, String> headers) {
            throw new AssertionError("Unexpected write after the locked object's package changed.");
        }

        @Override
        public HttpResponse<String> post(String path, String body, String type, String accept) {
            check(path.equals("/sap/bc/adt/oo/classes"));
            paths.add(path);
            posted = body;
            return response("");
        }
    }

    private static HttpResponse<String> response(String body) {
        return new Reply(body);
    }

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
