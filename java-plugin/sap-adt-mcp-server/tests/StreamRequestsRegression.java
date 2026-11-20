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
import java.util.concurrent.CompletableFuture;
import javax.net.ssl.SSLSession;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sap.adt.mcp.preferences.PermissionsModel;
import com.sap.adt.mcp.sap.AdtRestClient;
import com.sap.adt.mcp.server.e2e.Pairing;
import com.sap.adt.mcp.server.e2e.RelayPolicyView;
import com.sap.adt.mcp.server.e2e.StreamContext;
import com.sap.adt.mcp.server.e2e.StreamRequests;
import com.sap.adt.mcp.tools.*;

/**
 * Source-level regression harness for the encrypted-stream MCP session: initialize, listing and calling through the
 * shared execution path with a fake SAP client, per-desktop permissions, and the rules for unpinned peers.
 */
public final class StreamRequestsRegression {
    private static final String CORE = "http://www.sap.com/adt/core";
    private static final String URI = "/sap/bc/adt/oo/classes/%2fns%2fcl_demo";
    private static final String TARGET = "{\"objectType\":\"CLAS\",\"objectName\":\"/NS/CL_DEMO\"}";
    private static final List<String> ALL = List.of("sap_activate", "sap_create_object", "sap_get_source", "sap_lock",
            "sap_object_structure", "sap_search_object", "sap_set_source", "sap_sql_query", "sap_unlock");
    private static final String DESKTOP_A = "a".repeat(64);
    private static final String DESKTOP_B = "b".repeat(64);
    private static final int RELAY = -32_001;
    private static final int LOCAL = -32_002;

    private record Ctx(int streamId, String peerKeyFingerprint, boolean peerPinned, String assertedDesktopFingerprint,
            String assertedLabel) implements StreamContext {
    }

    public static void main(String[] args) {
        ToolCatalog catalog = loadCatalog();
        initializeThenListAndCall(catalog);
        callsBeforeInitializeAreRefused(catalog);
        perDesktopRestrictionAppliesToItsFingerprintOnly(catalog);
        relayLayerStillApplies(catalog);
        unpinnedPeerCanOnlyClaim(catalog);
        notificationsAndUnknownMethods(catalog);
    }

    private static void initializeThenListAndCall(ToolCatalog catalog) {
        Fixture f = new Fixture(catalog);
        Ctx a = pinned(1, DESKTOP_A);
        JsonObject init = f.send(a, request(1, "initialize", "{\"protocolVersion\":\"2025-03-26\"}"), f.policy(ALL));
        JsonObject result = init.getAsJsonObject("result");
        check(result.get("protocolVersion").getAsString().equals("2025-03-26"));
        check(result.getAsJsonObject("serverInfo").get("name").getAsString().equals("sap-adt-eclipse"));
        check(result.getAsJsonObject("capabilities").has("tools"));
        // An unknown protocol version negotiates the latest one.
        Ctx other = pinned(9, DESKTOP_A);
        check(f.send(other, request(1, "initialize", "{\"protocolVersion\":\"1999-01-01\"}"), f.policy(ALL))
                .getAsJsonObject("result").get("protocolVersion").getAsString().equals("2025-11-25"));
        check(f.send(other, request(2, "initialize", "{}"), f.policy(ALL)).has("error"));

        List<String> names = names(f.send(a, request(2, "tools/list", "{}"), f.policy(ALL)));
        check(names.contains("sap_get_source") && names.contains("sap_set_source"));
        JsonObject call = f.send(a, request(3, "tools/call", "{\"name\":\"sap_get_source\",\"arguments\":" + TARGET + "}"),
                f.policy(ALL));
        check(!call.has("error") && resultText(call).contains("CLASS"));
        check(call.get("id").getAsInt() == 3);
        // A string id is echoed back.
        JsonObject withStringId = f.send(a, "{\"jsonrpc\":\"2.0\",\"id\":\"abc\",\"method\":\"ping\"}", f.policy(ALL));
        check(withStringId.get("id").getAsString().equals("abc") && withStringId.has("result"));
        // Schema validation is the shared one.
        check(code(f.send(a, request(4, "tools/call", "{\"name\":\"sap_get_source\",\"arguments\":{\"bogus\":1}}"),
                f.policy(ALL))) == -32602);
    }

    private static void callsBeforeInitializeAreRefused(ToolCatalog catalog) {
        Fixture f = new Fixture(catalog);
        Ctx a = pinned(1, DESKTOP_A);
        check(code(f.send(a, request(1, "tools/list", "{}"), f.policy(ALL))) == -32600);
        check(code(f.send(a, request(2, "tools/call", "{\"name\":\"sap_get_source\",\"arguments\":" + TARGET + "}"),
                f.policy(ALL))) == -32600);
        check(f.sap.paths.isEmpty());
        // ping needs no session, and a second stream starts uninitialized even for the same desktop.
        check(f.send(a, request(3, "ping", "{}"), f.policy(ALL)).has("result"));
        f.send(a, request(4, "initialize", "{\"protocolVersion\":\"2025-11-25\"}"), f.policy(ALL));
        check(!f.send(a, request(5, "tools/list", "{}"), f.policy(ALL)).has("error"));
        Ctx second = pinned(2, DESKTOP_A);
        check(code(f.send(second, request(1, "tools/list", "{}"), f.policy(ALL))) == -32600);
        // Closing a stream forgets its session.
        f.handler.closed(1);
        check(code(f.send(a, request(6, "tools/list", "{}"), f.policy(ALL))) == -32600);
    }

    private static void perDesktopRestrictionAppliesToItsFingerprintOnly(ToolCatalog catalog) {
        Fixture f = new Fixture(catalog);
        Ctx a = pinned(1, DESKTOP_A);
        Ctx b = pinned(2, DESKTOP_B);
        f.initialize(a);
        f.initialize(b);
        // Desktop B may only search; desktop A is unrestricted.
        f.backend.user.put(PermissionsModel.DESKTOP_PREFIX + DESKTOP_B + ".allowedTools", "sap_search_object");
        check(names(f.send(b, request(10, "tools/list", "{}"), f.policy(ALL))).equals(List.of("sap_search_object")));
        check(names(f.send(a, request(10, "tools/list", "{}"), f.policy(ALL))).contains("sap_get_source"));
        String read = "{\"name\":\"sap_get_source\",\"arguments\":" + TARGET + "}";
        JsonObject denied = f.send(b, request(11, "tools/call", read), f.policy(ALL));
        check(code(denied) == LOCAL);
        check(denied.getAsJsonObject("error").get("message").getAsString()
                .startsWith("Denied by this Eclipse's permissions: "));
        check(f.sap.paths.isEmpty());
        check(!f.send(a, request(11, "tools/call", read), f.policy(ALL)).has("error"));

        // Read-only for B only: a write is refused for B before any SAP call.
        f.backend.user.remove(PermissionsModel.DESKTOP_PREFIX + DESKTOP_B + ".allowedTools");
        f.backend.user.put(PermissionsModel.DESKTOP_PREFIX + DESKTOP_B + ".readOnly", "true");
        f.sap.paths.clear();
        String write = "{\"name\":\"sap_set_source\",\"arguments\":"
                + TARGET.substring(0, TARGET.length() - 1) + ",\"source\":\"test\"}}";
        check(code(f.send(b, request(12, "tools/call", write), f.policy(ALL))) == LOCAL);
        check(!names(f.send(b, request(13, "tools/list", "{}"), f.policy(ALL))).contains("sap_set_source"));
        check(names(f.send(a, request(13, "tools/list", "{}"), f.policy(ALL))).contains("sap_set_source"));
        check(f.sap.paths.isEmpty());

        // Package patterns for B intersect with the global ones and with the relay's scopes.
        f.backend.user.remove(PermissionsModel.DESKTOP_PREFIX + DESKTOP_B + ".readOnly");
        f.backend.user.put(PermissionsModel.DESKTOP_PREFIX + DESKTOP_B + ".packagePatterns", "Z*");
        f.sap.owner = "/NS/ZAPP";
        check(code(f.send(b, request(14, "tools/call", read), f.policy(ALL))) == LOCAL);
        check(!f.send(a, request(14, "tools/call", read), f.policy(ALL)).has("error"));
        // The global permissions apply to every desktop on top of its own.
        f.backend.user.put(PermissionsModel.KEY_READ_ONLY, "true");
        check(!names(f.send(a, request(15, "tools/list", "{}"), f.policy(ALL))).contains("sap_set_source"));
        // A fingerprint that is not 64 hex characters (malformed context) refuses everything.
        Ctx bad = new Ctx(3, "not-a-fingerprint", true, "", "x");
        f.initialize(bad);
        check(names(f.send(bad, request(16, "tools/list", "{}"), f.policy(ALL))).isEmpty());
    }

    private static void relayLayerStillApplies(ToolCatalog catalog) {
        Fixture f = new Fixture(catalog);
        Ctx a = pinned(1, DESKTOP_A);
        f.initialize(a);
        RelayPolicyView searchOnly = f.policy(List.of("sap_search_object"));
        check(names(f.send(a, request(20, "tools/list", "{}"), searchOnly)).equals(List.of("sap_search_object")));
        check(code(f.send(a, request(21, "tools/call", "{\"name\":\"sap_get_source\",\"arguments\":" + TARGET + "}"),
                searchOnly)) == RELAY);
        check(f.sap.paths.isEmpty());
        // Package scopes from the relay apply to the stream path as well.
        JsonArray scopes = JsonParser.parseString("[[\"/NS/*\"]]").getAsJsonArray();
        f.sap.owner = "/OTHER/PKG";
        check(code(f.send(a, request(22, "tools/call", "{\"name\":\"sap_get_source\",\"arguments\":" + TARGET + "}"),
                new RelayPolicyView(ALL, scopes))) == RELAY);
        f.sap.owner = "/NS/ZAPP";
        check(!f.send(a, request(23, "tools/call", "{\"name\":\"sap_get_source\",\"arguments\":" + TARGET + "}"),
                new RelayPolicyView(ALL, scopes)).has("error"));
        // A missing policy view fails closed.
        check(code(f.send(a, request(24, "tools/list", "{}"), null)) == -32602);
        check(code(f.send(a, request(25, "tools/call", "{\"name\":\"sap_get_source\",\"arguments\":" + TARGET + "}"),
                new RelayPolicyView(ALL, null))) == -32602);
    }

    private static void unpinnedPeerCanOnlyClaim(ToolCatalog catalog) {
        Fixture f = new Fixture(catalog);
        Ctx stranger = new Ctx(5, DESKTOP_B, false, "c".repeat(64), "Stranger");
        check(code(f.send(stranger, request(1, "initialize", "{\"protocolVersion\":\"2025-11-25\"}"), f.policy(ALL)))
                == StreamRequests.NOT_PAIRED);
        check(code(f.send(stranger, request(2, "tools/list", "{}"), f.policy(ALL))) == StreamRequests.NOT_PAIRED);
        check(code(f.send(stranger, request(3, "tools/call", "{\"name\":\"sap_get_source\",\"arguments\":" + TARGET + "}"),
                f.policy(ALL))) == StreamRequests.NOT_PAIRED);
        check(code(f.send(stranger, request(4, "ping", "{}"), f.policy(ALL))) == StreamRequests.NOT_PAIRED);
        check(f.sap.paths.isEmpty());
        // pair/claim with no link outstanding, with a wrong secret, and with no secret: one generic error.
        JsonObject none = f.send(stranger, request(5, "pair/claim", "{\"secret\":\"" + "0".repeat(64) + "\"}"), f.policy(ALL));
        check(code(none) == Pairing.REFUSED_CODE
                && none.getAsJsonObject("error").get("message").getAsString().equals("Pairing refused."));
        String secret = f.mintSecret();
        JsonObject wrong = f.send(stranger, request(6, "pair/claim", "{\"secret\":\"" + "1".repeat(64) + "\"}"), f.policy(ALL));
        check(wrong.toString().equals(none.toString().replace("\"id\":5", "\"id\":6")));
        check(code(f.send(stranger, request(7, "pair/claim", "{}"), f.policy(ALL))) == Pairing.REFUSED_CODE);
        // The right secret, confirmed, pairs.
        JsonObject ok = f.send(stranger, request(8, "pair/claim", "{\"secret\":\"" + secret + "\"}"), f.policy(ALL));
        check(ok.getAsJsonObject("result").get("paired").getAsBoolean());
        check(f.pins.size() == 1 && f.pins.get(0).equals(DESKTOP_B + "|" + "c".repeat(64) + "|Stranger"));
        // The secret is single use.
        check(code(f.send(stranger, request(9, "pair/claim", "{\"secret\":\"" + secret + "\"}"), f.policy(ALL)))
                == Pairing.REFUSED_CODE);
        for (String line : f.log) check(!line.contains(secret));
    }

    private static void notificationsAndUnknownMethods(ToolCatalog catalog) {
        Fixture f = new Fixture(catalog);
        Ctx a = pinned(1, DESKTOP_A);
        check(f.handler.handle(a, json("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}"), f.policy(ALL)) == null);
        check(f.handler.handle(a, json("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{}}"),
                f.policy(ALL)) == null);
        check(code(f.send(a, request(1, "resources/list", "{}"), f.policy(ALL))) == -32601);
        check(code(f.send(a, "{\"jsonrpc\":\"1.0\",\"id\":2,\"method\":\"ping\"}", f.policy(ALL))) == -32600);
        check(code(f.send(a, "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\",\"params\":[]}", f.policy(ALL))) == -32602);
        check(code(f.send(a, "{\"jsonrpc\":\"2.0\",\"id\":{},\"method\":\"ping\"}", f.policy(ALL))) == -32600);
        // The relay/hello bridge method does not exist on a stream.
        check(code(f.send(a, request(4, "relay/hello", "{}"), f.policy(ALL))) == -32601);
    }

    private static final class Fixture {
        final FakeSap sap = new FakeSap();
        final MapBackend backend = new MapBackend();
        final List<String> pins = new ArrayList<>();
        final List<String> log = new ArrayList<>();
        final StreamRequests handler;
        private final Pairing pairing;
        private byte[] fingerprint = new byte[32];

        Fixture(ToolCatalog catalog) {
            PermissionsModel model = new PermissionsModel(backend);
            ToolExecutor executor = new ToolExecutor(List.of(new SearchObjectTool(sap), new GetSourceTool(sap),
                    new ObjectStructureTool(sap), new LockTool(sap), new UnlockTool(sap), new SqlQueryTool(sap),
                    new SetSourceTool(sap), new CreateObjectTool(sap), new ActivateTool(sap)), sap, catalog);
            for (int i = 0; i < fingerprint.length; i++) fingerprint[i] = (byte) (i + 1);
            pairing = new Pairing("d".repeat(64), "Test Eclipse", () -> fingerprint,
                    (key, relay, label) -> pins.add(key + "|" + relay + "|" + label),
                    (label, shortFingerprint) -> CompletableFuture.completedFuture(true), log::add);
            handler = new StreamRequests(executor, pairing, model::effectiveFor, "test");
        }

        RelayPolicyView policy(List<String> allowed) {
            return new RelayPolicyView(allowed, new JsonArray());
        }

        JsonObject send(StreamContext context, String message, RelayPolicyView policy) {
            String reply = handler.handle(context, json(message), policy);
            check(reply != null);
            return json(reply);
        }

        void initialize(StreamContext context) {
            check(!send(context, request(1, "initialize", "{\"protocolVersion\":\"2025-11-25\"}"), policy(ALL)).has("error"));
        }

        /** Mints a link and returns its secret as 64 hex characters. */
        String mintSecret() {
            try {
                RelayLink link = RelayLink.parse(pairing.mint());
                byte[] payload = RelayLink.decodeToken(new String(link.token()));
                StringBuilder hex = new StringBuilder();
                for (int i = 0; i < 32; i++) hex.append(String.format("%02x", payload[i] & 0xFF));
                return hex.toString();
            } catch (RelayLink.LinkException e) {
                throw new AssertionError("The minted link did not parse.", e);
            }
        }
    }

    private static Ctx pinned(int stream, String fingerprint) {
        return new Ctx(stream, fingerprint, true, "e".repeat(64), "Desktop");
    }

    private static String request(int id, String method, String params) {
        return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"method\":\"" + method + "\",\"params\":" + params + "}";
    }

    private static List<String> names(JsonObject listReply) {
        check(!listReply.has("error"));
        List<String> names = new ArrayList<>();
        listReply.getAsJsonObject("result").getAsJsonArray("tools")
                .forEach(tool -> names.add(tool.getAsJsonObject().get("name").getAsString()));
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
        if (!condition) throw new AssertionError("Stream requests regression.");
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
            throw new AssertionError("Unexpected delete in stream regression.");
        }

        @Override
        public HttpResponse<String> get(String path, String accept) {
            paths.add(path);
            if (path.startsWith("/sap/bc/adt/repository/informationsystem/search?")) {
                String ref = "<a:objectReference a:name='CL_DEMO' a:type='CLAS/OC' a:uri='" + URI + "' a:packageName='/NS/ZAPP'/>";
                return response("<a:objectReferences xmlns:a='" + CORE + "'>" + ref + "</a:objectReferences>");
            }
            if (path.equals(URI + "/source/main")) return response("CLASS /NS/CL_DEMO.");
            check(path.equals(URI));
            return response("<c:abapClass xmlns:c='http://www.sap.com/adt/oo/classes' xmlns:a='" + CORE
                    + "' a:name='/NS/CL_DEMO' a:type='CLAS/OC' a:uri='" + URI + "'><a:packageRef a:name='" + owner
                    + "'/></c:abapClass>");
        }

        @Override
        public HttpResponse<String> postWithHeaders(String path, String body, String type, String accept, Map<String, String> headers) {
            throw new AssertionError("Unexpected post in stream regression.");
        }

        @Override
        public HttpResponse<String> putWithHeaders(String path, String body, String type, Map<String, String> headers) {
            throw new AssertionError("Unexpected write in stream regression.");
        }

        @Override
        public HttpResponse<String> post(String path, String body, String type, String accept) {
            throw new AssertionError("Unexpected post in stream regression.");
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
