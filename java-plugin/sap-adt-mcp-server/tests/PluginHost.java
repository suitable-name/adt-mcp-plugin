package com.sap.adt.mcp.server;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLSession;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sap.adt.mcp.sap.AdtRestClient;
import com.sap.adt.mcp.server.e2e.InnerKeys;
import com.sap.adt.mcp.server.e2e.Pairing;
import com.sap.adt.mcp.server.e2e.PinStorage;
import com.sap.adt.mcp.server.e2e.PinStore;
import com.sap.adt.mcp.server.e2e.StreamRequests;
import com.sap.adt.mcp.tools.GetSourceTool;
import com.sap.adt.mcp.tools.McpTool;
import com.sap.adt.mcp.tools.SetSourceTool;
import com.sap.adt.mcp.tools.ToolClass;

/**
 * A headless Eclipse plugin for the end-to-end test: the real {@link RelayBridge}, the real stream handler and the
 * real pairing, with in-memory keys and pins and a fake SAP client. No Eclipse is needed.
 *
 * <p>Arguments: the profile JSON file (what {@link RelayIdentity#fromProfile} reads) and
 * {@code allowUnencrypted=true|false}. Standard input: {@code pair} prints {@code PAIR <link>}, {@code quit}
 * exits. Every other line of standard output is one JSON event. Only the {@code PAIR} line carries a secret.</p>
 */
public final class PluginHost {
    /** What the fake SAP answers for a source read; the test looks for it. */
    static final String RESULT = "REAL-E2E-RESULT-a9c4";
    private static final Object OUT = new Object();

    private PluginHost() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2 || !args[1].startsWith("allowUnencrypted=")) {
            System.err.println("Usage: PluginHost <profile.json> allowUnencrypted=true|false");
            System.exit(2);
        }
        boolean allowUnencrypted = Boolean.parseBoolean(args[1].substring("allowUnencrypted=".length()));
        JsonObject profile = JsonParser.parseString(Files.readString(Path.of(args[0]), StandardCharsets.UTF_8))
                .getAsJsonObject();
        RelayIdentity identity = RelayIdentity.fromProfile(profile);

        InnerKeys keys = InnerKeys.generate();
        PinStore pins = new PinStore(new MemoryPins());
        E2eServices.setInnerKeys(keys);
        E2eServices.setPinStore(pins);
        LocalPolicySource.install(LocalPolicy::unrestricted);
        LegacyCalls.install(() -> allowUnencrypted);
        LegacyCalls.onRefusal(line -> event("legacyRefused", null, null));
        PolicyDenials.addListener(PluginHost::onLine);

        FakeSap sap = new FakeSap();
        List<McpTool> tools = List.of(new Recording(new GetSourceTool(sap)), new Recording(new SetSourceTool(sap)));
        Pairing pairing = new Pairing(identity.relayFingerprint(), identity.label(), keys::fingerprintBytes, pins::add,
                (label, shortFingerprint) -> CompletableFuture.completedFuture(true), PluginHost::onLine);
        E2eServices.setHandler(new StreamRequests(new ToolExecutor(tools, sap), pairing,
                fingerprint -> LocalPolicy.unrestricted(), "plugin-host"));
        E2eServices.setPairingGate(pairing);

        RelayBridge bridge = new RelayBridge(identity, tools, sap, reason -> event("bridgeClosed", "reason", reason));
        try {
            bridge.connect().get(30, TimeUnit.SECONDS);
        } catch (Exception e) {
            event("error", "message", "The bridge did not connect.");
            System.exit(2);
        }
        event("connected", null, null);

        BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line;
        while ((line = input.readLine()) != null) {
            String command = line.strip();
            if (command.equals("quit")) {
                break;
            }
            if (command.equals("pair")) {
                String link = pairing.mint();
                synchronized (OUT) {
                    System.out.println("PAIR " + link);
                    System.out.flush();
                }
            }
        }
        bridge.close();
        System.exit(0);
    }

    /** One JSON line; {@code key} and {@code value} may be null. */
    private static void event(String name, String key, String value) {
        JsonObject event = new JsonObject();
        event.addProperty("event", name);
        if (key != null) {
            event.addProperty(key, value);
        }
        print(event);
    }

    private static void print(JsonObject event) {
        synchronized (OUT) {
            System.out.println(event);
            System.out.flush();
        }
    }

    /** Local log lines of the tunnel and of pairing. They never hold a secret. */
    private static void onLine(String line) {
        boolean closed = line.startsWith("Binding failure") || line.startsWith("Closed stream");
        event(closed ? "streamClosed" : "log", closed ? "reason" : "line", line);
    }

    /** Reports every executed SAP tool, then runs it. */
    private static final class Recording implements McpTool {
        private final McpTool inner;

        Recording(McpTool inner) {
            this.inner = inner;
        }

        @Override
        public String getName() {
            return inner.getName();
        }

        @Override
        public ToolClass toolClass() {
            return inner.toolClass();
        }

        @Override
        public String getDescription() {
            return inner.getDescription();
        }

        @Override
        public JsonObject getInputSchema() {
            return inner.getInputSchema();
        }

        @Override
        public String execute(JsonObject arguments) throws Exception {
            JsonObject event = new JsonObject();
            event.addProperty("event", "sap");
            event.addProperty("tool", inner.getName());
            event.add("args", arguments.deepCopy());
            print(event);
            return inner.execute(arguments);
        }
    }

    private static final class MemoryPins implements PinStorage {
        private byte[] blob;

        @Override
        public synchronized byte[] read() {
            return blob == null ? null : blob.clone();
        }

        @Override
        public synchronized void write(byte[] value) {
            blob = value.clone();
        }
    }

    /** Serves every source read with {@link #RESULT} and reports each HTTP call. Writes are not available. */
    private static final class FakeSap extends AdtRestClient {
        @Override
        public void login() {
        }

        @Override
        public boolean isLoggedIn() {
            return true;
        }

        @Override
        public String getUsername() {
            return "PLUGINHOST";
        }

        private static void report(String method, String path) {
            JsonObject event = new JsonObject();
            event.addProperty("event", "sapHttp");
            event.addProperty("method", method);
            event.addProperty("path", path);
            print(event);
        }

        @Override
        public HttpResponse<String> get(String path, String accept) {
            report("GET", path);
            return new Reply("REPORT Z_E2E. \" " + RESULT);
        }

        @Override
        public HttpResponse<String> delete(String path) {
            report("DELETE", path);
            throw new UnsupportedOperationException("The fake SAP is read-only.");
        }

        @Override
        public HttpResponse<String> postWithHeaders(String path, String body, String type, String accept,
                Map<String, String> headers) {
            report("POST", path);
            throw new UnsupportedOperationException("The fake SAP is read-only.");
        }

        @Override
        public HttpResponse<String> putWithHeaders(String path, String body, String type,
                Map<String, String> headers) {
            report("PUT", path);
            throw new UnsupportedOperationException("The fake SAP is read-only.");
        }
    }

    private record Reply(String body) implements HttpResponse<String> {
        @Override
        public int statusCode() {
            return 200;
        }

        @Override
        public HttpRequest request() {
            throw new UnsupportedOperationException();
        }

        @Override
        public HttpHeaders headers() {
            return HttpHeaders.of(Map.of(), (name, value) -> true);
        }

        @Override
        public URI uri() {
            return URI.create("https://unused.invalid");
        }

        @Override
        public HttpClient.Version version() {
            return HttpClient.Version.HTTP_1_1;
        }

        @Override
        public Optional<SSLSession> sslSession() {
            return Optional.empty();
        }

        @Override
        public Optional<HttpResponse<String>> previousResponse() {
            return Optional.empty();
        }
    }
}
