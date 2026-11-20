package com.sap.adt.mcp.server.e2e;

import java.io.ByteArrayOutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sap.adt.mcp.server.e2e.InnerChannel.ChannelException;
import com.sap.adt.mcp.server.e2e.TunnelProtocol.Envelope;
import com.sap.adt.mcp.tools.ToolCatalog;
import com.sap.adt.mcp.tools.ToolClass;

/**
 * Regression harness for {@link InnerChannel} and {@link RelayStreams}. A JDK {@code SSLEngine} client (TLS 1.3,
 * its own key) talks to the plugin side, first directly and then through the stream table with relay-forwarded
 * envelopes. Run from the checkout root (the shared tool table is read from the source tree; override with
 * {@code -Dtools.json=<path>}).
 */
public final class InnerChannelRegression {
    private static final String RELAY_FP = "ab".repeat(32);

    public static void main(String[] args) throws Exception {
        pinnedKeyIsAccepted();
        unpinnedKeyIsRefused();
        pairingGateAdmitsUnknownKeys();
        weakerSuiteIsRefused();
        oversizedMessageClosesTheChannel();
        streamsServeRequestsAndClassifyStatus();
        envelopeMismatchesCloseTheStream();
        unpairedStreamsMayOnlyClaim();
        streamLimitsAndCleanup();
        System.out.println("InnerChannelRegression passed.");
    }

    // ------------------------------------------------------------------ InnerChannel alone

    private static void pinnedKeyIsAccepted() throws Exception {
        InnerKeys server = InnerKeys.generate();
        InnerKeys clientKeys = InnerKeys.generate();
        PinStore pins = pins();
        pins.add(clientKeys.fingerprint(), RELAY_FP, "Laptop");
        InnerChannel channel = new InnerChannel(server, pins, () -> false);
        Client client = new Client(clientKeys, server.fingerprint(), InnerChannel.CIPHER_SUITE);
        handshake(channel, client);
        check(channel.handshakeComplete() && channel.peerPinned());
        check(clientKeys.fingerprint().equals(channel.peerKeyFingerprint()));
        check(InnerChannel.PROTOCOL.equals(client.engine.getSession().getProtocol()));
        check(InnerChannel.CIPHER_SUITE.equals(client.engine.getSession().getCipherSuite()));

        // A message each way, with length prefixes.
        byte[] request = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}".getBytes(StandardCharsets.UTF_8);
        List<byte[]> received = feed(channel, client.seal(TunnelProtocol.frameMessage(request, 1 << 20)));
        check(received.size() == 1 && Arrays.equals(received.get(0), request));
        byte[] response = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}".getBytes(StandardCharsets.UTF_8);
        byte[] sealed = channel.seal(response);
        client.exchange(channel.takeOutgoing());
        client.exchange(sealed);
        TunnelProtocol.MessageReader reader = new TunnelProtocol.MessageReader();
        reader.push(client.plain());
        check(Arrays.equals(reader.nextMessage(1 << 20), response));
        // Two messages in one burst, split across feeds.
        byte[] both = concat(TunnelProtocol.frameMessage(request, 1 << 20), TunnelProtocol.frameMessage(response, 1 << 20));
        List<byte[]> two = new ArrayList<>();
        byte[] cipher = client.seal(both);
        for (int i = 0; i < cipher.length; i += 7) {
            two.addAll(channel.feed(Arrays.copyOfRange(cipher, i, Math.min(cipher.length, i + 7))));
        }
        check(two.size() == 2);
    }

    private static void unpinnedKeyIsRefused() throws Exception {
        InnerKeys server = InnerKeys.generate();
        InnerKeys clientKeys = InnerKeys.generate();
        InnerKeys other = InnerKeys.generate();
        PinStore pins = pins();
        pins.add(other.fingerprint(), RELAY_FP, "Other");
        InnerChannel channel = new InnerChannel(server, pins, () -> false);
        Client client = new Client(clientKeys, server.fingerprint(), InnerChannel.CIPHER_SUITE);
        try {
            handshake(channel, client);
            throw new AssertionError("An unpinned key was accepted.");
        } catch (ChannelException expected) {
            check(!channel.handshakeComplete() && channel.peerKeyFingerprint() == null);
        }
    }

    private static void pairingGateAdmitsUnknownKeys() throws Exception {
        InnerKeys server = InnerKeys.generate();
        InnerKeys clientKeys = InnerKeys.generate();
        AtomicBoolean open = new AtomicBoolean(true);
        InnerChannel channel = new InnerChannel(server, pins(), open::get);
        Client client = new Client(clientKeys, server.fingerprint(), InnerChannel.CIPHER_SUITE);
        handshake(channel, client);
        check(channel.handshakeComplete() && !channel.peerPinned());
        check(clientKeys.fingerprint().equals(channel.peerKeyFingerprint()));
        // Closed gate: the same key is refused again.
        open.set(false);
        InnerChannel late = new InnerChannel(server, pins(), open::get);
        try {
            handshake(late, new Client(clientKeys, server.fingerprint(), InnerChannel.CIPHER_SUITE));
            throw new AssertionError("The closed gate admitted a key.");
        } catch (ChannelException expected) {
            check(!late.handshakeComplete());
        }
    }

    private static void weakerSuiteIsRefused() throws Exception {
        InnerKeys server = InnerKeys.generate();
        InnerKeys clientKeys = InnerKeys.generate();
        PinStore pins = pins();
        pins.add(clientKeys.fingerprint(), RELAY_FP, "Laptop");
        InnerChannel channel = new InnerChannel(server, pins, () -> false);
        try {
            handshake(channel, new Client(clientKeys, server.fingerprint(), "TLS_AES_128_GCM_SHA256"));
            throw new AssertionError("Another cipher suite was negotiated.");
        } catch (ChannelException expected) {
            check(!channel.handshakeComplete());
        }
    }

    private static void oversizedMessageClosesTheChannel() throws Exception {
        InnerKeys server = InnerKeys.generate();
        InnerKeys clientKeys = InnerKeys.generate();
        PinStore pins = pins();
        pins.add(clientKeys.fingerprint(), RELAY_FP, "Laptop");
        InnerChannel channel = new InnerChannel(server, pins, () -> false);
        Client client = new Client(clientKeys, server.fingerprint(), InnerChannel.CIPHER_SUITE);
        handshake(channel, client);
        byte[] prefix = {0, 0x50, 0, 0}; // 5 MiB, above the 4 MiB request limit
        try {
            channel.feed(client.seal(prefix));
            throw new AssertionError("An oversized message was accepted.");
        } catch (ChannelException expected) {
            check(channel.isClosed());
        }
    }

    // ------------------------------------------------------------------ RelayStreams

    private static void streamsServeRequestsAndClassifyStatus() throws Exception {
        Fixture fixture = new Fixture();
        InnerKeys clientKeys = InnerKeys.generate();
        fixture.pins.add(clientKeys.fingerprint(), RELAY_FP, "Laptop");
        Session session = fixture.open(1, RELAY_FP, "Laptop", clientKeys);
        check(session.established());
        check(fixture.streams.streamCount() == 1);

        JsonObject list = session.call(1, "tools/list", null, null, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}");
        check(list.get("result") != null);
        check(session.lastStatus().equals("ok"));
        check(fixture.lastContext.peerPinned() && RELAY_FP.equals(fixture.lastContext.assertedDesktopFingerprint())
                && "Laptop".equals(fixture.lastContext.assertedLabel())
                && clientKeys.fingerprint().equals(fixture.lastContext.peerKeyFingerprint()));

        fixture.reply = "{\"jsonrpc\":\"2.0\",\"id\":2,\"error\":{\"code\":-32001,\"message\":\"no\"}}";
        session.call(2, "tools/call", "sap_get_source", ToolClass.READ,
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"sap_get_source\",\"arguments\":{}}}");
        check(session.lastStatus().equals("denied"));
        check(fixture.lastPolicy.allowedTools().equals(List.of("sap_get_source")));
        check(session.lastResponseSeq == 2);

        fixture.reply = "{\"jsonrpc\":\"2.0\",\"id\":3,\"error\":{\"code\":-32602,\"message\":\"bad\"}}";
        session.call(3, "tools/call", "sap_set_source", ToolClass.WRITE,
                "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"sap_set_source\"}}");
        check(session.lastStatus().equals("error"));

        int before = fixture.handled;
        session.notify(4, "notifications/initialized", "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}");
        check(fixture.handled == before + 1 && fixture.streams.streamCount() == 1);
        check(session.responsesBeforeNotificationOk());

        // The relay's close frame ends the stream and tells the handler.
        fixture.streams.onControl("{\"type\":\"close\",\"stream\":1,\"reason\":\"done\"}");
        check(fixture.streams.streamCount() == 0 && fixture.closedStreams.contains(1));
    }

    private static void envelopeMismatchesCloseTheStream() throws Exception {
        // Tool differs.
        Fixture fixture = new Fixture();
        InnerKeys clientKeys = InnerKeys.generate();
        fixture.pins.add(clientKeys.fingerprint(), RELAY_FP, "Laptop");
        Session session = fixture.open(1, RELAY_FP, "Laptop", clientKeys);
        session.send(1, Envelope.of(1, "tools/call", "sap_get_source", ToolClass.READ),
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"sap_set_source\"}}", true);
        check(fixture.handled == 0 && fixture.streams.streamCount() == 0);
        check(session.lastStatus().equals("denied") && session.sawClose());
        check(session.lastPlain.contains("-32003"));

        // Class differs.
        fixture = new Fixture();
        fixture.pins.add(clientKeys.fingerprint(), RELAY_FP, "Laptop");
        session = fixture.open(1, RELAY_FP, "Laptop", clientKeys);
        session.send(1, Envelope.of(1, "tools/call", "sap_set_source", ToolClass.READ),
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"sap_set_source\"}}", true);
        check(fixture.handled == 0 && fixture.streams.streamCount() == 0);

        // Method differs.
        fixture = new Fixture();
        fixture.pins.add(clientKeys.fingerprint(), RELAY_FP, "Laptop");
        session = fixture.open(1, RELAY_FP, "Laptop", clientKeys);
        session.send(1, Envelope.of(1, "ping"), "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}", true);
        check(fixture.handled == 0 && fixture.streams.streamCount() == 0);

        // Wrong seq: the first message must carry seq 1.
        fixture = new Fixture();
        fixture.pins.add(clientKeys.fingerprint(), RELAY_FP, "Laptop");
        session = fixture.open(1, RELAY_FP, "Laptop", clientKeys);
        session.send(1, Envelope.of(5, "tools/list"), "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}", true);
        check(fixture.handled == 0 && fixture.streams.streamCount() == 0);

        // A seq that skips after a good request.
        fixture = new Fixture();
        fixture.pins.add(clientKeys.fingerprint(), RELAY_FP, "Laptop");
        session = fixture.open(1, RELAY_FP, "Laptop", clientKeys);
        session.call(1, "tools/list", null, null, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}");
        check(fixture.handled == 1);
        session.send(1, Envelope.of(3, "tools/list"), "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}", true);
        check(fixture.handled == 1 && fixture.streams.streamCount() == 0);

        // A message nobody announced.
        fixture = new Fixture();
        fixture.pins.add(clientKeys.fingerprint(), RELAY_FP, "Laptop");
        session = fixture.open(1, RELAY_FP, "Laptop", clientKeys);
        session.send(1, null, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}", true);
        check(fixture.handled == 0 && fixture.streams.streamCount() == 0 && session.sawClose());

        // An announced envelope for an unknown tool cannot be derived.
        fixture = new Fixture();
        fixture.pins.add(clientKeys.fingerprint(), RELAY_FP, "Laptop");
        session = fixture.open(1, RELAY_FP, "Laptop", clientKeys);
        session.send(1, Envelope.of(1, "tools/call", "sap_nothing", ToolClass.READ),
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"sap_nothing\"}}", true);
        check(fixture.handled == 0 && fixture.streams.streamCount() == 0);

        // Same desktop key under another relay identity: pair again.
        fixture = new Fixture();
        fixture.pins.add(clientKeys.fingerprint(), RELAY_FP, "Laptop");
        session = fixture.open(1, "cd".repeat(32), "Laptop", clientKeys);
        check(fixture.streams.streamCount() == 0 && session.closeReason().equals("pair again"));
    }

    private static void unpairedStreamsMayOnlyClaim() throws Exception {
        Fixture fixture = new Fixture();
        fixture.gateOpen.set(true);
        InnerKeys clientKeys = InnerKeys.generate();
        Session session = fixture.open(1, RELAY_FP, "Laptop", clientKeys);
        check(session.established());
        check(fixture.streams.streamCount() == 1);
        fixture.reply = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"paired\":false}}";
        session.call(1, "pair/claim", null, null,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"pair/claim\",\"params\":{}}");
        check(fixture.handled == 1 && !fixture.lastContext.peerPinned());
        check(fixture.streams.streamCount() == 1);
        session.send(2, Envelope.of(2, "tools/list"), "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}", true);
        check(fixture.handled == 1 && fixture.streams.streamCount() == 0 && session.lastPlain.contains("-32002"));

        // With the gate shut and no pin the handshake itself fails and the stream closes.
        fixture = new Fixture();
        session = fixture.open(1, RELAY_FP, "Laptop", clientKeys);
        check(!session.established() && fixture.streams.streamCount() == 0 && session.sawClose());
    }

    private static void streamLimitsAndCleanup() throws Exception {
        Fixture fixture = new Fixture();
        for (int i = 1; i <= TunnelProtocol.MAX_STREAMS_PER_DESKTOP; i++) {
            fixture.streams.onControl(TunnelProtocol.encode(TunnelProtocol.open(i, "aa", RELAY_FP, "L")));
        }
        check(fixture.streams.streamCount() == TunnelProtocol.MAX_STREAMS_PER_DESKTOP);
        fixture.clear();
        fixture.streams.onControl(TunnelProtocol.encode(TunnelProtocol.open(99, "aa", RELAY_FP, "L")));
        check(fixture.streams.streamCount() == TunnelProtocol.MAX_STREAMS_PER_DESKTOP);
        check(fixture.texts.size() == 1 && fixture.texts.get(0).contains("\"type\":\"close\""));
        // Other desktops still have room, up to the bridge limit.
        for (int i = 0; fixture.streams.streamCount() < TunnelProtocol.MAX_STREAMS_PER_BRIDGE; i++) {
            fixture.streams.onControl(TunnelProtocol.encode(
                    TunnelProtocol.open(1000 + i, "aa", String.format("%064x", i + 1), "L")));
        }
        check(fixture.streams.streamCount() == TunnelProtocol.MAX_STREAMS_PER_BRIDGE);
        fixture.clear();
        fixture.streams.onControl(TunnelProtocol.encode(TunnelProtocol.open(5000, "aa", "ff".repeat(32), "L")));
        check(fixture.streams.streamCount() == TunnelProtocol.MAX_STREAMS_PER_BRIDGE && fixture.texts.size() == 1);
        // Closing the bridge ends everything and tells the handler.
        fixture.clear();
        fixture.streams.closeAll();
        check(fixture.streams.streamCount() == 0 && fixture.texts.isEmpty());
        check(fixture.closedStreams.size() == TunnelProtocol.MAX_STREAMS_PER_BRIDGE);

        // No handler: the open is refused.
        Fixture none = new Fixture();
        none.handlerPresent = false;
        none.streams.onControl(TunnelProtocol.encode(TunnelProtocol.open(1, "aa", RELAY_FP, "L")));
        check(none.streams.streamCount() == 0 && none.texts.size() == 1 && none.texts.get(0).contains("\"close\""));
        fixture.scheduler.shutdownNow();
        none.scheduler.shutdownNow();
    }

    // ------------------------------------------------------------------ fixtures

    private static final class Memory implements PinStorage {
        byte[] blob;

        @Override
        public byte[] read() {
            return blob;
        }

        @Override
        public void write(byte[] data) {
            blob = data.clone();
        }
    }

    private static PinStore pins() {
        return new PinStore(new Memory());
    }

    /** The plugin side of a bridge: stream table, recording transport, scripted handler. */
    private static final class Fixture {
        final InnerKeys server;
        final PinStore pins = pins();
        final AtomicBoolean gateOpen = new AtomicBoolean(false);
        final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task);
            thread.setDaemon(true);
            return thread;
        });
        final List<String> texts = new ArrayList<>();
        final List<byte[]> binaries = new ArrayList<>();
        final List<Integer> closedStreams = new ArrayList<>();
        final RelayStreams streams;
        volatile String reply = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
        volatile boolean handlerPresent = true;
        int handled;
        StreamContext lastContext;
        RelayPolicyView lastPolicy;

        Fixture() throws Exception {
            server = InnerKeys.generate();
            StreamHandler handler = new StreamHandler() {
                @Override
                public String handle(StreamContext context, JsonObject message, RelayPolicyView policy) {
                    handled++;
                    lastContext = context;
                    lastPolicy = policy;
                    return message.has("id") ? reply : null;
                }

                @Override
                public void closed(int streamId) {
                    closedStreams.add(streamId);
                }
            };
            RelayStreams.Transport transport = new RelayStreams.Transport() {
                @Override
                public void sendText(String text) {
                    texts.add(text);
                }

                @Override
                public void sendBinary(byte[] frame) {
                    binaries.add(frame);
                }
            };
            ToolCatalog catalog;
            String path = System.getProperty("tools.json",
                    "java-plugin/sap-adt-mcp-server/com.sap.adt.mcp.server.plugin/resources/tools.json");
            try (java.io.Reader reader = java.nio.file.Files.newBufferedReader(java.nio.file.Path.of(path))) {
                catalog = ToolCatalog.load(reader);
            }
            // The same-thread executor makes handler calls synchronous and the test deterministic.
            streams = new RelayStreams(() -> server, pins, () -> handlerPresent ? handler : null, gateOpen::get,
                    catalog, transport, Runnable::run, scheduler, line -> { });
        }

        void clear() {
            texts.clear();
            binaries.clear();
        }

        Session open(int id, String desktop, String label, InnerKeys clientKeys) throws Exception {
            clear();
            streams.onControl(TunnelProtocol.encode(TunnelProtocol.open(id, "aa", desktop, label)));
            Session session = new Session(this, id, new Client(clientKeys, server.fingerprint(), InnerChannel.CIPHER_SUITE));
            session.handshake();
            return session;
        }
    }

    /** A client stream: its TLS engine plus the relay-side framing of control and data frames. */
    private static final class Session {
        final Fixture fixture;
        final int id;
        final Client client;
        String lastPlain = "";
        long lastResponseSeq;
        private int textsSeen;
        private int binariesSeen;
        private boolean established;
        private String lastStatus = "";
        private final TunnelProtocol.MessageReader reader = new TunnelProtocol.MessageReader();
        private int responses;

        Session(Fixture fixture, int id, Client client) {
            this.fixture = fixture;
            this.id = id;
            this.client = client;
        }

        boolean established() {
            return established;
        }

        void handshake() throws Exception {
            try {
                byte[] toServer = client.exchange(new byte[0]);
                for (int i = 0; i < 20 && fixture.streams.streamCount() > 0; i++) {
                    if (toServer.length > 0) {
                        for (byte[] frame : TunnelProtocol.encodeDataChunks(id, toServer)) {
                            fixture.streams.onData(frame);
                        }
                    }
                    toServer = client.exchange(drainData());
                    if (client.done && toServer.length == 0) {
                        break;
                    }
                }
            } catch (javax.net.ssl.SSLException refused) {
                // TLS 1.3: the client finishes first and only then reads the plugin's alert
                // (for example certificate_unknown for a key that is not pinned).
                established = false;
                return;
            }
            established = client.done && fixture.streams.streamCount() > 0;
        }

        /** Ciphertext the plugin sent on this stream since the last call. */
        private byte[] drainData() throws Exception {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (; binariesSeen < fixture.binaries.size(); binariesSeen++) {
                out.write(TunnelProtocol.decodeData(fixture.binaries.get(binariesSeen)).payload());
            }
            return out.toByteArray();
        }

        /** Announces {@code envelope} (unless null), sends the encrypted message, and collects the answer. */
        void send(long seq, Envelope envelope, String json, boolean ignored) throws Exception {
            fixture.streams.onControl(requestFrame(envelope, 100));
            byte[] cipher = client.seal(TunnelProtocol.frameMessage(json.getBytes(StandardCharsets.UTF_8), 1 << 20));
            for (byte[] frame : TunnelProtocol.encodeDataChunks(id, cipher)) {
                fixture.streams.onData(frame);
            }
            collect();
        }

        private String requestFrame(Envelope envelope, int len) {
            if (envelope == null) {
                return "{\"type\":\"close\",\"stream\":" + (id + 100000) + ",\"reason\":\"noop\"}";
            }
            JsonObject control = new JsonObject();
            control.addProperty("type", "request");
            control.addProperty("stream", id);
            control.add("envelope", envelope.toJson());
            JsonObject policy = new JsonObject();
            policy.add("allowedTools", JsonParser.parseString("[\"sap_get_source\"]"));
            policy.add("packageScopes", JsonParser.parseString("[]"));
            control.add("policy", policy);
            control.addProperty("len", len);
            return control.toString();
        }

        /** A request that is announced correctly; returns the decrypted JSON-RPC response. */
        JsonObject call(long seq, String method, String tool, ToolClass toolClass, String json) throws Exception {
            send(seq, Envelope.of(seq, method, tool, toolClass), json, false);
            check(lastPlain.length() > 0);
            return JsonParser.parseString(lastPlain).getAsJsonObject();
        }

        void notify(long seq, String method, String json) throws Exception {
            responses = 0;
            send(seq, Envelope.of(seq, method), json, false);
        }

        boolean responsesBeforeNotificationOk() {
            return responses == 0;
        }

        /** Reads what the plugin sent since the last call: response control frames, then their ciphertext. */
        private void collect() throws Exception {
            for (; textsSeen < fixture.texts.size(); textsSeen++) {
                JsonObject control = JsonParser.parseString(fixture.texts.get(textsSeen)).getAsJsonObject();
                String type = control.get("type").getAsString();
                if (type.equals("response")) {
                    lastStatus = control.get("status").getAsString();
                    lastResponseSeq = control.get("seq").getAsLong();
                    responses++;
                }
            }
            byte[] data = drainData();
            if (data.length > 0) {
                client.exchange(data);
                reader.push(client.plain());
                byte[] message = reader.nextMessage(TunnelProtocol.MAX_RESPONSE_BYTES);
                if (message != null) {
                    lastPlain = new String(message, StandardCharsets.UTF_8);
                }
            }
        }

        String lastStatus() {
            return lastStatus;
        }

        boolean sawClose() {
            return closeReason() != null;
        }

        String closeReason() {
            for (int i = fixture.texts.size() - 1; i >= 0; i--) {
                JsonElement parsed = JsonParser.parseString(fixture.texts.get(i));
                JsonObject control = parsed.getAsJsonObject();
                if (control.get("type").getAsString().equals("close")) {
                    return control.get("reason").getAsString();
                }
            }
            return null;
        }
    }

    /** A JDK TLS 1.3 client engine with its own key, trusting only the plugin's pinned key. */
    private static final class Client {
        final SSLEngine engine;
        boolean done;
        private ByteBuffer netIn = ByteBuffer.allocate(1 << 17);
        private final ByteArrayOutputStream plain = new ByteArrayOutputStream();
        private boolean started;

        Client(InnerKeys keys, String serverFingerprint, String suite) throws Exception {
            SSLContext context = SSLContext.getInstance("TLSv1.3");
            context.init(new KeyManager[] {new ClientKey(keys)},
                    new TrustManager[] {new PinServer(serverFingerprint)}, new SecureRandom());
            engine = context.createSSLEngine("localhost", 443);
            engine.setUseClientMode(true);
            engine.setEnabledProtocols(new String[] {"TLSv1.3"});
            engine.setEnabledCipherSuites(new String[] {suite});
            engine.beginHandshake();
            started = true;
        }

        /** The plaintext received since the last call. */
        byte[] plain() {
            byte[] bytes = plain.toByteArray();
            plain.reset();
            return bytes;
        }

        /** Feeds ciphertext from the plugin and returns the ciphertext to send back. */
        byte[] exchange(byte[] received) throws Exception {
            if (netIn.remaining() < received.length) {
                ByteBuffer larger = ByteBuffer.allocate(netIn.capacity() + received.length);
                netIn.flip();
                larger.put(netIn);
                netIn = larger;
            }
            netIn.put(received);
            netIn.flip();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ByteBuffer app = ByteBuffer.allocate(1 << 15);
            while (true) {
                HandshakeStatus status = engine.getHandshakeStatus();
                if (started && status == HandshakeStatus.NOT_HANDSHAKING) {
                    done = true;
                }
                if (status == HandshakeStatus.NEED_TASK) {
                    Runnable task;
                    while ((task = engine.getDelegatedTask()) != null) {
                        task.run();
                    }
                    continue;
                }
                if (status == HandshakeStatus.NEED_WRAP) {
                    wrap(ByteBuffer.allocate(0), out);
                    continue;
                }
                if (!netIn.hasRemaining() && status != HandshakeStatus.NEED_UNWRAP_AGAIN) {
                    break;
                }
                SSLEngineResult result = engine.unwrap(netIn, app);
                if (result.getHandshakeStatus() == HandshakeStatus.FINISHED) {
                    done = true;
                }
                if (result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW
                        || result.getStatus() == SSLEngineResult.Status.CLOSED) {
                    break;
                }
                app.flip();
                plain.write(app.array(), 0, app.remaining());
                app.clear();
            }
            netIn.compact();
            return out.toByteArray();
        }

        /** Encrypts application data. */
        byte[] seal(byte[] data) throws Exception {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ByteBuffer source = ByteBuffer.wrap(data);
            while (source.hasRemaining()) {
                wrap(source, out);
            }
            return out.toByteArray();
        }

        private void wrap(ByteBuffer source, ByteArrayOutputStream out) throws Exception {
            ByteBuffer packet = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
            SSLEngineResult result = engine.wrap(source, packet);
            if (result.getHandshakeStatus() == HandshakeStatus.FINISHED) {
                done = true;
            }
            packet.flip();
            out.write(packet.array(), 0, packet.remaining());
        }
    }

    private static final class ClientKey extends X509ExtendedKeyManager {
        private final PrivateKey key;
        private final X509Certificate[] chain;

        ClientKey(InnerKeys keys) {
            key = keys.privateKey();
            chain = new X509Certificate[] {keys.certificate()};
        }

        @Override
        public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
            return "client";
        }

        @Override
        public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
            return "client";
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            return chain;
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            return key;
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return new String[] {"client"};
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return null;
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return null;
        }
    }

    /** Accepts exactly the plugin's pinned key. */
    private static final class PinServer extends X509ExtendedTrustManager {
        private final String fingerprint;

        PinServer(String fingerprint) {
            this.fingerprint = fingerprint;
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            if (!fingerprint.equals(InnerKeys.fingerprint(chain[0].getPublicKey()))) {
                throw new CertificateException("Wrong plugin key.");
            }
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            throw new CertificateException("engine only");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("engine only");
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            throw new CertificateException("client side");
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            throw new CertificateException("client side");
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("client side");
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    // ------------------------------------------------------------------ helpers

    /** Runs the TLS handshake between a client and a bare channel; throws what the channel throws. */
    private static void handshake(InnerChannel channel, Client client) throws Exception {
        byte[] toServer = client.exchange(new byte[0]);
        for (int i = 0; i < 20; i++) {
            byte[] toClient = new byte[0];
            if (toServer.length > 0) {
                feed(channel, toServer);
                toClient = channel.takeOutgoing();
            }
            toServer = client.exchange(toClient);
            if (client.done && channel.handshakeComplete() && toServer.length == 0) {
                return;
            }
        }
        throw new AssertionError("The handshake did not finish.");
    }

    private static List<byte[]> feed(InnerChannel channel, byte[] cipher) throws ChannelException {
        List<byte[]> messages = new ArrayList<>();
        for (int i = 0; i < cipher.length; i += TunnelProtocol.MAX_DATA_PAYLOAD) {
            messages.addAll(channel.feed(Arrays.copyOfRange(cipher, i,
                    Math.min(cipher.length, i + TunnelProtocol.MAX_DATA_PAYLOAD))));
        }
        return messages;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] joined = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, joined, a.length, b.length);
        return joined;
    }

    private static void check(boolean condition) {
        if (!condition) {
            throw new AssertionError("Inner channel regression.");
        }
    }
}
