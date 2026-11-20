package com.sap.adt.mcp.server.e2e;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Supplier;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.Strictness;
import com.sap.adt.mcp.server.e2e.InnerChannel.ChannelException;
import com.sap.adt.mcp.server.e2e.TunnelProtocol.Envelope;
import com.sap.adt.mcp.server.e2e.TunnelProtocol.ProtocolException;
import com.sap.adt.mcp.server.e2e.TunnelProtocol.Status;
import com.sap.adt.mcp.tools.ToolCatalog;
import com.sap.adt.mcp.tools.ToolClass;

/**
 * The stream table of one bridge connection (plan sections 2 and 3, D7).
 *
 * <p>Control frames and data frames are fed in by the bridge, in arrival order and from one thread at a time.
 * For every decrypted inner message the plugin <b>derives</b> the envelope itself (method from the message, the
 * tool from {@code params.name}, the class from the shared tool table, {@code seq} from its own counter) and
 * compares it with the next envelope the relay forwarded on that stream. Any difference, or a message without a
 * forwarded envelope, closes the stream with a logged binding failure. Valid messages go to the
 * {@link StreamHandler}, one at a time per stream, on the handler executor.</p>
 */
public final class RelayStreams {
    /** Outbound side of the bridge. Both methods must keep call order and never interleave frames. */
    public interface Transport {
        void sendText(String text);

        void sendBinary(byte[] frame);
    }

    private static final int MAX_FORWARDED_PENDING = 64;
    private static final int MAX_QUEUED_MESSAGES = 64;
    private static final Gson JSON = new GsonBuilder().setStrictness(Strictness.STRICT).create();

    private final Supplier<InnerKeys> keys;
    private final PinStore pins;
    private final Supplier<StreamHandler> handler;
    private final PairingGate gate;
    private final ToolCatalog catalog;
    private final Transport transport;
    private final Executor handlers;
    private final ScheduledExecutorService scheduler;
    private final Consumer<String> log;
    private final Map<Integer, Stream> streams = new ConcurrentHashMap<>();

    /**
     * {@code keys} and {@code handler} are read when a stream opens, so they may change between streams; a null
     * handler or a failing key supplier makes the plugin refuse the {@code open}. {@code gate} is consulted live.
     */
    public RelayStreams(Supplier<InnerKeys> keys, PinStore pins, Supplier<StreamHandler> handler, PairingGate gate,
            ToolCatalog catalog, Transport transport, Executor handlers, ScheduledExecutorService scheduler,
            Consumer<String> log) {
        this.keys = Objects.requireNonNull(keys);
        this.pins = Objects.requireNonNull(pins);
        this.handler = Objects.requireNonNull(handler);
        this.gate = Objects.requireNonNull(gate);
        this.catalog = Objects.requireNonNull(catalog);
        this.transport = Objects.requireNonNull(transport);
        this.handlers = Objects.requireNonNull(handlers);
        this.scheduler = Objects.requireNonNull(scheduler);
        this.log = Objects.requireNonNull(log);
    }

    /** Number of open streams. */
    public int streamCount() {
        return streams.size();
    }

    // ------------------------------------------------------------------ inbound frames

    /** One control text frame from the relay. Unusable frames are logged and ignored. */
    public void onControl(String text) {
        JsonObject control;
        try {
            control = TunnelProtocol.decode(text);
        } catch (ProtocolException e) {
            log.accept("Ignored an invalid tunnel control frame from the relay.");
            return;
        }
        int id = TunnelProtocol.stream(control);
        switch (TunnelProtocol.type(control)) {
            case TunnelProtocol.OPEN -> open(id, control);
            case TunnelProtocol.REQUEST -> request(id, control);
            case TunnelProtocol.CLOSE -> {
                Stream stream = streams.get(id);
                if (stream != null) {
                    closeStream(stream, "closed by the relay", false);
                }
            }
            default -> log.accept("Ignored an unexpected tunnel control frame from the relay.");
        }
    }

    /** One binary data frame from the relay. */
    public void onData(byte[] frame) {
        TunnelProtocol.DataFrame data;
        try {
            data = TunnelProtocol.decodeData(frame);
        } catch (ProtocolException e) {
            log.accept("Ignored an invalid tunnel data frame from the relay.");
            return;
        }
        Stream stream = streams.get(data.stream());
        if (stream == null) {
            return;
        }
        synchronized (stream) {
            if (stream.closed) {
                return;
            }
            List<byte[]> messages;
            try {
                messages = stream.channel.feed(data.payload());
            } catch (ChannelException e) {
                flush(stream);
                closeLocked(stream, "inner TLS failure", true);
                return;
            }
            flush(stream);
            if (!stream.handshakeSeen && stream.channel.handshakeComplete()) {
                stream.handshakeSeen = true;
                if (!handshakeFinished(stream)) {
                    return;
                }
            }
            for (byte[] message : messages) {
                if (stream.closed) {
                    return;
                }
                process(stream, message);
            }
        }
    }

    /** The bridge is gone: closes every stream without sending anything. */
    public void closeAll() {
        for (Stream stream : new ArrayList<>(streams.values())) {
            closeStream(stream, "bridge closed", false);
        }
    }

    // ------------------------------------------------------------------ open / request

    private void open(int id, JsonObject control) {
        String desktop = optional(control, "desktop");
        String label = optional(control, "label");
        if (streams.containsKey(id)) {
            log.accept("The relay reused stream ID " + Integer.toUnsignedString(id) + ".");
            Stream old = streams.get(id);
            if (old != null) {
                closeStream(old, "stream ID reused", false);
            }
            sendClose(id, "stream ID reused");
            return;
        }
        if (streams.size() >= TunnelProtocol.MAX_STREAMS_PER_BRIDGE) {
            log.accept("Refused a stream: the bridge limit is reached.");
            sendClose(id, "too many streams");
            return;
        }
        String desktopKey = desktop == null ? "" : desktop;
        long same = streams.values().stream().filter(s -> s.desktopKey.equals(desktopKey)).count();
        if (same >= TunnelProtocol.MAX_STREAMS_PER_DESKTOP) {
            log.accept("Refused a stream: the per-desktop limit is reached.");
            sendClose(id, "too many streams for this desktop");
            return;
        }
        StreamHandler streamHandler = handler.get();
        if (streamHandler == null) {
            log.accept("Refused a stream: no request handler is registered.");
            sendClose(id, "end-to-end tunnel unavailable");
            return;
        }
        InnerChannel channel;
        try {
            channel = new InnerChannel(keys.get(), pins, gate);
        } catch (GeneralSecurityException | RuntimeException e) {
            log.accept("Refused a stream: the inner TLS server could not be created.");
            sendClose(id, "inner TLS unavailable");
            return;
        }
        Stream stream = new Stream(id, desktop, desktopKey, label, channel, streamHandler);
        streams.put(id, stream);
        try {
            stream.deadline = scheduler.schedule(() -> {
                if (!stream.handshakeSeen) {
                    log.accept("Closed stream " + Integer.toUnsignedString(id) + ": the inner handshake timed out.");
                    closeStream(stream, "handshake timeout", true);
                }
            }, TunnelProtocol.HANDSHAKE_DEADLINE.toMillis(), TimeUnit.MILLISECONDS);
        } catch (RejectedExecutionException e) {
            closeStream(stream, "bridge closed", false);
        }
    }

    private void request(int id, JsonObject control) {
        Stream stream = streams.get(id);
        if (stream == null) {
            return;
        }
        Envelope envelope;
        RelayPolicyView policy;
        try {
            envelope = TunnelProtocol.envelope(control);
            policy = TunnelProtocol.policy(control);
        } catch (ProtocolException e) {
            log.accept("Ignored an invalid request frame from the relay.");
            return;
        }
        synchronized (stream) {
            if (stream.closed) {
                return;
            }
            if (stream.forwarded.size() >= MAX_FORWARDED_PENDING) {
                log.accept("Closed stream " + Integer.toUnsignedString(id) + ": too many forwarded envelopes.");
                closeLocked(stream, "too many pending requests", true);
                return;
            }
            stream.forwarded.add(new Forwarded(envelope, policy));
        }
    }

    // ------------------------------------------------------------------ inner messages

    /** Called with the stream locked once the inner handshake finished. False when the stream was closed. */
    private boolean handshakeFinished(Stream stream) {
        if (stream.deadline != null) {
            stream.deadline.cancel(false);
        }
        String fingerprint = stream.channel.peerKeyFingerprint();
        Optional<PinStore.Pin> pin = fingerprint == null ? Optional.empty() : pins.find(fingerprint);
        if (pin.isPresent()) {
            String stored = pin.get().relayFingerprint();
            // The relay fingerprint is only asserted by the relay: a desktop that shows up under another one
            // must pair again.
            if (!stored.isEmpty() && !stored.equalsIgnoreCase(stream.desktop == null ? "" : stream.desktop)) {
                log.accept("Closed stream " + Integer.toUnsignedString(stream.id)
                        + ": the paired desktop key arrived under a different relay identity. Pair again.");
                closeLocked(stream, "pair again", true);
                return false;
            }
        }
        return true;
    }

    private void process(Stream stream, byte[] raw) {
        JsonElement parsed = null;
        try {
            parsed = JSON.fromJson(new String(raw, StandardCharsets.UTF_8), JsonElement.class);
        } catch (RuntimeException e) {
            // Falls through to the binding check, which refuses it.
        }
        JsonObject message = parsed != null && parsed.isJsonObject() ? parsed.getAsJsonObject() : null;
        JsonElement id = message != null && message.get("id") != null && message.get("id").isJsonPrimitive()
                ? message.get("id") : JsonNull.INSTANCE;
        long seq = stream.lastSeq + 1;
        Forwarded forwarded = stream.forwarded.poll();
        if (forwarded == null) {
            bindingFailure(stream, id, seq, "the message was not announced by a forwarded envelope");
            return;
        }
        Envelope derived;
        String why = null;
        derived = message == null ? null : derive(message, seq);
        if (derived == null) {
            why = "the envelope could not be derived from the message";
        } else {
            why = difference(derived, forwarded.envelope);
        }
        if (why != null) {
            bindingFailure(stream, id, seq, why);
            return;
        }
        stream.lastSeq = seq;
        if (!stream.paired() && !"pair/claim".equals(derived.method())) {
            log.accept("Closed stream " + Integer.toUnsignedString(stream.id) + ": an unpaired stream may only claim a pairing.");
            sendResponse(stream, seq, rpcError(id, TunnelProtocol.CODE_LOCAL_DENIED,
                    "This desktop is not paired. Pair it before sending requests."));
            closeLocked(stream, "not paired", true);
            return;
        }
        if (stream.work.size() >= MAX_QUEUED_MESSAGES) {
            log.accept("Closed stream " + Integer.toUnsignedString(stream.id) + ": too many queued requests.");
            closeLocked(stream, "too many pending requests", true);
            return;
        }
        stream.work.add(new Work(message, forwarded.policy, seq, derived.isNotification(), id));
        if (!stream.running) {
            stream.running = true;
            try {
                handlers.execute(() -> drain(stream));
            } catch (RejectedExecutionException e) {
                stream.running = false;
                closeLocked(stream, "bridge closed", true);
            }
        }
    }

    /** The envelope the plugin expects for this message, or null when the message does not allow one. */
    private Envelope derive(JsonObject message, long seq) {
        JsonElement method = message.get("method");
        if (method == null || !method.isJsonPrimitive() || !method.getAsJsonPrimitive().isString()) {
            return null;
        }
        String name = method.getAsString();
        Envelope envelope;
        if ("tools/call".equals(name)) {
            JsonElement params = message.get("params");
            JsonElement tool = params != null && params.isJsonObject() ? params.getAsJsonObject().get("name") : null;
            if (tool == null || !tool.isJsonPrimitive() || !tool.getAsJsonPrimitive().isString()) {
                return null;
            }
            Optional<ToolClass> toolClass = catalog.classOf(tool.getAsString());
            if (toolClass.isEmpty()) {
                return null;
            }
            envelope = Envelope.of(seq, name, tool.getAsString(), toolClass.get());
        } else {
            envelope = Envelope.of(seq, name);
        }
        try {
            envelope.validate();
        } catch (ProtocolException e) {
            return null;
        }
        return envelope;
    }

    /** Names the first differing field (never its value), or null when both envelopes are equal. */
    private static String difference(Envelope derived, Envelope forwarded) {
        if (derived.v() != forwarded.v()) {
            return "the envelope version differs";
        }
        if (derived.seq() != forwarded.seq()) {
            return "the envelope seq differs";
        }
        if (!derived.method().equals(forwarded.method())) {
            return "the envelope method differs";
        }
        if (!Objects.equals(derived.tool(), forwarded.tool())) {
            return "the envelope tool differs";
        }
        if (derived.toolClass() != forwarded.toolClass()) {
            return "the envelope class differs";
        }
        return null;
    }

    private void bindingFailure(Stream stream, JsonElement id, long seq, String why) {
        log.accept("Binding failure on stream " + Integer.toUnsignedString(stream.id) + ": " + why + ".");
        sendResponse(stream, seq, rpcError(id, TunnelProtocol.CODE_BINDING,
                "The request did not match the envelope the relay forwarded."));
        closeLocked(stream, "binding failure", true);
    }

    // ------------------------------------------------------------------ handler side

    private void drain(Stream stream) {
        while (true) {
            Work work;
            synchronized (stream) {
                work = stream.closed ? null : stream.work.poll();
                if (work == null) {
                    stream.running = false;
                    stream.work.clear();
                    return;
                }
            }
            String response = null;
            boolean failed = false;
            try {
                response = stream.handler.handle(stream, work.message, work.policy);
            } catch (RuntimeException e) {
                failed = true;
                log.accept("A tunnel request handler failed.");
            }
            if (work.notification) {
                continue;
            }
            if (failed || response == null) {
                response = rpcError(work.id, -32_603, "The request could not be completed.");
            }
            synchronized (stream) {
                if (!stream.closed) {
                    sendResponse(stream, work.seq, response);
                }
            }
        }
    }

    /** Encrypts and sends one JSON-RPC response with the stream locked. */
    private void sendResponse(Stream stream, long seq, String text) {
        if (stream.closed) {
            return;
        }
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > TunnelProtocol.MAX_RESPONSE_BYTES) {
            bytes = rpcError(responseId(text), -32_000,
                    "The tool response exceeded the tunnel limit. Check SAP before retrying an operation.")
                    .getBytes(StandardCharsets.UTF_8);
            text = new String(bytes, StandardCharsets.UTF_8);
        }
        Status status = status(text);
        flush(stream);
        byte[] sealed;
        try {
            sealed = stream.channel.seal(bytes);
        } catch (ChannelException e) {
            flush(stream);
            closeLocked(stream, "inner TLS failure", true);
            return;
        }
        transportText(TunnelProtocol.response(stream.id, seq, status, sealed.length));
        for (byte[] frame : TunnelProtocol.encodeDataChunks(stream.id, sealed)) {
            transport.sendBinary(frame);
        }
    }

    private static Status status(String text) {
        try {
            JsonElement parsed = JSON.fromJson(text, JsonElement.class);
            if (parsed != null && parsed.isJsonObject() && parsed.getAsJsonObject().has("error")) {
                JsonElement error = parsed.getAsJsonObject().get("error");
                if (error.isJsonObject() && error.getAsJsonObject().get("code") != null) {
                    int code = error.getAsJsonObject().get("code").getAsInt();
                    if (code == TunnelProtocol.CODE_RELAY_DENIED || code == TunnelProtocol.CODE_LOCAL_DENIED
                            || code == TunnelProtocol.CODE_BINDING) {
                        return Status.DENIED;
                    }
                }
                return Status.ERROR;
            }
            return Status.OK;
        } catch (RuntimeException e) {
            return Status.ERROR;
        }
    }

    private static JsonElement responseId(String text) {
        try {
            JsonElement parsed = JSON.fromJson(text, JsonElement.class);
            if (parsed != null && parsed.isJsonObject() && parsed.getAsJsonObject().get("id") != null
                    && parsed.getAsJsonObject().get("id").isJsonPrimitive()) {
                return parsed.getAsJsonObject().get("id");
            }
        } catch (RuntimeException e) {
            // No usable ID.
        }
        return JsonNull.INSTANCE;
    }

    private static String rpcError(JsonElement id, int code, String message) {
        JsonObject detail = new JsonObject();
        detail.addProperty("code", code);
        detail.addProperty("message", message);
        JsonObject response = new JsonObject();
        response.addProperty("jsonrpc", "2.0");
        response.add("id", id);
        response.add("error", detail);
        return response.toString();
    }

    // ------------------------------------------------------------------ sending and closing

    /** Sends whatever the engine produced as data frames; the stream must be locked. */
    private void flush(Stream stream) {
        byte[] bytes = stream.channel.takeOutgoing();
        for (byte[] frame : TunnelProtocol.encodeDataChunks(stream.id, bytes)) {
            transport.sendBinary(frame);
        }
    }

    private void transportText(JsonObject control) {
        try {
            transport.sendText(TunnelProtocol.encode(control));
        } catch (ProtocolException e) {
            log.accept("A tunnel control frame was too large to send.");
        }
    }

    private void sendClose(int id, String reason) {
        transportText(TunnelProtocol.close(id, reason));
    }

    private void closeStream(Stream stream, String reason, boolean notifyRelay) {
        synchronized (stream) {
            closeLocked(stream, reason, notifyRelay);
        }
    }

    /** Idempotent; the stream must be locked. */
    private void closeLocked(Stream stream, String reason, boolean notifyRelay) {
        if (stream.closed) {
            return;
        }
        stream.closed = true;
        streams.remove(stream.id, stream);
        if (stream.deadline != null) {
            stream.deadline.cancel(false);
        }
        stream.forwarded.clear();
        stream.work.clear();
        stream.channel.close();
        if (notifyRelay) {
            flush(stream);
            sendClose(stream.id, reason);
        }
        try {
            stream.handler.closed(stream.id);
        } catch (RuntimeException e) {
            log.accept("A tunnel stream handler failed while closing.");
        }
    }

    private static String optional(JsonObject control, String key) {
        JsonElement value = control.get(key);
        return value == null || value.isJsonNull() ? null : value.getAsString();
    }

    // ------------------------------------------------------------------ per-stream state

    private record Forwarded(Envelope envelope, RelayPolicyView policy) {
    }

    private record Work(JsonObject message, RelayPolicyView policy, long seq, boolean notification, JsonElement id) {
    }

    private final class Stream implements StreamContext {
        final int id;
        final String desktop;
        final String desktopKey;
        final String label;
        final InnerChannel channel;
        final StreamHandler handler;
        final Deque<Forwarded> forwarded = new ArrayDeque<>();
        final Deque<Work> work = new ArrayDeque<>();
        ScheduledFuture<?> deadline;
        boolean handshakeSeen;
        boolean closed;
        boolean running;
        long lastSeq;

        Stream(int id, String desktop, String desktopKey, String label, InnerChannel channel,
                StreamHandler handler) {
            this.handler = handler;
            this.id = id;
            this.desktop = desktop;
            this.desktopKey = desktopKey;
            this.label = label;
            this.channel = channel;
        }

        boolean paired() {
            String fingerprint = channel.peerKeyFingerprint();
            return fingerprint != null && pins.find(fingerprint).isPresent();
        }

        @Override
        public int streamId() {
            return id;
        }

        @Override
        public String peerKeyFingerprint() {
            return channel.peerKeyFingerprint();
        }

        @Override
        public boolean peerPinned() {
            return paired();
        }

        @Override
        public String assertedDesktopFingerprint() {
            return desktop;
        }

        @Override
        public String assertedLabel() {
            return label;
        }
    }
}
