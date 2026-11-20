package com.sap.adt.mcp.server;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.net.http.WebSocketHandshakeException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sap.adt.mcp.server.e2e.PairingGate;
import com.sap.adt.mcp.server.e2e.RelayStreams;
import com.sap.adt.mcp.server.e2e.TunnelProtocol;
import com.sap.adt.mcp.tools.McpTool;
import com.sap.adt.mcp.tools.ToolCatalog;
import com.sap.adt.mcp.sap.AdtRestClient;

/**
 * One outbound connection to a relay. Create a fresh instance when reconnecting.
 *
 * <p>Two kinds of traffic share the connection. Legacy JSON-RPC bridge calls run on the single-threaded
 * {@code worker} as before. End-to-end tunnel traffic (binary data frames and control text frames whose
 * {@code type} is a tunnel type) goes to {@link RelayStreams}: frames are processed in order on one frame
 * thread, tool calls run on handler threads, and SAP access stays serialised by the handler
 * ({@code synchronized (sapSession)}). All sends go through one queue, so no two messages interleave.</p>
 */
public final class RelayBridge implements WebSocket.Listener, AutoCloseable {
    /** The message contains only bridge-generated text suitable for display. */
    public static final class ConnectionFailure extends Exception {
        private static final long serialVersionUID = 1L;

        private ConnectionFailure(String message) {
            super(message);
        }
    }

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(15);
    private static final int MAX_REQUEST_BYTES = 4 * 1024 * 1024;
    private static final int MAX_DATA_FRAME_BYTES = TunnelProtocol.MAX_DATA_PAYLOAD + 5;
    /** Tunnel frames waiting for the frame thread; more than this means the relay floods the bridge. */
    private static final long MAX_QUEUED_FRAME_BYTES = 32L * 1024 * 1024;

    private final URI uri;
    private final HttpClient client;
    private final RelayRequests requests;
    private final Consumer<String> onClosed;
    private final StringBuilder fragments = new StringBuilder();
    private final ByteArrayOutputStream binaryFragments = new ByteArrayOutputStream();
    private final CompletableFuture<Void> connected = new CompletableFuture<>();
    private final ExecutorService worker = Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(task, "SAP ADT relay tools");
        thread.setDaemon(true);
        return thread;
    });
    private final ExecutorService frames = Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(task, "SAP ADT relay tunnel frames");
        thread.setDaemon(true);
        return thread;
    });
    private final ExecutorService handlers = Executors.newCachedThreadPool(task -> {
        Thread thread = new Thread(task, "SAP ADT relay tunnel handler");
        thread.setDaemon(true);
        return thread;
    });
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(task -> {
        Thread thread = new Thread(task, "SAP ADT relay tunnel timers");
        thread.setDaemon(true);
        return thread;
    });
    private final AtomicLong queuedFrameBytes = new AtomicLong();
    /** Null when no end-to-end handler is registered or the inner identity is unavailable. */
    private final RelayStreams streams;

    private final ArrayDeque<Outbound> outbox = new ArrayDeque<>();
    private boolean sending;

    private CompletableFuture<WebSocket> handshake;
    private WebSocket socket;
    private boolean closed;

    private record Outbound(Object message, CompletableFuture<Void> done) {
    }

    public RelayBridge(RelayIdentity identity, List<McpTool> tools, AdtRestClient sapSession, Consumer<String> onClosed) {
        this.uri = identity.bridge;
        this.client = identity.client;
        this.requests = new RelayRequests(tools, sapSession);
        this.onClosed = Objects.requireNonNull(onClosed);
        this.streams = createStreams();
    }

    private RelayStreams createStreams() {
        try {
            // Handler, keys and gate are read per stream / per handshake, so registration order does not matter.
            PairingGate gate = () -> E2eServices.pairingGate().pairingOpen();
            return new RelayStreams(E2eServices::innerKeys, E2eServices.pinStore(), E2eServices::handler, gate,
                    ToolCatalog.bundled(), new RelayStreams.Transport() {
                        @Override
                        public void sendText(String text) {
                            sendTunnel(text);
                        }

                        @Override
                        public void sendBinary(byte[] frame) {
                            sendTunnel(frame);
                        }
                    }, handlers, scheduler, PolicyDenials::report);
        } catch (RuntimeException e) {
            PolicyDenials.report("The end-to-end tunnel is unavailable.");
            return null;
        }
    }

    public synchronized CompletableFuture<Void> connect() {
        if (closed || handshake != null) {
            return CompletableFuture.failedFuture(new ConnectionFailure("This bridge has already been used."));
        }
        try {
            handshake = client.newWebSocketBuilder().connectTimeout(CONNECT_TIMEOUT).buildAsync(uri, this);
            handshake.whenComplete((webSocket, failure) -> {
                if (failure != null) {
                    finish(handshakeMessage(failure), false);
                }
            });
        } catch (RuntimeException e) {
            finish("The relay connection could not be started.", false);
        }
        return connected.copy();
    }

    private static String handshakeMessage(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof WebSocketHandshakeException handshakeError) {
                return "The relay refused the connection (HTTP " + handshakeError.getResponse().statusCode() + ").";
            }
        }
        return "Could not establish a secure connection. Check the network and certificate status with the operator.";
    }

    @Override
    public synchronized void onOpen(WebSocket webSocket) {
        if (closed) {
            webSocket.abort();
            return;
        }
        socket = webSocket;
        connected.complete(null);
        webSocket.request(1);
    }

    @Override
    public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
        if (data.length() > MAX_REQUEST_BYTES - fragments.length()) {
            finish("The relay sent a request that exceeds the bridge size limit.", true);
            return null;
        }
        fragments.append(data);
        if (!last) {
            webSocket.request(1);
            return null;
        }

        String message = fragments.toString();
        fragments.setLength(0);
        if (message.getBytes(StandardCharsets.UTF_8).length > MAX_REQUEST_BYTES) {
            finish("The relay request exceeds the bridge size limit.", true);
            return null;
        }
        JsonObject tunnel = tunnelControl(message);
        if (tunnel != null) {
            tunnelText(webSocket, message, tunnel);
            return null;
        }
        // Legacy bridge call. The relay sends one at a time and the worker is single-threaded, so replies stay in
        // order; asking for the next message right away keeps tunnel frames flowing during a long call.
        CompletableFuture.supplyAsync(() -> requests.reply(message), worker)
                .thenCompose(this::send)
                .orTimeout(10, TimeUnit.MINUTES)
                .whenComplete((sent, failure) -> {
                    if (failure != null) {
                        finish("The request failed or timed out. Check SAP for changes before retrying.", true);
                    }
                });
        webSocket.request(1);
        return null;
    }

    /** The parsed frame when {@code message} is a tunnel control frame, otherwise null (a legacy JSON-RPC call). */
    private static JsonObject tunnelControl(String message) {
        if (message.length() > TunnelProtocol.MAX_CONTROL_BYTES || !message.contains("\"type\"")) {
            return null;
        }
        try {
            JsonElement parsed = JsonParser.parseString(message);
            if (parsed.isJsonObject()) {
                JsonElement type = parsed.getAsJsonObject().get("type");
                if (type != null && type.isJsonPrimitive() && type.getAsJsonPrimitive().isString()
                        && TunnelProtocol.isControlType(type.getAsString())) {
                    return parsed.getAsJsonObject();
                }
            }
        } catch (RuntimeException e) {
            // Not JSON the tunnel understands: the legacy path answers it with its own error.
        }
        return null;
    }

    private void tunnelText(WebSocket webSocket, String message, JsonObject control) {
        if (streams == null) {
            // No tunnel here: refuse streams so the relay does not wait for a handshake.
            JsonElement type = control.get("type");
            JsonElement stream = control.get("stream");
            if (type != null && TunnelProtocol.OPEN.equals(type.getAsString()) && stream != null
                    && stream.isJsonPrimitive() && stream.getAsJsonPrimitive().isNumber()) {
                try {
                    sendTunnel(TunnelProtocol.encode(TunnelProtocol.close((int) stream.getAsLong(),
                            "end-to-end tunnel unavailable")));
                } catch (TunnelProtocol.ProtocolException | RuntimeException e) {
                    // Nothing sensible to send.
                }
            }
            webSocket.request(1);
            return;
        }
        submitFrame(message.length(), () -> streams.onControl(message));
        webSocket.request(1);
    }

    @Override
    public CompletionStage<?> onBinary(WebSocket webSocket, ByteBuffer data, boolean last) {
        if (streams == null) {
            finish("The relay sent an unsupported binary message.", true);
            return null;
        }
        if (data.remaining() > MAX_DATA_FRAME_BYTES - binaryFragments.size()) {
            finish("The relay sent a tunnel frame that exceeds the size limit.", true);
            return null;
        }
        byte[] chunk = new byte[data.remaining()];
        data.get(chunk);
        binaryFragments.write(chunk, 0, chunk.length);
        if (!last) {
            webSocket.request(1);
            return null;
        }
        byte[] frame = binaryFragments.toByteArray();
        binaryFragments.reset();
        submitFrame(frame.length, () -> streams.onData(frame));
        webSocket.request(1);
        return null;
    }

    private void submitFrame(int size, Runnable work) {
        if (queuedFrameBytes.addAndGet(size) > MAX_QUEUED_FRAME_BYTES) {
            finish("The relay sent tunnel traffic faster than it can be processed.", true);
            return;
        }
        try {
            frames.execute(() -> {
                try {
                    work.run();
                } catch (RuntimeException e) {
                    PolicyDenials.report("A tunnel frame could not be processed.");
                } finally {
                    queuedFrameBytes.addAndGet(-size);
                }
            });
        } catch (RuntimeException e) {
            // The executor is shut down: the bridge is closing.
        }
    }

    @Override
    public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
        finish("The relay disconnected. Reconnect to continue.", true);
        return null;
    }

    @Override
    public void onError(WebSocket webSocket, Throwable error) {
        finish("The relay connection was lost. Reconnect to continue.", true);
    }

    @Override
    public void close() {
        finish("The relay connection was closed.", false);
    }

    // ------------------------------------------------------------------ serialised sending

    /** Tunnel traffic: failures end the bridge like any other lost connection. */
    private void sendTunnel(Object message) {
        send(message).whenComplete((sent, failure) -> {
            if (failure != null) {
                finish("The relay connection was lost. Reconnect to continue.", true);
            }
        });
    }

    /** Queues one whole WebSocket message ({@code String} or {@code byte[]}); messages are sent strictly one after another. */
    private CompletableFuture<Void> send(Object message) {
        CompletableFuture<Void> done = new CompletableFuture<>();
        boolean start;
        synchronized (outbox) {
            outbox.add(new Outbound(message, done));
            start = !sending;
            sending = true;
        }
        if (start) {
            pumpOutbox();
        }
        return done;
    }

    private void pumpOutbox() {
        Outbound next;
        synchronized (outbox) {
            next = outbox.poll();
            if (next == null) {
                sending = false;
                return;
            }
        }
        WebSocket active;
        synchronized (this) {
            active = socket;
        }
        if (active == null) {
            next.done().completeExceptionally(new ConnectionFailure("The relay connection is closed."));
            pumpOutbox();
            return;
        }
        CompletableFuture<WebSocket> sent;
        try {
            sent = next.message() instanceof String text ? active.sendText(text, true)
                    : active.sendBinary(ByteBuffer.wrap((byte[]) next.message()), true);
        } catch (RuntimeException e) {
            next.done().completeExceptionally(e);
            pumpOutbox();
            return;
        }
        sent.whenComplete((webSocket, failure) -> {
            if (failure == null) {
                next.done().complete(null);
            } else {
                next.done().completeExceptionally(failure);
            }
            pumpOutbox();
        });
    }

    private void finish(String message, boolean notify) {
        WebSocket active;
        CompletableFuture<WebSocket> pending;
        synchronized (this) {
            if (closed) {
                return;
            }
            closed = true;
            active = socket;
            pending = handshake;
        }
        if (active != null) {
            active.abort();
        } else if (pending != null) {
            pending.cancel(true);
        }
        if (streams != null) {
            streams.closeAll();
        }
        worker.shutdownNow();
        frames.shutdownNow();
        handlers.shutdownNow();
        scheduler.shutdownNow();
        connected.completeExceptionally(new ConnectionFailure(message));
        if (notify && active != null) {
            onClosed.accept(message);
        }
    }
}
