package com.sap.adt.mcp.server;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.net.http.WebSocketHandshakeException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import com.sap.adt.mcp.tools.McpTool;
import com.sap.adt.mcp.sap.AdtRestClient;

/** One outbound connection to a relay. Create a fresh instance when reconnecting. */
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

    private final URI uri;
    private final HttpClient client;
    private final RelayRequests requests;
    private final Consumer<String> onClosed;
    private final StringBuilder fragments = new StringBuilder();
    private final CompletableFuture<Void> connected = new CompletableFuture<>();
    private final ExecutorService worker = Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(task, "SAP ADT relay tools");
        thread.setDaemon(true);
        return thread;
    });

    private CompletableFuture<WebSocket> handshake;
    private WebSocket socket;
    private boolean closed;

    public RelayBridge(RelayIdentity identity, List<McpTool> tools, AdtRestClient sapSession, Consumer<String> onClosed) {
        this.uri = identity.bridge;
        this.client = identity.client;
        this.requests = new RelayRequests(tools, sapSession);
        this.onClosed = Objects.requireNonNull(onClosed);
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
        // Request the next message after this reply. This also serializes access to the SAP client.
        return CompletableFuture.supplyAsync(() -> requests.reply(message), worker)
                .thenCompose(reply -> webSocket.sendText(reply, true))
                .orTimeout(10, TimeUnit.MINUTES)
                .whenComplete((sent, failure) -> {
                    if (failure == null) {
                        webSocket.request(1);
                    } else {
                        finish("The request failed or timed out. Check SAP for changes before retrying.", true);
                    }
                });
    }

    @Override
    public CompletionStage<?> onBinary(WebSocket webSocket, ByteBuffer data, boolean last) {
        finish("The relay sent an unsupported binary message.", true);
        return null;
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
        worker.shutdownNow();
        connected.completeExceptionally(new ConnectionFailure(message));
        if (notify && active != null) {
            onClosed.accept(message);
        }
    }
}
