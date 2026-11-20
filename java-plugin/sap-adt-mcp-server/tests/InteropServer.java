package com.sap.adt.mcp.server.e2e;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sap.adt.mcp.server.e2e.InnerChannel.ChannelException;

/**
 * The plugin's inner TLS server on a plain TCP port, for the Rust interop test ({@code tests/interop.rs}).
 *
 * <p>Usage: {@code InteropServer [port] [clientKeyPin|any]}. Port 0 (the default) picks an ephemeral port. The
 * second argument is the lowercase hex SHA-256 of the one client SPKI to accept, or {@code any} to accept every
 * client key (the pairing gate is then open). Standard output carries exactly two lines, {@code PORT <n>} and
 * {@code PIN <64 hex>} (the SPKI hash of this server's {@link InnerKeys} certificate); everything else goes to
 * standard error and never contains message content.</p>
 *
 * <p>Each TCP connection gets its own real {@link InnerChannel} with the production configuration. The raw TLS
 * byte stream travels directly over TCP, with no tunnel framing. {@link RelayStreams} is not used: it needs a
 * relay {@code request} frame with a matching envelope before every inner message, and the relay can only write
 * that because it sees message boundaries, which a raw TCP stream does not expose. Every inner message is a
 * length-prefixed JSON-RPC message, and every message that has an {@code id} is answered with
 * {@code {"jsonrpc":"2.0","id":<id>,"result":{"echo":<params>}}}.</p>
 */
public final class InteropServer {
    private InteropServer() {
    }

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 0;
        String clientPin = args.length > 1 ? args[1] : "any";
        boolean any = "any".equals(clientPin);
        if (!any && !PinStore.isFingerprint(clientPin)) {
            System.err.println("The client pin must be 64 lowercase hex digits or 'any'.");
            System.exit(2);
        }
        InnerKeys keys = InnerKeys.generate();
        PinStore pins = new PinStore(new MemoryPins());
        if (!any) {
            pins.add(clientPin, "", "interop client");
        }
        PairingGate gate = () -> any;
        try (ServerSocket server = new ServerSocket(port, 16, InetAddress.getLoopbackAddress())) {
            System.out.println("PORT " + server.getLocalPort());
            System.out.println("PIN " + keys.fingerprint());
            System.out.flush();
            while (true) {
                Socket socket = server.accept();
                Thread thread = new Thread(() -> serve(socket, keys, pins, gate), "interop-connection");
                thread.setDaemon(true);
                thread.start();
            }
        }
    }

    private static void serve(Socket socket, InnerKeys keys, PinStore pins, PairingGate gate) {
        try (socket) {
            socket.setTcpNoDelay(true);
            InnerChannel channel = new InnerChannel(keys, pins, gate);
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();
            byte[] buffer = new byte[16 * 1024];
            int read;
            while ((read = in.read(buffer)) > 0) {
                List<byte[]> messages;
                try {
                    messages = channel.feed(Arrays.copyOf(buffer, read));
                } catch (ChannelException e) {
                    System.err.println("Connection refused: " + e.getMessage());
                    out.write(channel.takeOutgoing());
                    break;
                }
                out.write(channel.takeOutgoing());
                for (byte[] message : messages) {
                    byte[] reply = echo(message);
                    if (reply != null) {
                        out.write(channel.takeOutgoing());
                        out.write(channel.seal(reply));
                    }
                }
                out.flush();
                if (channel.isClosed()) {
                    break;
                }
            }
            channel.close();
            out.write(channel.takeOutgoing());
            out.flush();
        } catch (IOException | ChannelException | java.security.GeneralSecurityException | RuntimeException e) {
            System.err.println("Connection ended: " + e.getClass().getSimpleName());
        }
    }

    /** The echo response, or null for a notification or for something that is not a JSON-RPC object. */
    private static byte[] echo(byte[] message) {
        JsonElement parsed = JsonParser.parseString(new String(message, StandardCharsets.UTF_8));
        if (!parsed.isJsonObject() || !parsed.getAsJsonObject().has("id")) {
            return null;
        }
        JsonObject request = parsed.getAsJsonObject();
        JsonObject result = new JsonObject();
        result.add("echo", request.has("params") ? request.get("params") : JsonNull.INSTANCE);
        JsonObject response = new JsonObject();
        response.addProperty("jsonrpc", "2.0");
        response.add("id", request.get("id"));
        response.add("result", result);
        return response.toString().getBytes(StandardCharsets.UTF_8);
    }

    /** Keeps the pin list in memory. */
    private static final class MemoryPins implements PinStorage {
        private byte[] blob;

        @Override
        public synchronized byte[] read() {
            return blob;
        }

        @Override
        public synchronized void write(byte[] data) {
            blob = data.clone();
        }
    }
}
