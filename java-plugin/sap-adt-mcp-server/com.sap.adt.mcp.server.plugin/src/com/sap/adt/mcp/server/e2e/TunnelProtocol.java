package com.sap.adt.mcp.server.e2e;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.Strictness;
import com.sap.adt.mcp.tools.ToolClass;

/**
 * Wire format of the end-to-end tunnel; mirrors {@code src/tunnel_proto.rs} (plan section 2).
 *
 * <p>Control frames are JSON text of at most {@link #MAX_CONTROL_BYTES}; data frames are binary
 * {@code [u32 big-endian stream][u8 kind = 0][payload]}. Inside the inner TLS every JSON-RPC message
 * carries a u32 big-endian length prefix. Stream IDs are unsigned 32-bit values carried in a Java
 * {@code int}; sequence numbers are limited to the range of a Java {@code long}.</p>
 */
public final class TunnelProtocol {
    public static final int ENVELOPE_VERSION = 1;
    public static final int MAX_CONTROL_BYTES = 64 * 1024;
    public static final int MAX_DATA_PAYLOAD = 64 * 1024;
    public static final long MAX_REQUEST_BYTES = 4L * 1024 * 1024;
    public static final long MAX_RESPONSE_BYTES = 8L * 1024 * 1024;
    public static final long MAX_ANNOUNCED_BYTES = MAX_RESPONSE_BYTES + MAX_RESPONSE_BYTES / 64 + 4096;
    public static final Duration ADMISSION_TTL = Duration.ofSeconds(30);
    public static final Duration HANDSHAKE_DEADLINE = Duration.ofSeconds(30);
    public static final int MAX_STREAMS_PER_BRIDGE = 128;
    public static final int MAX_STREAMS_PER_DESKTOP = 16;
    public static final int DATA_KIND_STREAM = 0;
    /** JSON-RPC error codes that map to the {@code denied} response status. */
    public static final int CODE_RELAY_DENIED = -32_001;
    public static final int CODE_LOCAL_DENIED = -32_002;
    public static final int CODE_BINDING = -32_003;

    public static final String OPEN = "open";
    public static final String ADMIT = "admit";
    public static final String ADMITTED = "admitted";
    public static final String DENIED = "denied";
    public static final String REQUEST = "request";
    public static final String RESPONSE = "response";
    public static final String CLOSE = "close";
    private static final Set<String> TYPES = Set.of(OPEN, ADMIT, ADMITTED, DENIED, REQUEST, RESPONSE, CLOSE);

    private static final int MAX_METHOD_LEN = 64;
    private static final int MAX_TOOL_LEN = 64;
    private static final int MAX_POLICY_TOOLS = 256;
    private static final long UINT32_MAX = 0xFFFF_FFFFL;
    private static final Gson JSON = new GsonBuilder().setStrictness(Strictness.STRICT).create();

    private TunnelProtocol() {
    }

    /** Why a frame or envelope was refused. Messages never echo frame content. */
    public static final class ProtocolException extends Exception {
        private static final long serialVersionUID = 1L;

        public enum Kind {
            MALFORMED, TOO_LARGE, BAD_ENVELOPE
        }

        private final Kind kind;

        ProtocolException(Kind kind, String message) {
            super(message);
            this.kind = kind;
        }

        public Kind kind() {
            return kind;
        }

        static ProtocolException malformed() {
            return new ProtocolException(Kind.MALFORMED, "Malformed tunnel frame.");
        }

        static ProtocolException tooLarge() {
            return new ProtocolException(Kind.TOO_LARGE, "Tunnel frame exceeds the size limit.");
        }

        static ProtocolException badEnvelope(String rule) {
            return new ProtocolException(Kind.BAD_ENVELOPE, "Invalid envelope: " + rule + ".");
        }
    }

    /** Clear-text outcome of a response. */
    public enum Status {
        OK("ok"), ERROR("error"), DENIED("denied");

        private final String wire;

        Status(String wire) {
            this.wire = wire;
        }

        public String wire() {
            return wire;
        }

        static Status parse(String text) {
            for (Status status : values()) {
                if (status.wire.equals(text)) {
                    return status;
                }
            }
            return null;
        }
    }

    // ------------------------------------------------------------------ envelope

    /** The readable part of a request: exactly {@code v, seq, method, tool, class}. */
    public record Envelope(int v, long seq, String method, String tool, ToolClass toolClass) {

        public static Envelope of(long seq, String method, String tool, ToolClass toolClass) {
            return new Envelope(ENVELOPE_VERSION, seq, method, tool, toolClass);
        }

        public static Envelope of(long seq, String method) {
            return of(seq, method, null, null);
        }

        public boolean isNotification() {
            return method.startsWith("notifications/");
        }

        /** Same schema rules as the Rust {@code Envelope::validate}. */
        public void validate() throws ProtocolException {
            if (v != ENVELOPE_VERSION) {
                throw ProtocolException.badEnvelope("unsupported envelope version");
            }
            boolean known = switch (method) {
                case "initialize", "tools/list", "tools/call", "ping", "pair/claim" -> true;
                default -> isNotification() && method.length() > "notifications/".length();
            };
            if (!known || method.length() > MAX_METHOD_LEN || !allMatch(method, true)) {
                throw ProtocolException.badEnvelope("unknown method");
            }
            if ("tools/call".equals(method)) {
                if (tool == null || toolClass == null) {
                    throw ProtocolException.badEnvelope("tools/call needs tool and class");
                }
                if (tool.isEmpty() || tool.length() > MAX_TOOL_LEN || !validToolName(tool)) {
                    throw ProtocolException.badEnvelope("invalid tool name");
                }
            } else if (tool != null || toolClass != null) {
                throw ProtocolException.badEnvelope("only tools/call carries tool and class");
            }
        }

        private static boolean allMatch(String text, boolean method) {
            for (int i = 0; i < text.length(); i++) {
                char c = text.charAt(i);
                boolean ok = c < 128 && (Character.isLetterOrDigit(c) || c == '/' || c == '_');
                if (!ok) {
                    return false;
                }
            }
            return true;
        }

        private static boolean validToolName(String name) {
            for (int i = 0; i < name.length(); i++) {
                char c = name.charAt(i);
                if (!(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_')) {
                    return false;
                }
            }
            return true;
        }

        /** Field order as serde writes it: v, seq, method, tool, class. */
        public JsonObject toJson() {
            JsonObject object = new JsonObject();
            object.addProperty("v", v);
            object.addProperty("seq", seq);
            object.addProperty("method", method);
            if (tool != null) {
                object.addProperty("tool", tool);
            }
            if (toolClass != null) {
                object.addProperty("class", toolClass.name().toLowerCase(java.util.Locale.ROOT));
            }
            return object;
        }

        /** Parses and validates an envelope object; unknown fields are refused. */
        public static Envelope fromJson(JsonElement element) throws ProtocolException {
            if (element == null || !element.isJsonObject()) {
                throw ProtocolException.malformed();
            }
            JsonObject object = element.getAsJsonObject();
            for (String key : object.keySet()) {
                if (!Set.of("v", "seq", "method", "tool", "class").contains(key)) {
                    throw ProtocolException.malformed();
                }
            }
            long version = requireUint(object, "v", UINT32_MAX);
            long seq = requireUint(object, "seq", Long.MAX_VALUE);
            String method = requireString(object, "method");
            String tool = optionalString(object, "tool");
            String className = optionalString(object, "class");
            ToolClass toolClass = null;
            if (className != null) {
                toolClass = ToolClass.parse(className).orElseThrow(ProtocolException::malformed);
            }
            Envelope envelope = new Envelope(version > Integer.MAX_VALUE ? -1 : (int) version, seq, method, tool,
                    toolClass);
            envelope.validate();
            return envelope;
        }
    }

    // ------------------------------------------------------------------ control frames

    /** True when {@code type} names a tunnel control frame. */
    public static boolean isControlType(String type) {
        return type != null && TYPES.contains(type);
    }

    /** The {@code type} of a decoded control frame. */
    public static String type(JsonObject control) {
        return control.get("type").getAsString();
    }

    /** The stream ID of a decoded control frame, as the unsigned 32-bit value reinterpreted as an int. */
    public static int stream(JsonObject control) {
        return (int) control.get("stream").getAsLong();
    }

    /**
     * Parses a control text frame and validates its fields, any envelope and any announced length.
     * The returned object keeps the field order of the text, so {@link #encode} reproduces it.
     */
    public static JsonObject decode(String text) throws ProtocolException {
        if (text.length() > MAX_CONTROL_BYTES || text.getBytes(StandardCharsets.UTF_8).length > MAX_CONTROL_BYTES) {
            throw ProtocolException.tooLarge();
        }
        JsonElement parsed;
        try {
            parsed = JSON.fromJson(text, JsonElement.class);
        } catch (RuntimeException e) {
            throw ProtocolException.malformed();
        }
        if (parsed == null || !parsed.isJsonObject()) {
            throw ProtocolException.malformed();
        }
        JsonObject control = parsed.getAsJsonObject();
        String type = requireString(control, "type");
        if (!isControlType(type)) {
            throw ProtocolException.malformed();
        }
        requireUint(control, "stream", UINT32_MAX);
        switch (type) {
            case OPEN -> {
                requireString(control, "endpoint");
                optionalString(control, "desktop");
                optionalString(control, "label");
            }
            case ADMIT -> Envelope.fromJson(control.get("envelope"));
            case ADMITTED -> requireUint(control, "seq", Long.MAX_VALUE);
            case DENIED -> {
                requireUint(control, "seq", Long.MAX_VALUE);
                requireInt(control, "code");
                requireString(control, "message");
            }
            case REQUEST -> {
                Envelope.fromJson(control.get("envelope"));
                JsonElement policy = control.get("policy");
                if (policy != null && !policy.isJsonNull()) {
                    parsePolicy(policy);
                }
                long len = requireUint(control, "len", UINT32_MAX);
                if (len == 0 || len > MAX_ANNOUNCED_BYTES) {
                    throw ProtocolException.tooLarge();
                }
            }
            case RESPONSE -> {
                requireUint(control, "seq", Long.MAX_VALUE);
                if (Status.parse(requireString(control, "status")) == null) {
                    throw ProtocolException.malformed();
                }
                if (requireUint(control, "len", UINT32_MAX) > MAX_ANNOUNCED_BYTES) {
                    throw ProtocolException.tooLarge();
                }
            }
            case CLOSE -> requireString(control, "reason");
            default -> throw ProtocolException.malformed();
        }
        return control;
    }

    /** The control frame as JSON text. */
    public static String encode(JsonObject control) throws ProtocolException {
        String text = control.toString();
        if (text.getBytes(StandardCharsets.UTF_8).length > MAX_CONTROL_BYTES) {
            throw ProtocolException.tooLarge();
        }
        return text;
    }

    public static JsonObject open(int stream, String endpoint, String desktop, String label) {
        JsonObject object = new JsonObject();
        object.addProperty("type", OPEN);
        object.addProperty("stream", Integer.toUnsignedLong(stream));
        object.addProperty("endpoint", endpoint);
        if (desktop != null) {
            object.addProperty("desktop", desktop);
        }
        if (label != null) {
            object.addProperty("label", label);
        }
        return object;
    }

    public static JsonObject response(int stream, long seq, Status status, long len) {
        JsonObject object = new JsonObject();
        object.addProperty("type", RESPONSE);
        object.addProperty("stream", Integer.toUnsignedLong(stream));
        object.addProperty("seq", seq);
        object.addProperty("status", status.wire());
        object.addProperty("len", len);
        return object;
    }

    public static JsonObject close(int stream, String reason) {
        JsonObject object = new JsonObject();
        object.addProperty("type", CLOSE);
        object.addProperty("stream", Integer.toUnsignedLong(stream));
        object.addProperty("reason", reason);
        return object;
    }

    /** The envelope of a decoded {@code request} (or {@code admit}) frame. */
    public static Envelope envelope(JsonObject control) throws ProtocolException {
        return Envelope.fromJson(control.get("envelope"));
    }

    /** The announced ciphertext length of a decoded {@code request} frame. */
    public static long length(JsonObject control) {
        return control.get("len").getAsLong();
    }

    /** The policy of a decoded {@code request} frame; an absent policy allows no tool. */
    public static RelayPolicyView policy(JsonObject request) throws ProtocolException {
        JsonElement policy = request.get("policy");
        if (policy == null || policy.isJsonNull()) {
            return new RelayPolicyView(List.of(), new JsonArray());
        }
        return parsePolicy(policy);
    }

    private static RelayPolicyView parsePolicy(JsonElement element) throws ProtocolException {
        if (!element.isJsonObject()) {
            throw ProtocolException.malformed();
        }
        JsonObject object = element.getAsJsonObject();
        for (String key : object.keySet()) {
            if (!key.equals("allowedTools") && !key.equals("packageScopes")) {
                throw ProtocolException.malformed();
            }
        }
        JsonElement tools = object.get("allowedTools");
        JsonElement scopes = object.get("packageScopes");
        if (tools == null || !tools.isJsonArray() || scopes == null || !scopes.isJsonArray()
                || tools.getAsJsonArray().size() > MAX_POLICY_TOOLS) {
            throw ProtocolException.malformed();
        }
        List<String> allowed = new ArrayList<>();
        for (JsonElement tool : tools.getAsJsonArray()) {
            if (!isString(tool) || tool.getAsString().length() > MAX_TOOL_LEN) {
                throw ProtocolException.malformed();
            }
            allowed.add(tool.getAsString());
        }
        for (JsonElement layer : scopes.getAsJsonArray()) {
            if (!layer.isJsonArray()) {
                throw ProtocolException.malformed();
            }
            for (JsonElement pattern : layer.getAsJsonArray()) {
                if (!isString(pattern)) {
                    throw ProtocolException.malformed();
                }
            }
        }
        return new RelayPolicyView(List.copyOf(allowed), scopes.getAsJsonArray());
    }

    private static boolean isString(JsonElement element) {
        return element != null && element.isJsonPrimitive() && element.getAsJsonPrimitive().isString();
    }

    static String requireString(JsonObject object, String key) throws ProtocolException {
        JsonElement value = object.get(key);
        if (!isString(value)) {
            throw ProtocolException.malformed();
        }
        return value.getAsString();
    }

    /** A string, or null when absent or JSON null. */
    static String optionalString(JsonObject object, String key) throws ProtocolException {
        JsonElement value = object.get(key);
        if (value == null || value instanceof JsonNull) {
            return null;
        }
        if (!isString(value)) {
            throw ProtocolException.malformed();
        }
        return value.getAsString();
    }

    private static boolean isInteger(JsonElement value) {
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isNumber()) {
            return false;
        }
        String text = value.getAsString();
        int start = text.startsWith("-") ? 1 : 0;
        if (text.length() == start || text.length() > 20) {
            return false;
        }
        for (int i = start; i < text.length(); i++) {
            if (text.charAt(i) < '0' || text.charAt(i) > '9') {
                return false;
            }
        }
        return true;
    }

    static long requireUint(JsonObject object, String key, long max) throws ProtocolException {
        JsonElement value = object.get(key);
        if (!isInteger(value)) {
            throw ProtocolException.malformed();
        }
        try {
            long number = Long.parseLong(value.getAsString());
            if (number < 0 || number > max) {
                throw ProtocolException.malformed();
            }
            return number;
        } catch (NumberFormatException e) {
            throw ProtocolException.malformed();
        }
    }

    private static void requireInt(JsonObject object, String key) throws ProtocolException {
        JsonElement value = object.get(key);
        if (!isInteger(value)) {
            throw ProtocolException.malformed();
        }
        try {
            Integer.parseInt(value.getAsString());
        } catch (NumberFormatException e) {
            throw ProtocolException.malformed();
        }
    }

    // ------------------------------------------------------------------ data frames

    /** A decoded data frame. */
    public record DataFrame(int stream, byte[] payload) {
    }

    public static byte[] encodeData(int stream, byte[] payload) throws ProtocolException {
        if (payload.length > MAX_DATA_PAYLOAD) {
            throw ProtocolException.tooLarge();
        }
        return dataFrame(stream, payload, 0, payload.length);
    }

    /** Splits {@code bytes} into data frames of at most {@link #MAX_DATA_PAYLOAD}. */
    public static List<byte[]> encodeDataChunks(int stream, byte[] bytes) {
        List<byte[]> frames = new ArrayList<>();
        for (int offset = 0; offset < bytes.length; offset += MAX_DATA_PAYLOAD) {
            frames.add(dataFrame(stream, bytes, offset, Math.min(MAX_DATA_PAYLOAD, bytes.length - offset)));
        }
        return frames;
    }

    private static byte[] dataFrame(int stream, byte[] bytes, int offset, int length) {
        byte[] frame = new byte[5 + length];
        frame[0] = (byte) (stream >>> 24);
        frame[1] = (byte) (stream >>> 16);
        frame[2] = (byte) (stream >>> 8);
        frame[3] = (byte) stream;
        frame[4] = DATA_KIND_STREAM;
        System.arraycopy(bytes, offset, frame, 5, length);
        return frame;
    }

    /** An empty payload, a short frame and an unknown kind are malformed; an oversized payload is too large. */
    public static DataFrame decodeData(byte[] frame) throws ProtocolException {
        if (frame.length < 5) {
            throw ProtocolException.malformed();
        }
        int stream = ((frame[0] & 0xFF) << 24) | ((frame[1] & 0xFF) << 16) | ((frame[2] & 0xFF) << 8)
                | (frame[3] & 0xFF);
        int payload = frame.length - 5;
        if (frame[4] != DATA_KIND_STREAM || payload == 0) {
            throw ProtocolException.malformed();
        }
        if (payload > MAX_DATA_PAYLOAD) {
            throw ProtocolException.tooLarge();
        }
        return new DataFrame(stream, Arrays.copyOfRange(frame, 5, frame.length));
    }

    // ------------------------------------------------------------------ inner messages

    /** Prefixes an inner message with its length. */
    public static byte[] frameMessage(byte[] message, long limit) throws ProtocolException {
        if (message.length > limit) {
            throw ProtocolException.tooLarge();
        }
        byte[] framed = new byte[4 + message.length];
        int length = message.length;
        framed[0] = (byte) (length >>> 24);
        framed[1] = (byte) (length >>> 16);
        framed[2] = (byte) (length >>> 8);
        framed[3] = (byte) length;
        System.arraycopy(message, 0, framed, 4, length);
        return framed;
    }

    /** Reassembles length-prefixed inner messages from decrypted plaintext. */
    public static final class MessageReader {
        private byte[] buffer = new byte[256];
        private int size;

        public void push(byte[] plaintext) {
            push(plaintext, 0, plaintext.length);
        }

        public void push(byte[] plaintext, int offset, int length) {
            if (size + length > buffer.length) {
                buffer = Arrays.copyOf(buffer, Math.max(buffer.length * 2, size + length));
            }
            System.arraycopy(plaintext, offset, buffer, size, length);
            size += length;
        }

        /**
         * The next complete message, or null. Throws as soon as a length prefix exceeds {@code limit};
         * the stream must then be closed.
         */
        public byte[] nextMessage(long limit) throws ProtocolException {
            if (size < 4) {
                return null;
            }
            long length = ((buffer[0] & 0xFFL) << 24) | ((buffer[1] & 0xFFL) << 16) | ((buffer[2] & 0xFFL) << 8)
                    | (buffer[3] & 0xFFL);
            if (length > limit) {
                throw ProtocolException.tooLarge();
            }
            int total = 4 + (int) length;
            if (size < total) {
                return null;
            }
            byte[] message = Arrays.copyOfRange(buffer, 4, total);
            System.arraycopy(buffer, total, buffer, 0, size - total);
            size -= total;
            return message;
        }

        /** Bytes buffered but not yet returned. */
        public int pending() {
            return size;
        }
    }
}
