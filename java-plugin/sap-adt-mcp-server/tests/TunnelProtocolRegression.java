package com.sap.adt.mcp.server.e2e;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.google.gson.JsonObject;
import com.sap.adt.mcp.server.e2e.TunnelProtocol.Envelope;
import com.sap.adt.mcp.server.e2e.TunnelProtocol.MessageReader;
import com.sap.adt.mcp.server.e2e.TunnelProtocol.ProtocolException;
import com.sap.adt.mcp.server.e2e.TunnelProtocol.ProtocolException.Kind;
import com.sap.adt.mcp.tools.ToolClass;

/**
 * Regression harness for {@link TunnelProtocol}. The golden frames are copied from the Rust tests in
 * {@code src/tunnel_proto.rs} and must round-trip byte for byte.
 */
public final class TunnelProtocolRegression {
    /** Golden control frames, shared with the Rust tests. */
    private static final String[] GOLDEN = {
        "{\"type\":\"open\",\"stream\":1,\"endpoint\":\"aa\"}",
        "{\"type\":\"open\",\"stream\":7,\"endpoint\":\"aa\",\"desktop\":\"bb\",\"label\":\"Laptop\"}",
        "{\"type\":\"admit\",\"stream\":1,\"envelope\":{\"v\":1,\"seq\":3,\"method\":\"tools/call\",\"tool\":\"sap_get_source\",\"class\":\"read\"}}",
        "{\"type\":\"admitted\",\"stream\":1,\"seq\":3}",
        "{\"type\":\"denied\",\"stream\":1,\"seq\":3,\"code\":-32001,\"message\":\"Denied by the relay.\"}",
        "{\"type\":\"request\",\"stream\":1,\"envelope\":{\"v\":1,\"seq\":3,\"method\":\"tools/list\"},\"policy\":{\"allowedTools\":[\"sap_get_source\"],\"packageScopes\":[[\"Z*\"]]},\"len\":512}",
        "{\"type\":\"response\",\"stream\":1,\"seq\":3,\"status\":\"ok\",\"len\":900}",
        "{\"type\":\"close\",\"stream\":1,\"reason\":\"done\"}",
    };

    private interface Action {
        void run() throws Exception;
    }

    public static void main(String[] args) throws Exception {
        goldenFramesRoundTripByteForByte();
        builtFramesMatchTheGoldenText();
        envelopesFollowTheSchemaRules();
        announcedLengthsAndFrameSizesAreBounded();
        dataFramesAndInnerMessagesRoundTrip();
        randomInputNeverThrowsAnythingButProtocolErrors();
        System.out.println("TunnelProtocolRegression passed.");
    }

    private static void goldenFramesRoundTripByteForByte() throws Exception {
        for (String text : GOLDEN) {
            JsonObject control = TunnelProtocol.decode(text);
            check(TunnelProtocol.encode(control).equals(text));
        }
        JsonObject request = TunnelProtocol.decode(GOLDEN[5]);
        check(TunnelProtocol.stream(request) == 1);
        check(TunnelProtocol.length(request) == 512);
        Envelope envelope = TunnelProtocol.envelope(request);
        check(envelope.equals(Envelope.of(3, "tools/list")));
        RelayPolicyView policy = TunnelProtocol.policy(request);
        check(policy.allowedTools().equals(List.of("sap_get_source")));
        check(policy.packageScopes().toString().equals("[[\"Z*\"]]"));
        Envelope call = TunnelProtocol.envelope(TunnelProtocol.decode(GOLDEN[2]));
        check(call.equals(Envelope.of(3, "tools/call", "sap_get_source", ToolClass.READ)));
        check(TunnelProtocol.policy(TunnelProtocol.decode(GOLDEN[1])).allowedTools().isEmpty());
    }

    private static void builtFramesMatchTheGoldenText() throws Exception {
        check(TunnelProtocol.encode(TunnelProtocol.open(1, "aa", null, null)).equals(GOLDEN[0]));
        check(TunnelProtocol.encode(TunnelProtocol.open(7, "aa", "bb", "Laptop")).equals(GOLDEN[1]));
        check(TunnelProtocol.encode(TunnelProtocol.response(1, 3, TunnelProtocol.Status.OK, 900)).equals(GOLDEN[6]));
        check(TunnelProtocol.encode(TunnelProtocol.close(1, "done")).equals(GOLDEN[7]));
        check(TunnelProtocol.encode(TunnelProtocol.response(1, 3, TunnelProtocol.Status.DENIED, 5))
                .equals("{\"type\":\"response\",\"stream\":1,\"seq\":3,\"status\":\"denied\",\"len\":5}"));
        // A stream ID above Integer.MAX_VALUE is an unsigned 32-bit value on the wire.
        JsonObject high = TunnelProtocol.close(0xFFFF_FFFF, "x");
        check(TunnelProtocol.encode(high).equals("{\"type\":\"close\",\"stream\":4294967295,\"reason\":\"x\"}"));
        check(TunnelProtocol.stream(TunnelProtocol.decode(TunnelProtocol.encode(high))) == -1);
        check(TunnelProtocol.encode(Envelope.of(3, "tools/call", "sap_get_source", ToolClass.READ).toJson())
                .equals("{\"v\":1,\"seq\":3,\"method\":\"tools/call\",\"tool\":\"sap_get_source\",\"class\":\"read\"}"));
    }

    private static void envelopesFollowTheSchemaRules() throws Exception {
        Envelope.of(1, "tools/call", "sap_set_source", ToolClass.WRITE).validate();
        Envelope.of(2, "tools/list").validate();
        Envelope.of(3, "notifications/initialized").validate();
        Envelope.of(4, "pair/claim").validate();
        Envelope.of(5, "initialize").validate();
        Envelope.of(6, "ping").validate();
        check(Envelope.of(3, "notifications/initialized").isNotification());
        check(!Envelope.of(2, "tools/list").isNotification());
        List<Envelope> bad = List.of(
                Envelope.of(5, "tools/call"),
                Envelope.of(6, "tools/list", "sap_get_source", ToolClass.READ),
                Envelope.of(7, "resources/read"),
                Envelope.of(8, "notifications/"),
                Envelope.of(9, "tools/call", "Bad-Tool", ToolClass.READ),
                Envelope.of(9, "tools/call", "", ToolClass.READ),
                Envelope.of(9, "tools/call", "a".repeat(65), ToolClass.READ),
                Envelope.of(9, "tools/call", "sap_get_source", null),
                new Envelope(2, 10, "ping", null, null));
        for (Envelope envelope : bad) {
            expect(envelope::validate, Kind.BAD_ENVELOPE);
        }
        String unknownField = "{\"type\":\"admit\",\"stream\":1,\"envelope\":{\"v\":1,\"seq\":1,\"method\":\"ping\",\"object\":\"Z\"}}";
        expect(() -> TunnelProtocol.decode(unknownField), Kind.MALFORMED);
        String badClass = "{\"type\":\"admit\",\"stream\":1,\"envelope\":{\"v\":1,\"seq\":1,\"method\":\"tools/call\",\"tool\":\"sap_get_source\",\"class\":\"admin\"}}";
        expect(() -> TunnelProtocol.decode(badClass), Kind.MALFORMED);
        String missingTool = "{\"type\":\"admit\",\"stream\":1,\"envelope\":{\"v\":1,\"seq\":1,\"method\":\"tools/call\"}}";
        expect(() -> TunnelProtocol.decode(missingTool), Kind.BAD_ENVELOPE);
        expect(() -> TunnelProtocol.decode("{\"type\":\"nope\",\"stream\":1}"), Kind.MALFORMED);
        expect(() -> TunnelProtocol.decode("{\"type\":\"close\",\"stream\":-1,\"reason\":\"x\"}"), Kind.MALFORMED);
        expect(() -> TunnelProtocol.decode("{\"type\":\"close\",\"stream\":4294967296,\"reason\":\"x\"}"), Kind.MALFORMED);
        expect(() -> TunnelProtocol.decode("{\"type\":\"close\",\"stream\":1.5,\"reason\":\"x\"}"), Kind.MALFORMED);
        expect(() -> TunnelProtocol.decode("{\"type\":\"close\",\"stream\":1}"), Kind.MALFORMED);
        expect(() -> TunnelProtocol.decode("not json"), Kind.MALFORMED);
        expect(() -> TunnelProtocol.decode("[]"), Kind.MALFORMED);
        expect(() -> TunnelProtocol.decode(""), Kind.MALFORMED);
        String badStatus = "{\"type\":\"response\",\"stream\":1,\"seq\":1,\"status\":\"maybe\",\"len\":1}";
        expect(() -> TunnelProtocol.decode(badStatus), Kind.MALFORMED);
        String badPolicy = "{\"type\":\"request\",\"stream\":1,\"envelope\":{\"v\":1,\"seq\":1,\"method\":\"ping\"},\"policy\":{\"allowedTools\":[],\"packageScopes\":[],\"extra\":1},\"len\":4}";
        expect(() -> TunnelProtocol.decode(badPolicy), Kind.MALFORMED);
    }

    private static void announcedLengthsAndFrameSizesAreBounded() throws Exception {
        String zero = "{\"type\":\"request\",\"stream\":1,\"envelope\":{\"v\":1,\"seq\":1,\"method\":\"ping\"},\"len\":0}";
        expect(() -> TunnelProtocol.decode(zero), Kind.TOO_LARGE);
        String huge = "{\"type\":\"response\",\"stream\":1,\"seq\":1,\"status\":\"ok\",\"len\":"
                + (TunnelProtocol.MAX_ANNOUNCED_BYTES + 1) + "}";
        expect(() -> TunnelProtocol.decode(huge), Kind.TOO_LARGE);
        String atLimit = "{\"type\":\"response\",\"stream\":1,\"seq\":1,\"status\":\"ok\",\"len\":"
                + TunnelProtocol.MAX_ANNOUNCED_BYTES + "}";
        TunnelProtocol.decode(atLimit);
        check(TunnelProtocol.MAX_ANNOUNCED_BYTES == 8_523_776L);
        String oversizedControl = "{\"type\":\"close\",\"stream\":1,\"reason\":\""
                + "x".repeat(TunnelProtocol.MAX_CONTROL_BYTES) + "\"}";
        expect(() -> TunnelProtocol.decode(oversizedControl), Kind.TOO_LARGE);
        expect(() -> TunnelProtocol.encode(TunnelProtocol.close(1, "x".repeat(TunnelProtocol.MAX_CONTROL_BYTES))),
                Kind.TOO_LARGE);
        expect(() -> TunnelProtocol.encodeData(1, new byte[TunnelProtocol.MAX_DATA_PAYLOAD + 1]), Kind.TOO_LARGE);
        expect(() -> TunnelProtocol.decodeData(new byte[] {0, 0, 0, 1, 0}), Kind.MALFORMED);
        expect(() -> TunnelProtocol.decodeData(new byte[] {0, 0, 0, 1}), Kind.MALFORMED);
        expect(() -> TunnelProtocol.decodeData(new byte[] {0, 0, 0, 1, 9, 1}), Kind.MALFORMED);
        byte[] big = new byte[5 + TunnelProtocol.MAX_DATA_PAYLOAD + 1];
        big[3] = 1;
        big[5] = 1;
        expect(() -> TunnelProtocol.decodeData(big), Kind.TOO_LARGE);
        byte[] frame = TunnelProtocol.encodeData(0x0102_0304, new byte[] {9, 8});
        check(Arrays.equals(frame, new byte[] {1, 2, 3, 4, 0, 9, 8}));
        TunnelProtocol.DataFrame decoded = TunnelProtocol.decodeData(frame);
        check(decoded.stream() == 0x0102_0304 && Arrays.equals(decoded.payload(), new byte[] {9, 8}));
    }

    private static void dataFramesAndInnerMessagesRoundTrip() throws Exception {
        byte[] bytes = new byte[TunnelProtocol.MAX_DATA_PAYLOAD * 2 + 5];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) i;
        }
        List<byte[]> frames = TunnelProtocol.encodeDataChunks(9, bytes);
        check(frames.size() == 3);
        java.io.ByteArrayOutputStream joined = new java.io.ByteArrayOutputStream();
        for (byte[] frame : frames) {
            TunnelProtocol.DataFrame data = TunnelProtocol.decodeData(frame);
            check(data.stream() == 9);
            joined.write(data.payload());
        }
        check(Arrays.equals(joined.toByteArray(), bytes));
        check(TunnelProtocol.encodeDataChunks(9, new byte[0]).isEmpty());

        MessageReader reader = new MessageReader();
        byte[] first = TunnelProtocol.frameMessage("{\"a\":1}".getBytes(StandardCharsets.UTF_8), 100);
        byte[] second = TunnelProtocol.frameMessage("{}".getBytes(StandardCharsets.UTF_8), 100);
        byte[] framed = new byte[first.length + second.length];
        System.arraycopy(first, 0, framed, 0, first.length);
        System.arraycopy(second, 0, framed, first.length, second.length);
        for (byte b : framed) {
            reader.push(new byte[] {b});
        }
        check(new String(reader.nextMessage(100), StandardCharsets.UTF_8).equals("{\"a\":1}"));
        check(new String(reader.nextMessage(100), StandardCharsets.UTF_8).equals("{}"));
        check(reader.nextMessage(100) == null && reader.pending() == 0);
        reader.push(new byte[] {0, 0, 3, (byte) 0xE8});
        expect(() -> reader.nextMessage(100), Kind.TOO_LARGE);
        expect(() -> TunnelProtocol.frameMessage(new byte[101], 100), Kind.TOO_LARGE);
        // An empty message is a valid frame.
        MessageReader empty = new MessageReader();
        empty.push(TunnelProtocol.frameMessage(new byte[0], 100));
        check(empty.nextMessage(100).length == 0);
    }

    private static void randomInputNeverThrowsAnythingButProtocolErrors() throws Exception {
        long state = 0x9E37_79B9_7F4A_7C15L;
        for (int i = 0; i < 4000; i++) {
            byte[] bytes = new byte[(int) Long.remainderUnsigned(state = next(state), 96)];
            for (int j = 0; j < bytes.length; j++) {
                state = next(state);
                bytes[j] = (byte) state;
            }
            try {
                TunnelProtocol.decodeData(bytes);
            } catch (ProtocolException e) {
                // expected
            }
            try {
                TunnelProtocol.decode(new String(bytes, StandardCharsets.UTF_8));
            } catch (ProtocolException e) {
                // expected
            }
            MessageReader reader = new MessageReader();
            reader.push(bytes);
            try {
                reader.nextMessage(64);
            } catch (ProtocolException e) {
                // expected
            }
        }
        // Mutations of real frames must not escape as other exceptions either.
        List<String> mutants = new ArrayList<>();
        for (String text : GOLDEN) {
            for (int cut = 0; cut < text.length(); cut += 3) {
                mutants.add(text.substring(0, cut));
                mutants.add(text.substring(0, cut) + "}" + text.substring(cut));
            }
        }
        for (String mutant : mutants) {
            try {
                TunnelProtocol.decode(mutant);
            } catch (ProtocolException e) {
                // expected
            }
        }
    }

    private static long next(long state) {
        state ^= state << 13;
        state ^= state >>> 7;
        state ^= state << 17;
        return state;
    }

    private static void expect(Action action, Kind kind) throws Exception {
        try {
            action.run();
        } catch (ProtocolException e) {
            check(e.kind() == kind);
            return;
        }
        throw new AssertionError("Expected " + kind);
    }

    private static void check(boolean condition) {
        if (!condition) {
            throw new AssertionError("Tunnel protocol regression.");
        }
    }
}
