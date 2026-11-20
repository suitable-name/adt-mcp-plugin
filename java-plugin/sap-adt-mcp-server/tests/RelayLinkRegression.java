package com.sap.adt.mcp.server;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Regression harness for {@link RelayLink}. Runs the vectors shared with the Rust parser
 * (tests/link-vectors.json, path in args[0]) plus a few self-contained cases.
 */
public final class RelayLinkRegression {
    private static final String CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    private static final String TOKEN = token(7);
    private static final String ENDPOINT = "0123456789abcdef".repeat(4);

    public static void main(String[] args) throws Exception {
        selfContained();
        Path file = Path.of(args.length > 0 ? args[0] : "tests/link-vectors.json");
        if (Files.exists(file)) {
            vectors(file);
        } else if (args.length > 0) {
            throw new AssertionError("Vector file not found: " + file);
        } else {
            System.err.println("WARNING: " + file + " not found; shared vectors were NOT checked.");
        }
        System.out.println("RelayLinkRegression passed.");
    }

    // ------------------------------------------------------------------ shared vectors

    private static void vectors(Path file) throws Exception {
        JsonObject root = JsonParser.parseString(Files.readString(file, StandardCharsets.UTF_8)).getAsJsonObject();
        JsonArray valid = root.getAsJsonArray("valid");
        JsonArray invalid = root.getAsJsonArray("invalid");
        check(valid.size() > 0 && invalid.size() > 0);
        for (JsonElement element : valid) {
            JsonObject vector = element.getAsJsonObject();
            RelayLink link = RelayLink.parse(vector.get("link").getAsString());
            expect(vector, link);
            String rebuilt = link.build();
            RelayLink again = RelayLink.parse(rebuilt);
            expect(vector, again);
            check(rebuilt.equals(again.build()));
        }
        for (JsonElement element : invalid) {
            JsonObject vector = element.getAsJsonObject();
            String expected = vector.get("error").getAsString();
            try {
                RelayLink.parse(vector.get("link").getAsString());
                throw new AssertionError("Accepted an invalid link, expected " + expected);
            } catch (RelayLink.LinkException e) {
                if (!e.code().name().equals(expected)) {
                    throw new AssertionError("Vector " + vector.get("link") + ": expected " + expected + " but got "
                            + e.code().name());
                }
                String link = vector.get("link").getAsString().strip();
                check(link.isEmpty() || !e.getMessage().contains(link));
            }
        }
    }

    private static void expect(JsonObject vector, RelayLink link) {
        String kind = text(vector, "kind");
        check(link.kind() == (kind.equals("enroll") ? RelayLink.Kind.ENROLL : RelayLink.Kind.PAIR));
        String role = text(vector, "role");
        check(role == null ? link.role() == null : link.role().word().equals(role));
        check(vector.get("name").getAsString().equals(link.name()));
        check(eq(text(vector, "server"), link.server()));
        check(eq(text(vector, "enrollment"), link.enrollment()));
        check(eq(text(vector, "endpoint"), link.endpoint()));
        check(eq(text(vector, "label"), link.label()));
        char[] token = link.token();
        check(vector.get("token").getAsString().equals(new String(token)));
        Arrays.fill(token, '\0');
    }

    private static String text(JsonObject object, String key) {
        JsonElement value = object.get(key);
        return value == null || value.isJsonNull() ? null : value.getAsString();
    }

    // ------------------------------------------------------------------ self-contained cases

    private static void selfContained() throws Exception {
        String enroll = "sap-adt://enroll?v=1&r=eclipse&n=Gussek+Relay&s=relay.example.com:8787"
                + "&e=relay.example.com:8788&l=Anna+Laptop&t=" + TOKEN;
        RelayLink link = RelayLink.parse("  \n" + enroll + "\r\n");
        check(link.kind() == RelayLink.Kind.ENROLL && link.role() == RelayLink.Role.ECLIPSE);
        check(link.name().equals("Gussek Relay") && link.label().equals("Anna Laptop"));
        check(link.server().equals("relay.example.com:8787") && link.enrollment().equals("relay.example.com:8788"));
        check(link.bridgeUrl().equals("wss://relay.example.com:8787/bridge"));
        check(link.registrationUrl().equals("https://relay.example.com:8788"));
        check(!link.toString().contains(TOKEN) && link.toString().contains("<redacted>"));
        check(RelayLink.parse(link.build()).build().equals(link.build()));
        link.wipe();
        check(new String(link.token()).chars().allMatch(c -> c == 0));

        RelayLink pair = RelayLink.parse("sap-adt://pair?v=1&p=" + ENDPOINT + "&n=Eclipse%20Laptop&t=" + TOKEN);
        check(pair.kind() == RelayLink.Kind.PAIR && pair.role() == null && pair.endpoint().equals(ENDPOINT));
        check(pair.name().equals("Eclipse Laptop"));

        // Unknown keys are skipped, the fragment is dropped, the scheme is case-insensitive.
        check(RelayLink.parse("SAP-ADT://Pair?v=1&x=1&x=2&p=" + ENDPOINT + "&t=" + TOKEN + "#frag")
                .endpoint().equals(ENDPOINT));
        // Hosts: IPv4 and bracketed IPv6.
        check(RelayLink.parse(enroll.replace("relay.example.com:8787", "10.0.0.5:8787")).server().equals("10.0.0.5:8787"));
        check(RelayLink.parse(enroll.replace("relay.example.com:8787", "[::1]:8787")).server().equals("[::1]:8787"));
        // A name with a non-ASCII character survives the round trip.
        RelayLink umlaut = RelayLink.enroll(RelayLink.Role.DESKTOP, "Rüssel", "h.test:1", "h.test:65535", null,
                TOKEN.toCharArray());
        check(RelayLink.parse(umlaut.build()).name().equals("Rüssel"));

        reject(enroll.replace("v=1", "v=2"), RelayLink.ErrorCode.NeedsNewerVersion);
        reject("v=2&garbage", RelayLink.ErrorCode.NotALink);
        reject("sap-adt://enroll?r=eclipse&t=x", RelayLink.ErrorCode.MissingPart);
        reject("https://example.com", RelayLink.ErrorCode.NotALink);
        reject(enroll + "&padding=" + "a".repeat(2100), RelayLink.ErrorCode.TooLong);
        reject(enroll + "&s=relay.example.com:1", RelayLink.ErrorCode.RepeatedPart);
        reject(enroll.replace("r=eclipse", "r=admin"), RelayLink.ErrorCode.UnknownRole);
        reject(enroll.replace("Gussek+Relay", "Bad%0AName"), RelayLink.ErrorCode.BadName);
        reject(enroll.replace("Gussek+Relay", "a".repeat(65)), RelayLink.ErrorCode.BadName);
        reject(enroll.replace("Gussek+Relay", "%ZZ"), RelayLink.ErrorCode.BadEncoding);
        reject(enroll.replace("relay.example.com:8787", "relay.example.com"), RelayLink.ErrorCode.BadAddress);
        reject(enroll.replace("relay.example.com:8787", "[::1]"), RelayLink.ErrorCode.BadAddress);
        reject(enroll.replace("relay.example.com:8787", "relay.example.com:0"), RelayLink.ErrorCode.BadPort);
        reject(enroll.replace("relay.example.com:8787", "relay.example.com:65536"), RelayLink.ErrorCode.BadPort);
        reject(enroll.replace("&t=" + TOKEN, ""), RelayLink.ErrorCode.MissingToken);
        reject(enroll.replace(TOKEN, "GW1-ABC"), RelayLink.ErrorCode.BadToken);
        reject(enroll.replace(TOKEN, TOKEN.substring(4)), RelayLink.ErrorCode.BadToken);
        reject("sap-adt://pair?v=1&p=" + ENDPOINT.toUpperCase() + "&t=" + TOKEN, RelayLink.ErrorCode.BadEndpoint);
        reject("sap-adt://pair?v=1&p=abcd&t=" + TOKEN, RelayLink.ErrorCode.BadEndpoint);
        reject("sap-adt://pair?v=1&t=" + TOKEN, RelayLink.ErrorCode.MissingPart);
    }

    private static void reject(String link, RelayLink.ErrorCode expected) {
        try {
            RelayLink.parse(link);
            throw new AssertionError("Accepted: expected " + expected);
        } catch (RelayLink.LinkException e) {
            if (e.code() != expected) throw new AssertionError("Expected " + expected + " but got " + e.code());
            // The message never echoes the link; it may name the scheme in plain words.
            check(!e.getMessage().contains(TOKEN) && !e.getMessage().contains("sap-adt://"));
        }
    }

    /** A well-formed token: GW1- plus Crockford Base32 of 64 bytes; {@code seed} varies the bytes. */
    static String token(int seed) {
        byte[] payload = new byte[64];
        for (int i = 0; i < payload.length; i++) payload[i] = (byte) (seed * 31 + i * 7 + 3);
        StringBuilder out = new StringBuilder("GW1-");
        int accumulator = 0;
        int bits = 0;
        for (byte b : payload) {
            accumulator = (accumulator << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                out.append(CROCKFORD.charAt((accumulator >> bits) & 31));
            }
            accumulator &= (1 << bits) - 1;
        }
        if (bits > 0) out.append(CROCKFORD.charAt((accumulator << (5 - bits)) & 31));
        return out.toString();
    }

    private static boolean eq(String a, String b) {
        return a == null ? b == null : a.equals(b);
    }

    private static void check(boolean condition) {
        if (!condition) throw new AssertionError();
    }
}
