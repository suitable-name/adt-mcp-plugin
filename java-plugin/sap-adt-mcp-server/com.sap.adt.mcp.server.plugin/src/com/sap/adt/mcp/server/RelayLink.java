package com.sap.adt.mcp.server;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * One-time links: {@code sap-adt://enroll?...} (relay operator to desktop or Eclipse) and
 * {@code sap-adt://pair?...} (Eclipse to desktop). The rules match the Rust parser in
 * {@code src/link.rs}.
 *
 * <pre>
 * sap-adt://enroll?v=1&amp;r=eclipse&amp;n=Gussek+Relay&amp;s=relay.example.com:8787&amp;e=relay.example.com:8788&amp;t=GW1-...
 * sap-adt://pair?v=1&amp;p=&lt;64 lowercase hex&gt;&amp;n=EclipseLaptop&amp;t=GW1-...
 * </pre>
 *
 * The token is a bearer secret. It is kept in a {@code char[]} that {@link #wipe()} clears,
 * {@link #toString()} redacts it, and no {@link LinkException} message contains link text. The
 * pasted {@code String} the caller parsed from cannot be cleared by this class.
 */
public final class RelayLink {
    public static final int VERSION = 1;
    public static final int MAX_LINK_LENGTH = 2048;
    public static final int MAX_NAME_BYTES = 64;
    public static final int MAX_TOKEN_LENGTH = 256;
    private static final String ENROLL_PREFIX = "sap-adt://enroll?";
    private static final String PAIR_PREFIX = "sap-adt://pair?";
    private static final String TOKEN_TAG = "GW1-";
    private static final String CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    private static final char[] HEX_UPPER = "0123456789ABCDEF".toCharArray();

    public enum Kind { ENROLL, PAIR }

    public enum Role {
        DESKTOP("desktop"), ECLIPSE("eclipse");

        private final String word;

        Role(String word) { this.word = word; }

        public String word() { return word; }

        static Role fromWord(String word) {
            for (Role role : values()) {
                if (role.word.equals(word)) return role;
            }
            return null;
        }
    }

    /** The names are the shared error codes of the link vectors. */
    public enum ErrorCode {
        NotALink("This is not an sap-adt link."),
        TooLong("This link is too long to be real."),
        NeedsNewerVersion("This link needs a newer version of this software."),
        MissingPart("This link is incomplete."),
        RepeatedPart("This link repeats a part that should appear once."),
        UnknownRole("This link names a role this software does not know."),
        BadName("This link has an unusable name."),
        BadAddress("This link has an address that is not written host:port."),
        BadPort("This link has an unusable port."),
        MissingToken("This link has no code in it."),
        BadToken("This link has a code that is not shaped right."),
        BadEndpoint("This link has an unusable endpoint ID."),
        BadEncoding("This link is damaged.");

        private final String message;

        ErrorCode(String message) { this.message = message; }

        public String message() { return message; }
    }

    /** The message is a plain sentence generated locally and never contains any text of the link. */
    public static final class LinkException extends Exception {
        private static final long serialVersionUID = 1L;
        private final ErrorCode code;

        LinkException(ErrorCode code) {
            super(code.message());
            this.code = code;
        }

        public ErrorCode code() { return code; }
    }

    private final Kind kind;
    private final Role role;
    private final String name;
    private final String server;
    private final String enrollment;
    private final String endpoint;
    private final String label;
    private final char[] token;

    private RelayLink(Kind kind, Role role, String name, String server, String enrollment, String endpoint,
            String label, char[] token) {
        this.kind = kind;
        this.role = role;
        this.name = name;
        this.server = server;
        this.enrollment = enrollment;
        this.endpoint = endpoint;
        this.label = label;
        this.token = token;
    }

    /** An enrollment link. Nothing is checked until {@link #build()}. The token array is copied. */
    public static RelayLink enroll(Role role, String name, String server, String enrollment, String label,
            char[] token) {
        return new RelayLink(Kind.ENROLL, role, name, server, enrollment, null, label, token.clone());
    }

    /** A pairing link. Nothing is checked until {@link #build()}. The token array is copied. */
    public static RelayLink pair(String endpoint, String name, char[] token) {
        return new RelayLink(Kind.PAIR, null, name, null, null, endpoint, null, token.clone());
    }

    public Kind kind() { return kind; }

    /** Enroll links only; {@code null} for a pair link. */
    public Role role() { return role; }

    public String name() { return name; }

    /** Enroll links only: the data address {@code host:port} (key {@code s}). */
    public String server() { return server; }

    /** Enroll links only: the enrollment address {@code host:port} (key {@code e}). */
    public String enrollment() { return enrollment; }

    /** Pair links only: the 64 lowercase hex endpoint ID (key {@code p}). */
    public String endpoint() { return endpoint; }

    /** Enroll links only, optional. */
    public String label() { return label; }

    /** A copy of the token characters. A secret: clear the copy after use. */
    public char[] token() { return token.clone(); }

    /** The data (mTLS) bridge URL derived from {@code s}. */
    public String bridgeUrl() { return "wss://" + server + "/bridge"; }

    /** The enrollment origin derived from {@code e}. */
    public String registrationUrl() { return "https://" + enrollment; }

    /** Clears the token. The link is unusable for {@link #build()} afterwards. */
    public void wipe() { Arrays.fill(token, '\0'); }

    @Override
    public String toString() {
        return "RelayLink[kind=" + kind + ", role=" + role + ", name=" + name + ", server=" + server
                + ", enrollment=" + enrollment + ", endpoint=" + endpoint + ", label=" + label
                + ", token=<redacted>]";
    }

    // ------------------------------------------------------------------ build

    /** Writes the link. The result contains the token: keep it out of logs. */
    public String build() throws LinkException {
        checkName(name);
        String tokenText = new String(token);
        checkToken(tokenText);
        StringBuilder out = new StringBuilder(160 + tokenText.length());
        if (kind == Kind.ENROLL) {
            if (role == null) throw new LinkException(ErrorCode.MissingPart);
            checkHostPort(server);
            checkHostPort(enrollment);
            if (label != null) checkName(label);
            out.append(ENROLL_PREFIX).append("v=").append(VERSION).append("&r=").append(role.word())
                    .append("&n=");
            encode(out, name == null ? "" : name);
            out.append("&s=");
            encode(out, server);
            out.append("&e=");
            encode(out, enrollment);
            if (label != null) {
                out.append("&l=");
                encode(out, label);
            }
        } else {
            checkEndpoint(endpoint);
            out.append(PAIR_PREFIX).append("v=").append(VERSION).append("&p=").append(endpoint).append("&n=");
            encode(out, name == null ? "" : name);
        }
        out.append("&t=").append(tokenText);
        return out.toString();
    }

    // ------------------------------------------------------------------ parse

    /**
     * Reads a link. Surrounding whitespace (and line breaks from pasting) is ignored, the scheme
     * is matched without regard to case and anything after a {@code #} is dropped. Unknown keys
     * are skipped; known keys may not repeat. The version is checked first.
     */
    public static RelayLink parse(CharSequence input) throws LinkException {
        String text = input.toString().strip();
        if (text.codePointCount(0, text.length()) > MAX_LINK_LENGTH) throw new LinkException(ErrorCode.TooLong);
        Kind kind;
        String query;
        if (text.regionMatches(true, 0, ENROLL_PREFIX, 0, ENROLL_PREFIX.length())) {
            kind = Kind.ENROLL;
            query = text.substring(ENROLL_PREFIX.length());
        } else if (text.regionMatches(true, 0, PAIR_PREFIX, 0, PAIR_PREFIX.length())) {
            kind = Kind.PAIR;
            query = text.substring(PAIR_PREFIX.length());
        } else {
            throw new LinkException(ErrorCode.NotALink);
        }
        int hash = query.indexOf('#');
        if (hash >= 0) query = query.substring(0, hash);

        String version = null;
        String r = null;
        String n = null;
        String s = null;
        String e = null;
        String l = null;
        String p = null;
        String t = null;
        boolean seenV = false;
        boolean seenR = false;
        boolean seenN = false;
        boolean seenS = false;
        boolean seenE = false;
        boolean seenL = false;
        boolean seenP = false;
        boolean seenT = false;
        for (String pair : query.split("&", -1)) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            String key = eq < 0 ? pair : pair.substring(0, eq);
            String value = eq < 0 ? "" : pair.substring(eq + 1);
            boolean enroll = kind == Kind.ENROLL;
            switch (key) {
                case "v" -> { if (seenV) throw repeated(); seenV = true; version = value; }
                case "n" -> { if (seenN) throw repeated(); seenN = true; n = value; }
                case "t" -> { if (seenT) throw repeated(); seenT = true; t = value; }
                case "r" -> { if (enroll) { if (seenR) throw repeated(); seenR = true; r = value; } }
                case "s" -> { if (enroll) { if (seenS) throw repeated(); seenS = true; s = value; } }
                case "e" -> { if (enroll) { if (seenE) throw repeated(); seenE = true; e = value; } }
                case "l" -> { if (enroll) { if (seenL) throw repeated(); seenL = true; l = value; } }
                case "p" -> { if (!enroll) { if (seenP) throw repeated(); seenP = true; p = value; } }
                default -> { }
            }
        }

        if (version == null) throw new LinkException(ErrorCode.MissingPart);
        boolean digits = !version.isEmpty() && version.chars().allMatch(c -> c >= '0' && c <= '9');
        if (!digits) throw new LinkException(ErrorCode.MissingPart);
        String trimmed = version.replaceFirst("^0+(?=.)", "");
        if (!trimmed.equals(Integer.toString(VERSION))) throw new LinkException(ErrorCode.NeedsNewerVersion);

        if (kind == Kind.ENROLL) {
            if (r == null) throw new LinkException(ErrorCode.MissingPart);
            Role role = Role.fromWord(r);
            if (role == null) throw new LinkException(ErrorCode.UnknownRole);
            String name = n == null ? "" : decode(n);
            checkName(name);
            // Same check order as `parse_enroll` in src/link.rs, so both report the same first error.
            if (s == null) throw new LinkException(ErrorCode.MissingPart);
            String server = decode(s);
            checkHostPort(server);
            if (e == null) throw new LinkException(ErrorCode.MissingPart);
            String enrollment = decode(e);
            checkHostPort(enrollment);
            String label = null;
            if (l != null) {
                label = decode(l);
                checkName(label);
            }
            if (t == null) throw new LinkException(ErrorCode.MissingToken);
            checkToken(t);
            return new RelayLink(Kind.ENROLL, role, name, server, enrollment, null, label, t.toCharArray());
        }
        // Same check order as `parse_pair` in src/link.rs: the endpoint before the name.
        if (p == null) throw new LinkException(ErrorCode.MissingPart);
        checkEndpoint(p);
        String name = n == null ? "" : decode(n);
        checkName(name);
        if (t == null) throw new LinkException(ErrorCode.MissingToken);
        checkToken(t);
        return new RelayLink(Kind.PAIR, null, name, null, null, p, null, t.toCharArray());
    }

    private static LinkException repeated() {
        return new LinkException(ErrorCode.RepeatedPart);
    }

    // ------------------------------------------------------------------ checks

    private static void checkName(String value) throws LinkException {
        if (value == null) return;
        if (value.getBytes(StandardCharsets.UTF_8).length > MAX_NAME_BYTES
                || value.codePoints().anyMatch(c -> Character.getType(c) == Character.CONTROL)) {
            throw new LinkException(ErrorCode.BadName);
        }
    }

    private static void checkEndpoint(String value) throws LinkException {
        if (value == null || value.length() != 64
                || !value.chars().allMatch(c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            throw new LinkException(ErrorCode.BadEndpoint);
        }
    }

    /** {@code GW1-} plus letters, digits and hyphens that decode to the 64-byte payload. */
    private static void checkToken(String value) throws LinkException {
        if (value == null || value.isEmpty()) throw new LinkException(ErrorCode.MissingToken);
        if (!value.startsWith(TOKEN_TAG) || value.length() == TOKEN_TAG.length()
                || value.length() > MAX_TOKEN_LENGTH
                || !value.substring(TOKEN_TAG.length()).chars()
                        .allMatch(c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')
                                || (c >= 'A' && c <= 'Z') || c == '-')) {
            throw new LinkException(ErrorCode.BadToken);
        }
        byte[] payload = decodeToken(value);
        if (payload == null) throw new LinkException(ErrorCode.BadToken);
        Arrays.fill(payload, (byte) 0);
    }

    /**
     * Decodes {@code GW1-} plus Crockford Base32 into the 64-byte payload (32-byte secret followed
     * by the 32-byte SHA-256 fingerprint), or returns {@code null} when the token is malformed.
     * The caller owns, and should clear, the returned array.
     */
    public static byte[] decodeToken(CharSequence token) {
        if (token.length() > MAX_TOKEN_LENGTH || token.length() < 3
                || !token.subSequence(0, 3).toString().equalsIgnoreCase("GW1")) {
            return null;
        }
        byte[] payload = new byte[64];
        int accumulator = 0;
        int bits = 0;
        int length = 0;
        for (int i = 3; i < token.length(); i++) {
            char symbol = token.charAt(i);
            if (symbol == '-' || symbol == ' ' || symbol == '\t' || symbol == '\n' || symbol == '\r'
                    || symbol == '\f') {
                continue;
            }
            int value = switch (symbol) {
                case 'O', 'o' -> 0;
                case 'I', 'i', 'L', 'l' -> 1;
                default -> symbol > 127 ? -1 : CROCKFORD.indexOf(Character.toUpperCase(symbol));
            };
            if (value < 0) {
                Arrays.fill(payload, (byte) 0);
                return null;
            }
            accumulator = ((accumulator << 5) | value) & 0xFFFF;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                if (length >= 64) {
                    Arrays.fill(payload, (byte) 0);
                    return null;
                }
                payload[length++] = (byte) (accumulator >> bits);
            }
        }
        if (length != 64 || bits != 3 || (accumulator & 7) != 0) {
            Arrays.fill(payload, (byte) 0);
            return null;
        }
        return payload;
    }

    /**
     * Encodes a 64-byte payload (32-byte secret followed by a 32-byte fingerprint) as {@code GW1-} plus
     * Crockford Base32. The inverse of {@link #decodeToken}. The result is a secret.
     */
    public static char[] encodeToken(byte[] payload) {
        if (payload.length != 64) throw new IllegalArgumentException("A token payload is 64 bytes.");
        StringBuilder out = new StringBuilder(TOKEN_TAG);
        int accumulator = 0;
        int bits = 0;
        for (byte b : payload) {
            accumulator = ((accumulator << 8) | (b & 0xFF)) & 0xFFFF;
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                out.append(CROCKFORD.charAt((accumulator >> bits) & 31));
            }
        }
        if (bits > 0) out.append(CROCKFORD.charAt((accumulator << (5 - bits)) & 31));
        char[] token = new char[out.length()];
        out.getChars(0, out.length(), token, 0);
        out.setLength(0);
        return token;
    }

    /** The CA (or inner key) fingerprint half of a token, or {@code null} when malformed. */
    public static byte[] tokenFingerprint(CharSequence token) {
        byte[] payload = decodeToken(token);
        if (payload == null) return null;
        byte[] fingerprint = Arrays.copyOfRange(payload, 32, 64);
        Arrays.fill(payload, (byte) 0);
        return fingerprint;
    }

    /** {@code host:port}; hosts are DNS names, IPv4 or bracketed IPv6; ports 1 to 65535. */
    private static void checkHostPort(String value) throws LinkException {
        if (value == null || value.isEmpty()) throw new LinkException(ErrorCode.BadAddress);
        String host;
        String port;
        if (value.charAt(0) == '[') {
            int close = value.indexOf(']');
            if (close < 0 || close + 1 >= value.length() || value.charAt(close + 1) != ':') {
                throw new LinkException(ErrorCode.BadAddress);
            }
            host = value.substring(1, close);
            port = value.substring(close + 2);
            if (!validIpv6(host)) throw new LinkException(ErrorCode.BadAddress);
        } else {
            int colon = value.lastIndexOf(':');
            if (colon <= 0) throw new LinkException(ErrorCode.BadAddress);
            host = value.substring(0, colon);
            port = value.substring(colon + 1);
            if (host.indexOf(':') >= 0 || !validDnsOrIpv4(host)) throw new LinkException(ErrorCode.BadAddress);
        }
        if (port.isEmpty() || port.length() > 5 || !port.chars().allMatch(c -> c >= '0' && c <= '9')
                || Integer.parseInt(port) < 1 || Integer.parseInt(port) > 65535) {
            throw new LinkException(ErrorCode.BadPort);
        }
    }

    private static boolean validIpv6(String host) {
        if (host.isEmpty() || host.indexOf(':') < 0
                || !host.chars().allMatch(c -> c == ':' || c == '.' || (c >= '0' && c <= '9')
                        || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return false;
        }
        try {
            // A literal containing ':' is parsed locally; no name lookup happens.
            return InetAddress.getByName(host) != null;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    private static boolean validDnsOrIpv4(String host) {
        if (host.isEmpty() || host.length() > 253) return false;
        if (host.chars().allMatch(c -> c == '.' || (c >= '0' && c <= '9'))) {
            String[] octets = host.split("\\.", -1);
            if (octets.length != 4) return false;
            for (String octet : octets) {
                if (octet.isEmpty() || octet.length() > 3 || Integer.parseInt(octet) > 255) return false;
            }
            return true;
        }
        for (String part : host.split("\\.", -1)) {
            if (part.isEmpty() || part.length() > 63 || part.startsWith("-") || part.endsWith("-")
                    || !part.chars().allMatch(c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')
                            || (c >= 'A' && c <= 'Z') || c == '-' || c == '_')) {
                return false;
            }
        }
        return true;
    }

    // ------------------------------------------------------------------ percent-encoding

    private static void encode(StringBuilder out, String text) {
        for (byte b : text.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xFF;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
                    || c == '.' || c == '_' || c == '~') {
                out.append((char) c);
            } else if (c == ' ') {
                out.append('+');
            } else {
                out.append('%').append(HEX_UPPER[c >> 4]).append(HEX_UPPER[c & 0x0F]);
            }
        }
    }

    private static String decode(String text) throws LinkException {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[bytes.length];
        int length = 0;
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i] & 0xFF;
            if (b == '+') {
                out[length++] = ' ';
            } else if (b == '%') {
                int hi = i + 1 < bytes.length ? hex(bytes[i + 1]) : -1;
                int lo = i + 2 < bytes.length ? hex(bytes[i + 2]) : -1;
                if (hi < 0 || lo < 0) throw new LinkException(ErrorCode.BadEncoding);
                out[length++] = (byte) ((hi << 4) | lo);
                i += 2;
            } else {
                out[length++] = (byte) b;
            }
        }
        try {
            CharBuffer chars = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(out, 0, length));
            return chars.toString();
        } catch (CharacterCodingException e) {
            throw new LinkException(ErrorCode.BadName);
        }
    }

    private static int hex(byte value) {
        int c = value & 0xFF;
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }
}
