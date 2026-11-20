package com.sap.adt.mcp.server.e2e;

import java.io.ByteArrayOutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;

import com.sap.adt.mcp.server.e2e.TunnelProtocol.MessageReader;
import com.sap.adt.mcp.server.e2e.TunnelProtocol.ProtocolException;

/**
 * The plugin's side of the inner TLS of one tunnel stream: an {@link SSLEngine} server with an opaque byte
 * stream on each side (plan section 2, D2).
 *
 * <p>Configuration: TLS 1.3 only, {@code TLS_AES_256_GCM_SHA384} only, client certificate required, the
 * plugin's own certificate, and a trust manager that accepts only a pinned client key (or, while the
 * {@link PairingGate} is open, an unknown one, and then {@link #peerPinned()} is false). A fresh
 * {@link SSLContext} serves each engine and keeps almost no session cache, so no session is ever resumed.
 * The named groups stay at the JDK default (x25519, secp256r1 and a few others): {@code
 * SSLParameters.setNamedGroups} needs Java 20, and the system property {@code jdk.tls.namedGroups} is
 * global. The signature scheme follows from the P-256 key ({@code ecdsa_secp256r1_sha256}).</p>
 *
 * <p>Usage: {@link #feed} the ciphertext of incoming data frames, send whatever {@link #takeOutgoing}
 * returns as data frames, and {@link #seal} each response. The caller serialises calls per channel and
 * sends what it takes in the order it took it (the TLS record order is the wire order).</p>
 */
public final class InnerChannel {
    public static final String PROTOCOL = "TLSv1.3";
    public static final String CIPHER_SUITE = "TLS_AES_256_GCM_SHA384";
    private static final int MAX_BUFFER = 1024 * 1024;

    /** The TLS session or an inner message is unusable; the stream must be closed. Messages never carry content. */
    public static final class ChannelException extends Exception {
        private static final long serialVersionUID = 1L;

        ChannelException(String message) {
            super(message);
        }
    }

    private final SSLEngine engine;
    private final PinTrust trust;
    private final MessageReader reader = new MessageReader();
    private final ByteArrayOutputStream outgoing = new ByteArrayOutputStream();
    private ByteBuffer netIn;
    private ByteBuffer appIn;
    private ByteBuffer netOut;
    private boolean handshakeDone;
    private boolean closed;
    private String peerFingerprint;
    private boolean pinned;

    public InnerChannel(InnerKeys keys, PinStore pins, PairingGate gate) throws GeneralSecurityException {
        Objects.requireNonNull(keys);
        this.trust = new PinTrust(Objects.requireNonNull(pins), Objects.requireNonNull(gate));
        SSLContext context = SSLContext.getInstance(PROTOCOL);
        context.init(new KeyManager[] {new OwnKey(keys)}, new TrustManager[] {trust}, new SecureRandom());
        context.getServerSessionContext().setSessionCacheSize(1);
        context.getServerSessionContext().setSessionTimeout(1);
        this.engine = context.createSSLEngine();
        engine.setUseClientMode(false);
        SSLParameters parameters = engine.getSSLParameters();
        parameters.setProtocols(new String[] {PROTOCOL});
        parameters.setCipherSuites(new String[] {CIPHER_SUITE});
        parameters.setNeedClientAuth(true);
        parameters.setUseCipherSuitesOrder(true);
        engine.setSSLParameters(parameters);
        engine.setNeedClientAuth(true);
        engine.setEnableSessionCreation(true);
        this.netIn = ByteBuffer.allocate(engine.getSession().getPacketBufferSize() * 2);
        this.netOut = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
        this.appIn = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize());
    }

    /**
     * Consumes ciphertext and returns the complete inner messages it carried (possibly none). Handshake
     * and alert bytes to send back are available from {@link #takeOutgoing()}, also after a failure.
     */
    public synchronized List<byte[]> feed(byte[] ciphertext) throws ChannelException {
        if (closed) {
            throw new ChannelException("The inner TLS session is closed.");
        }
        try {
            if (netIn.remaining() < ciphertext.length) {
                int needed = netIn.position() + ciphertext.length;
                if (needed > MAX_BUFFER) {
                    throw new SSLException("Too much unprocessed TLS data.");
                }
                ByteBuffer larger = ByteBuffer.allocate(Math.max(needed, netIn.capacity() * 2));
                netIn.flip();
                larger.put(netIn);
                netIn = larger;
            }
            netIn.put(ciphertext);
            run();
        } catch (SSLException | RuntimeException e) {
            fail();
            throw new ChannelException("The inner TLS session failed.");
        }
        List<byte[]> messages = new ArrayList<>();
        try {
            byte[] message;
            while ((message = reader.nextMessage(TunnelProtocol.MAX_REQUEST_BYTES)) != null) {
                messages.add(message);
            }
        } catch (ProtocolException e) {
            fail();
            throw new ChannelException("An inner message exceeds the size limit.");
        }
        return messages;
    }

    /** The ciphertext the engine produced since the last call (handshake messages, tickets, alerts); may be empty. */
    public synchronized byte[] takeOutgoing() {
        byte[] bytes = outgoing.toByteArray();
        outgoing.reset();
        return bytes;
    }

    /**
     * Frames and encrypts one inner message. The result is exactly the ciphertext that the {@code response}
     * control frame announces; call {@link #takeOutgoing()} first and send that before it.
     */
    public synchronized byte[] seal(byte[] message) throws ChannelException {
        if (!handshakeDone || closed) {
            throw new ChannelException("The inner TLS session is not open.");
        }
        byte[] framed;
        try {
            framed = TunnelProtocol.frameMessage(message, TunnelProtocol.MAX_RESPONSE_BYTES);
        } catch (ProtocolException e) {
            throw new ChannelException("The response exceeds the size limit.");
        }
        ByteArrayOutputStream sealed = new ByteArrayOutputStream(framed.length + 128);
        ByteBuffer source = ByteBuffer.wrap(framed);
        try {
            while (source.hasRemaining()) {
                HandshakeStatus status = engine.getHandshakeStatus();
                if (status == HandshakeStatus.NEED_TASK) {
                    runTasks();
                    continue;
                }
                if (status == HandshakeStatus.NEED_UNWRAP || status == HandshakeStatus.NEED_UNWRAP_AGAIN) {
                    throw new SSLException("The TLS session is waiting for the peer.");
                }
                if (wrap(source, sealed).getStatus() == SSLEngineResult.Status.CLOSED) {
                    throw new SSLException("The TLS session is closed.");
                }
            }
        } catch (SSLException | RuntimeException e) {
            fail();
            throw new ChannelException("The inner TLS session failed.");
        }
        if (sealed.size() > TunnelProtocol.MAX_ANNOUNCED_BYTES) {
            throw new ChannelException("The response exceeds the size limit.");
        }
        return sealed.toByteArray();
    }

    /** Starts an orderly shutdown; a close_notify may then be available from {@link #takeOutgoing()}. */
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        try {
            engine.closeOutbound();
            while (engine.getHandshakeStatus() == HandshakeStatus.NEED_WRAP && !engine.isOutboundDone()) {
                wrap(ByteBuffer.allocate(0), outgoing);
            }
        } catch (SSLException | RuntimeException e) {
            // Nothing more to say to a peer that is already gone.
        }
    }

    public synchronized boolean isClosed() {
        return closed;
    }

    /** True once the inner handshake finished: the peer key is then proven. */
    public synchronized boolean handshakeComplete() {
        return handshakeDone;
    }

    /** Lowercase hex SHA-256 of the client's SPKI; null until the handshake completed. */
    public synchronized String peerKeyFingerprint() {
        return handshakeDone ? peerFingerprint : null;
    }

    /** False for a client key that was accepted only because the pairing gate was open. */
    public synchronized boolean peerPinned() {
        return handshakeDone && pinned;
    }

    // ------------------------------------------------------------------ engine pump

    private void run() throws SSLException {
        netIn.flip();
        try {
            loop:
            while (true) {
                HandshakeStatus status = engine.getHandshakeStatus();
                if (!handshakeDone && status == HandshakeStatus.NOT_HANDSHAKING && trust.fingerprint() != null) {
                    finished();
                }
                if (status == HandshakeStatus.NEED_TASK) {
                    runTasks();
                    continue;
                }
                if (status == HandshakeStatus.NEED_WRAP) {
                    if (wrap(ByteBuffer.allocate(0), outgoing).getStatus() == SSLEngineResult.Status.CLOSED) {
                        closed = true;
                        break;
                    }
                    continue;
                }
                if (!netIn.hasRemaining() && status != HandshakeStatus.NEED_UNWRAP_AGAIN) {
                    break;
                }
                SSLEngineResult result = engine.unwrap(netIn, appIn);
                if (result.getHandshakeStatus() == HandshakeStatus.FINISHED) {
                    finished();
                }
                switch (result.getStatus()) {
                    case BUFFER_UNDERFLOW:
                        break loop;
                    case BUFFER_OVERFLOW:
                        if (appIn.capacity() >= MAX_BUFFER) {
                            throw new SSLException("TLS record too large.");
                        }
                        appIn = ByteBuffer.allocate(Math.max(appIn.capacity() * 2, engine.getSession().getApplicationBufferSize()));
                        break;
                    case CLOSED:
                        takeApplicationData();
                        closed = true;
                        break loop;
                    default:
                        takeApplicationData();
                        break;
                }
            }
        } finally {
            netIn.compact();
        }
    }

    private void takeApplicationData() {
        appIn.flip();
        if (appIn.hasRemaining()) {
            reader.push(appIn.array(), appIn.arrayOffset() + appIn.position(), appIn.remaining());
        }
        appIn.clear();
    }

    private void runTasks() {
        Runnable task;
        while ((task = engine.getDelegatedTask()) != null) {
            task.run();
        }
    }

    private SSLEngineResult wrap(ByteBuffer source, ByteArrayOutputStream target) throws SSLException {
        while (true) {
            SSLEngineResult result = engine.wrap(source, netOut);
            if (result.getHandshakeStatus() == HandshakeStatus.FINISHED) {
                finished();
            }
            if (result.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                if (netOut.capacity() >= MAX_BUFFER) {
                    throw new SSLException("TLS record too large.");
                }
                netOut = ByteBuffer.allocate(Math.max(netOut.capacity() * 2, engine.getSession().getPacketBufferSize()));
                continue;
            }
            netOut.flip();
            target.write(netOut.array(), netOut.arrayOffset() + netOut.position(), netOut.remaining());
            netOut.clear();
            return result;
        }
    }

    private void finished() throws SSLException {
        if (handshakeDone) {
            return;
        }
        if (!PROTOCOL.equals(engine.getSession().getProtocol())
                || !CIPHER_SUITE.equals(engine.getSession().getCipherSuite()) || trust.fingerprint() == null) {
            throw new SSLException("Unexpected TLS parameters.");
        }
        handshakeDone = true;
        peerFingerprint = trust.fingerprint();
        pinned = trust.pinned();
    }

    private void fail() {
        closed = true;
        try {
            engine.closeOutbound();
            // Hand the fatal alert (if the engine made one) to takeOutgoing().
            for (int i = 0; i < 4 && engine.getHandshakeStatus() == HandshakeStatus.NEED_WRAP; i++) {
                wrap(ByteBuffer.allocate(0), outgoing);
            }
        } catch (SSLException | RuntimeException e) {
            // Best effort only.
        }
    }

    // ------------------------------------------------------------------ key and trust managers

    /** Serves the plugin's own inner certificate and nothing else. */
    static final class OwnKey extends X509ExtendedKeyManager {
        private static final String ALIAS = "inner";
        private final PrivateKey key;
        private final X509Certificate[] chain;

        OwnKey(InnerKeys keys) {
            this.key = keys.privateKey();
            this.chain = new X509Certificate[] {keys.certificate()};
        }

        private static boolean ec(String keyType) {
            return keyType != null && keyType.startsWith("EC");
        }

        @Override
        public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
            return ec(keyType) ? ALIAS : null;
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return ec(keyType) ? ALIAS : null;
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return ec(keyType) ? new String[] {ALIAS} : null;
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            return ALIAS.equals(alias) ? chain.clone() : null;
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            return ALIAS.equals(alias) ? key : null;
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return null;
        }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            return null;
        }
    }

    /**
     * Accepts a client certificate only by its key: the SPKI fingerprint must be pinned or, with no pin
     * matching, the pairing gate must be open. Names, dates and issuers are ignored. The result is read
     * only after the handshake finished, when the TLS signature has proven possession of the key.
     */
    static final class PinTrust extends X509ExtendedTrustManager {
        private final PinStore pins;
        private final PairingGate gate;
        private volatile String fingerprint;
        private volatile boolean pinned;

        PinTrust(PinStore pins, PairingGate gate) {
            this.pins = pins;
            this.gate = gate;
        }

        String fingerprint() {
            return fingerprint;
        }

        boolean pinned() {
            return pinned;
        }

        private void check(X509Certificate[] chain) throws CertificateException {
            if (chain == null || chain.length == 0) {
                throw new CertificateException("No client certificate.");
            }
            PublicKey key = chain[0].getPublicKey();
            if (!InnerKeys.isP256(key)) {
                throw new CertificateException("The client key is not a P-256 key.");
            }
            String print = InnerKeys.fingerprint(key);
            boolean known = pins.find(print).isPresent();
            if (!known && !gate.pairingOpen()) {
                throw new CertificateException("The client key is not pinned.");
            }
            this.fingerprint = print;
            this.pinned = known;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            check(chain);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            throw new CertificateException("Only engine connections are supported.");
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("Only engine connections are supported.");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            throw new CertificateException("This is a server-side trust manager.");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            throw new CertificateException("This is a server-side trust manager.");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("This is a server-side trust manager.");
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
