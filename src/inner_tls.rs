//! The inner TLS session (`docs/plan-e2e-envelope.md` §2, D2): a rustls sans-IO client whose
//! bytes travel as tunnel data frames, so no async runtime is involved here.
//!
//! - TLS 1.3 only, `TLS_AES_256_GCM_SHA384` only, groups x25519 and secp256r1, signature
//!   scheme `ecdsa_secp256r1_sha256`.
//! - The client certificate is the profile's inner key.
//! - The server is accepted only if its `SubjectPublicKeyInfo` hashes to the pin. Names, dates
//!   and chains are ignored.
//! - No resumption, no early data.

use std::{
    io::{ErrorKind, Read, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Result, anyhow, bail};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error, SignatureScheme,
    client::{
        Resumption,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{CryptoProvider, ring, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use subtle::ConstantTimeEq;

use crate::{
    keys::{InnerKey, spki_fingerprint, spki_of},
    tunnel_proto::{MessageReader, frame_message},
};

/// The server name is a placeholder: the plugin ignores it and the pin decides.
pub const SERVER_NAME: &str = "sap-adt-plugin.invalid";
/// What the user reads when the pin does not match.
pub const MISMATCH: &str = "wrong Eclipse or attacker in the middle";
/// Plaintext handed to rustls per write, so no internal buffer limit is ever hit.
const WRITE_CHUNK: usize = 16 * 1024;

/// Accepts exactly the server whose SPKI SHA-256 equals the pin.
#[derive(Debug)]
pub struct PinnedKey {
    provider: Arc<CryptoProvider>,
    pin: [u8; 32],
    /// Set when the presented key is not the pinned one.
    mismatch: Arc<AtomicBool>,
}

impl PinnedKey {
    #[must_use]
    pub const fn new(
        provider: Arc<CryptoProvider>,
        pin: [u8; 32],
        mismatch: Arc<AtomicBool>,
    ) -> Self {
        Self {
            provider,
            pin,
            mismatch,
        }
    }
}

impl ServerCertVerifier for PinnedKey {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let found = spki_fingerprint(&spki_of(end_entity)?);
        if bool::from(found.as_slice().ct_eq(self.pin.as_slice())) {
            Ok(ServerCertVerified::assertion())
        } else {
            self.mismatch.store(true, Ordering::Release);
            Err(Error::General(MISMATCH.into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("The inner session requires TLS 1.3.".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

/// The crypto provider of the inner session: one suite, two groups.
#[must_use]
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider {
        cipher_suites: vec![ring::cipher_suite::TLS13_AES_256_GCM_SHA384],
        kx_groups: vec![ring::kx_group::X25519, ring::kx_group::SECP256R1],
        ..ring::default_provider()
    })
}

/// The client configuration of the inner session.
///
/// TLS 1.3 only, the single suite of [`provider`], `key` as the client certificate, the
/// Eclipse key pinned to `pin` (a mismatch sets `mismatch`), and no resumption or early data.
///
/// # Errors
/// `key` cannot be used as a TLS client certificate.
pub fn config(
    key: &InnerKey,
    pin: [u8; 32],
    mismatch: Arc<AtomicBool>,
) -> Result<Arc<ClientConfig>> {
    let provider = provider();
    let verifier = PinnedKey::new(provider.clone(), pin, mismatch);
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(vec![key.certificate()], key.private_key())
        .map_err(|_| anyhow!("The inner key cannot be used for TLS."))?;
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

/// A client-side inner TLS session over an opaque byte stream.
pub struct InnerTls {
    conn: ClientConnection,
    reader: MessageReader,
    mismatch: Arc<AtomicBool>,
    closed: bool,
}

impl InnerTls {
    /// A session that pins the Eclipse key `pin` and presents `key`.
    ///
    /// # Errors
    /// The TLS configuration cannot be built.
    pub fn new(key: &InnerKey, pin: [u8; 32]) -> Result<Self> {
        let mismatch = Arc::new(AtomicBool::new(false));
        let name = ServerName::try_from(SERVER_NAME)
            .map_err(|_| anyhow!("Invalid placeholder server name."))?;
        let conn = ClientConnection::new(config(key, pin, mismatch.clone())?, name)?;
        Ok(Self {
            conn,
            reader: MessageReader::default(),
            mismatch,
            closed: false,
        })
    }

    /// Whether the handshake failed because the server's key is not the pinned one.
    #[must_use]
    pub fn pin_mismatch(&self) -> bool {
        self.mismatch.load(Ordering::Acquire)
    }

    /// Whether the handshake is still running.
    #[must_use]
    pub fn handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    /// Whether the peer ended the session with `close_notify`.
    #[must_use]
    pub const fn closed(&self) -> bool {
        self.closed
    }

    /// Every TLS byte rustls has queued for the peer: handshake flights, alerts, key updates.
    ///
    /// # Errors
    /// rustls cannot serialize its output.
    pub fn take_output(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.drain_output(&mut out)?;
        Ok(out)
    }

    fn drain_output(&mut self, out: &mut Vec<u8>) -> Result<()> {
        while self.conn.wants_write() {
            self.conn.write_tls(out)?;
        }
        Ok(())
    }

    /// Feeds TLS bytes from the peer. Plaintext goes to the message reader; anything the
    /// session wants to send in answer is left for [`Self::take_output`].
    ///
    /// # Errors
    /// The bytes are not valid TLS for this session, or the handshake was refused. After a
    /// refusal the session is unusable.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        let mut input = bytes;
        while !input.is_empty() {
            let used = self.conn.read_tls(&mut input)?;
            if used == 0 {
                bail!("The inner TLS session accepts no more data.");
            }
            self.conn.process_new_packets()?;
            self.drain_plaintext()?;
        }
        Ok(())
    }

    fn drain_plaintext(&mut self) -> Result<()> {
        let mut buffer = [0_u8; WRITE_CHUNK];
        loop {
            match self.conn.reader().read(&mut buffer) {
                Ok(0) => {
                    self.closed = true;
                    return Ok(());
                }
                Ok(count) => self.reader.push(&buffer[..count]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Frames `message` with its length, encrypts it and returns all TLS bytes to send.
    ///
    /// # Errors
    /// The message exceeds `limit` or the session is unusable.
    pub fn seal(&mut self, message: &[u8], limit: u32) -> Result<Vec<u8>> {
        let framed = frame_message(message, limit)?;
        let mut out = Vec::with_capacity(framed.len() + 64);
        for chunk in framed.chunks(WRITE_CHUNK) {
            self.conn.writer().write_all(chunk)?;
            self.drain_output(&mut out)?;
        }
        Ok(out)
    }

    /// The next complete decrypted message, if the bytes fed so far hold one.
    ///
    /// # Errors
    /// A length prefix exceeds `limit`; the stream must then be closed.
    pub fn next_message(&mut self, limit: u32) -> Result<Option<Vec<u8>>> {
        Ok(self.reader.next_message(limit)?)
    }
}

#[cfg(test)]
mod tests {
    use rustls::ServerConnection;

    use super::*;
    use crate::test_plugin::{identity, plugin};
    use crate::tunnel_proto::{
        MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, decode_data, encode_data_chunks,
    };

    /// Client bytes to the server, through tunnel data frames.
    fn to_server(bytes: &[u8], server: &mut ServerConnection) -> Result<()> {
        for frame in encode_data_chunks(1, bytes) {
            let (stream, payload) = decode_data(&frame).unwrap();
            assert_eq!(stream, 1);
            let mut input = payload;
            while !input.is_empty() {
                server.read_tls(&mut input)?;
                server.process_new_packets()?;
            }
        }
        Ok(())
    }

    /// Server bytes to the client, through tunnel data frames.
    fn to_client(server: &mut ServerConnection, client: &mut InnerTls) -> Result<()> {
        let mut bytes = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut bytes)?;
        }
        for frame in encode_data_chunks(1, &bytes) {
            client.feed(decode_data(&frame).unwrap().1)?;
        }
        Ok(())
    }

    fn handshake(client: &mut InnerTls, server: &mut ServerConnection) -> Result<()> {
        for _ in 0..8 {
            let out = client.take_output()?;
            if out.is_empty() && !client.handshaking() && !server.is_handshaking() {
                return Ok(());
            }
            to_server(&out, server)?;
            to_client(server, client)?;
        }
        bail!("The handshake did not finish.")
    }

    fn desktop_key() -> (InnerKey, tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        (
            InnerKey::load_or_create(directory.path()).unwrap(),
            directory,
        )
    }

    #[test]
    fn the_verifier_accepts_the_pinned_key_and_refuses_another() {
        let (pinned, other) = (identity(), identity());
        let mismatch = Arc::new(AtomicBool::new(false));
        let verifier = PinnedKey::new(provider(), pinned.pin, mismatch.clone());
        let name = ServerName::try_from(SERVER_NAME).unwrap();
        let check = |cert: &CertificateDer<'_>| {
            verifier.verify_server_cert(cert, &[], &name, &[], UnixTime::now())
        };
        assert!(check(&pinned.cert).is_ok());
        assert!(!mismatch.load(Ordering::Acquire));
        assert!(check(&other.cert).is_err());
        assert!(mismatch.load(Ordering::Acquire));
        assert_eq!(
            verifier.supported_verify_schemes(),
            [SignatureScheme::ECDSA_NISTP256_SHA256]
        );
    }

    #[test]
    fn a_full_handshake_and_message_exchange_run_through_data_frames() {
        let (desktop, _directory) = desktop_key();
        let eclipse = identity();
        let mut client = InnerTls::new(&desktop, eclipse.pin).unwrap();
        let mut server = plugin(eclipse, *desktop.fingerprint());
        handshake(&mut client, &mut server).unwrap();
        assert!(!client.pin_mismatch());
        assert_eq!(
            client
                .conn
                .negotiated_cipher_suite()
                .map(|suite| suite.suite()),
            Some(rustls::CipherSuite::TLS13_AES_256_GCM_SHA384)
        );

        let request = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        let sealed = client.seal(request, MAX_REQUEST_BYTES).unwrap();
        to_server(&sealed, &mut server).unwrap();
        let mut plain = vec![0; 256];
        let count = server.reader().read(&mut plain).unwrap();
        let mut reader = MessageReader::default();
        reader.push(&plain[..count]);
        assert_eq!(
            reader.next_message(MAX_REQUEST_BYTES).unwrap().unwrap(),
            request
        );

        // A response larger than one data frame, with a ticket-style extra flight first.
        let response = vec![b'a'; 200_000];
        let framed = frame_message(&response, MAX_RESPONSE_BYTES).unwrap();
        // rustls buffers at most 64 KiB of unsent plaintext unless told otherwise.
        server.set_buffer_limit(None);
        server.writer().write_all(&framed).unwrap();
        to_client(&mut server, &mut client).unwrap();
        assert_eq!(
            client.next_message(MAX_RESPONSE_BYTES).unwrap().unwrap(),
            response
        );
        assert!(client.next_message(MAX_RESPONSE_BYTES).unwrap().is_none());
    }

    #[test]
    fn a_server_with_another_key_fails_the_handshake_and_is_flagged() {
        let (desktop, _directory) = desktop_key();
        let (expected, attacker) = (identity(), identity());
        let mut client = InnerTls::new(&desktop, expected.pin).unwrap();
        let mut server = plugin(attacker, *desktop.fingerprint());
        assert!(handshake(&mut client, &mut server).is_err());
        assert!(client.pin_mismatch());
    }

    #[test]
    fn a_desktop_key_the_plugin_has_not_pinned_is_refused_by_the_server() {
        let (desktop, _directory) = desktop_key();
        let eclipse = identity();
        let mut client = InnerTls::new(&desktop, eclipse.pin).unwrap();
        let mut server = plugin(eclipse, identity().pin);
        assert!(handshake(&mut client, &mut server).is_err());
        assert!(!client.pin_mismatch());
    }

    #[test]
    fn messages_over_the_limit_are_refused_before_encryption() {
        let (desktop, _directory) = desktop_key();
        let mut client = InnerTls::new(&desktop, [0; 32]).unwrap();
        assert!(client.seal(&[0; 33], 32).is_err());
    }
}
