//! Wire format of the end-to-end tunnel (`docs/plan-e2e-envelope.md` §2).
//!
//! Part of the shared library, used by the relay and the desktop client; the Eclipse plugin
//! implements the same format in Java. It may depend on no other module of this crate.
//!
//! Two kinds of WebSocket messages travel on `/tunnel` (desktop to relay) and on `/bridge`
//! (relay to an `e2e`-capable plugin):
//! - **Control** text frames: JSON [`Control`] values, at most [`MAX_CONTROL_BYTES`].
//! - **Data** binary frames: `[u32 big-endian stream][u8 kind = 0][payload]`, payload at most
//!   [`MAX_DATA_PAYLOAD`]. The payloads of one stream and direction, concatenated in order,
//!   are the inner TLS byte stream. The relay never interprets them.
//!
//! Inside the inner TLS, every JSON-RPC message is prefixed with its length as a `u32`
//! big-endian ([`frame_message`], [`MessageReader`]).
//!
//! A `Request` control frame announces that the next `len` data bytes the client sends on
//! that stream carry exactly one inner message. Data outside an announced request (TLS
//! handshake, tickets, alerts) is forwarded as is; the plugin refuses any inner message
//! that was not announced by a relay-forwarded envelope.

use std::{fmt, time::Duration};

use serde::{Deserialize, Serialize};

/// Envelope schema version.
pub const ENVELOPE_VERSION: u32 = 1;
/// Largest control text frame, in bytes.
pub const MAX_CONTROL_BYTES: usize = 64 * 1024;
/// Largest payload of one data frame, in bytes.
pub const MAX_DATA_PAYLOAD: usize = 64 * 1024;
/// Largest inner request message (plaintext JSON), as `mcp.rs` `MAX_BODY` today.
pub const MAX_REQUEST_BYTES: u32 = 4 * 1024 * 1024;
/// Largest inner response message (plaintext JSON), as the plugin's response limit today.
pub const MAX_RESPONSE_BYTES: u32 = 8 * 1024 * 1024;
/// Largest ciphertext a `Request` or `Response` may announce: the message, its length
/// prefix and TLS record overhead (at most 256 bytes per 16 KiB record).
pub const MAX_ANNOUNCED_BYTES: u32 = MAX_RESPONSE_BYTES + MAX_RESPONSE_BYTES / 64 + 4096;
/// How long an `Admitted` sequence number waits for its `Request`.
pub const ADMISSION_TTL: Duration = Duration::from_secs(30);
/// How long the inner TLS handshake may take after `Open`.
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(30);
/// Streams per Eclipse bridge.
pub const MAX_STREAMS_PER_BRIDGE: usize = 128;
/// Streams per desktop and endpoint.
pub const MAX_STREAMS_PER_DESKTOP: usize = 16;
/// The only data-frame kind: inner TLS bytes.
pub const DATA_KIND_STREAM: u8 = 0;
/// Longest method name an envelope may carry.
const MAX_METHOD_LEN: usize = 64;
/// Longest tool name an envelope may carry.
const MAX_TOOL_LEN: usize = 64;

/// What a tool does, as in `tools.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Class {
    Read,
    Execute,
    Write,
}

/// The readable part of a request, enforced by the relay and re-derived by the plugin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub v: u32,
    pub seq: u64,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<Class>,
}

impl Envelope {
    /// An envelope for `method` (and `tool` with its class, for `tools/call`).
    #[must_use]
    pub fn new(seq: u64, method: &str, tool: Option<(&str, Class)>) -> Self {
        Self {
            v: ENVELOPE_VERSION,
            seq,
            method: method.to_owned(),
            tool: tool.map(|(name, _)| name.to_owned()),
            class: tool.map(|(_, class)| class),
        }
    }

    /// A JSON-RPC notification: the plugin sends no response.
    #[must_use]
    pub fn is_notification(&self) -> bool {
        self.method.starts_with("notifications/")
    }

    /// Checks the schema rules of §2: version, known method, `tool` and `class` exactly
    /// for `tools/call`, and name lengths and characters.
    ///
    /// # Errors
    /// [`ProtoError::BadEnvelope`] naming the rule that failed.
    pub fn validate(&self) -> Result<(), ProtoError> {
        if self.v != ENVELOPE_VERSION {
            return Err(ProtoError::BadEnvelope("unsupported envelope version"));
        }
        let known = matches!(
            self.method.as_str(),
            "initialize" | "tools/list" | "tools/call" | "ping" | "pair/claim"
        ) || (self.is_notification() && self.method.len() > "notifications/".len());
        if !known
            || self.method.len() > MAX_METHOD_LEN
            || !self
                .method
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'/' || b == b'_')
        {
            return Err(ProtoError::BadEnvelope("unknown method"));
        }
        match (self.method.as_str(), &self.tool, self.class) {
            ("tools/call", Some(tool), Some(_)) => {
                if tool.is_empty()
                    || tool.len() > MAX_TOOL_LEN
                    || !tool
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                {
                    return Err(ProtoError::BadEnvelope("invalid tool name"));
                }
                Ok(())
            }
            ("tools/call", _, _) => Err(ProtoError::BadEnvelope("tools/call needs tool and class")),
            (_, None, None) => Ok(()),
            _ => Err(ProtoError::BadEnvelope(
                "only tools/call carries tool and class",
            )),
        }
    }
}

/// The relay's policy for one request, attached by the relay to `Request` frames it forwards.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RelayPolicy {
    pub allowed_tools: Vec<String>,
    pub package_scopes: Vec<Vec<String>>,
}

/// Clear-text outcome of a response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Error,
    Denied,
}

/// A control text frame. `stream` is the stream ID on that hop: the client chooses IDs on
/// `/tunnel`, the relay chooses its own on `/bridge` and translates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Control {
    /// Client to relay: open a stream to `endpoint`. Relay to plugin: the same, with the
    /// desktop's relay fingerprint and label as the relay sees them (`desktop`, `label`),
    /// which the plugin treats as assertions only.
    Open {
        stream: u32,
        endpoint: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        desktop: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    /// Client to relay: ask to send the request this envelope describes.
    Admit { stream: u32, envelope: Envelope },
    /// Relay to client: the envelope with this `seq` may be sent within [`ADMISSION_TTL`].
    Admitted { stream: u32, seq: u64 },
    /// Relay to client: the envelope was refused; nothing about it reaches the plugin.
    Denied {
        stream: u32,
        seq: u64,
        code: i32,
        message: String,
    },
    /// Client to relay to plugin: the next `len` data bytes on this stream are the
    /// encrypted request the envelope describes. The relay adds `policy` when forwarding.
    Request {
        stream: u32,
        envelope: Envelope,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy: Option<RelayPolicy>,
        len: u32,
    },
    /// Plugin to relay to client: the next `len` data bytes on this stream are the
    /// encrypted response to `seq`.
    Response {
        stream: u32,
        seq: u64,
        status: Status,
        len: u32,
    },
    /// Either direction: the stream ends.
    Close { stream: u32, reason: String },
}

impl Control {
    /// The stream this frame belongs to.
    #[must_use]
    pub const fn stream(&self) -> u32 {
        match self {
            Self::Open { stream, .. }
            | Self::Admit { stream, .. }
            | Self::Admitted { stream, .. }
            | Self::Denied { stream, .. }
            | Self::Request { stream, .. }
            | Self::Response { stream, .. }
            | Self::Close { stream, .. } => *stream,
        }
    }

    /// The control frame as JSON text.
    ///
    /// # Errors
    /// [`ProtoError::TooLarge`] if the text exceeds [`MAX_CONTROL_BYTES`].
    pub fn encode(&self) -> Result<String, ProtoError> {
        let text = serde_json::to_string(self).map_err(|_| ProtoError::Malformed)?;
        if text.len() > MAX_CONTROL_BYTES {
            return Err(ProtoError::TooLarge);
        }
        Ok(text)
    }

    /// Parses a control text frame and validates any envelope and announced length in it.
    ///
    /// # Errors
    /// [`ProtoError`] for oversized, malformed or invalid frames.
    pub fn decode(text: &str) -> Result<Self, ProtoError> {
        if text.len() > MAX_CONTROL_BYTES {
            return Err(ProtoError::TooLarge);
        }
        let control: Self = serde_json::from_str(text).map_err(|_| ProtoError::Malformed)?;
        match &control {
            Self::Admit { envelope, .. } => envelope.validate()?,
            Self::Request { envelope, len, .. } => {
                envelope.validate()?;
                if *len == 0 || *len > MAX_ANNOUNCED_BYTES {
                    return Err(ProtoError::TooLarge);
                }
            }
            Self::Response { len, .. } if *len > MAX_ANNOUNCED_BYTES => {
                return Err(ProtoError::TooLarge);
            }
            _ => {}
        }
        Ok(control)
    }
}

/// Encodes one data frame.
///
/// # Errors
/// [`ProtoError::TooLarge`] if `payload` exceeds [`MAX_DATA_PAYLOAD`].
pub fn encode_data(stream: u32, payload: &[u8]) -> Result<Vec<u8>, ProtoError> {
    if payload.len() > MAX_DATA_PAYLOAD {
        return Err(ProtoError::TooLarge);
    }
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.extend_from_slice(&stream.to_be_bytes());
    frame.push(DATA_KIND_STREAM);
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Splits `bytes` into data frames of at most [`MAX_DATA_PAYLOAD`].
#[must_use]
pub fn encode_data_chunks(stream: u32, bytes: &[u8]) -> Vec<Vec<u8>> {
    bytes
        .chunks(MAX_DATA_PAYLOAD)
        .map(|chunk| {
            let mut frame = Vec::with_capacity(5 + chunk.len());
            frame.extend_from_slice(&stream.to_be_bytes());
            frame.push(DATA_KIND_STREAM);
            frame.extend_from_slice(chunk);
            frame
        })
        .collect()
}

/// Decodes one data frame into its stream ID and payload.
///
/// # Errors
/// [`ProtoError::Malformed`] for a short frame or an unknown kind, [`ProtoError::TooLarge`]
/// for an oversized payload. An empty payload is malformed.
pub fn decode_data(frame: &[u8]) -> Result<(u32, &[u8]), ProtoError> {
    let (header, payload) = frame.split_at_checked(5).ok_or(ProtoError::Malformed)?;
    let stream = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    if header[4] != DATA_KIND_STREAM || payload.is_empty() {
        return Err(ProtoError::Malformed);
    }
    if payload.len() > MAX_DATA_PAYLOAD {
        return Err(ProtoError::TooLarge);
    }
    Ok((stream, payload))
}

/// Prefixes an inner message with its length.
///
/// # Errors
/// [`ProtoError::TooLarge`] if `message` exceeds `limit`.
pub fn frame_message(message: &[u8], limit: u32) -> Result<Vec<u8>, ProtoError> {
    let len = u32::try_from(message.len()).map_err(|_| ProtoError::TooLarge)?;
    if len > limit {
        return Err(ProtoError::TooLarge);
    }
    let mut framed = Vec::with_capacity(4 + message.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(message);
    Ok(framed)
}

/// Reassembles length-prefixed inner messages from decrypted plaintext.
#[derive(Debug, Default)]
pub struct MessageReader {
    buffer: Vec<u8>,
}

impl MessageReader {
    /// Appends decrypted plaintext.
    pub fn push(&mut self, plaintext: &[u8]) {
        self.buffer.extend_from_slice(plaintext);
    }

    /// The next complete message, if any.
    ///
    /// # Errors
    /// [`ProtoError::TooLarge`] as soon as a length prefix exceeds `limit`; the stream must
    /// then be closed.
    pub fn next_message(&mut self, limit: u32) -> Result<Option<Vec<u8>>, ProtoError> {
        let Some(prefix) = self.buffer.first_chunk::<4>() else {
            return Ok(None);
        };
        let len = u32::from_be_bytes(*prefix);
        if len > limit {
            return Err(ProtoError::TooLarge);
        }
        let total = 4 + usize::try_from(len).map_err(|_| ProtoError::TooLarge)?;
        if self.buffer.len() < total {
            return Ok(None);
        }
        let message = self.buffer[4..total].to_vec();
        self.buffer.drain(..total);
        Ok(Some(message))
    }

    /// Bytes buffered but not yet returned.
    #[must_use]
    pub const fn pending(&self) -> usize {
        self.buffer.len()
    }
}

/// Why a frame or envelope was refused. Messages never echo frame content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtoError {
    Malformed,
    TooLarge,
    BadEnvelope(&'static str),
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("Malformed tunnel frame."),
            Self::TooLarge => f.write_str("Tunnel frame exceeds the size limit."),
            Self::BadEnvelope(rule) => write!(f, "Invalid envelope: {rule}."),
        }
    }
}

impl std::error::Error for ProtoError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden control frames, shared with the Java tests (`TunnelProtocolRegression`).
    const GOLDEN: &[&str] = &[
        r#"{"type":"open","stream":1,"endpoint":"aa"}"#,
        r#"{"type":"open","stream":7,"endpoint":"aa","desktop":"bb","label":"Laptop"}"#,
        r#"{"type":"admit","stream":1,"envelope":{"v":1,"seq":3,"method":"tools/call","tool":"sap_get_source","class":"read"}}"#,
        r#"{"type":"admitted","stream":1,"seq":3}"#,
        r#"{"type":"denied","stream":1,"seq":3,"code":-32001,"message":"Denied by the relay."}"#,
        r#"{"type":"request","stream":1,"envelope":{"v":1,"seq":3,"method":"tools/list"},"policy":{"allowedTools":["sap_get_source"],"packageScopes":[["Z*"]]},"len":512}"#,
        r#"{"type":"response","stream":1,"seq":3,"status":"ok","len":900}"#,
        r#"{"type":"close","stream":1,"reason":"done"}"#,
    ];

    #[test]
    fn golden_control_frames_round_trip_byte_for_byte() {
        for text in GOLDEN {
            let control = Control::decode(text).unwrap();
            assert_eq!(&control.encode().unwrap(), text);
        }
    }

    #[test]
    fn envelopes_follow_the_schema_rules() {
        let call = Envelope::new(1, "tools/call", Some(("sap_set_source", Class::Write)));
        assert!(call.validate().is_ok());
        assert!(Envelope::new(2, "tools/list", None).validate().is_ok());
        assert!(
            Envelope::new(3, "notifications/initialized", None)
                .validate()
                .is_ok()
        );
        assert!(Envelope::new(4, "pair/claim", None).validate().is_ok());
        for bad in [
            Envelope::new(5, "tools/call", None),
            Envelope::new(6, "tools/list", Some(("sap_get_source", Class::Read))),
            Envelope::new(7, "resources/read", None),
            Envelope::new(8, "notifications/", None),
            Envelope::new(9, "tools/call", Some(("Bad-Tool", Class::Read))),
            Envelope {
                v: 2,
                ..Envelope::new(10, "ping", None)
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
        let unknown = r#"{"type":"admit","stream":1,"envelope":{"v":1,"seq":1,"method":"ping","object":"Z"}}"#;
        assert_eq!(Control::decode(unknown), Err(ProtoError::Malformed));
    }

    #[test]
    fn announced_lengths_and_frame_sizes_are_bounded() {
        let zero =
            r#"{"type":"request","stream":1,"envelope":{"v":1,"seq":1,"method":"ping"},"len":0}"#;
        assert_eq!(Control::decode(zero), Err(ProtoError::TooLarge));
        let huge = format!(
            r#"{{"type":"response","stream":1,"seq":1,"status":"ok","len":{}}}"#,
            MAX_ANNOUNCED_BYTES + 1
        );
        assert_eq!(Control::decode(&huge), Err(ProtoError::TooLarge));
        assert_eq!(
            encode_data(1, &vec![0; MAX_DATA_PAYLOAD + 1]),
            Err(ProtoError::TooLarge)
        );
        assert_eq!(decode_data(&[0, 0, 0, 1, 0]), Err(ProtoError::Malformed));
        assert_eq!(decode_data(&[0, 0, 0, 1, 9, 1]), Err(ProtoError::Malformed));
    }

    #[test]
    fn data_frames_and_inner_messages_round_trip() {
        let bytes: Vec<u8> = (0..=255).cycle().take(MAX_DATA_PAYLOAD * 2 + 5).collect();
        let frames = encode_data_chunks(9, &bytes);
        assert_eq!(frames.len(), 3);
        let joined: Vec<u8> = frames
            .iter()
            .flat_map(|frame| {
                let (stream, payload) = decode_data(frame).unwrap();
                assert_eq!(stream, 9);
                payload.to_vec()
            })
            .collect();
        assert_eq!(joined, bytes);

        let mut reader = MessageReader::default();
        let wire = [
            frame_message(b"{\"a\":1}", 100).unwrap(),
            frame_message(b"{}", 100).unwrap(),
        ]
        .concat();
        for byte in &wire {
            reader.push(std::slice::from_ref(byte));
        }
        assert_eq!(reader.next_message(100).unwrap().unwrap(), b"{\"a\":1}");
        assert_eq!(reader.next_message(100).unwrap().unwrap(), b"{}");
        assert_eq!(reader.next_message(100).unwrap(), None);
        reader.push(&1000_u32.to_be_bytes());
        assert_eq!(reader.next_message(100), Err(ProtoError::TooLarge));
        assert_eq!(frame_message(&[0; 101], 100), Err(ProtoError::TooLarge));
    }

    #[test]
    fn random_input_never_panics() {
        // Seeded xorshift, so failures are reproducible on every platform.
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..4000 {
            let len = usize::try_from(next() % 96).unwrap();
            let bytes: Vec<u8> = (0..len).map(|_| next().to_le_bytes()[0]).collect();
            let _ = decode_data(&bytes);
            let _ = Control::decode(&String::from_utf8_lossy(&bytes));
            let mut reader = MessageReader::default();
            reader.push(&bytes);
            let _ = reader.next_message(64);
        }
    }
}
