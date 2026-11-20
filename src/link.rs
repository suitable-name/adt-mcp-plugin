//! One-time links: `sap-adt://enroll?...` (the relay grants a certificate) and
//! `sap-adt://pair?...` (an Eclipse plugin grants a desktop access, phase P3).
//!
//! ```text
//! sap-adt://enroll?v=1&r=desktop&n=Gussek+Relay&s=relay.example:8787&e=relay.example:8788&t=GW1-...
//! sap-adt://pair?v=1&p=<64 lowercase hex endpoint id>&n=EclipseLaptop&t=GW1-...
//! ```
//!
//! | Key | Meaning |
//! |---|---|
//! | `v` | Link version. This build reads `1`; any other number is `NeedsNewerVersion`. |
//! | `r` | `desktop` or `eclipse` (enroll links only). |
//! | `n` | Display name, UTF-8 percent-encoded (a space is `+`), at most 64 bytes, no control characters. Optional: missing means the empty name. |
//! | `s` | Data (mutual TLS) address `host:port` (enroll only). Exactly once. |
//! | `e` | Enrollment address `host:port` (enroll only). Exactly once. |
//! | `l` | Optional label for the certificate (enroll only), same rules as `n`. |
//! | `p` | Endpoint ID, 64 lowercase hex digits (pair only). |
//! | `t` | The `GW1-` token. A secret. |
//!
//! A host is a DNS name, an IPv4 address or a bracketed IPv6 address. The error codes
//! ([`LinkError::code`]) are shared with the Java plugin; both sides check
//! `java-plugin/sap-adt-mcp-server/tests/link-vectors.json`.
//!
//! The token is a bearer secret. Links keep it in a zeroizing string, `Debug` redacts it,
//! and no [`LinkError`] message contains any text of the link. Callers keep the string
//! `build` returns out of logs.
//!
//! Part of the shared library: the relay, the client and the tests use it, and it depends
//! on no other module of this package.

use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

use zeroize::Zeroizing;

pub const ENROLL_PREFIX: &str = "sap-adt://enroll?";
pub const PAIR_PREFIX: &str = "sap-adt://pair?";
pub const LINK_VERSION: u32 = 1;
pub const MAX_NAME_BYTES: usize = 64;
pub const MAX_TOKEN_LEN: usize = 256;
pub const MAX_LINK_LEN: usize = 2048;
const TOKEN_TAG: &str = "GW1-";

/// Why a link could not be built or read. Messages are plain sentences and never contain
/// any text of the link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
    NotALink,
    TooLong,
    NeedsNewerVersion,
    MissingPart,
    RepeatedPart,
    UnknownRole,
    BadName,
    BadAddress,
    BadPort,
    MissingToken,
    BadToken,
    BadEndpoint,
    BadEncoding,
}

impl LinkError {
    /// The code name shared with the Java plugin and `link-vectors.json`.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotALink => "NotALink",
            Self::TooLong => "TooLong",
            Self::NeedsNewerVersion => "NeedsNewerVersion",
            Self::MissingPart => "MissingPart",
            Self::RepeatedPart => "RepeatedPart",
            Self::UnknownRole => "UnknownRole",
            Self::BadName => "BadName",
            Self::BadAddress => "BadAddress",
            Self::BadPort => "BadPort",
            Self::MissingToken => "MissingToken",
            Self::BadToken => "BadToken",
            Self::BadEndpoint => "BadEndpoint",
            Self::BadEncoding => "BadEncoding",
        }
    }
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotALink => "This is not a sap-adt link.",
            Self::TooLong => "This link is too long to be real.",
            Self::NeedsNewerVersion => "This link needs a newer version of this program.",
            Self::MissingPart => "This link is incomplete.",
            Self::RepeatedPart => "This link repeats a part that should appear once.",
            Self::UnknownRole => "This link names a role this program does not know.",
            Self::BadName => "This link has an unusable name.",
            Self::BadAddress => "This link has an address that is not written host:port.",
            Self::BadPort => "This link has an unusable port.",
            Self::MissingToken => "This link has no token in it.",
            Self::BadToken => "This link has a token that is not shaped right.",
            Self::BadEndpoint => "This link has an unusable endpoint ID.",
            Self::BadEncoding => "This link is damaged.",
        })
    }
}

impl std::error::Error for LinkError {}

/// The certificate role an enrollment link grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Desktop,
    Eclipse,
}

impl Role {
    /// The role's word in a link: `desktop` or `eclipse`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Eclipse => "eclipse",
        }
    }

    /// # Errors
    /// `UnknownRole` for anything but `desktop` or `eclipse`.
    pub fn from_word(word: &str) -> Result<Self, LinkError> {
        match word {
            "desktop" => Ok(Self::Desktop),
            "eclipse" => Ok(Self::Eclipse),
            _ => Err(LinkError::UnknownRole),
        }
    }
}

/// The decoded contents of an enrollment link. The token is a secret.
#[derive(Clone)]
pub struct EnrollLink {
    pub role: Role,
    pub name: String,
    /// The data (mutual TLS) address, `host:port`.
    pub server: String,
    /// The enrollment address, `host:port`.
    pub enrollment: String,
    pub label: Option<String>,
    pub token: Zeroizing<String>,
}

impl fmt::Debug for EnrollLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrollLink")
            .field("role", &self.role)
            .field("name", &self.name)
            .field("server", &self.server)
            .field("enrollment", &self.enrollment)
            .field("label", &self.label)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// The decoded contents of a pairing link. The token is a secret.
#[derive(Clone)]
pub struct PairLink {
    /// The endpoint ID: 64 lowercase hex digits.
    pub endpoint: String,
    pub name: String,
    pub token: Zeroizing<String>,
}

impl fmt::Debug for PairLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairLink")
            .field("endpoint", &self.endpoint)
            .field("name", &self.name)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Either kind of link.
#[derive(Debug, Clone)]
pub enum Link {
    Enroll(EnrollLink),
    Pair(PairLink),
}

impl Link {
    /// Read a link of either kind.
    ///
    /// Surrounding whitespace is ignored, the scheme is matched without regard to case and
    /// anything after a `#` is dropped. Unknown keys are skipped; a known key twice is
    /// refused. The version is checked before anything else of the link is interpreted.
    ///
    /// # Errors
    /// A [`LinkError`] naming the first problem found.
    pub fn parse(text: &str) -> Result<Self, LinkError> {
        let text = text.trim();
        if text.chars().count() > MAX_LINK_LEN {
            return Err(LinkError::TooLong);
        }
        if let Some(query) = strip_prefix_ignore_case(text, ENROLL_PREFIX) {
            return parse_enroll(query).map(Self::Enroll);
        }
        if let Some(query) = strip_prefix_ignore_case(text, PAIR_PREFIX) {
            return parse_pair(query).map(Self::Pair);
        }
        Err(LinkError::NotALink)
    }
}

impl EnrollLink {
    /// Read an enrollment link; a pairing link is `NotALink` here.
    ///
    /// # Errors
    /// A [`LinkError`] naming the first problem found.
    pub fn parse(text: &str) -> Result<Self, LinkError> {
        match Link::parse(text)? {
            Link::Enroll(link) => Ok(link),
            Link::Pair(_) => Err(LinkError::NotALink),
        }
    }

    /// Write the link. The result contains the token: treat it as a secret.
    ///
    /// # Errors
    /// The checks `parse` applies to each part.
    pub fn build(&self) -> Result<String, LinkError> {
        check_name(&self.name)?;
        check_hostport(&self.server)?;
        check_hostport(&self.enrollment)?;
        if let Some(label) = &self.label {
            check_name(label)?;
        }
        check_token(&self.token)?;
        let mut out = String::with_capacity(ENROLL_PREFIX.len() + 96 + self.token.len());
        out.push_str(ENROLL_PREFIX);
        out.push_str("v=1&r=");
        out.push_str(self.role.as_str());
        out.push_str("&n=");
        percent_encode_into(&mut out, &self.name);
        out.push_str("&s=");
        out.push_str(&self.server);
        out.push_str("&e=");
        out.push_str(&self.enrollment);
        if let Some(label) = &self.label {
            out.push_str("&l=");
            percent_encode_into(&mut out, label);
        }
        out.push_str("&t=");
        out.push_str(&self.token);
        Ok(out)
    }
}

impl PairLink {
    /// Read a pairing link; an enrollment link is `NotALink` here.
    ///
    /// # Errors
    /// A [`LinkError`] naming the first problem found.
    pub fn parse(text: &str) -> Result<Self, LinkError> {
        match Link::parse(text)? {
            Link::Pair(link) => Ok(link),
            Link::Enroll(_) => Err(LinkError::NotALink),
        }
    }

    /// Write the link. The result contains the token: treat it as a secret.
    ///
    /// # Errors
    /// The checks `parse` applies to each part.
    pub fn build(&self) -> Result<String, LinkError> {
        check_endpoint(&self.endpoint)?;
        check_name(&self.name)?;
        check_token(&self.token)?;
        let mut out = String::with_capacity(PAIR_PREFIX.len() + 96 + self.token.len());
        out.push_str(PAIR_PREFIX);
        out.push_str("v=1&p=");
        out.push_str(&self.endpoint);
        out.push_str("&n=");
        percent_encode_into(&mut out, &self.name);
        out.push_str("&t=");
        out.push_str(&self.token);
        Ok(out)
    }
}

fn parse_enroll(query: &str) -> Result<EnrollLink, LinkError> {
    let found = scan(query, &["v", "r", "n", "s", "e", "l", "t"])?;
    check_version(&found)?;
    let role = Role::from_word(find(&found, "r").ok_or(LinkError::MissingPart)?)?;
    let name = find(&found, "n").map_or_else(|| Ok(String::new()), decode_name)?;
    let server = decode_hostport(find(&found, "s").ok_or(LinkError::MissingPart)?)?;
    let enrollment = decode_hostport(find(&found, "e").ok_or(LinkError::MissingPart)?)?;
    let label = find(&found, "l").map(decode_name).transpose()?;
    let token = find(&found, "t").ok_or(LinkError::MissingToken)?;
    check_token(token)?;
    Ok(EnrollLink {
        role,
        name,
        server,
        enrollment,
        label,
        token: Zeroizing::new(token.to_owned()),
    })
}

fn parse_pair(query: &str) -> Result<PairLink, LinkError> {
    let found = scan(query, &["v", "p", "n", "t"])?;
    check_version(&found)?;
    let endpoint = find(&found, "p").ok_or(LinkError::MissingPart)?;
    check_endpoint(endpoint)?;
    let name = find(&found, "n").map_or_else(|| Ok(String::new()), decode_name)?;
    let token = find(&found, "t").ok_or(LinkError::MissingToken)?;
    check_token(token)?;
    Ok(PairLink {
        endpoint: endpoint.to_owned(),
        name,
        token: Zeroizing::new(token.to_owned()),
    })
}

/// The `key=value` pairs of the known keys. Unknown keys are skipped; a known key
/// twice is refused.
fn scan<'a>(query: &'a str, known: &[&str]) -> Result<Vec<(&'a str, &'a str)>, LinkError> {
    let query = query.split('#').next().unwrap_or("");
    let mut found: Vec<(&str, &str)> = Vec::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if !known.contains(&key) {
            continue;
        }
        if found.iter().any(|(seen, _)| *seen == key) {
            return Err(LinkError::RepeatedPart);
        }
        found.push((key, value));
    }
    Ok(found)
}

fn find<'a>(found: &[(&'a str, &'a str)], key: &str) -> Option<&'a str> {
    found
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, value)| *value)
}

/// The version decides whether the rest means anything, so it is read first. A number
/// too large for `u32` is certainly from the future.
fn check_version(found: &[(&str, &str)]) -> Result<(), LinkError> {
    let text = find(found, "v").ok_or(LinkError::MissingPart)?;
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(LinkError::MissingPart);
    }
    match text.parse::<u32>() {
        Ok(LINK_VERSION) => Ok(()),
        _ => Err(LinkError::NeedsNewerVersion),
    }
}

fn strip_prefix_ignore_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &text[prefix.len()..])
}

/// A name or label is up to [`MAX_NAME_BYTES`] bytes of UTF-8 without control characters.
/// A link without `n` carries the empty name.
///
/// # Errors
/// `BadName` when it is not.
pub fn check_name(name: &str) -> Result<(), LinkError> {
    if name.len() > MAX_NAME_BYTES || name.chars().any(char::is_control) {
        return Err(LinkError::BadName);
    }
    Ok(())
}

/// `host:port` with a DNS name, an IPv4 address or a bracketed IPv6 address.
///
/// # Errors
/// `BadAddress` for a malformed host or shape, `BadPort` for a port outside 1 to 65535.
pub fn check_hostport(text: &str) -> Result<(), LinkError> {
    let port = if let Some(rest) = text.strip_prefix('[') {
        let (inner, tail) = rest.split_once(']').ok_or(LinkError::BadAddress)?;
        inner
            .parse::<Ipv6Addr>()
            .map_err(|_| LinkError::BadAddress)?;
        tail.strip_prefix(':').ok_or(LinkError::BadAddress)?
    } else {
        let (host, port) = text.rsplit_once(':').ok_or(LinkError::BadAddress)?;
        check_host(host)?;
        port
    };
    check_port(port)
}

fn check_host(host: &str) -> Result<(), LinkError> {
    if host.is_empty() || host.len() > 253 {
        return Err(LinkError::BadAddress);
    }
    for label in host.split('.') {
        let valid = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !valid {
            return Err(LinkError::BadAddress);
        }
    }
    // A numeric last label makes this an IPv4 literal, which must then be a valid one.
    let last = host.rsplit('.').next().unwrap_or(host);
    if last.bytes().all(|b| b.is_ascii_digit()) && host.parse::<Ipv4Addr>().is_err() {
        return Err(LinkError::BadAddress);
    }
    Ok(())
}

fn check_port(port: &str) -> Result<(), LinkError> {
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(LinkError::BadPort);
    }
    match port.parse::<u16>() {
        Ok(0) | Err(_) => Err(LinkError::BadPort),
        Ok(_) => Ok(()),
    }
}

/// An endpoint ID is the SHA-256 of a certificate: 64 lowercase hex digits.
fn check_endpoint(endpoint: &str) -> Result<(), LinkError> {
    if endpoint.len() == 64
        && endpoint
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(LinkError::BadEndpoint)
    }
}

/// A token is `GW1-` followed by letters, digits and hyphens, at most [`MAX_TOKEN_LEN`] long.
fn check_token(token: &str) -> Result<(), LinkError> {
    if token.is_empty() {
        return Err(LinkError::MissingToken);
    }
    let body = token.strip_prefix(TOKEN_TAG).ok_or(LinkError::BadToken)?;
    if body.is_empty()
        || token.len() > MAX_TOKEN_LEN
        || !body.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        || !decodes_to_64_bytes(body)
    {
        return Err(LinkError::BadToken);
    }
    Ok(())
}

/// Whether the Crockford Base32 body (hyphens ignored) holds exactly 64 bytes with zero
/// padding bits: the 32-byte secret and the 32-byte fingerprint.
fn decodes_to_64_bytes(body: &str) -> bool {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut accumulator = 0_u16;
    let mut bits = 0_u32;
    let mut length = 0_usize;
    for symbol in body.bytes().filter(|b| *b != b'-') {
        let value = match symbol.to_ascii_uppercase() {
            b'O' => 0,
            b'I' | b'L' => 1,
            other => match ALPHABET.iter().position(|&item| item == other) {
                Some(position) => u16::try_from(position).unwrap_or(0),
                None => return false,
            },
        };
        accumulator = (accumulator << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            length += 1;
            accumulator &= (1 << bits) - 1;
        }
    }
    length == 64 && bits == 3 && accumulator == 0
}

fn decode_name(raw: &str) -> Result<String, LinkError> {
    let name = String::from_utf8(percent_decode(raw)?).map_err(|_| LinkError::BadName)?;
    check_name(&name)?;
    Ok(name)
}

fn decode_hostport(raw: &str) -> Result<String, LinkError> {
    let text = String::from_utf8(percent_decode(raw)?).map_err(|_| LinkError::BadName)?;
    check_hostport(&text)?;
    Ok(text)
}

/// Appends `text` percent-encoded: unreserved characters stay, a space becomes `+` and
/// every other byte becomes `%XX`.
fn percent_encode_into(out: &mut String, text: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in text.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(byte));
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(char::from(HEX[usize::from(byte >> 4)]));
                out.push(char::from(HEX[usize::from(byte & 0x0F)]));
            }
        }
    }
}

/// Reverses [`percent_encode_into`]: `+` is a space and `%XX` is a byte.
fn percent_decode(text: &str) -> Result<Vec<u8>, LinkError> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' => {
                let high = bytes.get(index + 1).and_then(|&b| hex_value(b));
                let low = bytes.get(index + 2).and_then(|&b| hex_value(b));
                match (high, low) {
                    (Some(high), Some(low)) => out.push((high << 4) | low),
                    _ => return Err(LinkError::BadEncoding),
                }
                index += 3;
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }
    Ok(out)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "GW1-000G4-0R40M-30E20-9185G-R38E1-W8124-GK2GA-HC5RR-34D1P-70X3R-FJ089-24CJ2-A9H75-0MJMA-SC5MQ-2YC1H-68SK8-D9P6W-W3JEH-V7GYK-WFR";

    fn enroll() -> EnrollLink {
        EnrollLink {
            role: Role::Desktop,
            name: "Gussek Relay".into(),
            server: "relay.example.org:8787".into(),
            enrollment: "relay.example.org:8788".into(),
            label: Some("Anna Laptop".into()),
            token: Zeroizing::new(TOKEN.into()),
        }
    }

    fn pair() -> PairLink {
        PairLink {
            endpoint: "ab".repeat(32),
            name: "Eclipse Laptop".into(),
            token: Zeroizing::new(TOKEN.into()),
        }
    }

    fn error(text: &str) -> LinkError {
        Link::parse(text).unwrap_err()
    }

    #[test]
    fn enrollment_links_round_trip() {
        let text = enroll().build().unwrap();
        assert_eq!(
            text,
            format!(
                "sap-adt://enroll?v=1&r=desktop&n=Gussek+Relay&s=relay.example.org:8787&e=relay.example.org:8788&l=Anna+Laptop&t={TOKEN}"
            )
        );
        let parsed = EnrollLink::parse(&text).unwrap();
        assert_eq!(parsed.role, Role::Desktop);
        assert_eq!(parsed.name, "Gussek Relay");
        assert_eq!(parsed.server, "relay.example.org:8787");
        assert_eq!(parsed.enrollment, "relay.example.org:8788");
        assert_eq!(parsed.label.as_deref(), Some("Anna Laptop"));
        assert_eq!(parsed.token.as_str(), TOKEN);
        assert!(PairLink::parse(&text).is_err());
    }

    #[test]
    fn pairing_links_round_trip() {
        let text = pair().build().unwrap();
        let parsed = PairLink::parse(&text).unwrap();
        assert_eq!(parsed.endpoint, "ab".repeat(32));
        assert_eq!(parsed.name, "Eclipse Laptop");
        assert_eq!(parsed.token.as_str(), TOKEN);
        assert!(EnrollLink::parse(&text).is_err());
    }

    #[test]
    fn hosts_may_be_dns_names_ipv4_or_bracketed_ipv6() {
        for good in [
            "relay.example.org:8787",
            "localhost:1",
            "10.0.0.5:65535",
            "[::1]:8787",
            "[2001:db8::1]:8787",
        ] {
            assert_eq!(check_hostport(good), Ok(()), "{good}");
        }
        for (bad, code) in [
            ("relay.example.org", LinkError::BadAddress),
            ("::1:8787", LinkError::BadAddress),
            ("[::1]", LinkError::BadAddress),
            ("[::1:8787", LinkError::BadAddress),
            ("999.1.1.1:80", LinkError::BadAddress),
            ("-bad.example:80", LinkError::BadAddress),
            ("a..b:80", LinkError::BadAddress),
            (":80", LinkError::BadAddress),
            ("host:0", LinkError::BadPort),
            ("host:65536", LinkError::BadPort),
            ("host:", LinkError::BadPort),
            ("host:80x", LinkError::BadPort),
        ] {
            assert_eq!(check_hostport(bad), Err(code), "{bad}");
        }
    }

    #[test]
    fn errors_follow_the_documented_checks() {
        let ok = enroll().build().unwrap();
        assert_eq!(error("https://example.org"), LinkError::NotALink);
        assert_eq!(
            error(&format!("{ok}&x={}", "a".repeat(MAX_LINK_LEN))),
            LinkError::TooLong
        );
        assert_eq!(
            error(&ok.replace("v=1", "v=2")),
            LinkError::NeedsNewerVersion
        );
        assert_eq!(
            error(&ok.replace("v=1", "v=99999999999")),
            LinkError::NeedsNewerVersion
        );
        assert_eq!(error(&ok.replace("&r=desktop", "")), LinkError::MissingPart);
        assert_eq!(
            error(&ok.replace("&s=relay.example.org:8787", "")),
            LinkError::MissingPart
        );
        assert_eq!(
            error(&format!("{ok}&s=a.example:1")),
            LinkError::RepeatedPart
        );
        assert_eq!(
            error(&ok.replace("desktop", "root")),
            LinkError::UnknownRole
        );
        assert_eq!(
            EnrollLink::parse(&ok.replace("&n=Gussek+Relay", ""))
                .unwrap()
                .name,
            ""
        );
        assert_eq!(error(&ok.replace(TOKEN, "GW1-ABCD")), LinkError::BadToken);
        assert_eq!(
            error(&ok.replace("Gussek+Relay", "A%00B")),
            LinkError::BadName
        );
        assert_eq!(
            error(&ok.replace("Gussek+Relay", "A%zz")),
            LinkError::BadEncoding
        );
        assert_eq!(
            error(&ok.replace("Gussek+Relay", "%FF")),
            LinkError::BadName
        );
        assert_eq!(error(&ok.replace(":8788&", ":0&")), LinkError::BadPort);
        assert_eq!(
            error(&ok.replace(&format!("&t={TOKEN}"), "")),
            LinkError::MissingToken
        );
        assert_eq!(error(&ok.replace(TOKEN, "XX1-ABCD")), LinkError::BadToken);
        let bad_endpoint = pair().build().unwrap().replace("abab", "ABab");
        assert_eq!(error(&bad_endpoint), LinkError::BadEndpoint);
    }

    #[test]
    fn scheme_is_case_insensitive_and_fragments_and_unknown_keys_are_ignored() {
        let text = format!(
            "  SAP-ADT://ENROLL?v=1&future=1&r=eclipse&n=A&s=h.example:1&e=h.example:2&t={TOKEN}#note "
        );
        let parsed = EnrollLink::parse(&text).unwrap();
        assert_eq!(parsed.role, Role::Eclipse);
        assert!(parsed.label.is_none());
    }

    #[test]
    fn the_token_is_never_shown() {
        let link = enroll();
        assert!(!format!("{link:?}").contains("000G4"));
        assert!(format!("{link:?}").contains("redacted"));
        let pairing = pair();
        assert!(!format!("{pairing:?}").contains("000G4"));
        for code in [
            LinkError::NotALink,
            LinkError::BadToken,
            LinkError::BadEncoding,
        ] {
            assert!(!code.to_string().contains("GW1"));
        }
    }

    #[test]
    fn names_are_limited() {
        assert_eq!(check_name(&"a".repeat(MAX_NAME_BYTES)), Ok(()));
        assert_eq!(
            check_name(&"a".repeat(MAX_NAME_BYTES + 1)),
            Err(LinkError::BadName)
        );
        assert_eq!(check_name("tab\there"), Err(LinkError::BadName));
        let mut link = enroll();
        link.name = "Zoë".into();
        let parsed = EnrollLink::parse(&link.build().unwrap()).unwrap();
        assert_eq!(parsed.name, "Zoë");
    }

    /// Seeded random input: the parser never panics and only ever returns a known code.
    #[test]
    fn random_input_never_panics() {
        let alphabet: Vec<char> =
            "sap-adt://enrolpiv=1&r%+#.:[]nstlGW0123456789ABCDEFabcdef \u{e9}\u{0}"
                .chars()
                .collect();
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let seeds = [enroll().build().unwrap(), pair().build().unwrap()];
        for round in 0..4000_usize {
            let text: String = if round % 2 == 0 {
                (0..(next() % 80))
                    .map(|_| alphabet[usize::try_from(next()).unwrap() % alphabet.len()])
                    .collect()
            } else {
                // Mutate a valid link: replace a few characters.
                let mut chars: Vec<char> = seeds[round / 2 % 2].chars().collect();
                for _ in 0..=(next() % 4) {
                    let at = usize::try_from(next()).unwrap() % chars.len();
                    chars[at] = alphabet[usize::try_from(next()).unwrap() % alphabet.len()];
                }
                chars.into_iter().collect()
            };
            if let Err(error) = Link::parse(&text) {
                assert_ne!(error.code(), "");
            }
        }
    }
}
