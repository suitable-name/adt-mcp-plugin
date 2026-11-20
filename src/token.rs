use zeroize::Zeroizing;

pub const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Decodes a `GW1-` token into its 64-byte payload: the 32-byte secret, then the 32-byte
/// fingerprint the link pins. `None` for anything that is not a well-formed token.
#[must_use]
pub fn decode(token: &str) -> Option<Zeroizing<[u8; 64]>> {
    let token = token.trim();
    if !token.get(..3)?.eq_ignore_ascii_case("GW1") {
        return None;
    }
    let mut bytes = Zeroizing::new([0; 64]);
    let mut accumulator = 0_u16;
    let mut bits = 0;
    let mut length = 0;
    for symbol in token[3..]
        .bytes()
        .filter(|b| *b != b'-' && !b.is_ascii_whitespace())
    {
        let value = match symbol.to_ascii_uppercase() {
            b'O' => 0,
            b'I' | b'L' => 1,
            other => u16::try_from(ALPHABET.iter().position(|&item| item == other)?).ok()?,
        };
        accumulator = (accumulator << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            *bytes.get_mut(length)? = u8::try_from(accumulator >> bits).ok()?;
            accumulator &= (1 << bits) - 1;
            length += 1;
        }
    }
    (length == bytes.len() && bits == 3 && accumulator == 0).then_some(bytes)
}
