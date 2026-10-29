//! Small shared helpers: errors, hex, text ranges, randomness.

use std::fmt::Write as _;
use std::ops::Range;

use rand_chacha::ChaCha20Rng;
use tokenator_crypto::rand_core::SeedableRng;
use tokenator_crypto::{HashAlg, digest};

use crate::dto::common::{Bytes, HashName, TextRange};
use crate::dto::error::{EngineError, ErrorCode};

/// `Err(EngineError)` with a code and message.
pub(crate) fn err<T>(code: ErrorCode, message: impl Into<String>) -> Result<T, EngineError> {
    Err(EngineError::new(code, message))
}

/// Lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String cannot fail.
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Parses hex, ignoring ASCII whitespace and `:`; `None` if it is not hex.
pub(crate) fn unhex(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b':')
        .collect();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    let value = |b: u8| {
        char::from(b)
            .to_digit(16)
            .and_then(|v| u8::try_from(v).ok())
    };
    digits
        .chunks(2)
        .map(|pair| match pair {
            [hi, lo] => Some(value(*hi)? << 4 | value(*lo)?),
            _ => None,
        })
        .collect()
}

/// A length or offset as a wire `u32` (saturating; tokens are small).
pub(crate) fn u32_of(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// The `tokenator-crypto` hash for a wire hash name.
pub(crate) fn hash_alg(h: HashName) -> HashAlg {
    match h {
        HashName::Sha256 => HashAlg::Sha256,
        HashName::Sha384 => HashAlg::Sha384,
        HashName::Sha512 => HashAlg::Sha512,
    }
}

/// JSON string literal for `s` (quotes included, minimal escaping).
pub(crate) fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Maps byte offsets of a text to UTF-16 offsets and line numbers.
pub(crate) struct TextIndex {
    /// UTF-16 offset of every byte offset (char boundaries only are meaningful).
    utf16: Vec<u32>,
    /// Byte offsets of the line feeds.
    newlines: Vec<usize>,
}

impl TextIndex {
    pub(crate) fn new(text: &str) -> TextIndex {
        let mut utf16 = Vec::with_capacity(text.len() + 1);
        let mut units = 0u32;
        for c in text.chars() {
            for _ in 0..c.len_utf8() {
                utf16.push(units);
            }
            units += u32_of(c.len_utf16());
        }
        utf16.push(units);
        let newlines = text
            .bytes()
            .enumerate()
            .filter(|(_, b)| *b == b'\n')
            .map(|(i, _)| i)
            .collect();
        TextIndex { utf16, newlines }
    }

    /// UTF-16 offset of a byte offset (clamped to the text).
    pub(crate) fn unit(&self, byte: usize) -> u32 {
        self.utf16
            .get(byte)
            .or_else(|| self.utf16.last())
            .copied()
            .unwrap_or(0)
    }

    /// The UTF-16 range and lines of a byte range.
    pub(crate) fn range(&self, bytes: Range<usize>) -> TextRange {
        let end = bytes.end.max(bytes.start);
        let before = self.newlines.partition_point(|&n| n < bytes.start);
        let inside = self.newlines.partition_point(|&n| n < end) - before;
        TextRange {
            start: self.unit(bytes.start),
            end: self.unit(end),
            line_start: u32_of(before),
            line_end: u32_of(before + inside + 1),
        }
    }
}

/// Number of lines as the main pane counts them (`split('\n')`).
pub(crate) fn line_count(text: &str) -> u32 {
    u32_of(text.bytes().filter(|b| *b == b'\n').count() + 1)
}

/// A validated 32-byte randomness seed, or `None` when absent.
pub(crate) fn seed32(randomness: Option<&Bytes>) -> Result<Option<[u8; 32]>, EngineError> {
    match randomness {
        None => Ok(None),
        Some(b) => <[u8; 32]>::try_from(&b[..]).map(Some).map_err(|_| {
            EngineError::new(
                ErrorCode::Randomness,
                format!("randomness must be 32 bytes, got {}", b.len()),
            )
        }),
    }
}

/// The RNG for one purpose of one call.
///
/// Every random value the Engine produces comes from a ChaCha20 stream
/// keyed by `SHA-256("tokenator-core/v1/" || purpose || 0x00 || seed)`, so
/// one seed drives independent, stable streams (salts, decoys, signatures,
/// keys) and the same inputs always give the same output on every target.
pub(crate) fn rng(seed: &[u8; 32], purpose: &str) -> ChaCha20Rng {
    let mut input = Vec::with_capacity(64);
    input.extend_from_slice(b"tokenator-core/v1/");
    input.extend_from_slice(purpose.as_bytes());
    input.push(0);
    input.extend_from_slice(seed);
    let mut key = [0u8; 32];
    for (k, d) in key.iter_mut().zip(digest(HashAlg::Sha256, &input)) {
        *k = d;
    }
    ChaCha20Rng::from_seed(key)
}

/// An RNG for calls whose randomness is never drawn (or is replaced by a
/// deterministic signature afterwards).
pub(crate) fn unused_rng() -> ChaCha20Rng {
    rng(&[0; 32], "unused")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        assert_eq!(hex(&[0, 0xab, 0xff]), "00abff");
        assert_eq!(unhex("00 AB:ff"), Some(vec![0, 0xab, 0xff]));
        assert_eq!(unhex("0"), None);
        assert_eq!(unhex("zz"), None);
    }

    #[test]
    fn text_index_counts_utf16_and_lines() {
        let text = "a\u{1f600}\nb";
        let idx = TextIndex::new(text);
        // "a" (1) + emoji (2 units, 4 bytes) + "\n" + "b"
        let b = text.find('b').unwrap();
        let r = idx.range(b..b + 1);
        assert_eq!((r.start, r.end, r.line_start, r.line_end), (4, 5, 1, 2));
        assert_eq!(idx.range(0..b).line_end, 2);
        assert_eq!(line_count(text), 2);
    }

    #[test]
    fn rng_streams_are_separated() {
        use tokenator_crypto::rand_core::Rng;
        let mut a = rng(&[1; 32], "salts");
        let mut b = rng(&[1; 32], "decoys");
        let mut c = rng(&[1; 32], "salts");
        let (x, y, z) = (a.next_u64(), b.next_u64(), c.next_u64());
        assert_ne!(x, y);
        assert_eq!(x, z);
    }

    #[test]
    fn json_strings_escape() {
        assert_eq!(json_string("a\"b\\\n\u{1}"), r#""a\"b\\\n\u0001""#);
    }
}
