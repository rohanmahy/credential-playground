//! Text encodings: base64 (both alphabets), hex, percent-encoding, and JSON
//! string escaping. Decoders are strict where detection needs them to be
//! (canonical base64 trailing bits, no mixed alphabets) and lenient about
//! layout (line breaks, hex separators), which `rewrap` re-creates.

use crate::Layer;

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Which base64 alphabet a decoder accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Alphabet {
    /// `+/` (RFC 4648 §4).
    Std,
    /// `-_` (RFC 4648 §5).
    Url,
}

/// The result of decoding base64 text.
pub(crate) struct Base64 {
    pub(crate) bytes: Vec<u8>,
    /// `+` or `/` was seen.
    pub(crate) std_chars: bool,
    /// `-` or `_` was seen.
    pub(crate) url_chars: bool,
    pub(crate) padded: bool,
    /// The data length is not a multiple of three, so padded text has `=`.
    pub(crate) needs_padding: bool,
    /// Length of the first line, if the text spans several lines.
    pub(crate) wrap: Option<usize>,
}

impl Base64 {
    /// The layer that describes this text (see [`Layer::Base64Url`] for the
    /// rule when neither alphabet's special characters appear).
    ///
    /// Text that needs no padding is recorded with each alphabet's usual
    /// form: padded for classic base64, unpadded for base64url.
    pub(crate) fn layer(&self) -> Layer {
        let wrap = self.wrap;
        if self.std_chars || (!self.url_chars && self.padded) {
            Layer::Base64Std {
                padded: self.padded || !self.needs_padding,
                wrap,
            }
        } else {
            Layer::Base64Url {
                padded: self.padded,
                wrap,
            }
        }
    }
}

fn b64_value(c: u8) -> Option<(u8, Option<Alphabet>)> {
    Some(match c {
        b'A'..=b'Z' => (c - b'A', None),
        b'a'..=b'z' => (c - b'a' + 26, None),
        b'0'..=b'9' => (c - b'0' + 52, None),
        b'+' => (62, Some(Alphabet::Std)),
        b'/' => (63, Some(Alphabet::Std)),
        b'-' => (62, Some(Alphabet::Url)),
        b'_' => (63, Some(Alphabet::Url)),
        _ => return None,
    })
}

/// Decodes base64, ignoring `\r` and `\n`. With `alphabet` set only that
/// alphabet is accepted; with `None` either is, but not both. Padding is
/// optional but must be correct when present, and the unused trailing bits
/// must be zero.
pub(crate) fn base64_decode(text: &[u8], alphabet: Option<Alphabet>) -> Option<Base64> {
    let mut bytes = Vec::with_capacity(text.len() / 4 * 3 + 2);
    let (mut acc, mut bits, mut chars, mut pad) = (0u32, 0u32, 0usize, 0usize);
    let (mut std_chars, mut url_chars) = (false, false);
    for &c in text {
        if c == b'\n' || c == b'\r' {
            continue;
        }
        if c == b'=' {
            pad += 1;
            continue;
        }
        if pad > 0 {
            return None;
        }
        let (v, alpha) = b64_value(c)?;
        match alpha {
            Some(Alphabet::Std) => std_chars = true,
            Some(Alphabet::Url) => url_chars = true,
            None => {}
        }
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        chars += 1;
        if bits >= 8 {
            bits -= 8;
            bytes.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    let alphabet_ok = match alphabet {
        Some(Alphabet::Std) => !url_chars,
        Some(Alphabet::Url) => !std_chars,
        None => !(std_chars && url_chars),
    };
    let expected_pad = (4 - chars % 4) % 4;
    if !alphabet_ok || chars % 4 == 1 || acc != 0 || (pad != 0 && pad != expected_pad) {
        return None;
    }
    let wrap = line_wrap(text, |line| line.len());
    Some(Base64 {
        bytes,
        std_chars,
        url_chars,
        padded: pad > 0,
        needs_padding: expected_pad > 0,
        wrap,
    })
}

/// If `text` has more than one non-empty line, `measure` of the first line
/// (without a trailing `\r`).
fn line_wrap(text: &[u8], measure: impl Fn(&[u8]) -> usize) -> Option<usize> {
    let mut lines = text.split(|&c| c == b'\n');
    let first = lines.next()?;
    if !lines.any(|l| !l.is_empty()) {
        return None;
    }
    let first = first.strip_suffix(b"\r").unwrap_or(first);
    Some(measure(first))
}

/// Encodes `data` as base64, wrapping lines at `wrap` characters.
pub(crate) fn base64_encode(
    data: &[u8],
    alphabet: Alphabet,
    padded: bool,
    wrap: Option<usize>,
) -> Vec<u8> {
    let table = match alphabet {
        Alphabet::Std => STD,
        Alphabet::Url => URL,
    };
    let char_at = |v: u32| table.get((v & 63) as usize).copied().unwrap_or(b'A');
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk.len();
        let b = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let v = (b(0) << 16) | (b(1) << 8) | b(2);
        for i in 0..4u32 {
            if i as usize <= n {
                out.push(char_at(v >> (18 - 6 * i)));
            } else if padded {
                out.push(b'=');
            }
        }
    }
    wrap_lines(out, wrap)
}

fn wrap_lines(text: Vec<u8>, wrap: Option<usize>) -> Vec<u8> {
    match wrap {
        Some(w) if w > 0 && text.len() > w => text.chunks(w).collect::<Vec<_>>().join(&b'\n'),
        _ => text,
    }
}

/// The result of decoding hex text.
pub(crate) struct Hex {
    pub(crate) bytes: Vec<u8>,
    pub(crate) layer: Layer,
}

fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decodes hex text, ignoring ASCII whitespace and `:`. The returned layer
/// describes the layout of the first line.
pub(crate) fn hex_decode(text: &[u8]) -> Option<Hex> {
    let mut bytes = Vec::with_capacity(text.len() / 2);
    let mut high: Option<u8> = None;
    let (mut upper, mut lower) = (false, false);
    for &c in text {
        if c.is_ascii_whitespace() || c == b':' {
            continue;
        }
        let v = hex_value(c)?;
        upper |= c.is_ascii_uppercase();
        lower |= c.is_ascii_lowercase();
        match high.take() {
            Some(h) => bytes.push(h << 4 | v),
            None => high = Some(v),
        }
    }
    if high.is_some() {
        return None;
    }
    let first_line = text.split(|&c| c == b'\n').next().unwrap_or_default();
    let separator = if first_line.contains(&b':') {
        Some(':')
    } else if first_line.trim_ascii().contains(&b' ') {
        Some(' ')
    } else {
        None
    };
    let digits = |line: &[u8]| line.iter().filter(|c| c.is_ascii_hexdigit()).count();
    let wrap = line_wrap(text, digits)
        .filter(|d| d % 2 == 0 && *d > 0)
        .map(|d| d / 2);
    Some(Hex {
        bytes,
        layer: Layer::Hex {
            upper: upper && !lower,
            separator,
            wrap,
        },
    })
}

/// Encodes `data` as hex with `separator` between bytes and `wrap` bytes per
/// line.
pub(crate) fn hex_encode(
    data: &[u8],
    upper: bool,
    separator: Option<char>,
    wrap: Option<usize>,
) -> Vec<u8> {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let digit = |v: u8| digits.get(usize::from(v & 15)).copied().unwrap_or(b'0');
    let per_line = wrap.filter(|&w| w > 0).unwrap_or(usize::MAX);
    let mut sep = [0u8; 4];
    let sep: &[u8] = match separator {
        Some(c) => c.encode_utf8(&mut sep).as_bytes(),
        None => &[],
    };
    let mut out = Vec::with_capacity(data.len() * (2 + sep.len()));
    for (i, &b) in data.iter().enumerate() {
        if i > 0 {
            if i % per_line == 0 {
                out.push(b'\n');
            } else {
                out.extend_from_slice(sep);
            }
        }
        out.push(digit(b >> 4));
        out.push(digit(b));
    }
    out
}

/// Decodes `%XX` escapes (either case). `+` is literal. Fails on a `%` not
/// followed by two hex digits. Returns the bytes and whether any escape was
/// present.
pub(crate) fn percent_decode(text: &[u8]) -> Option<(Vec<u8>, bool)> {
    let mut out = Vec::with_capacity(text.len());
    let mut escaped = false;
    let mut i = 0;
    while let Some(&c) = text.get(i) {
        if c == b'%' {
            let h = hex_value(*text.get(i + 1)?)?;
            let l = hex_value(*text.get(i + 2)?)?;
            out.push(h << 4 | l);
            escaped = true;
            i += 3;
        } else {
            out.push(c);
            i += 1;
        }
    }
    Some((out, escaped))
}

/// Escapes every byte outside the RFC 3986 unreserved set as upper-case
/// `%XX`.
pub(crate) fn percent_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b);
        } else {
            out.push(b'%');
            out.extend(hex_encode(&[b], true, None, None));
        }
    }
    out
}

/// Appends `s` as a JSON string literal with minimal escaping: `"`, `\`, and
/// control characters. `/` and non-ASCII are left as is.
pub(crate) fn json_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            c if u32::from(c) < 0x20 => {
                out.extend_from_slice(b"\\u00");
                out.extend(hex_encode(&[c as u8], false, None, None));
            }
            c => out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()),
        }
    }
    out.push(b'"');
}

/// The preferred CBOR head for tag `tag` (major type 6).
pub(crate) fn tag_head(tag: u64) -> Vec<u8> {
    const MAJOR: u8 = 6 << 5;
    match tag {
        0..=23 => vec![MAJOR | tag as u8],
        24..=0xff => vec![MAJOR | 24, tag as u8],
        0x100..=0xffff => [&[MAJOR | 25][..], &(tag as u16).to_be_bytes()].concat(),
        0x1_0000..=0xffff_ffff => [&[MAJOR | 26][..], &(tag as u32).to_be_bytes()].concat(),
        _ => [&[MAJOR | 27][..], &tag.to_be_bytes()].concat(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_rfc4648_vectors() {
        for (plain, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(
                base64_encode(plain.as_bytes(), Alphabet::Std, true, None),
                enc.as_bytes()
            );
            let d = base64_decode(enc.as_bytes(), None).unwrap();
            assert_eq!(d.bytes, plain.as_bytes());
        }
    }

    #[test]
    fn base64_rejects_noncanonical_and_mixed() {
        assert!(base64_decode(b"Zh==", None).is_none()); // trailing bits
        assert!(base64_decode(b"Zg=", None).is_none()); // short padding
        assert!(base64_decode(b"Z", None).is_none());
        assert!(base64_decode(b"+-AA", None).is_none());
        assert!(base64_decode(b"+/AA", Some(Alphabet::Url)).is_none());
    }

    #[test]
    fn hex_layout() {
        let h = hex_decode(b"A1:01\n26").unwrap();
        assert_eq!(h.bytes, [0xa1, 0x01, 0x26]);
        assert_eq!(
            h.layer,
            Layer::Hex {
                upper: true,
                separator: Some(':'),
                wrap: Some(2)
            }
        );
        assert!(hex_decode(b"abc").is_none());
    }

    #[test]
    fn percent() {
        assert_eq!(percent_decode(b"a%2b+").unwrap(), (b"a++".to_vec(), true));
        assert!(percent_decode(b"%g0").is_none());
        assert!(percent_decode(b"%0").is_none());
    }
}
