//! Application-extensions (prefixed literals such as `h'…'` and `dt'…'`).

use std::borrow::Cow;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

#[cfg(feature = "hash")]
use sha2::{Digest, Sha256, Sha384, Sha512};
use tokenator_cbor::{Item, Value, Width, decode};

use crate::datetime::Instant;

/// Tag number for an app-extension literal that no registered extension
/// resolved (draft-ietf-cbor-edn-literals-27 §5.1, "CPA999").
///
/// The content is `[prefix, [args…]]`: the prefix as written, then the
/// arguments. A string literal (`cri'…'` or ``cri`…` ``) has one text
/// string argument holding the decoded string content; a sequence literal
/// (`cri<<…>>`) has one argument per item, each with its encoding indicators.
pub const UNRESOLVED_EXTENSION_TAG: u64 = 999;

/// Tag number for elided content (draft-ietf-cbor-edn-literals-27 §5.2,
/// "CPA888"; -28 dropped it, issue #14 keeps it).
///
/// `888(null)` stands for one ellipsis. An `h''` literal with ellipses
/// between its bytes becomes `888([parts…])`, where the parts alternate
/// between byte strings and `888(null)`, in order; adjacent ellipses
/// count as one, and an `h''` holding only an ellipsis becomes `888(null)`.
/// For example `h'4711...0815'` is `888([h'4711', 888(null), h'0815'])`.
pub const ELLIPSIS_TAG: u64 = 888;

/// Why an app-extension rejected its input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtError(pub String);

impl fmt::Display for ExtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ExtError {}

/// An app-extension: turns the input of a prefixed literal into an item.
///
/// The input is a CBOR sequence. A string literal (`p'…'` or ``p`…` ``)
/// arrives as a single text string holding the decoded string content
/// (escapes processed, CRs removed); a sequence literal `p<<…>>` arrives as
/// its items, which keep their encoding indicators. As the draft requires,
/// an extension cannot tell `p'x'` from `p<<"x">>`.
pub trait AppExtension: Send + Sync {
    /// The app-extension identifier: lowercase, `[a-z][a-z0-9-]*`.
    fn name(&self) -> &str;

    /// Evaluates the literal. `uppercase` is true when the prefix was the
    /// all-uppercase variant (`DT`, `IP`); extensions without one return an
    /// error for it.
    fn evaluate(&self, args: &[Item<'static>], uppercase: bool) -> Result<Item<'static>, ExtError>;
}

/// The set of app-extensions a parse can use.
///
/// [`Extensions::builtin`] (also the [`Default`]) holds `h`, `b64`, `dt`,
/// `ip`, `hash`, `b1`, `t1`, `ilbs`, `ilts`, and `float`.
pub struct Extensions {
    exts: Vec<Box<dyn AppExtension>>,
}

impl Extensions {
    /// No extensions at all (every prefixed literal is unknown).
    pub fn empty() -> Extensions {
        Extensions { exts: Vec::new() }
    }

    /// The built-in extensions.
    pub fn builtin() -> Extensions {
        Extensions {
            exts: vec![
                Box::new(Builtin::H),
                Box::new(Builtin::B64),
                Box::new(Builtin::Dt),
                Box::new(Builtin::Ip),
                Box::new(Builtin::Hash),
                Box::new(Builtin::B1),
                Box::new(Builtin::T1),
                Box::new(Builtin::Ilbs),
                Box::new(Builtin::Ilts),
                Box::new(Builtin::Float),
            ],
        }
    }

    /// Adds an extension, replacing any existing one with the same name.
    pub fn register(&mut self, ext: Box<dyn AppExtension>) {
        match self.exts.iter_mut().find(|e| e.name() == ext.name()) {
            Some(slot) => *slot = ext,
            None => self.exts.push(ext),
        }
    }

    /// The extension registered under `name` (lowercase identifier).
    pub fn get(&self, name: &str) -> Option<&dyn AppExtension> {
        self.exts.iter().find(|e| e.name() == name).map(|e| &**e)
    }

    /// Names of the registered extensions, in registration order.
    pub fn names(&self) -> Vec<&str> {
        self.exts.iter().map(|e| e.name()).collect()
    }

    /// Whether `name` is the identifier of a built-in extension.
    pub fn is_builtin_name(name: &str) -> bool {
        Builtin::ALL.iter().any(|b| b.name() == name)
    }
}

impl Default for Extensions {
    fn default() -> Extensions {
        Extensions::builtin()
    }
}

impl fmt::Debug for Extensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.exts.iter().map(|e| e.name()))
            .finish()
    }
}

/// The built-in extensions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Builtin {
    H,
    B64,
    Dt,
    Ip,
    Hash,
    B1,
    T1,
    Ilbs,
    Ilts,
    Float,
}

impl Builtin {
    const ALL: [Builtin; 10] = [
        Builtin::H,
        Builtin::B64,
        Builtin::Dt,
        Builtin::Ip,
        Builtin::Hash,
        Builtin::B1,
        Builtin::T1,
        Builtin::Ilbs,
        Builtin::Ilts,
        Builtin::Float,
    ];
}

fn err<T>(message: impl Into<String>) -> Result<T, ExtError> {
    Err(ExtError(message.into()))
}

impl AppExtension for Builtin {
    fn name(&self) -> &str {
        match self {
            Builtin::H => "h",
            Builtin::B64 => "b64",
            Builtin::Dt => "dt",
            Builtin::Ip => "ip",
            Builtin::Hash => "hash",
            Builtin::B1 => "b1",
            Builtin::T1 => "t1",
            Builtin::Ilbs => "ilbs",
            Builtin::Ilts => "ilts",
            Builtin::Float => "float",
        }
    }

    fn evaluate(&self, args: &[Item<'static>], uppercase: bool) -> Result<Item<'static>, ExtError> {
        match self {
            Builtin::Dt => {
                let item = dt(&single_text(args)?)?;
                return Ok(if uppercase { Item::tag(1, item) } else { item });
            }
            Builtin::Ip => return ip(&single_text(args)?, uppercase),
            _ if uppercase => return err("no uppercase variant"),
            _ => {}
        }
        match self {
            Builtin::H => Ok(h(&single_text(args)?)?),
            Builtin::B64 => Ok(Item::bytes(base64(&single_text(args)?)?)),
            Builtin::Hash => hash(args),
            Builtin::B1 => Ok(Item::bytes(concat(args)?)),
            Builtin::T1 => String::from_utf8(concat(args)?)
                .map(Item::text)
                .or_else(|_| err("the concatenation is not valid UTF-8")),
            Builtin::Ilbs | Builtin::Ilts => indefinite(args, *self == Builtin::Ilts),
            Builtin::Float => float(args),
            Builtin::Dt | Builtin::Ip => err("unreachable"),
        }
    }
}

/// The content of the only argument, which must be a text string or a byte
/// string holding UTF-8.
fn single_text<'i>(args: &'i [Item<'static>]) -> Result<Cow<'i, str>, ExtError> {
    match args {
        [item] => match &item.value {
            Value::Text(t) => Ok(Cow::Borrowed(t)),
            Value::Bytes(b) => std::str::from_utf8(b)
                .map(Cow::Borrowed)
                .or_else(|_| err("expected text")),
            _ => err("expected a string"),
        },
        _ => err("expected exactly one string"),
    }
}

/// A piece of `h''` content.
enum HexPart {
    Bytes(Vec<u8>),
    Ellipsis,
}

/// Hex digits with blank space, comments, and ellipses (three or more
/// dots). Adjacent ellipses merge; bytes must be whole at each ellipsis.
fn hex_parts(text: &str) -> Result<Vec<HexPart>, ExtError> {
    let b = text.as_bytes();
    let mut parts = Vec::new();
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut high: Option<u8> = None;
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        i += 1;
        let nibble = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            b' ' | b'\t' | b'\n' | b'\r' => continue,
            b'#' => {
                i = skip_line(b, i);
                continue;
            }
            b'/' => {
                i = skip_comment(b, i)?;
                continue;
            }
            b'.' if b.get(i..i + 2) == Some(&b".."[..]) => {
                while b.get(i) == Some(&b'.') {
                    i += 1;
                }
                if high.is_some() {
                    return err("odd number of hex digits before an ellipsis");
                }
                if !out.is_empty() {
                    parts.push(HexPart::Bytes(std::mem::take(&mut out)));
                }
                if !matches!(parts.last(), Some(HexPart::Ellipsis)) {
                    parts.push(HexPart::Ellipsis);
                }
                continue;
            }
            _ => return err("not a hex digit"),
        };
        match high.take() {
            Some(h) => out.push(h << 4 | nibble),
            None => high = Some(nibble),
        }
    }
    if high.is_some() {
        return err("odd number of hex digits");
    }
    if !out.is_empty() || parts.is_empty() {
        parts.push(HexPart::Bytes(out));
    }
    Ok(parts)
}

/// Hex digits with blank space and comments (`float''`); no ellipses.
pub(crate) fn hex_text(text: &str) -> Result<Vec<u8>, ExtError> {
    let mut parts = hex_parts(text)?;
    match (parts.pop(), parts.is_empty()) {
        (Some(HexPart::Bytes(bytes)), true) => Ok(bytes),
        _ => err("an ellipsis is not allowed here"),
    }
}

/// `h''`: a byte string, or with ellipses the -27 §5.2 tag-888 form.
fn h(text: &str) -> Result<Item<'static>, ExtError> {
    let mut parts = hex_parts(text)?;
    let ellipsis = || Item::tag(ELLIPSIS_TAG, Item::new(Value::Null));
    match parts.as_slice() {
        [HexPart::Bytes(_)] => match parts.pop() {
            Some(HexPart::Bytes(bytes)) => Ok(Item::bytes(bytes)),
            _ => err("unreachable"),
        },
        [HexPart::Ellipsis] => Ok(ellipsis()),
        _ => Ok(Item::tag(
            ELLIPSIS_TAG,
            Item::array(
                parts
                    .into_iter()
                    .map(|p| match p {
                        HexPart::Bytes(bytes) => Item::bytes(bytes),
                        HexPart::Ellipsis => ellipsis(),
                    })
                    .collect(),
            ),
        )),
    }
}

/// Skips to the end of the line; returns the index after the LF.
fn skip_line(b: &[u8], from: usize) -> usize {
    b.get(from..)
        .and_then(|rest| rest.iter().position(|&c| c == b'\n'))
        .map_or(b.len(), |p| from + p + 1)
}

/// Skips a comment whose `/` was just consumed: `//…`, `/*…*/`, or `/…/`.
fn skip_comment(b: &[u8], from: usize) -> Result<usize, ExtError> {
    let rest = b.get(from..).unwrap_or_default();
    match rest.first() {
        Some(b'/') => Ok(skip_line(b, from + 1)),
        Some(b'*') => rest
            .get(1..)
            .and_then(|r| r.windows(2).position(|w| w == b"*/"))
            .map(|p| from + 1 + p + 2)
            .ok_or(ExtError("unterminated comment".into())),
        _ => rest
            .iter()
            .position(|&c| c == b'/')
            .map(|p| from + p + 1)
            .ok_or(ExtError("unterminated comment".into())),
    }
}

/// Base64 in either alphabet, padding optional, blank space and `#`
/// comments allowed.
fn base64(text: &str) -> Result<Vec<u8>, ExtError> {
    let b = text.as_bytes();
    let mut out = Vec::with_capacity(b.len() * 3 / 4);
    let (mut acc, mut bits, mut count, mut pad) = (0u32, 0u32, 0usize, 0usize);
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        i += 1;
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => {
                pad += 1;
                continue;
            }
            b' ' | b'\t' | b'\n' | b'\r' => continue,
            b'#' => {
                i = skip_line(b, i);
                continue;
            }
            _ => return err("not a base64 character"),
        };
        if pad > 0 {
            return err("data after padding");
        }
        count += 1;
        acc = acc << 6 | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    let ok = match count % 4 {
        0 => pad == 0,
        2 => pad == 0 || pad == 2,
        3 => pad == 0 || pad == 1,
        _ => false,
    };
    if !ok {
        return err("invalid base64 length or padding");
    }
    Ok(out)
}

/// `dt''`: RFC 3339 to epoch seconds, an integer unless the text has a
/// fraction.
pub(crate) fn dt(text: &str) -> Result<Item<'static>, ExtError> {
    let t = Instant::parse_rfc3339(text).map_err(|e| ExtError(e.to_string()))?;
    Ok(if text.contains('.') {
        Item::float(t.to_f64())
    } else {
        Item::int(t.secs())
    })
}

/// `ip''`/`IP''` (RFC 9164).
pub(crate) fn ip(text: &str, uppercase: bool) -> Result<Item<'static>, ExtError> {
    let (addr, prefix) = match text.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (text, None),
    };
    let (mut bytes, tag, max) = if addr.contains(':') {
        let a: Ipv6Addr = addr.parse().or_else(|_| err("invalid IPv6 address"))?;
        (a.octets().to_vec(), 54, 128)
    } else {
        // std rejects leading zeros in IPv4 octets.
        let a: Ipv4Addr = addr.parse().or_else(|_| err("invalid IPv4 address"))?;
        (a.octets().to_vec(), 52, 32)
    };
    let item = match prefix {
        None => Item::bytes(bytes),
        Some(p) => {
            if p.is_empty()
                || !p.bytes().all(|c| c.is_ascii_digit())
                || (p.len() > 1 && p.starts_with('0'))
            {
                return err("invalid prefix length");
            }
            let len: usize = p.parse().or_else(|_| err("invalid prefix length"))?;
            if len > max {
                return err("prefix length too long");
            }
            // Zero the host bits, then drop trailing zero bytes.
            for (i, byte) in bytes.iter_mut().enumerate() {
                let keep = len.saturating_sub(i * 8).min(8);
                *byte &= !(0xffu8.checked_shr(keep as u32).unwrap_or(0));
            }
            while bytes.last() == Some(&0) {
                bytes.pop();
            }
            Item::array(vec![Item::int(len as i64), Item::bytes(bytes)])
        }
    };
    Ok(if uppercase {
        Item::tag(tag, item)
    } else {
        item
    })
}

/// The text form of an address for `IP''`: dotted quad, or RFC 5952 IPv6
/// (with `::ffff:a.b.c.d` for IPv4-mapped addresses).
pub(crate) fn ip_text(bytes: &[u8]) -> Option<String> {
    if let Ok(v4) = <[u8; 4]>::try_from(bytes) {
        return Some(Ipv4Addr::from(v4).to_string());
    }
    let v6 = Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?);
    // std's Display follows RFC 5952, including the IPv4-mapped form.
    Some(v6.to_string())
}

/// Without the `hash` feature, `hash''` is a built-in that always fails
/// (issue #15), so it is not mistaken for an unknown extension.
#[cfg(not(feature = "hash"))]
fn hash(_: &[Item<'static>]) -> Result<Item<'static>, ExtError> {
    err("hash'' needs the tokenator-edn `hash` feature")
}

/// `hash<<data[, alg]>>` (draft §3.4).
#[cfg(feature = "hash")]
fn hash(args: &[Item<'static>]) -> Result<Item<'static>, ExtError> {
    let (data, alg) = match args {
        [data] => (data, None),
        [data, alg] => (data, Some(alg)),
        _ => return err("expected data and an optional algorithm"),
    };
    let data: &[u8] = match &data.value {
        Value::Bytes(b) => b,
        Value::Text(t) => t.as_bytes(),
        _ => return err("the data must be a string"),
    };
    let alg = match alg.map(|a| &a.value) {
        None => -16,
        Some(Value::Nint(n)) => -1 - i64::try_from(*n).unwrap_or(i64::MAX),
        Some(Value::Uint(n)) => i64::try_from(*n).unwrap_or(i64::MAX),
        Some(Value::Text(name)) => match name.as_ref() {
            "SHA-256" => -16,
            "SHA-384" => -43,
            "SHA-512" => -44,
            "SHA-256/64" => -15,
            _ => return err(format!("unsupported hash algorithm {name:?}")),
        },
        Some(_) => return err("the algorithm must be an integer or a name"),
    };
    let digest = match alg {
        -16 => Sha256::digest(data).to_vec(),
        -43 => Sha384::digest(data).to_vec(),
        -44 => Sha512::digest(data).to_vec(),
        -15 => Sha256::digest(data).get(..8).unwrap_or_default().to_vec(),
        _ => return err(format!("unsupported hash algorithm {alg}")),
    };
    Ok(Item::bytes(digest))
}

/// The concatenated content of string arguments (`b1`, `t1`).
fn concat(args: &[Item<'static>]) -> Result<Vec<u8>, ExtError> {
    let mut out = Vec::new();
    for arg in args {
        match &arg.value {
            Value::Bytes(b) => out.extend_from_slice(b),
            Value::Text(t) => out.extend_from_slice(t.as_bytes()),
            _ => return err("every argument must be a string"),
        }
    }
    Ok(out)
}

/// `ilbs`/`ilts`: an indefinite-length string with the arguments as chunks.
fn indefinite(args: &[Item<'static>], text: bool) -> Result<Item<'static>, ExtError> {
    let mut chunks = Vec::with_capacity(args.len());
    for arg in args {
        if arg.width == Width::Indefinite {
            return err("chunks must have definite length");
        }
        let content: &[u8] = match &arg.value {
            Value::Bytes(b) => b,
            Value::Text(t) => t.as_bytes(),
            _ => return err("every argument must be a string"),
        };
        let value = if text {
            match std::str::from_utf8(content) {
                Ok(t) => Value::Text(Cow::Owned(t.to_owned())),
                Err(_) => return err("a chunk is not valid UTF-8"),
            }
        } else {
            Value::Bytes(Cow::Owned(content.to_vec()))
        };
        chunks.push(Item::new(value).with_width(arg.width));
    }
    let mut item = Item::indefinite_string(chunks);
    if text && item.chunks.is_empty() {
        item.value = Value::Text(Cow::Borrowed(""));
    }
    Ok(item)
}

/// `float''`: binary16/32/64 bits as hex (or as a byte string).
fn float(args: &[Item<'static>]) -> Result<Item<'static>, ExtError> {
    let bytes: Cow<'_, [u8]> = match args {
        [
            Item {
                value: Value::Text(t),
                ..
            },
        ] => Cow::Owned(hex_text(t)?),
        [
            Item {
                value: Value::Bytes(b),
                ..
            },
        ] => Cow::Borrowed(b),
        _ => return err("expected one string"),
    };
    let initial = match bytes.len() {
        2 => 0xf9,
        4 => 0xfa,
        8 => 0xfb,
        _ => return err("expected 2, 4, or 8 bytes"),
    };
    let mut encoded = vec![initial];
    encoded.extend_from_slice(&bytes);
    // The decoder converts the bits exactly (NaN payloads included).
    match decode(&encoded).map(|i| i.value) {
        Ok(Value::Float(f, _)) => Ok(Item::float(f)),
        _ => err("not a float"),
    }
}
