//! Shared wire types: bytes, node ids, ranges.

use std::fmt;
use std::ops::Deref;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Binary data. Serialized as unpadded base64url text (TypeScript `string`).
///
/// ```
/// use tokenator_core::Bytes;
///
/// let b = Bytes::from(vec![0xd2, 0x84]);
/// assert_eq!(b.to_base64url(), "0oQ");
/// assert_eq!(Bytes::from_base64url("0oQ").unwrap(), b);
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct Bytes(#[cfg_attr(feature = "ts", ts(type = "string"))] pub Vec<u8>);

impl Bytes {
    /// The unpadded base64url form used on the wire.
    pub fn to_base64url(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.0)
    }

    /// Parses unpadded base64url; `None` if it is not.
    pub fn from_base64url(text: &str) -> Option<Bytes> {
        Base64UrlUnpadded::decode_vec(text).ok().map(Bytes)
    }

    /// The bytes as a vector.
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(v: Vec<u8>) -> Bytes {
        Bytes(v)
    }
}

impl From<&[u8]> for Bytes {
    fn from(v: &[u8]) -> Bytes {
        Bytes(v.to_vec())
    }
}

impl From<&str> for Bytes {
    fn from(v: &str) -> Bytes {
        Bytes(v.as_bytes().to_vec())
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_base64url())
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Bytes, D::Error> {
        let text = String::deserialize(d)?;
        Bytes::from_base64url(&text)
            .ok_or_else(|| serde::de::Error::custom("expected unpadded base64url"))
    }
}

/// A path-based, stable node identifier (see `TEST-PLAN.md` §4).
///
/// Segments are joined by `/`; the document root is the empty string.
/// Names are RFC 6901 escaped (`~` as `~0`, `/` as `~1`), so a segment
/// starting with `~` and a letter is always one of the specials: `~k` (key
/// node), `~e`/`~eN` (decoded view), `~t` (tag content), `~cN` (chunk),
/// `~iN` (entry by index).
///
/// ```
/// use tokenator_core::NodeId;
///
/// let iss = NodeId::root().child("payload").decoded(0).child("http://x/y");
/// assert_eq!(iss.as_str(), "payload/~e/http:~1~1x~1y");
/// assert_eq!(iss.segments(), ["payload", "~e", "http://x/y"]);
/// assert_eq!(iss.parent().unwrap().as_str(), "payload/~e");
/// assert_eq!(iss.key().as_str(), "payload/~e/http:~1~1x~1y/~k");
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct NodeId(pub String);

impl NodeId {
    /// The document root (`""`).
    pub fn root() -> NodeId {
        NodeId(String::new())
    }

    /// The id as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is the document root.
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// Appends an unescaped name (a part name, JSON member name, CBOR key
    /// EDN, or index), escaping it.
    pub fn child(&self, name: &str) -> NodeId {
        self.push_raw(&escape_segment(name))
    }

    /// Appends an array index.
    pub fn index(&self, i: usize) -> NodeId {
        self.push_raw(&i.to_string())
    }

    /// Appends an already escaped or special segment (`~k`, `~e`, `~i3`).
    pub fn push_raw(&self, segment: &str) -> NodeId {
        if self.0.is_empty() {
            NodeId(segment.to_owned())
        } else {
            NodeId(format!("{}/{segment}", self.0))
        }
    }

    /// The key node of the entry this id names (`…/~k`).
    pub fn key(&self) -> NodeId {
        self.push_raw("~k")
    }

    /// Decoded view `n` of this byte string (`~e` for 0, `~eN` otherwise).
    pub fn decoded(&self, n: usize) -> NodeId {
        if n == 0 {
            self.push_raw("~e")
        } else {
            self.push_raw(&format!("~e{n}"))
        }
    }

    /// The parent id; `None` for the root.
    pub fn parent(&self) -> Option<NodeId> {
        if self.0.is_empty() {
            return None;
        }
        Some(match self.0.rfind('/') {
            Some(i) => NodeId(self.0.get(..i).unwrap_or_default().to_owned()),
            None => NodeId::root(),
        })
    }

    /// The unescaped segments, outermost first (empty for the root).
    /// Specials (`~k`, `~e`, …) are returned as written.
    pub fn segments(&self) -> Vec<String> {
        if self.0.is_empty() {
            return Vec::new();
        }
        self.0.split('/').map(unescape_segment).collect()
    }

    /// Whether `self` is `other` or one of its ancestors.
    pub fn is_ancestor_of(&self, other: &NodeId) -> bool {
        self.0.is_empty()
            || other.0 == self.0
            || (other.0.starts_with(&self.0) && other.0.as_bytes().get(self.0.len()) == Some(&b'/'))
    }

    /// For a JSON claim set: the RFC 6901 pointer of this node (`""` for the
    /// root, `/address/street` otherwise). The escaping is the same.
    pub fn to_json_pointer(&self) -> String {
        if self.0.is_empty() {
            String::new()
        } else {
            format!("/{}", self.0)
        }
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for NodeId {
    fn from(s: &str) -> NodeId {
        NodeId(s.to_owned())
    }
}

/// Escapes a name for use as a NodeId segment: `~` as `~0`, `/` as `~1`.
pub fn escape_segment(name: &str) -> String {
    name.replace('~', "~0").replace('/', "~1")
}

/// Undoes [`escape_segment`]. Specials (`~k`, `~e`, …) come back unchanged.
pub fn unescape_segment(segment: &str) -> String {
    if segment
        .as_bytes()
        .get(1)
        .is_some_and(u8::is_ascii_alphabetic)
        && segment.starts_with('~')
    {
        return segment.to_owned();
    }
    segment.replace("~1", "/").replace("~0", "~")
}

/// A range of UTF-16 code units in `Document.main.text`, with the 0-based,
/// half-open range of lines it touches.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct TextRange {
    /// First code unit.
    pub start: u32,
    /// One past the last code unit.
    pub end: u32,
    /// First line.
    pub line_start: u32,
    /// One past the last line.
    pub line_end: u32,
}

/// A half-open byte range.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct ByteRange {
    /// First byte.
    pub start: u32,
    /// One past the last byte.
    pub end: u32,
}

/// Where a node sits in the raw pane: a byte range in the raw buffer (hex
/// views) or in the token text (segment views), and the rows it covers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct RawRange {
    /// First byte.
    pub start: u32,
    /// One past the last byte.
    pub end: u32,
    /// First row (hex row or segment index).
    pub row_start: u32,
    /// One past the last row.
    pub row_end: u32,
}

/// A JOSE or COSE nonce: KB-JWT `nonce` is text, SD-KBT `cnonce` is bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Nonce {
    /// A text nonce.
    Text {
        /// The text.
        value: String,
    },
    /// A binary nonce.
    Bytes {
        /// The bytes.
        value: Bytes,
    },
}

/// A key identifier: text (JOSE) or bytes (COSE).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KidValue {
    /// A text kid.
    Text {
        /// The text.
        value: String,
    },
    /// A binary kid.
    Bytes {
        /// The bytes.
        value: Bytes,
    },
}

/// A hash algorithm for SD digests and thumbprints.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum HashName {
    /// SHA-256 (the default).
    #[default]
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}
