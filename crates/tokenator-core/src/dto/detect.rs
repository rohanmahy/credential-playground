//! Detection results: kinds, unwrapping layers, candidates.

use serde::{Deserialize, Serialize};

use super::common::ByteRange;

/// What a document is. Mirrors `tokenator_detect::Kind`, except that EDN
/// text is only ever reported once the EDN parser confirmed it
/// ([`Kind::EdnClaims`]).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Kind {
    /// JWS compact whose payload is a JSON object (incl. unsecured JWTs).
    Jwt,
    /// JWS compact whose payload is not a JSON object.
    JwsCompact,
    /// SD-JWT, compact.
    SdJwt {
        /// Has a KB-JWT.
        kb: bool,
    },
    /// JWS JSON serialization.
    JwsJson {
        /// General rather than flattened.
        general: bool,
    },
    /// SD-JWT in JWS JSON serialization.
    SdJwtJson {
        /// General rather than flattened.
        general: bool,
        /// Has a KB-JWT.
        kb: bool,
    },
    /// COSE_Sign1 whose payload is not a claims map.
    CoseSign1,
    /// CWT.
    Cwt,
    /// SD-CWT.
    SdCwt,
    /// SD-KBT.
    SdKbt,
    /// Unsigned claim set, JSON text.
    JsonClaims,
    /// Unsigned claim set, binary CBOR map.
    CborClaims,
    /// Unsigned claim set, EDN text (parser-confirmed).
    EdnClaims,
    /// A JWK.
    Jwk,
    /// A JWK Set.
    JwkSet,
    /// A COSE_Key.
    CoseKey,
    /// A COSE_KeySet.
    CoseKeySet,
    /// PEM blocks.
    Pem {
        /// Block labels in order.
        labels: Vec<String>,
    },
}

/// Token family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum Family {
    /// JWT, SD-JWT, JSON claim sets: JSON main pane, segment raw pane.
    Jose,
    /// CWT, SD-CWT, CBOR/EDN claim sets, COSE_Keys: EDN main pane, hex raw pane.
    Cose,
}

impl Kind {
    /// The family whose views and actions apply; `None` for JWKs and PEM.
    pub fn family(&self) -> Option<Family> {
        match self {
            Kind::Jwt
            | Kind::JwsCompact
            | Kind::SdJwt { .. }
            | Kind::JwsJson { .. }
            | Kind::SdJwtJson { .. }
            | Kind::JsonClaims => Some(Family::Jose),
            Kind::CoseSign1
            | Kind::Cwt
            | Kind::SdCwt
            | Kind::SdKbt
            | Kind::CborClaims
            | Kind::EdnClaims
            | Kind::CoseKey
            | Kind::CoseKeySet => Some(Family::Cose),
            Kind::Jwk | Kind::JwkSet | Kind::Pem { .. } => None,
        }
    }

    /// Whether this kind belongs in the key panel.
    pub fn is_key(&self) -> bool {
        matches!(
            self,
            Kind::Jwk | Kind::JwkSet | Kind::CoseKey | Kind::CoseKeySet | Kind::Pem { .. }
        )
    }

    /// Whether this is an unsigned claim set (a draft for Issue/Redact).
    pub fn is_claims(&self) -> bool {
        matches!(self, Kind::JsonClaims | Kind::CborClaims | Kind::EdnClaims)
    }

    /// Whether this kind carries a signature.
    pub fn is_signed(&self) -> bool {
        !self.is_key() && !self.is_claims()
    }

    /// Short display name, the last breadcrumb entry.
    pub fn label(&self) -> &'static str {
        match self {
            Kind::Jwt => "JWT",
            Kind::JwsCompact => "JWS",
            Kind::SdJwt { kb: false } => "SD-JWT",
            Kind::SdJwt { kb: true } => "SD-JWT+KB",
            Kind::JwsJson { .. } => "JWS JSON",
            Kind::SdJwtJson { kb: false, .. } => "SD-JWT JSON",
            Kind::SdJwtJson { kb: true, .. } => "SD-JWT+KB JSON",
            Kind::CoseSign1 => "COSE_Sign1",
            Kind::Cwt => "CWT",
            Kind::SdCwt => "SD-CWT",
            Kind::SdKbt => "SD-KBT",
            Kind::JsonClaims => "JSON claim set",
            Kind::CborClaims => "CBOR claim set",
            Kind::EdnClaims => "EDN claim set",
            Kind::Jwk => "JWK",
            Kind::JwkSet => "JWK Set",
            Kind::CoseKey => "COSE_Key",
            Kind::CoseKeySet => "COSE_KeySet",
            Kind::Pem { .. } => "PEM",
        }
    }
}

/// One unwrapping step, outermost first. Mirrors `tokenator_detect::Layer`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Layer {
    /// Surrounding whitespace, kept verbatim.
    Trim {
        /// Before the content.
        leading: String,
        /// After the content.
        trailing: String,
    },
    /// A pair of quotes.
    Quotes {
        /// The quote character.
        quote: char,
    },
    /// An `Authorization:` header name.
    AuthorizationHeader {
        /// The exact text removed.
        prefix: String,
    },
    /// The `Bearer` scheme.
    BearerPrefix {
        /// The exact text removed.
        prefix: String,
    },
    /// Percent-encoding.
    UrlEncoded,
    /// A string member of a JSON document.
    JsonField {
        /// Path from the root to the string.
        path: Vec<JsonPathSegment>,
    },
    /// base64url.
    Base64Url {
        /// `=` padding.
        padded: bool,
        /// Line length if wrapped.
        wrap: Option<u32>,
    },
    /// Classic base64.
    Base64Std {
        /// `=` padding.
        padded: bool,
        /// Line length if wrapped.
        wrap: Option<u32>,
    },
    /// Hexadecimal text.
    Hex {
        /// Upper-case digits.
        upper: bool,
        /// Byte separator (`' '` or `':'`).
        separator: Option<char>,
        /// Bytes per line if wrapped.
        wrap: Option<u32>,
    },
    /// A CBOR tag around the payload.
    CborTag {
        /// Tag number.
        tag: u64,
    },
}

/// One step of a [`Layer::JsonField`] path: a member name or an index.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(untagged)]
pub enum JsonPathSegment {
    /// Member name.
    Key(String),
    /// Array index.
    Index(u32),
}

/// One reading of the input, ranked by `confidence`.
///
/// Pass it back unchanged to [`Engine::open`](crate::Engine::open).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct Candidate {
    /// Classification.
    pub kind: Kind,
    /// 0..=100; only the order matters.
    pub confidence: u8,
    /// Unwrapping steps, outermost first.
    pub layers: Vec<Layer>,
    /// Bytes of the input the first decoding layer operates on.
    pub payload_range: ByteRange,
    /// Display breadcrumb: one entry per shown layer, then `kind.label()`.
    pub breadcrumb: Vec<String>,
}
