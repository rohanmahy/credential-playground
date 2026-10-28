//! Registry entry types.

use serde::{Deserialize, Serialize};

/// One of the four IANA registry groups that can be fetched and merged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegistryId {
    /// CBOR Web Token (CWT) claims and confirmation methods.
    Cwt,
    /// COSE header parameters, algorithms, key types, curves, key parameters.
    Cose,
    /// JSON Web Token claims and confirmation methods.
    Jwt,
    /// JOSE header parameters, algorithms, JWK types, curves, parameters.
    Jose,
}

impl RegistryId {
    /// All four registries, in snapshot order.
    pub const ALL: [RegistryId; 4] = [Self::Cwt, Self::Cose, Self::Jwt, Self::Jose];

    /// The `id` attribute of the root `<registry>` element in the IANA XML.
    pub fn xml_id(self) -> &'static str {
        match self {
            Self::Cwt => "cwt",
            Self::Cose => "cose",
            Self::Jwt => "jwt",
            Self::Jose => "jose",
        }
    }

    /// URL of the IANA XML for this registry.
    pub fn url(self) -> &'static str {
        match self {
            Self::Cwt => "https://www.iana.org/assignments/cwt/cwt.xml",
            Self::Cose => "https://www.iana.org/assignments/cose/cose.xml",
            Self::Jwt => "https://www.iana.org/assignments/jwt/jwt.xml",
            Self::Jose => "https://www.iana.org/assignments/jose/jose.xml",
        }
    }

    /// The entry kinds populated from this registry (and replaced by a merge).
    pub fn kinds(self) -> &'static [EntryKind] {
        use EntryKind::*;
        match self {
            Self::Cwt => &[CwtClaim, CwtCnfMethod],
            Self::Cose => &[
                CoseHeader,
                CoseHeaderAlgParam,
                CoseAlg,
                CoseKeyParam,
                CoseKeyTypeParam,
                CoseKty,
                CoseCrv,
            ],
            Self::Jwt => &[JwtClaim, JwtCnfMethod],
            Self::Jose => &[JoseHeader, JoseAlg, JwkKty, JwkCrv, JwkParam],
        }
    }
}

/// What an entry describes. Together with [`Label`] (and, for
/// [`EntryKind::CoseKeyTypeParam`], [`Entry::key_type`]) it identifies an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// JWS/JWE header parameter (`jose.xml#web-signature-encryption-header-parameters`).
    JoseHeader,
    /// JWS/JWE algorithm (`jose.xml#web-signature-encryption-algorithms`).
    JoseAlg,
    /// JWK `kty` value (`jose.xml#web-key-types`).
    JwkKty,
    /// JWK `crv` value (`jose.xml#web-key-elliptic-curve`).
    JwkCrv,
    /// JWK member name (`jose.xml#web-key-parameters`).
    JwkParam,
    /// JWT claim name (`jwt.xml#claims`).
    JwtClaim,
    /// JWT `cnf` member (`jwt.xml#confirmation-methods`).
    JwtCnfMethod,
    /// COSE header label (`cose.xml#header-parameters`).
    CoseHeader,
    /// COSE algorithm-specific header label (`cose.xml#header-algorithm-parameters`).
    CoseHeaderAlgParam,
    /// COSE algorithm value (`cose.xml#algorithms`).
    CoseAlg,
    /// COSE_Key common parameter label (`cose.xml#key-common-parameters`).
    CoseKeyParam,
    /// COSE_Key type-specific parameter label (`cose.xml#key-type-parameters`).
    CoseKeyTypeParam,
    /// COSE key type value (`cose.xml#key-type`).
    CoseKty,
    /// COSE elliptic curve value (`cose.xml#elliptic-curves`).
    CoseCrv,
    /// CWT claim key (`cwt.xml#claims-registry`).
    CwtClaim,
    /// CWT `cnf` map key (`cwt.xml#confirmation-methods`).
    CwtCnfMethod,
    /// CBOR tag number relevant to tokens (local additions).
    CborTag,
    /// CBOR simple value relevant to tokens (local additions).
    CborSimple,
}

/// An integer or text label/value.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Label {
    /// Integer label, e.g. COSE header `4` or alg `-7`.
    Int(i64),
    /// Text label, e.g. JOSE `"kid"` or a COSE text header label.
    Text(String),
}

impl From<i64> for Label {
    fn from(v: i64) -> Self {
        Self::Int(v)
    }
}

impl From<&str> for Label {
    fn from(v: &str) -> Self {
        Self::Text(v.to_owned())
    }
}

impl From<String> for Label {
    fn from(v: String) -> Self {
        Self::Text(v)
    }
}

/// Where an entry came from. Precedence: `Refreshed` > `Iana` > `Local`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// From the bundled snapshot of the IANA registries.
    Iana,
    /// From `data/local-additions.json` (not, or not yet, in IANA).
    Local,
    /// From a refreshed IANA fetch merged with [`crate::Registry::merge_iana`].
    Refreshed,
}

/// A specification reference.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpecRef {
    /// Human-readable text, e.g. `RFC 7519, Section 4.1.1`.
    pub text: String,
    /// Link, e.g. `https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl SpecRef {
    /// `text` with the revision suffix removed from Internet-Draft names, for
    /// hover text: `draft-ietf-spice-sd-cwt-08, Section 3.3` becomes
    /// `draft-ietf-spice-sd-cwt, Section 3.3`. `RFC-ietf-…-NN` placeholders
    /// are shortened the same way. `url` keeps the exact revision.
    ///
    /// ```
    /// use tokenator_registry::SpecRef;
    /// let r = SpecRef { text: "draft-ietf-spice-sd-cwt-06, Section 4".into(), url: None };
    /// assert_eq!(r.display_text(), "draft-ietf-spice-sd-cwt, Section 4");
    /// ```
    pub fn display_text(&self) -> String {
        let text = self.text.as_str();
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(start) = find_draft_name(rest) {
            let (before, name_and_after) = rest.split_at(start);
            let name_len = name_and_after
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                .unwrap_or(name_and_after.len());
            let (name, after) = name_and_after.split_at(name_len);
            out.push_str(before);
            out.push_str(strip_revision(name));
            rest = after;
        }
        out.push_str(rest);
        out
    }
}

/// Byte offset of the next `draft-` or `RFC-ietf-` name in `s`.
fn find_draft_name(s: &str) -> Option<usize> {
    match (s.find("draft-"), s.find("RFC-ietf-")) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// Removes a trailing `-NN` (two-digit revision) from a draft name.
fn strip_revision(name: &str) -> &str {
    match name.rsplit_once('-') {
        Some((base, rev)) if rev.len() == 2 && rev.bytes().all(|b| b.is_ascii_digit()) => base,
        _ => name,
    }
}

/// One registered codepoint.
///
/// The serde form is the one used in the snapshot and in
/// `data/local-additions.json`: `kind` in snake_case, `label` as a JSON
/// number or string, and empty/default fields omitted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// What this entry describes.
    pub kind: EntryKind,
    /// The codepoint: claim key, header label, alg value, JOSE name, tag number…
    pub label: Label,
    /// Short name, e.g. `alg`, `ES256`, `iss`. Trailing IANA parentheticals
    /// such as `(type)` or `(TEMPORARY - …)` are stripped.
    pub name: String,
    /// Plain-text description (markup flattened, whitespace collapsed).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// Value type as given by the registry (e.g. `bstr`, `int / tstr`), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,
    /// Specification references.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reference: Vec<SpecRef>,
    /// Provenance.
    #[serde(default = "local_source")]
    pub source: Source,
    /// IANA marks the registration as TEMPORARY (early allocation).
    #[serde(default, skip_serializing_if = "is_false")]
    pub temporary: bool,
    /// For [`EntryKind::CoseKeyTypeParam`]: the kty value the label belongs to.
    /// For [`EntryKind::JwkParam`]: the key type from the `usage` column (`EC`, `*`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<Label>,
    /// For CWT claims and CWT cnf methods: the JWT name of the same claim or member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_name: Option<String>,
}

fn local_source() -> Source {
    Source::Local
}

fn is_false(b: &bool) -> bool {
    !*b
}
