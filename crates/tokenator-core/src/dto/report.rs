//! Validation report (SPEC §6).

use serde::{Deserialize, Serialize};

use super::common::{ByteRange, NodeId};

/// The result of [`Engine::validate`](crate::Engine::validate).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct ValidationReport {
    /// `fail` if any item fails, else `warn` if any warns, else `skip` if
    /// the signature or key binding was skipped, else `pass`.
    pub overall: Status,
    /// The checklist: signature, time, SD, key binding, lint.
    pub items: Vec<CheckItem>,
    /// URLs the user may choose to fetch keys from (never fetched here).
    pub fetchable: Vec<FetchHint>,
}

/// One checklist item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CheckItem {
    /// Stable id (`signature`, `time.exp`, `sd.match`, `kb.sd_hash`,
    /// `lint.encoding`, …). Ids may repeat (one item per finding).
    pub id: String,
    /// Group.
    pub category: Category,
    /// Outcome.
    pub status: Status,
    /// Human-readable text.
    pub message: String,
    /// The nodes concerned.
    pub node_ids: Vec<NodeId>,
    /// The exact byte span (encoding findings: the hex row's bytes).
    pub raw: Option<ByteRange>,
    /// Structured details.
    pub detail: Option<CheckDetail>,
}

/// Outcome of a check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Holds.
    Pass,
    /// Does not hold.
    Fail,
    /// A likely problem.
    Warn,
    /// Could not be checked.
    Skip,
    /// For information.
    Info,
}

/// Check groups, in report order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Issuer signature.
    Signature,
    /// exp / nbf / iat.
    Time,
    /// Selective disclosure.
    Sd,
    /// KB-JWT / SD-KBT.
    KeyBinding,
    /// Conformance lint (warn/info only).
    Lint,
}

/// Structured details of a check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CheckDetail {
    /// Which key verified (or was tried) and how it was chosen.
    Signature {
        /// JOSE name of the alg used.
        alg: Option<String>,
        /// Index into `ValidateRequest.keys`, for panel keys.
        key_index: Option<u32>,
        /// `KeyRef.label` of that key.
        key_label: Option<String>,
        /// How the key was selected.
        selection: KeySelection,
        /// An embedded key (x5c, cnf): not trusted.
        untrusted: bool,
    },
    /// A time claim against the clock.
    Time {
        /// `exp`, `nbf`, or `iat`.
        claim: String,
        /// The claim value (whole seconds).
        value: i64,
        /// The clock.
        now: i64,
        /// The skew.
        skew: u64,
    },
    /// A non-preferred encoding and its fix.
    Encoding {
        /// `non_preferred_argument`, `non_preferred_float`,
        /// `non_canonical_nan`, `non_preferred_bignum`, `indefinite_length`,
        /// `map_key_order`.
        finding: String,
        /// Replacement bytes for `CheckItem.raw`, as hex.
        preferred_hex: String,
    },
}

/// How the verification key was chosen (SPEC §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum KeySelection {
    /// A panel key whose kid matches the header kid.
    PanelKid,
    /// A panel key whose JWK or COSE thumbprint matches the header kid.
    PanelThumbprint,
    /// No kid match; a panel key that fits the alg.
    PanelUnmatched,
    /// The `x5c` / `x5chain` leaf (untrusted).
    EmbeddedX5c,
    /// The `cnf` key (untrusted; key binding).
    EmbeddedCnf,
    /// No key.
    None,
}

/// A place the user may fetch keys from. Core never fetches.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct FetchHint {
    /// What the URL is.
    pub kind: FetchKind,
    /// The URL.
    pub url: String,
    /// Why it is offered.
    pub reason: String,
}

/// Kinds of [`FetchHint`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum FetchKind {
    /// The header kid is a URL.
    KidUrl,
    /// `/.well-known/jwt-vc-issuer` metadata for an https `iss`.
    IssuerMetadata,
}
