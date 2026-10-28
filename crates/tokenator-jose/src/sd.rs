//! SD-JWT semantics: disclosures, digests, matching, and processing
//! (RFC 9901 §4.2, §7.1).

use std::borrow::Cow;
use std::collections::HashMap;

use tokenator_crypto::{HashAlg, digest};
use tokenator_json::{JsonError, Member, Node, Value};

use crate::b64::{B64Error, b64u_encode};
use crate::parse::{B64Part, Disclosure};

/// Why a disclosure is not a valid `[salt, name, value]` / `[salt, value]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisclosureError {
    /// The base64url text did not decode.
    Base64(B64Error),
    /// The decoded bytes are not JSON.
    Json(JsonError),
    /// The JSON is not an array.
    NotAnArray,
    /// An array with other than 2 or 3 elements.
    WrongLength(usize),
    /// The salt is not a string.
    SaltNotString,
    /// The claim name of a 3-element disclosure is not a string.
    NameNotString,
}

/// Whether a disclosure is for an object property or an array element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisclosureKind {
    /// `[salt, name, value]` (RFC 9901 §4.2.1).
    Property,
    /// `[salt, value]` (RFC 9901 §4.2.2).
    ArrayElement,
}

/// A decoded, well-formed disclosure. Forbidden names (`_sd`, `...`) are
/// accepted here and reported by [`process`].
#[derive(Debug, Clone)]
pub struct DisclosureView<'b> {
    tree: Node<'b>,
}

impl<'b> DisclosureView<'b> {
    /// The decoded JSON array; spans are relative to the decoded bytes.
    pub fn tree(&self) -> &Node<'b> {
        &self.tree
    }

    /// Property or array element.
    pub fn kind(&self) -> DisclosureKind {
        if self.elements().len() == 3 {
            DisclosureKind::Property
        } else {
            DisclosureKind::ArrayElement
        }
    }

    /// The salt.
    pub fn salt(&self) -> &str {
        match self.elements().first().map(Node::value) {
            Some(Value::String(s)) => s,
            _ => "",
        }
    }

    /// The claim name, for a property disclosure.
    pub fn name(&self) -> Option<&str> {
        self.name_node().and_then(|n| match n.value() {
            Value::String(s) => Some(s.as_ref()),
            _ => None,
        })
    }

    /// The claim value or array element.
    pub fn value(&self) -> &Node<'b> {
        // Validated in `new`: the value is the last of 2 or 3 elements.
        self.elements().last().unwrap_or(&self.tree)
    }
}

/// The `_sd_alg` of a payload (RFC 9901 §4.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdAlg {
    /// No top-level `_sd_alg`; SHA-256 applies.
    Default,
    /// A supported hash name (`sha-256`, `sha-384`, `sha-512`).
    Named(HashAlg),
    /// A string naming an unsupported hash (names are case-sensitive, so
    /// `SHA-256` lands here).
    Unsupported(String),
    /// `_sd_alg` is present but not a string.
    NotAString,
}

impl SdAlg {
    /// The hash to use, if supported.
    pub fn hash(&self) -> Option<HashAlg> {
        match self {
            SdAlg::Default => Some(HashAlg::Sha256),
            SdAlg::Named(h) => Some(*h),
            SdAlg::Unsupported(_) | SdAlg::NotAString => None,
        }
    }
}

/// Reads the top-level `_sd_alg` of `payload`.
pub fn sd_alg(payload: &Node<'_>) -> SdAlg {
    match payload.get("_sd_alg").map(Node::value) {
        None => SdAlg::Default,
        Some(Value::String(s)) => {
            HashAlg::from_name(s).map_or_else(|| SdAlg::Unsupported(s.to_string()), SdAlg::Named)
        }
        Some(_) => SdAlg::NotAString,
    }
}

/// Base64url of `hash` over the ASCII bytes of `text`: a disclosure digest
/// (RFC 9901 §4.2.3) or an `sd_hash` (§4.3.1).
///
/// ```
/// use tokenator_crypto::HashAlg;
/// assert_eq!(
///     tokenator_jose::sd_digest(
///         "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0",
///         HashAlg::Sha256,
///     ),
///     "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"
/// );
/// ```
pub fn sd_digest(text: &str, hash: HashAlg) -> String {
    b64u_encode(&digest(hash, text.as_bytes()))
}

/// Where a digest slot lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Container {
    /// In the issuer payload.
    Payload,
    /// Inside disclosure `n` (a recursive disclosure).
    Disclosure(usize),
}

/// How a digest is embedded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlotKind {
    /// An entry of an `_sd` array (object property).
    Object,
    /// A `{"...": digest}` array element.
    ArrayElement,
}

/// One embedded digest found in the payload or in a matched disclosure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestSlot {
    /// The digest string as embedded.
    pub digest: String,
    /// `_sd` entry or array element.
    pub kind: SlotKind,
    /// Payload or disclosure.
    pub container: Container,
    /// RFC 6901 pointer within the container's tree (the payload, or the
    /// disclosure's whole array) to the `_sd` entry (e.g. `/address/_sd/1`,
    /// `/2/_sd/0`) or to the `{"...": digest}` element (e.g.
    /// `/nationalities/0`).
    pub pointer: String,
    /// Index of the matching disclosure (set even if a finding keeps it
    /// from being inserted).
    pub disclosure: Option<usize>,
}

/// How one disclosure matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosureMatch {
    /// Its digest under the payload's `_sd_alg`; `None` if that hash is
    /// not supported.
    pub digest: Option<String>,
    /// Index into [`SdReport::digests`] of the slot it fills.
    pub slot: Option<usize>,
}

/// A problem found while matching (each corresponds to a validation report
/// item; none of them stops processing).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SdFinding {
    /// The disclosure matches no digest reachable from the payload (directly
    /// or through other matched disclosures).
    UnmatchedDisclosure {
        /// Disclosure index.
        disclosure: usize,
    },
    /// The same digest is embedded more than once (RFC 9901 §7.1 step 4).
    /// Only the first slot can be filled; the others are not also reported
    /// as [`SdFinding::DigestWithoutDisclosure`].
    DuplicateDigest {
        /// The digest.
        digest: String,
        /// Indexes into [`SdReport::digests`], in walk order.
        slots: Vec<usize>,
    },
    /// Several disclosures have the same digest (the same disclosure sent
    /// more than once). Only the first is used; the others are not also
    /// reported as [`SdFinding::UnmatchedDisclosure`].
    DuplicateDisclosure {
        /// Disclosure indexes, in input order.
        disclosures: Vec<usize>,
    },
    /// A slot no disclosure fills: a decoy, or a withheld claim.
    DigestWithoutDisclosure {
        /// Index into [`SdReport::digests`].
        slot: usize,
    },
    /// A property disclosure named `_sd` or `...`. It is not inserted.
    ForbiddenName {
        /// Disclosure index.
        disclosure: usize,
        /// The name.
        name: String,
    },
    /// A property disclosure matched an array slot, or an array-element
    /// disclosure matched an `_sd` slot. It is not inserted.
    KindMismatch {
        /// Disclosure index.
        disclosure: usize,
        /// Index into [`SdReport::digests`].
        slot: usize,
    },
    /// The disclosed name already exists in the object holding the `_sd`
    /// array. The existing member is kept; the disclosure is not inserted.
    NameCollision {
        /// Disclosure index.
        disclosure: usize,
        /// The name.
        name: String,
    },
    /// The disclosure could not be decoded. It is still hashed, so it may
    /// fill a slot (then it is not also unmatched), but nothing is inserted.
    MalformedDisclosure {
        /// Disclosure index.
        disclosure: usize,
        /// Why.
        error: DisclosureError,
    },
    /// An `_sd` member whose value is not an array.
    SdNotArray {
        /// Where.
        container: Container,
        /// Pointer to the `_sd` member.
        pointer: String,
    },
    /// A non-string entry in an `_sd` array.
    SdEntryNotString {
        /// Where.
        container: Container,
        /// Pointer to the entry.
        pointer: String,
    },
    /// An array element object with a `...` member that is not a slot
    /// (other members besides `...`, or a non-string value). It is kept as
    /// an ordinary element.
    MalformedArrayDigest {
        /// Where.
        container: Container,
        /// Pointer to the element.
        pointer: String,
    },
    /// `_sd_alg` anywhere but the top level of the payload. It is left in
    /// place.
    NestedSdAlg {
        /// Where.
        container: Container,
        /// Pointer to the `_sd_alg` member.
        pointer: String,
    },
    /// `_sd_alg` is unsupported or not a string. Slots are still listed,
    /// but no matching is done, so no unmatched/without-disclosure findings
    /// are reported.
    UnsupportedSdAlg,
}

/// The result of matching disclosures to digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdReport {
    /// The payload's `_sd_alg`.
    pub sd_alg: SdAlg,
    /// Every slot, in walk order: depth-first through the payload in member
    /// and element order, where a matched disclosure's value is walked right
    /// after the slot it fills (so its own slots come next).
    pub digests: Vec<DigestSlot>,
    /// One entry per input disclosure, in input order.
    pub disclosures: Vec<DisclosureMatch>,
    /// Problems: first `UnsupportedSdAlg`, then those met during the walk
    /// (in walk order), then duplicate digests (by first slot), duplicate
    /// disclosures (by first index), digests without disclosures (by slot),
    /// and finally unfilled disclosures by index (`MalformedDisclosure`
    /// before `UnmatchedDisclosure` for the same one).
    pub findings: Vec<SdFinding>,
}

/// Processed claims plus the matching report.
#[derive(Debug, Clone)]
pub struct Processed<'s> {
    /// The Processed SD-JWT Payload (RFC 9901 §7.1): every `_sd` removed,
    /// each disclosed property appended to the end of its object in the
    /// order of its digest in `_sd`, array slots replaced in place, unfilled
    /// array slots removed, top-level `_sd_alg` removed. Nodes copied from
    /// the payload or a disclosure keep their spans (relative to their own
    /// decoded bytes).
    pub claims: Node<'s>,
    /// The matching report.
    pub report: SdReport,
}

/// Matches `disclosures` against the digests in `payload` (recursively
/// through matched disclosures) and reconstructs the processed claims.
///
/// Works on any payload tree, signed or not. Problems never abort: the
/// offending disclosure is left out and reported. A disclosure is inserted
/// at most once, even when its digest appears in several slots.
pub fn process<'s>(payload: &Node<'s>, disclosures: &'s [Disclosure<'_>]) -> Processed<'s> {
    let alg = sd_alg(payload);
    let hash = alg.hash();
    let views: Vec<_> = disclosures.iter().map(Disclosure::view).collect();
    let mut walker = Walker::new(&views, disclosures, hash);
    let claims = walker.node(payload, Container::Payload, String::new(), true);
    walker.finish(alg, claims)
}

impl<'b> DisclosureView<'b> {
    /// Decodes and checks a disclosure part.
    pub(crate) fn new(part: &'b B64Part<'_>) -> Result<DisclosureView<'b>, DisclosureError> {
        let bytes = part.decoded().map_err(DisclosureError::Base64)?;
        let tree = tokenator_json::parse(bytes).map_err(DisclosureError::Json)?;
        let elements = tree.elements().ok_or(DisclosureError::NotAnArray)?;
        let is_str = |n: &Node<'_>| matches!(n.value(), Value::String(_));
        match elements {
            [salt, ..] if (2..=3).contains(&elements.len()) && !is_str(salt) => {
                return Err(DisclosureError::SaltNotString);
            }
            [_, name, _] if !is_str(name) => return Err(DisclosureError::NameNotString),
            [_, _] | [_, _, _] => {}
            _ => return Err(DisclosureError::WrongLength(elements.len())),
        }
        Ok(DisclosureView { tree })
    }

    fn elements(&self) -> &[Node<'b>] {
        self.tree.elements().unwrap_or_default()
    }

    fn name_node(&self) -> Option<&Node<'b>> {
        match self.elements() {
            [_, name, _] => Some(name),
            _ => None,
        }
    }

    /// The claim name, borrowing the decoded bytes when unescaped.
    pub(crate) fn name_cow(&self) -> Option<Cow<'b, str>> {
        match self.name_node()?.value() {
            Value::String(s) => Some(s.clone()),
            _ => None,
        }
    }
}

/// Escapes one RFC 6901 reference token.
pub(crate) fn escape_token(token: &str) -> Cow<'_, str> {
    if token.contains(['~', '/']) {
        Cow::Owned(token.replace('~', "~0").replace('/', "~1"))
    } else {
        Cow::Borrowed(token)
    }
}

/// The digest of a `{"...": digest}` array element, if `node` is exactly
/// that; `Err(())` for an object with `...` that is not a valid slot.
pub(crate) fn array_digest<'n>(node: &'n Node<'_>) -> Option<Result<&'n str, ()>> {
    let members = node.members()?;
    if !members.iter().any(|m| m.key() == "...") {
        return None;
    }
    Some(match members {
        [m] => match m.value().value() {
            Value::String(d) => Ok(d),
            _ => Err(()),
        },
        _ => Err(()),
    })
}

type Views<'s> = [Result<DisclosureView<'s>, DisclosureError>];

/// The state of one [`process`] run.
struct Walker<'s, 'v> {
    views: &'v Views<'s>,
    hash: Option<HashAlg>,
    matches: Vec<DisclosureMatch>,
    /// Digest to the group of disclosures with that digest.
    disclosure_group: HashMap<String, usize>,
    disclosure_groups: Vec<Vec<usize>>,
    slots: Vec<DigestSlot>,
    /// Digest to the group of slots with that digest.
    slot_group: HashMap<String, usize>,
    slot_groups: Vec<Vec<usize>>,
    /// Findings met during the walk.
    findings: Vec<SdFinding>,
}

impl<'s, 'v> Walker<'s, 'v> {
    fn new(views: &'v Views<'s>, disclosures: &[Disclosure<'_>], hash: Option<HashAlg>) -> Self {
        let mut walker = Walker {
            views,
            hash,
            matches: Vec::with_capacity(disclosures.len()),
            disclosure_group: HashMap::new(),
            disclosure_groups: Vec::new(),
            slots: Vec::new(),
            slot_group: HashMap::new(),
            slot_groups: Vec::new(),
            findings: Vec::new(),
        };
        for (i, d) in disclosures.iter().enumerate() {
            let digest = hash.map(|h| d.digest(h));
            if let Some(dg) = &digest {
                let next = walker.disclosure_groups.len();
                let g = *walker.disclosure_group.entry(dg.clone()).or_insert(next);
                match walker.disclosure_groups.get_mut(g) {
                    Some(group) => group.push(i),
                    None => walker.disclosure_groups.push(vec![i]),
                }
            }
            walker.matches.push(DisclosureMatch { digest, slot: None });
        }
        walker
    }

    /// Records a slot and returns its index and the disclosure that fills it.
    fn slot(
        &mut self,
        digest: &str,
        kind: SlotKind,
        container: Container,
        pointer: String,
    ) -> (usize, Option<usize>) {
        let index = self.slots.len();
        let mut disclosure = None;
        if let Some(&g) = self.slot_group.get(digest) {
            if let Some(group) = self.slot_groups.get_mut(g) {
                group.push(index);
            }
        } else {
            self.slot_group
                .insert(digest.to_owned(), self.slot_groups.len());
            self.slot_groups.push(vec![index]);
            if self.hash.is_some() {
                let first = self.disclosure_group.get(digest);
                disclosure = first.and_then(|g| self.disclosure_groups.get(*g)?.first().copied());
            }
        }
        if let Some(m) = disclosure.and_then(|d| self.matches.get_mut(d)) {
            m.slot = Some(index);
        }
        self.slots.push(DigestSlot {
            digest: digest.to_owned(),
            kind,
            container,
            pointer,
            disclosure,
        });
        (index, disclosure)
    }

    fn node(
        &mut self,
        node: &Node<'s>,
        container: Container,
        pointer: String,
        top: bool,
    ) -> Node<'s> {
        match node.value() {
            Value::Object(ms) => self.object(ms, container, &pointer, top),
            Value::Array(xs) => self.array(xs, container, &pointer),
            _ => node.clone(),
        }
    }

    fn object(
        &mut self,
        ms: &[Member<'s>],
        container: Container,
        pointer: &str,
        top: bool,
    ) -> Node<'s> {
        let mut plain = Vec::with_capacity(ms.len());
        let mut disclosed = Vec::new();
        for m in ms {
            let key: &str = m.key();
            let child = format!("{pointer}/{}", escape_token(key));
            match key {
                "_sd" => self.sd_array(m.value(), container, &child, ms, &mut disclosed),
                "_sd_alg" if top => {}
                _ => {
                    if key == "_sd_alg" {
                        let pointer = child.clone();
                        self.findings
                            .push(SdFinding::NestedSdAlg { container, pointer });
                    }
                    let value = self.node(m.value(), container, child, false);
                    plain.push(Member::new(m.key().clone(), value));
                }
            }
        }
        plain.append(&mut disclosed);
        Node::new(Value::Object(plain))
    }

    fn sd_array(
        &mut self,
        value: &Node<'s>,
        container: Container,
        pointer: &str,
        siblings: &[Member<'s>],
        disclosed: &mut Vec<Member<'s>>,
    ) {
        let Some(entries) = value.elements() else {
            let pointer = pointer.to_owned();
            self.findings
                .push(SdFinding::SdNotArray { container, pointer });
            return;
        };
        let views = self.views;
        for (j, entry) in entries.iter().enumerate() {
            let p = format!("{pointer}/{j}");
            let Value::String(dg) = entry.value() else {
                self.findings.push(SdFinding::SdEntryNotString {
                    container,
                    pointer: p,
                });
                continue;
            };
            let (slot, Some(d)) = self.slot(dg, SlotKind::Object, container, p) else {
                continue;
            };
            // A malformed disclosure is reported once, at the end.
            let Some(Ok(view)) = views.get(d) else {
                continue;
            };
            let name = match view.name_cow() {
                Some(name) if view.kind() == DisclosureKind::Property => name,
                _ => {
                    let finding = SdFinding::KindMismatch {
                        disclosure: d,
                        slot,
                    };
                    self.findings.push(finding);
                    continue;
                }
            };
            let taken = |m: &Member<'_>| m.key() == &name;
            let finding = if name == "_sd" || name == "..." {
                SdFinding::ForbiddenName {
                    disclosure: d,
                    name: name.into_owned(),
                }
            } else if siblings.iter().any(|m| m.key() != "_sd" && taken(m))
                || disclosed.iter().any(taken)
            {
                SdFinding::NameCollision {
                    disclosure: d,
                    name: name.into_owned(),
                }
            } else {
                let value = self.node(view.value(), Container::Disclosure(d), "/2".into(), false);
                disclosed.push(Member::new(name, value));
                continue;
            };
            self.findings.push(finding);
        }
    }

    fn array(&mut self, xs: &[Node<'s>], container: Container, pointer: &str) -> Node<'s> {
        let views = self.views;
        let mut out = Vec::with_capacity(xs.len());
        for (j, el) in xs.iter().enumerate() {
            let p = format!("{pointer}/{j}");
            match array_digest(el) {
                Some(Ok(dg)) => {
                    let (slot, d) = self.slot(dg, SlotKind::ArrayElement, container, p);
                    let Some((d, Some(Ok(view)))) = d.map(|d| (d, views.get(d))) else {
                        continue;
                    };
                    if view.kind() == DisclosureKind::Property {
                        let finding = SdFinding::KindMismatch {
                            disclosure: d,
                            slot,
                        };
                        self.findings.push(finding);
                    } else {
                        out.push(self.node(
                            view.value(),
                            Container::Disclosure(d),
                            "/1".into(),
                            false,
                        ));
                    }
                    continue;
                }
                Some(Err(())) => {
                    let pointer = p.clone();
                    self.findings
                        .push(SdFinding::MalformedArrayDigest { container, pointer });
                }
                None => {}
            }
            out.push(self.node(el, container, p, false));
        }
        Node::new(Value::Array(out))
    }

    fn finish(self, sd_alg: SdAlg, claims: Node<'s>) -> Processed<'s> {
        let matching = self.hash.is_some();
        let mut findings = Vec::new();
        if !matching {
            findings.push(SdFinding::UnsupportedSdAlg);
        }
        findings.extend(self.findings);
        for group in &self.slot_groups {
            if let (Some(&first), true) = (group.first(), group.len() > 1) {
                let digest = self
                    .slots
                    .get(first)
                    .map(|s| s.digest.clone())
                    .unwrap_or_default();
                findings.push(SdFinding::DuplicateDigest {
                    digest,
                    slots: group.clone(),
                });
            }
        }
        let mut repeated = vec![false; self.matches.len()];
        if matching {
            for group in self.disclosure_groups.iter().filter(|g| g.len() > 1) {
                for &i in group.iter().skip(1) {
                    if let Some(r) = repeated.get_mut(i) {
                        *r = true;
                    }
                }
                findings.push(SdFinding::DuplicateDisclosure {
                    disclosures: group.clone(),
                });
            }
            for (slot, s) in self.slots.iter().enumerate() {
                let first = self
                    .slot_group
                    .get(&s.digest)
                    .and_then(|g| self.slot_groups.get(*g)?.first());
                if s.disclosure.is_none() && first == Some(&slot) {
                    findings.push(SdFinding::DigestWithoutDisclosure { slot });
                }
            }
        }
        for (i, m) in self.matches.iter().enumerate() {
            if let Some(Err(error)) = self.views.get(i) {
                findings.push(SdFinding::MalformedDisclosure {
                    disclosure: i,
                    error: error.clone(),
                });
            }
            if matching && m.slot.is_none() && !repeated.get(i).copied().unwrap_or(false) {
                findings.push(SdFinding::UnmatchedDisclosure { disclosure: i });
            }
        }
        Processed {
            claims,
            report: SdReport {
                sd_alg,
                digests: self.slots,
                disclosures: self.matches,
                findings,
            },
        }
    }
}

impl core::fmt::Display for DisclosureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for DisclosureError {}
