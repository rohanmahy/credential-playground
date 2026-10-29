//! Rendering bytes of a kind into a [`Document`].

pub(crate) mod cbor;
pub(crate) mod jose;
pub(crate) mod json;

use std::collections::BTreeMap;

use tokenator_cbor::Item;
use tokenator_cose::sd::{DisclosureContent, ForbiddenReason, SdCwt, SlotKind, match_disclosures};
use tokenator_cose::{CborBackend, Sign1Backend, TokenKind};
use tokenator_edn::{ParseOptions, WarningKind};
use tokenator_json::{Node as JNode, Value as JValue, WarningKind as JWarning};
use tokenator_registry::Registry;

use crate::annotate::Notes;
use crate::cbor::exact_edn;
use crate::dto::common::{ByteRange, Bytes, NodeId, RawRange, escape_segment};
use crate::dto::detect::{Kind, Layer};
use crate::dto::document::{
    Diagnostic, DisclosureInfo, DisclosureStatus, Document, Language, Node, NodeKind, RawView,
    Rendered, SdMark, Severity, SlotInfo, ViewOptions,
};
use crate::dto::error::{EngineError, ErrorCode};
use crate::util::{TextIndex, err, hex, line_count, u32_of};
use cbor::{CborView, MainText, Role};

/// Sets SD marks by node id, and `DigestList` on nodes `list` accepts.
pub(crate) fn apply_marks(
    tree: &mut Node,
    marks: &[(NodeId, SdMark)],
    list: impl Fn(&Node) -> bool,
) {
    let mut by_id: BTreeMap<&NodeId, &SdMark> = BTreeMap::new();
    for (id, mark) in marks {
        by_id.entry(id).or_insert(mark);
    }
    let mut stack: Vec<&mut Node> = vec![tree];
    while let Some(n) = stack.pop() {
        if let Some(mark) = by_id.get(&n.id) {
            n.sd = Some((*mark).clone());
        } else if list(n) {
            n.sd = Some(SdMark::DigestList);
        }
        stack.extend(n.children.iter_mut());
    }
}

/// The deepest node whose byte span contains `start..end` (pre-order index).
pub(crate) fn innermost(
    index: &[(usize, usize, NodeId)],
    start: usize,
    end: usize,
) -> Option<NodeId> {
    index
        .iter()
        .rev()
        .find(|(s, e, _)| *s <= start && end <= *e)
        .map(|(_, _, id)| id.clone())
}

/// The node whose byte span is exactly `start..end` (the deepest one).
pub(crate) fn exact(index: &[(usize, usize, NodeId)], start: usize, end: usize) -> Option<NodeId> {
    index
        .iter()
        .rev()
        .find(|(s, e, _)| *s == start && *e == end)
        .map(|(_, _, id)| id.clone())
}

/// Every node in pre-order.
pub(crate) fn nodes(root: &Node) -> Vec<&Node> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if let Some(k) = &n.key {
            out.push(k.as_ref());
        }
        out.push(n);
        stack.extend(n.children.iter().rev());
    }
    out
}

/// The node with `id`, if any.
pub(crate) fn find<'n>(root: &'n Node, id: &NodeId) -> Option<&'n Node> {
    nodes(root).into_iter().find(|n| &n.id == id)
}

/// The NodeId of the deepest JSON node containing byte `offset`, with the
/// same naming rules as the tree (`~iN` for repeated names).
pub(crate) fn json_id_at(root: &JNode<'_>, offset: usize, base: NodeId) -> NodeId {
    let mut node = root;
    let mut id = base;
    loop {
        let next = match node.value() {
            JValue::Array(items) => items
                .iter()
                .enumerate()
                .find(|(_, c)| {
                    c.span()
                        .is_some_and(|s| s.start <= offset && offset < s.end)
                })
                .map(|(i, c)| (id.index(i), c)),
            JValue::Object(members) => {
                let mut seen = std::collections::BTreeSet::new();
                let mut found = None;
                for (i, m) in members.iter().enumerate() {
                    let seg = escape_segment(m.key());
                    let eid = if seen.insert(seg.clone()) {
                        id.push_raw(&seg)
                    } else {
                        id.push_raw(&format!("~i{i}"))
                    };
                    let in_key = m
                        .key_span()
                        .is_some_and(|s| s.start <= offset && offset < s.end);
                    let in_value = m
                        .value()
                        .span()
                        .is_some_and(|s| s.start <= offset && offset < s.end);
                    if in_key {
                        return eid;
                    }
                    if in_value {
                        found = Some((eid, m.value()));
                        break;
                    }
                }
                found
            }
            _ => None,
        };
        match next {
            Some((next_id, child)) => {
                id = next_id;
                node = child;
            }
            None => return id,
        }
    }
}

fn edn_warning_code(kind: &WarningKind) -> &'static str {
    match kind {
        WarningKind::UnknownExtension(_) => "edn.warning.unknown_extension",
        WarningKind::ReservedEncodingIndicator(_) => "edn.warning.reserved_encoding_indicator",
        WarningKind::IgnoredEncodingIndicator => "edn.warning.ignored_encoding_indicator",
        WarningKind::Ellipsis => "edn.warning.ellipsis",
        WarningKind::Streamstring => "edn.warning.streamstring",
        WarningKind::EolCommentAtEof => "edn.warning.eol_comment_at_eof",
        WarningKind::NonCanonicalNaN => "edn.warning.non_canonical_nan",
        _ => "edn.warning",
    }
}

/// EDN parse warnings as diagnostics at their text position.
pub(crate) fn edn_warnings(text: &str, warnings: &[tokenator_edn::Warning]) -> Vec<Diagnostic> {
    let index = TextIndex::new(text);
    warnings
        .iter()
        .map(|w| Diagnostic {
            severity: Severity::Warning,
            code: edn_warning_code(&w.kind).to_owned(),
            message: format!("{:?}", w.kind),
            node_id: None,
            main: Some(index.range(w.pos.offset..w.pos.offset)),
            raw: None,
        })
        .collect()
}

/// A tokenator-json warning code and message.
pub(crate) fn json_warning(kind: JWarning) -> (&'static str, &'static str) {
    match kind {
        JWarning::InvalidUtf8 => ("json.invalid_utf8", "invalid UTF-8 in a string"),
        JWarning::UnsafeInteger => ("json.unsafe_integer", "integer beyond 2^53 - 1"),
        JWarning::NumberOverflow => ("json.number_overflow", "number overflows a double"),
        JWarning::NumberUnderflow => ("json.number_underflow", "number underflows to zero"),
        _ => ("json.warning", "JSON warning"),
    }
}

/// The parts of a rendered document before it gets its kind and bytes.
pub(crate) struct Built {
    pub(crate) kind: Kind,
    pub(crate) tree: Node,
    pub(crate) main: Rendered,
    pub(crate) raw: RawView,
    pub(crate) disclosures: Vec<DisclosureInfo>,
    pub(crate) undisclosed: Vec<SlotInfo>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    /// `(start, end, id)` raw (COSE/CBOR) or main-text (JSON) spans.
    pub(crate) index: Vec<(usize, usize, NodeId)>,
}

fn utf8(bytes: &[u8]) -> Result<&str, EngineError> {
    std::str::from_utf8(bytes)
        .map_err(|_| EngineError::new(ErrorCode::Parse, "the text is not valid UTF-8"))
}

fn decode(bytes: &[u8]) -> Result<Item<'_>, EngineError> {
    tokenator_cbor::decode(bytes).map_err(|e| {
        EngineError::new(
            ErrorCode::Parse,
            format!("not CBOR: {:?} at byte {}", e.kind, e.offset),
        )
    })
}

fn edn_rendered(text: String) -> Rendered {
    Rendered {
        language: Language::Edn,
        line_count: line_count(&text),
        text,
    }
}

fn from_cbor(kind: Kind, v: CborView, bytes: Vec<u8>) -> Built {
    Built {
        kind,
        tree: v.tree,
        main: edn_rendered(v.text),
        raw: RawView::Hex {
            bytes: Bytes(bytes),
            rows: v.rows,
        },
        disclosures: Vec::new(),
        undisclosed: Vec::new(),
        diagnostics: v.diagnostics,
        index: v.index,
    }
}

/// The kind of a parsed COSE_Sign1.
pub(crate) fn cose_kind(k: TokenKind) -> Kind {
    match k {
        TokenKind::Sign1 => Kind::CoseSign1,
        TokenKind::Cwt => Kind::Cwt,
        TokenKind::SdCwt => Kind::SdCwt,
        TokenKind::SdKbt => Kind::SdKbt,
    }
}

/// Renders `bytes` as `kind`.
pub(crate) fn build(
    registry: &Registry,
    kind: &Kind,
    bytes: &[u8],
    view: &ViewOptions,
) -> Result<Built, EngineError> {
    let notes = Notes::new(registry, view.annotations);
    match kind {
        Kind::Jwt
        | Kind::JwsCompact
        | Kind::SdJwt { .. }
        | Kind::JwsJson { .. }
        | Kind::SdJwtJson { .. } => {
            let v = jose::build(utf8(bytes)?, kind, notes, view)?;
            Ok(Built {
                kind: v.kind,
                tree: v.tree,
                main: Rendered {
                    language: Language::Json,
                    line_count: line_count(&v.text),
                    text: v.text,
                },
                raw: RawView::Segments {
                    segments: v.segments,
                },
                disclosures: v.disclosures,
                undisclosed: v.undisclosed,
                diagnostics: v.diagnostics,
                index: v.index,
            })
        }
        Kind::JsonClaims => json_claims(bytes, notes, view),
        Kind::CborClaims => {
            let item = decode(bytes)?;
            let v = cbor::build(&item, bytes, &Role::Claims, notes, view, &MainText::Print);
            Ok(from_cbor(Kind::CborClaims, v, bytes.to_vec()))
        }
        Kind::EdnClaims => {
            let text = utf8(bytes)?;
            let parsed = tokenator_edn::parse_with(text, &ParseOptions::default())
                .map_err(|e| EngineError::new(ErrorCode::Parse, format!("EDN: {e:?}")))?;
            let Some(first) = parsed.items.first() else {
                return err(ErrorCode::Parse, "no EDN item");
            };
            let cbor = tokenator_cbor::encode(first, tokenator_cbor::EncodeMode::Preserve)
                .map_err(|e| EngineError::new(ErrorCode::Parse, format!("cannot encode: {e:?}")))?;
            let item = decode(&cbor)?;
            let main = MainText::Given {
                text,
                spans: &parsed.spans,
            };
            let v = cbor::build(&item, &cbor, &Role::Claims, notes, view, &main);
            let mut built = from_cbor(Kind::EdnClaims, v, cbor.clone());
            built
                .diagnostics
                .extend(edn_warnings(text, &parsed.warnings));
            Ok(built)
        }
        Kind::CoseKey | Kind::CoseKeySet => {
            let item = decode(bytes)?;
            let role = if *kind == Kind::CoseKey {
                Role::Key
            } else {
                Role::KeySet
            };
            let v = cbor::build(&item, bytes, &role, notes, view, &MainText::Print);
            Ok(from_cbor(kind.clone(), v, bytes.to_vec()))
        }
        Kind::CoseSign1 | Kind::Cwt | Kind::SdCwt | Kind::SdKbt => cose(kind, bytes, notes, view),
        Kind::Jwk | Kind::JwkSet | Kind::Pem { .. } => err(
            ErrorCode::UnsupportedKind,
            format!("{} belongs in the key panel", kind.label()),
        ),
    }
}

fn json_claims(bytes: &[u8], notes: Notes<'_>, view: &ViewOptions) -> Result<Built, EngineError> {
    let text = String::from_utf8_lossy(bytes).into_owned();
    let parsed = tokenator_json::parse_with_options(
        text.as_bytes(),
        &tokenator_json::ParseOptions::default(),
    )
    .map_err(|e| EngineError::new(ErrorCode::Parse, format!("JSON: {e}")))?;
    let index = TextIndex::new(&text);
    let none = |_: usize, _: usize| -> Option<RawRange> { None };
    let mut walk = json::JsonWalk {
        notes,
        now: view.now,
        text: &index,
        raw: &none,
        index: Vec::new(),
    };
    let tree = walk.tree(
        &parsed.node,
        NodeId::root(),
        String::new(),
        json::JRole::Claims,
    );
    let diagnostics = parsed
        .warnings
        .iter()
        .map(|w| {
            let (code, message) = json_warning(w.kind);
            Diagnostic {
                severity: Severity::Warning,
                code: code.to_owned(),
                message: message.to_owned(),
                node_id: Some(json_id_at(&parsed.node, w.offset, NodeId::root())),
                main: Some(index.range(w.offset..w.offset)),
                raw: None,
            }
        })
        .collect();
    let idx = walk.index;
    Ok(Built {
        kind: Kind::JsonClaims,
        tree,
        main: Rendered {
            language: Language::Json,
            line_count: line_count(&text),
            text,
        },
        raw: RawView::None,
        disclosures: Vec::new(),
        undisclosed: Vec::new(),
        diagnostics,
        index: idx,
    })
}

fn cose(
    kind: &Kind,
    bytes: &[u8],
    notes: Notes<'_>,
    view: &ViewOptions,
) -> Result<Built, EngineError> {
    let item = decode(bytes)?;
    let sign1 = CborBackend
        .parse(bytes)
        .map_err(|e| EngineError::new(ErrorCode::Parse, format!("not a COSE_Sign1: {e:?}")))?;
    let found = cose_kind(sign1.kind());
    let kind = match (kind, &found) {
        (Kind::Cwt | Kind::CoseSign1, Kind::Cwt | Kind::CoseSign1) => kind.clone(),
        _ => found,
    };
    let v = cbor::build(&item, bytes, &Role::Sign1, notes, view, &MainText::Print);
    let mut diagnostics = v.diagnostics.clone();
    let sd = SdCwt::from_sign1(sign1);
    for d in sd.sign1.diagnostics.iter().chain(&sd.diagnostics) {
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            code: "cose.diagnostic".to_owned(),
            message: format!("{:?}: {:?}", d.part, d.kind),
            node_id: d.span.and_then(|s| innermost(&v.index, s.start, s.end)),
            main: None,
            raw: d.span.map(|s| ByteRange {
                start: u32_of(s.start),
                end: u32_of(s.end),
            }),
        });
    }
    let mut built = from_cbor(kind.clone(), v, bytes.to_vec());
    built.diagnostics = diagnostics;
    if matches!(kind, Kind::SdCwt | Kind::SdKbt) || !sd.disclosures.is_empty() {
        let (infos, undisclosed, marks) = if kind == Kind::SdKbt {
            kcwt_sd(bytes, &built.index)
        } else {
            sd_view(&sd, 0, &NodeId::root(), &built.index)
        };
        apply_marks(&mut built.tree, &marks, |n| {
            n.label == "simple(59)" && n.kind == NodeKind::Array
        });
        built.disclosures = infos;
        built.undisclosed = undisclosed;
    }
    Ok(built)
}

/// The id of the SD-KBT's `kcwt` node.
pub(crate) fn kcwt_id() -> NodeId {
    NodeId::root().child("protected").decoded(0).child("13")
}

type SdParts = (Vec<DisclosureInfo>, Vec<SlotInfo>, Vec<(NodeId, SdMark)>);

fn kcwt_sd(bytes: &[u8], index: &[(usize, usize, NodeId)]) -> SdParts {
    let id = kcwt_id();
    let Some((s, e, _)) = index.iter().find(|(_, _, i)| *i == id) else {
        return (Vec::new(), Vec::new(), Vec::new());
    };
    let Some(slice) = bytes.get(*s..*e) else {
        return (Vec::new(), Vec::new(), Vec::new());
    };
    match CborBackend.parse(slice) {
        Ok(inner) => sd_view(&SdCwt::from_sign1(inner), *s, &id, index),
        Err(_) => (Vec::new(), Vec::new(), Vec::new()),
    }
}

/// Disclosure infos, undisclosed slots, and marks of an SD-CWT whose
/// bytes start at `base`, with node ids under `prefix`.
fn sd_view(
    sd: &SdCwt<'_>,
    base: usize,
    prefix: &NodeId,
    index: &[(usize, usize, NodeId)],
) -> SdParts {
    let report = match_disclosures(sd);
    let slot_node = |slot: &tokenator_cose::sd::Slot| -> Option<NodeId> {
        let id = exact(index, base + slot.span.start, base + slot.span.end)?;
        Some(match slot.kind {
            SlotKind::ArrayElement if id.as_str().ends_with("/~t") => id.parent().unwrap_or(id),
            _ => id,
        })
    };
    let mut marks = Vec::new();
    let mut decoys = Vec::new();
    let mut infos = Vec::with_capacity(sd.disclosures.len());
    for d in &sd.disclosures {
        let i = d.index;
        let node_id = prefix.child("unprotected").child("17").index(i);
        let matched = report.matched.iter().find(|m| m.disclosure == i);
        let slot = matched.and_then(|m| slot_node(&m.slot));
        let status = if report.malformed.contains(&i) {
            DisclosureStatus::Malformed
        } else if let Some(f) = report.forbidden.iter().find(|f| f.disclosure == i) {
            match f.reason {
                ForbiddenReason::KindMismatch => DisclosureStatus::KindMismatch,
                _ => DisclosureStatus::ForbiddenName,
            }
        } else if report.key_collisions.iter().any(|c| c.disclosure == i) {
            DisclosureStatus::NameCollision
        } else if report.duplicate_disclosures.contains(&i) {
            DisclosureStatus::Duplicate
        } else if matched.is_some() {
            DisclosureStatus::Matched
        } else {
            DisclosureStatus::Unmatched
        };
        let (salt, claim, value, decoy) = match &d.content {
            DisclosureContent::Claim { salt, value, key } => (
                hex(salt),
                Some(crate::cbor::compact_edn(key)),
                exact_edn(value),
                false,
            ),
            DisclosureContent::Element { salt, value } => {
                (hex(salt), None, exact_edn(value), false)
            }
            DisclosureContent::Decoy { salt } => (hex(salt), None, String::new(), true),
            DisclosureContent::Malformed(_) => (String::new(), None, String::new(), false),
        };
        let digest = d.digest.clone().map(|dg| hex(&dg)).unwrap_or_default();
        if let (Some(m), Some(sid)) = (matched, &slot) {
            // A slot filled by a decoy disclosure hides no claim: it is
            // listed as undisclosed (a decoy) and its mark links nothing.
            marks.push((
                sid.clone(),
                SdMark::Slot {
                    digest: hex(&m.slot.digest),
                    disclosure: (!decoy).then_some(u32_of(i)),
                },
            ));
            if decoy {
                decoys.push(SlotInfo {
                    node_id: sid.clone(),
                    digest: hex(&m.slot.digest),
                    array_element: m.slot.kind == SlotKind::ArrayElement,
                });
            }
        }
        marks.push((node_id.clone(), SdMark::Disclosure { index: u32_of(i) }));
        infos.push(DisclosureInfo {
            index: u32_of(i),
            node_id,
            digest,
            salt,
            claim,
            value,
            decoy,
            status,
            slot,
        });
    }
    let mut undisclosed = decoys;
    for s in &report.undisclosed {
        let Some(id) = slot_node(s) else { continue };
        marks.push((
            id.clone(),
            SdMark::Slot {
                digest: hex(&s.digest),
                disclosure: None,
            },
        ));
        undisclosed.push(SlotInfo {
            node_id: id,
            digest: hex(&s.digest),
            array_element: s.kind == SlotKind::ArrayElement,
        });
    }
    (infos, undisclosed, marks)
}

/// A full document.
pub(crate) fn document(
    registry: &Registry,
    kind: &Kind,
    bytes: &[u8],
    layers: Vec<Layer>,
    view: &ViewOptions,
) -> Result<Document, EngineError> {
    let b = build(registry, kind, bytes, view)?;
    Ok(Document {
        signed: b.kind.is_signed(),
        kind: b.kind,
        layers,
        bytes: Bytes(bytes.to_vec()),
        signature_stale: false,
        tree: b.tree,
        main: b.main,
        raw: b.raw,
        disclosures: b.disclosures,
        undisclosed: b.undisclosed,
        diagnostics: b.diagnostics,
    })
}

/// A document for bytes that cannot be read as `kind` (after `tamper`):
/// the root node and an error diagnostic.
pub(crate) fn unreadable(kind: &Kind, bytes: &[u8], error: &EngineError) -> Document {
    let jose = kind.family() == Some(crate::dto::detect::Family::Jose);
    let tree = Node {
        id: NodeId::root(),
        kind: if jose {
            NodeKind::Document
        } else {
            NodeKind::Bytes
        },
        label: String::new(),
        annotation: None,
        main: None,
        raw: Some(RawRange {
            start: 0,
            end: u32_of(bytes.len()),
            row_start: 0,
            row_end: 0,
        }),
        key: None,
        time: None,
        sd: None,
        children: Vec::new(),
    };
    Document {
        kind: kind.clone(),
        layers: Vec::new(),
        bytes: Bytes(bytes.to_vec()),
        signed: kind.is_signed(),
        signature_stale: true,
        tree,
        main: Rendered {
            language: if jose { Language::Json } else { Language::Edn },
            text: String::new(),
            line_count: 1,
        },
        raw: if jose {
            RawView::Segments {
                segments: Vec::new(),
            }
        } else {
            RawView::Hex {
                bytes: Bytes(bytes.to_vec()),
                rows: Vec::new(),
            }
        },
        disclosures: Vec::new(),
        undisclosed: Vec::new(),
        diagnostics: vec![Diagnostic {
            severity: Severity::Error,
            code: if jose { "jose.parse" } else { "cbor.decode" }.to_owned(),
            message: error.message.clone(),
            node_id: Some(NodeId::root()),
            main: None,
            raw: Some(ByteRange {
                start: 0,
                end: u32_of(bytes.len()),
            }),
        }],
    }
}
