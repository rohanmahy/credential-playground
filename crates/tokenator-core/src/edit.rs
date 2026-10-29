//! Live edit: main-pane text back to bytes, keeping unedited bytes.

use tokenator_edn::ParseOptions;
use tokenator_json::{Node as JNode, Value as JValue};
use tokenator_registry::Registry;

use crate::annotate::Notes;
use crate::dto::actions::{EditRequest, EditResult};
use crate::dto::common::{Bytes, NodeId};
use crate::dto::detect::{Family, Kind};
use crate::dto::document::{Diagnostic, Severity};
use crate::manipulate::signed_changed;
use crate::util::{TextIndex, json_string};
use crate::view::jose::{PartLoc, PartWhich, b64u};
use crate::view::{self, edn_warnings};

fn error_at(text: &str, offset: usize, code: &str, message: String) -> Diagnostic {
    let index = TextIndex::new(text);
    let end = text
        .get(offset..)
        .and_then(|rest| rest.chars().next())
        .map_or(offset, |c| offset + c.len_utf8());
    Diagnostic {
        severity: Severity::Error,
        code: code.to_owned(),
        message,
        node_id: None,
        main: Some(index.range(offset.min(text.len())..end.min(text.len()))),
        raw: None,
    }
}

fn error(code: &str, message: impl Into<String>) -> Diagnostic {
    Diagnostic {
        severity: Severity::Error,
        code: code.to_owned(),
        message: message.into(),
        node_id: None,
        main: None,
        raw: None,
    }
}

pub(crate) fn parse_edit(registry: &Registry, req: &EditRequest) -> EditResult {
    match edit(registry, req) {
        Ok((bytes, diagnostics)) => {
            let stale = signed_changed(&req.kind, &req.base, &bytes);
            match view::document(registry, &req.kind, &bytes, Vec::new(), &req.view) {
                Ok(mut doc) => {
                    doc.signature_stale = stale;
                    let mut diagnostics = diagnostics;
                    diagnostics.extend(doc.diagnostics.iter().filter(|d| d.severity == Severity::Error).cloned());
                    EditResult {
                        ok: true,
                        bytes: Some(Bytes(bytes)),
                        document: Some(doc),
                        signature_stale: stale,
                        diagnostics,
                    }
                }
                Err(e) => failed(vec![error("edit.structure", e.message)]),
            }
        }
        Err(diagnostics) => failed(diagnostics),
    }
}

fn failed(diagnostics: Vec<Diagnostic>) -> EditResult {
    EditResult {
        ok: false,
        bytes: None,
        document: None,
        signature_stale: false,
        diagnostics,
    }
}

type Edited = Result<(Vec<u8>, Vec<Diagnostic>), Vec<Diagnostic>>;

fn edit(registry: &Registry, req: &EditRequest) -> Edited {
    let text = req.text.as_str();
    match &req.kind {
        Kind::JsonClaims => match tokenator_json::parse(text.as_bytes()) {
            Ok(_) => Ok((text.as_bytes().to_vec(), Vec::new())),
            Err(e) => Err(vec![error_at(text, e.offset, "json.syntax", e.to_string())]),
        },
        Kind::EdnClaims => edn(text).map(|(_, warnings)| (text.as_bytes().to_vec(), warnings)),
        Kind::CborClaims | Kind::CoseKey | Kind::CoseKeySet | Kind::CoseSign1 | Kind::Cwt | Kind::SdCwt | Kind::SdKbt => {
            edn(text).and_then(|(item, warnings)| match tokenator_cbor::encode(&item, tokenator_cbor::EncodeMode::Preserve) {
                Ok(bytes) => Ok((bytes, warnings)),
                Err(e) => Err(vec![error("cbor.encode", format!("{e:?}"))]),
            })
        }
        k if k.family() == Some(Family::Jose) => jose(registry, req),
        k => Err(vec![error("edit.unsupported_kind", format!("a {} cannot be edited here", k.label()))]),
    }
}

fn edn(text: &str) -> Result<(tokenator_cbor::Item<'static>, Vec<Diagnostic>), Vec<Diagnostic>> {
    match tokenator_edn::parse_with(text, &ParseOptions::default()) {
        Ok(mut parsed) if parsed.items.len() == 1 => {
            let warnings = edn_warnings(text, &parsed.warnings);
            Ok((parsed.items.remove(0), warnings))
        }
        Ok(_) => Err(vec![error("edn.syntax", "expected exactly one item")]),
        Err(e) => Err(vec![error_at(text, e.pos.offset, "edn.syntax", format!("{:?}", e.kind))]),
    }
}

/// The node at a part's id (member names and indexes) in the edited view.
fn locate<'n>(root: &'n JNode<'n>, id: &NodeId) -> Option<&'n JNode<'n>> {
    let mut node = root;
    for seg in id.segments() {
        node = match node.value() {
            JValue::Object(_) => node.get(&seg)?,
            JValue::Array(_) => node.index(seg.parse().ok()?)?,
            _ => return None,
        };
    }
    Some(node)
}

#[allow(clippy::too_many_lines)]
fn jose(registry: &Registry, req: &EditRequest) -> Edited {
    let Ok(base_text) = std::str::from_utf8(&req.base) else {
        return Err(vec![error("jose.base", "the base token is not UTF-8")]);
    };
    let base = view::jose::build(base_text, &req.kind, Notes::new(registry, false), &req.view)
        .map_err(|e| vec![error("jose.base", e.message)])?;
    let text = req.text.as_str();
    let edited = tokenator_json::parse_with_options(text.as_bytes(), &tokenator_json::ParseOptions { max_depth: 1024 })
        .map_err(|e| vec![error_at(text, e.offset, "json.syntax", e.to_string())])?
        .node;
    let mut changed = false;
    let mut new_parts: Vec<(PartLoc, String)> = Vec::with_capacity(base.parts.len());
    for part in &base.parts {
        let Some(node) = locate(&edited, &part.id) else {
            if matches!(part.which, PartWhich::Disclosure(_)) {
                changed = true;
                continue;
            }
            return Err(vec![error("jose.part_missing", format!("{} is missing", part.id))]);
        };
        let Some(span) = node.span() else {
            return Err(vec![error("jose.part_missing", format!("{} has no text", part.id))]);
        };
        let slice = text.get(span.start..span.end).unwrap_or("");
        let old = base.text.get(part.value.0..part.value.1).unwrap_or("");
        let new = if slice == old {
            part.text.clone()
        } else {
            changed = true;
            if part.decoded {
                b64u(slice.as_bytes())
            } else if matches!(part.which, PartWhich::Unprotected(_)) {
                slice.to_owned()
            } else {
                match node.value() {
                    JValue::String(s) => s.to_string(),
                    _ => return Err(vec![error_at(text, span.start, "jose.not_a_string", format!("{} must be a base64url string", part.id))]),
                }
            }
        };
        new_parts.push((part.clone(), new));
    }
    // Disclosures added in the text.
    let base_count = base.parts.iter().filter(|p| matches!(p.which, PartWhich::Disclosure(_))).count();
    let mut added = Vec::new();
    if let Some(JValue::Array(items)) = edited.get("disclosures").map(JNode::value) {
        for item in items.iter().skip(base_count) {
            changed = true;
            let Some(span) = item.span() else { continue };
            let slice = text.get(span.start..span.end).unwrap_or("");
            added.push(match item.value() {
                JValue::String(s) => s.to_string(),
                _ => b64u(slice.as_bytes()),
            });
        }
    }
    if !changed {
        return Ok((req.base.0.clone(), Vec::new()));
    }
    let compact = !base_text.trim_start().starts_with('{');
    let get = |w: PartWhich| new_parts.iter().find(|(p, _)| p.which == w).map(|(_, t)| t.clone());
    let disclosures: Vec<String> = new_parts
        .iter()
        .filter(|(p, _)| matches!(p.which, PartWhich::Disclosure(_)))
        .map(|(_, t)| t.clone())
        .chain(added.iter().cloned())
        .collect();
    let sd = matches!(req.kind, Kind::SdJwt { .. } | Kind::SdJwtJson { .. }) || !disclosures.is_empty();
    if compact {
        let mut out = format!(
            "{}.{}.{}",
            get(PartWhich::Protected(0)).unwrap_or_default(),
            get(PartWhich::Payload).unwrap_or_default(),
            get(PartWhich::Signature(0)).unwrap_or_default()
        );
        if sd {
            for d in &disclosures {
                out.push('~');
                out.push_str(d);
            }
            out.push('~');
            if let Some(kp) = get(PartWhich::KbProtected) {
                out.push_str(&format!(
                    "{kp}.{}.{}",
                    get(PartWhich::KbPayload).unwrap_or_default(),
                    get(PartWhich::KbSignature).unwrap_or_default()
                ));
            }
        }
        return Ok((out.into_bytes(), Vec::new()));
    }
    // JSON serializations: splice the parts that changed into the envelope.
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    let header0 = new_parts
        .iter()
        .find(|(p, t)| p.which == PartWhich::Unprotected(0) && p.text != *t)
        .and_then(|(p, t)| p.source.map(|s| (s, t.clone())));
    let count_changed = disclosures.len() != base_count;
    for (p, t) in &new_parts {
        let Some((s, e)) = p.source else { continue };
        if p.text == *t {
            continue;
        }
        let inside_header = header0.as_ref().is_some_and(|((hs, he), _)| s >= *hs && e <= *he && p.which != PartWhich::Unprotected(0));
        if inside_header || (count_changed && matches!(p.which, PartWhich::Disclosure(_))) {
            continue;
        }
        if matches!(p.which, PartWhich::KbProtected | PartWhich::KbPayload | PartWhich::KbSignature) {
            continue;
        }
        edits.push((s, e, t.clone()));
    }
    let kb_changed = new_parts
        .iter()
        .any(|(p, t)| matches!(p.which, PartWhich::KbProtected | PartWhich::KbPayload | PartWhich::KbSignature) && p.text != *t);
    let envelope = tokenator_json::parse(base_text.as_bytes()).ok();
    let header_node = envelope
        .as_ref()
        .and_then(|r| r.get("header").or_else(|| r.get("signatures").and_then(|s| s.index(0)).and_then(|s| s.get("header"))));
    if header0.is_none() {
        if count_changed && let Some(span) = header_node.and_then(|h| h.get("disclosures")).and_then(JNode::span) {
            let list: Vec<String> = disclosures.iter().map(|d| json_string(d)).collect();
            edits.push((span.start, span.end, format!("[{}]", list.join(", "))));
        }
        if kb_changed && let Some(span) = header_node.and_then(|h| h.get("kb_jwt")).and_then(JNode::span) {
            let kb = format!(
                "{}.{}.{}",
                get(PartWhich::KbProtected).unwrap_or_default(),
                get(PartWhich::KbPayload).unwrap_or_default(),
                get(PartWhich::KbSignature).unwrap_or_default()
            );
            edits.push((span.start, span.end, json_string(&kb)));
        }
    }
    edits.sort_by_key(|e| std::cmp::Reverse(e.0));
    let mut out = base_text.to_owned();
    for (s, e, new) in edits {
        if let (Some(a), Some(b)) = (out.get(..s), out.get(e..)) {
            out = format!("{a}{new}{b}");
        }
    }
    Ok((out.into_bytes(), Vec::new()))
}
