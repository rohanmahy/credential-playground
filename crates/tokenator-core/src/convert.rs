//! Claim sets between JSON and EDN (#44), for switching a draft's format.
//!
//! JSON → EDN always works: objects become maps (member order and
//! duplicates kept), arrays arrays, strings text, `true`/`false`/`null`
//! themselves. A number lexeme without fraction or exponent becomes an
//! integer when it fits CBOR's range (−2^64 … 2^64−1; `-0` is 0); every
//! other number becomes a float, with the shortest exact width. With
//! `map_claim_labels`, registered JWT claim names at the top level become
//! their CWT labels (`iss` → 1).
//!
//! EDN → JSON works when the CBOR has a JSON form: text keys (or mapped
//! CWT labels at the top level), no byte strings, tags, undefined, or
//! simple values other than booleans and null, finite floats, and at most
//! 128 levels. Otherwise the first node that has no JSON form is reported.
//! Integers print in decimal, floats with Rust's shortest round-trip form
//! (`1.5`, `2.0`, `1e300`).

use std::borrow::Cow;

use tokenator_cbor::{EncodeMode, Item, Value, decode, encode};
use tokenator_edn::ParseOptions;
use tokenator_json::{Member, Node as JNode, PrintStyle, Value as JValue};
use tokenator_registry::{Label, Registry};

use crate::annotate::Notes;
use crate::dto::actions::{ConvertClaimsRequest, ConvertClaimsResult};
use crate::dto::common::NodeId;
use crate::dto::detect::Kind;
use crate::dto::document::{Diagnostic, Language, Severity};
use crate::edit::error_at;
use crate::view::{self, cbor::MainText, cbor::Role};

/// JSON's nesting limit (tokenator-json's default).
const JSON_DEPTH: usize = tokenator_json::DEFAULT_MAX_DEPTH;

fn failed(diagnostics: Vec<Diagnostic>) -> ConvertClaimsResult {
    ConvertClaimsResult {
        ok: false,
        text: None,
        document: None,
        diagnostics,
    }
}

fn plain_error(code: &str, message: String) -> Diagnostic {
    Diagnostic {
        severity: Severity::Error,
        code: code.to_owned(),
        message,
        node_id: None,
        main: None,
        raw: None,
    }
}

fn kind_of(lang: Language) -> Kind {
    match lang {
        Language::Json => Kind::JsonClaims,
        Language::Edn => Kind::EdnClaims,
    }
}

pub(crate) fn convert(registry: &Registry, req: &ConvertClaimsRequest) -> ConvertClaimsResult {
    let text = match (req.from, req.to) {
        (Language::Json, Language::Edn) => json_to_edn(registry, req),
        (Language::Edn, Language::Json) => edn_to_json(registry, req),
        (Language::Json, Language::Json) => tokenator_json::parse(req.text.as_bytes())
            .map(|_| req.text.clone())
            .map_err(|e| vec![error_at(&req.text, e.offset, "json.syntax", e.to_string())]),
        (Language::Edn, Language::Edn) => tokenator_edn::parse(&req.text)
            .map(|_| req.text.clone())
            .map_err(|e| {
                vec![error_at(
                    &req.text,
                    e.pos.offset,
                    "edn.syntax",
                    format!("{:?}", e.kind),
                )]
            }),
    };
    let text = match text {
        Ok(t) => t,
        Err(d) => return failed(d),
    };
    match view::document(
        registry,
        &kind_of(req.to),
        text.as_bytes(),
        Vec::new(),
        &req.view,
    ) {
        Ok(document) => ConvertClaimsResult {
            ok: true,
            text: Some(text),
            document: Some(document),
            diagnostics: Vec::new(),
        },
        Err(e) => failed(vec![plain_error("convert.render", e.message)]),
    }
}

// ---------------------------------------------------------------- JSON → EDN

/// A JSON number lexeme as a CBOR item.
fn number(lexeme: &str) -> Item<'static> {
    if !lexeme.contains(['.', 'e', 'E'])
        && let Ok(n) = lexeme.parse::<i128>()
    {
        if let Ok(u) = u64::try_from(n) {
            return Item::new(Value::Uint(u));
        }
        // -1 - n for the CBOR argument of a negative integer.
        if let Ok(arg) = u64::try_from(-1 - n) {
            return Item::new(Value::Nint(arg));
        }
    }
    Item::float(lexeme.parse::<f64>().unwrap_or(f64::NAN))
}

/// The CBOR item for a JSON value (depth ≤ JSON's limit, so recursion is
/// bounded).
fn json_item(node: &JNode<'_>, labels: Option<&Registry>) -> Item<'static> {
    match node.value() {
        JValue::Null => Item::new(Value::Null),
        JValue::Bool(b) => Item::new(Value::Bool(*b)),
        JValue::Number(n) => number(n),
        JValue::String(s) => Item::text(s.to_string()),
        JValue::Array(items) => Item::array(items.iter().map(|i| json_item(i, None)).collect()),
        JValue::Object(members) => Item::map(
            members
                .iter()
                .map(|m| {
                    let key = match labels.and_then(|r| r.jwt_to_cwt(m.key())) {
                        Some(Label::Int(n)) => Item::int(*n),
                        Some(Label::Text(t)) => Item::text(t.clone()),
                        None => Item::text(m.key().to_string()),
                    };
                    (key, json_item(m.value(), None))
                })
                .collect(),
        ),
    }
}

fn json_to_edn(registry: &Registry, req: &ConvertClaimsRequest) -> Result<String, Vec<Diagnostic>> {
    let root = tokenator_json::parse(req.text.as_bytes())
        .map_err(|e| vec![error_at(&req.text, e.offset, "json.syntax", e.to_string())])?;
    let item = json_item(&root, req.map_claim_labels.then_some(registry));
    // Print through the document builder, so the EDN carries the same
    // registry comments as a rendered claim set.
    let bytes = encode(&item, EncodeMode::Preserve)
        .map_err(|e| vec![plain_error("cbor.encode", format!("{e:?}"))])?;
    let decoded = decode(&bytes).map_err(|e| vec![plain_error("cbor.decode", format!("{e:?}"))])?;
    let notes = Notes::new(registry, req.view.annotations);
    let built = view::cbor::build(
        &decoded,
        &bytes,
        &Role::Claims,
        notes,
        &req.view,
        &MainText::Print,
    );
    Ok(built.text)
}

// ---------------------------------------------------------------- EDN → JSON

/// Why an item has no JSON form, if it has none.
fn no_json_form(item: &Item<'_>) -> Option<&'static str> {
    match &item.value {
        Value::Bytes(_) => Some("a byte string has no JSON form"),
        Value::Tag(..) => Some("a tag has no JSON form"),
        Value::Undefined => Some("undefined has no JSON form"),
        Value::Simple(_) => Some("a simple value has no JSON form"),
        Value::Float(f, _) if !f.is_finite() => Some("a non-finite float has no JSON form"),
        _ => None,
    }
}

/// One step of [`first_offender`].
enum Visit<'i, 'a> {
    /// A value at a nesting depth; `top` for the root claims map.
    Value(&'i Item<'a>, usize, bool),
    /// A map key; `top` for keys of the root map.
    Key(&'i Item<'a>, bool),
}

/// The first node in document order with no JSON form, and why.
/// Iterative, so deep items cost heap.
fn first_offender<'i, 'a>(
    root: &'i Item<'a>,
    labels: Option<&Registry>,
) -> Option<(&'i Item<'a>, &'static str)> {
    let mut stack = vec![Visit::Value(root, 1, true)];
    while let Some(visit) = stack.pop() {
        match visit {
            Visit::Key(k, top) => {
                let mapped = top
                    && labels
                        .zip(crate::cbor::int_of(k))
                        .is_some_and(|(r, n)| r.cwt_to_jwt(n).is_some());
                if !matches!(k.value, Value::Text(_)) && !mapped {
                    return Some((
                        k,
                        no_json_form(k).unwrap_or("a JSON member name must be text"),
                    ));
                }
            }
            Visit::Value(item, depth, top) => {
                if let Some(why) = no_json_form(item) {
                    return Some((item, why));
                }
                match &item.value {
                    Value::Array(_) | Value::Map(_) if depth > JSON_DEPTH => {
                        return Some((item, "nested deeper than JSON's 128 levels"));
                    }
                    Value::Array(items) => {
                        stack.extend(
                            items
                                .iter()
                                .rev()
                                .map(|i| Visit::Value(i, depth + 1, false)),
                        );
                    }
                    Value::Map(entries) => {
                        for (k, v) in entries.iter().rev() {
                            stack.push(Visit::Value(v, depth + 1, false));
                            stack.push(Visit::Key(k, top));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    None
}

/// The JSON value of an item that has one (checked by [`first_offender`]).
fn item_json(item: &Item<'_>, labels: Option<&Registry>) -> JNode<'static> {
    JNode::new(match &item.value {
        Value::Uint(n) => JValue::Number(Cow::Owned(n.to_string())),
        Value::Nint(n) => JValue::Number(Cow::Owned((-1 - i128::from(*n)).to_string())),
        Value::Float(f, _) => JValue::Number(Cow::Owned(format!("{f:?}"))),
        Value::Text(t) => JValue::String(Cow::Owned(t.to_string())),
        Value::Bool(b) => JValue::Bool(*b),
        Value::Array(items) => JValue::Array(items.iter().map(|i| item_json(i, None)).collect()),
        Value::Map(entries) => JValue::Object(
            entries
                .iter()
                .map(|(k, v)| {
                    let name = match &k.value {
                        Value::Text(t) => t.to_string(),
                        _ => crate::cbor::int_of(k)
                            .and_then(|n| labels.and_then(|r| r.cwt_to_jwt(n)))
                            .map(str::to_owned)
                            .unwrap_or_default(),
                    };
                    Member::new(name, item_json(v, None))
                })
                .collect(),
        ),
        _ => JValue::Null,
    })
}

fn edn_to_json(registry: &Registry, req: &ConvertClaimsRequest) -> Result<String, Vec<Diagnostic>> {
    let text = &req.text;
    let parsed = tokenator_edn::parse_with(text, &ParseOptions::default()).map_err(|e| {
        vec![error_at(
            text,
            e.pos.offset,
            "edn.syntax",
            format!("{:?}", e.kind),
        )]
    })?;
    let Some(first) = parsed.items.first() else {
        return Err(vec![plain_error("edn.syntax", "no EDN item".to_owned())]);
    };
    // Spans for node ids: the encoding, decoded again.
    let bytes = encode(first, EncodeMode::Preserve)
        .map_err(|e| vec![plain_error("cbor.encode", format!("{e:?}"))])?;
    let item = decode(&bytes).map_err(|e| vec![plain_error("cbor.decode", format!("{e:?}"))])?;
    let labels = req.map_claim_labels.then_some(registry);
    if let Some((bad, why)) = first_offender(&item, labels) {
        let (node_id, main) =
            match view::build(registry, &Kind::EdnClaims, text.as_bytes(), &req.view) {
                Ok(built) => {
                    let id = view::exact(&built.index, bad.span.start, bad.span.end);
                    let main = id
                        .as_ref()
                        .and_then(|id| view::find(&built.tree, id))
                        .and_then(|n| n.main);
                    (id, main)
                }
                Err(_) => (None, None),
            };
        return Err(vec![Diagnostic {
            severity: Severity::Error,
            code: "convert.not_representable".to_owned(),
            message: match &node_id {
                Some(id) if !id.is_root() => format!("{id}: {why}"),
                _ => why.to_owned(),
            },
            node_id: node_id.or_else(|| Some(NodeId::root())),
            main,
            raw: None,
        }]);
    }
    Ok(tokenator_json::print(
        &item_json(&item, labels),
        PrintStyle::Pretty,
    ))
}
