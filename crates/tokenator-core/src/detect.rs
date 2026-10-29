//! Detection (`tokenator-detect` plus EDN confirmation) and `open`.

use tokenator_detect as td;
use tokenator_registry::Registry;

use crate::dto::common::ByteRange;
use crate::dto::detect::{Candidate, JsonPathSegment, Kind, Layer};
use crate::dto::document::{Document, ViewOptions};
use crate::dto::error::{EngineError, ErrorCode};
use crate::util::{err, u32_of};
use crate::view;

fn opt_u32(n: Option<usize>) -> Option<u32> {
    n.map(u32_of)
}

fn opt_usize(n: Option<u32>) -> Option<usize> {
    n.and_then(|n| usize::try_from(n).ok())
}

/// A detect layer as a DTO.
pub(crate) fn layer_dto(l: &td::Layer) -> Layer {
    match l {
        td::Layer::Trim { leading, trailing } => Layer::Trim {
            leading: leading.clone(),
            trailing: trailing.clone(),
        },
        td::Layer::Quotes { quote } => Layer::Quotes { quote: *quote },
        td::Layer::AuthorizationHeader { prefix } => Layer::AuthorizationHeader {
            prefix: prefix.clone(),
        },
        td::Layer::BearerPrefix { prefix } => Layer::BearerPrefix {
            prefix: prefix.clone(),
        },
        td::Layer::UrlEncoded => Layer::UrlEncoded,
        td::Layer::JsonField { path } => Layer::JsonField {
            path: path
                .iter()
                .map(|s| match s {
                    td::PathSegment::Key(k) => JsonPathSegment::Key(k.clone()),
                    td::PathSegment::Index(i) => JsonPathSegment::Index(u32_of(*i)),
                })
                .collect(),
        },
        td::Layer::Base64Url { padded, wrap } => Layer::Base64Url {
            padded: *padded,
            wrap: opt_u32(*wrap),
        },
        td::Layer::Base64Std { padded, wrap } => Layer::Base64Std {
            padded: *padded,
            wrap: opt_u32(*wrap),
        },
        td::Layer::Hex {
            upper,
            separator,
            wrap,
        } => Layer::Hex {
            upper: *upper,
            separator: *separator,
            wrap: opt_u32(*wrap),
        },
        td::Layer::CborTag(tag) => Layer::CborTag { tag: *tag },
    }
}

/// A DTO layer for `tokenator-detect`; `None` for [`Layer::Edn`], which
/// only core applies.
pub(crate) fn layer_td(l: &Layer) -> Option<td::Layer> {
    Some(match l {
        Layer::Trim { leading, trailing } => td::Layer::Trim {
            leading: leading.clone(),
            trailing: trailing.clone(),
        },
        Layer::Quotes { quote } => td::Layer::Quotes { quote: *quote },
        Layer::AuthorizationHeader { prefix } => td::Layer::AuthorizationHeader {
            prefix: prefix.clone(),
        },
        Layer::BearerPrefix { prefix } => td::Layer::BearerPrefix {
            prefix: prefix.clone(),
        },
        Layer::UrlEncoded => td::Layer::UrlEncoded,
        Layer::JsonField { path } => td::Layer::JsonField {
            path: path
                .iter()
                .map(|s| match s {
                    JsonPathSegment::Key(k) => td::PathSegment::Key(k.clone()),
                    JsonPathSegment::Index(i) => {
                        td::PathSegment::Index(usize::try_from(*i).unwrap_or(usize::MAX))
                    }
                })
                .collect(),
        },
        Layer::Base64Url { padded, wrap } => td::Layer::Base64Url {
            padded: *padded,
            wrap: opt_usize(*wrap),
        },
        Layer::Base64Std { padded, wrap } => td::Layer::Base64Std {
            padded: *padded,
            wrap: opt_usize(*wrap),
        },
        Layer::Hex {
            upper,
            separator,
            wrap,
        } => td::Layer::Hex {
            upper: *upper,
            separator: *separator,
            wrap: opt_usize(*wrap),
        },
        Layer::CborTag { tag } => td::Layer::CborTag(*tag),
        Layer::Edn => return None,
    })
}

fn kind_dto(k: &td::Kind) -> Option<Kind> {
    Some(match k {
        td::Kind::JwsCompact => Kind::JwsCompact,
        td::Kind::Jwt => Kind::Jwt,
        td::Kind::SdJwt { kb } => Kind::SdJwt { kb: *kb },
        td::Kind::JwsJson { general } => Kind::JwsJson { general: *general },
        td::Kind::SdJwtJson { general, kb } => Kind::SdJwtJson {
            general: *general,
            kb: *kb,
        },
        td::Kind::CoseSign1 => Kind::CoseSign1,
        td::Kind::Cwt => Kind::Cwt,
        td::Kind::SdCwt => Kind::SdCwt,
        td::Kind::SdKbt => Kind::SdKbt,
        td::Kind::JsonClaims => Kind::JsonClaims,
        td::Kind::CborClaims => Kind::CborClaims,
        td::Kind::EdnText => return None,
        td::Kind::Jwk => Kind::Jwk,
        td::Kind::JwkSet => Kind::JwkSet,
        td::Kind::CoseKey => Kind::CoseKey,
        td::Kind::CoseKeySet => Kind::CoseKeySet,
        td::Kind::Pem { labels } => Kind::Pem {
            labels: labels.clone(),
        },
    })
}

/// The breadcrumb entry of a layer (`None` for layers not shown).
fn crumb(l: &Layer) -> Option<String> {
    Some(match l {
        Layer::Trim { .. } => return None,
        Layer::Quotes { .. } => "quotes".to_owned(),
        Layer::AuthorizationHeader { .. } => "Authorization header".to_owned(),
        Layer::BearerPrefix { .. } => "Bearer".to_owned(),
        Layer::UrlEncoded => "URL-encoded".to_owned(),
        Layer::JsonField { .. } => match layer_td(l) {
            Some(td::Layer::JsonField { path }) => {
                format!("JSON field {}", td::json_pointer(&path))
            }
            _ => "JSON field".to_owned(),
        },
        Layer::Edn => "EDN".to_owned(),
        Layer::Base64Url { .. } => "base64url".to_owned(),
        Layer::Base64Std { .. } => "base64".to_owned(),
        Layer::Hex { .. } => "hex".to_owned(),
        Layer::CborTag { tag: 61 } => "CWT tag 61".to_owned(),
        Layer::CborTag { tag: 18 } => "COSE_Sign1 tag 18".to_owned(),
        Layer::CborTag { tag } => format!("tag {tag}"),
    })
}

fn candidate(kind: Kind, c: &td::Candidate) -> Candidate {
    let layers: Vec<Layer> = c.layers.iter().map(layer_dto).collect();
    let mut breadcrumb: Vec<String> = layers.iter().filter_map(crumb).collect();
    breadcrumb.push(kind.label().to_owned());
    Candidate {
        kind,
        confidence: c.confidence,
        layers,
        payload_range: ByteRange {
            start: u32_of(c.payload_range.start),
            end: u32_of(c.payload_range.end),
        },
        breadcrumb,
    }
}

/// The CBOR encoding of EDN text (encoding indicators honored).
fn edn_cbor(text: &str) -> Option<Vec<u8>> {
    let item = tokenator_edn::parse(text).ok()?;
    tokenator_cbor::encode(&item, tokenator_cbor::EncodeMode::Preserve).ok()
}

/// The candidates for EDN text found by `tokenator-detect` (`c`): the CBOR
/// it encodes is classified like binary input, by `tokenator_detect::detect`
/// itself. A claims map stays an EDN claim set (its bytes are the text);
/// anything else (a COSE_Sign1, a COSE_Key, …) gets a [`Layer::Edn`] after
/// the text's own layers, one point below the binary reading. Text that
/// does not parse gives nothing.
fn edn_candidates(input: &[u8], c: &td::Candidate) -> Vec<Candidate> {
    let Some(cbor) = td::unwrap_layers(input, &c.layers)
        .ok()
        .and_then(|payload| String::from_utf8(payload).ok())
        .and_then(|text| edn_cbor(&text))
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for b in td::detect(&cbor) {
        // Only readings of the CBOR itself (tags peeled), not of it as text.
        if !b.layers.iter().all(|l| matches!(l, td::Layer::CborTag(_))) {
            continue;
        }
        let kind = match kind_dto(&b.kind) {
            Some(Kind::CborClaims) => Kind::EdnClaims,
            Some(kind) => kind,
            None => continue,
        };
        let mut found = candidate(kind.clone(), c);
        found.confidence = b.confidence.saturating_sub(1);
        if kind != Kind::EdnClaims {
            found.layers.push(Layer::Edn);
            found.layers.extend(b.layers.iter().map(layer_dto));
            found.breadcrumb = found.layers.iter().filter_map(crumb).collect();
            found.breadcrumb.push(kind.label().to_owned());
        }
        if !out
            .iter()
            .any(|o: &Candidate| o.kind == found.kind && o.layers == found.layers)
        {
            out.push(found);
        }
    }
    out
}

/// Ranked candidates. EDN look-alikes are confirmed by parsing and
/// classified by the CBOR they encode (#44); EDN that does not parse is
/// dropped.
pub(crate) fn detect(input: &[u8]) -> Vec<Candidate> {
    let mut out = Vec::new();
    for c in td::detect(input) {
        match kind_dto(&c.kind) {
            Some(kind) => out.push(candidate(kind, &c)),
            None => out.extend(edn_candidates(input, &c)),
        }
    }
    // Stable: ties keep tokenator-detect's order.
    out.sort_by_key(|c| std::cmp::Reverse(c.confidence));
    out
}

/// Applies `layers` (outermost first) to `input`; a trailing
/// [`Layer::Edn`] turns the text into its CBOR encoding.
fn unwrap_all(input: &[u8], layers: &[Layer]) -> Result<Vec<u8>, EngineError> {
    let (layers, edn) = match layers.split_last() {
        Some((Layer::Edn, rest)) => (rest, true),
        _ => (layers, false),
    };
    let td_layers: Option<Vec<td::Layer>> = layers.iter().map(layer_td).collect();
    let Some(td_layers) = td_layers else {
        return err(
            ErrorCode::InvalidCandidate,
            "an EDN layer must be the innermost",
        );
    };
    let bytes = td::unwrap_layers(input, &td_layers)
        .map_err(|e| EngineError::new(ErrorCode::InvalidCandidate, e.to_string()))?;
    if !edn {
        return Ok(bytes);
    }
    std::str::from_utf8(&bytes)
        .ok()
        .and_then(edn_cbor)
        .ok_or_else(|| EngineError::new(ErrorCode::InvalidCandidate, "the text is not EDN"))
}

/// The document bytes and the outer layers for opening `input` as
/// `candidate`: COSE tags stay in the bytes, and a text claim set keeps
/// its surrounding whitespace.
pub(crate) fn unwrap(
    input: &[u8],
    candidate: &Candidate,
) -> Result<(Vec<u8>, Vec<Layer>), EngineError> {
    let mut layers = candidate.layers.clone();
    while matches!(layers.last(), Some(Layer::CborTag { .. })) {
        layers.pop();
    }
    if matches!(candidate.kind, Kind::JsonClaims | Kind::EdnClaims)
        && matches!(layers.first(), Some(Layer::Trim { .. }))
    {
        layers.remove(0);
    }
    let bytes = unwrap_all(input, &layers)?;
    Ok((bytes, layers))
}

pub(crate) fn open(
    registry: &Registry,
    input: &[u8],
    candidate: &Candidate,
    view_opts: &ViewOptions,
) -> Result<Document, EngineError> {
    if candidate.kind.is_key() {
        return err(
            ErrorCode::UnsupportedKind,
            format!(
                "{} goes to the key panel (key_import)",
                candidate.kind.label()
            ),
        );
    }
    let (bytes, layers) = unwrap(input, candidate)?;
    view::document(registry, &candidate.kind, &bytes, layers, view_opts)
}
