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

/// A DTO layer for `tokenator-detect`.
pub(crate) fn layer_td(l: &Layer) -> td::Layer {
    match l {
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
    }
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
            td::Layer::JsonField { path } => format!("JSON field {}", td::json_pointer(&path)),
            _ => "JSON field".to_owned(),
        },
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

/// Ranked candidates; EDN look-alikes are kept only when they parse to a
/// map (then they are EDN claim sets).
pub(crate) fn detect(input: &[u8]) -> Vec<Candidate> {
    let mut out = Vec::new();
    for c in td::detect(input) {
        match kind_dto(&c.kind) {
            Some(kind) => out.push(candidate(kind, &c)),
            None => {
                let layers: Vec<td::Layer> = c.layers.clone();
                let is_map = td::unwrap_layers(input, &layers)
                    .ok()
                    .and_then(|payload| String::from_utf8(payload).ok())
                    .and_then(|text| tokenator_edn::parse(&text).ok())
                    .is_some_and(|item| matches!(item.value, tokenator_cbor::Value::Map(_)));
                if is_map {
                    out.push(candidate(Kind::EdnClaims, &c));
                }
            }
        }
    }
    out
}

/// The document bytes and the outer layers for opening `input` as
/// `candidate`: COSE tags stay in the bytes, and a text claim set keeps
/// its surrounding whitespace.
pub(crate) fn unwrap(input: &[u8], candidate: &Candidate) -> Result<(Vec<u8>, Vec<Layer>), EngineError> {
    let mut layers = candidate.layers.clone();
    while matches!(layers.last(), Some(Layer::CborTag { .. })) {
        layers.pop();
    }
    if matches!(candidate.kind, Kind::JsonClaims | Kind::EdnClaims)
        && matches!(layers.first(), Some(Layer::Trim { .. }))
    {
        layers.remove(0);
    }
    let td_layers: Vec<td::Layer> = layers.iter().map(layer_td).collect();
    match td::unwrap_layers(input, &td_layers) {
        Ok(bytes) => Ok((bytes, layers)),
        Err(e) => err(ErrorCode::InvalidCandidate, e.to_string()),
    }
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
            format!("{} goes to the key panel (key_import)", candidate.kind.label()),
        );
    }
    let (bytes, layers) = unwrap(input, candidate)?;
    view::document(registry, &candidate.kind, &bytes, layers, view_opts)
}
