//! Issue, redact, disclose, and present.

use std::borrow::Cow;

use base64ct::{Base64, Encoding};
use tokenator_cbor::{Item, Value};
use tokenator_cose::kbt::{PresentOptions, Selection};
use tokenator_cose::sd::{FixedSalts, IssueOptions as CoseIssue, RngSalts, SaltSource, Typ};
use tokenator_cose::{CborBackend, ContentType, CoseError};
use tokenator_crypto::{Alg, CryptoError};
use tokenator_jose as tj;
use tokenator_json::{Member, Node as JNode, Value as JValue};
use tokenator_keys::Key;
use tokenator_registry::Registry;

use crate::dto::actions::{
    CnfChoice, DiscloseRequest, DigestOrder, IssueRequest, JoseSerialization, KidChoice,
    PresentRequest, TypChoice,
};
use crate::dto::common::{KidValue, NodeId, Nonce};
use crate::dto::detect::{Family, Kind};
use crate::dto::document::{Document, ViewOptions};
use crate::dto::error::{EngineError, ErrorCode};
use crate::keyring::{jose_kid, key_error, resolve, resolve_private, signing_alg};
use crate::util::{err, hash_alg, rng, seed32, unhex, unused_rng};
use crate::view;
use crate::view::jose::{b64u, with_parsed};

// ---------------------------------------------------------------- errors

pub(crate) fn crypto_error(e: &CryptoError) -> EngineError {
    match e {
        CryptoError::RandomnessRequired(a) => EngineError::new(
            ErrorCode::Randomness,
            format!("{} needs randomness", tokenator_crypto::alg_to_jose(*a)),
        ),
        CryptoError::KeyNotSuitable { alg, .. } => EngineError::new(
            ErrorCode::UnsupportedAlg,
            format!("the key does not fit {}", tokenator_crypto::alg_to_jose(*alg)),
        ),
        _ => EngineError::new(ErrorCode::Crypto, format!("{e:?}")),
    }
}

pub(crate) fn jose_error(e: &tj::JoseError) -> EngineError {
    let pointer_id = |p: &str| NodeId(p.trim_start_matches('/').to_owned());
    match e {
        tj::JoseError::NoSuchClaim(p) => EngineError {
            code: ErrorCode::NodeNotFound,
            message: format!("no claim at {p}"),
            node_id: Some(pointer_id(p)),
        },
        tj::JoseError::InvalidSdPath(p) | tj::JoseError::InvalidDecoyTarget(p) | tj::JoseError::ClaimConflict(p) => EngineError {
            code: ErrorCode::InvalidInput,
            message: format!("{e:?}"),
            node_id: Some(pointer_id(p)),
        },
        tj::JoseError::NoPrivateKey => EngineError::new(ErrorCode::NoPrivateKey, "a private key is needed"),
        tj::JoseError::Crypto(c) => crypto_error(c),
        tj::JoseError::Key(k) => key_error(k),
        tj::JoseError::UnusableAlg(a) => EngineError::new(ErrorCode::UnsupportedAlg, format!("unusable alg {a:?}")),
        tj::JoseError::NoSuchDisclosure(i) => EngineError::new(ErrorCode::DisclosureIndex, format!("no disclosure {i}")),
        tj::JoseError::SaltsExhausted => EngineError::new(ErrorCode::InvalidInput, "not enough fixed salts"),
        tj::JoseError::Parse(_) | tj::JoseError::Part { .. } | tj::JoseError::NotAnObject(_) => {
            EngineError::new(ErrorCode::Parse, format!("{e:?}"))
        }
        tj::JoseError::NotSdJwt => EngineError::new(ErrorCode::UnsupportedKind, "not an SD-JWT"),
        _ => EngineError::new(ErrorCode::InvalidInput, format!("{e:?}")),
    }
}

pub(crate) fn cose_error(e: &CoseError) -> EngineError {
    match e {
        CoseError::Cbor(_) | CoseError::NotSign1 | CoseError::UnsupportedStructure { .. } | CoseError::MalformedPart(_) => {
            EngineError::new(ErrorCode::Parse, format!("{e:?}"))
        }
        CoseError::MissingAlg | CoseError::UnsupportedAlg(_) | CoseError::KeyNotSuitable { .. } => {
            EngineError::new(ErrorCode::UnsupportedAlg, format!("{e:?}"))
        }
        CoseError::NoPrivateKey => EngineError::new(ErrorCode::NoPrivateKey, "a private key is needed"),
        CoseError::Crypto(c) => crypto_error(c),
        CoseError::Key(k) => key_error(k),
        CoseError::SaltExhausted => EngineError::new(ErrorCode::InvalidInput, "not enough fixed salts"),
        CoseError::DisclosureIndex(i) => EngineError::new(ErrorCode::DisclosureIndex, format!("no disclosure {i}")),
        CoseError::NotKbt => EngineError::new(ErrorCode::UnsupportedKind, "not an SD-KBT"),
        _ => EngineError::new(ErrorCode::InvalidInput, format!("{e:?}")),
    }
}

// ---------------------------------------------------------------- signing

fn is_pss(alg: Alg) -> bool {
    matches!(alg, Alg::PS256 | Alg::PS384 | Alg::PS512)
}

/// Fails early when signing with `alg` needs randomness that is missing.
pub(crate) fn need_randomness(alg: Alg, seed: Option<&[u8; 32]>) -> Result<(), EngineError> {
    if seed.is_none() && is_pss(alg) {
        return err(ErrorCode::Randomness, "PSS signatures need randomness");
    }
    Ok(())
}

/// Signs `msg`: hedged by the seed's `purpose` stream, or deterministic
/// without one (RFC 6979 ECDSA, deterministic ML-DSA).
pub(crate) fn sign(alg: Alg, key: &Key, msg: &[u8], seed: Option<&[u8; 32]>, purpose: &str) -> Result<Vec<u8>, EngineError> {
    let Some(private) = key.private_key() else {
        return err(ErrorCode::NoPrivateKey, "a private key is needed");
    };
    match seed {
        Some(s) => tokenator_crypto::sign(alg, private, msg, &mut rng(s, purpose)),
        None => tokenator_crypto::sign_deterministic(alg, private, msg),
    }
    .map_err(|e| crypto_error(&e))
}

/// `header.payload.signature` signed again (deterministically without a seed).
pub(crate) fn resign_compact(jws: &str, alg: Alg, key: &Key, seed: Option<&[u8; 32]>, purpose: &str) -> Result<String, EngineError> {
    let input = jws.rsplit_once('.').map_or(jws, |(input, _)| input);
    let sig = sign(alg, key, input.as_bytes(), seed, purpose)?;
    Ok(format!("{input}.{}", b64u(&sig)))
}

// ---------------------------------------------------------------- helpers

/// A JSON tree that owns its data (for `tokenator-jose` options).
pub(crate) fn owned_json(node: &JNode<'_>) -> JNode<'static> {
    JNode::new(match node.value() {
        JValue::Null => JValue::Null,
        JValue::Bool(b) => JValue::Bool(*b),
        JValue::Number(n) => JValue::Number(Cow::Owned(n.to_string())),
        JValue::String(s) => JValue::String(Cow::Owned(s.to_string())),
        JValue::Array(items) => JValue::Array(items.iter().map(owned_json).collect()),
        JValue::Object(members) => JValue::Object(
            members
                .iter()
                .map(|m| Member::new(m.key().to_string(), owned_json(m.value())))
                .collect(),
        ),
    })
}

/// Parses a JSON value given as text.
pub(crate) fn json_value(text: &str) -> Result<JNode<'static>, EngineError> {
    tokenator_json::parse(text.as_bytes())
        .map(|n| owned_json(&n))
        .map_err(|e| EngineError::new(ErrorCode::Parse, format!("JSON: {e}")))
}

/// Parses an EDN item given as text.
pub(crate) fn edn_value(text: &str) -> Result<Item<'static>, EngineError> {
    tokenator_edn::parse(text).map_err(|e| EngineError::new(ErrorCode::Parse, format!("EDN: {e:?}")))
}

fn kid_text(kid: &KidValue) -> String {
    match kid {
        KidValue::Text { value } => value.clone(),
        KidValue::Bytes { value } => match std::str::from_utf8(value) {
            Ok(t) => t.to_owned(),
            Err(_) => b64u(value),
        },
    }
}

fn kid_bytes(kid: &KidValue) -> Vec<u8> {
    match kid {
        KidValue::Text { value } => value.as_bytes().to_vec(),
        KidValue::Bytes { value } => value.0.clone(),
    }
}

/// Renders an action's result; the kind comes from the bytes.
pub(crate) fn result_doc(registry: &Registry, family: Family, bytes: &[u8], view_opts: &ViewOptions) -> Result<Document, EngineError> {
    let probe = match family {
        Family::Jose => Kind::SdJwt { kb: false },
        Family::Cose => Kind::SdKbt,
    };
    view::document(registry, &probe, bytes, Vec::new(), view_opts)
}

fn entries_of(text: Option<&String>) -> Result<Vec<(Item<'static>, Item<'static>)>, EngineError> {
    let Some(text) = text else { return Ok(Vec::new()) };
    match edn_value(text)?.value {
        Value::Map(m) => Ok(m),
        _ => err(ErrorCode::InvalidInput, "header extras must be an EDN map"),
    }
}

// ---------------------------------------------------------------- issue

fn marked(req: &IssueRequest) -> Result<bool, EngineError> {
    Ok(match req.claims.kind {
        Kind::JsonClaims => !req.sd.marks.is_empty() || req.sd.decoys.iter().any(|d| d.count > 0),
        Kind::EdnClaims | Kind::CborClaims => crate::cbor::has_sd_tags(&cose_claims(req)?),
        _ => false,
    })
}

pub(crate) fn redact(registry: &Registry, req: &IssueRequest) -> Result<Document, EngineError> {
    if !req.claims.kind.is_claims() {
        return err(ErrorCode::UnsupportedKind, "issue takes a claim set");
    }
    if !marked(req)? {
        return err(ErrorCode::NothingToRedact, "no claim is marked");
    }
    issue(registry, req)
}

pub(crate) fn issue(registry: &Registry, req: &IssueRequest) -> Result<Document, EngineError> {
    let seed = seed32(req.randomness.as_ref())?;
    match req.claims.kind {
        Kind::JsonClaims => issue_jose(registry, req, seed.as_ref()),
        Kind::EdnClaims | Kind::CborClaims => issue_cose(registry, req, seed.as_ref()),
        _ => err(ErrorCode::UnsupportedKind, format!("issue takes a claim set, not a {}", req.claims.kind.label())),
    }
}

#[allow(clippy::too_many_lines)]
fn issue_jose(registry: &Registry, req: &IssueRequest, seed: Option<&[u8; 32]>) -> Result<Document, EngineError> {
    let key = resolve_private(&req.issuer)?;
    let alg = signing_alg(&key, req.alg.as_deref())?;
    need_randomness(alg, seed)?;
    let claims = tokenator_json::parse(&req.claims.bytes).map_err(|e| EngineError::new(ErrorCode::Parse, format!("JSON: {e}")))?;
    if claims.members().is_none() {
        return err(ErrorCode::InvalidInput, "the claim set must be a JSON object");
    }
    let mut pointers = Vec::with_capacity(req.sd.marks.len());
    for m in &req.sd.marks {
        let p = m.to_json_pointer();
        if p.is_empty() || claims.pointer(&p).is_none() {
            return Err(EngineError {
                code: ErrorCode::NodeNotFound,
                message: format!("no claim {m}"),
                node_id: Some(m.clone()),
            });
        }
        pointers.push(p);
    }
    let decoys: Vec<tj::DecoySpec> = req
        .sd
        .decoys
        .iter()
        .filter(|d| d.count > 0)
        .map(|d| tj::DecoySpec {
            at: d.at.to_json_pointer(),
            digests: tj::DecoyDigests::Random(usize::try_from(d.count).unwrap_or(0)),
        })
        .collect();
    let fixed = !req.sd.fixed_salts.is_empty();
    if seed.is_none() && ((!pointers.is_empty() && !fixed) || !decoys.is_empty()) {
        return err(ErrorCode::Randomness, "salts and decoys need randomness or fixed salts");
    }
    let mut extra_header = Vec::new();
    if let Some(text) = &req.header.extra {
        let node = json_value(text)?;
        let Some(members) = node.members() else {
            return err(ErrorCode::InvalidInput, "header extras must be a JSON object");
        };
        for m in members {
            extra_header.push((m.key().to_string(), owned_json(m.value())));
        }
    }
    let cnf = match &req.cnf {
        None => None,
        Some(CnfChoice::Key { key }) => {
            let holder = tokenator_keys::to_public(&resolve(key)?);
            Some(tj::Cnf::Jwk(tokenator_keys::to_jwk(&holder, tokenator_keys::Visibility::Public).map_err(|e| key_error(&e))?))
        }
        Some(CnfChoice::Kid { kid }) => Some(tj::Cnf::Kid(kid_text(kid))),
    };
    let mut opts = tj::IssueOptions::new(&key, alg);
    opts.typ = match &req.header.typ {
        TypChoice::Auto | TypChoice::Omit => None,
        TypChoice::Value { value } => Some(value.clone()),
    };
    opts.kid = match &req.header.kid {
        KidChoice::None => None,
        KidChoice::FromKey => jose_kid(&key),
        KidChoice::Value { kid } => Some(kid_text(kid)),
    };
    opts.x5c.clone_from(&req.header.x5c);
    opts.extra_header = extra_header;
    opts.cnf = cnf;
    opts.sd = pointers;
    opts.decoys = decoys;
    opts.sd_alg = req.sd.sd_alg.map(hash_alg);
    opts.digest_order = match req.sd.digest_order {
        DigestOrder::Sorted => tj::DigestOrder::Sorted,
        DigestOrder::Creation => tj::DigestOrder::Creation,
    };
    opts.salts = if fixed {
        tj::SaltSource::Fixed(req.sd.fixed_salts.clone())
    } else {
        tj::SaltSource::Random
    };
    let issued = match seed {
        Some(s) => tj::issue(&claims, &opts, &mut rng(s, "issue")),
        None => tj::issue(&claims, &opts, &mut unused_rng()),
    }
    .map_err(|e| jose_error(&e))?;
    let mut token = issued.token;
    if seed.is_none() {
        // Deterministic signature (RFC 6979 / deterministic ML-DSA).
        let (jwt, rest) = match token.find('~') {
            Some(i) => token.split_at(i),
            None => (token.as_str(), ""),
        };
        token = format!("{}{rest}", resign_compact(jwt, alg, &key, None, "issue")?);
    }
    if req.sd.force_sd && !token.contains('~') {
        token.push('~');
    }
    let text = match req.jose_serialization {
        JoseSerialization::Compact => token,
        form => to_json_text(&token, form)?,
    };
    result_doc(registry, Family::Jose, text.as_bytes(), &req.view)
}

/// Converts a token to a JOSE serialization.
pub(crate) fn to_json_text(token: &str, form: JoseSerialization) -> Result<String, EngineError> {
    let out = tj::parse(token)
        .map_err(|e| EngineError::new(ErrorCode::Parse, format!("{e:?}")))
        .and_then(|p| {
            let r = match form {
                JoseSerialization::Compact => tj::to_compact(&p.token, 0).map(|c| c.text),
                JoseSerialization::JsonFlattened => tj::to_json(&p.token, tj::JsonSerialization::Flattened),
                JoseSerialization::JsonGeneral => tj::to_json(&p.token, tj::JsonSerialization::General),
            };
            r.map_err(|e| jose_error(&e))
        })?;
    Ok(out)
}

fn cose_claims(req: &IssueRequest) -> Result<Item<'static>, EngineError> {
    match req.claims.kind {
        Kind::EdnClaims => {
            let text = std::str::from_utf8(&req.claims.bytes).map_err(|_| EngineError::new(ErrorCode::Parse, "EDN is not UTF-8"))?;
            edn_value(text)
        }
        _ => tokenator_cbor::decode(&req.claims.bytes)
            .map(Item::into_owned)
            .map_err(|e| EngineError::new(ErrorCode::Parse, format!("not CBOR: {e:?}"))),
    }
}

fn content_type(text: &str) -> ContentType {
    match text.parse::<u64>() {
        Ok(n) => ContentType::Uint(n),
        Err(_) => ContentType::Text(text.to_owned()),
    }
}

#[allow(clippy::too_many_lines)]
fn issue_cose(registry: &Registry, req: &IssueRequest, seed: Option<&[u8; 32]>) -> Result<Document, EngineError> {
    let key = resolve_private(&req.issuer)?;
    let alg = signing_alg(&key, req.alg.as_deref())?;
    need_randomness(alg, seed)?;
    let mut claims = cose_claims(req)?;
    if !req.sd.marks.is_empty() {
        return err(ErrorCode::InvalidInput, "mark COSE claims with tags 58/62 in the EDN");
    }
    let Value::Map(entries) = &mut claims.value else {
        return err(ErrorCode::InvalidInput, "the claim set must be a CBOR map");
    };
    if let Some(cnf) = &req.cnf {
        if entries.iter().any(|(k, _)| crate::cbor::int_of(k) == Some(8)) {
            return err(ErrorCode::InvalidInput, "the claims already have a cnf (8)");
        }
        let method = match cnf {
            CnfChoice::Key { key } => {
                let holder = tokenator_keys::to_public(&resolve(key)?);
                let cwk = tokenator_keys::to_cwk(&holder, tokenator_keys::Visibility::Public).map_err(|e| key_error(&e))?;
                (Item::int(1), cwk.item().clone())
            }
            CnfChoice::Kid { kid } => (Item::int(3), Item::bytes(kid_bytes(kid))),
        };
        entries.push((Item::int(8), Item::map(vec![method])));
    }
    let sd = crate::cbor::has_sd_tags(&claims);
    let fixed: Option<Vec<Vec<u8>>> = if req.sd.fixed_salts.is_empty() {
        None
    } else {
        Some(
            req.sd
                .fixed_salts
                .iter()
                .map(|s| unhex(s).ok_or_else(|| EngineError::new(ErrorCode::InvalidInput, format!("salt {s:?} is not hex"))))
                .collect::<Result<_, _>>()?,
        )
    };
    if sd && fixed.is_none() && seed.is_none() {
        return err(ErrorCode::Randomness, "salts need randomness or fixed salts");
    }
    let mut protected_extra = entries_of(req.header.extra.as_ref())?;
    if !req.header.x5c.is_empty() {
        let certs: Vec<Item<'static>> = req
            .header
            .x5c
            .iter()
            .map(|c| Base64::decode_vec(c).map(Item::bytes).map_err(|_| EngineError::new(ErrorCode::InvalidInput, "x5c is not base64")))
            .collect::<Result<_, _>>()?;
        let value = match <[Item<'static>; 1]>::try_from(certs) {
            Ok([one]) => one,
            Err(many) => Item::array(many),
        };
        protected_extra.push((Item::int(33), value));
    }
    let opts = CoseIssue {
        alg,
        kid: match &req.header.kid {
            KidChoice::None => None,
            KidChoice::FromKey => key.kid.as_ref().map(|k| Cow::Owned(k.as_bytes().to_vec())),
            KidChoice::Value { kid } => Some(Cow::Owned(kid_bytes(kid))),
        },
        typ: match &req.header.typ {
            TypChoice::Auto => Typ::Auto,
            TypChoice::Omit => Typ::Omit,
            TypChoice::Value { value } => Typ::Value(content_type(value)),
        },
        sd_alg: Some(req.sd.sd_alg.map_or(tokenator_crypto::HashAlg::Sha256, hash_alg)),
        force_sd: req.sd.force_sd,
        tags: req.cose_tags.clone().unwrap_or_else(|| vec![tokenator_cose::codepoints::TAG_COSE_SIGN1]),
        protected_extra,
        unprotected_extra: entries_of(req.header.unprotected_extra.as_ref())?,
        external_aad: Cow::Borrowed(&[]),
    };
    let mut salt_rng = seed.map(|s| rng(s, "salts"));
    let mut fixed_salts = FixedSalts::new(fixed.unwrap_or_default());
    let mut rng_salts;
    let salts: &mut dyn SaltSource = match (&mut salt_rng, req.sd.fixed_salts.is_empty()) {
        (Some(r), true) => {
            rng_salts = RngSalts::new(r);
            &mut rng_salts
        }
        _ => &mut fixed_salts,
    };
    let mut sign_rng = seed.map(|s| rng(s, "sign"));
    let issued = tokenator_cose::sd::issue(
        &CborBackend,
        &claims,
        &key,
        &opts,
        salts,
        sign_rng.as_mut().map(|r| r as &mut dyn tokenator_cose::CryptoRng),
    )
    .map_err(|e| cose_error(&e))?;
    result_doc(registry, Family::Cose, &issued.bytes, &req.view)
}

// ---------------------------------------------------------------- disclose / present

fn indices(keep: &[u32]) -> Vec<usize> {
    keep.iter().map(|&i| usize::try_from(i).unwrap_or(usize::MAX)).collect()
}

pub(crate) fn disclose(registry: &Registry, req: &DiscloseRequest) -> Result<Document, EngineError> {
    let keep = indices(&req.keep);
    match req.doc.kind {
        Kind::SdJwt { .. } | Kind::SdJwtJson { .. } => {
            let text = std::str::from_utf8(&req.doc.bytes).map_err(|_| EngineError::new(ErrorCode::Parse, "not UTF-8"))?;
            let out = with_parsed(text, |parsed, _| -> Result<String, EngineError> {
                let sd = parsed.token.sd_jwt().ok_or_else(|| EngineError::new(ErrorCode::UnsupportedKind, "not an SD-JWT"))?;
                check_indices(&keep, sd.disclosures.len())?;
                tj::present(sd, &keep, None, &mut unused_rng()).map(|p| p.token).map_err(|e| jose_error(&e))
            })
            .map_err(|e| EngineError::new(ErrorCode::Parse, format!("{e:?}")))??;
            result_doc(registry, Family::Jose, out.as_bytes(), &req.view)
        }
        Kind::SdCwt | Kind::SdKbt => {
            let out = tokenator_cose::kbt::disclose(&CborBackend, &req.doc.bytes, &Selection::Indices(keep)).map_err(|e| cose_error(&e))?;
            result_doc(registry, Family::Cose, &out, &req.view)
        }
        _ => err(ErrorCode::UnsupportedKind, format!("cannot disclose from a {}", req.doc.kind.label())),
    }
}

fn check_indices(keep: &[usize], len: usize) -> Result<(), EngineError> {
    match keep.iter().find(|&&i| i >= len) {
        Some(i) => err(ErrorCode::DisclosureIndex, format!("no disclosure {i} ({len} present)")),
        None => Ok(()),
    }
}

/// Re-signs the KB-JWT of a presentation deterministically.
fn resign_kb(token: &str, alg: Alg, key: &Key) -> Result<String, EngineError> {
    if !token.trim_start().starts_with('{') {
        let (prefix, kb) = token.rsplit_once('~').unwrap_or(("", token));
        return Ok(format!("{prefix}~{}", resign_compact(kb, alg, key, None, "present")?));
    }
    let root = tokenator_json::parse(token.as_bytes()).map_err(|e| EngineError::new(ErrorCode::Parse, format!("{e}")))?;
    let header = root
        .get("header")
        .or_else(|| root.get("signatures").and_then(|s| s.index(0)).and_then(|s| s.get("header")));
    let Some(kb_node) = header.and_then(|h| h.get("kb_jwt")) else {
        return Ok(token.to_owned());
    };
    let (JValue::String(kb), Some(span)) = (kb_node.value(), kb_node.span()) else {
        return Ok(token.to_owned());
    };
    let new = crate::util::json_string(&resign_compact(kb, alg, key, None, "present")?);
    let (before, after) = (token.get(..span.start).unwrap_or(""), token.get(span.end..).unwrap_or(""));
    Ok(format!("{before}{new}{after}"))
}

pub(crate) fn present(registry: &Registry, req: &PresentRequest) -> Result<Document, EngineError> {
    let seed = seed32(req.randomness.as_ref())?;
    let keep = indices(&req.keep);
    match req.doc.kind {
        Kind::SdJwt { kb: false } | Kind::SdJwtJson { kb: false, .. } => {}
        Kind::SdJwt { kb: true } | Kind::SdJwtJson { kb: true, .. } | Kind::SdKbt => {
            return err(ErrorCode::UnsupportedKind, "this is already a presentation");
        }
        Kind::SdCwt | Kind::Cwt => {}
        _ => return err(ErrorCode::UnsupportedKind, format!("cannot present a {}", req.doc.kind.label())),
    }
    let key = resolve_private(&req.holder)?;
    let alg = signing_alg(&key, req.alg.as_deref())?;
    need_randomness(alg, seed.as_ref())?;
    if req.doc.kind.family() == Some(Family::Jose) {
        let nonce = match &req.nonce {
            Some(Nonce::Text { value }) => value.clone(),
            Some(Nonce::Bytes { .. }) => return err(ErrorCode::InvalidInput, "a KB-JWT nonce is text"),
            None => return err(ErrorCode::InvalidInput, "a KB-JWT needs a nonce"),
        };
        let Some(aud) = req.aud.as_deref() else {
            return err(ErrorCode::InvalidInput, "a KB-JWT needs an aud");
        };
        let text = std::str::from_utf8(&req.doc.bytes).map_err(|_| EngineError::new(ErrorCode::Parse, "not UTF-8"))?;
        let token = with_parsed(text, |parsed, _| -> Result<String, EngineError> {
            let sd = parsed.token.sd_jwt().ok_or_else(|| EngineError::new(ErrorCode::UnsupportedKind, "not an SD-JWT"))?;
            check_indices(&keep, sd.disclosures.len())?;
            let kb = tj::KbOptions::new(&key, alg, aud, &nonce, req.iat);
            let presented = match &seed {
                Some(s) => tj::present(sd, &keep, Some(&kb), &mut rng(s, "present")),
                None => tj::present(sd, &keep, Some(&kb), &mut unused_rng()),
            };
            presented.map(|p| p.token).map_err(|e| jose_error(&e))
        })
        .map_err(|e| EngineError::new(ErrorCode::Parse, format!("{e:?}")))??;
        let token = if seed.is_none() { resign_kb(&token, alg, &key)? } else { token };
        return result_doc(registry, Family::Jose, token.as_bytes(), &req.view);
    }
    let selection = if req.doc.kind == Kind::Cwt {
        if !keep.is_empty() {
            return err(ErrorCode::DisclosureIndex, "a CWT has no disclosures");
        }
        Selection::All
    } else {
        Selection::Indices(keep)
    };
    let cnonce = req.nonce.as_ref().map(|n| match n {
        Nonce::Text { value } => value.as_bytes().to_vec(),
        Nonce::Bytes { value } => value.0.clone(),
    });
    let opts = PresentOptions {
        selection,
        aud: req.aud.as_deref().map(Cow::Borrowed),
        iat: Some(req.iat),
        cnonce: cnonce.map(Cow::Owned),
        ..PresentOptions::new(alg)
    };
    let mut sign_rng = seed.as_ref().map(|s| rng(s, "present"));
    let out = tokenator_cose::kbt::present(
        &CborBackend,
        &req.doc.bytes,
        &key,
        &opts,
        sign_rng.as_mut().map(|r| r as &mut dyn tokenator_cose::CryptoRng),
    )
    .map_err(|e| cose_error(&e))?;
    result_doc(registry, Family::Cose, &out, &req.view)
}
