//! Validation (SPEC §6) and the conformance lint.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use tokenator_cbor::{FindingKind as CborFinding, Item};
use tokenator_cose::claims::{Cnf, NumericDate, TimeOptions, TimeStatus as CoseTime, check_times};
use tokenator_cose::kbt::{KbtFinding, KbtOptions, verify_kbt};
use tokenator_cose::lint::{FindingKind as CoseLint, LintOptions, Severity as CoseSeverity};
use tokenator_cose::sd::SdAlg as CoseSdAlg;
use tokenator_cose::{CborBackend, CoseError, Sign1, Sign1Backend, VerifyOptions};
use tokenator_crypto::{Alg, DeclaredAlg, alg_to_jose};
use tokenator_jose as tj;
use tokenator_json::{Node as JNode, ParseOptions, Value as JValue};
use tokenator_keys::Key;
use tokenator_registry::Registry;

use crate::dto::actions::{LintRequest, ValidateRequest};
use crate::dto::common::{ByteRange, NodeId, Nonce};
use crate::dto::detect::{Family, Kind};
use crate::dto::document::{DisclosureStatus, Node, SdMark, ViewOptions};
use crate::dto::error::{EngineError, ErrorCode};
use crate::dto::keys::KeyRef;
use crate::dto::report::{
    Category, CheckDetail, CheckItem, FetchHint, FetchKind, KeySelection, Status, ValidationReport,
};
use crate::keyring::{fits, resolve, thumbprints};
use crate::util::{err, hex, u32_of};
use crate::view::jose::{part_ref_id, with_parsed};
use crate::view::{Built, innermost, json_id_at, json_warning, kcwt_id, nodes};

fn check(id: &str, category: Category, status: Status, message: impl Into<String>, node_ids: Vec<NodeId>) -> CheckItem {
    CheckItem {
        id: id.to_owned(),
        category,
        status,
        message: message.into(),
        node_ids,
        raw: None,
        detail: None,
    }
}

fn lint_item(id: &str, status: Status, message: impl Into<String>, node_ids: Vec<NodeId>) -> CheckItem {
    check(id, Category::Lint, status, message, node_ids)
}

fn nid(s: &str) -> NodeId {
    NodeId(s.to_owned())
}

/// Resolves every panel key (a broken key is an error).
fn resolve_all(refs: &[KeyRef]) -> Result<Vec<Key>, EngineError> {
    refs.iter().map(resolve).collect()
}

/// The outcome of choosing and trying keys for one signature.
struct Selected {
    status: Status,
    selection: KeySelection,
    index: Option<usize>,
    message: String,
}

/// SPEC §6 key selection over the panel keys: kid match, thumbprint match,
/// then every key that fits the alg. Keys tried and none verifies is a
/// failure; nothing to try is a skip.
fn select(keys: &[Key], refs: &[KeyRef], alg: Alg, kid: Option<&[u8]>, verify: &dyn Fn(&Key) -> bool) -> Selected {
    let fitting: Vec<usize> = (0..keys.len())
        .filter(|&i| keys.get(i).is_some_and(|k| fits(k, alg)))
        .collect();
    let label = |i: usize| {
        refs.get(i)
            .and_then(|r| r.label.clone())
            .unwrap_or_else(|| format!("key {i}"))
    };
    let by_kid: Vec<usize> = match kid {
        Some(kid) => fitting
            .iter()
            .copied()
            .filter(|&i| keys.get(i).and_then(|k| k.kid.as_ref()).is_some_and(|k| k.as_bytes() == kid))
            .collect(),
        None => Vec::new(),
    };
    let by_tp: Vec<usize> = match kid {
        Some(kid) if by_kid.is_empty() => fitting
            .iter()
            .copied()
            .filter(|&i| {
                keys.get(i).is_some_and(|k| {
                    let (jwk, cose) = thumbprints(k);
                    kid == jwk.as_bytes() || kid == cose.as_slice() || kid == hex(&cose).as_bytes()
                })
            })
            .collect(),
        _ => Vec::new(),
    };
    let (tried, selection) = if !by_kid.is_empty() {
        (by_kid, KeySelection::PanelKid)
    } else if !by_tp.is_empty() {
        (by_tp, KeySelection::PanelThumbprint)
    } else {
        (fitting, KeySelection::PanelUnmatched)
    };
    if tried.is_empty() {
        return Selected {
            status: Status::Skip,
            selection: KeySelection::None,
            index: None,
            message: format!("no key for {}", alg_to_jose(alg)),
        };
    }
    for &i in &tried {
        if keys.get(i).is_some_and(verify) {
            return Selected {
                status: Status::Pass,
                selection,
                index: Some(i),
                message: format!("{} signature verified with {}", alg_to_jose(alg), label(i)),
            };
        }
    }
    Selected {
        status: Status::Fail,
        selection,
        index: if tried.len() == 1 { tried.first().copied() } else { None },
        message: format!("{} signature does not verify with {} key(s) tried", alg_to_jose(alg), tried.len()),
    }
}

fn signature_item(id: &str, category: Category, sel: &Selected, alg: Option<Alg>, refs: &[KeyRef], untrusted: bool, node_ids: Vec<NodeId>) -> CheckItem {
    CheckItem {
        detail: Some(CheckDetail::Signature {
            alg: alg.map(|a| alg_to_jose(a).to_owned()),
            key_index: sel.index.map(u32_of),
            key_label: sel.index.and_then(|i| refs.get(i)).and_then(|r| r.label.clone()),
            selection: sel.selection,
            untrusted,
        }),
        ..check(id, category, sel.status, sel.message.clone(), node_ids)
    }
}

fn plain_signature_item(status: Status, message: impl Into<String>, alg: Option<String>, node_ids: Vec<NodeId>) -> CheckItem {
    CheckItem {
        detail: Some(CheckDetail::Signature {
            alg,
            key_index: None,
            key_label: None,
            selection: KeySelection::None,
            untrusted: false,
        }),
        ..check("signature", Category::Signature, status, message, node_ids)
    }
}

fn is_url(s: &str) -> bool {
    s.starts_with("https://") || s.starts_with("http://")
}

fn kid_hint(kid: &[u8]) -> Option<FetchHint> {
    let text = std::str::from_utf8(kid).ok().filter(|t| is_url(t))?;
    Some(FetchHint {
        kind: FetchKind::KidUrl,
        url: text.to_owned(),
        reason: "the header kid is a URL".to_owned(),
    })
}

/// SD-JWT VC issuer metadata for an https `iss`.
fn issuer_hint(iss: &str) -> Option<FetchHint> {
    let rest = iss.strip_prefix("https://")?;
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let path = path.trim_end_matches('/');
    let url = if path.is_empty() {
        format!("https://{host}/.well-known/jwt-vc-issuer")
    } else {
        format!("https://{host}/.well-known/jwt-vc-issuer/{path}")
    };
    Some(FetchHint {
        kind: FetchKind::IssuerMetadata,
        url,
        reason: "SD-JWT VC issuer metadata for the iss".to_owned(),
    })
}

fn time_item(claim: &str, status: Status, value: i64, req: &ValidateRequest, node: NodeId, message: String) -> CheckItem {
    CheckItem {
        detail: Some(CheckDetail::Time {
            claim: claim.to_owned(),
            value,
            now: req.now,
            skew: req.skew,
        }),
        ..check(&format!("time.{claim}"), Category::Time, status, message, vec![node])
    }
}

fn floor(f: f64) -> i64 {
    // Saturating float to int conversion.
    #[allow(clippy::cast_possible_truncation)]
    let n = f.floor() as i64;
    n
}

// ---------------------------------------------------------------- SD

/// SD items from the rendered document (both families).
fn sd_items(built: &Built, sd_alg: (Status, String, NodeId), out: &mut Vec<CheckItem>) {
    out.push(check("sd.sd_alg", Category::Sd, sd_alg.0, sd_alg.1, vec![sd_alg.2]));
    let all_matched = built.disclosures.iter().all(|d| d.status == DisclosureStatus::Matched);
    out.push(check(
        "sd.match",
        Category::Sd,
        if all_matched { Status::Pass } else { Status::Fail },
        if all_matched {
            format!("{} disclosure(s), each matching exactly one digest", built.disclosures.len())
        } else {
            "some disclosures do not match exactly one digest".to_owned()
        },
        built.disclosures.iter().map(|d| d.node_id.clone()).collect(),
    ));
    for d in &built.disclosures {
        let (id, what) = match d.status {
            DisclosureStatus::Matched => continue,
            DisclosureStatus::Unmatched => ("sd.unmatched", "matches no digest"),
            DisclosureStatus::Duplicate => ("sd.duplicate_disclosure", "repeats an earlier disclosure"),
            DisclosureStatus::Malformed => ("sd.malformed", "is malformed"),
            DisclosureStatus::ForbiddenName => ("sd.forbidden_name", "has a forbidden claim name"),
            DisclosureStatus::KindMismatch => ("sd.kind_mismatch", "is in the wrong kind of slot"),
            DisclosureStatus::NameCollision => ("sd.name_collision", "collides with an existing claim"),
        };
        let mut ids = vec![d.node_id.clone()];
        ids.extend(d.slot.clone());
        out.push(check(id, Category::Sd, Status::Fail, format!("disclosure {} {what}", d.index), ids));
    }
    // Duplicate digests: the same digest in more than one slot.
    let mut slots: BTreeMap<String, Vec<NodeId>> = BTreeMap::new();
    for n in nodes(&built.tree) {
        if let Some(SdMark::Slot { digest, .. }) = &n.sd {
            slots.entry(digest.clone()).or_default().push(n.id.clone());
        }
    }
    let mut dups: Vec<(String, Vec<NodeId>)> = slots.into_iter().filter(|(_, v)| v.len() > 1).collect();
    dups.sort_by(|a, b| a.1.first().cmp(&b.1.first()));
    for (digest, ids) in dups {
        out.push(check("sd.duplicate_digest", Category::Sd, Status::Fail, format!("digest {digest} appears {} times", ids.len()), ids));
    }
    for s in &built.undisclosed {
        out.push(check(
            "sd.undisclosed",
            Category::Sd,
            Status::Info,
            "digest without a disclosure (a decoy or a withheld claim)",
            vec![s.node_id.clone()],
        ));
    }
}

// ---------------------------------------------------------------- JOSE

fn jose_numeric(claims: &JNode<'_>, name: &str) -> Option<i64> {
    match claims.get(name)?.value() {
        JValue::Number(n) => n.parse::<f64>().ok().filter(|f| f.is_finite()).map(floor),
        _ => None,
    }
}

fn header_kid(sig: &tj::JwsSignature<'_>) -> Option<String> {
    let from = |n: &JNode<'_>| match n.get("kid")?.value() {
        JValue::String(s) => Some(s.to_string()),
        _ => None,
    };
    sig.protected
        .as_ref()
        .and_then(|p| p.json().ok())
        .and_then(|h| from(&h))
        .or_else(|| sig.unprotected.as_ref().and_then(from))
}

fn header_alg(sig: &tj::JwsSignature<'_>) -> tj::AlgFact {
    let from = |n: &JNode<'_>| n.get("alg").is_some().then(|| tj::header_facts(n).alg);
    sig.protected
        .as_ref()
        .and_then(|p| p.json().ok())
        .and_then(|h| from(&h))
        .or_else(|| sig.unprotected.as_ref().and_then(from))
        .unwrap_or(tj::AlgFact::Missing)
}

struct Report {
    items: Vec<CheckItem>,
    fetchable: Vec<FetchHint>,
    /// The key that verified the issuer signature (for the alg/key lint).
    verifier: Option<usize>,
}

#[allow(clippy::too_many_lines)]
fn validate_jose(req: &ValidateRequest, keys: &[Key], built: &Built, text: &str) -> Result<Report, EngineError> {
    let nonce = match &req.expected_nonce {
        None => None,
        Some(Nonce::Text { value }) => Some(value.clone()),
        Some(Nonce::Bytes { .. }) => return err(ErrorCode::InvalidInput, "a KB-JWT nonce is text"),
    };
    with_parsed(text, |parsed, _| {
        let token = &parsed.token;
        let jws = token.jws();
        let general = jws.serialization == tj::Serialization::JsonGeneral;
        let mut r = Report {
            items: Vec::new(),
            fetchable: Vec::new(),
            verifier: None,
        };
        let mut skipped_kid = None;
        for (i, sig) in jws.signatures.iter().enumerate() {
            let sig_node = part_ref_id(tj::PartRef::Signature(i), general);
            let ids = vec![sig_node, part_ref_id(tj::PartRef::ProtectedHeader(i), general)];
            let item = match header_alg(sig) {
                tj::AlgFact::None => plain_signature_item(Status::Fail, "alg is none: the token is unsecured", Some("none".to_owned()), ids),
                tj::AlgFact::Missing | tj::AlgFact::NotAString => plain_signature_item(Status::Fail, "no usable alg in the header", None, ids),
                tj::AlgFact::Unsupported(name) => plain_signature_item(Status::Skip, format!("{name} is not supported"), Some(name), ids),
                tj::AlgFact::Known(alg) => {
                    let kid = header_kid(sig);
                    let verify = |k: &Key| tj::verify_signature(jws, i, k).is_ok();
                    let sel = select(keys, &req.keys, alg, kid.as_deref().map(str::as_bytes), &verify);
                    if sel.status == Status::Skip {
                        skipped_kid = skipped_kid.or(kid);
                    }
                    if i == 0 && sel.status == Status::Pass {
                        r.verifier = sel.index;
                    }
                    signature_item("signature", Category::Signature, &sel, Some(alg), &req.keys, false, ids)
                }
            };
            let skip = item.status == Status::Skip;
            r.items.push(item);
            if skip && i == 0 {
                if let Some(h) = skipped_kid.as_deref().and_then(|k| kid_hint(k.as_bytes())) {
                    r.fetchable.push(h);
                }
                if token.sd_jwt().is_some()
                    && let Ok(claims) = jws.claims()
                    && let Some(JValue::String(iss)) = claims.get("iss").map(JNode::value)
                    && let Some(h) = issuer_hint(iss)
                {
                    r.fetchable.push(h);
                }
            }
        }
        // Time claims of the issuer payload.
        if let Ok(claims) = jws.claims() {
            let t = tj::check_time_claims(&claims, req.now, req.skew);
            for (name, st) in [("exp", t.exp), ("nbf", t.nbf), ("iat", t.iat)] {
                let (status, what) = match st {
                    tj::TimeStatus::Absent => continue,
                    tj::TimeStatus::Valid => (Status::Pass, "valid"),
                    tj::TimeStatus::Expired => (Status::Fail, "expired"),
                    tj::TimeStatus::NotYetValid => (Status::Fail, "not yet valid"),
                    tj::TimeStatus::InFuture => (Status::Warn, "in the future"),
                    tj::TimeStatus::TooOld => (Status::Fail, "too old"),
                    tj::TimeStatus::NotANumber => (Status::Fail, "not a number"),
                };
                let node = nid("payload/~e").child(name);
                let value = jose_numeric(&claims, name).unwrap_or_default();
                r.items.push(time_item(name, status, value, req, node, format!("{name} {what}")));
            }
        }
        if let Some(sd) = token.sd_jwt() {
            let alg = jws.claims().map(|c| tj::sd_alg(&c)).unwrap_or(tj::SdAlg::Default);
            let st = match &alg {
                tj::SdAlg::Default => (Status::Pass, "_sd_alg absent: sha-256".to_owned()),
                tj::SdAlg::Named(h) => (Status::Pass, format!("_sd_alg {}", h.name())),
                tj::SdAlg::Unsupported(s) => (Status::Fail, format!("_sd_alg {s} is not supported")),
                tj::SdAlg::NotAString => (Status::Fail, "_sd_alg is not a string".to_owned()),
            };
            sd_items(built, (st.0, st.1, nid("payload/~e/_sd_alg")), &mut r.items);
            match &sd.kb_jwt {
                None => r.items.push(missing_kb(req, true)),
                Some(_) => {
                    let expect = tj::KbExpectations {
                        aud: req.expected_aud.as_deref(),
                        nonce: nonce.as_deref(),
                        now: req.now,
                        skew: req.skew,
                        max_age: req.max_kb_age,
                    };
                    if let Some(mut kb) = tj::check_kb_jwt(sd, keys, &expect) {
                        // `max_kb_age` without skew, as tokenator-cose
                        // checks the SD-KBT (tokenator-jose adds the skew).
                        let iat = sd.kb_jwt.as_ref().and_then(|k| k.claims().ok()).and_then(|c| jose_numeric(&c, "iat"));
                        if let (Some(max), Some(iat), tj::TimeStatus::Valid) = (req.max_kb_age, iat, kb.iat)
                            && i128::from(req.now) > i128::from(iat) + i128::from(max)
                        {
                            kb.iat = tj::TimeStatus::TooOld;
                        }
                        kb_jose_items(&kb, &req.keys, &mut r.items);
                    }
                }
            }
        } else if req.expected_aud.is_some() || req.expected_nonce.is_some() {
            r.items.push(missing_kb(req, false));
        }
        Ok(r)
    })
    .map_err(|e| EngineError::new(ErrorCode::Parse, format!("not a JOSE token: {e}")))?
}

fn missing_kb(req: &ValidateRequest, sd: bool) -> CheckItem {
    if req.expected_aud.is_some() || req.expected_nonce.is_some() {
        check("kb", Category::KeyBinding, Status::Fail, "key binding was expected but there is none", vec![NodeId::root()])
    } else if sd {
        check("kb", Category::KeyBinding, Status::Skip, "no key binding", vec![NodeId::root()])
    } else {
        check("kb", Category::KeyBinding, Status::Skip, "no key binding", vec![NodeId::root()])
    }
}

fn value_status(v: &tj::ValueCheck) -> (Status, String) {
    match v {
        tj::ValueCheck::Match => (Status::Pass, "as expected".to_owned()),
        tj::ValueCheck::Mismatch { expected, found } => (Status::Fail, format!("{found:?}, expected {expected:?}")),
        tj::ValueCheck::Unchecked(v) => (Status::Info, format!("{v:?} (not checked)")),
        tj::ValueCheck::Missing => (Status::Fail, "missing".to_owned()),
        tj::ValueCheck::NotAString => (Status::Fail, "not a string".to_owned()),
    }
}

fn kb_jose_items(kb: &tj::KbReport, refs: &[KeyRef], out: &mut Vec<CheckItem>) {
    let (selection, index, untrusted) = match &kb.holder_key {
        tj::HolderKey::CnfJwk => (KeySelection::EmbeddedCnf, None, true),
        tj::HolderKey::CnfKid { candidate, .. } => (KeySelection::PanelKid, Some(*candidate), false),
        _ => (KeySelection::None, None, false),
    };
    let (status, message, alg) = match &kb.signature {
        Ok(alg) => (Status::Pass, format!("KB-JWT signature verified ({})", alg_to_jose(*alg)), Some(*alg)),
        Err(tj::VerifyError::NoKey) => (Status::Skip, format!("no holder key ({:?})", kb.holder_key), None),
        Err(e) => (Status::Fail, format!("KB-JWT signature: {e:?}"), None),
    };
    let sel = Selected {
        status,
        selection,
        index,
        message,
    };
    out.push(signature_item("kb.signature", Category::KeyBinding, &sel, alg, refs, untrusted, vec![nid("kb/signature")]));
    for (id, v, node) in [
        ("kb.sd_hash", &kb.sd_hash, "kb/payload/~e/sd_hash"),
        ("kb.aud", &kb.aud, "kb/payload/~e/aud"),
        ("kb.nonce", &kb.nonce, "kb/payload/~e/nonce"),
    ] {
        let (status, what) = value_status(v);
        out.push(check(id, Category::KeyBinding, status, format!("{}: {what}", &id[3..]), vec![nid(node)]));
    }
    let (status, what) = match kb.iat {
        tj::TimeStatus::Valid => (Status::Pass, "fresh"),
        tj::TimeStatus::Absent => (Status::Fail, "missing"),
        tj::TimeStatus::InFuture => (Status::Fail, "in the future"),
        tj::TimeStatus::TooOld => (Status::Fail, "too old"),
        _ => (Status::Fail, "not usable"),
    };
    out.push(check("kb.iat", Category::KeyBinding, status, format!("iat {what}"), vec![nid("kb/payload/~e/iat")]));
}

// ---------------------------------------------------------------- COSE

fn cose_time_items(claims: &Item<'_>, prefix: &NodeId, req: &ValidateRequest, out: &mut Vec<CheckItem>) {
    let t = check_times(claims, &TimeOptions { now: req.now, skew: req.skew });
    for (name, label, st) in [("exp", "4", t.exp), ("nbf", "5", t.nbf), ("iat", "6", t.iat)] {
        let Some(st) = st else { continue };
        let (status, what, value) = match st {
            CoseTime::Ok(d) => (Status::Pass, "valid", Some(d)),
            CoseTime::Expired(d) => (Status::Fail, "expired", Some(d)),
            CoseTime::NotYetValid(d) => (Status::Fail, "not yet valid", Some(d)),
            CoseTime::IssuedInFuture(d) => (Status::Warn, "in the future", Some(d)),
            CoseTime::Invalid(_) => (Status::Fail, "not a NumericDate", None),
        };
        let value = value.map_or(0, |d: NumericDate| floor(d.as_f64()));
        let node = prefix.child("payload").decoded(0).child(label);
        out.push(time_item(name, status, value, req, node, format!("{name} {what}")));
    }
}

fn cose_signature(msg: &Sign1<'_>, prefix: &NodeId, keys: &[Key], refs: &[KeyRef], r: &mut Report) {
    let ids = vec![prefix.child("signature"), prefix.child("protected")];
    let item = match msg.alg() {
        None => plain_signature_item(Status::Fail, "no alg in the header", None, ids),
        Some(DeclaredAlg::Known(alg)) => {
            let kid = msg.kid().map(<[u8]>::to_vec);
            let verify = |k: &Key| CborBackend.verify(msg, k, &VerifyOptions::default()).is_ok();
            let sel = select(keys, refs, alg, kid.as_deref(), &verify);
            if sel.status == Status::Pass {
                r.verifier = sel.index;
            }
            if sel.status == Status::Skip
                && let Some(h) = kid.as_deref().and_then(kid_hint)
            {
                r.fetchable.push(h);
            }
            signature_item("signature", Category::Signature, &sel, Some(alg), refs, false, ids)
        }
        Some(DeclaredAlg::UnknownCose(l)) => plain_signature_item(Status::Skip, format!("alg {l} is not supported"), Some(l.to_string()), ids),
        Some(DeclaredAlg::UnknownJose(s)) => plain_signature_item(Status::Skip, format!("alg {s} is not supported"), Some(s), ids),
    };
    r.items.push(item);
}

fn cose_sd_alg(alg: CoseSdAlg, prefix: &NodeId) -> (Status, String, NodeId) {
    let node = prefix.child("protected").decoded(0).child("170");
    match alg {
        CoseSdAlg::Default => (Status::Pass, "sd_alg absent: SHA-256".to_owned(), node),
        CoseSdAlg::Known(h) => (Status::Pass, format!("sd_alg {}", h.name()), node),
        CoseSdAlg::Unsupported(l) => (Status::Fail, format!("sd_alg {l} is not supported"), node),
        CoseSdAlg::Invalid => (Status::Fail, "sd_alg is not an integer".to_owned(), node),
    }
}

#[allow(clippy::too_many_lines)]
fn validate_cose(req: &ValidateRequest, keys: &[Key], built: &Built, bytes: &[u8]) -> Result<Report, EngineError> {
    let parse_err = |e: CoseError| EngineError::new(ErrorCode::Parse, format!("not a COSE_Sign1: {e:?}"));
    let msg = CborBackend.parse(bytes).map_err(parse_err)?;
    let mut r = Report {
        items: Vec::new(),
        fetchable: Vec::new(),
        verifier: None,
    };
    let cnonce: Option<Vec<u8>> = req.expected_nonce.as_ref().map(|n| match n {
        Nonce::Text { value } => value.as_bytes().to_vec(),
        Nonce::Bytes { value } => value.0.clone(),
    });
    if built.kind == Kind::SdKbt {
        let opts = KbtOptions {
            now: req.now,
            skew: req.skew,
            expected_aud: req.expected_aud.as_deref().map(Cow::Borrowed),
            expected_cnonce: cnonce.as_deref().map(Cow::Borrowed),
            max_age: req.max_kb_age,
            holder_keys: keys.to_vec(),
        };
        let kbt = verify_kbt(&CborBackend, bytes, None, &opts).map_err(parse_err)?;
        let prefix = kcwt_id();
        match &kbt.sd_cwt {
            Some(inner) => {
                cose_signature(&inner.sign1, &prefix, keys, &req.keys, &mut r);
                if let Some(claims) = inner.sign1.payload_item() {
                    cose_time_items(claims, &prefix, req, &mut r.items);
                }
                sd_items(built, cose_sd_alg(inner.sd_alg, &prefix), &mut r.items);
            }
            None => r.items.push(plain_signature_item(Status::Fail, "kcwt is not a COSE_Sign1", None, vec![prefix])),
        }
        kb_cose_items(&kbt, keys, req, &mut r.items);
        return Ok(r);
    }
    let root = NodeId::root();
    cose_signature(&msg, &root, keys, &req.keys, &mut r);
    if let Some(claims) = msg.payload_item()
        && matches!(claims.value, tokenator_cbor::Value::Map(_))
    {
        cose_time_items(claims, &root, req, &mut r.items);
    }
    if built.kind == Kind::SdCwt {
        let sd = tokenator_cose::sd::SdCwt::from_sign1(msg);
        sd_items(built, cose_sd_alg(sd.sd_alg, &root), &mut r.items);
        r.items.push(missing_kb(req, true));
    } else if req.expected_aud.is_some() || req.expected_nonce.is_some() {
        r.items.push(missing_kb(req, false));
    }
    Ok(r)
}

fn kb_cose_items(kbt: &tokenator_cose::kbt::KbtReport<'_>, keys: &[Key], req: &ValidateRequest, out: &mut Vec<CheckItem>) {
    let (selection, index, untrusted) = match &kbt.cnf {
        Some(Ok(Cnf::CoseKey(_))) => (KeySelection::EmbeddedCnf, None, true),
        Some(Ok(Cnf::Kid(kid))) => (
            KeySelection::PanelKid,
            keys.iter().position(|k| k.kid.as_ref().is_some_and(|i| i.as_bytes() == &kid[..])),
            false,
        ),
        Some(Ok(Cnf::Thumbprint(tp))) => (
            KeySelection::PanelThumbprint,
            keys.iter().position(|k| thumbprints(k).1 == tp[..]),
            false,
        ),
        _ => (KeySelection::None, None, false),
    };
    let (status, message, alg) = match &kbt.kbt_signature {
        Ok(alg) => (Status::Pass, format!("SD-KBT signature verified ({})", alg_to_jose(*alg)), Some(*alg)),
        Err(CoseError::NoKey) => (Status::Skip, "no holder key".to_owned(), None),
        Err(e) => (Status::Fail, format!("SD-KBT signature: {e:?}"), None),
    };
    let sel = Selected {
        status,
        selection,
        index,
        message,
    };
    out.push(signature_item("kb.signature", Category::KeyBinding, &sel, alg, &req.keys, untrusted, vec![nid("signature")]));
    let has = |f: &dyn Fn(&KbtFinding) -> bool| kbt.findings.iter().any(f);
    let claims = kbt.kbt.payload_item();
    let present = |label: i64| claims.and_then(|c| crate::cbor::map_get(c, label)).is_some();
    // aud
    if has(&|f| matches!(f, KbtFinding::AudMissing)) {
        out.push(check("kb.aud", Category::KeyBinding, Status::Fail, "aud missing", vec![nid("payload")]));
    } else if has(&|f| matches!(f, KbtFinding::AudMismatch)) {
        out.push(check("kb.aud", Category::KeyBinding, Status::Fail, "aud is not the expected value", vec![nid("payload/~e/3")]));
    } else if req.expected_aud.is_some() {
        out.push(check("kb.aud", Category::KeyBinding, Status::Pass, "aud as expected", vec![nid("payload/~e/3")]));
    } else if present(3) {
        out.push(check("kb.aud", Category::KeyBinding, Status::Info, "aud not checked", vec![nid("payload/~e/3")]));
    }
    // cnonce
    if has(&|f| matches!(f, KbtFinding::CnonceMissing)) {
        out.push(check("kb.nonce", Category::KeyBinding, Status::Fail, "cnonce missing", vec![nid("payload")]));
    } else if has(&|f| matches!(f, KbtFinding::CnonceMismatch)) {
        out.push(check("kb.nonce", Category::KeyBinding, Status::Fail, "cnonce is not the expected value", vec![nid("payload/~e/39")]));
    } else if req.expected_nonce.is_some() {
        out.push(check("kb.nonce", Category::KeyBinding, Status::Pass, "cnonce as expected", vec![nid("payload/~e/39")]));
    } else if present(39) {
        out.push(check("kb.nonce", Category::KeyBinding, Status::Info, "cnonce not checked", vec![nid("payload/~e/39")]));
    }
    // iat freshness
    let stale = kbt.findings.iter().find_map(|f| match f {
        KbtFinding::KbtClock(st) => Some(format!("KBT time claim: {st:?}")),
        KbtFinding::Stale => Some("iat is older than the maximum age".to_owned()),
        KbtFinding::NoIatOrCti => Some("neither iat nor cti".to_owned()),
        _ => None,
    });
    match stale {
        Some(why) => out.push(check("kb.iat", Category::KeyBinding, Status::Fail, why, vec![nid("payload/~e/6")])),
        None if present(6) => out.push(check("kb.iat", Category::KeyBinding, Status::Pass, "iat fresh", vec![nid("payload/~e/6")])),
        None => {}
    }
    for f in &kbt.findings {
        let why = match f {
            KbtFinding::KcwtNotSign1 => "kcwt is not a COSE_Sign1",
            KbtFinding::CwtClaimsHeader => "CWT Claims header parameter in the KBT",
            KbtFinding::IssPresent => "the KBT has iss",
            KbtFinding::SubPresent => "the KBT has sub",
            KbtFinding::TimeWithoutIat => "exp or nbf without iat",
            KbtFinding::Time(_) => "time claims are inconsistent",
            KbtFinding::IndefiniteLength => "indefinite-length CBOR",
            KbtFinding::EmptySdClaims => "empty sd_claims",
            _ => continue,
        };
        out.push(check("kb.rules", Category::KeyBinding, Status::Fail, format!("{why} ({f:?})"), vec![NodeId::root()]));
    }
}

// ---------------------------------------------------------------- lint

fn encoding_finding(kind: CborFinding) -> (&'static str, &'static str) {
    match kind {
        CborFinding::NonPreferredArgument => ("lint.encoding", "non_preferred_argument"),
        CborFinding::NonPreferredFloat => ("lint.encoding", "non_preferred_float"),
        CborFinding::NonCanonicalNaN => ("lint.nan", "non_canonical_nan"),
        CborFinding::NonPreferredBignum => ("lint.bignum", "non_preferred_bignum"),
        CborFinding::IndefiniteLength => ("lint.encoding", "indefinite_length"),
        CborFinding::MapKeyOrder => ("lint.map_order", "map_key_order"),
    }
}

fn encoding_item(kind: CborFinding, status: Status, start: usize, end: usize, preferred: &[u8], node: Option<NodeId>) -> CheckItem {
    let (id, finding) = encoding_finding(kind);
    CheckItem {
        raw: Some(ByteRange {
            start: u32_of(start),
            end: u32_of(end),
        }),
        detail: Some(CheckDetail::Encoding {
            finding: finding.to_owned(),
            preferred_hex: hex(preferred),
        }),
        ..lint_item(id, status, format!("{finding}: preferred {}", hex(preferred)), node.into_iter().collect())
    }
}

fn json_lint(root: &JNode<'_>, warnings: &[tokenator_json::Warning], base: &NodeId, out: &mut Vec<CheckItem>) {
    for w in warnings {
        let (code, message) = json_warning(w.kind);
        let id = if code == "json.invalid_utf8" { "lint.json_utf8" } else { "lint.json_number" };
        out.push(lint_item(id, Status::Warn, message, vec![json_id_at(root, w.offset, base.clone())]));
    }
    for d in tj::duplicate_members(root) {
        let ids: Vec<NodeId> = d.spans.iter().skip(1).map(|s| json_id_at(root, s.start, base.clone())).collect();
        out.push(lint_item("lint.duplicate_key", Status::Warn, format!("duplicate member {:?}", d.name), ids));
    }
}

fn json_part_lint(part: &tj::B64Part<'_>, base: NodeId, out: &mut Vec<CheckItem>) {
    let Ok(bytes) = part.decoded() else { return };
    if let Ok(parsed) = tokenator_json::parse_with_options(bytes, &ParseOptions::default()) {
        json_lint(&parsed.node, &parsed.warnings, &base, out);
    }
}

fn mismatch_text(m: &[tokenator_crypto::KeyMismatch]) -> String {
    m.iter().map(|x| format!("{x:?}")).collect::<Vec<_>>().join("; ")
}

#[allow(clippy::too_many_lines)]
fn lint_jose(text: &str, keys: &[Key]) -> Result<Vec<CheckItem>, EngineError> {
    with_parsed(text, |parsed, _| {
        let mut out = Vec::new();
        let token = &parsed.token;
        let jws = token.jws();
        let general = jws.serialization == tj::Serialization::JsonGeneral;
        for (i, sig) in jws.signatures.iter().enumerate() {
            let hid = part_ref_id(tj::PartRef::ProtectedHeader(i), general).decoded(0);
            let header = sig.protected.as_ref().and_then(|p| p.json().ok());
            if let Some(p) = &sig.protected {
                json_part_lint(p, part_ref_id(tj::PartRef::ProtectedHeader(i), general).decoded(0), &mut out);
            }
            if let Some(h) = &header {
                let facts = tj::header_facts(h);
                if facts.alg == tj::AlgFact::None {
                    out.push(lint_item("lint.alg_none", Status::Warn, "alg none: the token is unsecured", vec![hid.child("alg")]));
                }
                match &facts.crit {
                    tj::CritFact::Absent => {}
                    tj::CritFact::Malformed => out.push(lint_item("lint.crit", Status::Warn, "crit is not an array of strings", vec![hid.child("crit")])),
                    tj::CritFact::Empty => out.push(lint_item("lint.crit", Status::Warn, "crit is empty", vec![hid.child("crit")])),
                    tj::CritFact::Entries { not_understood, registered, missing } => {
                        for (what, names) in [("not understood", not_understood), ("registered", registered), ("missing from the header", missing)] {
                            if !names.is_empty() {
                                out.push(lint_item("lint.crit", Status::Warn, format!("crit {what}: {}", names.join(", ")), vec![hid.child("crit")]));
                            }
                        }
                    }
                }
                if let tj::AlgFact::Known(alg) = facts.alg {
                    for k in keys {
                        let m = tj::key_findings(alg, k);
                        if !m.is_empty() {
                            out.push(lint_item("lint.alg_key", Status::Warn, format!("key does not fit {}: {}", alg_to_jose(alg), mismatch_text(&m)), vec![hid.child("alg")]));
                        }
                    }
                }
            } else if sig.protected.is_none() {
                out.push(lint_item("lint.header", Status::Warn, "no protected header", vec![NodeId::root()]));
            }
            if let Some(u) = &sig.unprotected {
                let uid = part_ref_id(tj::PartRef::UnprotectedHeader(i), general);
                json_lint(u, &[], &uid, &mut out);
                let protected_names: BTreeSet<String> = header
                    .as_ref()
                    .and_then(JNode::members)
                    .unwrap_or_default()
                    .iter()
                    .map(|m| m.key().to_string())
                    .collect();
                for m in u.members().unwrap_or_default() {
                    if protected_names.contains(m.key().as_ref()) {
                        out.push(lint_item("lint.header", Status::Warn, format!("{} is in both headers", m.key()), vec![uid.child(m.key())]));
                    }
                }
                if u.get("alg").is_some() && !protected_names.contains("alg") {
                    out.push(lint_item("lint.header", Status::Warn, "alg is not integrity protected", vec![uid.child("alg")]));
                }
            }
        }
        json_part_lint(&jws.payload, NodeId::root().child("payload").decoded(0), &mut out);
        if let Some(sd) = token.sd_jwt() {
            for (i, d) in sd.disclosures.iter().enumerate() {
                json_part_lint(d.part(), NodeId::root().child("disclosures").index(i).decoded(0), &mut out);
            }
            if let Some(kb) = &sd.kb_jwt {
                let kh = nid("kb/protected/~e");
                let kb_header = kb.signatures.first().and_then(|s| s.protected.as_ref());
                if let Some(p) = kb_header {
                    json_part_lint(p, kh.clone(), &mut out);
                }
                json_part_lint(&kb.payload, nid("kb/payload/~e"), &mut out);
                let facts = kb_header.and_then(|p| p.json().ok()).map(|h| tj::header_facts(&h));
                if let Some(f) = &facts {
                    match &f.typ {
                        tj::StrFact::Value(t) if t == "kb+jwt" => {}
                        tj::StrFact::Absent => out.push(lint_item("lint.typ", Status::Warn, "KB-JWT without typ kb+jwt", vec![nid("kb/protected/~e")])),
                        _ => out.push(lint_item("lint.typ", Status::Warn, "KB-JWT typ is not kb+jwt", vec![kh.child("typ")])),
                    }
                    if f.alg == tj::AlgFact::None {
                        out.push(lint_item("lint.alg_none", Status::Warn, "KB-JWT alg none", vec![kh.child("alg")]));
                    }
                    if let (tj::AlgFact::Known(kb_alg), Ok(claims)) = (&f.alg, jws.claims())
                        && let tj::CnfFact::Jwk(jwk) = tj::cnf(&claims)
                        && let Ok(m) = tj::jwk_findings(*kb_alg, &jwk)
                        && !m.is_empty()
                    {
                        out.push(lint_item("lint.alg_key", Status::Warn, format!("cnf key does not fit {}: {}", alg_to_jose(*kb_alg), mismatch_text(&m)), vec![nid("payload/~e/cnf/jwk")]));
                    }
                }
            }
        }
        out
    })
    .map_err(|e| EngineError::new(ErrorCode::Parse, format!("not a JOSE token: {e}")))
}

fn cose_lint_id(kind: &CoseLint) -> &'static str {
    match kind {
        CoseLint::DuplicateMapKey => "lint.duplicate_key",
        CoseLint::AlgKeyMismatch { .. } => "lint.alg_key",
        CoseLint::CritNotProtected | CoseLint::CritMalformed | CoseLint::CritMissingLabel(_) | CoseLint::CritNotUnderstood(_) => "lint.crit",
        CoseLint::TypMissing | CoseLint::TypUnexpected(_) => "lint.typ",
        CoseLint::SaltLength(_) => "lint.salt",
        _ => "lint.header",
    }
}

fn lint_cose(bytes: &[u8], built: &Built, keys: &[Key]) -> Result<Vec<CheckItem>, EngineError> {
    let findings = tokenator_cose::lint::lint(&CborBackend, bytes, &LintOptions { signer: None })
        .map_err(|e| EngineError::new(ErrorCode::Parse, format!("not a COSE_Sign1: {e:?}")))?;
    let mut out = Vec::new();
    for f in findings {
        let status = match f.severity {
            CoseSeverity::Warn => Status::Warn,
            CoseSeverity::Info => Status::Info,
        };
        let node = f.span.and_then(|s| innermost(&built.index, s.start, s.end));
        match &f.kind {
            CoseLint::Encoding { kind, preferred_bytes } => {
                let (s, e) = f.span.map_or((0, 0), |s| (s.start, s.end));
                out.push(encoding_item(*kind, status, s, e, preferred_bytes, node));
            }
            other => {
                let mut item = lint_item(cose_lint_id(other), status, format!("{other:?}"), node.into_iter().collect());
                item.raw = f.span.map(|s| ByteRange {
                    start: u32_of(s.start),
                    end: u32_of(s.end),
                });
                out.push(item);
            }
        }
    }
    // The verifying keys against the issuer alg.
    let msg = CborBackend.parse(bytes).ok();
    let (alg, alg_node) = match (&built.kind, &msg) {
        (Kind::SdKbt, Some(_)) => {
            let inner = crate::view::find(&built.tree, &kcwt_id().child("protected").decoded(0).child("1"));
            let alg = inner.and_then(|_| inner_alg(bytes, built));
            (alg, kcwt_id().child("protected").decoded(0).child("1"))
        }
        (_, Some(m)) => (
            match m.alg() {
                Some(DeclaredAlg::Known(a)) => Some(a),
                _ => None,
            },
            nid("protected/~e/1"),
        ),
        _ => (None, NodeId::root()),
    };
    if let Some(alg) = alg {
        for k in keys {
            let m = tokenator_crypto::check_key(alg, &tokenator_keys::params(k));
            if !m.is_empty() {
                out.push(lint_item("lint.alg_key", Status::Warn, format!("key does not fit {}: {}", alg_to_jose(alg), mismatch_text(&m)), vec![alg_node.clone()]));
            }
        }
    }
    Ok(out)
}

/// The alg of the SD-CWT inside an SD-KBT.
fn inner_alg(bytes: &[u8], built: &Built) -> Option<Alg> {
    let id = kcwt_id();
    let (s, e, _) = built.index.iter().find(|(_, _, i)| *i == id)?;
    let msg = CborBackend.parse(bytes.get(*s..*e)?).ok()?;
    match msg.alg()? {
        DeclaredAlg::Known(a) => Some(a),
        _ => None,
    }
}

fn lint_cbor_claims(built: &Built) -> Result<Vec<CheckItem>, EngineError> {
    let crate::dto::document::RawView::Hex { bytes, .. } = &built.raw else {
        return Ok(Vec::new());
    };
    let item = tokenator_cbor::decode(bytes)
        .map_err(|e| EngineError::new(ErrorCode::Parse, format!("not CBOR: {e:?}")))?;
    let mut out = Vec::new();
    for f in tokenator_cbor::preferred_plus_findings(&item) {
        let node = innermost(&built.index, f.span.start, f.span.end);
        out.push(encoding_item(f.kind, Status::Info, f.span.start, f.span.end, &f.preferred_bytes, node));
    }
    for d in tokenator_cbor::duplicate_keys(&item) {
        let node = crate::view::exact(&built.index, d.duplicate_key.start, d.duplicate_key.end)
            .map(|k| k.parent().unwrap_or(k));
        let mut it = lint_item("lint.duplicate_key", Status::Warn, "duplicate map key", node.into_iter().collect());
        it.raw = Some(ByteRange {
            start: u32_of(d.duplicate_key.start),
            end: u32_of(d.duplicate_key.end),
        });
        out.push(it);
    }
    Ok(out)
}

fn lint_items(kind: &Kind, bytes: &[u8], built: &Built, keys: &[Key]) -> Result<Vec<CheckItem>, EngineError> {
    match kind {
        Kind::JsonClaims => {
            let mut out = Vec::new();
            if let Ok(parsed) = tokenator_json::parse_with_options(bytes, &ParseOptions::default()) {
                json_lint(&parsed.node, &parsed.warnings, &NodeId::root(), &mut out);
            }
            Ok(out)
        }
        Kind::CborClaims | Kind::EdnClaims => lint_cbor_claims(built),
        k if k.family() == Some(Family::Jose) => {
            let text = std::str::from_utf8(bytes).map_err(|_| EngineError::new(ErrorCode::Parse, "not UTF-8"))?;
            lint_jose(text, keys)
        }
        _ => lint_cose(bytes, built, keys),
    }
}

/// Maps every node id to itself or its nearest existing ancestor.
fn existing(tree: &Node, items: &mut [CheckItem]) {
    let all: BTreeSet<&NodeId> = nodes(tree).into_iter().map(|n| &n.id).collect();
    for item in items {
        for id in &mut item.node_ids {
            let mut cur = id.clone();
            while !all.contains(&cur) {
                match cur.parent() {
                    Some(p) => cur = p,
                    None => break,
                }
            }
            *id = cur;
        }
        item.node_ids.dedup();
    }
}

fn built(registry: &Registry, kind: &Kind, bytes: &[u8]) -> Result<Built, EngineError> {
    crate::view::build(registry, kind, bytes, &ViewOptions::default())
}

pub(crate) fn lint(registry: &Registry, req: &LintRequest) -> Result<Vec<CheckItem>, EngineError> {
    if req.doc.kind.is_key() {
        return err(ErrorCode::UnsupportedKind, "keys are not linted");
    }
    let keys = resolve_all(&req.keys)?;
    let b = built(registry, &req.doc.kind, &req.doc.bytes)?;
    let mut items = lint_items(&b.kind, &req.doc.bytes, &b, &keys)?;
    existing(&b.tree, &mut items);
    Ok(items)
}

pub(crate) fn validate(registry: &Registry, req: &ValidateRequest) -> Result<ValidationReport, EngineError> {
    let kind = &req.doc.kind;
    if kind.is_key() || kind.is_claims() {
        return err(ErrorCode::UnsupportedKind, format!("a {} cannot be validated", kind.label()));
    }
    let keys = resolve_all(&req.keys)?;
    let b = built(registry, kind, &req.doc.bytes)?;
    let mut r = if kind.family() == Some(Family::Jose) {
        let text = std::str::from_utf8(&req.doc.bytes).map_err(|_| EngineError::new(ErrorCode::Parse, "not UTF-8"))?;
        validate_jose(req, &keys, &b, text)?
    } else {
        validate_cose(req, &keys, &b, &req.doc.bytes)?
    };
    let verifier: Vec<Key> = r.verifier.and_then(|i| keys.get(i)).cloned().into_iter().collect();
    let mut lint = lint_items(&b.kind, &req.doc.bytes, &b, &verifier)?;
    r.items.append(&mut lint);
    existing(&b.tree, &mut r.items);
    r.items.sort_by_key(|i| i.category);
    let any = |s: Status| r.items.iter().any(|i| i.status == s);
    let overall = if any(Status::Fail) {
        Status::Fail
    } else if any(Status::Warn) {
        Status::Warn
    } else if r
        .items
        .iter()
        .any(|i| i.status == Status::Skip && (i.id == "signature" || i.id.starts_with("kb")))
    {
        Status::Skip
    } else {
        Status::Pass
    };
    Ok(ValidationReport {
        overall,
        items: r.items,
        fetchable: r.fetchable,
    })
}
