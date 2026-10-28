//! Choosing disclosures and adding a KB-JWT (RFC 9901 §7.2).

use std::collections::{HashMap, HashSet};

use tokenator_crypto::rand_core::CryptoRng;
use tokenator_crypto::{Alg, HashAlg, alg_to_jose};
use tokenator_json::{Member, Node, Value};
use tokenator_keys::Key;

use crate::b64::b64u_encode;
use crate::error::JoseError;
use crate::issue::{JsonStyle, sign_compact, string_node};
use crate::json_out;
use crate::manipulate::{EnvelopeEdit, KbEdit, edit_envelope};
use crate::parse::{Disclosure, PartRef, SdJwt};
use crate::sd::{SdAlg, array_digest, sd_alg, sd_digest};

/// A problem with a chosen set of disclosures. Reported, never fixed: the
/// output contains exactly the disclosures asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionFinding {
    /// The digest of `disclosure` is embedded in disclosure `parent`, which
    /// is not kept (RFC 9901 §7.2 step 2). Only the immediate parent is
    /// reported; a missing grandparent is reported for the parent.
    MissingParent {
        /// The kept disclosure.
        disclosure: usize,
        /// The disclosure holding its digest.
        parent: usize,
    },
    /// The digest of `disclosure` is embedded nowhere: not in the payload,
    /// not in any disclosure of the input.
    Unreachable {
        /// The kept disclosure.
        disclosure: usize,
    },
    /// `disclosure` is kept more than once (RFC 9901 §4 forbids sending a
    /// disclosure twice). Reported once per extra occurrence.
    Duplicate {
        /// The disclosure.
        disclosure: usize,
    },
}

/// The checked selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// Input disclosure indexes in output order (as given, duplicates kept).
    pub kept: Vec<usize>,
    /// Problems, ordered by position in `kept`.
    pub findings: Vec<SelectionFinding>,
}

/// Checks keeping `keep` (indexes into `sd.disclosures`, in the order they
/// will be sent) without building anything.
pub fn select(sd: &SdJwt<'_>, keep: &[usize]) -> Result<Selection, JoseError> {
    if let Some(&bad) = keep.iter().find(|&&i| i >= sd.disclosures.len()) {
        return Err(JoseError::NoSuchDisclosure(bad));
    }
    let payload = sd.issuer.claims().map_err(|error| JoseError::Part {
        part: PartRef::Payload,
        error,
    })?;
    let mut findings = Vec::new();
    let hash = sd_alg(&payload).hash();
    let views: Vec<_> = sd.disclosures.iter().map(Disclosure::view).collect();
    let mut in_payload = Vec::new();
    collect_digests(&payload, &mut in_payload);
    let in_payload: HashSet<&str> = in_payload.into_iter().collect();
    let mut parents: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, view) in views.iter().enumerate() {
        if let Ok(view) = view {
            let mut inner = Vec::new();
            collect_digests(view.value(), &mut inner);
            for d in inner {
                parents.entry(d).or_default().push(i);
            }
        }
    }
    for (pos, &k) in keep.iter().enumerate() {
        if keep.iter().take(pos).any(|&j| j == k) {
            findings.push(SelectionFinding::Duplicate { disclosure: k });
            continue;
        }
        let Some(digest) = hash.zip(sd.disclosures.get(k)).map(|(h, d)| d.digest(h)) else {
            continue;
        };
        if in_payload.contains(digest.as_str()) {
            continue;
        }
        match parents.get(digest.as_str()) {
            None => findings.push(SelectionFinding::Unreachable { disclosure: k }),
            Some(ps) if !ps.iter().any(|p| keep.contains(p)) => {
                let parent = ps.first().copied().unwrap_or_default();
                findings.push(SelectionFinding::MissingParent {
                    disclosure: k,
                    parent,
                });
            }
            Some(_) => {}
        }
    }
    Ok(Selection {
        kept: keep.to_vec(),
        findings,
    })
}

/// Options for the KB-JWT (RFC 9901 §4.3).
#[derive(Debug, Clone)]
pub struct KbOptions<'k> {
    /// The holder's private key.
    pub key: &'k Key,
    /// The signature algorithm.
    pub alg: Alg,
    /// Header `typ`; `None` omits it (non-conformant, for experiments).
    pub typ: Option<String>,
    /// `aud`.
    pub aud: String,
    /// `nonce`.
    pub nonce: String,
    /// `iat`, NumericDate seconds.
    pub iat: i64,
    /// Style of the KB-JWT header and payload.
    pub style: JsonStyle,
}

impl<'k> KbOptions<'k> {
    /// `typ: kb+jwt`, compact style.
    pub fn new(key: &'k Key, alg: Alg, aud: &str, nonce: &str, iat: i64) -> KbOptions<'k> {
        KbOptions {
            key,
            alg,
            typ: Some("kb+jwt".to_owned()),
            aud: aud.to_owned(),
            nonce: nonce.to_owned(),
            iat,
            style: JsonStyle::Compact,
        }
    }
}

/// A presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presented {
    /// The SD-JWT (or SD-JWT+KB), in the input's serialization.
    pub token: String,
    /// The checked selection.
    pub selection: Selection,
}

/// Builds the SD-JWT with exactly the disclosures `keep` (in that order)
/// and, with `kb`, a KB-JWT over it.
///
/// The issuer-signed JWT is copied byte for byte and any KB-JWT of the
/// input is dropped. The KB-JWT header is `alg` then `typ`; its payload is
/// `nonce`, `aud`, `iat`, `sd_hash` (the RFC 9901 order), with `sd_hash`
/// computed with the payload's `_sd_alg` over
/// [`SdJwt::sd_hash_input`] of the result. A JSON serialization stays JSON:
/// `disclosures` and `kb_jwt` are replaced in the first unprotected header
/// and everything else is copied. Selection problems are reported in
/// [`Presented::selection`], never corrected.
pub fn present(
    sd: &SdJwt<'_>,
    keep: &[usize],
    kb: Option<&KbOptions<'_>>,
    rng: &mut dyn CryptoRng,
) -> Result<Presented, JoseError> {
    let selection = select(sd, keep)?;
    let texts: Vec<&str> = keep
        .iter()
        .filter_map(|&i| sd.disclosures.get(i))
        .map(Disclosure::text)
        .collect();
    let issuer = match sd.issuer.compact_source() {
        Some(text) => Some(text.to_owned()),
        None => sd.issuer.compact(),
    };
    let sd_input = issuer.map(|jwt| join_sd(&jwt, &texts));
    let kb_jwt = match kb {
        None => None,
        Some(kb) => {
            let input = sd_input.as_deref().ok_or(JoseError::NoProtectedHeader)?;
            Some(kb_jwt(sd, input, kb, rng)?)
        }
    };
    let token = match sd.issuer.envelope() {
        None => {
            let mut token = sd_input.unwrap_or_default();
            token.push_str(kb_jwt.as_deref().unwrap_or_default());
            token
        }
        Some(root) => {
            let kb = kb_jwt.as_deref().map_or(KbEdit::Remove, KbEdit::Set);
            let edit = EnvelopeEdit {
                disclosures: Some(&texts),
                kb,
                ..EnvelopeEdit::default()
            };
            edit_envelope(root, &edit)
        }
    };
    Ok(Presented { token, selection })
}

/// `<jwt>~<D.1>~...~<D.N>~`.
pub(crate) fn join_sd(jwt: &str, disclosures: &[&str]) -> String {
    let len = disclosures.iter().map(|d| d.len() + 1).sum::<usize>();
    let mut out = String::with_capacity(jwt.len() + 1 + len);
    out.push_str(jwt);
    out.push('~');
    for d in disclosures {
        out.push_str(d);
        out.push('~');
    }
    out
}

/// Every digest embedded in `node`: `_sd` entries and `{"...": digest}`
/// elements, at any depth.
fn collect_digests<'n>(node: &'n Node<'_>, out: &mut Vec<&'n str>) {
    match node.value() {
        Value::Object(ms) => {
            for m in ms {
                if m.key() == "_sd" {
                    let entries = m.value().elements().unwrap_or_default();
                    out.extend(entries.iter().filter_map(|e| match e.value() {
                        Value::String(s) => Some(s.as_ref()),
                        _ => None,
                    }));
                } else {
                    collect_digests(m.value(), out);
                }
            }
        }
        Value::Array(xs) => {
            for x in xs {
                match array_digest(x) {
                    Some(Ok(d)) => out.push(d),
                    _ => collect_digests(x, out),
                }
            }
        }
        _ => {}
    }
}

/// Builds and signs a KB-JWT over `sd_input` (RFC 9901 §4.3).
fn kb_jwt(
    sd: &SdJwt<'_>,
    sd_input: &str,
    kb: &KbOptions<'_>,
    rng: &mut dyn CryptoRng,
) -> Result<String, JoseError> {
    let payload = sd.issuer.claims().map_err(|error| JoseError::Part {
        part: PartRef::Payload,
        error,
    })?;
    let hash = match sd_alg(&payload) {
        SdAlg::Unsupported(name) => return Err(JoseError::UnsupportedSdAlg(Some(name))),
        SdAlg::NotAString => return Err(JoseError::UnsupportedSdAlg(None)),
        SdAlg::Default => HashAlg::Sha256,
        SdAlg::Named(h) => h,
    };
    let mut header = vec![Member::new("alg", string_node(alg_to_jose(kb.alg)))];
    if let Some(typ) = &kb.typ {
        header.push(Member::new("typ", string_node(typ)));
    }
    let sd_hash = sd_digest(sd_input, hash);
    let claims = vec![
        Member::new("nonce", string_node(&kb.nonce)),
        Member::new("aud", string_node(&kb.aud)),
        Member::new("iat", Node::new(Value::Number(kb.iat.to_string().into()))),
        Member::new("sd_hash", string_node(&sd_hash)),
    ];
    let encode = |members| {
        b64u_encode(json_out::write(&Node::new(Value::Object(members)), kb.style).as_bytes())
    };
    sign_compact(&encode(header), &encode(claims), kb.alg, kb.key, rng)
}
