//! Facts the core's linter needs. Judgement (severity, wording) is the
//! core's job.

use std::collections::HashMap;

use tokenator_crypto::{Alg, KeyMismatch, alg_from_jose, check_key};
use tokenator_json::{Node, Span, Value};
use tokenator_keys::{Jwk, Key, KeyError, params, params_from_jwk};

use crate::sd::escape_token;

/// Header parameters defined by RFC 7515 §4.1 and RFC 7518 §4.1, §4.6,
/// §4.7, §4.8 (JWE ones included), which must not appear in `crit`.
const REGISTERED: [&str; 20] = [
    "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit", "enc",
    "zip", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c",
];

/// The header `alg`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlgFact {
    /// Absent.
    Missing,
    /// Not a string.
    NotAString,
    /// `none`.
    None,
    /// A supported algorithm.
    Known(Alg),
    /// A string naming an unsupported algorithm.
    Unsupported(String),
}

/// A header member expected to be a string (`typ`, `cty`, `kid`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StrFact {
    /// Absent.
    Absent,
    /// A string.
    Value(String),
    /// Present but not a string.
    NotAString,
}

/// The header `crit` (RFC 7515 §4.1.11). This crate understands no
/// extension parameters, so every proper entry is not understood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CritFact {
    /// Absent.
    Absent,
    /// Not an array of strings.
    Malformed,
    /// An empty array (forbidden).
    Empty,
    /// The entries, sorted into what is wrong with them.
    Entries {
        /// Extension names this crate does not understand (all proper ones).
        not_understood: Vec<String>,
        /// Names defined by RFC 7515/7518 itself (`alg`, `kid`, ...), which
        /// must not be listed.
        registered: Vec<String>,
        /// Listed names that are not present in the header.
        missing: Vec<String>,
    },
}

/// Header facts for the linter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderFacts {
    /// `alg`.
    pub alg: AlgFact,
    /// `typ`.
    pub typ: StrFact,
    /// `cty`.
    pub cty: StrFact,
    /// `kid`.
    pub kid: StrFact,
    /// `crit`.
    pub crit: CritFact,
}

/// Facts about a header object (a non-object gives all-absent facts with
/// `alg: Missing`).
pub fn header_facts(header: &Node<'_>) -> HeaderFacts {
    let str_fact = |name: &str| match header.get(name).map(Node::value) {
        None => StrFact::Absent,
        Some(Value::String(s)) => StrFact::Value(s.to_string()),
        Some(_) => StrFact::NotAString,
    };
    let alg = match header.get("alg").map(Node::value) {
        None => AlgFact::Missing,
        Some(Value::String(s)) if s == "none" => AlgFact::None,
        Some(Value::String(s)) => {
            alg_from_jose(s).map_or_else(|| AlgFact::Unsupported(s.to_string()), AlgFact::Known)
        }
        Some(_) => AlgFact::NotAString,
    };
    HeaderFacts {
        alg,
        typ: str_fact("typ"),
        cty: str_fact("cty"),
        kid: str_fact("kid"),
        crit: crit_fact(header),
    }
}

/// A member name that occurs more than once in one object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateMember {
    /// RFC 6901 pointer to the object.
    pub pointer: String,
    /// The repeated (decoded) name.
    pub name: String,
    /// Key spans of every occurrence, in order (relative to the tree's
    /// source bytes; empty for synthesized keys).
    pub spans: Vec<Span>,
}

/// Every repeated member name in `node`, depth-first in document order.
pub fn duplicate_members(node: &Node<'_>) -> Vec<DuplicateMember> {
    let mut out = Vec::new();
    collect_duplicates(node, &mut String::new(), &mut out);
    out
}

/// The `cnf` claim of a payload (RFC 7800).
#[derive(Debug, Clone)]
pub enum CnfFact {
    /// No `cnf`.
    Absent,
    /// `cnf` is not an object.
    NotAnObject,
    /// `cnf.jwk` (an object; whether it imports is a separate question).
    Jwk(Jwk),
    /// `cnf.kid` as a string.
    Kid(String),
    /// Neither `jwk` nor `kid`; the member names present.
    Other(Vec<String>),
}

/// Reads `cnf` from a payload. `jwk` wins over `kid` when both are present.
pub fn cnf(payload: &Node<'_>) -> CnfFact {
    let Some(cnf) = payload.get("cnf") else {
        return CnfFact::Absent;
    };
    let Some(members) = cnf.members() else {
        return CnfFact::NotAnObject;
    };
    if let Some(jwk) = cnf.get("jwk").and_then(|j| Jwk::from_node(j).ok()) {
        return CnfFact::Jwk(jwk);
    }
    if let Some(Value::String(kid)) = cnf.get("kid").map(Node::value) {
        return CnfFact::Kid(kid.to_string());
    }
    CnfFact::Other(members.iter().map(|m| m.key().to_string()).collect())
}

/// `tokenator_crypto::check_key` for a key (including its declared `alg`).
pub fn key_findings(alg: Alg, key: &Key) -> Vec<KeyMismatch> {
    check_key(alg, &params(key))
}

/// `tokenator_crypto::check_key` for a JWK (e.g. `cnf.jwk`), without
/// needing valid key material.
pub fn jwk_findings(alg: Alg, jwk: &Jwk) -> Result<Vec<KeyMismatch>, KeyError> {
    Ok(check_key(alg, &params_from_jwk(jwk)?))
}

fn crit_fact(header: &Node<'_>) -> CritFact {
    let Some(crit) = header.get("crit") else {
        return CritFact::Absent;
    };
    let Some(entries) = crit.elements() else {
        return CritFact::Malformed;
    };
    let mut names = Vec::with_capacity(entries.len());
    for e in entries {
        match e.value() {
            Value::String(s) => names.push(s.as_ref()),
            _ => return CritFact::Malformed,
        }
    }
    if names.is_empty() {
        return CritFact::Empty;
    }
    let (registered, not_understood): (Vec<&str>, Vec<&str>) =
        names.iter().partition(|n| REGISTERED.contains(n));
    let owned = |v: Vec<&str>| v.into_iter().map(str::to_owned).collect();
    CritFact::Entries {
        not_understood: owned(not_understood),
        registered: owned(registered),
        missing: owned(
            names
                .iter()
                .copied()
                .filter(|n| header.get(n).is_none())
                .collect(),
        ),
    }
}

/// Reports the repeated names of `node` itself, then recurses. `pointer` is
/// the pointer to `node`, restored before returning.
fn collect_duplicates(node: &Node<'_>, pointer: &mut String, out: &mut Vec<DuplicateMember>) {
    let len = pointer.len();
    if let Some(members) = node.members() {
        let mut groups: Vec<(&str, Vec<Span>, usize)> = Vec::new();
        let mut index: HashMap<&str, usize> = HashMap::new();
        for m in members {
            let name: &str = m.key();
            let g = *index.entry(name).or_insert_with(|| {
                groups.push((name, Vec::new(), 0));
                groups.len() - 1
            });
            if let Some((_, spans, count)) = groups.get_mut(g) {
                spans.extend(m.key_span());
                *count += 1;
            }
        }
        for (name, spans, count) in groups {
            if count > 1 {
                out.push(DuplicateMember {
                    pointer: pointer.clone(),
                    name: name.to_owned(),
                    spans,
                });
            }
        }
        for m in members {
            pointer.push('/');
            pointer.push_str(&escape_token(m.key()));
            collect_duplicates(m.value(), pointer, out);
            pointer.truncate(len);
        }
    } else if let Some(elements) = node.elements() {
        for (i, e) in elements.iter().enumerate() {
            pointer.push('/');
            pointer.push_str(&i.to_string());
            collect_duplicates(e, pointer, out);
            pointer.truncate(len);
        }
    }
}
