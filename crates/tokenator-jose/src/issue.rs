//! Issuing JWTs and SD-JWTs.

use std::collections::{HashMap, HashSet};

use tokenator_crypto::rand_core::CryptoRng;
use tokenator_crypto::{Alg, HashAlg, alg_to_jose, sign};
use tokenator_json::{Member, Node, Value};
use tokenator_keys::{Jwk, Key};

use crate::b64::b64u_encode;
use crate::error::JoseError;
use crate::json_out;
use crate::parse::PartRef;
use crate::sd::{escape_token, sd_digest};

/// How generated JSON (headers, payloads, disclosures) is written.
///
/// Values copied from an input tree keep their number lexemes; strings are
/// re-escaped by the style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum JsonStyle {
    /// No insignificant whitespace; non-ASCII characters written as UTF-8.
    #[default]
    Compact,
    /// `", "` and `": "` separators, as in the RFC 9901 examples (Python's
    /// `json.dumps` default). With `ascii_only`, every non-ASCII character
    /// is written as a lowercase `\uXXXX` escape (a surrogate pair above
    /// U+FFFF), as the RFC 9901 Appendix A examples do.
    Spaced {
        /// Escape all non-ASCII characters.
        ascii_only: bool,
    },
}

/// Order of the digests in each `_sd` array.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DigestOrder {
    /// Sorted by byte value, after adding decoys (the RFC 9901 §4.2.4.1
    /// recommendation, and what its examples do).
    #[default]
    Sorted,
    /// Disclosures in creation order, then decoys. Reveals claim order; for
    /// experiments only.
    Creation,
}

/// Where disclosure salts come from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SaltSource {
    /// Base64url of 16 bytes (128 bits) from the RNG per salt.
    #[default]
    Random,
    /// These salts, in disclosure creation order (to reproduce published
    /// examples). Running out is [`JoseError::SaltsExhausted`].
    Fixed(Vec<String>),
}

/// The decoy digests to add at one place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecoyDigests {
    /// `n` decoys, each the base64url digest (under the `_sd_alg` hash) of
    /// the base64url of 16 random bytes.
    Random(usize),
    /// These digest strings, verbatim.
    Fixed(Vec<String>),
}

/// Decoys for one object (added to its `_sd`) or array (appended as
/// `{"...": digest}` elements).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoySpec {
    /// RFC 6901 pointer into the input claims (`""` for the top level). The
    /// target may be inside a selectively disclosable claim; its decoys then
    /// live in that claim's disclosure.
    pub at: String,
    /// What to add.
    pub digests: DecoyDigests,
}

/// The confirmation (`cnf`, RFC 7800) to put in the payload.
#[derive(Debug, Clone)]
pub enum Cnf {
    /// `{"jwk": ...}`, members in the JWK's order.
    Jwk(Jwk),
    /// `{"kid": ...}`.
    Kid(String),
}

/// Everything [`issue`] needs besides the claims.
#[derive(Debug, Clone)]
pub struct IssueOptions<'k> {
    /// The issuer's private key.
    pub key: &'k Key,
    /// The signature algorithm (header `alg`).
    pub alg: Alg,
    /// Header `typ`.
    pub typ: Option<String>,
    /// Header `kid`.
    pub kid: Option<String>,
    /// Header `x5c` (base64 DER certificates, in order); omitted if empty.
    pub x5c: Vec<String>,
    /// More header members, appended in order.
    pub extra_header: Vec<(String, Node<'static>)>,
    /// `cnf`, appended as the last payload member.
    pub cnf: Option<Cnf>,
    /// RFC 6901 pointers of the claims to make selectively disclosable.
    /// Marking a claim and something inside it gives recursive disclosures.
    pub sd: Vec<String>,
    /// Decoy digests.
    pub decoys: Vec<DecoySpec>,
    /// The `_sd_alg` hash. `None` omits the claim and uses SHA-256 (the
    /// default the RFC prescribes).
    pub sd_alg: Option<HashAlg>,
    /// `_sd` order.
    pub digest_order: DigestOrder,
    /// Salt source.
    pub salts: SaltSource,
    /// Style for the header, payload, and disclosures.
    pub style: JsonStyle,
}

impl<'k> IssueOptions<'k> {
    /// Defaults: no `typ`/`kid`/`x5c`/`cnf`, nothing selectively disclosable,
    /// no decoys, `_sd_alg` SHA-256, sorted digests, random salts, compact
    /// JSON.
    pub fn new(key: &'k Key, alg: Alg) -> IssueOptions<'k> {
        IssueOptions {
            key,
            alg,
            typ: None,
            kid: None,
            x5c: Vec::new(),
            extra_header: Vec::new(),
            cnf: None,
            sd: Vec::new(),
            decoys: Vec::new(),
            sd_alg: Some(HashAlg::Sha256),
            digest_order: DigestOrder::Sorted,
            salts: SaltSource::Random,
            style: JsonStyle::Compact,
        }
    }
}

/// One disclosure created by [`issue`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedDisclosure {
    /// Pointer of the claim in the input claims.
    pub pointer: String,
    /// The base64url disclosure.
    pub text: String,
    /// Its digest.
    pub digest: String,
}

/// The output of [`issue`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issued {
    /// A compact JWT, or a compact SD-JWT ending in `~`.
    pub token: String,
    /// Disclosures in creation order (also their order in the token).
    pub disclosures: Vec<IssuedDisclosure>,
}

/// Issues a JWT, or an SD-JWT if `opts.sd` or `opts.decoys` is non-empty.
///
/// Header members: `alg`, then `typ`, `kid`, `x5c` when set, then
/// `extra_header`. Payload: an object's `_sd` (if it gets digests) comes
/// first, then its remaining members in input order; at the top level
/// `_sd_alg` (SD-JWT only) and `cnf` follow. Claims are walked in document
/// order and a claim's disclosure is created after those inside it, which
/// fixes the order of salts, disclosures, and RNG use (salts, then random
/// decoys in `decoys` order, then the signature). With fixed salts and
/// decoys and [`JsonStyle::Spaced`], this reproduces the RFC 9901 example
/// payloads and disclosures byte for byte.
///
/// Errors: pointers and decoy targets are checked first
/// ([`JoseError::NoSuchClaim`], [`JoseError::InvalidSdPath`],
/// [`JoseError::InvalidDecoyTarget`]), then conflicts with generated
/// members ([`JoseError::ClaimConflict`]), then salts and signing.
pub fn issue(
    claims: &Node<'_>,
    opts: &IssueOptions<'_>,
    rng: &mut dyn CryptoRng,
) -> Result<Issued, JoseError> {
    if claims.members().is_none() {
        return Err(JoseError::NotAnObject(PartRef::Payload));
    }
    check_pointers(claims, opts)?;
    let is_sd = !opts.sd.is_empty() || !opts.decoys.is_empty();
    check_conflicts(claims, opts, is_sd)?;

    let sd: HashSet<&str> = opts.sd.iter().map(String::as_str).collect();
    let salts = match &opts.salts {
        SaltSource::Fixed(salts) if salts.len() < sd.len() => {
            return Err(JoseError::SaltsExhausted);
        }
        SaltSource::Fixed(salts) => salts.iter().take(sd.len()).cloned().collect(),
        SaltSource::Random => (0..sd.len()).map(|_| random_b64(rng)).collect::<Vec<_>>(),
    };
    let hash = opts.sd_alg.unwrap_or(HashAlg::Sha256);
    let mut decoys: HashMap<&str, Vec<String>> = HashMap::new();
    for spec in &opts.decoys {
        let digests = decoys.entry(spec.at.as_str()).or_default();
        match &spec.digests {
            DecoyDigests::Fixed(fixed) => digests.extend(fixed.iter().cloned()),
            DecoyDigests::Random(n) => {
                digests.extend((0..*n).map(|_| sd_digest(&random_b64(rng), hash)));
            }
        }
    }

    let mut builder = Builder {
        sd,
        decoys,
        salts: salts.into_iter(),
        hash,
        order: opts.digest_order,
        style: opts.style,
        disclosures: Vec::new(),
    };
    let mut payload = builder.build(claims, "")?;
    if let Value::Object(members) = payload.value_mut() {
        if let (true, Some(h)) = (is_sd, opts.sd_alg) {
            members.push(Member::new("_sd_alg", string_node(h.name())));
        }
        match &opts.cnf {
            Some(Cnf::Jwk(jwk)) => {
                let jwk = Member::new("jwk", jwk.node().clone());
                members.push(Member::new("cnf", Node::new(Value::Object(vec![jwk]))));
            }
            Some(Cnf::Kid(kid)) => {
                let kid = Member::new("kid", string_node(kid));
                members.push(Member::new("cnf", Node::new(Value::Object(vec![kid]))));
            }
            None => {}
        }
    }

    let mut header = vec![Member::new("alg", string_node(alg_to_jose(opts.alg)))];
    if let Some(typ) = &opts.typ {
        header.push(Member::new("typ", string_node(typ)));
    }
    if let Some(kid) = &opts.kid {
        header.push(Member::new("kid", string_node(kid)));
    }
    if !opts.x5c.is_empty() {
        let certs = opts.x5c.iter().map(|c| string_node(c)).collect();
        header.push(Member::new("x5c", Node::new(Value::Array(certs))));
    }
    for (name, value) in &opts.extra_header {
        header.push(Member::new(name.as_str(), value.clone()));
    }
    let header =
        b64u_encode(json_out::write(&Node::new(Value::Object(header)), opts.style).as_bytes());
    let payload = b64u_encode(json_out::write(&payload, opts.style).as_bytes());
    let mut token = sign_compact(&header, &payload, opts.alg, opts.key, rng)?;
    if is_sd {
        token.push('~');
        for d in &builder.disclosures {
            token.push_str(&d.text);
            token.push('~');
        }
    }
    Ok(Issued {
        token,
        disclosures: builder.disclosures,
    })
}

/// Base64url of 16 random bytes: a salt, or the input of a decoy digest.
pub(crate) fn random_b64(rng: &mut dyn CryptoRng) -> String {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    b64u_encode(&bytes)
}

/// A synthesized JSON string.
pub(crate) fn string_node<'a>(s: &'a str) -> Node<'a> {
    Node::new(Value::String(s.into()))
}

/// Signs `header.payload` and returns the compact JWS.
pub(crate) fn sign_compact(
    header: &str,
    payload: &str,
    alg: Alg,
    key: &Key,
    rng: &mut dyn CryptoRng,
) -> Result<String, JoseError> {
    let private = key.private_key().ok_or(JoseError::NoPrivateKey)?;
    let input = format!("{header}.{payload}");
    let signature = sign(alg, private, input.as_bytes(), rng)?;
    Ok(format!("{input}.{}", b64u_encode(&signature)))
}

/// The base64url text of a disclosure array `[salt, name, value]` or
/// `[salt, value]`.
pub(crate) fn disclosure_text(
    salt: &str,
    name: Option<&str>,
    value: Node<'_>,
    style: JsonStyle,
) -> String {
    let mut elements = vec![string_node(salt)];
    elements.extend(name.map(string_node));
    elements.push(value);
    b64u_encode(json_out::write(&Node::new(Value::Array(elements)), style).as_bytes())
}

/// Checks the `sd` pointers and decoy targets.
fn check_pointers(claims: &Node<'_>, opts: &IssueOptions<'_>) -> Result<(), JoseError> {
    for p in &opts.sd {
        let reserved = p
            .split('/')
            .skip(1)
            .any(|t| matches!(t, "_sd" | "_sd_alg" | "..."));
        if p.is_empty() || reserved {
            return Err(JoseError::InvalidSdPath(p.clone()));
        }
        if claims.pointer(p).is_none() {
            return Err(JoseError::NoSuchClaim(p.clone()));
        }
    }
    for d in &opts.decoys {
        match claims.pointer(&d.at).map(Node::value) {
            None => return Err(JoseError::NoSuchClaim(d.at.clone())),
            Some(Value::Object(_) | Value::Array(_)) => {}
            Some(_) => return Err(JoseError::InvalidDecoyTarget(d.at.clone())),
        }
    }
    Ok(())
}

/// Checks that no generated member (`_sd`, `_sd_alg`, `cnf`) is already in
/// the claims.
fn check_conflicts(
    claims: &Node<'_>,
    opts: &IssueOptions<'_>,
    is_sd: bool,
) -> Result<(), JoseError> {
    let parents = opts
        .sd
        .iter()
        .map(|p| p.rsplit_once('/').map_or("", |(parent, _)| parent));
    for target in parents.chain(opts.decoys.iter().map(|d| d.at.as_str())) {
        let object = claims.pointer(target).filter(|n| n.members().is_some());
        if object.is_some_and(|o| o.get("_sd").is_some()) {
            return Err(JoseError::ClaimConflict(format!("{target}/_sd")));
        }
    }
    if is_sd && opts.sd_alg.is_some() && claims.get("_sd_alg").is_some() {
        return Err(JoseError::ClaimConflict("/_sd_alg".into()));
    }
    if opts.cnf.is_some() && claims.get("cnf").is_some() {
        return Err(JoseError::ClaimConflict("/cnf".into()));
    }
    Ok(())
}

/// Builds the payload tree, creating disclosures inner-first in document
/// order.
struct Builder<'o> {
    /// Pointers still to disclose (each is used once, at its first match).
    sd: HashSet<&'o str>,
    decoys: HashMap<&'o str, Vec<String>>,
    salts: std::vec::IntoIter<String>,
    hash: HashAlg,
    order: DigestOrder,
    style: JsonStyle,
    disclosures: Vec<IssuedDisclosure>,
}

impl Builder<'_> {
    fn build<'a>(&mut self, node: &Node<'a>, pointer: &str) -> Result<Node<'a>, JoseError> {
        match node.value() {
            Value::Object(ms) => {
                let mut digests = Vec::new();
                let mut members = Vec::with_capacity(ms.len() + 1);
                for m in ms {
                    let child = format!("{pointer}/{}", escape_token(m.key()));
                    let value = self.build(m.value(), &child)?;
                    if self.sd.remove(child.as_str()) {
                        digests.push(self.disclose(child, Some(m.key()), value)?);
                    } else {
                        members.push(Member::new(m.key().clone(), value));
                    }
                }
                digests.extend(self.decoys.remove(pointer).unwrap_or_default());
                if self.order == DigestOrder::Sorted {
                    digests.sort_unstable();
                }
                if !digests.is_empty() {
                    let sd = digests
                        .into_iter()
                        .map(|d| Node::new(Value::String(d.into())))
                        .collect();
                    members.insert(0, Member::new("_sd", Node::new(Value::Array(sd))));
                }
                Ok(Node::new(Value::Object(members)))
            }
            Value::Array(xs) => {
                let mut elements = Vec::with_capacity(xs.len());
                for (i, x) in xs.iter().enumerate() {
                    let child = format!("{pointer}/{i}");
                    let value = self.build(x, &child)?;
                    if self.sd.remove(child.as_str()) {
                        let digest = self.disclose(child, None, value)?;
                        elements.push(array_slot(digest));
                    } else {
                        elements.push(value);
                    }
                }
                let decoys = self.decoys.remove(pointer).unwrap_or_default();
                elements.extend(decoys.into_iter().map(array_slot));
                Ok(Node::new(Value::Array(elements)))
            }
            _ => Ok(node.clone()),
        }
    }

    /// Creates a disclosure and returns its digest.
    fn disclose(
        &mut self,
        pointer: String,
        name: Option<&str>,
        value: Node<'_>,
    ) -> Result<String, JoseError> {
        let salt = self.salts.next().ok_or(JoseError::SaltsExhausted)?;
        let text = disclosure_text(&salt, name, value, self.style);
        let digest = sd_digest(&text, self.hash);
        self.disclosures.push(IssuedDisclosure {
            pointer,
            text,
            digest: digest.clone(),
        });
        Ok(digest)
    }
}

/// `{"...": digest}`.
pub(crate) fn array_slot<'a>(digest: String) -> Node<'a> {
    let member = Member::new("...", Node::new(Value::String(digest.into())));
    Node::new(Value::Object(vec![member]))
}
