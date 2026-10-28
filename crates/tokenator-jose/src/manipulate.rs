//! Playground manipulation: re-signing, raw assembly, tampering, editing
//! disclosures, and converting between serializations.

use std::borrow::Cow;

use tokenator_crypto::rand_core::CryptoRng;
use tokenator_crypto::{Alg, HashAlg, alg_from_jose};
use tokenator_json::{Member, Node, PrintStyle, Span, Value, print};
use tokenator_keys::Key;

use crate::b64::b64u_encode;
use crate::error::JoseError;
use crate::issue::{JsonStyle, array_slot, disclosure_text, random_b64, sign_compact, string_node};
use crate::parse::{
    B64Part, Disclosure, JSON_WS, Jws, PartError, PartRef, SdJwt, Serialization, Token, parse,
};
use crate::present::join_sd;
use crate::sd::{DisclosureError, array_digest, sd_alg, sd_digest};

/// Unprotected header members that belong to the SD-JWT, not the signature.
const SD_MEMBERS: [&str; 2] = ["disclosures", "kb_jwt"];

/// Edited trees to re-sign. `None` keeps that part's original encoded text.
#[derive(Debug, Clone, Copy, Default)]
pub struct Edits<'e, 'n> {
    /// A replacement protected header (signature 0).
    pub header: Option<&'e Node<'n>>,
    /// A replacement payload.
    pub payload: Option<&'e Node<'n>>,
}

/// Re-signs signature 0 with `key`, using the `alg` of the (possibly
/// edited) protected header.
///
/// Edited trees are printed with `tokenator_json::PrintStyle::Original`, so
/// unedited bytes inside them stay identical; parts without an edit keep
/// their encoded text exactly. Disclosures and any KB-JWT are copied
/// unchanged (so a KB-JWT goes stale), and so are other signatures of a
/// general JSON serialization. The output has the input's serialization.
pub fn resign(
    token: &Token<'_>,
    edits: &Edits<'_, '_>,
    key: &Key,
    rng: &mut dyn CryptoRng,
) -> Result<String, JoseError> {
    let jws = token.jws();
    let sig = jws
        .signatures
        .first()
        .ok_or(JoseError::NoSuchSignature(0))?;
    let header_ref = PartRef::ProtectedHeader(0);
    let (alg, header) = match edits.header {
        Some(h) => (
            usable_alg(h)?,
            Cow::Owned(b64u_encode(print(h, PrintStyle::Original).as_bytes())),
        ),
        None => {
            let protected = sig.protected.as_ref().ok_or(JoseError::NoProtectedHeader)?;
            let node = protected.json().map_err(|error| JoseError::Part {
                part: header_ref,
                error,
            })?;
            (usable_alg(&node)?, Cow::Borrowed(protected.text()))
        }
    };
    let payload = match edits.payload {
        Some(p) => Cow::Owned(b64u_encode(print(p, PrintStyle::Original).as_bytes())),
        None => Cow::Borrowed(jws.payload.text()),
    };
    let jwt = sign_compact(&header, &payload, alg, key, rng)?;
    let Some(root) = jws.envelope() else {
        return Ok(match token.sd_jwt() {
            Some(sd) => with_disclosures(&jwt, sd),
            None => jwt,
        });
    };
    let signature = jwt.rsplit('.').next().unwrap_or_default();
    Ok(edit_envelope(
        root,
        &EnvelopeEdit {
            protected: edits.header.map(|_| header.as_ref()),
            payload: edits.payload.map(|_| payload.as_ref()),
            signature: Some(signature),
            ..EnvelopeEdit::default()
        },
    ))
}

/// Raw text parts of a compact token, joined without any checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawParts<'r> {
    /// Header segment.
    pub header: &'r str,
    /// Payload segment.
    pub payload: &'r str,
    /// Signature segment.
    pub signature: &'r str,
    /// `None` for a JWS; `Some` for an SD-JWT (each followed by `~`).
    pub disclosures: Option<&'r [&'r str]>,
    /// Appended after the last `~` (SD-JWT only).
    pub kb_jwt: Option<&'r str>,
}

/// `header.payload.signature`, plus `~D1~...~DN~[KB]` for an SD-JWT.
///
/// ```
/// use tokenator_jose::{RawParts, assemble_compact};
/// let raw = RawParts { header: "h", payload: "p", signature: "", disclosures: Some(&["d"]), kb_jwt: None };
/// assert_eq!(assemble_compact(&raw), "h.p.~d~");
/// ```
pub fn assemble_compact(parts: &RawParts<'_>) -> String {
    let mut out = format!("{}.{}.{}", parts.header, parts.payload, parts.signature);
    if let Some(disclosures) = parts.disclosures {
        out.push('~');
        for d in disclosures {
            out.push_str(d);
            out.push('~');
        }
        out.push_str(parts.kb_jwt.unwrap_or_default());
    }
    out
}

/// A deliberate break, applied without re-signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tamper {
    /// Flip bit `bit` of the decoded bytes of `part` (byte `bit / 8`, mask
    /// `0x80 >> (bit % 8)`) and re-encode it. Parts: protected header,
    /// payload, signature, disclosure, and the KB-JWT parts.
    FlipBit {
        /// Which part.
        part: PartRef,
        /// Bit index.
        bit: usize,
    },
    /// Set the protected header's `alg` (added at the end if absent). Other
    /// header bytes are kept (`Original` printing).
    SetAlg(String),
    /// Empty the signature segment.
    StripSignature,
    /// Set (or add) the protected header's `kid`, or remove it with `None`.
    SetKid(Option<String>),
    /// Keep only the first `n` bytes of the token text.
    Truncate(usize),
    /// Append a copy of disclosure `n` after the last disclosure.
    DuplicateDisclosure(usize),
    /// Re-encode the protected header as equivalent JSON with different
    /// bytes (`Pretty`, or `Compact` if that would not change the bytes,
    /// or with a trailing newline if neither would).
    ReencodeHeader,
}

/// Applies `op` to a compact JWS or SD-JWT (with surrounding whitespace
/// ignored). Everything not targeted is copied byte for byte.
pub fn tamper(token: &str, op: &Tamper) -> Result<String, JoseError> {
    let text = token.trim_matches(JSON_WS);
    let parsed = parse(text)?;
    let jws = parsed.token.jws();
    if jws.serialization != Serialization::Compact {
        return Err(JoseError::NotCompact);
    }
    let replace = |span: Span, new: &str| {
        let before = text.get(..span.start).unwrap_or_default();
        let after = text.get(span.end..).unwrap_or_default();
        format!("{before}{new}{after}")
    };
    let protected = jws
        .signatures
        .first()
        .and_then(|s| s.protected.as_ref())
        .ok_or(JoseError::NoProtectedHeader)?;
    let edit_header = |f: &dyn Fn(&mut Node<'_>)| -> Result<String, JoseError> {
        let part = PartRef::ProtectedHeader(0);
        let mut header = protected
            .json()
            .map_err(|error| JoseError::Part { part, error })?;
        if header.members().is_none() {
            return Err(JoseError::NotAnObject(part));
        }
        f(&mut header);
        let encoded = b64u_encode(print(&header, PrintStyle::Original).as_bytes());
        Ok(replace(protected.span(), &encoded))
    };
    match op {
        Tamper::FlipBit { part, bit } => {
            let target = tamper_part(&parsed.token, *part)?;
            let mut bytes = target
                .decoded()
                .map_err(|e| JoseError::Part {
                    part: *part,
                    error: PartError::Base64(e),
                })?
                .to_vec();
            let byte = bytes.get_mut(bit / 8).ok_or(JoseError::OutOfRange)?;
            *byte ^= 0x80 >> (bit % 8);
            Ok(replace(target.span(), &b64u_encode(&bytes)))
        }
        Tamper::SetAlg(alg) => {
            edit_header(&|h| set_member(h, "alg", Some(Value::String(alg.clone().into()))))
        }
        Tamper::SetKid(kid) => {
            edit_header(&|h| set_member(h, "kid", kid.clone().map(|k| Value::String(k.into()))))
        }
        Tamper::StripSignature => {
            let sig = jws.signatures.first().map(|s| s.signature.span());
            Ok(replace(sig.unwrap_or(jws.span), ""))
        }
        Tamper::Truncate(n) => text
            .get(..*n)
            .filter(|_| *n < text.len())
            .map(str::to_owned)
            .ok_or(JoseError::OutOfRange),
        Tamper::DuplicateDisclosure(n) => {
            let sd = parsed.token.sd_jwt().ok_or(JoseError::NotSdJwt)?;
            let d = sd
                .disclosures
                .get(*n)
                .ok_or(JoseError::NoSuchDisclosure(*n))?;
            let at = sd
                .disclosures
                .last()
                .map_or(0, |last| last.part().span().end + 1);
            let at = Span { start: at, end: at };
            Ok(replace(at, &format!("{}~", d.text())))
        }
        Tamper::ReencodeHeader => {
            let part = PartRef::ProtectedHeader(0);
            let header = protected
                .json()
                .map_err(|error| JoseError::Part { part, error })?;
            let original = protected.decoded().unwrap_or_default();
            let mut json = print(&header, PrintStyle::Pretty);
            if json.as_bytes() == original {
                json = print(&header, PrintStyle::Compact);
            }
            if json.as_bytes() == original {
                json.push('\n');
            }
            Ok(replace(protected.span(), &b64u_encode(json.as_bytes())))
        }
    }
}

/// One edit of an SD-JWT's disclosures or digests.
#[derive(Debug, Clone)]
pub enum DisclosureOp {
    /// Remove disclosure `n`.
    Remove(usize),
    /// Append this base64url text as a disclosure.
    Append(String),
    /// Reorder: the new list is these indexes (repeats and omissions allowed).
    Reorder(Vec<usize>),
    /// Append a new disclosure (property with `name`, array element
    /// without). `salt: None` draws 16 random bytes.
    Forge {
        /// Salt.
        salt: Option<String>,
        /// Claim name.
        name: Option<String>,
        /// Value.
        value: Node<'static>,
    },
    /// Replace the value of disclosure `index`, keeping its salt and name.
    /// The new disclosure's digest no longer matches.
    ReplaceValue {
        /// Disclosure index.
        index: usize,
        /// New value.
        value: Node<'static>,
    },
    /// Add a digest (random if `None`) to the `_sd` of the payload object at
    /// pointer `at`, or as a `{"...": digest}` element appended to the array
    /// at `at`. Changes the payload, so the signature goes stale.
    AddDigest {
        /// Pointer into the issuer payload.
        at: String,
        /// The digest.
        digest: Option<String>,
    },
    /// Remove every occurrence of this digest from the payload (`_sd`
    /// entries and `{"...": digest}` elements). The signature goes stale.
    RemoveDigest(String),
}

/// Applies `ops` in order. Indexes refer to the disclosure list as it is
/// when each op runs. Payload edits print the payload with `Original` style
/// and keep the old signature; new disclosures use `style`. Any KB-JWT is
/// copied unchanged. The output has the input's serialization.
pub fn edit_disclosures(
    sd: &SdJwt<'_>,
    ops: &[DisclosureOp],
    style: JsonStyle,
    rng: &mut dyn CryptoRng,
) -> Result<String, JoseError> {
    let mut texts: Vec<Cow<'_, str>> = sd
        .disclosures
        .iter()
        .map(|d| Cow::Borrowed(d.text()))
        .collect();
    let mut payload: Option<Node<'_>> = None;
    for op in ops {
        match op {
            DisclosureOp::Remove(n) => {
                if *n >= texts.len() {
                    return Err(JoseError::NoSuchDisclosure(*n));
                }
                texts.remove(*n);
            }
            DisclosureOp::Append(text) => texts.push(Cow::Borrowed(text)),
            DisclosureOp::Reorder(order) => {
                texts = order
                    .iter()
                    .map(|&i| texts.get(i).cloned().ok_or(JoseError::NoSuchDisclosure(i)))
                    .collect::<Result<_, _>>()?;
            }
            DisclosureOp::Forge { salt, name, value } => {
                let salt = salt.clone().unwrap_or_else(|| random_b64(rng));
                texts.push(Cow::Owned(disclosure_text(
                    &salt,
                    name.as_deref(),
                    value.clone(),
                    style,
                )));
            }
            DisclosureOp::ReplaceValue { index, value } => {
                let text = texts
                    .get(*index)
                    .ok_or(JoseError::NoSuchDisclosure(*index))?;
                let d = Disclosure::new(text);
                let view = d.view().map_err(|e| disclosure_error(*index, e))?;
                let new = disclosure_text(view.salt(), view.name(), value.clone(), style);
                if let Some(slot) = texts.get_mut(*index) {
                    *slot = Cow::Owned(new);
                }
            }
            DisclosureOp::AddDigest { at, digest } => {
                let tree = payload_tree(&mut payload, sd)?;
                let digest = match digest {
                    Some(d) => d.clone(),
                    None => {
                        let hash = sd_alg(tree).hash().unwrap_or(HashAlg::Sha256);
                        sd_digest(&random_b64(rng), hash)
                    }
                };
                let target = tree
                    .pointer_mut(at)
                    .ok_or_else(|| JoseError::NoSuchClaim(at.clone()))?;
                add_digest(target, digest, at)?;
            }
            DisclosureOp::RemoveDigest(digest) => {
                remove_digest(payload_tree(&mut payload, sd)?, digest)
            }
        }
    }
    let texts: Vec<&str> = texts.iter().map(AsRef::as_ref).collect();
    let new_payload = payload.map(|p| b64u_encode(print(&p, PrintStyle::Original).as_bytes()));
    if let Some(root) = sd.issuer.envelope() {
        return Ok(edit_envelope(
            root,
            &EnvelopeEdit {
                payload: new_payload.as_deref(),
                disclosures: Some(&texts),
                ..EnvelopeEdit::default()
            },
        ));
    }
    let jwt = match (&new_payload, sd.issuer.compact_source()) {
        (None, Some(source)) => Cow::Borrowed(source),
        _ => {
            let sig = sd.issuer.signatures.first();
            Cow::Owned(assemble_compact(&RawParts {
                header: sig
                    .and_then(|s| s.protected.as_ref())
                    .map_or("", B64Part::text),
                payload: new_payload.as_deref().unwrap_or(sd.issuer.payload.text()),
                signature: sig.map_or("", |s| s.signature.text()),
                disclosures: None,
                kb_jwt: None,
            }))
        }
    };
    let mut out = join_sd(&jwt, &texts);
    if let Some(kb) = &sd.kb_jwt {
        out.push_str(&jws_text(kb));
    }
    Ok(out)
}

/// A token in another serialization, plus what could not be carried over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Converted {
    /// The token text.
    pub text: String,
    /// Unprotected header members that compact serialization cannot hold
    /// (by name, in order; `disclosures` and `kb_jwt` are carried over and
    /// not listed).
    pub dropped: Vec<String>,
}

/// Which JSON serialization to produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonSerialization {
    /// Flattened (RFC 7515 §7.2.2).
    Flattened,
    /// General (RFC 7515 §7.2.1).
    General,
}

/// Converts to compact serialization, using signature `index`. An SD-JWT's
/// disclosures and KB-JWT belong to the token, so they are appended whichever
/// signature is chosen.
pub fn to_compact(token: &Token<'_>, index: usize) -> Result<Converted, JoseError> {
    let jws = token.jws();
    let sig = jws
        .signatures
        .get(index)
        .ok_or(JoseError::NoSuchSignature(index))?;
    let protected = sig.protected.as_ref().ok_or(JoseError::NoProtectedHeader)?;
    let jwt = match jws.compact_source() {
        Some(source) => source.to_owned(),
        None => format!(
            "{}.{}.{}",
            protected.text(),
            jws.payload.text(),
            sig.signature.text()
        ),
    };
    let dropped = sig
        .unprotected
        .as_ref()
        .and_then(Node::members)
        .unwrap_or_default()
        .iter()
        .map(|m| m.key().as_ref())
        .filter(|k| !SD_MEMBERS.contains(k))
        .map(str::to_owned)
        .collect();
    let text = match token.sd_jwt() {
        Some(sd) => with_disclosures(&jwt, sd),
        None => jwt,
    };
    Ok(Converted { text, dropped })
}

/// Converts to a JSON serialization (compact JSON text). An SD-JWT's
/// disclosures and KB-JWT go into the first unprotected header as
/// `disclosures` (always, possibly empty) and `kb_jwt`. Encoded parts and
/// other unprotected header members are copied verbatim. A general
/// serialization with several signatures cannot become flattened.
pub fn to_json(token: &Token<'_>, form: JsonSerialization) -> Result<String, JoseError> {
    let jws = token.jws();
    if form == JsonSerialization::Flattened && jws.signatures.len() > 1 {
        return Err(JoseError::MultipleSignatures);
    }
    let sd = token.sd_jwt();
    let kb = sd.and_then(|sd| sd.kb_jwt.as_ref()).map(jws_text);
    let mut signatures = Vec::with_capacity(jws.signatures.len());
    for (i, sig) in jws.signatures.iter().enumerate() {
        let mut members = Vec::with_capacity(3);
        if let Some(p) = &sig.protected {
            members.push(Member::new("protected", string_node(p.text())));
        }
        let mut header = sig.unprotected.clone();
        if let (0, Some(sd)) = (i, sd) {
            let mut h = header.unwrap_or_else(|| Node::new(Value::Object(Vec::new())));
            let disclosures = sd
                .disclosures
                .iter()
                .map(|d| string_node(d.text()))
                .collect();
            set_member(&mut h, "disclosures", Some(Value::Array(disclosures)));
            set_member(
                &mut h,
                "kb_jwt",
                kb.as_deref().map(|k| Value::String(k.into())),
            );
            header = Some(h);
        }
        if let Some(h) = header {
            members.push(Member::new("header", h));
        }
        members.push(Member::new("signature", string_node(sig.signature.text())));
        signatures.push(members);
    }
    let mut root = vec![Member::new("payload", string_node(jws.payload.text()))];
    match form {
        JsonSerialization::Flattened => root.extend(signatures.into_iter().flatten()),
        JsonSerialization::General => {
            let sigs = signatures
                .into_iter()
                .map(|ms| Node::new(Value::Object(ms)))
                .collect();
            root.push(Member::new("signatures", Node::new(Value::Array(sigs))));
        }
    }
    Ok(print(&Node::new(Value::Object(root)), PrintStyle::Compact))
}

/// The `alg` of a header to sign with.
fn usable_alg(header: &Node<'_>) -> Result<Alg, JoseError> {
    if header.members().is_none() {
        return Err(JoseError::NotAnObject(PartRef::ProtectedHeader(0)));
    }
    match header.get("alg").map(Node::value) {
        Some(Value::String(name)) if name != "none" => {
            alg_from_jose(name).ok_or_else(|| JoseError::UnusableAlg(Some(name.to_string())))
        }
        Some(Value::String(name)) => Err(JoseError::UnusableAlg(Some(name.to_string()))),
        _ => Err(JoseError::UnusableAlg(None)),
    }
}

/// The original compact text of a JWS (a KB-JWT), or its signature 0.
fn jws_text<'j>(jws: &'j Jws<'_>) -> Cow<'j, str> {
    match jws.compact_source() {
        Some(text) => Cow::Borrowed(text),
        None => Cow::Owned(jws.compact().unwrap_or_default()),
    }
}

/// `jwt` followed by the disclosures and KB-JWT of `sd`.
fn with_disclosures(jwt: &str, sd: &SdJwt<'_>) -> String {
    let texts: Vec<&str> = sd.disclosures.iter().map(Disclosure::text).collect();
    let mut out = join_sd(jwt, &texts);
    if let Some(kb) = &sd.kb_jwt {
        out.push_str(&jws_text(kb));
    }
    out
}

/// Sets member `name` of an object (appending it if absent), or removes
/// every member with that name.
fn set_member<'a>(obj: &mut Node<'a>, name: &str, value: Option<Value<'a>>) {
    match value {
        Some(value) => match obj.get_mut(name) {
            Some(node) => node.set_value(value),
            None => {
                if let Value::Object(ms) = obj.value_mut() {
                    ms.push(Member::new(name.to_owned(), Node::new(value)));
                }
            }
        },
        None => {
            if obj.get(name).is_some()
                && let Value::Object(ms) = obj.value_mut()
            {
                ms.retain(|m| m.key() != name);
            }
        }
    }
}

/// What to do with `kb_jwt` in the first unprotected header.
#[derive(Debug, Clone, Copy)]
pub(crate) enum KbEdit<'t> {
    Keep,
    Remove,
    Set(&'t str),
}

/// Replacements for a JSON serialization envelope. `None` keeps a member.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EnvelopeEdit<'t> {
    pub(crate) protected: Option<&'t str>,
    pub(crate) payload: Option<&'t str>,
    pub(crate) signature: Option<&'t str>,
    pub(crate) disclosures: Option<&'t [&'t str]>,
    pub(crate) kb: KbEdit<'t>,
}

impl Default for EnvelopeEdit<'_> {
    fn default() -> Self {
        EnvelopeEdit {
            protected: None,
            payload: None,
            signature: None,
            disclosures: None,
            kb: KbEdit::Keep,
        }
    }
}

/// Applies `edit` to a copy of the envelope (signature 0 and the first
/// unprotected header) and prints it with `Original` style.
pub(crate) fn edit_envelope(root: &Node<'_>, edit: &EnvelopeEdit<'_>) -> String {
    let string = |s: &str| Value::String(s.to_owned().into());
    let mut root = root.clone();
    if let Some(p) = edit.payload {
        set_member(&mut root, "payload", Some(string(p)));
    }
    let sig = if root.get("signatures").is_some() {
        root.get_mut("signatures")
            .and_then(Node::elements_mut)
            .and_then(|sigs| sigs.iter_mut().find(|s| s.members().is_some()))
    } else {
        Some(&mut root)
    };
    if let Some(sig) = sig {
        if let Some(p) = edit.protected {
            set_member(sig, "protected", Some(string(p)));
        }
        if let Some(s) = edit.signature {
            set_member(sig, "signature", Some(string(s)));
        }
        if edit.disclosures.is_some() || !matches!(edit.kb, KbEdit::Keep) {
            if !sig.get("header").is_some_and(|h| h.members().is_some()) {
                set_member(sig, "header", Some(Value::Object(Vec::new())));
            }
            if let Some(header) = sig.get_mut("header") {
                if let Some(ds) = edit.disclosures {
                    let ds = ds.iter().map(|d| Node::new(string(d))).collect();
                    set_member(header, "disclosures", Some(Value::Array(ds)));
                }
                match edit.kb {
                    KbEdit::Keep => {}
                    KbEdit::Remove => set_member(header, "kb_jwt", None),
                    KbEdit::Set(kb) => set_member(header, "kb_jwt", Some(string(kb))),
                }
            }
        }
    }
    print(&root, PrintStyle::Original)
}

/// The part [`Tamper::FlipBit`] targets.
fn tamper_part<'t>(token: &'t Token<'_>, part: PartRef) -> Result<&'t B64Part<'t>, JoseError> {
    let jws = token.jws();
    let sig = |n: usize| jws.signatures.get(n).ok_or(JoseError::NoSuchSignature(n));
    let kb = || {
        token
            .sd_jwt()
            .and_then(|sd| sd.kb_jwt.as_ref())
            .ok_or(JoseError::OutOfRange)
    };
    let kb_sig = |kb: &'t Jws<'t>| kb.signatures.first().ok_or(JoseError::OutOfRange);
    match part {
        PartRef::ProtectedHeader(n) => sig(n)?.protected.as_ref().ok_or(JoseError::OutOfRange),
        PartRef::Payload => Ok(&jws.payload),
        PartRef::Signature(n) => Ok(&sig(n)?.signature),
        PartRef::Disclosure(n) => token
            .sd_jwt()
            .and_then(|sd| sd.disclosures.get(n))
            .map(Disclosure::part)
            .ok_or(JoseError::NoSuchDisclosure(n)),
        PartRef::KbProtectedHeader => kb_sig(kb()?)?
            .protected
            .as_ref()
            .ok_or(JoseError::OutOfRange),
        PartRef::KbPayload => Ok(&kb()?.payload),
        PartRef::KbSignature => Ok(&kb_sig(kb()?)?.signature),
        PartRef::Envelope | PartRef::UnprotectedHeader(_) | PartRef::KbJwt => {
            Err(JoseError::OutOfRange)
        }
    }
}

/// A disclosure that cannot be read for [`DisclosureOp::ReplaceValue`].
fn disclosure_error(index: usize, e: DisclosureError) -> JoseError {
    let part = PartRef::Disclosure(index);
    match e {
        DisclosureError::Base64(e) => JoseError::Part {
            part,
            error: PartError::Base64(e),
        },
        DisclosureError::Json(e) => JoseError::Part {
            part,
            error: PartError::Json(e),
        },
        _ => JoseError::NotAnObject(part),
    }
}

/// The issuer payload tree being edited, parsed on first use.
fn payload_tree<'p, 's>(
    slot: &'p mut Option<Node<'s>>,
    sd: &'s SdJwt<'_>,
) -> Result<&'p mut Node<'s>, JoseError> {
    let tree = match slot.take() {
        Some(tree) => tree,
        None => sd.issuer.claims().map_err(|error| JoseError::Part {
            part: PartRef::Payload,
            error,
        })?,
    };
    Ok(slot.insert(tree))
}

/// Adds `digest` to the `_sd` of an object or as a slot of an array.
fn add_digest<'a>(target: &mut Node<'a>, digest: String, at: &str) -> Result<(), JoseError> {
    let invalid = || JoseError::InvalidDecoyTarget(at.to_owned());
    let entry = Node::new(Value::String(digest.clone().into()));
    match target.value() {
        Value::Object(_) => match target.get_mut("_sd") {
            Some(sd) => match sd.value_mut() {
                Value::Array(xs) => xs.push(entry),
                _ => return Err(invalid()),
            },
            None => set_member(target, "_sd", Some(Value::Array(vec![entry]))),
        },
        Value::Array(_) => {
            if let Value::Array(xs) = target.value_mut() {
                xs.push(array_slot(digest));
            }
        }
        _ => return Err(invalid()),
    }
    Ok(())
}

/// Removes every `_sd` entry and `{"...": digest}` element equal to `digest`.
fn remove_digest(node: &mut Node<'_>, digest: &str) {
    let is_digest = |n: &Node<'_>| matches!(n.value(), Value::String(s) if s == digest);
    let is_slot = |n: &Node<'_>| array_digest(n) == Some(Ok(digest));
    if node.members().is_some() {
        if let Some(sd) = node.get_mut("_sd")
            && sd.elements().is_some_and(|xs| xs.iter().any(is_digest))
            && let Value::Array(xs) = sd.value_mut()
        {
            xs.retain(|x| !is_digest(x));
        }
        for m in node.members_mut().unwrap_or_default() {
            remove_digest(m.value_mut(), digest);
        }
    } else if node.elements().is_some() {
        if node.elements().is_some_and(|xs| xs.iter().any(is_slot))
            && let Value::Array(xs) = node.value_mut()
        {
            xs.retain(|x| !is_slot(x));
        }
        for x in node.elements_mut().unwrap_or_default() {
            remove_digest(x, digest);
        }
    }
}
