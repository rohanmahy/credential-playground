//! JWK (RFC 7517, RFC 7518 §6, RFC 8037, RFC 9964 §3) conversion.

use std::borrow::Cow;

use tokenator_crypto::{
    Curve, DeclaredAlg, HashAlg, KeyParams, KeyType, PrivateKeyMaterial, PublicKeyMaterial,
    alg_to_jose, digest,
};
use tokenator_json::{Member, Node, PrintStyle, Value};
use zeroize::Zeroizing;

use crate::key::declared_alg_from_jose;
use crate::material::{
    Components, RsaPrivate, alg_for_export, b64u_decode, b64u_encode, bit_len, exact_len, left_pad,
    ml_dsa_for_alg, ml_dsa_for_public_len, private_for_export,
};
use crate::{Extra, Key, KeyError, KeyOp, Kid, Label, Visibility};

/// A JSON Web Key: one JSON object, members in arrival order.
///
/// A `Jwk` is only known to be a JSON object; whether it describes a usable
/// key is checked by [`from_jwk`]. That lets [`params_from_jwk`] and
/// [`jwk_thumbprint`] work on keys with missing or broken material (for
/// example a `cnf` key being linted).
///
/// ```
/// use tokenator_keys::Jwk;
///
/// let jwk = Jwk::parse(br#"{ "kty": "OKP", "crv": "Ed25519", "x": "AAAA" }"#)?;
/// assert_eq!(jwk.member_names(), ["kty", "crv", "x"]);
/// assert_eq!(jwk.get_str("crv"), Some("Ed25519"));
/// assert_eq!(jwk.to_json(), r#"{"kty":"OKP","crv":"Ed25519","x":"AAAA"}"#);
/// # Ok::<(), tokenator_keys::KeyError>(())
/// ```
#[derive(Clone)]
pub struct Jwk {
    node: tokenator_json::Node<'static>,
}

/// Shows member names only, so private keys never end up in logs.
impl core::fmt::Debug for Jwk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Jwk")
            .field("members", &self.member_names())
            .finish_non_exhaustive()
    }
}

impl Jwk {
    /// Parses JSON text that must be a single object.
    pub fn parse(json: &[u8]) -> Result<Jwk, KeyError> {
        Jwk::from_node(&tokenator_json::parse(json)?)
    }

    /// Copies an object node, e.g. the `jwk` member of a `cnf` claim.
    pub fn from_node(node: &tokenator_json::Node<'_>) -> Result<Jwk, KeyError> {
        match node.value() {
            Value::Object(_) => Ok(Jwk {
                node: to_static(node),
            }),
            _ => Err(KeyError::UnrecognizedFormat),
        }
    }

    /// The object as a JSON tree.
    pub fn node(&self) -> &tokenator_json::Node<'static> {
        &self.node
    }

    /// Compact JSON text (no whitespace), members in order. Unedited
    /// scalars keep their original lexeme.
    pub fn to_json(&self) -> String {
        tokenator_json::print(&self.node, PrintStyle::Compact)
    }

    /// Member names in order, duplicates included.
    pub fn member_names(&self) -> Vec<&str> {
        self.members().iter().map(|m| m.key().as_ref()).collect()
    }

    /// The value of member `name` if it is a JSON string (the first one, if
    /// duplicated).
    pub fn get_str(&self, name: &str) -> Option<&str> {
        match self.node.get(name)?.value() {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    fn members(&self) -> &[Member<'static>] {
        self.node.members().unwrap_or_default()
    }

    fn get(&self, name: &str) -> Option<&Node<'static>> {
        self.node.get(name)
    }

    /// A string member, if present.
    fn str_opt(&self, name: &str) -> Result<Option<&str>, KeyError> {
        match self.get(name).map(Node::value) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s)),
            Some(_) => Err(invalid(name, "not a string")),
        }
    }

    /// A required string member.
    fn str_req(&self, name: &str) -> Result<&str, KeyError> {
        self.str_opt(name)?
            .ok_or_else(|| KeyError::MissingParameter(name.to_owned()))
    }

    /// A base64url member, if present.
    fn b64_opt(&self, name: &str) -> Result<Option<Vec<u8>>, KeyError> {
        self.str_opt(name)?
            .map(|s| b64u_decode(name, s))
            .transpose()
    }

    /// A required base64url member.
    fn b64_req(&self, name: &str) -> Result<Vec<u8>, KeyError> {
        b64u_decode(name, self.str_req(name)?)
    }

    /// A base64url secret, if present.
    fn secret_opt(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyError> {
        Ok(self.b64_opt(name)?.map(Zeroizing::new))
    }

    /// The key type, which every operation needs first.
    fn kty(&self) -> Result<KeyType, KeyError> {
        let kty = self.str_req("kty")?;
        KeyType::from_jwk_kty(kty).ok_or_else(|| KeyError::UnsupportedKeyType(kty.to_owned()))
    }
}

/// An owned copy of a JSON tree. Number lexemes are kept.
fn to_static(node: &Node<'_>) -> Node<'static> {
    Node::new(match node.value() {
        Value::Null => Value::Null,
        Value::Bool(b) => Value::Bool(*b),
        Value::Number(n) => Value::Number(Cow::Owned(n.to_string())),
        Value::String(s) => Value::String(Cow::Owned(s.to_string())),
        Value::Array(xs) => Value::Array(xs.iter().map(to_static).collect()),
        Value::Object(ms) => Value::Object(
            ms.iter()
                .map(|m| Member::new(m.key().to_string(), to_static(m.value())))
                .collect(),
        ),
    })
}

fn invalid(name: &str, reason: &'static str) -> KeyError {
    KeyError::InvalidParameter {
        name: name.to_owned(),
        reason,
    }
}

fn string(s: impl Into<String>) -> Node<'static> {
    Node::new(Value::String(Cow::Owned(s.into())))
}

fn number(n: i64) -> Node<'static> {
    Node::new(Value::Number(Cow::Owned(n.to_string())))
}

/// The members a key type defines (besides the common ones).
fn key_members(kty: KeyType) -> &'static [&'static str] {
    match kty {
        KeyType::Ec => &["crv", "x", "y", "d"],
        KeyType::Okp => &["crv", "x", "d"],
        KeyType::Rsa => &["n", "e", "d", "p", "q", "dp", "dq", "qi"],
        KeyType::Akp => &["pub", "priv"],
    }
}

const COMMON_MEMBERS: [&str; 5] = ["kty", "kid", "alg", "use", "key_ops"];

/// Builds the JWK for `key`.
///
/// Member order: `kty`, `kid`, `alg`, `use`, `key_ops`, then the key
/// parameters (`crv`, `x`, `y`, `d` for EC; `crv`, `x`, `d` for OKP; `n`,
/// `e`, `d`, `p`, `q`, `dp`, `dq`, `qi` for RSA; `pub`, `priv` for AKP),
/// then JOSE [`Extra`](crate::Extra)s in arrival order. Absent metadata is
/// omitted, except that AKP keys always get `alg` (RFC 9964 §3 requires it),
/// taken from the ML-DSA parameter set when the key declares none.
///
/// EC coordinates and scalars are fixed-width ([`Curve::field_len`]); RSA
/// integers have no leading zero bytes; the AKP `priv` is the 32-byte seed
/// (RFC 9964 §4). An ML-DSA private key known only in expanded form has no
/// RFC 9964 private representation, so [`Visibility::Private`] fails with
/// [`KeyError::MlDsaSeedUnknown`].
///
/// ```
/// use tokenator_crypto::{KeySpec, generate_from_seed};
/// use tokenator_keys::{Key, Kid, Visibility, to_jwk};
///
/// // The RFC 8037 Appendix A Ed25519 key, from its secret.
/// let d = [
///     0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
///     0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
///     0x7f, 0x60,
/// ];
/// let mut key = Key::from_private(generate_from_seed(KeySpec::Ed25519, &d)?);
/// key.kid = Some(Kid::Text("rfc8037".into()));
/// assert_eq!(
///     to_jwk(&key, Visibility::Public)?.to_json(),
///     r#"{"kty":"OKP","kid":"rfc8037","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// [`Curve::field_len`]: tokenator_crypto::Curve::field_len
pub fn to_jwk(key: &Key, visibility: Visibility) -> Result<Jwk, KeyError> {
    let secret = private_for_export(key, visibility)?;
    let public = key.public_key().to_material();
    let mut members: Vec<Member<'static>> = Vec::new();
    let mut push =
        |name: &'static str, value: Node<'static>| members.push(Member::new(name, value));

    push("kty", string(key.key_type().jwk_kty()));
    if let Some(kid) = &key.kid {
        push("kid", string(kid.to_jose_string()));
    }
    match alg_for_export(key, &public) {
        Some(DeclaredAlg::Known(alg)) => push("alg", string(alg_to_jose(alg))),
        Some(DeclaredAlg::UnknownJose(name)) => push("alg", string(name)),
        Some(DeclaredAlg::UnknownCose(label)) => push("alg", number(label)),
        None => {}
    }
    if let Some(key_use) = &key.key_use {
        push("use", string(key_use.as_str()));
    }
    if let Some(ops) = &key.key_ops {
        let ops = ops
            .iter()
            .map(|op| match (op.jose_name(), op) {
                (Some(name), _) => string(name),
                (None, KeyOp::Other(Label::Int(n))) => number(*n),
                (None, KeyOp::Other(Label::Text(t))) => string(t.as_str()),
                // Every named op has a JOSE name.
                (None, _) => Node::new(Value::Null),
            })
            .collect();
        push("key_ops", Node::new(Value::Array(ops)));
    }

    let b64 = |bytes: &[u8]| string(b64u_encode(bytes));
    match &public {
        PublicKeyMaterial::Ec { curve, x, y } => {
            push("crv", string(curve.jwk_name()));
            push("x", b64(x));
            push("y", b64(y));
        }
        PublicKeyMaterial::Ed25519 { x } => {
            push("crv", string(Curve::Ed25519.jwk_name()));
            push("x", b64(x));
        }
        PublicKeyMaterial::Rsa { n, e } => {
            push("n", b64(n));
            push("e", b64(e));
        }
        PublicKeyMaterial::MlDsa { public, .. } => push("pub", b64(public)),
    }
    match secret.as_ref().map(|s| &s.0) {
        Some(PrivateKeyMaterial::Ec { d, .. } | PrivateKeyMaterial::Ed25519 { d }) => {
            push("d", b64(d));
        }
        Some(PrivateKeyMaterial::Rsa(m)) => {
            push("d", b64(&m.d));
            for (name, value) in [
                ("p", &m.p),
                ("q", &m.q),
                ("dp", &m.dp),
                ("dq", &m.dq),
                ("qi", &m.qi),
            ] {
                if let Some(value) = value {
                    push(name, b64(value));
                }
            }
        }
        Some(PrivateKeyMaterial::MlDsa {
            seed: Some(seed), ..
        }) => push("priv", b64(seed)),
        Some(PrivateKeyMaterial::MlDsa { seed: None, .. }) | None => {}
    }

    for extra in &key.extras {
        if let Extra::Jose { name, json } = extra {
            let value = tokenator_json::parse(json.as_bytes())
                .map_err(|_| invalid(name, "extra value is not valid JSON"))?;
            members.push(Member::new(name.clone(), to_static(&value)));
        }
    }
    Ok(Jwk {
        node: Node::new(Value::Object(members)),
    })
}

/// Parses a JWK into a key, validating the material with
/// `tokenator-crypto`.
///
/// A private JWK must agree with its own public members (`x`/`y`, RSA `n`/`e`,
/// AKP `pub`), otherwise [`KeyError::InconsistentKey`]. Duplicate members
/// are rejected. Unrecognized members become JOSE extras.
///
/// EC `x`, `y`, and `d` shorter than the field length (an encoder dropped
/// leading zero bytes, which RFC 7518 §6.2.1.2 forbids) are left-padded,
/// as tokenator-crypto expects (#11); longer ones are errors. Ed25519 and
/// AKP values must have exactly the right length.
///
/// ```
/// use tokenator_keys::{Extra, Jwk, KeyError, Kid, from_jwk};
///
/// // RFC 8037 A.2, with a kid and an extra member.
/// let jwk = Jwk::parse(br#"{"kty":"OKP","crv":"Ed25519","kid":"a",
///     "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","ext":true}"#)?;
/// let key = from_jwk(&jwk)?;
/// assert!(!key.is_private());
/// assert_eq!(key.kid, Some(Kid::Text("a".into())));
/// assert_eq!(key.extras, [Extra::Jose { name: "ext".into(), json: "true".into() }]);
///
/// // A secret that belongs to another public key is refused.
/// let jwk = Jwk::parse(br#"{"kty":"OKP","crv":"Ed25519",
///     "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
///     "d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#)?;
/// assert!(matches!(from_jwk(&jwk), Err(KeyError::InconsistentKey(_))));
/// # Ok::<(), KeyError>(())
/// ```
pub fn from_jwk(jwk: &Jwk) -> Result<Key, KeyError> {
    let names = jwk.member_names();
    for (i, name) in names.iter().enumerate() {
        if names.iter().take(i).any(|n| n == name) {
            return Err(invalid(name, "duplicated"));
        }
    }
    let kty = jwk.kty()?;

    let kid = jwk.str_opt("kid")?.map(|k| Kid::Text(k.to_owned()));
    let alg = jwk_alg(jwk)?;
    let key_use = jwk.str_opt("use")?.map(str::to_owned);
    let key_ops = jwk.get("key_ops").map(jwk_key_ops).transpose()?;

    let components = match kty {
        KeyType::Ec | KeyType::Okp => {
            let crv = jwk.str_req("crv")?;
            let curve = Curve::from_jwk_name(crv)
                .ok_or_else(|| KeyError::UnsupportedCurve(crv.to_owned()))?;
            if curve.key_type() != kty {
                return Err(KeyError::InconsistentKey("crv does not belong to kty"));
            }
            let len = curve.field_len();
            let x = jwk.b64_req("x")?;
            if kty == KeyType::Ec {
                let x = left_pad("x", x, len)?;
                let y = left_pad("y", jwk.b64_req("y")?, len)?;
                let d = jwk
                    .secret_opt("d")?
                    .map(|d| left_pad("d", d.to_vec(), len).map(Zeroizing::new))
                    .transpose()?;
                Components::Curve {
                    curve,
                    x,
                    y: Some(y),
                    d,
                }
            } else {
                exact_len("x", &x, len)?;
                let d = jwk.secret_opt("d")?;
                if let Some(d) = &d {
                    exact_len("d", d, len)?;
                }
                Components::Curve {
                    curve,
                    x,
                    y: None,
                    d,
                }
            }
        }
        KeyType::Rsa => {
            let n = jwk.b64_req("n")?;
            let e = jwk.b64_req("e")?;
            let private = match jwk.secret_opt("d")? {
                None => None,
                Some(d) => {
                    let crt = ["p", "q", "dp", "dq", "qi"].map(|name| jwk.secret_opt(name));
                    let [p, q, dp, dq, qi] = crt;
                    let crt = [p?, q?, dp?, dq?, qi?];
                    let crt = if crt.iter().all(Option::is_none) {
                        None
                    } else {
                        let [p, q, dp, dq, qi] = crt;
                        let missing = |name: &str| KeyError::MissingParameter(name.to_owned());
                        Some([
                            p.ok_or_else(|| missing("p"))?,
                            q.ok_or_else(|| missing("q"))?,
                            dp.ok_or_else(|| missing("dp"))?,
                            dq.ok_or_else(|| missing("dq"))?,
                            qi.ok_or_else(|| missing("qi"))?,
                        ])
                    };
                    Some(RsaPrivate { d, crt })
                }
            };
            Components::Rsa { n, e, private }
        }
        KeyType::Akp => {
            let params = match &alg {
                None => return Err(KeyError::MissingParameter("alg".into())),
                Some(DeclaredAlg::Known(a)) => ml_dsa_for_alg(*a),
                Some(_) => None,
            }
            .ok_or_else(|| invalid("alg", "not an ML-DSA algorithm"))?;
            let public = jwk.b64_req("pub")?;
            if public.len() != params.public_key_len() {
                return Err(KeyError::InconsistentKey(
                    "pub has the wrong length for alg",
                ));
            }
            let seed = jwk.secret_opt("priv")?;
            if let Some(seed) = &seed {
                exact_len("priv", seed, tokenator_crypto::MlDsaParams::SEED_LEN)?;
            }
            Components::Akp {
                params,
                public,
                seed,
            }
        }
    };

    let mut key = Key::with_material(components.into_material()?);
    key.kid = kid;
    key.alg = alg;
    key.key_use = key_use;
    key.key_ops = key_ops;
    let known = key_members(kty);
    key.extras = jwk
        .members()
        .iter()
        .filter(|m| {
            !COMMON_MEMBERS.contains(&m.key().as_ref()) && !known.contains(&m.key().as_ref())
        })
        .map(|m| Extra::Jose {
            name: m.key().to_string(),
            json: tokenator_json::print(m.value(), PrintStyle::Compact),
        })
        .collect();
    Ok(key)
}

/// `alg`: a JOSE name, or (non-conformant) an integer COSE label.
fn jwk_alg(jwk: &Jwk) -> Result<Option<DeclaredAlg>, KeyError> {
    match jwk.get("alg").map(Node::value) {
        None => Ok(None),
        Some(Value::String(name)) => Ok(Some(declared_alg_from_jose(name))),
        Some(Value::Number(n)) => n
            .parse::<i64>()
            .map(|n| Some(DeclaredAlg::UnknownCose(n)))
            .map_err(|_| invalid("alg", "not a string or an integer")),
        Some(_) => Err(invalid("alg", "not a string or an integer")),
    }
}

fn jwk_key_ops(node: &Node<'_>) -> Result<Vec<KeyOp>, KeyError> {
    let bad = || invalid("key_ops", "not an array of strings");
    node.elements()
        .ok_or_else(bad)?
        .iter()
        .map(|op| match op.value() {
            Value::String(name) => Ok(KeyOp::from_jose_name(name)),
            Value::Number(n) => n
                .parse::<i64>()
                .map(|n| KeyOp::Other(Label::Int(n)))
                .map_err(|_| bad()),
            _ => Err(bad()),
        })
        .collect()
}

/// Describes a JWK without validating its material.
///
/// Needs only a recognized `kty`. Reports `crv` as declared, even when it
/// contradicts `kty` (so the linter can flag it), and `None` for an unknown
/// curve name. RSA size is the bit length of `n` when `n` decodes. The ML-DSA
/// parameter set comes from `alg` when it names one, otherwise from the
/// length of `pub`. `alg` becomes the declared alg.
///
/// ```
/// use tokenator_crypto::{Alg, Curve, check_key};
/// use tokenator_keys::{Jwk, params_from_jwk};
///
/// // An EC kty with an OKP curve: described as is, so the linter can say why
/// // it does not fit ES256.
/// let p = params_from_jwk(&Jwk::parse(br#"{"kty":"EC","crv":"Ed25519"}"#)?)?;
/// assert_eq!(p.crv, Some(Curve::Ed25519));
/// assert!(!check_key(Alg::ES256, &p).is_empty());
/// # Ok::<(), tokenator_keys::KeyError>(())
/// ```
pub fn params_from_jwk(jwk: &Jwk) -> Result<KeyParams, KeyError> {
    let kty = jwk.kty()?;
    let declared_alg = match jwk.get("alg").map(Node::value) {
        Some(Value::String(name)) => Some(declared_alg_from_jose(name)),
        // A JWK integer alg is always "unknown" (see `Key::alg`).
        Some(Value::Number(n)) => n.parse::<i64>().ok().map(DeclaredAlg::UnknownCose),
        _ => None,
    };
    let decoded = |name: &str| jwk.get_str(name).and_then(|s| b64u_decode(name, s).ok());
    let crv = match kty {
        KeyType::Ec | KeyType::Okp => jwk.get_str("crv").and_then(Curve::from_jwk_name),
        KeyType::Rsa | KeyType::Akp => None,
    };
    let rsa_bits = match kty {
        KeyType::Rsa => decoded("n").as_deref().and_then(bit_len),
        _ => None,
    };
    let ml_dsa = match kty {
        KeyType::Akp => match &declared_alg {
            Some(DeclaredAlg::Known(alg)) if ml_dsa_for_alg(*alg).is_some() => ml_dsa_for_alg(*alg),
            Some(DeclaredAlg::Known(_)) => None,
            _ => decoded("pub").and_then(|p| ml_dsa_for_public_len(p.len())),
        },
        _ => None,
    };
    Ok(KeyParams {
        kty,
        crv,
        rsa_bits,
        ml_dsa,
        declared_alg,
    })
}

/// The RFC 7638 JWK thumbprint, computed from the JWK's required members
/// exactly as they appear (no decoding or re-encoding of values).
///
/// Required members: EC `crv`, `kty`, `x`, `y`; OKP `crv`, `kty`, `x`; RSA
/// `e`, `kty`, `n`; AKP `alg`, `kty`, `pub` (RFC 9964 §6). Other members
/// and member order do not matter. A missing required member is
/// [`KeyError::MissingParameter`].
///
/// ```
/// use base64ct::{Base64UrlUnpadded, Encoding};
/// use tokenator_keys::{HashAlg, Jwk, jwk_thumbprint};
///
/// // RFC 8037 Appendix A.3.
/// let jwk = Jwk::parse(br#"{"kty":"OKP","crv":"Ed25519",
///     "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#)?;
/// let tp = jwk_thumbprint(&jwk, HashAlg::Sha256)?;
/// assert_eq!(
///     Base64UrlUnpadded::encode_string(&tp),
///     "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
/// );
/// # Ok::<(), tokenator_keys::KeyError>(())
/// ```
pub fn jwk_thumbprint(jwk: &Jwk, hash: HashAlg) -> Result<Vec<u8>, KeyError> {
    let kty = jwk.kty()?;
    let members = thumbprint_members(kty)
        .iter()
        .map(|name| Ok((*name, jwk.str_req(name)?)))
        .collect::<Result<Vec<_>, KeyError>>()?;
    Ok(hash_members(&members, hash))
}

/// RFC 7638 §3.2 required members, in lexicographic order.
pub(crate) fn thumbprint_members(kty: KeyType) -> &'static [&'static str] {
    match kty {
        KeyType::Ec => &["crv", "kty", "x", "y"],
        KeyType::Okp => &["crv", "kty", "x"],
        KeyType::Rsa => &["e", "kty", "n"],
        KeyType::Akp => &["alg", "kty", "pub"],
    }
}

/// Hashes `{"name":"value",...}` with no whitespace and minimal escaping.
pub(crate) fn hash_members(members: &[(&str, &str)], hash: HashAlg) -> Vec<u8> {
    let node = Node::new(Value::Object(
        members
            .iter()
            .map(|(name, value)| Member::new(name.to_string(), string(*value)))
            .collect(),
    ));
    digest(
        hash,
        tokenator_json::print(&node, PrintStyle::Compact).as_bytes(),
    )
}

/// The RFC 7638 thumbprint of `key`'s public part.
pub(crate) fn key_thumbprint(key: &Key, hash: HashAlg) -> Vec<u8> {
    let public = key.public_key().to_material();
    let kty = key.key_type().jwk_kty();
    let members: Vec<(&str, String)> = match &public {
        PublicKeyMaterial::Ec { curve, x, y } => vec![
            ("crv", curve.jwk_name().to_owned()),
            ("kty", kty.to_owned()),
            ("x", b64u_encode(x)),
            ("y", b64u_encode(y)),
        ],
        PublicKeyMaterial::Ed25519 { x } => vec![
            ("crv", Curve::Ed25519.jwk_name().to_owned()),
            ("kty", kty.to_owned()),
            ("x", b64u_encode(x)),
        ],
        PublicKeyMaterial::Rsa { n, e } => vec![
            ("e", b64u_encode(e)),
            ("kty", kty.to_owned()),
            ("n", b64u_encode(n)),
        ],
        PublicKeyMaterial::MlDsa { params, public } => vec![
            ("alg", alg_to_jose(params.alg()).to_owned()),
            ("kty", kty.to_owned()),
            ("pub", b64u_encode(public)),
        ],
    };
    let members: Vec<(&str, &str)> = members.iter().map(|(n, v)| (*n, v.as_str())).collect();
    hash_members(&members, hash)
}
