//! PEM armor (RFC 7468) and the DER structures inside it: SPKI, PKCS#8,
//! SEC1, PKCS#1, and the RFC 9881 ML-DSA private key forms.

use base64ct::{Base64, Encoding};
use der::asn1::{AnyRef, BitStringRef, ObjectIdentifier, OctetStringRef, UintRef};
use der::{Decode, Encode, Reader, SliceReader, Tag, TagNumber, Tagged};
use pem_rfc7468::LineEnding;
use pkcs8::PrivateKeyInfoRef;
use spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};
use tokenator_crypto::{
    Curve, MlDsaParams, PrivateKey, PrivateKeyMaterial, PublicKey, PublicKeyMaterial,
    RsaPrivateMaterial,
};
use zeroize::Zeroizing;

use crate::key::{Material, wipe};
use crate::material::{Secret, left_pad};
use crate::{Key, KeyError, KeyFormat, MlDsaPrivateForm, PemEncoding, Visibility};

const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const SECP521R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
const ID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const ID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
const ID_ML_DSA_44: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
const ID_ML_DSA_65: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
const ID_ML_DSA_87: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

const BEGIN: &[u8] = b"-----BEGIN ";
const DASHES: &[u8] = b"-----";

/// True if `input` contains a PEM `-----BEGIN ` line.
pub(crate) fn looks_like_pem(input: &[u8]) -> bool {
    find(input, BEGIN).is_some()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Splits PEM text into one result per key block, in order. Text outside
/// blocks and `EC PARAMETERS` blocks are skipped.
pub(crate) fn import_blocks(input: &[u8]) -> Result<Vec<Result<Key, KeyError>>, KeyError> {
    let mut results = Vec::new();
    let mut rest = input;
    while let Some(start) = find(rest, BEGIN) {
        let after = rest.get(start + BEGIN.len()..).unwrap_or_default();
        let Some(label_len) = find(after, DASHES) else {
            results.push(Err(KeyError::Pem("unterminated BEGIN line")));
            break;
        };
        let label = core::str::from_utf8(after.get(..label_len).unwrap_or_default())
            .map_err(|_| KeyError::Pem("label is not UTF-8"));
        let body_and_rest = after.get(label_len + DASHES.len()..).unwrap_or_default();
        let label = match label {
            Ok(label) => label,
            Err(e) => {
                results.push(Err(e));
                rest = body_and_rest;
                continue;
            }
        };
        let end_line = [b"-----END ", label.as_bytes(), DASHES].concat();
        let Some(body_len) = find(body_and_rest, &end_line) else {
            results.push(Err(KeyError::Pem("missing END line")));
            break;
        };
        let body = body_and_rest.get(..body_len).unwrap_or_default();
        rest = body_and_rest
            .get(body_len + end_line.len()..)
            .unwrap_or_default();
        if label == "EC PARAMETERS" {
            continue;
        }
        results.push(decode_body(body).and_then(|der| import_der(label, &der)));
    }
    if results.is_empty() && !looks_like_pem(input) {
        return Err(KeyError::Pem("no PEM block"));
    }
    Ok(results)
}

/// Decodes the base64 body of a block (any line breaks, no headers).
fn decode_body(body: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    let line = body.first().copied();
    if !matches!(line, Some(b'\n' | b'\r')) {
        return Err(KeyError::Pem("BEGIN line is not followed by a line break"));
    }
    let text: Zeroizing<Vec<u8>> = Zeroizing::new(
        body.iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect(),
    );
    if text.contains(&b':') {
        return Err(KeyError::Pem("PEM headers are not supported"));
    }
    Base64::decode_vec(core::str::from_utf8(&text).map_err(|_| KeyError::Pem("bad base64"))?)
        .map(Zeroizing::new)
        .map_err(|_| KeyError::Pem("bad base64"))
}

fn import_der(label: &str, der: &[u8]) -> Result<Key, KeyError> {
    let material = match label {
        "PUBLIC KEY" => Material::Public(from_spki(der)?),
        "PRIVATE KEY" => Material::Private(from_pkcs8(der)?),
        "EC PRIVATE KEY" => Material::Private(from_sec1(der, None)?),
        "RSA PRIVATE KEY" => Material::Private(from_pkcs1_private(der)?),
        "RSA PUBLIC KEY" => Material::Public(from_pkcs1_public(der)?),
        "ENCRYPTED PRIVATE KEY" => return Err(KeyError::EncryptedPrivateKey),
        other => return Err(KeyError::UnsupportedPemLabel(other.to_owned())),
    };
    Ok(Key::with_material(material))
}

// ------------------------------------------------------------------ import

/// The algorithm of an SPKI / PKCS#8 structure.
enum KeyAlg {
    Ec(Curve),
    Ed25519,
    Rsa,
    MlDsa(MlDsaParams),
}

fn key_alg(alg: &AlgorithmIdentifierRef<'_>) -> Result<KeyAlg, KeyError> {
    let oid = alg.oid;
    if oid == ID_EC_PUBLIC_KEY {
        let params = alg
            .parameters
            .ok_or(KeyError::Der("EC key without curve parameters"))?;
        return curve_of(params).map(KeyAlg::Ec);
    }
    // RFC 8410 §3 and RFC 9881 §2: parameters MUST be absent.
    let no_params = || {
        if alg.parameters.is_some() {
            Err(KeyError::Der("unexpected algorithm parameters"))
        } else {
            Ok(())
        }
    };
    Ok(match oid {
        ID_ED25519 => no_params().map(|()| KeyAlg::Ed25519)?,
        // RSASSA-PSS parameters only restrict use; the key is plain RSA (#16).
        RSA_ENCRYPTION | ID_RSASSA_PSS => KeyAlg::Rsa,
        ID_ML_DSA_44 => no_params().map(|()| KeyAlg::MlDsa(MlDsaParams::MlDsa44))?,
        ID_ML_DSA_65 => no_params().map(|()| KeyAlg::MlDsa(MlDsaParams::MlDsa65))?,
        ID_ML_DSA_87 => no_params().map(|()| KeyAlg::MlDsa(MlDsaParams::MlDsa87))?,
        other => return Err(KeyError::UnsupportedAlgorithm(other.to_string())),
    })
}

/// The named curve of `ECParameters` (RFC 5480 §2.1.1).
fn curve_of(params: AnyRef<'_>) -> Result<Curve, KeyError> {
    match params.tag() {
        Tag::ObjectIdentifier => {
            let oid: ObjectIdentifier = params
                .decode_as()
                .map_err(|_| KeyError::Der("malformed curve OID"))?;
            match oid {
                SECP256R1 => Ok(Curve::P256),
                SECP384R1 => Ok(Curve::P384),
                SECP521R1 => Ok(Curve::P521),
                other => Err(KeyError::UnsupportedCurve(other.to_string())),
            }
        }
        Tag::Sequence => Err(KeyError::UnsupportedCurve(
            "explicit EC domain parameters".into(),
        )),
        _ => Err(KeyError::Der("malformed EC parameters")),
    }
}

fn curve_oid(curve: Curve) -> ObjectIdentifier {
    match curve {
        Curve::P256 => SECP256R1,
        Curve::P384 => SECP384R1,
        // Ed25519 never reaches here.
        Curve::P521 | Curve::Ed25519 => SECP521R1,
    }
}

/// An uncompressed SEC1 point `04 || x || y`.
fn ec_point(curve: Curve, point: &[u8]) -> Result<PublicKeyMaterial, KeyError> {
    let len = curve.field_len();
    match point.split_first() {
        Some((0x04, xy)) if xy.len() == 2 * len => {
            let (x, y) = xy.split_at(len);
            Ok(PublicKeyMaterial::Ec {
                curve,
                x: x.to_vec(),
                y: y.to_vec(),
            })
        }
        Some((0x02 | 0x03, _)) => Err(KeyError::InvalidParameter {
            name: "subjectPublicKey".into(),
            reason: "compressed points are not supported (#18)",
        }),
        _ => Err(KeyError::Der("malformed EC point")),
    }
}

fn from_spki(der: &[u8]) -> Result<PublicKey, KeyError> {
    let spki =
        SubjectPublicKeyInfoRef::from_der(der).map_err(|_| KeyError::Der("malformed SPKI"))?;
    let alg = key_alg(&spki.algorithm)?;
    let key = spki
        .subject_public_key
        .as_bytes()
        .ok_or(KeyError::Der("public key BIT STRING has unused bits"))?;
    Ok(PublicKey::from_material(&public_material(&alg, key)?)?)
}

/// The public key from an SPKI `subjectPublicKey` (or PKCS#8 v2 `publicKey`).
fn public_material(alg: &KeyAlg, key: &[u8]) -> Result<PublicKeyMaterial, KeyError> {
    Ok(match alg {
        KeyAlg::Ec(curve) => ec_point(*curve, key)?,
        KeyAlg::Ed25519 => PublicKeyMaterial::Ed25519 { x: key.to_vec() },
        KeyAlg::Rsa => {
            let rsa = pkcs1::RsaPublicKey::<UintRef<'_>>::from_der(key)
                .map_err(|_| KeyError::Der("malformed RSAPublicKey"))?;
            PublicKeyMaterial::Rsa {
                n: rsa.modulus.as_bytes().to_vec(),
                e: rsa.public_exponent.as_bytes().to_vec(),
            }
        }
        KeyAlg::MlDsa(params) => PublicKeyMaterial::MlDsa {
            params: *params,
            public: key.to_vec(),
        },
    })
}

fn from_pkcs8(der: &[u8]) -> Result<PrivateKey, KeyError> {
    let info = PrivateKeyInfoRef::from_der(der).map_err(|_| KeyError::Der("malformed PKCS#8"))?;
    let alg = key_alg(&info.algorithm)?;
    let inner = info.private_key.as_bytes();
    let key = match &alg {
        KeyAlg::Ec(curve) => from_sec1(inner, Some(*curve))?,
        KeyAlg::Ed25519 => {
            // RFC 8410 §7: CurvePrivateKey ::= OCTET STRING
            let d = <&OctetStringRef>::from_der(inner)
                .map_err(|_| KeyError::Der("malformed CurvePrivateKey"))?;
            private_key(PrivateKeyMaterial::Ed25519 {
                d: d.as_bytes().to_vec(),
            })?
        }
        KeyAlg::Rsa => from_pkcs1_private(inner)?,
        KeyAlg::MlDsa(params) => from_ml_dsa_private(*params, inner)?,
    };
    if let Some(public) = info.public_key {
        let public = public
            .as_bytes()
            .ok_or(KeyError::Der("public key BIT STRING has unused bits"))?;
        if public_material(&alg, public)? != key.public_key().to_material() {
            return Err(KeyError::InconsistentKey(
                "the PKCS#8 public key does not match the private key",
            ));
        }
    }
    Ok(key)
}

/// Validates raw private material and wipes it.
fn private_key(mut material: PrivateKeyMaterial) -> Result<PrivateKey, KeyError> {
    let key = PrivateKey::from_material(&material);
    wipe(&mut material);
    Ok(key?)
}

/// RFC 5915 `ECPrivateKey`. Inside PKCS#8 the curve comes from the
/// algorithm (`outer`); a SEC1 block must name it itself.
fn from_sec1(der: &[u8], outer: Option<Curve>) -> Result<PrivateKey, KeyError> {
    let bad = |_| KeyError::Der("malformed ECPrivateKey");
    let seq = AnyRef::from_der(der).map_err(bad)?;
    if seq.tag() != Tag::Sequence {
        return Err(KeyError::Der("malformed ECPrivateKey"));
    }
    let mut r = SliceReader::new(seq.value()).map_err(bad)?;
    if r.decode::<u8>().map_err(bad)? != 1 {
        return Err(KeyError::Der("ECPrivateKey version must be 1"));
    }
    let d = Zeroizing::new(
        r.decode::<&OctetStringRef>()
            .map_err(bad)?
            .as_bytes()
            .to_vec(),
    );
    let mut curve = None;
    let mut point = None;
    while !r.is_finished() {
        let field = r.decode::<AnyRef<'_>>().map_err(bad)?;
        match field.tag() {
            Tag::ContextSpecific {
                constructed: true,
                number: TagNumber(0),
            } if curve.is_none() && point.is_none() => {
                curve = Some(curve_of(AnyRef::from_der(field.value()).map_err(bad)?)?);
            }
            Tag::ContextSpecific {
                constructed: true,
                number: TagNumber(1),
            } if point.is_none() => {
                let bits = BitStringRef::from_der(field.value()).map_err(bad)?;
                point = Some(bits.as_bytes().ok_or(KeyError::Der("malformed EC point"))?);
            }
            _ => return Err(KeyError::Der("malformed ECPrivateKey")),
        }
    }
    let curve = match (outer, curve) {
        (Some(a), Some(b)) if a != b => {
            return Err(KeyError::InconsistentKey(
                "ECPrivateKey curve differs from the algorithm",
            ));
        }
        (Some(c), _) | (None, Some(c)) => c,
        (None, None) => return Err(KeyError::Der("ECPrivateKey without a curve")),
    };
    let d = left_pad("privateKey", d.to_vec(), curve.field_len())?;
    let key = private_key(PrivateKeyMaterial::Ec { curve, d })?;
    if let Some(point) = point
        && ec_point(curve, point)? != key.public_key().to_material()
    {
        return Err(KeyError::InconsistentKey(
            "the ECPrivateKey public key does not match the private key",
        ));
    }
    Ok(key)
}

fn from_pkcs1_private(der: &[u8]) -> Result<PrivateKey, KeyError> {
    let rsa = pkcs1::RsaPrivateKey::<UintRef<'_>>::from_der(der)
        .map_err(|_| KeyError::Der("malformed RSAPrivateKey"))?;
    if rsa.other_prime_infos.is_some() {
        return Err(KeyError::Der("multi-prime RSA keys are not supported"));
    }
    let v = |u: UintRef<'_>| Some(u.as_bytes().to_vec());
    private_key(PrivateKeyMaterial::Rsa(RsaPrivateMaterial {
        n: rsa.modulus.as_bytes().to_vec(),
        e: rsa.public_exponent.as_bytes().to_vec(),
        d: rsa.private_exponent.as_bytes().to_vec(),
        p: v(rsa.prime1),
        q: v(rsa.prime2),
        dp: v(rsa.exponent1),
        dq: v(rsa.exponent2),
        qi: v(rsa.coefficient),
    }))
}

fn from_pkcs1_public(der: &[u8]) -> Result<PublicKey, KeyError> {
    Ok(PublicKey::from_material(&public_material(
        &KeyAlg::Rsa,
        der,
    )?)?)
}

/// RFC 9881 §6 `ML-DSA-PrivateKey`.
fn from_ml_dsa_private(params: MlDsaParams, der: &[u8]) -> Result<PrivateKey, KeyError> {
    let bad = |_| KeyError::Der("malformed ML-DSA-PrivateKey");
    let choice = AnyRef::from_der(der).map_err(bad)?;
    let (seed, expanded) = match choice.tag() {
        // seed [0] IMPLICIT OCTET STRING (SIZE (32))
        Tag::ContextSpecific {
            constructed: false,
            number: TagNumber(0),
        } => (Some(choice.value()), None),
        Tag::OctetString => (None, Some(choice.value())),
        Tag::Sequence => {
            let mut r = SliceReader::new(choice.value()).map_err(bad)?;
            let seed = r.decode::<&OctetStringRef>().map_err(bad)?.as_bytes();
            let expanded = r.decode::<&OctetStringRef>().map_err(bad)?.as_bytes();
            r.finish().map_err(bad)?;
            (Some(seed), Some(expanded))
        }
        _ => return Err(KeyError::Der("malformed ML-DSA-PrivateKey")),
    };
    if seed.is_some_and(|s| s.len() != MlDsaParams::SEED_LEN) {
        return Err(KeyError::Der("ML-DSA seed must be 32 bytes"));
    }
    if expanded.is_some_and(|e| e.len() != params.expanded_private_key_len()) {
        return Err(KeyError::Der("ML-DSA expanded key has the wrong length"));
    }
    private_key(PrivateKeyMaterial::MlDsa {
        params,
        seed: seed.map(<[u8]>::to_vec),
        expanded: expanded.map(<[u8]>::to_vec),
    })
}

// ------------------------------------------------------------------ export

fn not_applicable(enc: PemEncoding, reason: &'static str) -> KeyError {
    KeyError::FormatNotApplicable {
        format: KeyFormat::Pem(enc),
        reason,
    }
}

fn der_err(_: der::Error) -> KeyError {
    KeyError::Der("DER encoding failed")
}

/// PEM text for one key.
pub(crate) fn export(
    key: &Key,
    enc: PemEncoding,
    visibility: Visibility,
) -> Result<Vec<u8>, KeyError> {
    let public = key.public_key().to_material();
    let kind_ok = matches!(
        (enc, &public),
        (
            PemEncoding::Auto | PemEncoding::Spki | PemEncoding::Pkcs8,
            _
        ) | (PemEncoding::Sec1, PublicKeyMaterial::Ec { .. })
            | (PemEncoding::Pkcs1, PublicKeyMaterial::Rsa { .. })
            | (PemEncoding::Pkcs8MlDsa(_), PublicKeyMaterial::MlDsa { .. })
    );
    if !kind_ok {
        return Err(not_applicable(
            enc,
            "the format does not hold this key type",
        ));
    }
    let (label, der) = match (enc, visibility) {
        (PemEncoding::Auto | PemEncoding::Spki, Visibility::Public) => {
            ("PUBLIC KEY", Zeroizing::new(spki(&public)?))
        }
        (PemEncoding::Pkcs1, Visibility::Public) => {
            ("RSA PUBLIC KEY", Zeroizing::new(rsa_public_key(&public)?))
        }
        (PemEncoding::Spki, Visibility::Private) => {
            return Err(not_applicable(enc, "SPKI holds only public keys"));
        }
        (
            PemEncoding::Pkcs8 | PemEncoding::Pkcs8MlDsa(_) | PemEncoding::Sec1,
            Visibility::Public,
        ) => return Err(not_applicable(enc, "the format holds only private keys")),
        (_, Visibility::Private) => {
            let secret = Secret(
                key.private_key()
                    .ok_or(KeyError::NoPrivateKey)?
                    .to_material(),
            );
            match enc {
                PemEncoding::Sec1 => ("EC PRIVATE KEY", ec_private_key(&secret.0, &public, true)?),
                PemEncoding::Pkcs1 => ("RSA PRIVATE KEY", rsa_private_key(&secret.0)?),
                PemEncoding::Pkcs8MlDsa(form) => ("PRIVATE KEY", pkcs8(&secret.0, &public, form)?),
                _ => {
                    // RFC 9881 §6: the seed form when the seed is known.
                    let form = match secret.0 {
                        PrivateKeyMaterial::MlDsa { seed: None, .. } => MlDsaPrivateForm::Expanded,
                        _ => MlDsaPrivateForm::Seed,
                    };
                    ("PRIVATE KEY", pkcs8(&secret.0, &public, form)?)
                }
            }
        }
    };
    let text = pem_rfc7468::encode_string(label, LineEnding::LF, &der)
        .map_err(|_| KeyError::Pem("PEM encoding failed"))?;
    Ok(text.into_bytes())
}

fn ml_dsa_oid(params: MlDsaParams) -> ObjectIdentifier {
    match params {
        MlDsaParams::MlDsa44 => ID_ML_DSA_44,
        MlDsaParams::MlDsa65 => ID_ML_DSA_65,
        MlDsaParams::MlDsa87 => ID_ML_DSA_87,
    }
}

/// An SPKI algorithm OID, its DER-encoded parameters, and the subject
/// public key.
struct SpkiParts {
    oid: ObjectIdentifier,
    params: Option<Vec<u8>>,
    key: Vec<u8>,
}

/// The SPKI parts of `public`. EC parameters are the curve OID, RSA's a
/// NULL; the others have none.
fn spki_parts(public: &PublicKeyMaterial) -> Result<SpkiParts, KeyError> {
    let (oid, params, key) = match public {
        PublicKeyMaterial::Ec { curve, x, y } => {
            let point = [&[0x04][..], x, y].concat();
            (
                ID_EC_PUBLIC_KEY,
                Some(curve_oid(*curve).to_der().map_err(der_err)?),
                point,
            )
        }
        PublicKeyMaterial::Ed25519 { x } => (ID_ED25519, None, x.clone()),
        PublicKeyMaterial::Rsa { .. } => (
            RSA_ENCRYPTION,
            Some(vec![0x05, 0x00]),
            rsa_public_key(public)?,
        ),
        PublicKeyMaterial::MlDsa { params, public } => (ml_dsa_oid(*params), None, public.clone()),
    };
    Ok(SpkiParts { oid, params, key })
}

fn algorithm<'a>(
    oid: ObjectIdentifier,
    params: Option<&'a [u8]>,
) -> Result<AlgorithmIdentifierRef<'a>, KeyError> {
    Ok(AlgorithmIdentifierRef {
        oid,
        parameters: params.map(AnyRef::from_der).transpose().map_err(der_err)?,
    })
}

fn spki(public: &PublicKeyMaterial) -> Result<Vec<u8>, KeyError> {
    let SpkiParts { oid, params, key } = spki_parts(public)?;
    SubjectPublicKeyInfoRef {
        algorithm: algorithm(oid, params.as_deref())?,
        subject_public_key: BitStringRef::from_bytes(&key).map_err(der_err)?,
    }
    .to_der()
    .map_err(der_err)
}

fn rsa_public_key(public: &PublicKeyMaterial) -> Result<Vec<u8>, KeyError> {
    let PublicKeyMaterial::Rsa { n, e } = public else {
        return Err(KeyError::Der("not an RSA key"));
    };
    pkcs1::RsaPublicKey {
        modulus: UintRef::new(n).map_err(der_err)?,
        public_exponent: UintRef::new(e).map_err(der_err)?,
    }
    .to_der()
    .map_err(der_err)
}

fn uint(v: &Option<Vec<u8>>) -> Result<UintRef<'_>, KeyError> {
    UintRef::new(
        v.as_deref()
            .ok_or(KeyError::Der("RSA key without CRT values"))?,
    )
    .map_err(der_err)
}

fn rsa_private_key(secret: &PrivateKeyMaterial) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    let PrivateKeyMaterial::Rsa(m) = secret else {
        return Err(KeyError::Der("not an RSA key"));
    };
    let key = pkcs1::RsaPrivateKey {
        modulus: UintRef::new(&m.n).map_err(der_err)?,
        public_exponent: UintRef::new(&m.e).map_err(der_err)?,
        private_exponent: UintRef::new(&m.d).map_err(der_err)?,
        prime1: uint(&m.p)?,
        prime2: uint(&m.q)?,
        exponent1: uint(&m.dp)?,
        exponent2: uint(&m.dq)?,
        coefficient: uint(&m.qi)?,
        other_prime_infos: None,
    };
    Ok(Zeroizing::new(key.to_der().map_err(der_err)?))
}

/// `ECPrivateKey` with the public key, and with the curve when
/// `with_curve` (SEC1; PKCS#8 has it in the algorithm), as OpenSSL writes it.
fn ec_private_key(
    secret: &PrivateKeyMaterial,
    public: &PublicKeyMaterial,
    with_curve: bool,
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    let (PrivateKeyMaterial::Ec { curve, d }, PublicKeyMaterial::Ec { x, y, .. }) =
        (secret, public)
    else {
        return Err(KeyError::Der("not an EC key"));
    };
    let point = [&[0x04][..], x, y].concat();
    let key = sec1::EcPrivateKey {
        private_key: d,
        parameters: with_curve.then(|| sec1::EcParameters::NamedCurve(curve_oid(*curve))),
        public_key: Some(&point),
    };
    Ok(Zeroizing::new(key.to_der().map_err(der_err)?))
}

/// PKCS#8 v1 `PrivateKeyInfo`. `form` picks the ML-DSA private key form.
fn pkcs8(
    secret: &PrivateKeyMaterial,
    public: &PublicKeyMaterial,
    form: MlDsaPrivateForm,
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    let SpkiParts { oid, params, .. } = spki_parts(public)?;
    let inner = match secret {
        PrivateKeyMaterial::Ec { .. } => ec_private_key(secret, public, false)?,
        PrivateKeyMaterial::Ed25519 { d } => Zeroizing::new(
            OctetStringRef::new(d)
                .map_err(der_err)?
                .to_der()
                .map_err(der_err)?,
        ),
        PrivateKeyMaterial::Rsa(_) => rsa_private_key(secret)?,
        PrivateKeyMaterial::MlDsa { seed, expanded, .. } => {
            ml_dsa_private_key(seed.as_deref(), expanded.as_deref(), form)?
        }
    };
    let info = PrivateKeyInfoRef::new(
        algorithm(oid, params.as_deref())?,
        OctetStringRef::new(&inner).map_err(der_err)?,
    );
    Ok(Zeroizing::new(info.to_der().map_err(der_err)?))
}

/// RFC 9881 §6 `ML-DSA-PrivateKey` in the requested form.
fn ml_dsa_private_key(
    seed: Option<&[u8]>,
    expanded: Option<&[u8]>,
    form: MlDsaPrivateForm,
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    let expanded = expanded.ok_or(KeyError::Der("ML-DSA key without expanded form"))?;
    let octets = |b: &[u8]| -> Result<Vec<u8>, KeyError> {
        OctetStringRef::new(b)
            .map_err(der_err)?
            .to_der()
            .map_err(der_err)
    };
    Ok(Zeroizing::new(match (form, seed) {
        (MlDsaPrivateForm::Expanded, _) => octets(expanded)?,
        (MlDsaPrivateForm::Seed, Some(seed)) => {
            // [0] IMPLICIT OCTET STRING: retag the OCTET STRING.
            let mut der = octets(seed)?;
            if let Some(tag) = der.first_mut() {
                *tag = 0x80;
            }
            der
        }
        (MlDsaPrivateForm::Both, Some(seed)) => {
            let body = Zeroizing::new([octets(seed)?, octets(expanded)?].concat());
            let len = der::Length::try_from(body.len()).map_err(der_err)?;
            let mut der = der::Header::new(Tag::Sequence, len)
                .to_der()
                .map_err(der_err)?;
            der.extend_from_slice(&body);
            der
        }
        (MlDsaPrivateForm::Seed | MlDsaPrivateForm::Both, None) => {
            return Err(KeyError::MlDsaSeedUnknown);
        }
    }))
}
