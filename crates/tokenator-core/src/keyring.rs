//! Keys at the boundary: [`KeyRef`] resolution, key cards, and the key
//! panel operations.

use base64ct::{Base64UrlUnpadded, Encoding};
use tokenator_cbor::EncodeMode;
use tokenator_crypto::{Alg, DeclaredAlg, KeyType, MlDsaParams, alg_to_jose, algs_for_key};
use tokenator_keys as tk;
use tokenator_keys::{Key, Kid, ThumbprintKind as TkThumb};

use crate::dto::common::{Bytes, KidValue};
use crate::dto::error::{EngineError, ErrorCode};
use crate::dto::keys::{
    AssignKidRequest, KeyConvertRequest, KeyExport, KeyExportRequest, KeyFormat, KeyGenRequest,
    KeyImportRequest, KeyInfo, KeyRef, KeySeed, KeySpec, KidSource, PemEncoding, Role,
    Thumbprint, ThumbprintKind, ThumbprintRequest, Visibility,
};
use crate::util::{err, hash_alg, hex, rng, seed32, unused_rng};

/// A `tokenator-keys` error as an Engine error.
pub(crate) fn key_error(e: &tk::KeyError) -> EngineError {
    match e {
        tk::KeyError::NoPrivateKey => EngineError::new(ErrorCode::NoPrivateKey, e.to_string()),
        _ => EngineError::new(ErrorCode::Key, e.to_string()),
    }
}

fn tk_format(f: KeyFormat) -> tk::KeyFormat {
    match f {
        KeyFormat::Jwk => tk::KeyFormat::Jwk,
        KeyFormat::JwkSet => tk::KeyFormat::JwkSet,
        KeyFormat::CoseKey => tk::KeyFormat::CoseKey,
        KeyFormat::CoseKeySet => tk::KeyFormat::CoseKeySet,
        KeyFormat::Pem { encoding } => tk::KeyFormat::Pem(match encoding {
            PemEncoding::Auto => tk::PemEncoding::Auto,
            PemEncoding::Spki => tk::PemEncoding::Spki,
            PemEncoding::Pkcs8 => tk::PemEncoding::Pkcs8,
            PemEncoding::Pkcs8MlDsaSeed => tk::PemEncoding::Pkcs8MlDsa(tk::MlDsaPrivateForm::Seed),
            PemEncoding::Pkcs8MlDsaExpanded => {
                tk::PemEncoding::Pkcs8MlDsa(tk::MlDsaPrivateForm::Expanded)
            }
            PemEncoding::Pkcs8MlDsaBoth => tk::PemEncoding::Pkcs8MlDsa(tk::MlDsaPrivateForm::Both),
            PemEncoding::Sec1 => tk::PemEncoding::Sec1,
            PemEncoding::Pkcs1 => tk::PemEncoding::Pkcs1,
        }),
    }
}

fn tk_visibility(v: Visibility) -> tk::Visibility {
    match v {
        Visibility::Public => tk::Visibility::Public,
        Visibility::Private => tk::Visibility::Private,
    }
}

fn tk_role(r: Role) -> tk::Role {
    match r {
        Role::Issuer => tk::Role::Issuer,
        Role::Holder => tk::Role::Holder,
        Role::Verifier => tk::Role::Verifier,
    }
}

/// Imports keys, also reading COSE_Keys and COSE_KeySets written as EDN
/// (SPEC §4.2; `tokenator_keys::import` reads binary CBOR only, #32).
pub(crate) fn import(bytes: &[u8], hint: Option<KeyFormat>) -> Result<Vec<Key>, EngineError> {
    let hint = hint.map(tk_format);
    match tk::import(bytes, hint) {
        Ok(keys) => Ok(keys),
        Err(first) => {
            let cose_hint = matches!(
                hint,
                None | Some(tk::KeyFormat::CoseKey | tk::KeyFormat::CoseKeySet)
            );
            let cbor = std::str::from_utf8(bytes)
                .ok()
                .filter(|_| cose_hint)
                .and_then(|text| tokenator_edn::parse(text).ok())
                .and_then(|item| tokenator_cbor::encode(&item, EncodeMode::Preserve).ok());
            match cbor {
                Some(cbor) => {
                    tk::import(&cbor, Some(tk::KeyFormat::CoseKey)).map_err(|_| key_error(&first))
                }
                None => Err(key_error(&first)),
            }
        }
    }
}

/// The one key a [`KeyRef`] names, with its role.
pub(crate) fn resolve(r: &KeyRef) -> Result<Key, EngineError> {
    let keys = import(&r.bytes, r.format)?;
    let count = keys.len();
    let mut key = usize::try_from(r.index)
        .ok()
        .and_then(|i| keys.into_iter().nth(i))
        .ok_or_else(|| {
            EngineError::new(
                ErrorCode::Key,
                format!("key index {} out of range ({count} keys)", r.index),
            )
        })?;
    if let Some(role) = r.role {
        key.role = Some(tk_role(role));
    }
    Ok(key)
}

/// A private key, or `no_private_key`.
pub(crate) fn resolve_private(r: &KeyRef) -> Result<Key, EngineError> {
    let key = resolve(r)?;
    if key.is_private() {
        Ok(key)
    } else {
        err(ErrorCode::NoPrivateKey, "a private key is needed")
    }
}

/// The JOSE kid string of a key, if any.
pub(crate) fn jose_kid(key: &Key) -> Option<String> {
    key.kid.as_ref().map(Kid::to_jose_string)
}

/// Whether a key can be used with `alg` (wrong size RSA keys still can).
pub(crate) fn fits(key: &Key, alg: Alg) -> bool {
    algs_for_key(&key.public_key().params()).contains(&alg)
}

/// The algorithm to sign with: the requested JOSE name, or one derived from
/// the key (its declared alg when it fits, `Ed25519` for OKP keys, else the
/// first algorithm the key supports).
pub(crate) fn signing_alg(key: &Key, requested: Option<&str>) -> Result<Alg, EngineError> {
    let alg = match requested {
        Some(name) => tokenator_crypto::alg_from_jose(name).ok_or_else(|| {
            EngineError::new(
                ErrorCode::UnsupportedAlg,
                format!("unsupported algorithm {name}"),
            )
        })?,
        None => match &key.alg {
            Some(DeclaredAlg::Known(a)) if fits(key, *a) => *a,
            _ if key.key_type() == KeyType::Okp => Alg::Ed25519,
            _ => algs_for_key(&key.public_key().params())
                .first()
                .copied()
                .ok_or_else(|| {
                    EngineError::new(ErrorCode::UnsupportedAlg, "no algorithm fits the key")
                })?,
        },
    };
    if fits(key, alg) {
        Ok(alg)
    } else {
        err(
            ErrorCode::UnsupportedAlg,
            format!("{} does not fit this key", alg_to_jose(alg)),
        )
    }
}

fn kid_value(kid: &Kid) -> KidValue {
    match kid {
        Kid::Text(t) => KidValue::Text { value: t.clone() },
        Kid::Bytes(b) => KidValue::Bytes {
            value: Bytes(b.clone()),
        },
    }
}

fn param_set_name(p: MlDsaParams) -> &'static str {
    alg_to_jose(p.alg())
}

/// The key card of a key. `label` is echoed into the card's reference.
pub(crate) fn info(key: &Key, label: Option<String>) -> Result<KeyInfo, EngineError> {
    let params = key.public_key().params();
    let crv = params.crv.map(|c| c.jwk_name().to_owned());
    let param_set = params.ml_dsa.map(|p| param_set_name(p).to_owned());
    let description = match (params.kty, &crv, params.rsa_bits, &param_set) {
        (KeyType::Ec, Some(c), _, _) => format!("EC {c}"),
        (KeyType::Rsa, _, Some(bits), _) => format!("RSA {bits}"),
        (_, Some(c), _, _) => c.clone(),
        (_, _, _, Some(s)) => s.clone(),
        (kty, ..) => kty.jwk_kty().to_owned(),
    };
    // A binary kid only survives in a COSE_Key; everything else as a JWK.
    let binary_kid = matches!(key.kid, Some(Kid::Bytes(_)));
    let visibility = if key.is_private() {
        tk::Visibility::Private
    } else {
        tk::Visibility::Public
    };
    let cwk = || tk::to_cwk(key, visibility).map(|c| (c.to_cbor(), KeyFormat::CoseKey));
    let jwk = || tk::to_jwk(key, visibility).map(|j| (j.to_json().into_bytes(), KeyFormat::Jwk));
    // An ML-DSA key known only by its expanded private key has no JWK or
    // COSE_Key private form (both carry the seed): PKCS#8 holds it.
    let pem = || {
        let format = KeyFormat::Pem {
            encoding: PemEncoding::Pkcs8,
        };
        tk::export(key, tk_format(format), visibility).map(|b| (b, format))
    };
    let (bytes, format) = if binary_kid {
        cwk().or_else(|_| pem())
    } else {
        jwk().or_else(|_| pem())
    }
    .map_err(|e| key_error(&e))?;
    let role = key.role.map(|r| match r {
        tk::Role::Issuer => Role::Issuer,
        tk::Role::Holder => Role::Holder,
        tk::Role::Verifier => Role::Verifier,
    });
    let sha256 = tokenator_crypto::HashAlg::Sha256;
    Ok(KeyInfo {
        key: KeyRef {
            bytes: Bytes(bytes),
            format: Some(format),
            index: 0,
            role,
            label,
        },
        kty: params.kty.jwk_kty().to_owned(),
        crv,
        bits: params.rsa_bits,
        param_set,
        description,
        private: key.is_private(),
        kid: key.kid.as_ref().map(kid_value),
        alg: key.alg.as_ref().map(|a| match a {
            DeclaredAlg::Known(a) => alg_to_jose(*a).to_owned(),
            DeclaredAlg::UnknownJose(s) => s.clone(),
            DeclaredAlg::UnknownCose(l) => l.to_string(),
        }),
        algs: algs_for_key(&params)
            .into_iter()
            .map(|a| alg_to_jose(a).to_owned())
            .collect(),
        role,
        jwk_thumbprint: Base64UrlUnpadded::encode_string(&tk::thumbprint(
            key,
            TkThumb::Jwk,
            sha256,
        )),
        jwk_thumbprint_uri: tk::jwk_thumbprint_uri(key, sha256),
        cose_thumbprint: hex(&tk::thumbprint(key, TkThumb::Cose, sha256)),
        cose_thumbprint_uri: tk::cose_thumbprint_uri(key, sha256),
    })
}

pub(crate) fn key_import(req: &KeyImportRequest) -> Result<Vec<KeyInfo>, EngineError> {
    import(&req.bytes, req.format)?
        .iter()
        .map(|k| info(k, None))
        .collect()
}

pub(crate) fn key_export(req: &KeyExportRequest) -> Result<KeyExport, EngineError> {
    let key = resolve(&req.key)?;
    let bytes = tk::export(&key, tk_format(req.format), tk_visibility(req.visibility))
        .map_err(|e| key_error(&e))?;
    let text = match req.format {
        KeyFormat::Jwk | KeyFormat::JwkSet | KeyFormat::Pem { .. } => {
            String::from_utf8(bytes.clone()).ok()
        }
        KeyFormat::CoseKey | KeyFormat::CoseKeySet => None,
    };
    Ok(KeyExport {
        bytes: Bytes(bytes),
        text,
        private: req.visibility == Visibility::Private,
    })
}

pub(crate) fn key_public(r: &KeyRef) -> Result<KeyInfo, EngineError> {
    let key = resolve(r)?;
    info(&tk::to_public(&key), r.label.clone())
}

fn tk_spec(spec: KeySpec) -> tk::KeySpec {
    match spec {
        KeySpec::P256 => tk::KeySpec::P256,
        KeySpec::P384 => tk::KeySpec::P384,
        KeySpec::P521 => tk::KeySpec::P521,
        KeySpec::Ed25519 => tk::KeySpec::Ed25519,
        KeySpec::Rsa { bits } => tk::KeySpec::Rsa { bits },
        KeySpec::MlDsa44 => tk::KeySpec::MlDsa(MlDsaParams::MlDsa44),
        KeySpec::MlDsa65 => tk::KeySpec::MlDsa(MlDsaParams::MlDsa65),
        KeySpec::MlDsa87 => tk::KeySpec::MlDsa(MlDsaParams::MlDsa87),
    }
}

fn tk_kid_source(source: &KidSource) -> tk::KidSource {
    match source {
        KidSource::JwkThumbprint { hash } => tk::KidSource::JwkThumbprint(hash_alg(*hash)),
        KidSource::CoseThumbprint { hash } => tk::KidSource::CoseThumbprint(hash_alg(*hash)),
        KidSource::Text { value } => tk::KidSource::Text(value.clone()),
        KidSource::Bytes { value } => tk::KidSource::Bytes(value.0.clone()),
    }
}

pub(crate) fn key_generate(req: &KeyGenRequest) -> Result<KeyInfo, EngineError> {
    let spec = tk_spec(req.spec);
    let role = req.role.map(tk_role);
    let generated = match &req.seed {
        KeySeed::WellKnown => tk::generate(
            spec,
            role,
            Some(&tk::WELL_KNOWN_TEST_SEED),
            &mut unused_rng(),
        ),
        KeySeed::Seed { bytes } => tk::generate(spec, role, Some(bytes), &mut unused_rng()),
        KeySeed::Entropy { bytes } => {
            let seed = seed32(Some(bytes))?.unwrap_or_default();
            tk::generate(spec, role, None, &mut rng(&seed, "keygen"))
        }
    };
    let mut key = generated.map_err(|e| key_error(&e))?;
    if let Some(source) = &req.kid {
        tk::assign_kid(&mut key, tk_kid_source(source));
    }
    info(&key, None)
}

pub(crate) fn key_thumbprint(req: &ThumbprintRequest) -> Result<Thumbprint, EngineError> {
    let key = resolve(&req.key)?;
    let hash = hash_alg(req.hash);
    let (kind, uri) = match req.kind {
        ThumbprintKind::Jwk => (TkThumb::Jwk, tk::jwk_thumbprint_uri(&key, hash)),
        ThumbprintKind::Cose => (TkThumb::Cose, tk::cose_thumbprint_uri(&key, hash)),
    };
    let tp = tk::thumbprint(&key, kind, hash);
    Ok(Thumbprint {
        kind: req.kind,
        hash: req.hash,
        hex: hex(&tp),
        base64url: Base64UrlUnpadded::encode_string(&tp),
        uri,
    })
}

pub(crate) fn key_assign_kid(req: &AssignKidRequest) -> Result<KeyInfo, EngineError> {
    let mut key = resolve(&req.key)?;
    tk::assign_kid(&mut key, tk_kid_source(&req.source));
    info(&key, req.key.label.clone())
}

pub(crate) fn key_to_jwk(req: &KeyConvertRequest) -> Result<String, EngineError> {
    let key = resolve(&req.key)?;
    Ok(tk::to_jwk(&key, tk_visibility(req.visibility))
        .map_err(|e| key_error(&e))?
        .to_json())
}

/// The COSE_Key bytes for [`Engine::key_to_cwk`](crate::Engine::key_to_cwk).
pub(crate) fn key_to_cwk_bytes(req: &KeyConvertRequest) -> Result<Vec<u8>, EngineError> {
    let key = resolve(&req.key)?;
    Ok(tk::to_cwk(&key, tk_visibility(req.visibility))
        .map_err(|e| key_error(&e))?
        .to_cbor())
}

/// SHA-256 thumbprints a header kid may name: the base64url JWK
/// thumbprint, and the raw COSE thumbprint.
pub(crate) fn thumbprints(key: &Key) -> (String, Vec<u8>) {
    let sha256 = tokenator_crypto::HashAlg::Sha256;
    (
        Base64UrlUnpadded::encode_string(&tk::thumbprint(key, TkThumb::Jwk, sha256)),
        tk::thumbprint(key, TkThumb::Cose, sha256),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edn_cose_keys_import() {
        let edn = "{1: 1, -1: 6, -2: h'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'}";
        let keys = import(edn.as_bytes(), None).unwrap();
        assert_eq!(keys.len(), 1);
        assert!(!keys[0].is_private());
    }
}
