//! Redaction and issuance (sd-cwt-08 §4.1, §6, §10, §11): the draft
//! examples are reproduced byte for byte from pre-issuance claims and the
//! fixture salts.

// Test crate: panicking helpers are intended.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::borrow::Cow;

use common::*;
use tokenator_cbor::{Item, Value, Width, decode};
use tokenator_cose::sd::{
    FixedSalts, IssueOptions, RedactWarning, RngSalts, SaltRequest, SaltSource, Typ,
    encode_disclosure, issue, redact,
};
use tokenator_cose::{
    Alg, ContentType, CoseError, HashAlg, Label, RedactionError, Sign1Backend, VerifyOptions,
};
use tokenator_crypto::rand_core::Rng;

/// Records every request and hands out salts `[ordinal; 16]`.
#[derive(Default)]
struct Recorder {
    requests: Vec<SaltRequest>,
}

impl SaltSource for Recorder {
    fn salt(&mut self, req: &SaltRequest) -> Result<Vec<u8>, CoseError> {
        self.requests.push(req.clone());
        Ok(vec![u8::try_from(req.ordinal).unwrap(); 16])
    }
}

fn fixed(name: &str) -> FixedSalts {
    FixedSalts::new(salts_of(&token(name)))
}

fn err(claims: &Item<'_>) -> RedactionError {
    match redact(claims, HashAlg::Sha256, &mut Recorder::default()) {
        Err(CoseError::Redaction(e)) => e,
        other => panic!("expected a redaction error, got {other:?}"),
    }
}

fn claims_of(extra: Vec<(Item<'static>, Item<'static>)>) -> Item<'static> {
    let mut m = sd_standard_claims();
    m.extend(extra);
    map(m)
}

// ------------------------------------------------------------ draft examples

#[test]
fn redact_reproduces_issuer_example() {
    let fx = token(SD_ISSUER);
    let r = redact(
        &issuer_preissuance(),
        HashAlg::Sha256,
        &mut fixed(SD_ISSUER),
    )
    .unwrap();
    assert_eq!(enc(&r.payload), payload_of(&fx));
    assert_eq!(r.disclosures, disclosures_of(&fx));
    assert!(r.warnings.is_empty());
}

#[test]
fn redact_reproduces_nested_example() {
    let fx = token(SD_NESTED_ISSUER);
    let r = redact(
        &nested_preissuance(),
        HashAlg::Sha256,
        &mut fixed(SD_NESTED_ISSUER),
    )
    .unwrap();
    assert_eq!(r.disclosures.len(), 15);
    assert_eq!(r.disclosures, disclosures_of(&fx));
    assert_eq!(enc(&r.payload), payload_of(&fx));
}

#[test]
fn redact_reproduces_decoy_example() {
    let fx = token(SD_DECOY);
    let r = redact(&decoy_preissuance(), HashAlg::Sha256, &mut fixed(SD_DECOY)).unwrap();
    assert_eq!(r.disclosures, disclosures_of(&fx));
    assert_eq!(enc(&r.payload), payload_of(&fx));
}

#[test]
fn issue_reproduces_issuer_example_headers() {
    let fx = token(SD_ISSUER);
    let issuer = sd_issuer();
    let mut opts = IssueOptions::new(Alg::ES384);
    opts.kid = Some(Cow::Borrowed(SD_ISSUER_KID));
    let out = issue(
        &B,
        &issuer_preissuance(),
        &issuer,
        &opts,
        &mut fixed(SD_ISSUER),
        None,
    )
    .unwrap();
    assert_eq!(protected_of(&out.bytes), protected_of(&fx));
    assert_eq!(unprotected_of(&out.bytes), unprotected_of(&fx));
    assert_eq!(payload_of(&out.bytes), payload_of(&fx));
    assert_eq!(out.disclosures, disclosures_of(&fx));
    assert_eq!(elements(&out.bytes).0, [18]);
    let msg = B.parse(&out.bytes).unwrap();
    assert_eq!(
        B.verify(&msg, &public(&issuer), &VerifyOptions::default()),
        Ok(Alg::ES384)
    );
    // Deterministic ECDSA: issuing again gives the same bytes.
    let again = issue(
        &B,
        &issuer_preissuance(),
        &issuer,
        &opts,
        &mut fixed(SD_ISSUER),
        None,
    )
    .unwrap();
    assert_eq!(again.bytes, out.bytes);
}

#[test]
fn issue_reproduces_nested_and_decoy_headers() {
    for (name, claims) in [
        (SD_NESTED_ISSUER, nested_preissuance()),
        (SD_DECOY, decoy_preissuance()),
    ] {
        let fx = token(name);
        let mut opts = IssueOptions::new(Alg::ES384);
        opts.kid = Some(Cow::Borrowed(SD_ISSUER_KID));
        let out = issue(&B, &claims, &sd_issuer(), &opts, &mut fixed(name), None).unwrap();
        assert_eq!(protected_of(&out.bytes), protected_of(&fx), "{name}");
        assert_eq!(unprotected_of(&out.bytes), unprotected_of(&fx), "{name}");
        assert_eq!(payload_of(&out.bytes), payload_of(&fx), "{name}");
    }
}

// ------------------------------------------------------------ salts

#[test]
fn salt_requests_are_post_order_with_decoy_numbers() {
    let mut rec = Recorder::default();
    redact(&decoy_preissuance(), HashAlg::Sha256, &mut rec).unwrap();
    let got: Vec<(usize, Option<u64>)> =
        rec.requests.iter().map(|r| (r.ordinal, r.decoy)).collect();
    assert_eq!(got, [(0, None), (1, Some(1)), (2, None), (3, Some(2))]);

    let mut rec = Recorder::default();
    let r = redact(&nested_preissuance(), HashAlg::Sha256, &mut rec).unwrap();
    assert_eq!(rec.requests.len(), 15);
    // The salt of disclosure i is [i; 16].
    for (i, d) in r.disclosures.iter().enumerate() {
        let Value::Array(a) = decode(d).unwrap().value else {
            panic!()
        };
        assert_eq!(bstr_of(&a[0]), vec![u8::try_from(i).unwrap(); 16]);
    }
}

#[test]
fn rng_salts_are_16_bytes_from_fill_bytes() {
    let mut r1 = rng(5);
    let a = redact(
        &issuer_preissuance(),
        HashAlg::Sha256,
        &mut RngSalts::new(&mut r1),
    )
    .unwrap();
    let mut r2 = rng(5);
    let b = redact(
        &issuer_preissuance(),
        HashAlg::Sha256,
        &mut RngSalts::new(&mut r2),
    )
    .unwrap();
    assert_eq!(a, b, "seeded salts are reproducible");

    let mut expect = rng(5);
    for d in &a.disclosures {
        let mut salt = [0u8; 16];
        expect.fill_bytes(&mut salt);
        let Value::Array(items) = decode(d).unwrap().value else {
            panic!()
        };
        assert_eq!(bstr_of(&items[0]), salt);
    }

    let mut r3 = rng(6);
    let c = redact(
        &issuer_preissuance(),
        HashAlg::Sha256,
        &mut RngSalts::new(&mut r3),
    )
    .unwrap();
    assert_ne!(a.disclosures, c.disclosures);
}

#[test]
fn fixed_salts_run_out() {
    let mut few = FixedSalts::new(vec![vec![0; 16]; 2]);
    assert_eq!(
        redact(&issuer_preissuance(), HashAlg::Sha256, &mut few).unwrap_err(),
        CoseError::SaltExhausted
    );
}

#[test]
fn short_salts_are_allowed_with_a_warning() {
    let mut salts = FixedSalts::new(vec![vec![7; 8]]);
    let claims = claims_of(vec![(tbr(int(500)), tru())]);
    let r = redact(&claims, HashAlg::Sha256, &mut salts).unwrap();
    assert_eq!(r.warnings, [RedactWarning::SaltLength(8)]);
    assert_eq!(
        r.disclosures[0],
        encode_disclosure(&[7; 8], Some(&tru()), Some(&int(500)))
    );
}

// ------------------------------------------------------------ structure

#[test]
fn digests_use_the_requested_hash() {
    for hash in [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512] {
        let claims = claims_of(vec![
            (tbr(int(500)), tru()),
            (int(98), arr(vec![tbr(text("fr"))])),
        ]);
        let r = redact(&claims, hash, &mut Recorder::default()).unwrap();
        let Value::Map(entries) = &r.payload.value else {
            panic!()
        };
        // ..., 98: [60(d1)], simple(59): [d0]
        let (k, v) = entries.last().unwrap();
        assert_eq!(enc(k), enc(&simple(59)));
        let Value::Array(digests) = &v.value else {
            panic!()
        };
        let want = tokenator_crypto::digest(hash, &bstr_item(&r.disclosures[0]));
        assert_eq!(want.len(), hash.output_len());
        assert_eq!(bstr_of(&digests[0]), want);

        let (_, countries) = &entries[entries.len() - 2];
        let Value::Array(c) = &countries.value else {
            panic!()
        };
        let Value::Tag(60, inner) = &c[0].value else {
            panic!()
        };
        assert_eq!(
            bstr_of(inner),
            tokenator_crypto::digest(hash, &bstr_item(&r.disclosures[1]))
        );
    }
}

#[test]
fn redacted_keys_go_last_in_key_order() {
    // {1: "a", 58(2): "b", 3: "c", 58("x"): "d", 62(7): null, 4: "e"}
    let claims = map(vec![
        (int(1), text("a")),
        (tbr(int(2)), text("b")),
        (int(3), text("c")),
        (tbr(text("x")), text("d")),
        (decoy(7), null()),
        (int(4), text("e")),
    ]);
    let r = redact(&claims, HashAlg::Sha256, &mut Recorder::default()).unwrap();
    let d: Vec<Item> = r
        .disclosures
        .iter()
        .map(|c| bs(&sha256(&bstr_item(c))))
        .collect();
    let want = map(vec![
        (int(1), text("a")),
        (int(3), text("c")),
        (int(4), text("e")),
        (simple(59), arr(d)),
    ]);
    assert_eq!(enc(&r.payload), enc(&want));
    assert_eq!(
        r.disclosures,
        [
            encode_disclosure(&[0; 16], Some(&text("b")), Some(&int(2))),
            encode_disclosure(&[1; 16], Some(&text("d")), Some(&text("x"))),
            encode_disclosure(&[2; 16], None, None),
        ]
    );
}

#[test]
fn nested_redaction_inside_elements_and_other_tags() {
    // {1: [58([58(10), 11])], 2: 100([58(5)])}
    let claims = map(vec![
        (int(1), arr(vec![tbr(arr(vec![tbr(int(10)), int(11)]))])),
        (int(2), tag(100, arr(vec![tbr(int(5))]))),
    ]);
    let r = redact(&claims, HashAlg::Sha256, &mut Recorder::default()).unwrap();
    assert_eq!(r.disclosures.len(), 3);
    let d0 = encode_disclosure(&[0; 16], Some(&int(10)), None);
    assert_eq!(r.disclosures[0], d0);
    let inner = arr(vec![tag(60, bs(&sha256(&bstr_item(&d0)))), int(11)]);
    let d1 = encode_disclosure(&[1; 16], Some(&inner), None);
    assert_eq!(r.disclosures[1], d1);
    let d2 = encode_disclosure(&[2; 16], Some(&int(5)), None);
    assert_eq!(r.disclosures[2], d2);
    let want = map(vec![
        (int(1), arr(vec![tag(60, bs(&sha256(&bstr_item(&d1))))])),
        (
            int(2),
            tag(100, arr(vec![tag(60, bs(&sha256(&bstr_item(&d2))))])),
        ),
    ]);
    assert_eq!(enc(&r.payload), enc(&want));
}

#[test]
fn no_markers_means_no_disclosures() {
    let bytes = token(RFC8392_A1);
    let claims = decode(&bytes).unwrap();
    let r = redact(&claims, HashAlg::Sha256, &mut Recorder::default()).unwrap();
    assert!(r.disclosures.is_empty());
    assert_eq!(enc(&r.payload), bytes);
}

#[test]
fn copied_items_keep_their_encoding() {
    // {0x18 0x01: "a", 58(0x19 0x01f5): 0x1a 0x00000005}
    let key = Item::int(501).with_width(Width::U32);
    let claims = map(vec![
        (Item::int(1).with_width(Width::U8), text("a")),
        (tbr(key.clone()), Item::int(5).with_width(Width::U32)),
    ]);
    let r = redact(&claims, HashAlg::Sha256, &mut Recorder::default()).unwrap();
    assert_eq!(
        r.disclosures[0],
        [h("83 50"), vec![0; 16], h("1a00000005 1a000001f5")].concat()
    );
    let enc_payload = enc(&r.payload);
    assert_eq!(&enc_payload[..5], h("a2 1801 6161"));
}

#[test]
fn encode_disclosure_shapes() {
    let salt = h("bae611067bb823486797da1ebbb52f83");
    assert_eq!(
        encode_disclosure(&salt, Some(&text("ABCD-123456")), Some(&int(501))),
        h("8350bae611067bb823486797da1ebbb52f836b414243442d3132333435361901f5")
    );
    assert_eq!(
        encode_disclosure(&salt, Some(&int(1)), None),
        [h("8250"), salt.clone(), h("01")].concat()
    );
    assert_eq!(
        encode_disclosure(&salt, None, None),
        [h("8150"), salt.clone()].concat()
    );
    assert_eq!(
        encode_disclosure(&salt, None, Some(&int(1))),
        [h("8150"), salt].concat()
    );
}

// ------------------------------------------------------------ warnings

#[test]
fn never_redacted_claims_warn() {
    let claims = map(vec![
        (tbr(int(8)), holder_cnf()),
        (tbr(int(2)), text("sub may be redacted")),
        (int(503), map(vec![(tbr(int(1)), text("not top level"))])),
        (tbr(int(39)), bs(b"cnonce")),
    ]);
    let r = redact(&claims, HashAlg::Sha256, &mut Recorder::default()).unwrap();
    assert_eq!(
        r.warnings,
        [
            RedactWarning::NeverRedactedClaim(8),
            RedactWarning::NeverRedactedClaim(39)
        ]
    );
    assert_eq!(r.disclosures.len(), 4);
}

#[test]
fn indefinite_lengths_warn_and_are_kept() {
    // {_ 1: [_ 58(2)]}
    let mut inner = arr(vec![tbr(int(2))]);
    inner.width = Width::Indefinite;
    let mut claims = map(vec![(int(1), inner)]);
    claims.width = Width::Indefinite;
    let r = redact(&claims, HashAlg::Sha256, &mut Recorder::default()).unwrap();
    assert_eq!(r.warnings, [RedactWarning::IndefiniteLength]);
    let out = enc(&r.payload);
    assert_eq!(out[0], 0xbf);
    assert_eq!(out[2], 0x9f);
}

// ------------------------------------------------------------ errors

#[test]
fn redaction_errors() {
    assert_eq!(err(&arr(vec![])), RedactionError::NotAMap);
    assert_eq!(err(&tbr(map(vec![]))), RedactionError::NotAMap);
    assert_eq!(
        err(&map(vec![
            (int(500), text("a")),
            (tbr(int(500)), text("b"))
        ])),
        RedactionError::DuplicateKey(Label::Int(500))
    );
    assert_eq!(
        err(&map(vec![(tbr(text("k")), int(1)), (text("k"), int(2))])),
        RedactionError::DuplicateKey(Label::Text("k".into()))
    );
    assert_eq!(
        err(&map(vec![
            (int(1), int(1)),
            (Item::int(1).with_width(Width::U8), int(2))
        ])),
        RedactionError::DuplicateKey(Label::Int(1))
    );
    assert_eq!(
        err(&map(vec![(tbr(tbr(int(1))), int(1))])),
        RedactionError::NestedTag
    );
    assert_eq!(
        err(&map(vec![(tbr(decoy(1)), null())])),
        RedactionError::NestedTag
    );
    assert_eq!(
        err(&map(vec![(tbr(bs(b"k")), int(1))])),
        RedactionError::InvalidRedactedKey
    );
    assert_eq!(
        err(&map(vec![(tbr(text("")), int(1))])),
        RedactionError::InvalidRedactedKey
    );
    let long = "x".repeat(256);
    assert_eq!(
        err(&map(vec![(tbr(Item::text(long.clone())), int(1))])),
        RedactionError::InvalidRedactedKey
    );
    assert_eq!(
        err(&map(vec![(bs(b"k"), int(1))])),
        RedactionError::InvalidMapKey
    );
    assert_eq!(
        err(&map(vec![(tag(1, int(5)), int(1))])),
        RedactionError::InvalidMapKey
    );
    assert_eq!(
        err(&map(vec![(int(1), tbr(int(2)))])),
        RedactionError::TagOnMapValue(58)
    );
    assert_eq!(
        err(&map(vec![(int(1), decoy(1))])),
        RedactionError::TagOnMapValue(62)
    );
    assert_eq!(
        err(&map(vec![(decoy(0), null())])),
        RedactionError::InvalidDecoy
    );
    assert_eq!(
        err(&map(vec![(tag(62, text("x")), null())])),
        RedactionError::InvalidDecoy
    );
    assert_eq!(
        err(&map(vec![(decoy(1), int(5))])),
        RedactionError::InvalidDecoy
    );
    assert_eq!(
        err(&map(vec![(int(1), arr(vec![decoy(0)]))])),
        RedactionError::InvalidDecoy
    );
    assert_eq!(
        err(&map(vec![
            (int(1), arr(vec![decoy(1)])),
            (decoy(1), null())
        ])),
        RedactionError::DuplicateDecoy(1)
    );
    // Errors deep inside are found too.
    assert_eq!(
        err(&map(vec![(
            int(1),
            arr(vec![tbr(map(vec![(int(2), tbr(int(3)))]))])
        )])),
        RedactionError::TagOnMapValue(58)
    );
}

#[test]
fn long_but_legal_text_key() {
    let k = "y".repeat(255);
    let claims = map(vec![(tbr(Item::text(k)), int(1))]);
    assert!(redact(&claims, HashAlg::Sha256, &mut Recorder::default()).is_ok());
}

// ------------------------------------------------------------ issue options

#[test]
fn issue_plain_cwt() {
    let key = key_for(Alg::ES256, 1);
    let bytes = token(RFC8392_A1);
    let claims = decode(&bytes).unwrap();
    let out = issue(
        &B,
        &claims,
        &key,
        &IssueOptions::new(Alg::ES256),
        &mut Recorder::default(),
        None,
    )
    .unwrap();
    assert!(out.disclosures.is_empty());
    assert_eq!(protected_of(&out.bytes), h("a10126"));
    assert_eq!(unprotected_of(&out.bytes), h("a0"));
    assert_eq!(payload_of(&out.bytes), bytes);
    let msg = B.parse(&out.bytes).unwrap();
    assert_eq!(msg.kind(), tokenator_cose::TokenKind::Cwt);
    assert_eq!(
        B.verify(&msg, &key, &VerifyOptions::default()),
        Ok(Alg::ES256)
    );
}

#[test]
fn issue_force_sd_without_redactions() {
    let key = key_for(Alg::Ed25519, 1);
    let mut opts = IssueOptions::new(Alg::Ed25519);
    opts.force_sd = true;
    let out = issue(
        &B,
        &claims_of(vec![]),
        &key,
        &opts,
        &mut Recorder::default(),
        None,
    )
    .unwrap();
    // {1: -19, 16: 293, 170: -16}
    assert_eq!(protected_of(&out.bytes), h("a3 01 32 10 190125 18aa 2f"));
    assert_eq!(unprotected_of(&out.bytes), h("a0"));
    assert_eq!(
        B.parse(&out.bytes).unwrap().kind(),
        tokenator_cose::TokenKind::SdCwt
    );
}

#[test]
fn issue_header_options() {
    let key = key_for(Alg::ES256, 1);
    let claims = claims_of(vec![(tbr(int(500)), tru())]);

    let mut opts = IssueOptions::new(Alg::ES256);
    opts.typ = Typ::Omit;
    opts.sd_alg = None;
    let out = issue(&B, &claims, &key, &opts, &mut Recorder::default(), None).unwrap();
    assert_eq!(protected_of(&out.bytes), h("a10126"));
    // Without sd_alg the digests are SHA-256.
    let payload = payload_of(&out.bytes);
    assert!(
        payload
            .windows(32)
            .any(|w| w == sha256(&bstr_item(&out.disclosures[0])))
    );

    let mut opts = IssueOptions::new(Alg::ES256);
    opts.typ = Typ::Value(ContentType::Text("application/sd-cwt".into()));
    opts.sd_alg = Some(HashAlg::Sha384);
    opts.kid = Some(Cow::Borrowed(b"k1"));
    opts.tags = vec![61, 18];
    opts.protected_extra = vec![(int(3), text("application/cwt"))];
    opts.unprotected_extra = vec![(int(99), int(1))];
    let out = issue(&B, &claims, &key, &opts, &mut Recorder::default(), None).unwrap();
    let want_prot = map(vec![
        (int(1), int(-7)),
        (int(4), bs(b"k1")),
        (int(16), text("application/sd-cwt")),
        (int(170), int(-43)),
        (int(3), text("application/cwt")),
    ]);
    assert_eq!(protected_of(&out.bytes), enc(&want_prot));
    let want_unprot = map(vec![
        (
            int(17),
            arr(out.disclosures.iter().map(|d| bs(d)).collect()),
        ),
        (int(99), int(1)),
    ]);
    assert_eq!(unprotected_of(&out.bytes), enc(&want_unprot));
    assert_eq!(elements(&out.bytes).0, [61, 18]);
    assert!(
        payload_of(&out.bytes).windows(48).any(
            |w| w == tokenator_crypto::digest(HashAlg::Sha384, &bstr_item(&out.disclosures[0]))
        )
    );

    let mut opts = IssueOptions::new(Alg::ES256);
    opts.tags = vec![];
    let out = issue(&B, &claims, &key, &opts, &mut Recorder::default(), None).unwrap();
    assert!(elements(&out.bytes).0.is_empty());
}

#[test]
fn issue_external_aad() {
    let key = key_for(Alg::ES256, 1);
    let mut opts = IssueOptions::new(Alg::ES256);
    opts.external_aad = Cow::Borrowed(b"aad");
    let out = issue(
        &B,
        &claims_of(vec![]),
        &key,
        &opts,
        &mut Recorder::default(),
        None,
    )
    .unwrap();
    let msg = B.parse(&out.bytes).unwrap();
    assert_eq!(
        B.verify(&msg, &key, &VerifyOptions::default()),
        Err(CoseError::InvalidSignature)
    );
    let v = VerifyOptions {
        external_aad: b"aad",
        ..VerifyOptions::default()
    };
    assert_eq!(B.verify(&msg, &key, &v), Ok(Alg::ES256));
}

#[test]
fn issue_errors_and_warnings() {
    let claims = claims_of(vec![(tbr(int(8)), int(1))]);
    let key = key_for(Alg::ES256, 1);
    let out = issue(
        &B,
        &claims,
        &key,
        &IssueOptions::new(Alg::ES256),
        &mut Recorder::default(),
        None,
    )
    .unwrap();
    assert_eq!(out.warnings, [RedactWarning::NeverRedactedClaim(8)]);

    assert!(matches!(
        issue(
            &B,
            &claims,
            &key,
            &IssueOptions::new(Alg::ES384),
            &mut Recorder::default(),
            None
        ),
        Err(CoseError::KeyNotSuitable { .. })
    ));
    assert_eq!(
        issue(
            &B,
            &claims,
            &public(&key),
            &IssueOptions::new(Alg::ES256),
            &mut Recorder::default(),
            None
        )
        .unwrap_err(),
        CoseError::NoPrivateKey
    );
    assert!(matches!(
        issue(
            &B,
            &arr(vec![]),
            &key,
            &IssueOptions::new(Alg::ES256),
            &mut Recorder::default(),
            None
        ),
        Err(CoseError::Redaction(RedactionError::NotAMap))
    ));
}
