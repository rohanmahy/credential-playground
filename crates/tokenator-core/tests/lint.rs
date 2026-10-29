//! Conformance lint (SPEC §6): one input per category.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_core::{
    Category, CheckDetail, CheckItem, DisclosureOp, DocRef, Document, EditDisclosuresRequest,
    Engine, EquivalentEncoding, IssueRequest, KeyInfo, KeyRef, KeySpec, Kind, LintRequest, RawView,
    Status, TamperOp, TamperRequest, TypChoice, ViewOptions,
};

fn lint(e: &Engine, doc: &DocRef, keys: Vec<KeyRef>) -> Vec<CheckItem> {
    e.lint(&LintRequest {
        doc: doc.clone(),
        keys,
    })
    .unwrap()
}

fn lint_doc(e: &Engine, doc: &Document) -> Vec<CheckItem> {
    lint(e, &DocRef::from(doc), vec![])
}

fn with_id<'a>(items: &'a [CheckItem], id: &str) -> Vec<&'a CheckItem> {
    items.iter().filter(|i| i.id == id).collect()
}

fn one<'a>(items: &'a [CheckItem], id: &str) -> &'a CheckItem {
    let found = with_id(items, id);
    assert!(
        !found.is_empty(),
        "no {id} in {:?}",
        items.iter().map(|i| &i.id).collect::<Vec<_>>()
    );
    found[0]
}

fn tampered(e: &Engine, doc: &Document, op: TamperOp) -> Document {
    e.tamper(&TamperRequest {
        doc: DocRef::from(doc),
        op,
        view: ViewOptions::default(),
    })
    .unwrap()
}

fn claims(hex: &str) -> DocRef {
    DocRef::new(Kind::CborClaims, hexd(hex))
}

fn issue(e: &Engine, claims: DocRef, key: &KeyInfo, f: impl FnOnce(&mut IssueRequest)) -> Document {
    let mut req = IssueRequest {
        claims,
        issuer: key.key.clone(),
        alg: None,
        header: Default::default(),
        sd: Default::default(),
        cnf: None,
        jose_serialization: Default::default(),
        cose_tags: None,
        randomness: Some(seed(6)),
        view: ViewOptions::default(),
    };
    f(&mut req);
    e.issue(&req).unwrap()
}

#[test]
fn conforming_tokens_have_no_warnings() {
    let e = engine();
    for name in [
        CWT_TAGGED,
        "rfc7515-a3-jws-es256.txt",
        "rfc9901-s5.1-sd-jwt.txt",
    ] {
        let items = lint_doc(&e, &open_token(&e, name));
        let warns: Vec<_> = items.iter().filter(|i| i.status == Status::Warn).collect();
        assert!(warns.is_empty(), "{name}: {warns:?}");
        assert!(items.iter().all(|i| i.category == Category::Lint));
    }
}

#[test]
fn wide_bstr_head_is_info_on_its_hex_row() {
    let e = engine();
    let doc = tampered(
        &e,
        &open_token(&e, CWT_TAGGED),
        TamperOp::ReencodeProtected {
            how: EquivalentEncoding::WideBstrHead,
        },
    );
    let items = lint_doc(&e, &doc);
    let f = one(&items, "lint.encoding");
    assert_eq!(f.status, Status::Info, "the bstr head is not signed");
    // d2 84 | 58 03 a1 01 26: the head of the protected bstr.
    let raw = f.raw.unwrap();
    assert_eq!((raw.start, raw.end), (2, 4));
    assert_eq!(
        f.detail,
        Some(CheckDetail::Encoding {
            finding: "non_preferred_argument".into(),
            preferred_hex: "43".into(),
        })
    );
    assert_eq!(f.node_ids, [node_id("protected")]);
    let RawView::Hex { rows, .. } = &doc.raw else {
        panic!()
    };
    assert!(
        rows.iter()
            .any(|r| r.head.start == raw.start && r.head.end == raw.end)
    );
}

#[test]
fn non_preferred_signed_contents_warn() {
    let e = engine();
    let doc = tampered(
        &e,
        &open_token(&e, CWT_TAGGED),
        TamperOp::ReencodeProtected {
            how: EquivalentEncoding::WideIntegers,
        },
    );
    let items = lint_doc(&e, &doc);
    let enc = with_id(&items, "lint.encoding");
    assert!(enc.iter().any(|i| i.status == Status::Warn), "{enc:?}");
    assert!(
        enc.iter().all(|i| i
            .node_ids
            .iter()
            .all(|n| n.as_str().starts_with("protected"))),
        "{enc:?}"
    );
}

#[test]
fn indefinite_lengths_are_encoding_findings() {
    let e = engine();
    let items = lint(&e, &claims("bf 01 02 ff"), vec![]);
    let f = one(&items, "lint.encoding");
    assert_eq!(
        f.status,
        Status::Info,
        "drafts need no deterministic encoding"
    );
    assert!(matches!(
        &f.detail,
        Some(CheckDetail::Encoding { finding, preferred_hex })
            if finding == "indefinite_length" && preferred_hex == "a10102"
    ));
}

#[test]
fn nan_and_bignum_findings() {
    let e = engine();
    let items = lint(&e, &claims("a2 01 fa 7f c0 00 00 02 c2 41 01"), vec![]);
    let nan = one(&items, "lint.nan");
    assert_eq!(nan.node_ids, [node_id("1")]);
    assert!(matches!(
        &nan.detail,
        Some(CheckDetail::Encoding { preferred_hex, .. }) if preferred_hex == "f97e00"
    ));
    let big = one(&items, "lint.bignum");
    assert_eq!(big.node_ids, [node_id("2")]);
    assert!(matches!(
        &big.detail,
        Some(CheckDetail::Encoding { preferred_hex, .. }) if preferred_hex == "01"
    ));
    assert!(matches!(nan.status, Status::Info | Status::Warn));
}

#[test]
fn map_order_only_where_required() {
    let e = engine();
    assert!(
        with_id(
            &lint(&e, &claims("a2 02 01 01 02"), vec![]),
            "lint.map_order"
        )
        .is_empty()
    );
    let key = gen_key(&e, KeySpec::P256, 1);
    let cwt = issue(
        &e,
        DocRef::new(Kind::EdnClaims, br#"{2: "b", 1: "a", 58(500): 1}"#.to_vec()),
        &key,
        |_| {},
    );
    let items = lint_doc(&e, &cwt);
    let order = one(&items, "lint.map_order");
    assert_eq!(order.status, Status::Info);
    assert!(order.node_ids.contains(&node_id("payload/~e")), "{order:?}");
}

#[test]
fn duplicate_keys_and_members() {
    let e = engine();
    let items = lint(
        &e,
        &DocRef::new(Kind::JsonClaims, br#"{"a": 1, "b": 2, "a": 3}"#.to_vec()),
        vec![],
    );
    let d = one(&items, "lint.duplicate_key");
    assert_eq!(d.status, Status::Warn);
    assert!(d.node_ids.contains(&node_id("~i2")), "{d:?}");

    let items = lint(&e, &claims("a2 01 01 01 02"), vec![]);
    assert_eq!(one(&items, "lint.duplicate_key").status, Status::Warn);

    // Inside a JWT payload.
    let key = gen_key(&e, KeySpec::P256, 1);
    let jwt = issue(
        &e,
        DocRef::new(Kind::JsonClaims, br#"{"iss": "a", "iss": "b"}"#.to_vec()),
        &key,
        |_| {},
    );
    let items = lint_doc(&e, &jwt);
    assert!(
        one(&items, "lint.duplicate_key")
            .node_ids
            .iter()
            .any(|n| n.as_str().starts_with("payload/~e/"))
    );
}

#[test]
fn alg_key_consistency_for_signing_keys() {
    let e = engine();
    // The RFC 7515 A.3 key, declaring a different alg.
    let mut jwk: serde_json::Value = serde_json::from_slice(&rfc7515_key("A.3").bytes).unwrap();
    jwk["alg"] = "ES384".into();
    let declared = jwk_ref(&jwk.to_string());
    let doc = open_token(&e, "rfc7515-a3-jws-es256.txt");
    let items = lint(&e, &DocRef::from(&doc), vec![declared]);
    assert_eq!(one(&items, "lint.alg_key").status, Status::Warn);
    // A matching key gives nothing.
    let items = lint(&e, &DocRef::from(&doc), vec![rfc7515_key("A.3")]);
    assert!(with_id(&items, "lint.alg_key").is_empty());
    // COSE: the sd-cwt-08 issuer key declares ESP384 (-51), the header says
    // ES384 (-35).
    let doc = open_token(&e, SD_ISSUER);
    let items = lint(&e, &DocRef::from(&doc), vec![sd_issuer_key()]);
    assert_eq!(one(&items, "lint.alg_key").status, Status::Warn);
}

#[test]
fn alg_key_consistency_for_cnf_keys() {
    // A KB signed with an alg the cnf key does not fit.
    let e = engine();
    let issuer = gen_key(&e, KeySpec::P256, 1);
    let holder_p256 = gen_key(&e, KeySpec::P256, 2);
    let holder_ed = gen_key(&e, KeySpec::Ed25519, 3);
    let sd = issue(
        &e,
        DocRef::new(Kind::JsonClaims, br#"{"sub": "x", "email": "y"}"#.to_vec()),
        &issuer,
        |r| {
            r.sd.marks = vec![node_id("email")];
            r.cnf = Some(tokenator_core::CnfChoice::Key {
                key: e.key_public(&holder_p256.key).unwrap().key,
            });
        },
    );
    let presented = e
        .present(&tokenator_core::PresentRequest {
            doc: DocRef::from(&sd),
            keep: vec![0],
            holder: holder_ed.key.clone(),
            alg: None,
            aud: Some("a".into()),
            nonce: Some(tokenator_core::Nonce::Text { value: "n".into() }),
            iat: LATER,
            randomness: None,
            view: ViewOptions::default(),
        })
        .unwrap();
    let items = lint_doc(&e, &presented);
    let f = one(&items, "lint.alg_key");
    assert!(
        f.node_ids.iter().any(|n| n.as_str().contains("cnf")),
        "{f:?}"
    );
}

#[test]
fn typ_rules() {
    let e = engine();
    let key = gen_key(&e, KeySpec::P256, 1);
    let sd_cwt = issue(
        &e,
        DocRef::new(Kind::EdnClaims, br#"{1: "x", 58(500): 1}"#.to_vec()),
        &key,
        |r| r.header.typ = TypChoice::Omit,
    );
    assert_eq!(sd_cwt.kind, Kind::SdCwt);
    assert_eq!(one(&lint_doc(&e, &sd_cwt), "lint.typ").status, Status::Warn);

    let odd = issue(
        &e,
        DocRef::new(Kind::EdnClaims, br#"{1: "x", 58(500): 1}"#.to_vec()),
        &key,
        |r| {
            r.header.typ = TypChoice::Value {
                value: "application/json".into(),
            }
        },
    );
    assert_eq!(one(&lint_doc(&e, &odd), "lint.typ").status, Status::Warn);
}

#[test]
fn crit_not_understood() {
    let e = engine();
    let key = gen_key(&e, KeySpec::P256, 1);
    let jwt = issue(
        &e,
        DocRef::new(Kind::JsonClaims, br#"{"sub": "x"}"#.to_vec()),
        &key,
        |r| r.header.extra = Some(r#"{"crit": ["x-ext"], "x-ext": 1}"#.into()),
    );
    let items = lint_doc(&e, &jwt);
    let f = one(&items, "lint.crit");
    assert_eq!(f.status, Status::Warn);
    assert!(f.node_ids.contains(&node_id("protected/~e/crit")), "{f:?}");
}

#[test]
fn cose_header_rules() {
    let e = engine();
    // 18([h'a0', {1: -7}, h'a1016178', h'00']): empty protected header not
    // zero-length, and alg only unprotected.
    let bytes = hexd("d2 84 41 a0 a1 01 26 44 a1 01 61 78 41 00");
    let items = lint(&e, &DocRef::new(Kind::Cwt, bytes), vec![]);
    let header = with_id(&items, "lint.header");
    assert!(header.len() >= 2, "{items:?}");
    assert!(header.iter().all(|i| i.status == Status::Warn));
}

#[test]
fn short_sd_cwt_salts() {
    let e = engine();
    let doc = e
        .edit_disclosures(&EditDisclosuresRequest {
            doc: DocRef::from(&open_token(&e, SD_ISSUER)),
            ops: vec![DisclosureOp::Forge {
                salt: Some("0011".into()),
                claim: Some("600".into()),
                value: Some("1".into()),
            }],
            randomness: None,
            view: ViewOptions::default(),
        })
        .unwrap();
    let items = lint_doc(&e, &doc);
    let f = one(&items, "lint.salt");
    assert_eq!(f.status, Status::Warn);
    let n = doc.disclosures.len() - 1;
    assert!(
        f.node_ids
            .iter()
            .any(|id| id.as_str().starts_with(&format!("unprotected/17/{n}"))),
        "{f:?}"
    );
}

#[test]
fn json_number_and_utf8_warnings() {
    let e = engine();
    let items = lint(
        &e,
        &DocRef::new(
            Kind::JsonClaims,
            br#"{"big": 12345678901234567890, "huge": 1e400, "tiny": 1e-400}"#.to_vec(),
        ),
        vec![],
    );
    let nums = with_id(&items, "lint.json_number");
    assert_eq!(nums.len(), 3, "{nums:?}");
    assert!(nums.iter().all(|i| i.status == Status::Warn));
    assert_eq!(nums[0].node_ids, [node_id("big")]);

    let items = lint(
        &e,
        &DocRef::new(Kind::JsonClaims, b"{\"a\": \"\xff\"}".to_vec()),
        vec![],
    );
    assert_eq!(one(&items, "lint.json_utf8").node_ids, [node_id("a")]);
}

#[test]
fn lint_matches_validate() {
    let e = engine();
    let names = JOSE_FIXTURES.iter().chain(COSE_FIXTURES.iter());
    for name in names {
        let doc = open_token(&e, name);
        let from_lint = lint_doc(&e, &doc);
        let report = validate(&e, &doc, vec![], LATER);
        let from_validate: Vec<_> = report
            .items
            .into_iter()
            .filter(|i| i.category == Category::Lint)
            .collect();
        assert_eq!(from_lint, from_validate, "{name}");
    }
}

#[test]
fn lint_rejects_keys_documents() {
    let e = engine();
    let err = e
        .lint(&LintRequest {
            doc: DocRef::new(Kind::Jwk, key_file("rfc9901-a5-ec-p256-public.jwk.json")),
            keys: vec![],
        })
        .unwrap_err();
    assert_eq!(err.code, tokenator_core::ErrorCode::UnsupportedKind);
}
