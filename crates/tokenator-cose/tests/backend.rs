//! The `Sign1Backend` seam: high-level operations go through whatever
//! backend they are given.

// Test crate: panicking helpers are intended.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::cell::RefCell;

use common::*;
use tokenator_cose::edit::{
    DisclosureOp, ResignOptions, TamperOp, edit_disclosures, resign, tamper,
};
use tokenator_cose::kbt::{KbtOptions, PresentOptions, Selection, disclose, present, verify_kbt};
use tokenator_cose::lint::{LintOptions, lint};
use tokenator_cose::sd::{FixedSalts, IssueOptions, issue, parse_sd_cwt};
use tokenator_cose::{
    Alg, CborBackend, CoseError, Sign1, Sign1Backend, Sign1Parts, SignOptions, VerifyOptions,
};

/// Delegates to `CborBackend` and records each required-method call.
#[derive(Default)]
struct Spy {
    calls: RefCell<Vec<&'static str>>,
}

impl Spy {
    fn count(&self, name: &str) -> usize {
        self.calls.borrow().iter().filter(|c| **c == name).count()
    }
}

impl Sign1Backend for Spy {
    fn parse<'a>(&self, bytes: &'a [u8]) -> Result<Sign1<'a>, CoseError> {
        self.calls.borrow_mut().push("parse");
        CborBackend.parse(bytes)
    }
    fn sig_structure(&self, protected: &[u8], external_aad: &[u8], payload: &[u8]) -> Vec<u8> {
        self.calls.borrow_mut().push("sig_structure");
        CborBackend.sig_structure(protected, external_aad, payload)
    }
    fn assemble(&self, parts: &Sign1Parts<'_>) -> Result<Vec<u8>, CoseError> {
        self.calls.borrow_mut().push("assemble");
        CborBackend.assemble(parts)
    }
}

/// A backend that builds a COSE_Signature-style `Sig_structure`
/// ("Signature" context), so its signatures differ from RFC 9052 COSE_Sign1.
struct WrongContext;

impl Sign1Backend for WrongContext {
    fn parse<'a>(&self, bytes: &'a [u8]) -> Result<Sign1<'a>, CoseError> {
        CborBackend.parse(bytes)
    }
    fn sig_structure(&self, protected: &[u8], external_aad: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut out = CborBackend.sig_structure(protected, external_aad, payload);
        // 0x6a "Signature1" -> 0x69 "Signature"
        out.splice(1..12, *b"\x69Signature");
        out
    }
    fn assemble(&self, parts: &Sign1Parts<'_>) -> Result<Vec<u8>, CoseError> {
        CborBackend.assemble(parts)
    }
}

#[test]
fn backend_is_object_safe() {
    let backends: [&dyn Sign1Backend; 2] = [&CborBackend, &WrongContext];
    let bytes = token(RFC8392_A3);
    for b in backends {
        assert!(b.parse(&bytes).is_ok());
    }
}

#[test]
fn provided_sign_and_verify_use_required_methods() {
    let spy = Spy::default();
    let key = key_for(Alg::Ed25519, 1);
    let bytes = token(RFC8392_A3);
    let msg = CborBackend.parse(&bytes).unwrap();
    let p = Sign1Parts::from_sign1(&msg).unwrap();
    let out = spy
        .sign(&p, &key, &SignOptions::new(Alg::EdDSA), None)
        .unwrap();
    assert_eq!(spy.count("sig_structure"), 1);
    assert_eq!(spy.count("assemble"), 1);
    let msg = spy.parse(&out).unwrap();
    let opts = VerifyOptions {
        alg: Some(Alg::EdDSA),
        ..VerifyOptions::default()
    };
    assert_eq!(spy.verify(&msg, &key, &opts), Ok(Alg::EdDSA));
    assert_eq!(spy.count("sig_structure"), 2);
}

#[test]
fn wrong_context_backend_is_incompatible() {
    let key = key_for(Alg::ES256, 1);
    let bytes = token(RFC8392_A3);
    let msg = CborBackend.parse(&bytes).unwrap();
    assert_eq!(
        WrongContext.verify(&msg, &rfc8392_key(), &VerifyOptions::default()),
        Err(CoseError::InvalidSignature)
    );
    let p = Sign1Parts::from_sign1(&msg).unwrap();
    let out = WrongContext
        .sign(&p, &key, &SignOptions::new(Alg::ES256), None)
        .unwrap();
    let msg = CborBackend.parse(&out).unwrap();
    assert_eq!(
        WrongContext.verify(&msg, &key, &VerifyOptions::default()),
        Ok(Alg::ES256)
    );
    assert_eq!(
        CborBackend.verify(&msg, &key, &VerifyOptions::default()),
        Err(CoseError::InvalidSignature)
    );
}

#[test]
fn issue_goes_through_backend() {
    let spy = Spy::default();
    let issuer = key_for(Alg::ES256, 1);
    let out = issue(
        &spy,
        &issuer_preissuance(),
        &issuer,
        &IssueOptions::new(Alg::ES256),
        &mut FixedSalts::new(salts_of(&token(SD_ISSUER))),
        None,
    )
    .unwrap();
    assert!(spy.count("sig_structure") >= 1);
    assert!(spy.count("assemble") >= 1);
    // Issued with WrongContext: only WrongContext verifies it.
    let wc = issue(
        &WrongContext,
        &issuer_preissuance(),
        &issuer,
        &IssueOptions::new(Alg::ES256),
        &mut FixedSalts::new(salts_of(&token(SD_ISSUER))),
        None,
    )
    .unwrap();
    for (bytes, good) in [(&out.bytes, true), (&wc.bytes, false)] {
        let msg = CborBackend.parse(bytes).unwrap();
        assert_eq!(
            CborBackend
                .verify(&msg, &issuer, &VerifyOptions::default())
                .is_ok(),
            good
        );
    }
}

#[test]
fn present_and_verify_go_through_backend() {
    let spy = Spy::default();
    let mut opts = PresentOptions::new(Alg::ES256);
    opts.aud = Some(SD_AUD.into());
    opts.iat = Some(SD_KBT_IAT);
    let kbt = present(&spy, &token(SD_ISSUER), &sd_holder(), &opts, None).unwrap();
    assert!(spy.count("parse") >= 1);
    assert!(spy.count("sig_structure") >= 1);
    assert!(spy.count("assemble") >= 1);

    let spy = Spy::default();
    let kopts = KbtOptions {
        now: SD_NOW,
        skew: 60,
        ..KbtOptions::default()
    };
    let report = verify_kbt(&spy, &kbt, Some(&sd_issuer()), &kopts).unwrap();
    assert!(report.is_valid(), "{report:?}");
    assert!(spy.count("parse") >= 1);
    assert!(spy.count("sig_structure") >= 2, "issuer and KBT signatures");

    // The KBT signature was made with CborBackend's Sig_structure.
    let report = verify_kbt(&WrongContext, &kbt, Some(&sd_issuer()), &kopts).unwrap();
    assert_eq!(report.kbt_signature, Err(CoseError::InvalidSignature));
    assert_eq!(report.issuer_signature, Err(CoseError::InvalidSignature));
}

#[test]
fn edit_operations_go_through_backend() {
    let bytes = token(SD_ISSUER);
    let spy = Spy::default();
    resign(&spy, &bytes, &sd_issuer(), &ResignOptions::default(), None).unwrap();
    assert!(spy.count("parse") >= 1 && spy.count("sig_structure") >= 1);

    let spy = Spy::default();
    tamper(&spy, &bytes, &TamperOp::StripSignature).unwrap();
    assert!(spy.count("parse") >= 1);

    let spy = Spy::default();
    edit_disclosures(&spy, &bytes, &[DisclosureOp::Remove(0)]).unwrap();
    assert!(spy.count("parse") >= 1);

    let spy = Spy::default();
    disclose(&spy, &bytes, &Selection::None).unwrap();
    assert!(spy.count("parse") >= 1);

    let spy = Spy::default();
    lint(&spy, &bytes, &LintOptions::default()).unwrap();
    assert!(spy.count("parse") >= 1);

    let spy = Spy::default();
    parse_sd_cwt(&spy, &bytes).unwrap();
    assert_eq!(spy.count("parse"), 1);
}
