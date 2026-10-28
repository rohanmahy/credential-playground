//! COSE_Sign1, CWT, SD-CWT, and SD-KBT.
//!
//! Everything here works on the original bytes: a parsed [`Sign1`] keeps the
//! exact protected header, payload, and signature bytes with their spans, and
//! signatures and disclosure digests are always computed over those bytes.
//! The crate does no I/O; time and randomness are always passed in.
//!
//! - [`Sign1Backend`] is the seam for COSE_Sign1 parsing, `Sig_structure`
//!   construction, assembly, signing, and verification. [`CborBackend`] is the
//!   span-preserving default built on `tokenator-cbor`.
//! - [`claims`]: CWT claims, time claims, and `cnf` (RFC 8392, RFC 8747).
//! - [`sd`]: SD-CWT redaction, disclosures, digests, and disclosure matching
//!   (draft-ietf-spice-sd-cwt-08).
//! - [`kbt`]: presenting an SD-CWT (or a plain CWT) in an SD-KBT, and
//!   verifying one.
//! - [`edit`]: re-signing and deliberate tampering.
//! - [`lint`]: conformance facts for the core's linter.
//!
//! The codepoints used are in [`codepoints`].
//!
//! Verifying the RFC 8392 A.3 signed CWT and checking its time claims:
//!
//! ```
//! use tokenator_cose::claims::{TimeOptions, check_times, claim};
//! use tokenator_cose::{Alg, CborBackend, Label, Sign1Backend, TokenKind, VerifyOptions};
//!
//! let token = include_bytes!("../../../testdata/tokens/rfc8392-a3-signed-cwt.cbor");
//! let key_file = include_bytes!("../../../testdata/keys/rfc8392-a2.3-ec-p256.cosekey.cbor");
//! let key = &tokenator_keys::import(key_file, None)?[0];
//!
//! let msg = CborBackend.parse(token)?;
//! assert_eq!(msg.tags, [18]);
//! assert_eq!(msg.kind(), TokenKind::Cwt);
//! assert_eq!(msg.kid(), Some(&b"AsymmetricECDSA256"[..]));
//! assert_eq!(CborBackend.verify(&msg, key, &VerifyOptions::default())?, Alg::ES256);
//!
//! let claims = msg.payload_item().ok_or("no claims")?;
//! let sub = claim(claims, &Label::Int(2)).ok_or("no sub")?;
//! assert_eq!(sub.value, tokenator_cose::Value::Text("erikw".into()));
//! // RFC 8392 A.1: exp 1444064944.
//! let at = |now| check_times(claims, &TimeOptions { now, skew: 60 }).is_ok();
//! assert!(at(1_444_000_000));
//! assert!(!at(1_444_064_944 + 60));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Issuing an SD-CWT from claims marked to be redacted, presenting one
//! disclosure in an SD-KBT, and verifying it as a Verifier:
//!
//! ```
//! use std::borrow::Cow;
//!
//! use rand_chacha::ChaCha20Rng;
//! use tokenator_cose::claims::claim;
//! use tokenator_cose::kbt::{KbtOptions, PresentOptions, Selection, present, verify_kbt};
//! use tokenator_cose::sd::{IssueOptions, RngSalts, issue};
//! use tokenator_cose::{Alg, CborBackend, Item, Label, Value};
//! use tokenator_crypto::{KeySpec, rand_core::SeedableRng};
//! use tokenator_keys::{Visibility, generate, to_cwk, to_public};
//!
//! let mut rng = ChaCha20Rng::from_seed([7; 32]);
//! let issuer = generate(KeySpec::for_alg(Alg::ES256), None, Some(&[1; 32]), &mut rng)?;
//! let holder = generate(KeySpec::for_alg(Alg::Ed25519), None, Some(&[2; 32]), &mut rng)?;
//!
//! // {1: "https://issuer.example", 8: {1: COSE_Key},
//! //  58(500): "secret", 501: [58("a"), "b"]}
//! let cnf = to_cwk(&holder, Visibility::Public)?;
//! let claims = Item::map(vec![
//!     (Item::int(1), Item::text("https://issuer.example")),
//!     (Item::int(8), Item::map(vec![(Item::int(1), cnf.item().clone())])),
//!     (Item::tag(58, Item::int(500)), Item::text("secret")),
//!     (
//!         Item::int(501),
//!         Item::array(vec![Item::tag(58, Item::text("a")), Item::text("b")]),
//!     ),
//! ]);
//! let opts = IssueOptions::new(Alg::ES256);
//! let sd_cwt = issue(&CborBackend, &claims, &issuer, &opts, &mut RngSalts::new(&mut rng), None)?;
//! // Disclosures in creation order: the claim 500, then the element "a".
//! assert_eq!(sd_cwt.disclosures.len(), 2);
//!
//! // The holder presents only claim 500.
//! let mut present_opts = PresentOptions::new(Alg::Ed25519);
//! present_opts.selection = Selection::Indices(vec![0]);
//! present_opts.aud = Some("https://verifier.example".into());
//! present_opts.iat = Some(1_800_000_000);
//! present_opts.cnonce = Some(Cow::Borrowed(b"nonce"));
//! let kbt = present(&CborBackend, &sd_cwt.bytes, &holder, &present_opts, None)?;
//!
//! let verify_opts = KbtOptions {
//!     now: 1_800_000_010,
//!     skew: 60,
//!     expected_aud: Some("https://verifier.example".into()),
//!     expected_cnonce: Some(Cow::Borrowed(b"nonce")),
//!     ..KbtOptions::default()
//! };
//! let report = verify_kbt(&CborBackend, &kbt, Some(&to_public(&issuer)), &verify_opts)?;
//! assert!(report.is_valid(), "{report:?}");
//! assert_eq!(report.kbt_signature, Ok(Alg::Ed25519));
//!
//! // The element "a" was withheld; claim 500 is back in the claims set.
//! let sd = report.sd.as_ref().ok_or("no SD report")?;
//! assert_eq!(sd.undisclosed.len(), 1);
//! let processed = sd.processed.as_ref().ok_or("no claims")?;
//! let secret = claim(processed, &Label::Int(500)).map(|v| &v.value);
//! assert_eq!(secret, Some(&Value::Text("secret".into())));
//! let Some(Value::Array(elements)) = claim(processed, &Label::Int(501)).map(|a| &a.value) else {
//!     panic!("501 is not an array");
//! };
//! assert_eq!(elements.len(), 1);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod backend;
pub mod claims;
pub mod codepoints;
pub mod edit;
mod error;
pub mod kbt;
pub mod lint;
mod model;
pub mod sd;
mod util;

pub use backend::{CborBackend, Sign1Backend, Sign1Parts, SignOptions, VerifyOptions};
pub use error::{CoseError, RedactionError};
pub use model::{
    Bstr, Bucket, ContentType, Diagnostic, DiagnosticKind, Part, Payload, RawBytes, Sign1,
    TokenKind,
};
/// Re-exported so callers name the same types as this crate's API.
pub use tokenator_cbor::{Item, Span, Value};
/// Re-exported so callers name the same types as this crate's API.
pub use tokenator_crypto::{Alg, DeclaredAlg, HashAlg, rand_core::CryptoRng};
/// Re-exported so callers name the same types as this crate's API.
pub use tokenator_keys::{Key, Label};
