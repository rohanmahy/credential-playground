//! JWS, JWT, SD-JWT, and KB-JWT.
//!
//! A pure library: no I/O, and time and randomness are always passed in.
//!
//! - [`parse`] reads JWS compact / JSON (flattened, general), SD-JWT, and
//!   SD-JWT+KB in either serialization. Every part keeps its original
//!   encoded text and its byte range in the input; decoded headers,
//!   payloads, and disclosures are `tokenator-json` trees. A part that
//!   fails to decode becomes a [`Diagnostic`] instead of an error.
//! - [`process`] matches disclosures to digests (RFC 9901 §7.1), reporting
//!   every problem as an [`SdFinding`] rather than aborting.
//! - [`issue`], [`select`] and [`present`] build JWTs, SD-JWTs, and
//!   presentations with KB-JWTs.
//! - [`verify_signature`], [`check_kb_jwt`] and [`check_time_claims`]
//!   return structured results for the core's validation report.
//! - [`resign`], [`assemble_compact`], [`tamper`], [`edit_disclosures`],
//!   [`to_compact`] and [`to_json`] make the deliberately broken or
//!   re-encoded artifacts the playground needs.
//! - [`header_facts`], [`duplicate_members`], [`cnf`], [`key_findings`] and
//!   [`jwk_findings`] feed the core's linter.
//!
//! # Verifying a JWT
//!
//! RFC 7515 Appendix A.3, verified with its public key:
//!
//! ```
//! use tokenator_crypto::Alg;
//! use tokenator_jose::{TimeStatus, check_time_claims, parse, verify_signature};
//! use tokenator_keys::{Jwk, from_jwk};
//!
//! let token = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
//! let key = from_jwk(&Jwk::parse(br#"{"kty":"EC","crv":"P-256",
//!     "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
//!     "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#)?)?;
//!
//! let parsed = parse(token)?;
//! assert!(parsed.diagnostics.is_empty());
//! let jws = parsed.token.jws();
//! assert_eq!(verify_signature(jws, 0, &key), Ok(Alg::ES256));
//!
//! // The payload keeps its CRLFs; time checks use an injected clock.
//! let claims = jws.claims()?;
//! assert_eq!(check_time_claims(&claims, 1_300_819_379, 0).exp, TimeStatus::Valid);
//! assert_eq!(check_time_claims(&claims, 1_300_819_380, 0).exp, TimeStatus::Expired);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Issue, present, verify
//!
//! An issuer makes `email` and one array element selectively disclosable
//! and binds the holder's key; the holder discloses only the element and
//! adds a KB-JWT; the verifier checks both signatures and rebuilds the
//! claims. Seeded keys and a seeded RNG make the run reproducible.
//!
//! ```
//! use rand_chacha::ChaCha20Rng;
//! use tokenator_crypto::{Alg, KeySpec, rand_core::SeedableRng};
//! use tokenator_jose::{
//!     Cnf, IssueOptions, KbExpectations, KbOptions, SdFinding, ValueCheck, check_kb_jwt, issue,
//!     parse, present, verify_signature,
//! };
//! use tokenator_keys::{Role, Visibility, generate, to_jwk, to_public};
//!
//! let mut rng = ChaCha20Rng::from_seed([7; 32]);
//! let issuer = generate(KeySpec::P256, Some(Role::Issuer), Some(&[1; 32]), &mut rng)?;
//! let holder = generate(KeySpec::Ed25519, Some(Role::Holder), Some(&[2; 32]), &mut rng)?;
//!
//! // Issue.
//! let claims = tokenator_json::parse(br#"{"sub":"alice","email":"a@example.com","langs":["de","fr"]}"#)?;
//! let mut opts = IssueOptions::new(&issuer, Alg::ES256);
//! opts.typ = Some("example+sd-jwt".into());
//! opts.sd = vec!["/email".into(), "/langs/1".into()];
//! opts.cnf = Some(Cnf::Jwk(to_jwk(&holder, Visibility::Public)?));
//! let issued = issue(&claims, &opts, &mut rng)?;
//! assert_eq!(issued.disclosures[1].pointer, "/langs/1");
//!
//! // Present only "fr", bound to the verifier's nonce.
//! let parsed = parse(&issued.token)?;
//! let sd = parsed.token.sd_jwt().expect("an SD-JWT");
//! let kb = KbOptions::new(&holder, Alg::Ed25519, "https://verifier.example", "n-42", 1_800_000_000);
//! let presented = present(sd, &[1], Some(&kb), &mut rng)?;
//! assert!(presented.selection.findings.is_empty());
//!
//! // Verify.
//! let parsed = parse(&presented.token)?;
//! let sd = parsed.token.sd_jwt().expect("an SD-JWT");
//! assert_eq!(verify_signature(&sd.issuer, 0, &to_public(&issuer)), Ok(Alg::ES256));
//! let processed = sd.process()?;
//! let claims = tokenator_json::print(&processed.claims, tokenator_json::PrintStyle::Compact);
//! assert!(claims.starts_with(r#"{"sub":"alice","langs":["de","fr"],"cnf":"#));
//! // The withheld email is just an unfilled digest.
//! assert!(matches!(processed.report.findings[..], [SdFinding::DigestWithoutDisclosure { .. }]));
//!
//! let expect = KbExpectations {
//!     aud: Some("https://verifier.example"),
//!     nonce: Some("n-42"),
//!     now: 1_800_000_030,
//!     skew: 60,
//!     max_age: Some(300),
//! };
//! let report = check_kb_jwt(sd, &[], &expect).expect("has a KB-JWT");
//! assert_eq!(report.signature, Ok(Alg::Ed25519));
//! assert_eq!(report.sd_hash, ValueCheck::Match);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod b64;
mod error;
mod issue;
mod json_out;
mod lint;
mod manipulate;
mod parse;
mod present;
mod sd;
mod verify;

pub use b64::{B64Error, b64u_decode, b64u_encode};
pub use error::JoseError;
pub use issue::{
    Cnf, DecoyDigests, DecoySpec, DigestOrder, IssueOptions, Issued, IssuedDisclosure, JsonStyle,
    SaltSource, issue,
};
pub use lint::{
    AlgFact, CnfFact, CritFact, DuplicateMember, HeaderFacts, StrFact, cnf, duplicate_members,
    header_facts, jwk_findings, key_findings,
};
pub use manipulate::{
    Converted, DisclosureOp, Edits, JsonSerialization, RawParts, Tamper, assemble_compact,
    edit_disclosures, resign, tamper, to_compact, to_json,
};
pub use parse::{
    B64Part, Diagnostic, DiagnosticKind, Disclosure, Jws, JwsSignature, ParseError, Parsed,
    PartError, PartRef, SdJwt, Serialization, Token, parse,
};
pub use present::{KbOptions, Presented, Selection, SelectionFinding, present, select};
pub use sd::{
    Container, DigestSlot, DisclosureError, DisclosureKind, DisclosureMatch, DisclosureView,
    Processed, SdAlg, SdFinding, SdReport, SlotKind, process, sd_alg, sd_digest,
};
/// Byte ranges, shared with `tokenator-json`.
pub use tokenator_json::Span;
pub use verify::{
    HolderKey, KbExpectations, KbReport, TimeReport, TimeStatus, ValueCheck, VerifyError,
    check_kb_jwt, check_time_claims, verify_signature,
};
