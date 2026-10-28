//! Tags, header labels, claim keys, and simple values.
//!
//! SD-CWT codepoints are from [`SD_CWT_REVISION`]; a test checks that they
//! agree with the `tokenator-registry` snapshot.

/// The SD-CWT draft revision this crate implements.
pub const SD_CWT_REVISION: &str = "draft-ietf-spice-sd-cwt-08";

/// COSE_Sign1 tag (RFC 9052 §4.2).
pub const TAG_COSE_SIGN1: u64 = 18;
/// CWT tag (RFC 8392 §6).
pub const TAG_CWT: u64 = 61;
/// To Be Redacted tag (sd-cwt-08 §11.1).
pub const TAG_TO_BE_REDACTED: u64 = 58;
/// Redacted claim element tag (sd-cwt-08 §4.1).
pub const TAG_REDACTED_ELEMENT: u64 = 60;
/// To Be Decoy tag (sd-cwt-08 §11.2).
pub const TAG_TO_BE_DECOY: u64 = 62;
/// `redacted_claim_keys` simple value, used as a map key (sd-cwt-08 §4.1).
pub const SIMPLE_REDACTED_KEYS: u8 = 59;

/// `alg` header parameter.
pub const HDR_ALG: i64 = 1;
/// `crit` header parameter.
pub const HDR_CRIT: i64 = 2;
/// `content type` header parameter.
pub const HDR_CONTENT_TYPE: i64 = 3;
/// `kid` header parameter.
pub const HDR_KID: i64 = 4;
/// `kcwt` header parameter (RFC 9528 §3.5.3.1).
pub const HDR_KCWT: i64 = 13;
/// `CWT Claims` header parameter (RFC 9597).
pub const HDR_CWT_CLAIMS: i64 = 15;
/// `typ` header parameter (RFC 9596).
pub const HDR_TYP: i64 = 16;
/// `sd_claims` header parameter (sd-cwt-08 §17.1.1).
pub const HDR_SD_CLAIMS: i64 = 17;
/// `sd_alg` header parameter (sd-cwt-08 §17.1.2).
pub const HDR_SD_ALG: i64 = 170;

/// `iss` claim.
pub const CLAIM_ISS: i64 = 1;
/// `sub` claim.
pub const CLAIM_SUB: i64 = 2;
/// `aud` claim.
pub const CLAIM_AUD: i64 = 3;
/// `exp` claim.
pub const CLAIM_EXP: i64 = 4;
/// `nbf` claim.
pub const CLAIM_NBF: i64 = 5;
/// `iat` claim.
pub const CLAIM_IAT: i64 = 6;
/// `cti` claim.
pub const CLAIM_CTI: i64 = 7;
/// `cnf` claim (RFC 8747).
pub const CLAIM_CNF: i64 = 8;
/// `vct` claim (sd-cwt-08 §13).
pub const CLAIM_VCT: i64 = 11;
/// `cnonce` claim (RFC 9200).
pub const CLAIM_CNONCE: i64 = 39;

/// Claims that an SD-CWT never redacts (sd-cwt-08 §6, Table 2).
pub const NEVER_REDACTED: [i64; 8] = [
    CLAIM_ISS,
    CLAIM_AUD,
    CLAIM_EXP,
    CLAIM_NBF,
    CLAIM_IAT,
    CLAIM_CTI,
    CLAIM_CNF,
    CLAIM_CNONCE,
];

/// `cnf` method: COSE_Key (RFC 8747 §3.2).
pub const CNF_COSE_KEY: i64 = 1;
/// `cnf` method: Encrypted_COSE_Key (RFC 8747 §3.3).
pub const CNF_ENCRYPTED_COSE_KEY: i64 = 2;
/// `cnf` method: kid (RFC 8747 §3.4).
pub const CNF_KID: i64 = 3;
/// `cnf` method: COSE Key Thumbprint, `ckt` (RFC 9679 §5.6).
pub const CNF_CKT: i64 = 5;

/// CoAP content-format of `application/sd-cwt` (sd-cwt-08 §4).
pub const TYP_SD_CWT: u64 = 293;
/// CoAP content-format of `application/kb+cwt` (sd-cwt-08 §8.1).
pub const TYP_KB_CWT: u64 = 294;
/// Media type of an SD-CWT.
pub const MEDIA_SD_CWT: &str = "application/sd-cwt";
/// Media type of an SD-KBT.
pub const MEDIA_KB_CWT: &str = "application/kb+cwt";
