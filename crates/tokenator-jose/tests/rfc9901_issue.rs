//! Reproducing the RFC 9901 issuance examples byte for byte (header and
//! payload segments, every disclosure). ECDSA signatures are randomized, so
//! only the signature differs; it is checked by verifying.

// Helpers outside #[test] fns unwrap and panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{
    RFC9901_HOLDER_JWK, b64d, issuer_key, json, raw, rng, section_disclosures, segments, split_sd,
    str_of, token,
};
use tokenator_crypto::{Alg, HashAlg};
use tokenator_jose::{
    Cnf, DecoyDigests, DecoySpec, DigestOrder, IssueOptions, JsonStyle, SaltSource, issue, parse,
    verify_signature,
};
use tokenator_keys::Jwk;

/// Salts of the RFC disclosures of `section`, in RFC (= creation) order,
/// decoded independently of the crate.
fn rfc_salts(section: &str) -> Vec<String> {
    section_disclosures(section)
        .iter()
        .map(|d| {
            let bytes = b64d(d);
            let text = String::from_utf8(bytes).unwrap();
            str_of(&json(&text), "/0").to_owned()
        })
        .collect()
}

/// The input claims with `iss`, `iat`, `exp` placed first, the way the RFC
/// examples were generated (an existing `iss` keeps its value).
fn with_registered(input_file: &str, iss: &str) -> String {
    let text = raw(input_file);
    let root = json(&text);
    let mut out = format!(r#"{{"iss": "{iss}", "iat": 1683000000, "exp": 1883000000"#);
    for m in root.members().unwrap() {
        if m.key() != "iss" {
            out.push_str(&format!(", \"{}\": {}", m.key(), m.value().raw().unwrap()));
        }
    }
    out.push('}');
    out
}

fn ptrs(prefix: &str, names: &[&str]) -> Vec<String> {
    names.iter().map(|n| format!("{prefix}/{n}")).collect()
}

struct Case {
    section: &'static str,
    claims: String,
    sd: Vec<String>,
    decoys: Vec<DecoySpec>,
    typ: &'static str,
    cnf: bool,
    reference: String,
}

fn run(case: Case) {
    let key = issuer_key(Alg::ES256);
    let claims = json(&case.claims);
    let mut opts = IssueOptions::new(&key, Alg::ES256);
    opts.typ = Some(case.typ.to_owned());
    opts.sd = case.sd;
    opts.decoys = case.decoys;
    opts.salts = SaltSource::Fixed(rfc_salts(case.section));
    opts.style = JsonStyle::Spaced { ascii_only: true };
    opts.digest_order = DigestOrder::Sorted;
    opts.sd_alg = Some(HashAlg::Sha256);
    if case.cnf {
        opts.cnf = Some(Cnf::Jwk(Jwk::parse(RFC9901_HOLDER_JWK.as_bytes()).unwrap()));
    }
    let issued = issue(&claims, &opts, &mut rng(1)).unwrap();
    let section = case.section;

    let (jwt, discs, kb) = split_sd(&issued.token);
    assert_eq!(kb, "", "{section}: an issued SD-JWT ends with ~");
    let (ref_jwt, _, _) = split_sd(&case.reference);
    let [h, p, _] = segments(jwt);
    let [rh, rp, _] = segments(ref_jwt);
    assert_eq!(h, rh, "{section}: header");
    assert_eq!(
        p,
        rp,
        "{section}: payload\n{}\n{}",
        common::segment_json(p),
        common::segment_json(rp)
    );
    assert_eq!(
        discs,
        section_disclosures(section),
        "{section}: disclosures"
    );
    let listed: Vec<String> = issued.disclosures.iter().map(|d| d.text.clone()).collect();
    assert_eq!(listed, section_disclosures(section), "{section}");
    for d in &issued.disclosures {
        assert_eq!(d.digest, common::sha256_b64(&d.text), "{section}");
    }

    let parsed = parse(&issued.token).unwrap();
    assert_eq!(
        verify_signature(parsed.token.jws(), 0, &key),
        Ok(Alg::ES256),
        "{section}"
    );
}

#[test]
fn s5_1() {
    run(Case {
        section: "5.1",
        claims: with_registered(
            "rfc9901-s5.1-input-claims.json",
            "https://issuer.example.com",
        ),
        sd: [
            ptrs(
                "",
                &[
                    "given_name",
                    "family_name",
                    "email",
                    "phone_number",
                    "phone_number_verified",
                    "address",
                    "birthdate",
                    "updated_at",
                ],
            ),
            ptrs("/nationalities", &["0", "1"]),
        ]
        .concat(),
        decoys: vec![],
        typ: "example+sd-jwt",
        cnf: true,
        reference: token("rfc9901-s5.1-sd-jwt.txt"),
    });
}

#[test]
fn s5_1_disclosure_pointers() {
    let key = issuer_key(Alg::ES256);
    let text = with_registered(
        "rfc9901-s5.1-input-claims.json",
        "https://issuer.example.com",
    );
    let claims = json(&text);
    let mut opts = IssueOptions::new(&key, Alg::ES256);
    opts.sd = vec!["/nationalities/1".into(), "/email".into()];
    opts.salts = SaltSource::Fixed(vec!["s1".into(), "s2".into()]);
    let issued = issue(&claims, &opts, &mut rng(1)).unwrap();
    // Creation follows document order, not the order of `sd`.
    let pointers: Vec<&str> = issued
        .disclosures
        .iter()
        .map(|d| d.pointer.as_str())
        .collect();
    assert_eq!(pointers, ["/email", "/nationalities/1"]);
}

#[test]
fn a1_with_fixed_decoys() {
    run(Case {
        section: "A.1",
        claims: with_registered("rfc9901-a1-input-claims.json", "https://issuer.example.com"),
        sd: [
            ptrs(
                "",
                &["sub", "given_name", "family_name", "email", "phone_number"],
            ),
            ptrs(
                "/address",
                &["street_address", "locality", "region", "country"],
            ),
            ptrs("", &["birthdate"]),
        ]
        .concat(),
        decoys: vec![
            DecoySpec {
                at: String::new(),
                digests: DecoyDigests::Fixed(vec![
                    "fyGp0WTwwPv2JDQln1lSiaeobZsMWA10bQ5989-9DTs".into(),
                    "Y34zmIo0QLLOtdMpXGwjBgLvr17yEhhYT0FGofR-aIE".into(),
                ]),
            },
            DecoySpec {
                at: "/address".into(),
                digests: DecoyDigests::Fixed(vec![
                    "AzLlFobkJ2xiaupREPyoJz-9-NSldB6Cgjr7fUyoHzg".into(),
                    "cPYJHIZ8Vu-f9CCyVub2UfgEk8jvvXezwK1p_JneeXQ".into(),
                    "glT3hrSU7fSWgwF5UDZmWwBTw32gnUldIhi8hGVCaV4".into(),
                    "b2Dkw0jcIF9rGg8_PF8ZcvncW7zwZj5ryBWvXfrpzek".into(),
                ]),
            },
        ],
        typ: "example+sd-jwt",
        cnf: false,
        reference: token("rfc9901-a1-presentation.txt"),
    });
}

#[test]
fn a2_recursive_inside_an_array_element() {
    let v = "/verified_claims/verification";
    let c = "/verified_claims/claims";
    let e = format!("{v}/evidence/0");
    run(Case {
        section: "A.2",
        claims: with_registered("rfc9901-a2-input-claims.json", "https://issuer.example.com"),
        sd: [
            ptrs(v, &["time", "verification_process"]),
            vec![e.clone()],
            ptrs(&e, &["type", "method", "time", "document"]),
            ptrs(
                c,
                &[
                    "given_name",
                    "family_name",
                    "nationalities",
                    "birthdate",
                    "place_of_birth",
                    "address",
                ],
            ),
            ptrs("", &["birth_middle_name", "salutation", "msisdn"]),
        ]
        .concat(),
        decoys: vec![],
        typ: "example+sd-jwt",
        cnf: false,
        reference: token("rfc9901-a2-presentation.txt"),
    });
}

#[test]
fn a3_sd_jwt_vc() {
    let top = [
        "given_name",
        "family_name",
        "birthdate",
        "address",
        "nationalities",
        "sex",
        "birth_family_name",
        "place_of_birth",
        "age_equal_or_over",
        "age_in_years",
        "age_birth_year",
        "issuance_date",
        "expiry_date",
        "issuing_authority",
        "issuing_country",
    ];
    run(Case {
        section: "A.3",
        claims: with_registered(
            "rfc9901-a3-input-claims.json",
            "https://pid-issuer.bund.de.example",
        ),
        sd: [
            ptrs("", &top),
            ptrs(
                "/address",
                &["street_address", "locality", "postal_code", "country"],
            ),
            ptrs("/place_of_birth", &["locality", "country"]),
            ptrs("/age_equal_or_over", &["12", "14", "16", "18", "21", "65"]),
        ]
        .concat(),
        decoys: vec![],
        typ: "dc+sd-jwt",
        cnf: true,
        reference: token("rfc9901-a3-sd-jwt.txt"),
    });
}

#[test]
fn a4_w3c_vc() {
    let cs = "/credentialSubject";
    run(Case {
        section: "A.4",
        claims: raw("rfc9901-a4-input-claims.json"),
        sd: [
            ptrs(
                cs,
                &[
                    "nextVaccinationDate",
                    "countryOfVaccination",
                    "dateOfVaccination",
                    "order",
                    "administeringCentre",
                    "batchNumber",
                    "healthProfessional",
                ],
            ),
            ptrs(
                &format!("{cs}/vaccine"),
                &[
                    "atcCode",
                    "medicinalProductName",
                    "marketingAuthorizationHolder",
                ],
            ),
            ptrs(
                &format!("{cs}/recipient"),
                &["gender", "birthDate", "givenName", "familyName"],
            ),
        ]
        .concat(),
        decoys: vec![],
        typ: "example+sd-jwt",
        cnf: true,
        reference: token("rfc9901-a4-sd-jwt.txt"),
    });
}

#[test]
fn issued_rfc_examples_process_to_the_input_claims() {
    // Issue A.4 and process it: the processed payload has every input claim.
    let key = issuer_key(Alg::ES256);
    let input = raw("rfc9901-a4-input-claims.json");
    let claims = json(&input);
    let mut opts = IssueOptions::new(&key, Alg::ES256);
    opts.sd = ptrs("/credentialSubject", &["order", "type"]);
    let issued = issue(&claims, &opts, &mut rng(1)).unwrap();
    let parsed = parse(&issued.token).unwrap();
    let processed = parsed.token.sd_jwt().unwrap().process().unwrap();
    let cs = processed.claims.get("credentialSubject").unwrap();
    assert_eq!(str_of(cs, "/order"), "3/3");
    assert_eq!(str_of(cs, "/type"), "VaccinationEvent");
    assert_eq!(
        cs.members().unwrap().len(),
        claims
            .get("credentialSubject")
            .unwrap()
            .members()
            .unwrap()
            .len()
    );
}
