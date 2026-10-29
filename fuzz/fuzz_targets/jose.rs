//! JOSE parse and process: JWS, JWT, SD-JWT, and SD-JWT+KB in compact and
//! JSON serializations. Every parsed token is processed, linted, checked
//! against a fixed key, and converted to the other serializations, which
//! must parse again.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tokenator_jose::{
    JsonSerialization, Jws, KbExpectations, Token, check_kb_jwt, check_time_claims, cnf,
    duplicate_members, header_facts, parse, to_compact, to_json, verify_signature,
};
use tokenator_keys::{HashAlg, Key, import};

/// The RFC 7515 A.3 P-256 public key.
fn key() -> &'static Key {
    static KEY: OnceLock<Key> = OnceLock::new();
    KEY.get_or_init(|| {
        let jwk = br#"{"kty":"EC","crv":"P-256",
            "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;
        import(jwk, None).unwrap().remove(0)
    })
}

fn jws(jws: &Jws<'_>) {
    for (i, _) in jws.signatures.iter().enumerate() {
        let _ = jws.signing_input(i);
        if let Some(Ok(header)) = jws.header(i) {
            let _ = header_facts(&header);
            let _ = duplicate_members(&header);
        }
        let _ = verify_signature(jws, i, key());
    }
    let _ = jws.compact();
    if let Ok(claims) = jws.claims() {
        let _ = duplicate_members(&claims);
        let _ = cnf(&claims);
        let _ = check_time_claims(&claims, 1_800_000_000, 60);
    }
}

fn token(token: &Token<'_>) {
    jws(token.jws());
    if let Some(sd) = token.sd_jwt() {
        let _ = sd.process();
        let _ = sd.sd_hash_input();
        for disclosure in &sd.disclosures {
            let _ = disclosure.view();
            let _ = disclosure.digest(HashAlg::Sha256);
        }
        if let Some(kb) = &sd.kb_jwt {
            jws(kb);
        }
        let expect = KbExpectations {
            aud: Some("https://verifier.example"),
            nonce: Some("n"),
            now: 1_800_000_000,
            skew: 60,
            max_age: Some(300),
        };
        let _ = check_kb_jwt(sd, std::slice::from_ref(key()), &expect);
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(parsed) = parse(text) else {
        return;
    };
    token(&parsed.token);
    for index in 0..parsed.token.jws().signatures.len() {
        if let Ok(converted) = to_compact(&parsed.token, index) {
            let again = parse(&converted.text)
                .unwrap_or_else(|e| panic!("compact {:?}: {e}", converted.text));
            token(&again.token);
        }
    }
    for form in [JsonSerialization::Flattened, JsonSerialization::General] {
        if let Ok(json) = to_json(&parsed.token, form) {
            let again = parse(&json).unwrap_or_else(|e| panic!("{form:?} {json:?}: {e}"));
            token(&again.token);
        }
    }
});
