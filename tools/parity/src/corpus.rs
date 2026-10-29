//! Builds the parity corpus from `testdata/tokens/` and `testdata/keys/`.
//!
//! Requests that need an earlier result (a `Candidate` for `open`, an
//! issued document for `present`, …) are computed here with the native
//! engine, so every stored case is self-contained. Seeds are constant
//! (`[n; 32]`) and every clock is a constant, so the corpus and its
//! goldens are reproducible.

use std::path::Path;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::Serialize;
use tokenator_core::{
    AlgValue, AssignKidRequest, Bytes, CborSerialization, CnfChoice, DateTimeInput,
    DateTimeRequest, DecodeEmbeddedRequest, DecoyRequest, DiscloseRequest, DisclosureOp, DocRef,
    Document, EditDisclosuresRequest, EditRequest, Engine, EngineError, EquivalentEncoding,
    HashName, IssueRequest, JoseSerialization, JsonLayout, KeyConvertRequest, KeyExportRequest,
    KeyFormat, KeyGenRequest, KeyImportRequest, KeyInfo, KeyRef, KeySeed, KeySpec, KidSource, Kind,
    Layer, Layout, LintRequest, NodeId, Nonce, PartRef, PemEncoding, PresentRequest,
    ReencodeRequest, RegistryId, RegistryKind, RegistryLabel, RegistryMergeRequest, RegistryQuery,
    RenderRequest, ResignRequest, SdOptions, TamperOp, TamperRequest, ThumbprintKind,
    ThumbprintRequest, ValidateRequest, ViewOptions, Visibility,
};

use crate::{Arg, Case};

/// RFC 7515 / RFC 7519 examples: exp 1300819380.
const RFC7515_NOW: i64 = 1_300_819_000;
/// RFC 8392 A.1: iat/nbf 1443944944, exp 1444064944.
const RFC8392_NOW: i64 = 1_444_000_000;
/// RFC 9901: issuer iat 1683000000, exp 1883000000; KB-JWT iat 1748537244.
const RFC9901_NOW: i64 = 1_748_537_250;
const RFC9901_AUD: &str = "https://verifier.example.org";
const RFC9901_NONCE: &str = "1234567890";
const RFC9901_ISSUER_JWK: &str = r#"{"kty":"EC","crv":"P-256","x":"b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ","y":"Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"}"#;
/// sd-cwt-08: a clock at which every example is valid.
const SD_NOW: i64 = 1_725_244_240;
const SD_AUD: &str = "https://verifier.example/app";
const SD_CNONCE_HEX: &str = "8c0f5f523b95bea44a9a48c649240803";
/// The clock for freshly issued tokens.
const LATER: i64 = 1_800_000_000;
const AUD: &str = "https://verifier.example";

/// CBOR and EDN nesting at the decoder limit (`tokenator_cbor::MAX_DEPTH`).
const MAX_DEPTH: usize = tokenator_cbor::MAX_DEPTH;
/// Nested SD-JWT disclosures: one per JSON level, below tokenator-json's
/// default depth limit (128) for claim sets.
const SD_CHAIN: usize = 120;

/// Builds every case, in id order. Fails on a duplicate id or when a
/// chained native call fails unexpectedly.
pub fn build(e: &Engine, testdata: &Path) -> Result<Vec<(String, Case)>, String> {
    let mut b = Builder {
        e,
        td: testdata,
        cases: Vec::new(),
    };
    b.info();
    b.detect_and_open()?;
    b.render()?;
    b.parse_edit()?;
    b.keys()?;
    b.actions()?;
    b.validate()?;
    b.manipulate()?;
    b.datetime();
    b.registry()?;
    b.stack_audit()?;
    let mut cases = b.cases;
    cases.sort_by(|a, b| a.0.cmp(&b.0));
    for pair in cases.windows(2) {
        if let [a, b] = pair
            && a.0 == b.0
        {
            return Err(format!("duplicate case id {}", a.0));
        }
    }
    Ok(cases)
}

struct Builder<'a> {
    e: &'a Engine,
    td: &'a Path,
    cases: Vec<(String, Case)>,
}

fn must<T>(r: Result<T, EngineError>, what: &str) -> Result<T, String> {
    r.map_err(|e| format!("{what}: {e}"))
}

fn seed(n: u8) -> Bytes {
    Bytes(vec![n; 32])
}

fn view() -> ViewOptions {
    ViewOptions::default()
}

fn node(s: &str) -> NodeId {
    NodeId(s.to_owned())
}

/// A file name as an id segment.
fn slug(path: &str) -> String {
    path.replace('/', "_")
}

fn hexd(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s.bytes().filter(u8::is_ascii_hexdigit).collect();
    digits
        .chunks(2)
        .map(|p| {
            let h = |c: u8| (c as char).to_digit(16).unwrap_or(0) as u8;
            match p {
                [a, b] => (h(*a) << 4) | h(*b),
                _ => 0,
            }
        })
        .collect()
}

/// Request numbers must survive `JSON.parse` in JS unchanged.
fn check_numbers(v: &serde_json::Value) -> Result<(), String> {
    const SAFE: u64 = (1 << 53) - 1;
    match v {
        serde_json::Value::Number(n) => {
            let ok = n.as_u64().is_some_and(|x| x <= SAFE)
                || n.as_i64().is_some_and(|x| x.unsigned_abs() <= SAFE);
            if ok {
                Ok(())
            } else {
                Err(format!("number {n} is not exact in JavaScript"))
            }
        }
        serde_json::Value::Array(a) => a.iter().try_for_each(check_numbers),
        serde_json::Value::Object(o) => o.values().try_for_each(check_numbers),
        _ => Ok(()),
    }
}

fn json<T: Serialize>(v: &T) -> Result<Arg, String> {
    let value = serde_json::to_value(v).map_err(|e| e.to_string())?;
    check_numbers(&value)?;
    Ok(Arg::Json(value))
}

fn raw(bytes: &[u8]) -> Arg {
    Arg::Bytes(Base64UrlUnpadded::encode_string(bytes))
}

/// `{0: {0: … 0 …}}`: `depth` nested maps, as CBOR.
fn deep_cbor_maps(depth: usize) -> Vec<u8> {
    let mut v = [0xa1, 0x00].repeat(depth);
    v.push(0x00);
    v
}

/// `[[ … ]]`: `depth` nested arrays, as CBOR.
fn deep_cbor_arrays(depth: usize) -> Vec<u8> {
    let mut v = [0x81].repeat(depth);
    v.push(0x00);
    v
}

/// `{0: {0: … 0 …}}` as EDN text, `depth` maps deep.
fn deep_edn_maps(depth: usize) -> String {
    format!("{}0{}", "{0: ".repeat(depth), "}".repeat(depth))
}

/// `{"a": {"a": … "x" …}}` as JSON text, `depth` objects deep.
fn deep_json(depth: usize) -> String {
    format!(r#"{}"x"{}"#, r#"{"a": "#.repeat(depth), "}".repeat(depth))
}

impl Builder<'_> {
    fn add(&mut self, id: String, source: impl Into<String>, method: &str, args: Vec<Arg>) {
        self.push(id, source, method, args, false);
    }

    fn add_stack(&mut self, id: String, source: impl Into<String>, method: &str, args: Vec<Arg>) {
        self.push(id, source, method, args, true);
    }

    fn push(
        &mut self,
        id: String,
        source: impl Into<String>,
        method: &str,
        args: Vec<Arg>,
        stack: bool,
    ) {
        self.cases.push((
            id,
            Case {
                method: method.to_owned(),
                source: source.into(),
                stack,
                args,
            },
        ));
    }

    fn read(&self, rel: &str) -> Result<Vec<u8>, String> {
        let p = self.td.join(rel);
        std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))
    }

    fn token(&self, name: &str) -> Result<Vec<u8>, String> {
        self.read(&format!("tokens/{name}"))
    }

    fn key(&self, name: &str) -> Result<KeyRef, String> {
        let mut k = KeyRef::new(self.read(&format!("keys/{name}"))?);
        k.label = Some(name.to_owned());
        Ok(k)
    }

    fn files(&self, dir: &str, exts: &[&str]) -> Result<Vec<String>, String> {
        let p = self.td.join(dir);
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&p).map_err(|e| format!("{}: {e}", p.display()))? {
            let path = entry.map_err(|e| e.to_string())?.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if path.is_file() && exts.iter().any(|x| name.ends_with(x)) {
                out.push(name.to_owned());
            }
        }
        out.sort();
        Ok(out)
    }

    /// Every key fixture (`keys/openssl/*.json` hold the OpenSSL test
    /// values, not keys).
    fn key_files(&self) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        for (dir, exts) in [
            ("keys", &[".pem", ".json", ".cbor"][..]),
            ("keys/openssl", &[".pem"][..]),
            ("keys/rfc7517", &[".json"][..]),
            ("keys/rfc7638", &[".json"][..]),
        ] {
            out.extend(
                self.files(dir, exts)?
                    .into_iter()
                    .map(|n| format!("{dir}/{n}")),
            );
        }
        Ok(out)
    }

    /// paste → detect → open with the top candidate.
    fn open(&self, input: &[u8], what: &str) -> Result<Document, String> {
        let c = self
            .e
            .detect(input)
            .into_iter()
            .next()
            .ok_or_else(|| format!("{what}: nothing detected"))?;
        must(self.e.open(input, &c, &view()), what)
    }

    fn open_token(&self, name: &str) -> Result<Document, String> {
        self.open(&self.token(name)?, name)
    }

    fn keygen(&self, spec: KeySpec, n: u8) -> Result<KeyInfo, String> {
        must(
            self.e.key_generate(&KeyGenRequest {
                spec,
                role: None,
                seed: KeySeed::Seed { bytes: seed(n) },
                kid: None,
            }),
            "key_generate",
        )
    }

    fn public(&self, k: &KeyInfo) -> Result<KeyRef, String> {
        must(self.e.key_public(&k.key), "key_public").map(|k| k.key)
    }

    fn issue_req(&self, claims: DocRef, issuer: &KeyInfo) -> IssueRequest {
        IssueRequest {
            claims,
            issuer: issuer.key.clone(),
            alg: None,
            header: Default::default(),
            sd: SdOptions::default(),
            cnf: None,
            jose_serialization: JoseSerialization::Compact,
            cose_tags: None,
            randomness: None,
            view: view(),
        }
    }

    // ------------------------------------------------------------ info

    fn info(&mut self) {
        self.add("info--bundled".into(), "Engine::new()", "info", vec![]);
    }

    // ------------------------------------------------------------ detect, open

    fn detect_and_open(&mut self) -> Result<(), String> {
        let exts = [".txt", ".json", ".cbor", ".hex", ".edn"];
        for name in self.files("tokens", &exts)? {
            let input = self.token(&name)?;
            let source = format!("tokens/{name}");
            self.add(
                format!("detect--tokens--{name}"),
                &source,
                "detect",
                vec![raw(&input)],
            );
            // Open the top candidate of every token fixture (failures, such
            // as unsupported COSE_Mac0, are goldens too).
            if let Some(c) = self.e.detect(&input).into_iter().next() {
                self.add(
                    format!("open--{name}"),
                    &source,
                    "open",
                    vec![raw(&input), json(&c)?, json(&view())?],
                );
            }
        }
        for rel in self.key_files()? {
            {
                let input = self.read(&rel)?;
                self.add(
                    format!("detect--{}", slug(&rel)),
                    &rel,
                    "detect",
                    vec![raw(&input)],
                );
            }
        }
        let jws = String::from_utf8(self.token("rfc7515-a3-jws-es256.txt")?)
            .map_err(|e| e.to_string())?;
        let jws = jws.trim();
        let cwt = self.token("rfc8392-a3-signed-cwt.cbor")?;
        let wrapped: Vec<(&str, Vec<u8>)> = vec![
            ("bearer", format!("Bearer {jws}").into_bytes()),
            (
                "authorization-header",
                format!("Authorization: Bearer {jws}").into_bytes(),
            ),
            ("quoted", format!("\"{jws}\"").into_bytes()),
            (
                "json-container",
                format!(r#"{{"credential": "{jws}", "other": 1}}"#).into_bytes(),
            ),
            ("url-encoded", jws.replace('.', "%2E").into_bytes()),
            (
                "cwt-base64url",
                Base64UrlUnpadded::encode_string(&cwt).into_bytes(),
            ),
            (
                "cwt-hex-colons",
                cwt.iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(":")
                    .into_bytes(),
            ),
            ("empty", Vec::new()),
            ("garbage", b"\x00\xff not a token \xfe".to_vec()),
        ];
        for (name, input) in wrapped {
            self.add(
                format!("detect--wrapped--{name}"),
                format!("constructed: {name} around RFC 7515 A.3 / RFC 8392 A.3"),
                "detect",
                vec![raw(&input)],
            );
            if let Some(c) = self.e.detect(&input).into_iter().next() {
                self.add(
                    format!("open--wrapped--{name}"),
                    format!("constructed: {name}"),
                    "open",
                    vec![raw(&input), json(&c)?, json(&view())?],
                );
            }
        }
        // A candidate that does not fit the input.
        let jwt_candidate = self
            .e
            .detect(jws.as_bytes())
            .into_iter()
            .next()
            .ok_or("no JWT candidate")?;
        self.add(
            "open--error--candidate-mismatch".into(),
            "RFC 8392 A.3 bytes with the RFC 7515 A.3 candidate",
            "open",
            vec![raw(&cwt), json(&jwt_candidate)?, json(&view())?],
        );
        Ok(())
    }

    // ------------------------------------------------------------ render

    fn render(&mut self) -> Result<(), String> {
        let cwt = self.open_token("rfc8392-a3-signed-cwt.cbor")?;
        let sdjwt = self.open_token("rfc9901-s5.2-sd-jwt-kb.txt")?;
        let sdcwt = self.open_token("sd-cwt-08-sd-kbt.cbor")?;
        let views: Vec<(&str, &Document, ViewOptions)> = vec![
            ("cwt-default", &cwt, view()),
            (
                "cwt-compact",
                &cwt,
                ViewOptions {
                    layout: Layout::Compact,
                    ..view()
                },
            ),
            (
                "cwt-indent-4",
                &cwt,
                ViewOptions {
                    indent: 4,
                    ..view()
                },
            ),
            (
                "cwt-no-decoded-views",
                &cwt,
                ViewOptions {
                    decoded_views: false,
                    ..view()
                },
            ),
            (
                "cwt-no-annotations",
                &cwt,
                ViewOptions {
                    annotations: false,
                    ..view()
                },
            ),
            (
                "cwt-base64-bytes",
                &cwt,
                ViewOptions {
                    byte_style: tokenator_core::ByteStyle::Base64,
                    ..view()
                },
            ),
            (
                "cwt-dt-literals-now",
                &cwt,
                ViewOptions {
                    dt_literals: true,
                    now: Some(RFC8392_NOW),
                    local_offset_minutes: -300,
                    ..view()
                },
            ),
            (
                "cwt-hide-decoded-payload",
                &cwt,
                ViewOptions {
                    hide_decoded: vec![node("payload")],
                    ..view()
                },
            ),
            (
                "cwt-manual-decode-signature",
                &cwt,
                ViewOptions {
                    manual_decode: vec![node("signature")],
                    ..view()
                },
            ),
            (
                "sd-jwt-kb-pretty",
                &sdjwt,
                ViewOptions {
                    json_layout: JsonLayout::Pretty,
                    ..view()
                },
            ),
            (
                "sd-jwt-kb-now",
                &sdjwt,
                ViewOptions {
                    now: Some(RFC9901_NOW),
                    ..view()
                },
            ),
            (
                "sd-kbt-compact",
                &sdcwt,
                ViewOptions {
                    layout: Layout::Compact,
                    ..view()
                },
            ),
        ];
        for (name, doc, v) in views {
            let req = RenderRequest {
                doc: DocRef::from(doc),
                layers: doc.layers.clone(),
                view: v,
            };
            self.add(
                format!("render--{name}"),
                "opened fixture",
                "render",
                vec![json(&req)?],
            );
        }
        // Claim sets of every kind, and bytes that are not the kind.
        let claims: Vec<(&str, Kind, Vec<u8>)> = vec![
            (
                "json-claims",
                Kind::JsonClaims,
                self.token("rfc7519-s3.1-claims.json")?,
            ),
            (
                "cbor-claims",
                Kind::CborClaims,
                self.token("rfc8392-a1-claims.cbor")?,
            ),
            (
                "edn-claims",
                Kind::EdnClaims,
                self.token("sd-cwt-08-fig4-claims.edn")?,
            ),
            ("error--cwt-not-cbor", Kind::Cwt, b"not cbor".to_vec()),
        ];
        for (name, kind, bytes) in claims {
            let req = RenderRequest {
                doc: DocRef::new(kind, bytes),
                layers: Vec::new(),
                view: view(),
            };
            self.add(
                format!("render--{name}"),
                "fixture bytes",
                "render",
                vec![json(&req)?],
            );
        }
        Ok(())
    }

    // ------------------------------------------------------------ parse_edit

    fn parse_edit(&mut self) -> Result<(), String> {
        let jwt = self.open_token("rfc7515-a3-jws-es256.txt")?;
        let cwt = self.open_token("rfc8392-a3-signed-cwt.cbor")?;
        let edn = self.open_token("sd-cwt-08-fig4-claims.edn")?;
        let edits: Vec<(&str, &Document, String)> = vec![
            ("jwt-unchanged", &jwt, jwt.main.text.clone()),
            (
                "jwt-payload-edit",
                &jwt,
                jwt.main.text.replacen("joe", "jane", 1),
            ),
            ("jwt-invalid", &jwt, jwt.main.text.replacen('{', "{{", 2)),
            ("cwt-unchanged", &cwt, cwt.main.text.clone()),
            (
                "cwt-payload-edit",
                &cwt,
                cwt.main.text.replacen("\"erikw\"", "\"erika\"", 1),
            ),
            (
                "cwt-indicator-edit",
                &cwt,
                cwt.main.text.replacen("1444064944", "1444064944_2", 1),
            ),
            ("cwt-invalid", &cwt, format!("{} ]", cwt.main.text)),
            (
                "edn-claims-edit",
                &edn,
                format!("{}\n/ appended comment /", edn.main.text),
            ),
        ];
        for (name, doc, text) in edits {
            let req = EditRequest {
                kind: doc.kind.clone(),
                base: doc.bytes.clone(),
                text,
                view: view(),
            };
            self.add(
                format!("parse_edit--{name}"),
                "opened fixture",
                "parse_edit",
                vec![json(&req)?],
            );
        }
        Ok(())
    }

    // ------------------------------------------------------------ keys

    fn keys(&mut self) -> Result<(), String> {
        // Import every key fixture (sets give several keys; unsupported
        // ones are error goldens).
        for rel in self.key_files()? {
            {
                let req = KeyImportRequest {
                    bytes: Bytes(self.read(&rel)?),
                    format: None,
                    candidate: None,
                };
                self.add(
                    format!("key_import--{}", slug(&rel)),
                    &rel,
                    "key_import",
                    vec![json(&req)?],
                );
            }
        }
        for name in self.files("keys/openssl/unsupported", &[".pem"])? {
            let rel = format!("keys/openssl/unsupported/{name}");
            let req = KeyImportRequest {
                bytes: Bytes(self.read(&rel)?),
                format: None,
                candidate: None,
            };
            self.add(
                format!("key_import--{}", slug(&rel)),
                &rel,
                "key_import",
                vec![json(&req)?],
            );
        }
        let edn_key = br#"{1: 1, -1: 6, -2: h'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'}"#;
        for (name, bytes, format) in [
            ("edn-cose-key", edn_key.to_vec(), None),
            (
                "hinted-jwk",
                br#"{"kty":"oct","k":"AAAA"}"#.to_vec(),
                Some(KeyFormat::Jwk),
            ),
            ("error--garbage", b"not a key".to_vec(), None),
        ] {
            let req = KeyImportRequest {
                bytes: Bytes(bytes),
                format,
                candidate: None,
            };
            self.add(
                format!("key_import--{name}"),
                "constructed",
                "key_import",
                vec![json(&req)?],
            );
        }

        // A key pasted as `xxd -p` hex: import the detected candidate (#42).
        let cose_key = self.read("keys/rfc8392-a2.3-ec-p256.cosekey.cbor")?;
        let hex_text: String = cose_key.iter().map(|b| format!("{b:02x}")).collect();
        let hex_input = format!("{hex_text}\n").into_bytes();
        let candidate = self
            .e
            .detect(&hex_input)
            .into_iter()
            .next()
            .ok_or("no candidate for the hex COSE_Key")?;
        let req = KeyImportRequest {
            bytes: Bytes(hex_input),
            format: None,
            candidate: Some(candidate),
        };
        self.add(
            "key_import--hex-cose-key-candidate".into(),
            "keys/rfc8392-a2.3-ec-p256.cosekey.cbor as hex",
            "key_import",
            vec![json(&req)?],
        );

        // Generate: every spec, seeded; plus well-known, entropy, kid sources.
        let specs: Vec<(&str, KeySpec)> = vec![
            ("p256", KeySpec::P256),
            ("p384", KeySpec::P384),
            ("p521", KeySpec::P521),
            ("ed25519", KeySpec::Ed25519),
            ("rsa2048", KeySpec::Rsa { bits: 2048 }),
            ("ml-dsa-44", KeySpec::MlDsa44),
            ("ml-dsa-65", KeySpec::MlDsa65),
            ("ml-dsa-87", KeySpec::MlDsa87),
        ];
        for (name, spec) in &specs {
            let req = KeyGenRequest {
                spec: *spec,
                role: None,
                seed: KeySeed::Seed { bytes: seed(7) },
                kid: None,
            };
            self.add(
                format!("key_generate--seeded-{name}"),
                "seed [7; 32]",
                "key_generate",
                vec![json(&req)?],
            );
        }
        let gens: Vec<(&str, KeyGenRequest)> = vec![
            (
                "well-known-p256",
                KeyGenRequest {
                    spec: KeySpec::P256,
                    role: None,
                    seed: KeySeed::WellKnown,
                    kid: None,
                },
            ),
            (
                "well-known-ml-dsa-44-issuer",
                KeyGenRequest {
                    spec: KeySpec::MlDsa44,
                    role: Some(tokenator_core::Role::Issuer),
                    seed: KeySeed::WellKnown,
                    kid: None,
                },
            ),
            (
                "entropy-ed25519",
                KeyGenRequest {
                    spec: KeySpec::Ed25519,
                    role: None,
                    seed: KeySeed::Entropy { bytes: seed(9) },
                    kid: None,
                },
            ),
            (
                "kid-jwk-thumbprint",
                KeyGenRequest {
                    spec: KeySpec::P256,
                    role: None,
                    seed: KeySeed::Seed { bytes: seed(1) },
                    kid: Some(KidSource::JwkThumbprint {
                        hash: HashName::Sha256,
                    }),
                },
            ),
            (
                "kid-cose-thumbprint-sha512",
                KeyGenRequest {
                    spec: KeySpec::Ed25519,
                    role: None,
                    seed: KeySeed::Seed { bytes: seed(1) },
                    kid: Some(KidSource::CoseThumbprint {
                        hash: HashName::Sha512,
                    }),
                },
            ),
            (
                "kid-bytes",
                KeyGenRequest {
                    spec: KeySpec::P384,
                    role: None,
                    seed: KeySeed::Seed { bytes: seed(1) },
                    kid: Some(KidSource::Bytes {
                        value: Bytes(vec![1, 2, 3]),
                    }),
                },
            ),
            (
                "error--short-entropy",
                KeyGenRequest {
                    spec: KeySpec::P256,
                    role: None,
                    seed: KeySeed::Entropy {
                        bytes: Bytes(vec![1; 16]),
                    },
                    kid: None,
                },
            ),
            (
                "error--rsa-bits",
                KeyGenRequest {
                    spec: KeySpec::Rsa { bits: 1000 },
                    role: None,
                    seed: KeySeed::Seed { bytes: seed(1) },
                    kid: None,
                },
            ),
        ];
        for (name, req) in gens {
            self.add(
                format!("key_generate--{name}"),
                "constructed",
                "key_generate",
                vec![json(&req)?],
            );
        }

        // Export, public, thumbprints, kid, conversion.
        let holder = self.key("sd-cwt-08-c1-holder-private.cosekey.cbor")?;
        let mldsa = self.key("openssl/mldsa87-both.pem")?;
        let rsa = self.key("openssl/rsa2048-pkcs8.pem")?;
        let p256 = self.keygen(KeySpec::P256, 3)?.key;
        let pem = |encoding| KeyFormat::Pem { encoding };
        let exports: Vec<(&str, &KeyRef, KeyFormat, Visibility)> = vec![
            (
                "holder-jwk-public",
                &holder,
                KeyFormat::Jwk,
                Visibility::Public,
            ),
            (
                "holder-jwk-private",
                &holder,
                KeyFormat::Jwk,
                Visibility::Private,
            ),
            (
                "holder-jwk-set-public",
                &holder,
                KeyFormat::JwkSet,
                Visibility::Public,
            ),
            (
                "holder-cose-key-private",
                &holder,
                KeyFormat::CoseKey,
                Visibility::Private,
            ),
            (
                "holder-cose-key-set-public",
                &holder,
                KeyFormat::CoseKeySet,
                Visibility::Public,
            ),
            (
                "holder-pem-spki",
                &holder,
                pem(PemEncoding::Spki),
                Visibility::Public,
            ),
            (
                "holder-pem-pkcs8",
                &holder,
                pem(PemEncoding::Pkcs8),
                Visibility::Private,
            ),
            (
                "holder-pem-sec1",
                &holder,
                pem(PemEncoding::Sec1),
                Visibility::Private,
            ),
            (
                "ml-dsa-87-pem-both",
                &mldsa,
                pem(PemEncoding::Pkcs8MlDsaBoth),
                Visibility::Private,
            ),
            (
                "ml-dsa-87-pem-seed",
                &mldsa,
                pem(PemEncoding::Pkcs8MlDsaSeed),
                Visibility::Private,
            ),
            (
                "ml-dsa-87-jwk-public",
                &mldsa,
                KeyFormat::Jwk,
                Visibility::Public,
            ),
            (
                "rsa2048-pem-pkcs1",
                &rsa,
                pem(PemEncoding::Pkcs1),
                Visibility::Private,
            ),
            (
                "rsa2048-cose-key-public",
                &rsa,
                KeyFormat::CoseKey,
                Visibility::Public,
            ),
            (
                "p256-pem-auto",
                &p256,
                pem(PemEncoding::Auto),
                Visibility::Private,
            ),
            (
                "error--rsa-as-sec1",
                &rsa,
                pem(PemEncoding::Sec1),
                Visibility::Private,
            ),
        ];
        for (name, key, format, visibility) in exports {
            let req = KeyExportRequest {
                key: key.clone(),
                format,
                visibility,
            };
            self.add(
                format!("key_export--{name}"),
                "key fixture",
                "key_export",
                vec![json(&req)?],
            );
        }
        let set = self.key("rfc7517-a2-private.jwks.json")?;
        let second = KeyRef {
            index: 1,
            ..set.clone()
        };
        for (name, key) in [
            ("holder", &holder),
            ("ml-dsa-87", &mldsa),
            ("jwk-set-index-1", &second),
            ("error--garbage", &KeyRef::new(b"nope".to_vec())),
        ] {
            self.add(
                format!("key_public--{name}"),
                "key fixture",
                "key_public",
                vec![json(key)?],
            );
        }
        for (name, key, kind, hash) in [
            (
                "holder-jwk-sha256",
                &holder,
                ThumbprintKind::Jwk,
                HashName::Sha256,
            ),
            (
                "holder-cose-sha256",
                &holder,
                ThumbprintKind::Cose,
                HashName::Sha256,
            ),
            (
                "rsa-jwk-sha512",
                &rsa,
                ThumbprintKind::Jwk,
                HashName::Sha512,
            ),
            (
                "ml-dsa-87-cose-sha384",
                &mldsa,
                ThumbprintKind::Cose,
                HashName::Sha384,
            ),
        ] {
            let req = ThumbprintRequest {
                key: key.clone(),
                kind,
                hash,
            };
            self.add(
                format!("key_thumbprint--{name}"),
                "key fixture",
                "key_thumbprint",
                vec![json(&req)?],
            );
        }
        for (name, source) in [
            (
                "jwk-thumbprint",
                KidSource::JwkThumbprint {
                    hash: HashName::Sha256,
                },
            ),
            (
                "cose-thumbprint",
                KidSource::CoseThumbprint {
                    hash: HashName::Sha256,
                },
            ),
            (
                "text",
                KidSource::Text {
                    value: "holder-1".into(),
                },
            ),
            (
                "bytes",
                KidSource::Bytes {
                    value: Bytes(vec![0xde, 0xad]),
                },
            ),
        ] {
            let req = AssignKidRequest {
                key: holder.clone(),
                source,
            };
            self.add(
                format!("key_assign_kid--{name}"),
                "sd-cwt-08 holder key",
                "key_assign_kid",
                vec![json(&req)?],
            );
        }
        for (name, key, visibility) in [
            ("holder-public", &holder, Visibility::Public),
            ("holder-private", &holder, Visibility::Private),
            ("ml-dsa-87-public", &mldsa, Visibility::Public),
            ("rsa2048-private", &rsa, Visibility::Private),
        ] {
            let req = KeyConvertRequest {
                key: key.clone(),
                visibility,
            };
            self.add(
                format!("key_to_jwk--{name}"),
                "key fixture",
                "key_to_jwk",
                vec![json(&req)?],
            );
            self.add(
                format!("key_to_cwk--{name}"),
                "key fixture",
                "key_to_cwk",
                vec![json(&req)?],
            );
        }
        Ok(())
    }

    // ------------------------------------------------------------ actions

    fn actions(&mut self) -> Result<(), String> {
        let e = self.e;
        let issuer = self.keygen(KeySpec::P256, 1)?;
        let holder = self.keygen(KeySpec::Ed25519, 2)?;
        let rsa = KeyInfo {
            key: self.key("openssl/rsa2048-pkcs8.pem")?,
            ..issuer.clone()
        };
        let json_claims = DocRef::new(
            Kind::JsonClaims,
            self.token("rfc9901-s5.1-input-claims.json")?,
        );
        let edn_cwt = DocRef::new(
            Kind::EdnClaims,
            br#"{1: "https://issuer.example", 2: "alice", 4: 1900000000, 6: 1700000000}"#.to_vec(),
        );
        let fig4 = DocRef::new(Kind::EdnClaims, self.token("sd-cwt-08-fig4-claims.edn")?);
        let edn_sd = DocRef::new(
            Kind::EdnClaims,
            br#"{1: "https://issuer.example", 58(500): "x", 501: [58(1), 2], 502: {58("a"): 1}}"#
                .to_vec(),
        );

        let mut issues: Vec<(&str, IssueRequest)> = Vec::new();
        issues.push(("jwt-es256", self.issue_req(json_claims.clone(), &issuer)));
        let mut r = self.issue_req(json_claims.clone(), &issuer);
        r.sd = SdOptions {
            marks: vec![node("email"), node("address"), node("nationalities/0")],
            decoys: vec![DecoyRequest {
                at: node(""),
                count: 2,
            }],
            ..SdOptions::default()
        };
        r.cnf = Some(CnfChoice::Key {
            key: self.public(&holder)?,
        });
        r.randomness = Some(seed(4));
        let sd_jwt_req = r.clone();
        issues.push(("sd-jwt-es256-cnf-decoys", r.clone()));
        r.jose_serialization = JoseSerialization::JsonGeneral;
        issues.push(("sd-jwt-json-general", r.clone()));
        r.jose_serialization = JoseSerialization::JsonFlattened;
        r.sd.sd_alg = Some(HashName::Sha512);
        issues.push(("sd-jwt-json-flattened-sha512", r));
        let mut r = self.issue_req(json_claims.clone(), &issuer);
        r.sd.marks = vec![node("email")];
        issues.push(("error--sd-without-randomness", r));
        let mut r = self.issue_req(json_claims.clone(), &rsa);
        r.alg = Some("RS256".into());
        issues.push(("jwt-rs256", r.clone()));
        r.alg = Some("PS256".into());
        r.randomness = Some(seed(5));
        issues.push(("jwt-ps256", r.clone()));
        r.randomness = None;
        issues.push(("error--ps256-without-randomness", r));
        let mut r = self.issue_req(json_claims.clone(), &issuer);
        r.alg = Some("RS256".into());
        issues.push(("error--alg-key-mismatch", r));
        issues.push(("cwt-es256", self.issue_req(edn_cwt.clone(), &issuer)));
        let mut r = self.issue_req(edn_cwt.clone(), &holder);
        r.alg = Some("EdDSA".into());
        r.cose_tags = Some(vec![61, 18]);
        issues.push(("cwt-eddsa-tag61", r));
        // Figure 4 carries its own cnf.
        let mut r = self.issue_req(fig4.clone(), &issuer);
        r.randomness = Some(seed(6));
        issues.push(("sd-cwt-fig4", r.clone()));
        r.cnf = Some(CnfChoice::Key {
            key: self.public(&holder)?,
        });
        issues.push(("error--sd-cwt-fig4-second-cnf", r));
        let mut r = self.issue_req(edn_sd.clone(), &issuer);
        r.randomness = Some(seed(6));
        r.cnf = Some(CnfChoice::Key {
            key: self.public(&holder)?,
        });
        let sd_cwt_req = r.clone();
        issues.push(("sd-cwt-tags-58-cnf", r));
        for (name, req) in issues {
            self.add(
                format!("issue--{name}"),
                "seeded keys and randomness",
                "issue",
                vec![json(&req)?],
            );
        }

        // Redact: ok, and nothing to redact.
        self.add(
            "redact--sd-jwt".into(),
            "seeded",
            "redact",
            vec![json(&sd_jwt_req)?],
        );
        self.add(
            "redact--error--nothing-to-redact".into(),
            "seeded",
            "redact",
            vec![json(&self.issue_req(edn_cwt.clone(), &issuer))?],
        );

        // Disclose and present, both families, from the issued documents.
        let sd_jwt = must(e.issue(&sd_jwt_req), "issue sd-jwt")?;
        let sd_cwt = must(e.issue(&sd_cwt_req), "issue sd-cwt")?;
        let cwt = must(
            e.issue(&self.issue_req(edn_cwt.clone(), &issuer)),
            "issue cwt",
        )?;
        for (name, doc, keep) in [
            ("sd-jwt-keep-1-0", &sd_jwt, vec![1, 0]),
            ("sd-jwt-keep-none", &sd_jwt, vec![]),
            ("sd-cwt-keep-0", &sd_cwt, vec![0]),
            ("error--index-out-of-range", &sd_jwt, vec![99]),
        ] {
            let req = DiscloseRequest {
                doc: DocRef::from(doc),
                keep,
                view: view(),
            };
            self.add(
                format!("disclose--{name}"),
                "issued above",
                "disclose",
                vec![json(&req)?],
            );
        }
        let present = |doc: &Document, keep: Vec<u32>, nonce: Nonce, randomness| PresentRequest {
            doc: DocRef::from(doc),
            keep,
            holder: holder.key.clone(),
            alg: None,
            aud: Some(AUD.into()),
            nonce: Some(nonce),
            iat: LATER,
            randomness,
            view: view(),
        };
        let text_nonce = Nonce::Text {
            value: "n-42".into(),
        };
        let bytes_nonce = Nonce::Bytes {
            value: Bytes(b"nonce-bytes".to_vec()),
        };
        let presents = vec![
            (
                "sd-jwt-kb",
                present(&sd_jwt, vec![0, 2], text_nonce.clone(), None),
            ),
            (
                "sd-jwt-kb-seeded",
                present(&sd_jwt, vec![1], text_nonce.clone(), Some(seed(8))),
            ),
            (
                "sd-kbt",
                present(&sd_cwt, vec![0], bytes_nonce.clone(), None),
            ),
            (
                "plain-cwt-in-sd-kbt",
                present(&cwt, vec![], bytes_nonce.clone(), Some(seed(8))),
            ),
        ];
        for (name, req) in &presents {
            self.add(
                format!("present--{name}"),
                "issued above",
                "present",
                vec![json(req)?],
            );
        }
        let [(_, jwt_kb), _, (_, kbt), (_, presented)] = presents.as_slice() else {
            return Err("four presentations".into());
        };
        let jwt_kb = must(e.present(jwt_kb), "present sd-jwt")?;
        let kbt = must(e.present(kbt), "present sd-cwt")?;
        let presented = must(e.present(presented), "present cwt")?;
        let mut again = present(&jwt_kb, vec![], text_nonce.clone(), None);
        again.keep = vec![];
        self.add(
            "present--error--already-presented".into(),
            "presented above",
            "present",
            vec![json(&again)?],
        );

        // Validate the round trips.
        let issuer_pub = self.public(&issuer)?;
        for (name, doc, nonce) in [
            ("issued-sd-jwt-kb", &jwt_kb, text_nonce.clone()),
            ("issued-sd-kbt", &kbt, bytes_nonce.clone()),
            (
                "issued-plain-cwt-in-sd-kbt",
                &presented,
                bytes_nonce.clone(),
            ),
        ] {
            let mut req = ValidateRequest::new(DocRef::from(doc), LATER + 5);
            req.keys = vec![issuer_pub.clone()];
            req.expected_aud = Some(AUD.into());
            req.expected_nonce = Some(nonce);
            self.add(
                format!("validate--{name}"),
                "presented above",
                "validate",
                vec![json(&req)?],
            );
        }
        for (name, doc) in [("issued-sd-jwt", &sd_jwt), ("issued-cwt", &cwt)] {
            let mut req = ValidateRequest::new(DocRef::from(doc), LATER);
            req.keys = vec![issuer_pub.clone()];
            self.add(
                format!("validate--{name}"),
                "issued above",
                "validate",
                vec![json(&req)?],
            );
        }

        // Resign an edited JWT and an edited CWT.
        let jwt = must(e.issue(&self.issue_req(json_claims, &issuer)), "issue jwt")?;
        for (name, doc, from, to) in [
            ("jwt", &jwt, "Doe", "Roe"),
            ("cwt", &cwt, "alice", "alicia"),
        ] {
            let edited = e.parse_edit(&EditRequest {
                kind: doc.kind.clone(),
                base: doc.bytes.clone(),
                text: doc.main.text.replacen(from, to, 1),
                view: view(),
            });
            let bytes = edited.bytes.ok_or(format!("edit {name} did not parse"))?;
            let req = ResignRequest {
                doc: DocRef::new(doc.kind.clone(), bytes.0),
                key: issuer.key.clone(),
                alg: None,
                randomness: None,
                view: view(),
            };
            self.add(
                format!("resign--edited-{name}"),
                "issued and edited above",
                "resign",
                vec![json(&req)?],
            );
        }
        let req = ResignRequest {
            doc: DocRef::from(&cwt),
            key: issuer_pub,
            alg: None,
            randomness: Some(seed(3)),
            view: view(),
        };
        self.add(
            "resign--error--public-key".into(),
            "issued above",
            "resign",
            vec![json(&req)?],
        );
        Ok(())
    }

    // ------------------------------------------------------------ validate, lint

    fn validate(&mut self) -> Result<(), String> {
        let rfc7515_key = |section: &str| -> Result<KeyRef, String> {
            let text = std::fs::read_to_string(self.td.join("rfc/rfc7515-jws.json"))
                .map_err(|e| e.to_string())?;
            let root: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
            let jwk = root
                .get("vectors")
                .and_then(|v| v.as_array())
                .and_then(|v| v.iter().find(|v| v.get("section") == Some(&section.into())))
                .and_then(|v| v.get("jwk"))
                .map(|v| v.to_string())
                .ok_or(format!("no RFC 7515 vector {section}"))?;
            Ok(KeyRef::new(jwk.into_bytes()))
        };
        let rfc9901 = KeyRef::new(RFC9901_ISSUER_JWK.as_bytes().to_vec());
        let rfc8392 = self.key("rfc8392-a2.3-ec-p256.cosekey.cbor")?;
        let sd_issuer = self.key("sd-cwt-08-c2-issuer-private.cosekey.cbor")?;
        let cnonce = Nonce::Bytes {
            value: Bytes(hexd(SD_CNONCE_HEX)),
        };
        let rfc_nonce = Nonce::Text {
            value: RFC9901_NONCE.into(),
        };
        struct V {
            name: &'static str,
            file: &'static str,
            keys: Vec<KeyRef>,
            now: i64,
            aud: Option<&'static str>,
            nonce: Option<Nonce>,
        }
        let v = |name, file, keys, now| V {
            name,
            file,
            keys,
            now,
            aud: None,
            nonce: None,
        };
        let cases = vec![
            v(
                "jwt-es256-key",
                "rfc7515-a3-jws-es256.txt",
                vec![rfc7515_key("A.3")?],
                RFC7515_NOW,
            ),
            v(
                "jwt-es256-no-key",
                "rfc7515-a3-jws-es256.txt",
                vec![],
                RFC7515_NOW,
            ),
            v(
                "jwt-es256-expired",
                "rfc7515-a3-jws-es256.txt",
                vec![rfc7515_key("A.3")?],
                LATER,
            ),
            v(
                "jwt-rs256-key",
                "rfc7515-a2-jws-rs256.txt",
                vec![rfc7515_key("A.2")?],
                RFC7515_NOW,
            ),
            v(
                "jwt-es512-wrong-key",
                "rfc7515-a4-jws-es512-nonjson-payload.txt",
                vec![rfc7515_key("A.3")?],
                RFC7515_NOW,
            ),
            v(
                "jwt-hs256-unsupported",
                "rfc7515-a1-jws-hs256.txt",
                vec![],
                RFC7515_NOW,
            ),
            v(
                "jwt-alg-none",
                "rfc7519-s6.1-unsecured-jwt.txt",
                vec![],
                RFC7515_NOW,
            ),
            v(
                "jws-json-general",
                "rfc7515-a6-jws-json-general.json",
                vec![rfc7515_key("A.3")?],
                RFC7515_NOW,
            ),
            v(
                "sd-jwt-s5.1",
                "rfc9901-s5.1-sd-jwt.txt",
                vec![rfc9901.clone()],
                RFC9901_NOW,
            ),
            V {
                aud: Some(RFC9901_AUD),
                nonce: Some(rfc_nonce.clone()),
                ..v(
                    "sd-jwt-kb-s5.2",
                    "rfc9901-s5.2-sd-jwt-kb.txt",
                    vec![rfc9901.clone()],
                    RFC9901_NOW,
                )
            },
            V {
                aud: Some("https://wrong.example"),
                nonce: Some(rfc_nonce.clone()),
                ..v(
                    "sd-jwt-kb-s5.2-wrong-aud",
                    "rfc9901-s5.2-sd-jwt-kb.txt",
                    vec![rfc9901.clone()],
                    RFC9901_NOW,
                )
            },
            v(
                "sd-jwt-a1-decoys",
                "rfc9901-a1-presentation.txt",
                vec![rfc9901.clone()],
                RFC9901_NOW,
            ),
            v(
                "sd-jwt-a2-recursive",
                "rfc9901-a2-presentation.txt",
                vec![rfc9901.clone()],
                RFC9901_NOW,
            ),
            v(
                "sd-jwt-a3-vc",
                "rfc9901-a3-sd-jwt.txt",
                vec![rfc9901.clone()],
                RFC9901_NOW,
            ),
            v(
                "sd-jwt-kb-json-general",
                "rfc9901-s8.3-sd-jwt-kb-json-general.json",
                vec![rfc9901.clone()],
                RFC9901_NOW,
            ),
            v(
                "cwt-tagged",
                "rfc8392-a3-signed-cwt.cbor",
                vec![rfc8392.clone()],
                RFC8392_NOW,
            ),
            v(
                "cwt-untagged",
                "derived-rfc8392-a3-untagged.cbor",
                vec![rfc8392.clone()],
                RFC8392_NOW,
            ),
            v(
                "cwt-tag61-no-key",
                "derived-rfc8392-a3-tag61.cbor",
                vec![],
                RFC8392_NOW,
            ),
            v(
                "cose-sign1-not-cwt",
                "rfc9052-c2.1-sign1.cbor",
                vec![],
                RFC8392_NOW,
            ),
            v(
                "sd-cwt-issuer",
                "sd-cwt-08-issuer-sd-cwt.cbor",
                vec![sd_issuer.clone()],
                SD_NOW,
            ),
            v(
                "sd-cwt-decoys",
                "sd-cwt-08-decoy-sd-cwt.cbor",
                vec![sd_issuer.clone()],
                SD_NOW,
            ),
            V {
                aud: Some(SD_AUD),
                nonce: Some(cnonce.clone()),
                ..v(
                    "sd-kbt",
                    "sd-cwt-08-sd-kbt.cbor",
                    vec![sd_issuer.clone()],
                    SD_NOW,
                )
            },
            V {
                aud: Some(SD_AUD),
                nonce: Some(cnonce.clone()),
                ..v(
                    "sd-kbt-nested",
                    "sd-cwt-08-nested-sd-kbt.cbor",
                    vec![sd_issuer.clone()],
                    SD_NOW,
                )
            },
        ];
        for c in cases {
            let doc = self.open_token(c.file)?;
            let mut req = ValidateRequest::new(DocRef::from(&doc), c.now);
            req.keys = c.keys;
            req.expected_aud = c.aud.map(str::to_owned);
            req.expected_nonce = c.nonce;
            self.add(
                format!("validate--{}", c.name),
                format!("tokens/{}", c.file),
                "validate",
                vec![json(&req)?],
            );
        }
        let claims = self.open_token("rfc7519-s3.1-claims.json")?;
        self.add(
            "validate--error--claim-set".into(),
            "tokens/rfc7519-s3.1-claims.json",
            "validate",
            vec![json(&ValidateRequest::new(DocRef::from(&claims), LATER))?],
        );

        // Lint: fixtures and constructed non-preferred encodings.
        for (name, file) in [
            ("sd-cwt-issuer", "sd-cwt-08-issuer-sd-cwt.cbor"),
            ("cwt-tagged", "rfc8392-a3-signed-cwt.cbor"),
            ("sd-jwt-kb", "rfc9901-s5.2-sd-jwt-kb.txt"),
            ("jwt-alg-none", "rfc7519-s6.1-unsecured-jwt.txt"),
        ] {
            let doc = self.open_token(file)?;
            let req = LintRequest {
                doc: DocRef::from(&doc),
                keys: vec![],
            };
            self.add(
                format!("lint--{name}"),
                format!("tokens/{file}"),
                "lint",
                vec![json(&req)?],
            );
        }
        let constructed: Vec<(&str, Kind, Vec<u8>)> = vec![
            // {1: 2} with a one-byte argument for the key, a duplicate key,
            // an indefinite-length map, a bignum that fits, a non-canonical NaN.
            (
                "cbor-non-preferred",
                Kind::CborClaims,
                hexd("a3 1801 02 01 03 02 c2 41 05"),
            ),
            ("cbor-indefinite", Kind::CborClaims, hexd("bf 01 02 ff")),
            (
                "cbor-nan",
                Kind::CborClaims,
                hexd("a1 01 fb 7ff8 0000 0000 0001"),
            ),
            (
                "json-duplicate-unsafe-int",
                Kind::JsonClaims,
                br#"{"a":1,"a":9007199254740993}"#.to_vec(),
            ),
        ];
        for (name, kind, bytes) in constructed {
            let req = LintRequest {
                doc: DocRef::new(kind, bytes),
                keys: vec![],
            };
            self.add(
                format!("lint--{name}"),
                "constructed",
                "lint",
                vec![json(&req)?],
            );
        }
        Ok(())
    }

    // ------------------------------------------------------------ tamper, reencode, disclosures, decode

    fn manipulate(&mut self) -> Result<(), String> {
        let jwt = self.open_token("rfc7515-a3-jws-es256.txt")?;
        let cwt = self.open_token("rfc8392-a3-signed-cwt.cbor")?;
        let sd_jwt = self.open_token("rfc9901-s5.2-sd-jwt-kb.txt")?;
        let sd_cwt = self.open_token("sd-cwt-08-issuer-sd-cwt.cbor")?;
        let ops: Vec<(&str, &Document, TamperOp)> = vec![
            (
                "jwt-flip-signature-bit",
                &jwt,
                TamperOp::FlipBit {
                    part: PartRef::Signature,
                    bit: 3,
                },
            ),
            (
                "jwt-flip-payload-bit",
                &jwt,
                TamperOp::FlipBit {
                    part: PartRef::Payload,
                    bit: 10,
                },
            ),
            (
                "jwt-alg-none",
                &jwt,
                TamperOp::SetAlg {
                    alg: AlgValue::Name("none".into()),
                },
            ),
            ("jwt-remove-alg", &jwt, TamperOp::RemoveAlg),
            ("jwt-strip-signature", &jwt, TamperOp::StripSignature),
            (
                "jwt-set-kid",
                &jwt,
                TamperOp::SetKid {
                    kid: Some(tokenator_core::KidValue::Text {
                        value: "evil".into(),
                    }),
                },
            ),
            ("jwt-truncate", &jwt, TamperOp::Truncate { len: 40 }),
            (
                "cwt-flip-byte-bit",
                &cwt,
                TamperOp::FlipByteBit { offset: 20, bit: 0 },
            ),
            (
                "cwt-set-alg-label",
                &cwt,
                TamperOp::SetAlg {
                    alg: AlgValue::Label(-8),
                },
            ),
            ("cwt-strip-signature", &cwt, TamperOp::StripSignature),
            (
                "cwt-reencode-protected-wide",
                &cwt,
                TamperOp::ReencodeProtected {
                    how: EquivalentEncoding::WideBstrHead,
                },
            ),
            (
                "cwt-reencode-protected-indefinite",
                &cwt,
                TamperOp::ReencodeProtected {
                    how: EquivalentEncoding::IndefiniteMap,
                },
            ),
            (
                "cwt-set-tags-none",
                &cwt,
                TamperOp::SetTags { tags: vec![] },
            ),
            (
                "cwt-set-tags-61-18",
                &cwt,
                TamperOp::SetTags { tags: vec![61, 18] },
            ),
            (
                "sd-jwt-duplicate-disclosure",
                &sd_jwt,
                TamperOp::DuplicateDisclosure { index: 0 },
            ),
            (
                "sd-jwt-flip-disclosure",
                &sd_jwt,
                TamperOp::FlipBit {
                    part: PartRef::Disclosure { index: 1 },
                    bit: 7,
                },
            ),
            (
                "sd-jwt-flip-kb-signature",
                &sd_jwt,
                TamperOp::FlipBit {
                    part: PartRef::KbSignature,
                    bit: 1,
                },
            ),
            (
                "sd-cwt-duplicate-disclosure",
                &sd_cwt,
                TamperOp::DuplicateDisclosure { index: 1 },
            ),
            (
                "error--jwt-duplicate-disclosure",
                &jwt,
                TamperOp::DuplicateDisclosure { index: 0 },
            ),
        ];
        for (name, doc, op) in ops {
            let req = TamperRequest {
                doc: DocRef::from(doc),
                op,
                view: view(),
            };
            self.add(
                format!("tamper--{name}"),
                "opened fixture",
                "tamper",
                vec![json(&req)?],
            );
        }

        let wide = self.e.tamper(&TamperRequest {
            doc: DocRef::from(&cwt),
            op: TamperOp::ReencodeProtected {
                how: EquivalentEncoding::WideIntegers,
            },
            view: view(),
        });
        let wide = must(wide, "tamper wide")?;
        let reencode = |doc: &Document| ReencodeRequest {
            doc: DocRef::from(doc),
            layers: Vec::new(),
            cose_tags: None,
            cbor: CborSerialization::Preserve,
            deep: false,
            jose: None,
            view: view(),
        };
        let mut reqs: Vec<(&str, ReencodeRequest)> = vec![("cwt-preserve", reencode(&cwt))];
        reqs.push((
            "cwt-base64url",
            ReencodeRequest {
                layers: vec![Layer::Base64Url {
                    padded: false,
                    wrap: None,
                }],
                ..reencode(&cwt)
            },
        ));
        reqs.push((
            "cwt-hex-upper-colons",
            ReencodeRequest {
                layers: vec![Layer::Hex {
                    upper: true,
                    separator: Some(':'),
                    wrap: Some(16),
                }],
                ..reencode(&cwt)
            },
        ));
        reqs.push((
            "cwt-tags-61",
            ReencodeRequest {
                cose_tags: Some(vec![61, 18]),
                ..reencode(&cwt)
            },
        ));
        reqs.push((
            "cwt-untagged",
            ReencodeRequest {
                cose_tags: Some(vec![]),
                ..reencode(&cwt)
            },
        ));
        reqs.push((
            "wide-preferred-plus",
            ReencodeRequest {
                cbor: CborSerialization::PreferredPlus,
                ..reencode(&wide)
            },
        ));
        reqs.push((
            "wide-deterministic-deep",
            ReencodeRequest {
                cbor: CborSerialization::Deterministic,
                deep: true,
                ..reencode(&wide)
            },
        ));
        reqs.push((
            "sd-jwt-json-flattened",
            ReencodeRequest {
                jose: Some(JoseSerialization::JsonFlattened),
                ..reencode(&sd_jwt)
            },
        ));
        reqs.push((
            "sd-jwt-json-general",
            ReencodeRequest {
                jose: Some(JoseSerialization::JsonGeneral),
                ..reencode(&sd_jwt)
            },
        ));
        reqs.push((
            "jwt-base64-std-wrapped",
            ReencodeRequest {
                layers: vec![Layer::Base64Std {
                    padded: true,
                    wrap: Some(20),
                }],
                ..reencode(&jwt)
            },
        ));
        for (name, req) in reqs {
            self.add(
                format!("reencode--{name}"),
                "opened fixture",
                "reencode",
                vec![json(&req)?],
            );
        }

        let ops: Vec<(&str, &Document, Vec<DisclosureOp>)> = vec![
            (
                "sd-jwt-remove",
                &sd_jwt,
                vec![DisclosureOp::Remove { index: 0 }],
            ),
            (
                "sd-jwt-duplicate-move",
                &sd_jwt,
                vec![
                    DisclosureOp::Duplicate { index: 1 },
                    DisclosureOp::Move { from: 0, to: 2 },
                ],
            ),
            (
                "sd-jwt-select",
                &sd_jwt,
                vec![DisclosureOp::Select {
                    indices: vec![2, 0],
                }],
            ),
            (
                "sd-jwt-forge",
                &sd_jwt,
                vec![DisclosureOp::Forge {
                    salt: Some("c2FsdA".into()),
                    claim: Some("admin".into()),
                    value: Some("true".into()),
                }],
            ),
            (
                "sd-jwt-replace-value",
                &sd_jwt,
                vec![DisclosureOp::ReplaceValue {
                    index: 0,
                    value: "\"Mallory\"".into(),
                }],
            ),
            (
                "sd-jwt-add-decoy",
                &sd_jwt,
                vec![DisclosureOp::AddDecoy {
                    at: node("payload/~e"),
                    digest: None,
                }],
            ),
            (
                "sd-cwt-remove-move",
                &sd_cwt,
                vec![
                    DisclosureOp::Remove { index: 0 },
                    DisclosureOp::Move { from: 1, to: 0 },
                ],
            ),
            (
                "sd-cwt-forge",
                &sd_cwt,
                vec![DisclosureOp::Forge {
                    salt: None,
                    claim: Some("500".into()),
                    value: Some("\"x\"".into()),
                }],
            ),
            (
                "error--sd-cwt-add-decoy",
                &sd_cwt,
                vec![DisclosureOp::AddDecoy {
                    at: node("payload/~e"),
                    digest: None,
                }],
            ),
            (
                "error--index",
                &sd_jwt,
                vec![DisclosureOp::Remove { index: 99 }],
            ),
        ];
        for (name, doc, ops) in ops {
            let req = EditDisclosuresRequest {
                doc: DocRef::from(doc),
                ops,
                randomness: Some(seed(11)),
                view: view(),
            };
            self.add(
                format!("edit_disclosures--{name}"),
                "opened fixture",
                "edit_disclosures",
                vec![json(&req)?],
            );
        }

        for (name, doc, id) in [
            ("cwt-protected", &cwt, "protected"),
            ("cwt-signature-not-cbor", &cwt, "signature"),
            ("cwt-claim-not-bytes", &cwt, "payload/~e/1"),
            ("sd-cwt-disclosure", &sd_cwt, "unprotected/17/0"),
            ("error--node-not-found", &cwt, "nope/0"),
        ] {
            let req = DecodeEmbeddedRequest {
                doc: DocRef::from(doc),
                node_id: node(id),
                view: view(),
            };
            self.add(
                format!("decode_embedded--{name}"),
                "opened fixture",
                "decode_embedded",
                vec![json(&req)?],
            );
        }
        Ok(())
    }

    // ------------------------------------------------------------ datetime

    fn datetime(&mut self) {
        let inputs: Vec<(&str, DateTimeInput, Option<i64>, i32)> = vec![
            (
                "epoch",
                DateTimeInput::Epoch {
                    text: "1700000000".into(),
                },
                Some(LATER),
                60,
            ),
            (
                "epoch-fractional",
                DateTimeInput::Epoch {
                    text: "1443944944.5".into(),
                },
                Some(RFC8392_NOW),
                0,
            ),
            (
                "millis",
                DateTimeInput::Millis {
                    millis: 1_700_000_000_123,
                },
                None,
                -330,
            ),
            (
                "rfc3339",
                DateTimeInput::Rfc3339 {
                    text: "2026-10-29T12:00:00+02:00".into(),
                },
                Some(LATER),
                120,
            ),
            (
                "date",
                DateTimeInput::Date {
                    text: "2026-10-29".into(),
                },
                None,
                0,
            ),
            ("days", DateTimeInput::Days { days: 20000 }, None, 0),
            (
                "edn-dt",
                DateTimeInput::Edn {
                    text: "dt'2011-03-22T18:43:00Z'".into(),
                },
                Some(RFC7515_NOW),
                0,
            ),
            (
                "cbor-hex-tag1",
                DateTimeInput::CborHex {
                    hex: "c11a5f5e1000".into(),
                },
                Some(LATER),
                0,
            ),
            (
                "error--rfc3339",
                DateTimeInput::Rfc3339 {
                    text: "yesterday".into(),
                },
                None,
                0,
            ),
        ];
        for (name, input, now, local_offset_minutes) in inputs {
            let req = DateTimeRequest {
                input,
                now,
                local_offset_minutes,
            };
            if let Ok(arg) = json(&req) {
                self.add(
                    format!("datetime--{name}"),
                    "constructed",
                    "datetime",
                    vec![arg],
                );
            }
        }
    }

    // ------------------------------------------------------------ registry

    fn registry(&mut self) -> Result<(), String> {
        let queries: Vec<(&str, RegistryQuery)> = vec![
            (
                "all-jwt-iss",
                RegistryQuery {
                    name: Some("iss".into()),
                    ..Default::default()
                },
            ),
            (
                "cose-alg-minus-7",
                RegistryQuery {
                    kind: Some(RegistryKind::CoseAlg),
                    label: Some(RegistryLabel::Int(-7)),
                    ..Default::default()
                },
            ),
            (
                "jose-header-prefix-x5",
                RegistryQuery {
                    kind: Some(RegistryKind::JoseHeader),
                    prefix: Some("x5".into()),
                    ..Default::default()
                },
            ),
            (
                "cwt-claims",
                RegistryQuery {
                    kind: Some(RegistryKind::CwtClaim),
                    ..Default::default()
                },
            ),
            (
                "none-found",
                RegistryQuery {
                    name: Some("no-such-name".into()),
                    ..Default::default()
                },
            ),
        ];
        for (name, q) in queries {
            self.add(
                format!("registry_lookup--{name}"),
                "bundled registry",
                "registry_lookup",
                vec![json(&q)?],
            );
        }
        // One registry (the smallest XML): the request embeds it. The app
        // test (`app/src/test/wasm/engine.test.ts`) merges all four.
        let req = RegistryMergeRequest {
            base_snapshot: None,
            xml: Bytes(self.read("iana/cwt.xml")?),
            which: RegistryId::Cwt,
        };
        self.add(
            "registry_merge--cwt".into(),
            "iana/cwt.xml",
            "registry_merge",
            vec![json(&req)?],
        );
        let req = RegistryMergeRequest {
            base_snapshot: None,
            xml: Bytes(b"<not-a-registry/>".to_vec()),
            which: RegistryId::Jose,
        };
        self.add(
            "registry_merge--error--bad-xml".into(),
            "constructed",
            "registry_merge",
            vec![json(&req)?],
        );
        Ok(())
    }

    // ------------------------------------------------------------ stack audit (#27)

    fn stack_audit(&mut self) -> Result<(), String> {
        let e = self.e;
        // CBOR at MAX_DEPTH (decodes) and one level deeper (an error).
        for (name, bytes) in [
            ("cbor-maps-max-depth", deep_cbor_maps(MAX_DEPTH)),
            ("cbor-arrays-max-depth", deep_cbor_arrays(MAX_DEPTH)),
            ("cbor-maps-over-max-depth", deep_cbor_maps(MAX_DEPTH + 1)),
        ] {
            let src = format!("constructed: {name}");
            self.add_stack(
                format!("detect--stack--{name}"),
                &src,
                "detect",
                vec![raw(&bytes)],
            );
            let doc = DocRef::new(Kind::CborClaims, bytes.clone());
            self.add_stack(
                format!("render--stack--{name}"),
                &src,
                "render",
                vec![json(&RenderRequest {
                    doc: doc.clone(),
                    layers: Vec::new(),
                    view: view(),
                })?],
            );
            self.add_stack(
                format!("lint--stack--{name}"),
                &src,
                "lint",
                vec![json(&LintRequest { doc, keys: vec![] })?],
            );
        }
        // EDN at MAX_DEPTH: detect (EDN confirmation parses it), open,
        // live edit, and issue a CWT whose payload is that deep.
        let issuer = self.keygen(KeySpec::P256, 1)?;
        let edn_text = deep_edn_maps(MAX_DEPTH);
        let src = "constructed: EDN maps at MAX_DEPTH";
        self.add_stack(
            "detect--stack--edn-max-depth".into(),
            src,
            "detect",
            vec![raw(edn_text.as_bytes())],
        );
        let edn_doc = DocRef::new(Kind::EdnClaims, edn_text.clone().into_bytes());
        self.add_stack(
            "render--stack--edn-max-depth".into(),
            src,
            "render",
            vec![json(&RenderRequest {
                doc: edn_doc.clone(),
                layers: Vec::new(),
                view: view(),
            })?],
        );
        self.add_stack(
            "parse_edit--stack--edn-max-depth".into(),
            src,
            "parse_edit",
            vec![json(&EditRequest {
                kind: Kind::EdnClaims,
                base: Bytes(edn_text.clone().into_bytes()),
                text: edn_text.replacen("0}", "1}", 1),
                view: view(),
            })?],
        );
        // The COSE_Sign1 array and the protected/payload bstr wrap add levels.
        let deep_claims = DocRef::new(
            Kind::EdnClaims,
            format!(
                "{{1: \"https://issuer.example\", 500: {}}}",
                deep_edn_maps(MAX_DEPTH - 8)
            )
            .into_bytes(),
        );
        let deep_cwt_req = self.issue_req(deep_claims, &issuer);
        self.add_stack(
            "issue--stack--deep-cwt".into(),
            src,
            "issue",
            vec![json(&deep_cwt_req)?],
        );
        let deep_cwt = must(e.issue(&deep_cwt_req), "issue deep cwt")?;
        let mut req = ValidateRequest::new(DocRef::from(&deep_cwt), LATER);
        req.keys = vec![self.public(&issuer)?];
        self.add_stack(
            "validate--stack--deep-cwt".into(),
            src,
            "validate",
            vec![json(&req)?],
        );

        // A long chain of nested SD-JWT disclosures: every level marked.
        let deep = deep_json(SD_CHAIN);
        let marks: Vec<NodeId> = (1..=SD_CHAIN)
            .map(|n| node(&vec!["a"; n].join("/")))
            .collect();
        let mut req = self.issue_req(DocRef::new(Kind::JsonClaims, deep.into_bytes()), &issuer);
        req.sd = SdOptions {
            marks,
            ..SdOptions::default()
        };
        req.randomness = Some(seed(12));
        let src =
            "constructed: JSON objects nested SD_CHAIN deep, every level selectively disclosable";
        self.add_stack(
            "issue--stack--sd-jwt-chain".into(),
            src,
            "issue",
            vec![json(&req)?],
        );
        let chain = must(e.issue(&req), "issue sd-jwt chain")?;
        let mut v = ValidateRequest::new(DocRef::from(&chain), LATER);
        v.keys = vec![self.public(&issuer)?];
        self.add_stack(
            "validate--stack--sd-jwt-chain".into(),
            src,
            "validate",
            vec![json(&v)?],
        );
        let all: Vec<u32> = (0..SD_CHAIN as u32).collect();
        self.add_stack(
            "disclose--stack--sd-jwt-chain".into(),
            src,
            "disclose",
            vec![json(&DiscloseRequest {
                doc: DocRef::from(&chain),
                keep: all,
                view: view(),
            })?],
        );

        // ML-DSA-87: keygen, sign (issue, both families), verify.
        let mldsa = self.keygen(KeySpec::MlDsa87, 13)?;
        let src = "seeded ML-DSA-87 key";
        self.add_stack(
            "key_generate--stack--ml-dsa-87".into(),
            src,
            "key_generate",
            vec![json(&KeyGenRequest {
                spec: KeySpec::MlDsa87,
                role: None,
                seed: KeySeed::Seed { bytes: seed(13) },
                kid: None,
            })?],
        );
        for (name, claims, now) in [
            (
                "jose",
                DocRef::new(Kind::JsonClaims, self.token("rfc7519-s3.1-claims.json")?),
                RFC7515_NOW,
            ),
            (
                "cose",
                DocRef::new(Kind::CborClaims, self.token("rfc8392-a1-claims.cbor")?),
                RFC8392_NOW,
            ),
        ] {
            let mut req = self.issue_req(claims, &mldsa);
            req.alg = Some("ML-DSA-87".into());
            req.randomness = Some(seed(14));
            self.add_stack(
                format!("issue--stack--ml-dsa-87-{name}"),
                src,
                "issue",
                vec![json(&req)?],
            );
            let doc = must(e.issue(&req), "issue ml-dsa-87")?;
            let mut v = ValidateRequest::new(DocRef::from(&doc), now);
            v.keys = vec![self.public(&mldsa)?];
            self.add_stack(
                format!("validate--stack--ml-dsa-87-{name}"),
                src,
                "validate",
                vec![json(&v)?],
            );
        }
        Ok(())
    }
}
