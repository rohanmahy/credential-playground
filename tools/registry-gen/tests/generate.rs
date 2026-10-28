//! registry-gen over the IANA fixtures.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::Path;

use registry_gen::{Args, GenError, Inputs, build, generate};
use tokenator_registry::{Registry, RegistryId, Source};

const CWT: &[u8] = include_bytes!("../../../testdata/iana/cwt.xml");
const COSE: &[u8] = include_bytes!("../../../testdata/iana/cose.xml");
const JWT: &[u8] = include_bytes!("../../../testdata/iana/jwt.xml");
const JOSE: &[u8] = include_bytes!("../../../testdata/iana/jose.xml");
const LOCAL: &str = include_str!("../../../crates/tokenator-registry/data/local-additions.json");
const CHECKED_IN: &[u8] = include_bytes!("../../../crates/tokenator-registry/data/snapshot.json");

fn inputs() -> Inputs<'static> {
    Inputs {
        cwt: CWT,
        cose: COSE,
        jwt: JWT,
        jose: JOSE,
        local_additions: LOCAL,
    }
}

fn args(v: &[&str]) -> Result<Args, GenError> {
    Args::parse(v.iter().map(|s| s.to_string()))
}

#[test]
fn generates_loadable_snapshot_with_well_known_entries() {
    let bytes = generate(&inputs()).unwrap();
    let r = Registry::from_snapshot(&bytes).unwrap();
    assert_eq!(r.cose_alg(-7).unwrap().name, "ES256");
    assert_eq!(r.cose_alg(-50).unwrap().name, "ML-DSA-87");
    assert_eq!(r.cose_header(4).unwrap().name, "kid");
    assert_eq!(r.cose_header(33).unwrap().name, "x5chain");
    assert_eq!(r.cwt_claim(8).unwrap().name, "cnf");
    assert_eq!(r.jose_header("typ").unwrap().description, "Type");
    assert_eq!(
        r.jose_header("x5c").unwrap().description,
        "X.509 Certificate Chain"
    );
    assert!(r.jwt_claim("_sd").is_some());
    assert_eq!(r.cbor_tag(58).unwrap().source, Source::Local);
    assert_eq!(r.cose_header(17).unwrap().source, Source::Iana);
    assert_eq!(r.sd_cwt_revision(), "draft-ietf-spice-sd-cwt-08");
    assert_eq!(
        r.info()
            .iana_updated
            .get(&RegistryId::Cose)
            .map(String::as_str),
        Some("2026-08-25")
    );
}

#[test]
fn generate_is_deterministic() {
    assert_eq!(generate(&inputs()).unwrap(), generate(&inputs()).unwrap());
}

#[test]
fn generate_equals_build_then_serialize() {
    let r = build(&inputs()).unwrap();
    assert_eq!(r.to_snapshot().unwrap(), generate(&inputs()).unwrap());
}

#[test]
fn checked_in_snapshot_is_up_to_date() {
    // Fails until `cargo run -p registry-gen` has been run after changing the
    // fixtures or local-additions.json.
    assert!(
        !CHECKED_IN.is_empty(),
        "data/snapshot.json is still the empty placeholder"
    );
    assert!(
        generate(&inputs()).unwrap() == CHECKED_IN,
        "crates/tokenator-registry/data/snapshot.json is stale: run `cargo run -p registry-gen`"
    );
}

#[test]
fn bad_iana_input_names_the_registry() {
    let mut i = inputs();
    i.jose = b"<registry id=\"jose\"><broken";
    match generate(&i) {
        Err(GenError::Registry {
            registry: Some(RegistryId::Jose),
            ..
        }) => {}
        other => panic!("expected jose error, got {other:?}"),
    }
}

#[test]
fn swapped_inputs_are_rejected() {
    let mut i = inputs();
    i.cwt = JWT;
    assert!(matches!(
        generate(&i),
        Err(GenError::Registry {
            registry: Some(RegistryId::Cwt),
            ..
        })
    ));
}

#[test]
fn bad_local_additions_are_rejected() {
    let mut i = inputs();
    i.local_additions = "{ nope";
    match generate(&i) {
        Err(e @ GenError::Registry { registry: None, .. }) => {
            assert!(e.to_string().starts_with("local additions"), "{e}");
        }
        other => panic!("expected local additions error, got {other:?}"),
    }
}

#[test]
fn default_args_point_into_the_repo() {
    let a = args(&[]).unwrap();
    assert!(a.input_dir.ends_with("testdata/iana"), "{:?}", a.input_dir);
    assert!(
        a.local_additions
            .ends_with("crates/tokenator-registry/data/local-additions.json"),
        "{:?}",
        a.local_additions
    );
    assert!(
        a.out
            .ends_with("crates/tokenator-registry/data/snapshot.json"),
        "{:?}",
        a.out
    );
    assert!(
        a.input_dir.join("cose.xml").exists(),
        "default input dir should resolve"
    );
}

#[test]
fn explicit_args() {
    let a = args(&[
        "--input-dir",
        "/tmp/in",
        "--local",
        "/tmp/local.json",
        "--out",
        "/tmp/out.json",
    ])
    .unwrap();
    assert_eq!(a.input_dir, Path::new("/tmp/in"));
    assert_eq!(a.local_additions, Path::new("/tmp/local.json"));
    assert_eq!(a.out, Path::new("/tmp/out.json"));
    let b = args(&["--out", "x.json"]).unwrap();
    assert_eq!(b.out, Path::new("x.json"));
    assert!(b.input_dir.ends_with("testdata/iana"));
}

#[test]
fn bad_args() {
    assert!(matches!(args(&["--bogus"]), Err(GenError::Usage(_))));
    assert!(matches!(args(&["--out"]), Err(GenError::Usage(_))));
    assert!(matches!(args(&["positional"]), Err(GenError::Usage(_))));
}

#[test]
fn run_reports_missing_input_files() {
    let a = Args {
        input_dir: "/nonexistent/registry-gen-test".into(),
        local_additions: "/nonexistent/local.json".into(),
        out: std::env::temp_dir().join("registry-gen-should-not-exist.json"),
    };
    match registry_gen::run(&a) {
        Err(GenError::Io { path, .. }) => assert!(path.starts_with("/nonexistent")),
        other => panic!("expected Io error, got {other:?}"),
    }
    assert!(!a.out.exists());
}

#[test]
fn run_writes_snapshot() {
    let dir = std::env::temp_dir().join(format!("registry-gen-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("snapshot.json");
    let mut a = args(&[]).unwrap();
    a.out = out.clone();
    let n = registry_gen::run(&a).unwrap();
    let written = std::fs::read(&out).unwrap();
    let r = Registry::from_snapshot(&written).unwrap();
    assert_eq!(r.len(), n);
    assert_eq!(written, generate(&inputs()).unwrap());
    std::fs::remove_dir_all(&dir).unwrap();
}
