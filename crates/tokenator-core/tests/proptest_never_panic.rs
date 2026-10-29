//! Wrong input never panics: `detect`, `open`, `render`, and `parse_edit`
//! on random and mutated inputs (SPEC §11, "Parsers must never panic").
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use proptest::prelude::*;
use tokenator_core::{DocRef, EditRequest, Kind, RenderRequest, ViewOptions};

fn kinds() -> impl Strategy<Value = Kind> {
    prop_oneof![
        Just(Kind::Jwt),
        Just(Kind::JwsCompact),
        Just(Kind::SdJwt { kb: true }),
        Just(Kind::JwsJson { general: true }),
        Just(Kind::SdJwtJson {
            general: false,
            kb: true
        }),
        Just(Kind::CoseSign1),
        Just(Kind::Cwt),
        Just(Kind::SdCwt),
        Just(Kind::SdKbt),
        Just(Kind::JsonClaims),
        Just(Kind::CborClaims),
        Just(Kind::EdnClaims),
    ]
}

/// Fixture bytes with a few random byte edits.
fn mutated() -> impl Strategy<Value = Vec<u8>> {
    let names: Vec<&'static str> = JOSE_FIXTURES
        .iter()
        .chain(COSE_FIXTURES.iter())
        .copied()
        .collect();
    (
        prop::sample::select(names),
        prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..4),
    )
        .prop_map(|(name, edits)| {
            let mut b = token(name);
            for (i, v) in edits {
                let at = i.index(b.len());
                b[at] = v;
            }
            b
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn detect_and_open_random_bytes(input in prop::collection::vec(any::<u8>(), 0..300)) {
        let e = engine();
        for c in e.detect(&input) {
            let _ = e.open(&input, &c, &ViewOptions::default());
        }
    }

    #[test]
    fn detect_and_open_random_text(input in "[ -~\\n]{0,200}") {
        let e = engine();
        for c in e.detect(input.as_bytes()) {
            let _ = e.open(input.as_bytes(), &c, &ViewOptions::default());
        }
    }

    #[test]
    fn detect_and_open_mutated_fixtures(input in mutated()) {
        let e = engine();
        for c in e.detect(&input) {
            let _ = e.open(&input, &c, &ViewOptions::default());
        }
    }

    #[test]
    fn render_any_bytes_as_any_kind(kind in kinds(), input in prop::collection::vec(any::<u8>(), 0..200)) {
        let e = engine();
        let _ = e.render(&RenderRequest {
            doc: DocRef::new(kind, input),
            layers: vec![],
            view: ViewOptions::default(),
        });
    }

    #[test]
    fn parse_edit_never_panics(kind in kinds(), text in "\\PC{0,200}") {
        let e = engine();
        let r = e.parse_edit(&EditRequest {
            kind,
            base: token(CWT_TAGGED).into(),
            text,
            view: ViewOptions::default(),
        });
        prop_assert_eq!(r.ok, r.bytes.is_some());
    }

    #[test]
    fn parse_edit_of_mutated_main_text(cut in any::<prop::sample::Index>(), insert in "[\\[\\]{}<>(),:\"' a-z0-9_]{0,6}") {
        let e = engine();
        let doc = open_token(&e, SD_KBT);
        let mut text: Vec<char> = doc.main.text.chars().collect();
        let at = cut.index(text.len());
        text.splice(at..at, insert.chars());
        let r = e.parse_edit(&EditRequest {
            kind: doc.kind.clone(),
            base: doc.bytes.clone(),
            text: text.into_iter().collect(),
            view: ViewOptions::default(),
        });
        prop_assert_eq!(r.ok, r.document.is_some());
    }
}

#[test]
fn deep_nesting_does_not_overflow() {
    let e = engine();
    let deep_json = format!("{}1{}", "[".repeat(5000), "]".repeat(5000));
    let deep_cbor = [vec![0x81u8; 5000], vec![0x01]].concat();
    for input in [deep_json.as_bytes().to_vec(), deep_cbor] {
        for c in e.detect(&input) {
            let _ = e.open(&input, &c, &ViewOptions::default());
        }
        for kind in [Kind::JsonClaims, Kind::CborClaims, Kind::EdnClaims] {
            let _ = e.render(&RenderRequest {
                doc: DocRef::new(kind, input.clone()),
                layers: vec![],
                view: ViewOptions::default(),
            });
        }
    }
}
