//! Property tests: detection never panics and its invariants hold, and
//! `rewrap`/`unwrap_layers` are inverses over arbitrary layer stacks.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use proptest::prelude::*;
use tokenator_detect::{Kind, Layer, PathSegment, rewrap, unwrap_layers};

fn fixtures() -> Vec<Vec<u8>> {
    vec![
        token(JWT),
        token(SD_JWT_KB),
        token(CWT_TAG18),
        token(SD_CWT),
        token(SD_KBT),
        token("rfc9901-s8.3-sd-jwt-kb-json-general.json"),
        token("sd-cwt-08-fig4-claims.edn"),
        key("rfc7517-a1-public.jwks.json"),
        key("rfc8152-c7.1-public.cosekeyset.cbor"),
        key("rfc8410-s10.2-x25519-cert.pem"),
    ]
}

#[derive(Clone, Debug)]
enum Mutation {
    Flip(usize, u8),
    Set(usize, u8),
    Insert(usize, u8),
    Delete(usize),
    Truncate(usize),
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        (any::<usize>(), 0u8..8).prop_map(|(i, b)| Mutation::Flip(i, b)),
        (any::<usize>(), any::<u8>()).prop_map(|(i, b)| Mutation::Set(i, b)),
        (any::<usize>(), any::<u8>()).prop_map(|(i, b)| Mutation::Insert(i, b)),
        any::<usize>().prop_map(Mutation::Delete),
        any::<usize>().prop_map(Mutation::Truncate),
    ]
}

fn apply(mut v: Vec<u8>, muts: &[Mutation]) -> Vec<u8> {
    for m in muts {
        if v.is_empty() {
            break;
        }
        let n = v.len();
        match *m {
            Mutation::Flip(i, b) => v[i % n] ^= 1 << b,
            Mutation::Set(i, b) => v[i % n] = b,
            Mutation::Insert(i, b) => v.insert(i % (n + 1), b),
            Mutation::Delete(i) => {
                v.remove(i % n);
            }
            Mutation::Truncate(i) => v.truncate(i % n),
        }
    }
    v
}

fn ws() -> impl Strategy<Value = String> {
    "[ \t\r\n]{1,4}"
}

fn tag() -> impl Strategy<Value = u64> {
    prop_oneof![Just(18u64), Just(61), Just(55799), 0u64..30, any::<u64>()]
}

/// Encoding layers whose output is ASCII text.
fn encoding() -> impl Strategy<Value = Layer> {
    let wrap = prop::option::of(1usize..100);
    prop_oneof![
        (any::<bool>(), wrap.clone()).prop_map(|(padded, wrap)| Layer::Base64Url { padded, wrap }),
        (any::<bool>(), wrap.clone()).prop_map(|(padded, wrap)| Layer::Base64Std { padded, wrap }),
        (
            any::<bool>(),
            prop::option::of(prop_oneof![Just(' '), Just(':')]),
            wrap
        )
            .prop_map(|(upper, separator, wrap)| Layer::Hex {
                upper,
                separator,
                wrap
            }),
    ]
}

fn json_path() -> impl Strategy<Value = Vec<PathSegment>> {
    prop::collection::vec(
        prop_oneof![
            "[a-z_]{1,8}".prop_map(PathSegment::Key),
            (0usize..4).prop_map(PathSegment::Index),
        ],
        1..4,
    )
}

/// A layer stack (outermost first) and whether it ends in CBOR tags (which
/// need the payload to be one CBOR item).
fn stack(url: bool) -> impl Strategy<Value = Vec<Layer>> {
    (
        prop::collection::vec(tag(), 0..3),
        prop::option::of(encoding()),
        any::<bool>(),
        prop::option::of(json_path()),
        prop::option::of(prop_oneof![Just('"'), Just('\''), Just('`')]),
        prop::option::of(prop_oneof![Just("Bearer "), Just("bearer  ")]),
        prop::option::of(prop_oneof![Just("Authorization: "), Just("authorization:")]),
        prop::option::of((ws(), ws())),
    )
        .prop_map(
            move |(tags, enc, use_url, json, quote, bearer, auth, trimmed)| {
                let mut inner_first = Vec::new();
                for t in tags.into_iter().rev() {
                    inner_first.push(Layer::CborTag(t));
                }
                // Text layers need a text payload: only add them over an encoding.
                if let Some(enc) = enc {
                    inner_first.push(enc);
                    if url && use_url {
                        inner_first.push(Layer::UrlEncoded);
                    }
                    if let Some(path) = json {
                        inner_first.push(Layer::JsonField { path });
                    }
                    if let Some(quote) = quote {
                        inner_first.push(Layer::Quotes { quote });
                    }
                    if let Some(p) = bearer {
                        inner_first.push(Layer::BearerPrefix {
                            prefix: p.to_owned(),
                        });
                    }
                    if let Some(p) = auth {
                        inner_first.push(Layer::AuthorizationHeader {
                            prefix: p.to_owned(),
                        });
                    }
                    if let Some((leading, trailing)) = trimmed {
                        inner_first.push(Layer::Trim { leading, trailing });
                    }
                }
                inner_first.reverse();
                inner_first
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn never_panics_on_bytes(input in prop::collection::vec(any::<u8>(), 0..512)) {
        run(&input);
    }

    #[test]
    fn never_panics_on_strings(input in ".{0,300}") {
        run(input.as_bytes());
    }

    #[test]
    fn never_panics_on_token_alphabet(input in "[A-Za-z0-9_\\-.~=+/%: \n\"'{}\\[\\],]{0,300}") {
        run(input.as_bytes());
    }

    #[test]
    fn never_panics_on_cbor_like_bytes(
        head in prop::sample::select(vec![0xd2u8, 0xd8, 0x84, 0xa1, 0xa4, 0x9f, 0xbf, 0x5f]),
        rest in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let mut input = vec![head];
        input.extend(rest);
        run(&input);
    }

    #[test]
    fn rewrap_then_unwrap_is_identity(
        data in prop::collection::vec(any::<u8>(), 1..200),
        layers in stack(true),
    ) {
        // CBOR tags need one well-formed item inside: use a CBOR bstr.
        let payload = if layers.iter().any(|l| matches!(l, Layer::CborTag(_))) {
            cbor(&bstr(&data))
        } else {
            data
        };
        let wrapped = rewrap(&payload, &layers);
        let back = unwrap_layers(&wrapped, &layers);
        prop_assert_eq!(back, Ok(payload));
        run(&wrapped);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn never_panics_on_mutated_fixtures(
        which in 0usize..10,
        muts in prop::collection::vec(mutation(), 1..8),
    ) {
        let input = apply(fixtures()[which].clone(), &muts);
        run(&input);
    }

    #[test]
    fn never_panics_on_mutated_encoded_fixtures(
        which in 0usize..10,
        enc in encoding(),
        muts in prop::collection::vec(mutation(), 1..4),
    ) {
        let input = apply(rewrap(&fixtures()[which], &[enc]), &muts);
        run(&input);
    }

    #[test]
    fn detect_recognizes_its_own_rewrap_output(
        layers in stack(false),
    ) {
        // A real CWT inside any canonical stack is found with exactly those
        // layers. (UrlEncoded is excluded: it is only recorded when the text
        // actually contains an escape.)
        let mut layers = layers;
        layers.retain(|l| !matches!(l, Layer::CborTag(_)));
        // One byte per line leaves no room for a separator, so the text
        // cannot tell which one was asked for.
        for l in &mut layers {
            if let Layer::Hex { separator, wrap: Some(1), .. } = l {
                *separator = None;
            }
        }
        layers.push(Layer::CborTag(18));
        let input = rewrap(&cwt_untagged(), &layers);
        let cands = run(&input);
        prop_assert!(
            find_with(&cands, &Kind::Cwt, &layers).is_some(),
            "layers {:?} not found in {}",
            layers,
            summary(&cands)
        );
    }
}
