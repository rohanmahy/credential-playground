//! Property tests: never panic on arbitrary bytes, and exact round trips of
//! arbitrary items.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::{check_spans, sem, sem_unordered};
use proptest::prelude::*;
use tokenator_cbor::{
    EncodeMode, FloatWidth, Item, Value, Width, decode, decode_seq, deterministic_findings, encode,
    preferred_findings,
};

/// Everything a caller might do with a decoded item.
fn exercise(bytes: &[u8]) {
    if let Ok(item) = decode(bytes) {
        assert_eq!(encode(&item, EncodeMode::Preserve), bytes);
        check_spans(&item, bytes).unwrap();
        let _ = preferred_findings(&item);
        let _ = deterministic_findings(&item);
        let det = encode(&item, EncodeMode::Deterministic);
        let again = decode(&det).unwrap();
        assert!(deterministic_findings(&again).is_empty());
        let _ = item.into_owned();
    }
    if let Ok(items) = decode_seq(bytes) {
        let mut out = Vec::new();
        for item in &items {
            out.extend(encode(item, EncodeMode::Preserve));
        }
        assert_eq!(out, bytes);
    }
}

/// Byte strings biased towards CBOR structure: heads with every additional
/// information value, breaks, and short runs.
fn cborish() -> impl Strategy<Value = Vec<u8>> {
    let byte = prop_oneof![
        4 => any::<u8>(),
        2 => (0u8..8, prop_oneof![0u8..24, 24u8..32]).prop_map(|(m, ai)| (m << 5) | ai),
        1 => Just(0xffu8),
        1 => Just(0x00u8),
    ];
    prop::collection::vec(byte, 0..64)
}

fn width() -> impl Strategy<Value = Width> {
    prop_oneof![
        Just(Width::Immediate),
        Just(Width::U8),
        Just(Width::U16),
        Just(Width::U32),
        Just(Width::U64),
    ]
}

fn float() -> impl Strategy<Value = Value<'static>> {
    let width = prop_oneof![
        Just(FloatWidth::F16),
        Just(FloatWidth::F32),
        Just(FloatWidth::F64)
    ];
    prop_oneof![
        (any::<u16>(), Just(FloatWidth::F16)).prop_map(|(b, w)| (f64::from(half_to_f32(b)), w)),
        (any::<u32>(), Just(FloatWidth::F32)).prop_map(|(b, w)| (f64::from(f32::from_bits(b)), w)),
        (any::<u64>(), Just(FloatWidth::F64)).prop_map(|(b, w)| (f64::from_bits(b), w)),
        (any::<f64>(), width),
    ]
    .prop_map(|(f, w)| Value::Float(f, w))
}

/// IEEE binary16 to binary32 for non-NaN values (NaNs map to the f32 quiet
/// NaN; payload handling is tested with fixed vectors instead).
fn half_to_f32(bits: u16) -> f32 {
    let sign = if bits & 0x8000 != 0 { -1.0f32 } else { 1.0 };
    let exp = i32::from((bits >> 10) & 0x1f);
    let mant = f32::from(bits & 0x3ff);
    match exp {
        0 => sign * mant * 2f32.powi(-24),
        31 if mant == 0.0 => sign * f32::INFINITY,
        31 => f32::NAN,
        _ => sign * (1.0 + mant / 1024.0) * 2f32.powi(exp - 15),
    }
}

fn leaf() -> impl Strategy<Value = Item<'static>> {
    let value = prop_oneof![
        any::<u64>().prop_map(Value::Uint),
        any::<u64>().prop_map(Value::Nint),
        prop::collection::vec(any::<u8>(), 0..40).prop_map(|b| Value::Bytes(b.into())),
        ".{0,20}".prop_map(|s| Value::Text(s.into())),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Null),
        Just(Value::Undefined),
        prop_oneof![0u8..20, 32u8..=255].prop_map(Value::Simple),
        float(),
    ];
    (value, width(), any::<bool>()).prop_map(|(v, w, keep)| {
        let item = Item::new(v);
        if keep { item } else { item.with_width(w) }
    })
}

fn arb_item() -> impl Strategy<Value = Item<'static>> {
    leaf().prop_recursive(6, 64, 8, |inner| {
        prop_oneof![
            (
                prop::collection::vec(inner.clone(), 0..8),
                width(),
                any::<bool>()
            )
                .prop_map(|(items, w, indef)| {
                    Item::array(items).with_width(if indef { Width::Indefinite } else { w })
                }),
            (
                prop::collection::vec((inner.clone(), inner.clone()), 0..6),
                width(),
                any::<bool>()
            )
                .prop_map(|(entries, w, indef)| {
                    Item::map(entries).with_width(if indef { Width::Indefinite } else { w })
                }),
            (any::<u64>(), inner.clone(), width())
                .prop_map(|(t, item, w)| Item::tag(t, item).with_width(w)),
            prop::collection::vec(prop::collection::vec(any::<u8>(), 0..8), 0..4).prop_map(
                |chunks| Item::indefinite_string(chunks.into_iter().map(Item::bytes).collect())
            ),
            prop::collection::vec(".{0,6}", 1..4).prop_map(|chunks| {
                Item::indefinite_string(chunks.into_iter().map(Item::text).collect())
            }),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 4096, ..ProptestConfig::default() })]

    #[test]
    fn never_panics_on_random_bytes(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        exercise(&bytes);
    }

    #[test]
    fn never_panics_on_cbor_like_bytes(bytes in cborish()) {
        exercise(&bytes);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1024, ..ProptestConfig::default() })]

    /// Encoding any item in Preserve mode gives bytes that decode and
    /// re-encode to the same bytes, with the same meaning.
    #[test]
    fn preserve_encoding_is_stable(item in arb_item()) {
        let bytes = encode(&item, EncodeMode::Preserve);
        let decoded = decode(&bytes).unwrap();
        prop_assert_eq!(encode(&decoded, EncodeMode::Preserve), bytes.clone());
        prop_assert_eq!(sem(&decoded), sem(&item));
        check_spans(&decoded, &bytes).unwrap();
    }

    /// Deterministic encoding keeps the meaning, is idempotent, and leaves
    /// nothing for deterministic_findings to report.
    #[test]
    fn deterministic_encoding_is_canonical(item in arb_item()) {
        let det = encode(&item, EncodeMode::Deterministic);
        let decoded = decode(&det).unwrap();
        prop_assert_eq!(sem_unordered(&decoded), sem_unordered(&item));
        prop_assert_eq!(encode(&decoded, EncodeMode::Deterministic), det.clone());
        prop_assert_eq!(encode(&decoded, EncodeMode::Preserve), det.clone());
        prop_assert!(deterministic_findings(&decoded).is_empty());
    }

    /// deterministic_findings is empty exactly when the bytes already are
    /// the deterministic encoding.
    #[test]
    fn no_findings_iff_already_deterministic(item in arb_item()) {
        let bytes = encode(&item, EncodeMode::Preserve);
        let decoded = decode(&bytes).unwrap();
        let det = encode(&decoded, EncodeMode::Deterministic);
        prop_assert_eq!(deterministic_findings(&decoded).is_empty(), det == bytes);
    }
}
