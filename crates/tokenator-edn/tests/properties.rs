//! Property tests: parsing never panics, printing round-trips for arbitrary
//! items, span maps and hex rows stay consistent, and instants survive
//! their conversions.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::{check_span_map, roundtrip_options};
use proptest::prelude::*;
use proptest::sample::select;
use tokenator_cbor::{EncodeMode, FloatWidth, Item, Value, Width, decode, encode};
use tokenator_edn::datetime::{EpochValue, Instant};
use tokenator_edn::{
    EmbeddedCbor, HexOptions, HexRowKind, ParseOptions, PrintOptions, annotated_hex, parse,
    parse_seq, parse_with, print,
};

// ---------------------------------------------------------------- strategies

const TOKENS: &[&str] = &[
    "[",
    "]",
    "{",
    "}",
    "(",
    ")",
    "<<",
    ">>",
    ",",
    ":",
    "_",
    "_0",
    "_1",
    "_3",
    "_i",
    "_x",
    "'",
    "\"",
    "`",
    "```",
    "/",
    "*",
    "/*",
    "*/",
    "#",
    "//",
    "\n",
    "\r\n",
    "\t",
    " ",
    "h",
    "b64",
    "dt",
    "DT",
    "ip",
    "hash",
    "t1",
    "b1",
    "ilbs",
    "float",
    "cri",
    "0",
    "1",
    "9",
    "-",
    "+",
    ".",
    "e",
    "x",
    "0x",
    "0b",
    "0o",
    "p",
    "NaN",
    "Infinity",
    "true",
    "null",
    "undefined",
    "simple(",
    "\\",
    "\\u",
    "\\u{",
    "d800",
    "ff",
    "...",
    "\u{fc}",
    "\u{1F600}",
    "\u{0}",
    "18446744073709551616",
    "24(",
    "2013-03-21T20:04:00Z",
];

fn edn_like() -> impl Strategy<Value = String> {
    prop::collection::vec(select(TOKENS), 0..48).prop_map(|t| t.concat())
}

fn width() -> impl Strategy<Value = Width> {
    prop_oneof![
        4 => Just(Width::Immediate),
        1 => Just(Width::U8),
        1 => Just(Width::U16),
        1 => Just(Width::U32),
        1 => Just(Width::U64),
    ]
}

fn container_width() -> impl Strategy<Value = Width> {
    prop_oneof![4 => width(), 1 => Just(Width::Indefinite)]
}

fn small_text() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<char>(), 0..6).prop_map(String::from_iter)
}

/// Floats as they come off the wire: every bit pattern of every width,
/// including NaN payloads and subnormals.
fn float_item() -> impl Strategy<Value = Item<'static>> {
    prop_oneof![
        any::<u16>().prop_map(|b| {
            let [x, y] = b.to_be_bytes();
            vec![0xf9, x, y]
        }),
        any::<u32>().prop_map(|b| {
            let mut v = vec![0xfa];
            v.extend(b.to_be_bytes());
            v
        }),
        any::<u64>().prop_map(|b| {
            let mut v = vec![0xfb];
            v.extend(b.to_be_bytes());
            v
        }),
    ]
    .prop_map(|bytes| decode(&bytes).unwrap().into_owned())
}

fn leaf() -> impl Strategy<Value = Item<'static>> {
    prop_oneof![
        (any::<u64>(), width()).prop_map(|(n, w)| Item::new(Value::Uint(n)).with_width(w)),
        (0u64..30, width()).prop_map(|(n, w)| Item::new(Value::Uint(n)).with_width(w)),
        (any::<u64>(), width()).prop_map(|(n, w)| Item::new(Value::Nint(n)).with_width(w)),
        (prop::collection::vec(any::<u8>(), 0..8), width())
            .prop_map(|(b, w)| Item::bytes(b).with_width(w)),
        (small_text(), width()).prop_map(|(t, w)| Item::text(t).with_width(w)),
        any::<u8>()
            .prop_filter("well-formed simple", |n| !(24..32).contains(n))
            .prop_map(Item::simple),
        float_item(),
        (
            any::<f64>(),
            select(vec![FloatWidth::F16, FloatWidth::F32, FloatWidth::F64])
        )
            .prop_map(|(f, w)| Item::new(Value::Float(f, w))),
        prop::collection::vec(
            (prop::collection::vec(any::<u8>(), 0..4), width())
                .prop_map(|(b, w)| Item::bytes(b).with_width(w)),
            0..4
        )
        .prop_map(Item::indefinite_string),
        prop::collection::vec(
            (small_text(), width()).prop_map(|(t, w)| Item::text(t).with_width(w)),
            1..4
        )
        .prop_map(Item::indefinite_string),
        // Byte strings holding CBOR, to exercise embedded rendering.
        prop::collection::vec(any::<u8>(), 1..4).prop_map(|b| {
            let mut v = vec![0x82];
            v.extend(b.iter().map(|x| x & 0x17));
            v.truncate(3);
            Item::bytes(v)
        }),
    ]
}

fn item() -> impl Strategy<Value = Item<'static>> {
    leaf().prop_recursive(4, 48, 5, |inner| {
        prop_oneof![
            (
                prop::collection::vec(inner.clone(), 0..5),
                container_width()
            )
                .prop_map(|(v, w)| Item::array(v).with_width(w)),
            (
                prop::collection::vec((inner.clone(), inner.clone()), 0..4),
                container_width()
            )
                .prop_map(|(v, w)| Item::map(v).with_width(w)),
            (
                select(vec![
                    0u64,
                    1,
                    2,
                    3,
                    24,
                    63,
                    100,
                    888,
                    999,
                    1004,
                    55799,
                    u64::MAX
                ]),
                inner.clone(),
                width()
            )
                .prop_map(|(t, i, w)| Item::tag(t, i).with_width(w)),
            (any::<u64>(), inner, width()).prop_map(|(t, i, w)| Item::tag(t, i).with_width(w)),
        ]
    })
}

// ---------------------------------------------------------------- never panic

fn exercise(text: &str) {
    let _ = parse_seq(text);
    let _ = parse_with(
        text,
        &ParseOptions {
            sequence: true,
            ..ParseOptions::default()
        },
    );
    if let Ok(item) = parse(text) {
        let bytes = encode(&item, EncodeMode::Preserve).unwrap();
        let decoded = decode(&bytes).unwrap_or_else(|e| panic!("{text:?} encoded badly: {e}"));
        let again = print(&decoded, &PrintOptions::new()).text;
        let back = parse(&again).unwrap_or_else(|e| panic!("{again:?}: {e:?}"));
        assert_eq!(
            encode(&back, EncodeMode::Preserve).unwrap(),
            bytes,
            "{text:?} -> {again:?}"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn arbitrary_strings_never_panic(text in any::<String>()) {
        exercise(&text);
    }

    #[test]
    fn edn_like_strings_never_panic(text in edn_like()) {
        exercise(&text);
    }

    #[test]
    fn valid_documents_with_garbage_never_panic(
        text in edn_like(),
        at in any::<prop::sample::Index>(),
    ) {
        let base = "{1: [h'00', \"a\", 1.5_2], 2: 1(1363896240), 3: <<[_ 1]>>}";
        let cut = at.index(base.len() + 1);
        if base.is_char_boundary(cut) {
            exercise(&format!("{}{text}{}", &base[..cut], &base[cut..]));
            exercise(&base[..cut]);
        }
    }
}

// ---------------------------------------------------------------- round trips

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn built_items_print_and_reparse_exactly(item in item()) {
        let want = encode(&item, EncodeMode::Preserve).unwrap();
        for (name, opts) in roundtrip_options() {
            let text = print(&item, &opts).text;
            let back = parse(&text);
            prop_assert!(back.is_ok(), "[{name}] {text:?}: {:?}", back.err());
            prop_assert_eq!(
                encode(&back.unwrap(), EncodeMode::Preserve).unwrap(),
                want.clone(),
                "[{}] {}",
                name,
                text
            );
        }
    }

    #[test]
    fn default_output_parses_without_warnings(item in item()) {
        let bytes = encode(&item, EncodeMode::Preserve).unwrap();
        // Tags 888 and 999 warn by design (ellipsis, unknown extension), and
        // so do non-canonical NaNs (#7).
        let decoded = decode(&bytes).unwrap();
        prop_assume!(!common::nodes(&decoded).iter().any(|(_, i)| match i.value {
            Value::Tag(888 | 999, _) => true,
            Value::Float(f, _) if f.is_nan() => {
                encode(i, EncodeMode::Preserve).unwrap() != [0xf9, 0x7e, 0x00]
            }
            _ => false,
        }));
        let strict = ParseOptions { strict: true, ..ParseOptions::default() };
        for opts in [PrintOptions::new(), PrintOptions::indented(2)] {
            let text = print(&decoded, &opts).text;
            let parsed = parse_with(&text, &strict);
            prop_assert!(parsed.is_ok(), "{text:?}: {:?}", parsed.err());
            let parsed = parsed.unwrap();
            prop_assert!(parsed.warnings.is_empty(), "{text:?}: {:?}", parsed.warnings);
            prop_assert_eq!(encode(&parsed.items[0], EncodeMode::Preserve).unwrap(), bytes.clone());
        }
    }

    #[test]
    fn decoded_items_have_consistent_spans_and_rows(item in item()) {
        let bytes = encode(&item, EncodeMode::Preserve).unwrap();
        let decoded = decode(&bytes).unwrap();
        common::rt(&bytes).map_err(TestCaseError::fail)?;
        for opts in [PrintOptions::new(), PrintOptions::indented(2)] {
            let r = print(&decoded, &opts);
            check_span_map(&decoded, Some(&bytes), &r).map_err(TestCaseError::fail)?;
        }
        check_rows_and_spans(&decoded, &bytes, EmbeddedCbor::OFF)?;
    }

    #[test]
    fn embedded_views_have_consistent_spans_and_rows(item in item()) {
        let bytes = encode(&item, EncodeMode::Preserve).unwrap();
        let decoded = decode(&bytes).unwrap();
        common::rt_embedded(&bytes).map_err(TestCaseError::fail)?;
        let paths = common::all_bstr_paths(&decoded);
        check_rows_and_spans(&decoded, &bytes, EmbeddedCbor::tagged())?;
        check_rows_and_spans(&decoded, &bytes, EmbeddedCbor::at(&paths))?;
    }
}

/// Hex rows and the indented printer agree on paths, and rows cover the
/// bytes exactly once.
fn check_rows_and_spans(
    decoded: &tokenator_cbor::Item,
    bytes: &[u8],
    embedded: EmbeddedCbor<'_>,
) -> Result<(), TestCaseError> {
    let rows = annotated_hex(
        decoded,
        bytes,
        &HexOptions {
            embedded_cbor: embedded,
            ..HexOptions::default()
        },
    );
    let r = print(
        decoded,
        &PrintOptions {
            embedded_cbor: embedded,
            ..PrintOptions::indented(2)
        },
    );
    let row_paths: Vec<_> = rows
        .rows
        .iter()
        .filter(|r| r.kind == HexRowKind::Item)
        .map(|r| r.path.clone())
        .collect();
    let span_paths: Vec<_> = r.spans.iter().map(|(p, _)| p.clone()).collect();
    prop_assert_eq!(row_paths, span_paths);
    let mut at = 0;
    for row in &rows.rows {
        prop_assert_eq!(row.head.start, at);
        at = row.payload.end;
    }
    prop_assert_eq!(at, bytes.len());
    Ok(())
}

// ---------------------------------------------------------------- instants

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn rfc3339_roundtrip(secs in -62_167_219_200i64..=253_402_300_799, nanos in 0u32..1_000_000_000) {
        let t = Instant::new(secs, nanos).unwrap();
        let text = t.to_rfc3339().unwrap();
        prop_assert_eq!(Instant::parse_rfc3339(&text).unwrap(), t, "{}", text);
        let date = t.to_date().unwrap();
        prop_assert_eq!(&text[..10], date.as_str());
        prop_assert_eq!(Instant::parse_date(&date).unwrap(), Instant::from_days(t.days()));
    }

    #[test]
    fn offsets_roundtrip(secs in -10_000_000_000i64..10_000_000_000, nanos in 0u32..1_000_000_000, offset in -1439i32..=1439) {
        let t = Instant::new(secs, nanos).unwrap();
        let text = t.to_rfc3339_with_offset(offset).unwrap();
        prop_assert_eq!(Instant::parse_rfc3339(&text).unwrap(), t, "{}", text);
    }

    #[test]
    fn epoch_roundtrip(secs in -2_147_483_648i64..2_147_483_648, nanos in 0u32..1_000_000_000) {
        let t = Instant::new(secs, nanos).unwrap();
        match t.epoch() {
            EpochValue::Int(n) => {
                prop_assert_eq!(nanos, 0);
                prop_assert_eq!(n, secs);
            }
            EpochValue::Float(f) => {
                let back = Instant::from_epoch(EpochValue::Float(f)).unwrap();
                let diff = (back.secs() - secs) * 1_000_000_000
                    + i64::from(back.nanos()) - i64::from(nanos);
                prop_assert!(diff.abs() <= 1_000, "{f}: off by {diff} ns");
            }
        }
    }

    #[test]
    fn dt_literal_matches_epoch(secs in -62_167_219_200i64..=253_402_300_799, millis in 0u32..1000, frac in any::<bool>()) {
        let t = Instant::new(secs, if frac { millis * 1_000_000 } else { 0 }).unwrap();
        let text = t.to_rfc3339().unwrap();
        let from_dt = parse(&format!("dt'{text}'")).unwrap();
        let from_epoch = t.to_item(tokenator_edn::datetime::DateForm::Epoch).unwrap();
        prop_assert_eq!(
            encode(&from_dt, EncodeMode::Preserve).unwrap(),
            encode(&from_epoch, EncodeMode::Preserve).unwrap()
        );
    }
}
