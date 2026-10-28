//! Property tests: never panic, and print/parse round trips.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;
use common::assert_same;
use proptest::prelude::*;
use tokenator_json::{PrintStyle, Value, parse, print};

fn ws() -> impl Strategy<Value = String> {
    "[ \t\n\r]{0,2}"
}

fn string_lit() -> impl Strategy<Value = String> {
    let piece = prop_oneof![
        4 => "[a-zA-Z0-9 /é日😀\u{7f}\u{feff}]",
        1 => prop::sample::select(vec![
            r#"\""#, r"\\", r"\/", r"\b", r"\f", r"\n", r"\r", r"\t",
            r"\u0000", r"\u001F", r"\u00e9", r"\uD83D\uDE00", r"\uFFFF",
        ])
        .prop_map(str::to_owned),
    ];
    prop::collection::vec(piece, 0..6).prop_map(|ps| format!("\"{}\"", ps.concat()))
}

fn number_lit() -> impl Strategy<Value = String> {
    "-?(0|[1-9][0-9]{0,24})(\\.[0-9]{1,5})?([eE][+-]?[0-9]{1,3})?"
}

/// Valid JSON text with random insignificant whitespace inside containers.
fn json_text() -> impl Strategy<Value = String> {
    let leaf = prop_oneof![
        Just("null".to_owned()),
        Just("true".to_owned()),
        Just("false".to_owned()),
        number_lit(),
        string_lit(),
    ];
    leaf.prop_recursive(5, 64, 6, |inner| {
        let elem = (ws(), inner.clone(), ws()).prop_map(|(a, v, b)| format!("{a}{v}{b}"));
        let key = prop_oneof![
            prop::sample::select(vec!["\"a\"", "\"b\"", "\"\\u0061\"", "\"\""])
                .prop_map(str::to_owned),
            string_lit(),
        ];
        let member = (ws(), key, ws(), ws(), inner, ws())
            .prop_map(|(a, k, b, c, v, d)| format!("{a}{k}{b}:{c}{v}{d}"));
        prop_oneof![
            (prop::collection::vec(elem, 0..5), ws()).prop_map(|(xs, w)| {
                if xs.is_empty() {
                    format!("[{w}]")
                } else {
                    format!("[{}]", xs.join(","))
                }
            }),
            (prop::collection::vec(member, 0..5), ws()).prop_map(|(ms, w)| {
                if ms.is_empty() {
                    format!("{{{w}}}")
                } else {
                    format!("{{{}}}", ms.join(","))
                }
            }),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2048, ..ProptestConfig::default() })]

    #[test]
    fn random_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        match parse(&bytes) {
            Err(e) => prop_assert!(e.offset <= bytes.len()),
            Ok(node) => {
                let span = node.span().unwrap();
                let out = print(&node, PrintStyle::Original);
                prop_assert_eq!(out.as_bytes(), &bytes[span.start..span.end]);
                let _ = print(&node, PrintStyle::Compact);
                let _ = print(&node, PrintStyle::Pretty);
            }
        }
    }

    #[test]
    fn json_token_soup_never_panics(
        toks in prop::collection::vec(prop::sample::select(vec![
            "{", "}", "[", "]", ",", ":", "\"", "\"a\"", "\\", "\\u", "d800", "dc00",
            "0", "1", "-", ".", "e", "+", " ", "\n", "null", "tru", "\u{feff}", "\u{0}", "\u{ff}",
        ]), 0..80)
    ) {
        let s = toks.concat();
        if let Err(e) = parse(s.as_bytes()) {
            prop_assert!(e.offset <= s.len());
        }
    }

    #[test]
    fn generated_json_round_trips(text in json_text(), lead in ws(), trail in ws()) {
        let input = format!("{lead}{text}{trail}");
        let node = parse(input.as_bytes()).map_err(|e| TestCaseError::fail(format!("{e}: {input:?}")))?;
        let span = node.span().unwrap();
        prop_assert_eq!(span.start, lead.len());
        prop_assert_eq!(span.end, lead.len() + text.len());
        prop_assert!(node.is_original());
        prop_assert_eq!(print(&node, PrintStyle::Original), text.clone());
        for style in [PrintStyle::Compact, PrintStyle::Pretty] {
            let out = print(&node, style);
            let re = parse(out.as_bytes()).map_err(|e| TestCaseError::fail(format!("{style:?} {e}: {out:?}")))?;
            assert_same(&re, &node);
            // Printing is idempotent once normalized.
            prop_assert_eq!(print(&re, style), out);
        }
    }

    #[test]
    fn editing_one_value_changes_only_its_bytes(text in json_text(), pick in any::<prop::sample::Index>()) {
        let mut node = parse(text.as_bytes()).unwrap();
        // Collect JSON pointers of all non-root nodes.
        fn pointers(n: &tokenator_json::Node<'_>, prefix: String, out: &mut Vec<String>) {
            match n.value() {
                Value::Array(xs) => for (i, x) in xs.iter().enumerate() {
                    let p = format!("{prefix}/{i}");
                    out.push(p.clone());
                    pointers(x, p, out);
                },
                Value::Object(ms) => {
                    let mut seen = std::collections::HashSet::new();
                    for m in ms {
                        // Pointers only reach the first of duplicate names.
                        if !seen.insert(m.key().to_string()) { continue; }
                        let k = m.key().replace('~', "~0").replace('/', "~1");
                        let p = format!("{prefix}/{k}");
                        out.push(p.clone());
                        pointers(m.value(), p, out);
                    }
                }
                _ => {}
            }
        }
        let mut ps = Vec::new();
        pointers(&node, String::new(), &mut ps);
        prop_assume!(!ps.is_empty());
        let ptr = pick.get(&ps).clone();
        let target = node.pointer_mut(&ptr).unwrap();
        let span = target.span().unwrap();
        target.set_value(Value::Number("42".into()));
        let want = format!("{}42{}", &text[..span.start], &text[span.end..]);
        prop_assert_eq!(print(&node, PrintStyle::Original), want);
    }
}
