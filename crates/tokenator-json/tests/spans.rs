//! Exact byte spans and `raw()` for every kind of node.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;
use common::{p, string};
use tokenator_json::{Node, Span, Value};

fn sp(start: usize, end: usize) -> Span {
    Span { start, end }
}

/// Assert span and raw text agree with the input.
fn check(input: &str, node: &Node<'_>, want: Span, text: &str) {
    assert_eq!(node.span(), Some(want), "span of {text:?}");
    assert_eq!(
        &input[want.start..want.end],
        text,
        "test is self-consistent"
    );
    assert_eq!(node.raw(), Some(text));
}

#[test]
fn scalar_roots() {
    for (input, start, end) in [
        ("null", 0, 4),
        ("true", 0, 4),
        ("false", 0, 5),
        ("0", 0, 1),
        ("-12.5e+3", 0, 8),
        (r#""hi""#, 0, 4),
        ("  42  ", 2, 4),
        ("\t\r\n\"x\"\n", 3, 6),
    ] {
        let n = p(input);
        check(input, &n, sp(start, end), &input[start..end]);
    }
}

#[test]
fn root_span_excludes_surrounding_whitespace() {
    let input = " \n {\"a\" : 1 }\r\n\t ";
    let n = p(input);
    check(input, &n, sp(3, 13), "{\"a\" : 1 }");
}

#[test]
fn nested_containers() {
    let input = r#"{"a": [1, {"b": "c"}], "d": null}"#;
    let n = p(input);
    check(input, &n, sp(0, 33), input);

    let a = &n.members().unwrap()[0];
    assert_eq!(a.key_span(), Some(sp(1, 4)));
    assert_eq!(a.key_raw(), Some(r#""a""#));
    check(input, a.value(), sp(6, 21), r#"[1, {"b": "c"}]"#);

    let arr = a.value();
    check(input, arr.index(0).unwrap(), sp(7, 8), "1");
    let inner = arr.index(1).unwrap();
    check(input, inner, sp(10, 20), r#"{"b": "c"}"#);
    let b = &inner.members().unwrap()[0];
    assert_eq!(b.key_span(), Some(sp(11, 14)));
    check(input, b.value(), sp(16, 19), r#""c""#);

    let d = &n.members().unwrap()[1];
    assert_eq!(d.key_span(), Some(sp(23, 26)));
    check(input, d.value(), sp(28, 32), "null");
}

#[test]
fn empty_containers_with_inner_whitespace() {
    let input = "[ [ ] , { \n } ,[],{}]";
    let n = p(input);
    let e = n.elements().unwrap();
    assert_eq!(e.len(), 4);
    check(input, &e[0], sp(2, 5), "[ ]");
    check(input, &e[1], sp(8, 13), "{ \n }");
    check(input, &e[2], sp(15, 17), "[]");
    check(input, &e[3], sp(18, 20), "{}");
}

#[test]
fn strings_with_escapes_and_unicode() {
    let input = r#"["a\"b", "\u00e9", "é", "\ud83d\ude00", "😀"]"#;
    let n = p(input);
    let e = n.elements().unwrap();
    check(input, &e[0], sp(1, 7), r#""a\"b""#);
    check(input, &e[1], sp(9, 17), r#""\u00e9""#);
    check(input, &e[2], sp(19, 23), "\"é\"");
    check(input, &e[3], sp(25, 39), r#""\ud83d\ude00""#);
    check(input, &e[4], sp(41, 47), "\"😀\"");
    assert_eq!(string(&e[0]), "a\"b");
    assert_eq!(string(&e[1]), "é");
    assert_eq!(string(&e[2]), "é");
    assert_eq!(string(&e[3]), "😀");
    assert_eq!(string(&e[4]), "😀");
}

#[test]
fn keys_with_escapes_and_whitespace_around_colon() {
    let input = "{ \"\\u0061\\n\" \t:\n\"v\" , \"ü\":1}";
    let n = p(input);
    let m = n.members().unwrap();
    assert_eq!(m[0].key(), "a\n");
    assert_eq!(m[0].key_span(), Some(sp(2, 12)));
    assert_eq!(m[0].key_raw(), Some("\"\\u0061\\n\""));
    check(input, m[0].value(), sp(16, 19), "\"v\"");
    assert_eq!(m[1].key(), "ü");
    assert_eq!(m[1].key_span(), Some(sp(22, 26)));
    check(input, m[1].value(), sp(27, 28), "1");
}

#[test]
fn spans_are_byte_offsets_after_multibyte_text() {
    // "日本" is 6 bytes; the following number must be addressed by bytes, not chars.
    let input = "[\"日本\",7]";
    let n = p(input);
    check(input, n.index(0).unwrap(), sp(1, 9), "\"日本\"");
    check(input, n.index(1).unwrap(), sp(10, 11), "7");
}

#[test]
fn every_span_slices_back_to_raw() {
    // Walk a bigger document and check raw() == input[span] everywhere.
    let input = r#"
    {"iss":"https://example.com","nbf":1.7e9,"nested":{"x":[true,false,null,[[]],{"":""}],
     "esc":"\t\u0000\/"},"dup":1,"dup":2}
    "#;
    fn walk(input: &str, n: &Node<'_>, count: &mut usize) {
        *count += 1;
        let s = n.span().unwrap();
        assert_eq!(Some(&input[s.start..s.end]), n.raw());
        match n.value() {
            Value::Array(xs) => xs.iter().for_each(|x| walk(input, x, count)),
            Value::Object(ms) => {
                let mut prev_end = s.start;
                for m in ms {
                    let ks = m.key_span().unwrap();
                    assert_eq!(Some(&input[ks.start..ks.end]), m.key_raw());
                    assert!(ks.start > prev_end, "members in arrival order");
                    let vs = m.value().span().unwrap();
                    assert!(vs.start > ks.end);
                    prev_end = vs.end;
                    walk(input, m.value(), count);
                }
                assert!(prev_end < s.end);
            }
            _ => {}
        }
    }
    let mut count = 0;
    walk(input, &p(input), &mut count);
    assert_eq!(count, 15);
}
