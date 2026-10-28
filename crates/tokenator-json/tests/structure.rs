//! Arrival order, duplicates, lookups, number lexemes, and Cow borrowing.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;
use common::{keys, num, p, string};
use std::borrow::Cow;
use tokenator_json::{Value, parse};

#[test]
fn members_keep_arrival_order_not_sorted() {
    let n = p(r#"{"z":1,"a":2,"m":3,"b":4,"A":5,"":6}"#);
    assert_eq!(keys(&n), ["z", "a", "m", "b", "A", ""]);
}

#[test]
fn duplicates_preserved_in_order() {
    let n = p(r#"{"a":1,"b":2,"a":3,"a":{"x":4}}"#);
    assert_eq!(keys(&n), ["a", "b", "a", "a"]);
    assert_eq!(num(n.get("a").unwrap()), "1", "get returns first match");
    let all = n.get_all("a");
    assert_eq!(all.len(), 3);
    assert_eq!(num(all[0]), "1");
    assert_eq!(num(all[1]), "3");
    assert!(all[2].get("x").is_some());
    assert!(n.get_all("nope").is_empty());
}

#[test]
fn duplicate_keys_with_different_escapes_compare_decoded() {
    let n = p(r#"{"a":1,"\u0061":2}"#);
    assert_eq!(n.get_all("a").len(), 2);
    let m = n.members().unwrap();
    assert_eq!(m[0].key_raw(), Some(r#""a""#));
    assert_eq!(m[1].key_raw(), Some(r#""\u0061""#));
}

#[test]
fn accessors_on_wrong_types() {
    let n = p("[1,2]");
    assert!(n.members().is_none());
    assert!(n.get("0").is_none());
    assert!(n.get_all("0").is_empty());
    assert_eq!(n.elements().unwrap().len(), 2);
    assert!(n.index(2).is_none());
    let o = p(r#"{"0":1}"#);
    assert!(o.elements().is_none());
    assert!(o.index(0).is_none());
    let s = p("\"x\"");
    assert!(s.get("x").is_none() && s.index(0).is_none());
}

#[test]
fn json_pointer() {
    let n = p(r#"{"a":[10,{"b":"c"}],"x/y":1,"m~n":2,"":3,"a":"dup","0":4}"#);
    assert!(std::ptr::eq(n.pointer("").unwrap(), &n));
    assert_eq!(num(n.pointer("/a/0").unwrap()), "10");
    assert_eq!(string(n.pointer("/a/1/b").unwrap()), "c");
    assert_eq!(num(n.pointer("/x~1y").unwrap()), "1");
    assert_eq!(num(n.pointer("/m~0n").unwrap()), "2");
    assert_eq!(num(n.pointer("/").unwrap()), "3");
    assert_eq!(
        num(n.pointer("/0").unwrap()),
        "4",
        "object key that looks numeric"
    );
    assert!(n.pointer("/a/2").is_none());
    assert!(n.pointer("/a/-").is_none());
    assert!(n.pointer("/a/01").is_none(), "leading zero is not an index");
    assert!(n.pointer("/a/b").is_none());
    assert!(n.pointer("a").is_none(), "must start with /");
    assert!(n.pointer("/missing").is_none());
    assert!(n.pointer("/a/0/deeper").is_none());
}

#[test]
fn number_lexemes_kept_verbatim() {
    let lexemes = [
        "0",
        "-0",
        "1.0",
        "1.50",
        "1e3",
        "1E3",
        "1e+3",
        "1E-03",
        "-0.0e0",
        "123456789012345678901234567890",
        "-123456789012345678901234567890",
        "1e999",
        "1.7976931348623157e309",
        "0.000000000000000000000000000001",
    ];
    let input = format!("[{}]", lexemes.join(" , "));
    let n = p(&input);
    let got: Vec<_> = n.elements().unwrap().iter().map(num).collect();
    assert_eq!(got, lexemes);
    // Lexemes are borrowed from input.
    for e in n.elements().unwrap() {
        assert!(matches!(e.value(), Value::Number(Cow::Borrowed(_))));
    }
}

#[test]
fn escape_free_strings_and_keys_are_borrowed() {
    let input = r#"{"plain":"value é 😀","esc\n":"a\/b"}"#;
    let n = p(input);
    let m = n.members().unwrap();
    assert!(matches!(m[0].key(), Cow::Borrowed("plain")));
    assert!(matches!(
        m[0].value().value(),
        Value::String(Cow::Borrowed("value é 😀"))
    ));
    assert!(matches!(m[1].key(), Cow::Owned(k) if k == "esc\n"));
    assert!(matches!(m[1].value().value(), Value::String(Cow::Owned(s)) if s == "a/b"));
}

#[test]
fn borrowed_strings_point_into_the_input() {
    let input = br#"["abc"]"#;
    let n = parse(input).unwrap();
    let Value::String(Cow::Borrowed(s)) = n.index(0).unwrap().value() else {
        panic!("not borrowed")
    };
    let range = input.as_ptr_range();
    assert!(
        range.contains(&s.as_ptr()),
        "borrowed slice must alias the input"
    );
}

#[test]
fn all_escapes_decode() {
    let n = p(r#""\"\\\/\b\f\n\r\t\u0000\u001f\u00A9\u20AC\uD834\uDD1E""#);
    assert_eq!(
        string(&n),
        "\"\\/\u{8}\u{c}\n\r\t\u{0}\u{1f}\u{a9}\u{20ac}\u{1d11e}"
    );
}

#[test]
fn literals_and_scalars() {
    let n = p("[null,true,false]");
    let e = n.elements().unwrap();
    assert!(matches!(e[0].value(), Value::Null));
    assert!(matches!(e[1].value(), Value::Bool(true)));
    assert!(matches!(e[2].value(), Value::Bool(false)));
}

#[test]
fn fresh_parse_is_original_everywhere() {
    let n = p(r#"{"a":[1,{"b":null}]}"#);
    assert!(n.is_original());
    assert!(n.members().unwrap()[0].is_original());
    assert!(n.pointer("/a/1/b").unwrap().is_original());
}

#[test]
fn moderately_deep_nesting_within_limit() {
    let depth = tokenator_json::DEFAULT_MAX_DEPTH;
    let input = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
    let n = p(&input);
    let mut cur = &n;
    for _ in 1..depth {
        cur = cur.index(0).unwrap();
    }
    assert_eq!(cur.elements().unwrap().len(), 0);
}

#[test]
fn large_flat_document() {
    let items: Vec<String> = (0..10_000).map(|i| format!(r#""k{i}":{i}"#)).collect();
    let input = format!("{{{}}}", items.join(","));
    let n = p(&input);
    assert_eq!(n.members().unwrap().len(), 10_000);
    assert_eq!(num(n.get("k9999").unwrap()), "9999");
    assert_eq!(n.members().unwrap()[1234].key(), "k1234");
}
