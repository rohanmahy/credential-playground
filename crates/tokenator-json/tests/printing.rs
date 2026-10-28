//! Printer: Original byte identity, Compact/Pretty layout, and edits that
//! leave untouched bytes alone.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;
use common::{assert_same, keys, num, p, string};
use tokenator_json::{Member, Node, PrintStyle, Span, Value, parse, print};

use PrintStyle::{Compact, Original, Pretty};

fn s(x: &str) -> Value<'_> {
    Value::String(x.into())
}
fn n(x: &str) -> Value<'_> {
    Value::Number(x.into())
}

const CLAIMS: &str = "{\n  \"iss\": \"https://issuer.example\",\n  \"exp\" :1700000000,\n\t\"nested\": { \"list\": [1, 2.50,  3e0 ], \"esc\": \"a\\u0062c\\/\" },\n  \"dup\": 1, \"dup\": 2\n}";

#[test]
fn original_is_byte_identical() {
    for input in [
        CLAIMS,
        "[]",
        "{}",
        "[ ]",
        "{ \r\n }",
        "\"\\ud83d\\ude00\"",
        "[1,[2,[3,[4]]]]",
        "{\"a\":\"\\u0000\",\"b\":-0.0E-0}",
        "[\n\t1 ,\n\t2\n]",
    ] {
        let node = p(input);
        assert_eq!(print(&node, Original), input);
    }
}

#[test]
fn original_of_subtree_is_its_raw() {
    let node = p(CLAIMS);
    let nested = node.get("nested").unwrap();
    assert_eq!(print(nested, Original), nested.raw().unwrap());
    assert_eq!(
        print(nested, Original),
        "{ \"list\": [1, 2.50,  3e0 ], \"esc\": \"a\\u0062c\\/\" }"
    );
}

#[test]
fn compact_keeps_tokens_order_and_duplicates() {
    let node = p(CLAIMS);
    assert_eq!(
        print(&node, Compact),
        r#"{"iss":"https://issuer.example","exp":1700000000,"nested":{"list":[1,2.50,3e0],"esc":"a\u0062c\/"},"dup":1,"dup":2}"#
    );
}

#[test]
fn pretty_layout() {
    let node = p(r#"{"a":[1,{"b":"c"}],"e":{},"f":[ ],"g":{"h":null}}"#);
    let want = r#"{
  "a": [
    1,
    {
      "b": "c"
    }
  ],
  "e": {},
  "f": [],
  "g": {
    "h": null
  }
}"#;
    assert_eq!(print(&node, Pretty), want);
    assert_eq!(print(&p("[]"), Pretty), "[]");
    assert_eq!(print(&p(" 5 "), Pretty), "5");
}

#[test]
fn compact_and_pretty_reparse_to_same_structure() {
    let node = p(CLAIMS);
    for style in [Compact, Pretty] {
        let out = print(&node, style);
        assert_same(&p(&out), &node);
    }
}

#[test]
fn edit_one_member_keeps_all_other_bytes() {
    let mut node = p(CLAIMS);
    node.get_mut("exp").unwrap().set_value(n("1800000000"));
    let want = CLAIMS.replace("1700000000", "1800000000");
    assert_eq!(print(&node, Original), want);
}

#[test]
fn edit_nested_via_pointer() {
    let input = r#"{"a": {"b": [1, 2,  3]}, "c": "keep\u0020me"}"#;
    let mut node = p(input);
    node.pointer_mut("/a/b/1").unwrap().set_value(n("20"));
    assert_eq!(
        print(&node, Original),
        r#"{"a": {"b": [1, 20,  3]}, "c": "keep\u0020me"}"#
    );
    assert_eq!(
        print(&node, Compact),
        r#"{"a":{"b":[1,20,3]},"c":"keep\u0020me"}"#
    );
}

#[test]
fn edited_string_uses_minimal_escaping() {
    let mut node = p(r#"{"k": "old", "z": 0}"#);
    node.get_mut("k")
        .unwrap()
        .set_value(s("say \"hi\"\\/\u{8}\u{c}\n\r\t\u{1}\u{1f}\u{7f}é😀"));
    assert_eq!(
        print(&node, Original),
        "{\"k\": \"say \\\"hi\\\"\\\\/\\b\\f\\n\\r\\t\\u0001\\u001f\u{7f}é😀\", \"z\": 0}"
    );
}

#[test]
fn edited_string_does_not_reuse_old_escapes() {
    // Same decoded text, but the node was edited: emit fresh minimal form.
    let mut node = p(r#"["\u0061"]"#);
    node.index_mut(0).unwrap().set_value(s("a"));
    assert_eq!(print(&node, Original), r#"["a"]"#);
}

#[test]
fn set_key_keeps_other_bytes() {
    let mut node = p(r#"{"a" : 1,  "b":2}"#);
    node.members_mut().unwrap()[0].set_key("z\"");
    assert_eq!(print(&node, Original), r#"{"z\"" : 1,  "b":2}"#);
    assert!(!node.is_original());
    assert!(!node.members().unwrap()[0].is_original());
    assert!(node.members().unwrap()[1].is_original());
}

#[test]
fn edit_through_elements_mut_and_members_mut() {
    let mut node = p("[ 1 ,\n 2 ]");
    node.elements_mut().unwrap()[1].set_value(Value::Null);
    assert_eq!(print(&node, Original), "[ 1 ,\n null ]");

    let mut obj = p(r#"{ "a" : true }"#);
    obj.members_mut().unwrap()[0]
        .value_mut()
        .set_value(Value::Bool(false));
    assert_eq!(print(&obj, Original), r#"{ "a" : false }"#);
}

#[test]
fn edit_state_tracking() {
    let mut node = p(r#"{"a":{"b":1,"c":[2]},"d":3}"#);
    let orig_span = node.pointer("/a/b").unwrap().span();
    node.pointer_mut("/a/b").unwrap().set_value(n("9"));
    assert!(!node.is_original(), "ancestor of an edit");
    assert!(!node.get("a").unwrap().is_original());
    assert!(!node.pointer("/a/b").unwrap().is_original());
    assert!(
        node.pointer("/a/c").unwrap().is_original(),
        "sibling untouched"
    );
    assert!(node.get("d").unwrap().is_original());
    assert_eq!(node.pointer("/a/b").unwrap().span(), orig_span, "span kept");
    assert_eq!(num(node.pointer("/a/b").unwrap()), "9");
}

#[test]
fn value_mut_marks_edited_even_without_change() {
    let mut node = p("[1]");
    let _ = node.index_mut(0).unwrap().value_mut();
    assert!(!node.index(0).unwrap().is_original());
}

#[test]
fn lookups_do_not_mark_edited() {
    let mut node = p(r#"{"a":[1]}"#);
    let _ = node.pointer_mut("/a/0");
    let _ = node.get_mut("a");
    let _ = node.members_mut();
    assert!(node.is_original());
    assert_eq!(print(&node, Original), r#"{"a":[1]}"#);
}

#[test]
fn edited_number_lexeme_printed_verbatim() {
    let mut node = p("[0]");
    node.index_mut(0).unwrap().set_value(n("1.000E+10"));
    for style in [Original, Compact, Pretty] {
        let out = print(&node, style);
        assert!(out.contains("1.000E+10"), "{style:?}: {out}");
    }
}

#[test]
fn replace_value_with_synthesized_subtree() {
    let mut node = p(r#"{"a":  0 , "b": 2}"#);
    let sub = Value::Object(vec![
        Member::new(
            "x",
            Node::new(Value::Array(vec![Node::new(n("1")), Node::new(s("y"))])),
        ),
        Member::new("e", Node::new(Value::Object(vec![]))),
    ]);
    node.get_mut("a").unwrap().set_value(sub);
    assert_eq!(
        print(&node, Original),
        r#"{"a":  {"x":[1,"y"],"e":{}} , "b": 2}"#
    );
}

#[test]
fn replace_container_with_scalar_and_back() {
    let mut node = p(r#"[{"a": 1}, [2, 3]]"#);
    node.index_mut(0).unwrap().set_value(Value::Null);
    node.index_mut(1).unwrap().set_value(Value::Array(vec![]));
    assert_eq!(print(&node, Original), "[null, []]");
}

#[test]
fn append_member() {
    let input = r#"{"a": 1, "b": 2}"#;
    let mut node = p(input);
    let Value::Object(ms) = node.value_mut() else {
        panic!()
    };
    ms.push(Member::new("c", Node::new(Value::Bool(true))));
    assert!(!node.is_original());
    let out = print(&node, Original);
    let re = p(&out);
    assert_eq!(keys(&re), ["a", "b", "c"]);
    assert!(out.starts_with(r#"{"a": 1, "b": 2"#), "{out}");
    assert!(out.ends_with('}'), "{out}");
}

#[test]
fn insert_member_in_middle() {
    let mut node = p(r#"{"a": 1,   "b": 2}"#);
    let Value::Object(ms) = node.value_mut() else {
        panic!()
    };
    ms.insert(1, Member::new("m", Node::new(s("mid"))));
    let out = print(&node, Original);
    let re = p(&out);
    assert_eq!(keys(&re), ["a", "m", "b"]);
    assert_eq!(string(re.get("m").unwrap()), "mid");
    assert!(out.starts_with(r#"{"a": 1"#), "{out}");
    assert!(out.ends_with(r#""b": 2}"#), "{out}");
}

#[test]
fn remove_members() {
    let input = r#"{"a": 1, "b": 2, "c": 3}"#;

    let mut first = p(input);
    let Value::Object(ms) = first.value_mut() else {
        panic!()
    };
    ms.remove(0);
    let out = print(&first, Original);
    assert_eq!(keys(&p(&out)), ["b", "c"]);
    assert!(out.contains(r#""b": 2, "c": 3"#), "{out}");

    let mut last = p(input);
    let Value::Object(ms) = last.value_mut() else {
        panic!()
    };
    ms.remove(2);
    let out = print(&last, Original);
    assert_eq!(keys(&p(&out)), ["a", "b"]);
    assert!(out.contains(r#"{"a": 1, "b": 2"#), "{out}");

    let mut all = p(input);
    let Value::Object(ms) = all.value_mut() else {
        panic!()
    };
    ms.clear();
    let out = print(&all, Original);
    assert_eq!(p(&out).members().unwrap().len(), 0, "{out}");
}

#[test]
fn remove_one_duplicate() {
    let mut node = p(r#"{"dup": 1, "x": 0, "dup": 2}"#);
    let Value::Object(ms) = node.value_mut() else {
        panic!()
    };
    ms.remove(2);
    let out = print(&node, Original);
    let re = p(&out);
    assert_eq!(keys(&re), ["dup", "x"]);
    assert_eq!(num(re.get("dup").unwrap()), "1");
}

#[test]
fn array_push_and_remove() {
    let mut node = p("[ 1, 2 ]");
    let Value::Array(xs) = node.value_mut() else {
        panic!()
    };
    xs.push(Node::new(n("3")));
    let out = print(&node, Original);
    let re = p(&out);
    assert_eq!(re.elements().unwrap().len(), 3);
    assert!(out.starts_with("[ 1, 2"), "{out}");

    let mut node = p("[ 1, 2, 3 ]");
    let Value::Array(xs) = node.value_mut() else {
        panic!()
    };
    xs.remove(1);
    let out = print(&node, Original);
    let got: Vec<_> = p(&out)
        .elements()
        .unwrap()
        .iter()
        .map(|e| num(e).to_owned())
        .collect();
    assert_eq!(got, ["1", "3"]);
}

#[test]
fn moved_original_nodes_still_print_their_raw_bytes() {
    let mut node = p(r#"[{"a" :  1}, "x\u0079"]"#);
    let Value::Array(xs) = node.value_mut() else {
        panic!()
    };
    xs.swap(0, 1);
    let out = print(&node, Original);
    assert!(out.contains(r#"{"a" :  1}"#), "{out}");
    assert!(out.contains(r#""x\u0079""#), "{out}");
    let re = p(&out);
    assert_eq!(string(re.index(0).unwrap()), "xy");
}

#[test]
fn synthesized_tree_all_styles() {
    let tree = Node::new(Value::Object(vec![
        Member::new("alg", Node::new(s("ES256"))),
        Member::new("crit", Node::new(Value::Array(vec![Node::new(s("b64"))]))),
        Member::new("b64", Node::new(Value::Bool(false))),
        Member::new("n", Node::new(Value::Null)),
    ]));
    assert_eq!(tree.span(), None::<Span>);
    assert_eq!(tree.raw(), None);
    assert!(!tree.is_original());
    let compact = r#"{"alg":"ES256","crit":["b64"],"b64":false,"n":null}"#;
    assert_eq!(print(&tree, Compact), compact);
    assert_eq!(print(&tree, Original), compact);
    assert_eq!(
        print(&tree, Pretty),
        "{\n  \"alg\": \"ES256\",\n  \"crit\": [\n    \"b64\"\n  ],\n  \"b64\": false,\n  \"n\": null\n}"
    );
}

#[test]
fn synthesized_key_escaping() {
    let tree = Node::new(Value::Object(vec![Member::new(
        "a\"\n\u{0}",
        Node::new(Value::Null),
    )]));
    assert_eq!(print(&tree, Compact), r#"{"a\"\n\u0000":null}"#);
}

#[test]
fn pretty_after_edit_matches_pretty_of_equivalent_parse() {
    let mut node = p(CLAIMS);
    node.pointer_mut("/nested/list/0")
        .unwrap()
        .set_value(s("one"));
    let compact = print(&node, Compact);
    let expect = p(&compact);
    assert_eq!(print(&node, Pretty), print(&expect, Pretty));
}

#[test]
fn print_output_always_reparses_after_edits() {
    let mut node = p(CLAIMS);
    node.get_mut("iss").unwrap().set_value(Value::Array(vec![]));
    node.pointer_mut("/nested/list")
        .unwrap()
        .set_value(Value::Object(vec![]));
    for style in [Original, Compact, Pretty] {
        let out = print(&node, style);
        assert!(parse(out.as_bytes()).is_ok(), "{style:?}: {out}");
    }
}
