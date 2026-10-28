//! Layout of inserted and synthesized content under `PrintStyle::Original`
//! (issues #4.3, #4.4): `InsertedLayout::Compact` (default) or `Canonical`.
//!
//! Canonical rules, as specified in TEST-PLAN.md:
//! - A container is multi-line if the source gap between its open bracket and
//!   its first child contains a newline. Its child indent is the whitespace
//!   after the last newline in that gap.
//! - An inserted child (not first) is preceded by `,` + newline + child indent
//!   in a multi-line container, else by `, `. The original gap in front of the
//!   following original sibling stays where it was. Members use `": "`.
//! - Synthesized containers are laid out like Pretty, starting from the indent
//!   of the source line they are placed on. The indent unit is the nearest
//!   multi-line original ancestor's child indent minus that ancestor's own line
//!   indent, falling back to two spaces.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;
use common::{assert_same, keys, p};
use tokenator_json::{
    InsertedLayout, Member, Node, PrintOptions, PrintStyle, Value, print, print_with,
};

const CANONICAL: PrintOptions = PrintOptions {
    style: PrintStyle::Original,
    inserted: InsertedLayout::Canonical,
};
const COMPACT: PrintOptions = PrintOptions {
    style: PrintStyle::Original,
    inserted: InsertedLayout::Compact,
};

fn s(x: &str) -> Node<'_> {
    Node::new(Value::String(x.into()))
}
fn n(x: &str) -> Node<'_> {
    Node::new(Value::Number(x.into()))
}
fn t() -> Node<'static> {
    Node::new(Value::Bool(true))
}
/// `{"x":[1,"y"],"e":{}}`
fn sub() -> Node<'static> {
    Node::new(Value::Object(vec![
        Member::new("x", Node::new(Value::Array(vec![n("1"), s("y")]))),
        Member::new("e", Node::new(Value::Object(vec![]))),
    ]))
}

fn members<'n, 'a>(node: &'n mut Node<'a>) -> &'n mut Vec<Member<'a>> {
    match node.value_mut() {
        Value::Object(ms) => ms,
        v => panic!("not an object: {v:?}"),
    }
}
fn elements<'n, 'a>(node: &'n mut Node<'a>) -> &'n mut Vec<Node<'a>> {
    match node.value_mut() {
        Value::Array(xs) => xs,
        v => panic!("not an array: {v:?}"),
    }
}

#[track_caller]
fn check(node: &Node<'_>, opts: &PrintOptions, want: &str) {
    let out = print_with(node, opts);
    assert_eq!(out, want);
    assert_same(&p(&out), node);
}

#[test]
fn default_layout_is_compact() {
    assert_eq!(PrintOptions::default(), COMPACT);
    assert_eq!(InsertedLayout::default(), InsertedLayout::Compact);
    let mut node = p(r#"{"a":  0 , "b": 2}"#);
    node.get_mut("a").unwrap().set_value(sub().value().clone());
    let want = r#"{"a":  {"x":[1,"y"],"e":{}} , "b": 2}"#;
    assert_eq!(print(&node, PrintStyle::Original), want);
    check(&node, &COMPACT, want);
}

#[test]
fn compact_layout_inserted_subtree_in_multiline_object() {
    let mut node = p("{\n  \"a\": 1\n}");
    members(&mut node).push(Member::new("obj", sub()));
    let out = print_with(&node, &COMPACT);
    assert!(out.starts_with("{\n  \"a\": 1"), "{out}");
    assert!(out.contains(r#"{"x":[1,"y"],"e":{}}"#), "{out}");
    assert_eq!(keys(&p(&out)), ["a", "obj"]);
}

// ---- objects ----

#[test]
fn canonical_append_member_multiline() {
    let mut node = p("{\n  \"a\": 1,\n  \"b\": 2\n}");
    members(&mut node).push(Member::new("c", t()));
    check(
        &node,
        &CANONICAL,
        "{\n  \"a\": 1,\n  \"b\": 2,\n  \"c\": true\n}",
    );
}

#[test]
fn canonical_insert_member_middle_multiline() {
    let mut node = p("{\n  \"a\": 1,\n  \"b\": 2\n}");
    members(&mut node).insert(1, Member::new("m", s("mid")));
    check(
        &node,
        &CANONICAL,
        "{\n  \"a\": 1,\n  \"m\": \"mid\",\n  \"b\": 2\n}",
    );
}

#[test]
fn canonical_keeps_odd_original_gaps() {
    let mut node = p("{\n  \"a\" :  1 ,\n  \"b\":2\n}");
    members(&mut node).push(Member::new("c", t()));
    check(
        &node,
        &CANONICAL,
        "{\n  \"a\" :  1 ,\n  \"b\":2,\n  \"c\": true\n}",
    );
}

#[test]
fn canonical_append_member_single_line() {
    let mut node = p(r#"{"a":1,"b":2}"#);
    members(&mut node).push(Member::new("c", t()));
    check(&node, &CANONICAL, r#"{"a":1,"b":2, "c": true}"#);
}

#[test]
fn canonical_insert_member_middle_single_line() {
    let mut node = p(r#"{"a": 1,   "b": 2}"#);
    members(&mut node).insert(1, Member::new("m", s("mid")));
    check(&node, &CANONICAL, r#"{"a": 1, "m": "mid",   "b": 2}"#);
}

#[test]
fn canonical_insert_into_empty_containers() {
    let mut obj = p("{}");
    members(&mut obj).push(Member::new("c", t()));
    check(&obj, &CANONICAL, r#"{"c": true}"#);
    let mut arr = p("[]");
    elements(&mut arr).push(n("1"));
    check(&arr, &CANONICAL, "[1]");
}

#[test]
fn canonical_inserted_member_with_synthesized_subtree() {
    let mut node = p("{\n  \"a\": 1\n}");
    members(&mut node).push(Member::new("obj", sub()));
    check(
        &node,
        &CANONICAL,
        "{\n  \"a\": 1,\n  \"obj\": {\n    \"x\": [\n      1,\n      \"y\"\n    ],\n    \"e\": {}\n  }\n}",
    );
}

#[test]
fn canonical_nested_object_insert_uses_nested_indent() {
    let mut node = p("{\n  \"o\": {\n    \"a\": 1\n  }\n}");
    let inner = Node::new(Value::Object(vec![Member::new("c", n("1"))]));
    members(node.get_mut("o").unwrap()).push(Member::new("b", inner));
    check(
        &node,
        &CANONICAL,
        "{\n  \"o\": {\n    \"a\": 1,\n    \"b\": {\n      \"c\": 1\n    }\n  }\n}",
    );
}

#[test]
fn canonical_infers_four_space_indent() {
    let mut node = p("{\n    \"a\": 1,\n    \"b\": {\n        \"c\": 2\n    }\n}");
    let x = Value::Object(vec![Member::new(
        "x",
        Node::new(Value::Array(vec![n("1")])),
    )]);
    node.pointer_mut("/b/c").unwrap().set_value(x);
    check(
        &node,
        &CANONICAL,
        "{\n    \"a\": 1,\n    \"b\": {\n        \"c\": {\n            \"x\": [\n                1\n            ]\n        }\n    }\n}",
    );
}

#[test]
fn canonical_infers_tab_indent() {
    let mut node = p("{\n\t\"a\": 1\n}");
    let b = Node::new(Value::Object(vec![Member::new("c", t())]));
    members(&mut node).push(Member::new("b", b));
    check(
        &node,
        &CANONICAL,
        "{\n\t\"a\": 1,\n\t\"b\": {\n\t\t\"c\": true\n\t}\n}",
    );
}

#[test]
fn canonical_replaced_value_in_single_line_falls_back_to_two_spaces() {
    let mut node = p(r#"{"a":  0 , "b": 2}"#);
    node.get_mut("a").unwrap().set_value(sub().value().clone());
    check(
        &node,
        &CANONICAL,
        "{\"a\":  {\n  \"x\": [\n    1,\n    \"y\"\n  ],\n  \"e\": {}\n} , \"b\": 2}",
    );
}

// ---- arrays ----

#[test]
fn canonical_array_push() {
    let mut multi = p("[\n  1,\n  2\n]");
    elements(&mut multi).push(n("3"));
    check(&multi, &CANONICAL, "[\n  1,\n  2,\n  3\n]");

    let mut spaced = p("[1, 2]");
    elements(&mut spaced).push(n("3"));
    check(&spaced, &CANONICAL, "[1, 2, 3]");

    let mut tight = p("[1,2]");
    elements(&mut tight).push(n("3"));
    check(&tight, &CANONICAL, "[1,2, 3]");
}

#[test]
fn canonical_array_insert_middle() {
    let mut node = p("[\n  1,\n  3\n]");
    elements(&mut node).insert(1, n("2"));
    check(&node, &CANONICAL, "[\n  1,\n  2,\n  3\n]");
}

#[test]
fn canonical_array_push_synthesized_object() {
    let mut node = p("[\n  1\n]");
    elements(&mut node).push(Node::new(Value::Object(vec![Member::new(
        "k",
        Node::new(Value::Null),
    )])));
    check(&node, &CANONICAL, "[\n  1,\n  {\n    \"k\": null\n  }\n]");
}

#[test]
fn compact_array_push_synthesized_object() {
    let mut node = p("[\n  1\n]");
    elements(&mut node).push(Node::new(Value::Object(vec![Member::new(
        "k",
        Node::new(Value::Array(vec![n("1")])),
    )])));
    let out = print_with(&node, &COMPACT);
    assert!(out.starts_with("[\n  1"), "{out}");
    assert!(out.contains(r#"{"k":[1]}"#), "{out}");
    assert_same(&p(&out), &node);
}

// ---- whole trees and other styles ----

#[test]
fn canonical_synthesized_root_matches_pretty() {
    let tree = sub();
    assert_eq!(
        print_with(&tree, &CANONICAL),
        print(&tree, PrintStyle::Pretty)
    );
    assert_eq!(
        print_with(&tree, &COMPACT),
        print(&tree, PrintStyle::Compact)
    );
}

#[test]
fn canonical_unedited_document_is_byte_identical() {
    let input = "{\n  \"a\" : [1,2],\n\t\"b\":{ }\n}";
    check(&p(input), &CANONICAL, input);
}

#[test]
fn inserted_layout_ignored_for_compact_and_pretty() {
    let mut node = p("{\n  \"a\": 1\n}");
    members(&mut node).push(Member::new("obj", sub()));
    for style in [PrintStyle::Compact, PrintStyle::Pretty] {
        let canonical = PrintOptions {
            style,
            inserted: InsertedLayout::Canonical,
        };
        assert_eq!(print_with(&node, &canonical), print(&node, style));
    }
}
