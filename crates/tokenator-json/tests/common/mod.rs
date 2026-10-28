//! Shared helpers for tokenator-json integration tests.
#![allow(dead_code, clippy::expect_used, clippy::panic)]

use tokenator_json::{Node, Value, parse};

/// Parse a test string, panicking with the error on failure.
pub fn p(s: &str) -> Node<'_> {
    match parse(s.as_bytes()) {
        Ok(n) => n,
        Err(e) => panic!("parse failed for {s:?}: {e}"),
    }
}

/// Member keys of an object node, in order.
pub fn keys<'n>(node: &'n Node<'_>) -> Vec<&'n str> {
    node.members()
        .expect("object")
        .iter()
        .map(|m| m.key().as_ref())
        .collect()
}

/// Structural equality ignoring spans and edit state. Numbers compare by
/// lexeme, objects by ordered member list (duplicates included).
pub fn same(a: &Value<'_>, b: &Value<'_>) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Number(x), Value::Number(y)) => x == y,
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(a, b)| same(a.value(), b.value()))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .zip(y)
                    .all(|(a, b)| a.key() == b.key() && same(a.value().value(), b.value().value()))
        }
        _ => false,
    }
}

/// Assert two trees are structurally equal.
pub fn assert_same(a: &Node<'_>, b: &Node<'_>) {
    assert!(
        same(a.value(), b.value()),
        "trees differ:\n{a:#?}\n---\n{b:#?}"
    );
}

/// Return the number lexeme or panic.
pub fn num<'n>(node: &'n Node<'_>) -> &'n str {
    match node.value() {
        Value::Number(n) => n,
        v => panic!("expected number, got {v:?}"),
    }
}

/// Return the decoded string or panic.
pub fn string<'n>(node: &'n Node<'_>) -> &'n str {
    match node.value() {
        Value::String(s) => s,
        v => panic!("expected string, got {v:?}"),
    }
}
