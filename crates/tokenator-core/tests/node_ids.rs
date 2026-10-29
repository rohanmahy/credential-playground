//! The NodeId scheme (TEST-PLAN §4) on real documents, its helpers, and its
//! stability across re-renders, tagging, view changes, and edits.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::collections::HashSet;

use common::*;
use tokenator_core::{
    DocRef, Document, Kind, Layout, NodeId, NodeKind, RenderRequest, ViewOptions, escape_segment,
    unescape_segment,
};

fn rerender(e: &tokenator_core::Engine, doc: &Document, view: ViewOptions) -> Document {
    e.render(&RenderRequest {
        doc: DocRef::from(doc),
        layers: doc.layers.clone(),
        view,
    })
    .unwrap()
}

// ---------------------------------------------------------------- helpers

#[test]
fn helpers_build_and_split_ids() {
    let root = NodeId::root();
    assert!(root.is_root());
    assert_eq!(root.parent(), None);
    assert!(root.segments().is_empty());
    let p = root.child("payload");
    assert_eq!(p.as_str(), "payload");
    assert_eq!(p.parent(), Some(NodeId::root()));
    let iss = p.decoded(0).child("iss");
    assert_eq!(iss.as_str(), "payload/~e/iss");
    assert_eq!(iss.key().as_str(), "payload/~e/iss/~k");
    assert_eq!(p.decoded(2).as_str(), "payload/~e2");
    assert_eq!(p.index(3).as_str(), "payload/3");
    assert!(p.is_ancestor_of(&iss));
    assert!(iss.is_ancestor_of(&iss));
    assert!(!iss.is_ancestor_of(&p));
    assert!(!node_id("pay").is_ancestor_of(&p), "segment boundaries");
    assert!(root.is_ancestor_of(&p));
}

#[test]
fn names_are_rfc6901_escaped() {
    assert_eq!(
        escape_segment("http://example.com/is_root"),
        "http:~1~1example.com~1is_root"
    );
    assert_eq!(escape_segment("a~b"), "a~0b");
    assert_eq!(
        escape_segment("~k"),
        "~0k",
        "a literal ~k is not the key special"
    );
    for name in [
        "a/b",
        "~",
        "~1",
        "x~0/y",
        "",
        "\"country\"",
        "simple(59)",
        "58(501)",
    ] {
        assert_eq!(unescape_segment(&escape_segment(name)), name);
    }
    // Specials pass through unescape unchanged.
    for special in ["~k", "~e", "~e1", "~t", "~c0", "~i3"] {
        assert_eq!(unescape_segment(special), special);
    }
    let id = NodeId::root().child("payload").decoded(0).child("a/b~c");
    assert_eq!(id.segments(), ["payload", "~e", "a/b~c"]);
}

#[test]
fn json_pointer_of_claim_ids() {
    assert_eq!(NodeId::root().to_json_pointer(), "");
    assert_eq!(
        node_id("address/street_address").to_json_pointer(),
        "/address/street_address"
    );
    assert_eq!(NodeId::root().child("a/b").to_json_pointer(), "/a~1b");
}

// ---------------------------------------------------------------- JOSE ids

#[test]
fn jwt_ids() {
    let e = engine();
    let doc = open_token(&e, "rfc7515-a3-jws-es256.txt");
    assert_eq!(doc.tree.id, NodeId::root());
    assert_eq!(doc.tree.kind, NodeKind::Document);
    let parts: Vec<_> = doc.tree.children.iter().map(|n| n.id.0.as_str()).collect();
    assert_eq!(parts, ["protected", "payload", "signature"]);
    for id in [
        "protected/~e",
        "protected/~e/alg",
        "protected/~e/alg/~k",
        "payload/~e",
        "payload/~e/iss",
        "payload/~e/exp",
        "payload/~e/http:~1~1example.com~1is_root",
    ] {
        assert!(has_node(&doc, id), "{id}: {:?}", ids(&doc));
    }
    assert_eq!(find(&doc, "payload").kind, NodeKind::Part);
    assert_eq!(find(&doc, "payload/~e").kind, NodeKind::Decoded);
    assert_eq!(find(&doc, "payload/~e/exp").kind, NodeKind::Number);
    assert_eq!(find(&doc, "payload/~e/iss").label, "iss");
    assert_eq!(main_text(&doc, "payload/~e/iss/~k"), r#""iss""#);
}

#[test]
fn sd_jwt_kb_ids() {
    let e = engine();
    let doc = open_token(&e, "rfc9901-s5.2-sd-jwt-kb.txt");
    let parts: Vec<_> = doc.tree.children.iter().map(|n| n.id.0.as_str()).collect();
    assert_eq!(
        parts,
        ["protected", "payload", "signature", "disclosures", "kb"]
    );
    for id in [
        "disclosures/0",
        "disclosures/3",
        "disclosures/0/~e",
        "disclosures/0/~e/0",
        "disclosures/0/~e/1",
        "kb/protected/~e/typ",
        "kb/payload/~e/nonce",
        "kb/payload/~e/sd_hash",
        "kb/signature",
        "payload/~e/_sd/0",
        "payload/~e/cnf/jwk/x",
    ] {
        assert!(has_node(&doc, id), "{id}");
    }
    assert!(!has_node(&doc, "disclosures/4"));
}

#[test]
fn jws_json_ids() {
    let e = engine();
    let doc = open_token(&e, "rfc7515-a6-jws-json-general.json");
    for id in [
        "payload/~e/iss",
        "signatures/0/protected/~e/alg",
        "signatures/0/unprotected/kid",
        "signatures/1/signature",
    ] {
        assert!(has_node(&doc, id), "{id}: {:?}", ids(&doc));
    }
    let doc = open_token(&e, "rfc7515-a7-jws-json-flattened.json");
    for id in [
        "protected/~e/alg",
        "unprotected/kid",
        "payload/~e/iss",
        "signature",
    ] {
        assert!(has_node(&doc, id), "{id}: {:?}", ids(&doc));
    }
    let doc = open_token(&e, "rfc9901-s8.2-sd-jwt-kb-json-flattened.json");
    for id in ["disclosures/0/~e/1", "kb/payload/~e/nonce"] {
        assert!(has_node(&doc, id), "{id}: {:?}", ids(&doc));
    }
}

// ---------------------------------------------------------------- COSE ids

#[test]
fn cwt_ids() {
    let e = engine();
    let doc = open_token(&e, CWT_TAGGED);
    let parts: Vec<_> = doc.tree.children.iter().map(|n| n.id.0.as_str()).collect();
    assert_eq!(parts, ["protected", "unprotected", "payload", "signature"]);
    for id in [
        "protected/~e",
        "protected/~e/1",
        "protected/~e/1/~k",
        "unprotected/4",
        "payload/~e/1",
        "payload/~e/7",
    ] {
        assert!(has_node(&doc, id), "{id}: {:?}", ids(&doc));
    }
    assert_eq!(main_text(&doc, "protected/~e/1"), "-7");
    assert_eq!(main_text(&doc, "payload/~e/2"), r#""erikw""#);
    assert_eq!(find(&doc, "payload/~e/2").kind, NodeKind::Text);
    assert_eq!(find(&doc, "protected").kind, NodeKind::Part);
    assert_eq!(find(&doc, "protected/~e").kind, NodeKind::Map);
}

#[test]
fn sd_cwt_ids() {
    let e = engine();
    let doc = open_token(&e, SD_ISSUER);
    for id in [
        "protected/~e/170",
        "unprotected/17",
        "unprotected/17/0",
        "unprotected/17/0/~e",
        "unprotected/17/0/~e/0",
        "payload/~e/simple(59)",
        "payload/~e/simple(59)/0",
        "payload/~e/503/\"country\"",
        "payload/~e/8/1/-2",
    ] {
        assert!(has_node(&doc, id), "{id}: {:?}", ids(&doc));
    }
    // A redacted array element 60(h'…') has a tag content child.
    let redacted = walk(&doc.tree)
        .into_iter()
        .find(|n| n.kind == NodeKind::Tag && n.id.as_str().starts_with("payload/~e/502/"))
        .expect("a redacted inspection date");
    assert!(has_node(&doc, &format!("{}/~t", redacted.id)));
}

#[test]
fn sd_kbt_ids_nest_part_names() {
    let e = engine();
    let doc = open_token(&e, SD_KBT);
    for id in [
        "protected/~e/13",
        "protected/~e/13/protected/~e/1",
        "protected/~e/13/unprotected/17/0/~e",
        "protected/~e/13/payload/~e/1",
        "protected/~e/13/signature",
        "payload/~e/3",
        "payload/~e/39",
    ] {
        assert!(has_node(&doc, id), "{id}: {:?}", ids(&doc));
    }
}

#[test]
fn claim_set_and_key_ids() {
    let e = engine();
    let doc = open_token(&e, "rfc9901-s5.1-input-claims.json");
    for id in ["sub", "address/street_address", "nationalities/1"] {
        assert!(has_node(&doc, id), "{id}");
    }
    let doc = open_token(&e, "sd-cwt-08-fig4-claims.edn");
    for id in ["1", "8/1/-2", "502/2", "503/\"postal_code\""] {
        assert!(has_node(&doc, id), "{id}: {:?}", ids(&doc));
    }
}

// ---------------------------------------------------------------- uniqueness and shape

#[test]
fn ids_are_unique_and_children_extend_their_parent() {
    let e = engine();
    let names = JOSE_FIXTURES.iter().chain(COSE_FIXTURES.iter());
    for name in names {
        let doc = open_token(&e, name);
        let all = ids(&doc);
        let set: HashSet<_> = all.iter().collect();
        assert_eq!(set.len(), all.len(), "{name}: duplicate ids");
        for n in walk(&doc.tree) {
            for c in &n.children {
                assert_eq!(c.id.parent().as_ref(), Some(&n.id), "{name}: {}", c.id);
            }
            if let Some(k) = &n.key {
                assert_eq!(k.id, n.id.key(), "{name}");
            }
        }
    }
}

#[test]
fn duplicate_keys_fall_back_to_entry_indexes() {
    let e = engine();
    let doc = render(&e, Kind::JsonClaims, br#"{"a": 1, "b": 2, "a": 3}"#);
    let kids: Vec<_> = doc.tree.children.iter().map(|n| n.id.0.as_str()).collect();
    assert_eq!(kids, ["a", "b", "~i2"]);
    let doc = render(&e, Kind::CborClaims, &edn(r#"{1: 1, "1": 2, 1: 3}"#));
    let kids: Vec<_> = doc.tree.children.iter().map(|n| n.id.0.as_str()).collect();
    assert_eq!(kids, ["1", "\"1\"", "~i2"]);
}

#[test]
fn container_and_long_keys_use_entry_indexes() {
    let e = engine();
    let long = "x".repeat(80);
    let doc = render(
        &e,
        Kind::CborClaims,
        &edn(&format!(r#"{{[1, 2]: 1, "{long}": 2, h'0102': 3, -7: 4}}"#)),
    );
    let kids: Vec<_> = doc.tree.children.iter().map(|n| n.id.0.as_str()).collect();
    assert_eq!(kids, ["~i0", "~i1", "h'0102'", "-7"]);
}

#[test]
fn indicators_do_not_change_ids() {
    let e = engine();
    let a = render(&e, Kind::CborClaims, &hexd("a1 01 02"));
    let b = render(&e, Kind::CborClaims, &hexd("a1 18 01 19 00 02"));
    assert_eq!(ids(&a), ids(&b));
    assert_eq!(main_text(&b, "1/~k"), "1_0");
}

#[test]
fn indefinite_chunks_have_ids() {
    let e = engine();
    let doc = render(&e, Kind::CborClaims, &hexd("a1 01 7f 61 61 61 62 ff"));
    assert!(
        has_node(&doc, "1/~c0") && has_node(&doc, "1/~c1"),
        "{:?}",
        ids(&doc)
    );
}

// ---------------------------------------------------------------- stability

#[test]
fn ids_survive_rerender_and_view_changes() {
    let e = engine();
    for name in JOSE_FIXTURES.iter().chain(COSE_FIXTURES.iter()) {
        let doc = open_token(&e, name);
        let again = rerender(&e, &doc, ViewOptions::default());
        assert_eq!(ids(&again), ids(&doc), "{name}");
        let compact = rerender(
            &e,
            &doc,
            ViewOptions {
                layout: Layout::Compact,
                annotations: false,
                ..ViewOptions::default()
            },
        );
        assert_eq!(ids(&compact), ids(&doc), "{name}: layout/annotations");
    }
}

#[test]
fn tagging_does_not_change_ids() {
    let e = engine();
    let tagged = open_token(&e, CWT_TAGGED);
    let untagged = open_token(&e, CWT_UNTAGGED);
    let tag61 = open_token(&e, CWT_TAG61);
    assert_eq!(ids(&tagged), ids(&untagged));
    assert_eq!(ids(&tagged), ids(&tag61));
}

#[test]
fn hiding_a_decoded_view_removes_only_that_subtree() {
    let e = engine();
    let doc = open_token(&e, CWT_TAGGED);
    let hidden = rerender(
        &e,
        &doc,
        ViewOptions {
            hide_decoded: vec![node_id("payload")],
            ..ViewOptions::default()
        },
    );
    let kept: Vec<_> = ids(&doc)
        .into_iter()
        .filter(|id| !id.starts_with("payload/~e"))
        .collect();
    assert_eq!(ids(&hidden), kept);
}

#[test]
fn ids_survive_value_edits() {
    let e = engine();
    let doc = open_token(&e, SD_ISSUER);
    let r = edit(
        &e,
        &doc,
        replace_node(&doc, "payload/~e/2", r#""someone-else""#),
    );
    assert!(r.ok, "{:?}", r.diagnostics);
    assert_eq!(ids(&r.document.unwrap()), ids(&doc));
}

#[test]
fn inserting_a_member_keeps_sibling_ids() {
    let e = engine();
    let doc = open_token(&e, "rfc7519-s3.1-claims.json");
    let text = replace_node(&doc, "iss", r#""joe", "new": 1"#);
    let r = edit(&e, &doc, text);
    assert!(r.ok, "{:?}", r.diagnostics);
    let new = r.document.unwrap();
    for id in ids(&doc) {
        assert!(has_node(&new, &id), "{id} disappeared");
    }
    assert!(has_node(&new, "new"));
}
