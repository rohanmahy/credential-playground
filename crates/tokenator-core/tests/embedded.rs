//! Decoded views appear only at format-defined locations (#15), can be
//! toggled, and manual decoding warns about trailing bytes (SPEC §4.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_core::{
    DecodeEmbeddedRequest, DocRef, Document, Engine, ErrorCode, Kind, Layout, NodeKind,
    RenderRequest, Severity, ViewOptions,
};

/// The id prefixes (before `~e`) of every decoded view.
fn decoded_at(doc: &Document) -> Vec<String> {
    ids(doc)
        .into_iter()
        .filter_map(|id| {
            let segs: Vec<&str> = id.split('/').collect();
            let last = *segs.last()?;
            (last == "~e" || (last.starts_with("~e") && last[2..].parse::<u32>().is_ok()))
                .then(|| segs[..segs.len() - 1].join("/"))
        })
        .collect()
}

fn allowed_cose(prefix: &str) -> bool {
    let rest = prefix.strip_prefix("protected/~e/13/").unwrap_or(prefix);
    let segs: Vec<&str> = rest.split('/').collect();
    matches!(segs.as_slice(), ["protected"] | ["payload"])
        || matches!(segs.as_slice(), ["unprotected", "17", n] if n.parse::<u32>().is_ok())
        || segs.last() == Some(&"~t")
}

fn allowed_jose(prefix: &str) -> bool {
    let segs: Vec<&str> = prefix.split('/').collect();
    matches!(
        segs.as_slice(),
        ["protected"] | ["payload"] | ["kb", "protected"] | ["kb", "payload"]
    ) || matches!(segs.as_slice(), ["disclosures", n] if n.parse::<u32>().is_ok())
        || matches!(segs.as_slice(), ["signatures", n, "protected"] if n.parse::<u32>().is_ok())
}

fn with_view(e: &Engine, doc: &Document, view: ViewOptions) -> Document {
    e.render(&RenderRequest {
        doc: DocRef::from(doc),
        layers: vec![],
        view,
    })
    .unwrap()
}

#[test]
fn cose_decoded_views_only_at_defined_locations() {
    let e = engine();
    for name in COSE_FIXTURES {
        let doc = open_token(&e, name);
        let at = decoded_at(&doc);
        assert!(at.contains(&"protected".to_owned()), "{name}: {at:?}");
        for prefix in &at {
            assert!(allowed_cose(prefix), "{name}: decoded view at {prefix}");
        }
    }
}

#[test]
fn jose_decoded_views_only_at_defined_locations() {
    let e = engine();
    for name in JOSE_FIXTURES {
        let doc = open_token(&e, name);
        for prefix in decoded_at(&doc) {
            assert!(allowed_jose(&prefix), "{name}: decoded view at {prefix}");
        }
        assert!(!has_node(&doc, "signature/~e"), "{name}");
    }
}

#[test]
fn every_defined_location_is_decoded() {
    let e = engine();
    let doc = open_token(&e, SD_KBT);
    let at = decoded_at(&doc);
    for want in [
        "protected",
        "payload",
        "protected/~e/13/protected",
        "protected/~e/13/payload",
        "protected/~e/13/unprotected/17/0",
    ] {
        assert!(at.contains(&want.to_owned()), "{want}: {at:?}");
    }
    let doc = open_token(&e, "rfc9901-s5.2-sd-jwt-kb.txt");
    let at = decoded_at(&doc);
    for want in [
        "protected",
        "payload",
        "disclosures/0",
        "disclosures/3",
        "kb/protected",
        "kb/payload",
    ] {
        assert!(at.contains(&want.to_owned()), "{want}: {at:?}");
    }
}

#[test]
fn text_payload_is_not_decoded() {
    let e = engine();
    // RFC 9052 C.2.1: "This is the content." is not CBOR.
    let doc = open_token(&e, "rfc9052-c2.1-sign1.cbor");
    assert!(!has_node(&doc, "payload/~e"));
    assert_eq!(find(&doc, "payload").kind, NodeKind::Part);
}

#[test]
fn no_guessing_inside_claims() {
    // A claim whose value happens to be valid CBOR stays h''.
    let e = engine();
    let doc = render(&e, Kind::CborClaims, &edn("{1: h'a10101', 2: h'00'}"));
    assert!(!has_node(&doc, "1/~e"));
    assert_eq!(main_text(&doc, "1"), "h'a10101'");
    // Inside a CWT payload as well (the cnf key's coordinates, too).
    let doc = open_token(&e, SD_ISSUER);
    for id in ids(&doc) {
        if let Some(rest) = id.strip_prefix("payload/~e/") {
            assert!(!rest.contains("~e"), "guessed {id}");
        }
    }
}

#[test]
fn tag_24_contents_are_decoded() {
    let e = engine();
    let doc = render(&e, Kind::CborClaims, &edn("{1: 24(h'a10101')}"));
    assert!(has_node(&doc, "1/~t/~e"), "{:?}", ids(&doc));
}

#[test]
fn decoded_views_can_be_turned_off() {
    let e = engine();
    for name in [CWT_TAGGED, SD_KBT, "rfc9901-s5.2-sd-jwt-kb.txt"] {
        let doc = open_token(&e, name);
        let off = with_view(
            &e,
            &doc,
            ViewOptions {
                decoded_views: false,
                ..ViewOptions::default()
            },
        );
        assert!(decoded_at(&off).is_empty(), "{name}");
        assert_eq!(off.bytes, doc.bytes);
    }
}

#[test]
fn decoded_views_can_be_hidden_per_node() {
    let e = engine();
    let doc = open_token(&e, CWT_TAGGED);
    let hidden = with_view(
        &e,
        &doc,
        ViewOptions {
            hide_decoded: vec![node_id("protected")],
            ..ViewOptions::default()
        },
    );
    assert!(!has_node(&hidden, "protected/~e"));
    assert!(has_node(&hidden, "payload/~e"));
    assert_eq!(main_text(&hidden, "protected"), "h'a10126'");
}

#[test]
fn hex_alignment_stays_on_the_original_bytes() {
    let e = engine();
    let doc = open_token(&e, CWT_TAGGED);
    let off = with_view(
        &e,
        &doc,
        ViewOptions {
            decoded_views: false,
            ..ViewOptions::default()
        },
    );
    assert_eq!(hex_bytes(&off), hex_bytes(&doc));
    assert_eq!(
        find(&off, "protected").raw.unwrap().start,
        find(&doc, "protected").raw.unwrap().start
    );
}

// ---------------------------------------------------------------- manual decode

fn claims_with_bstrs(e: &Engine) -> Document {
    render(
        e,
        Kind::CborClaims,
        &edn("{1: h'a10101', 2: h'0102', 3: h'18', 4: \"text\", 5: h''}"),
    )
}

fn decode(
    e: &Engine,
    doc: &Document,
    id: &str,
) -> Result<tokenator_core::ManualDecode, tokenator_core::EngineError> {
    e.decode_embedded(&DecodeEmbeddedRequest {
        doc: DocRef::from(doc),
        node_id: node_id(id),
        view: ViewOptions {
            layout: Layout::Compact,
            annotations: false,
            ..ViewOptions::default()
        },
    })
}

#[test]
fn manual_decode_of_one_item() {
    let e = engine();
    let doc = claims_with_bstrs(&e);
    let m = decode(&e, &doc, "1").unwrap();
    assert_eq!(m.text, "{1: 1}");
    assert_eq!(m.tree.id, node_id("1/~e"));
    assert!(m.diagnostics.is_empty());
    // Raw ranges stay absolute in the document's buffer.
    let content = find(&doc, "1").raw.unwrap();
    assert_eq!(m.tree.raw.unwrap().start, content.start + 1);
}

#[test]
fn manual_decode_warns_about_trailing_bytes() {
    let e = engine();
    let doc = claims_with_bstrs(&e);
    let m = decode(&e, &doc, "2").unwrap();
    assert_eq!(m.text, "1");
    let w = m
        .diagnostics
        .iter()
        .find(|d| d.code == "cbor.trailing_bytes")
        .expect("trailing bytes warning");
    assert_eq!(w.severity, Severity::Warning);
    let r = w.raw.unwrap();
    assert_eq!(r.end - r.start, 1, "one byte left over");
}

#[test]
fn manual_decode_failures_are_errors() {
    let e = engine();
    let doc = claims_with_bstrs(&e);
    assert_eq!(
        decode(&e, &doc, "3").unwrap_err().code,
        ErrorCode::Decode,
        "missing bytes"
    );
    assert_eq!(
        decode(&e, &doc, "5").unwrap_err().code,
        ErrorCode::Decode,
        "empty"
    );
    assert_eq!(decode(&e, &doc, "4").unwrap_err().code, ErrorCode::NotBytes);
    assert_eq!(
        decode(&e, &doc, "9").unwrap_err().code,
        ErrorCode::NodeNotFound
    );
    let jwt = open_token(&e, "rfc7515-a3-jws-es256.txt");
    assert_eq!(
        decode(&e, &jwt, "payload/~e/iss").unwrap_err().code,
        ErrorCode::NotBytes
    );
}

#[test]
fn manual_decode_through_view_options() {
    let e = engine();
    let doc = claims_with_bstrs(&e);
    let shown = with_view(
        &e,
        &doc,
        ViewOptions {
            manual_decode: vec![node_id("1"), node_id("2")],
            ..ViewOptions::default()
        },
    );
    assert!(has_node(&shown, "1/~e"));
    assert!(has_node(&shown, "2/~e"));
    assert!(
        shown
            .diagnostics
            .iter()
            .any(|d| d.code == "cbor.trailing_bytes" && d.node_id == Some(node_id("2"))),
        "{:?}",
        shown.diagnostics
    );
    // The hex view gets rows for the decoded item, still on the original bytes.
    assert_eq!(hex_bytes(&shown), hex_bytes(&doc));
    assert!(find(&shown, "1/~e").raw.is_some());
}

#[test]
fn manual_decode_in_a_cwt_claim() {
    let e = engine();
    let doc = open_token(&e, CWT_TAGGED);
    // cti (7) is h'0b71': 0x0b is the integer 11, 0x71 is left over.
    let m = decode(&e, &doc, "payload/~e/7").unwrap();
    assert_eq!(m.text, "11");
    assert!(
        m.diagnostics
            .iter()
            .any(|d| d.code == "cbor.trailing_bytes")
    );
}
