//! Main-pane ranges and raw-pane ranges point at the same item
//! (TEST-PLAN §5), and hex rows line up with the tree.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use base64ct::{Base64UrlUnpadded, Encoding};
use common::*;
use tokenator_core::{Document, HexRowKind, Kind, Node, RawView, TextRange};

fn lines_of(text: &str, r: TextRange) -> (u32, u32) {
    let units: Vec<u16> = text.encode_utf16().collect();
    let nl = |u: &u16| *u == u16::from(b'\n');
    let start = units[..r.start as usize].iter().filter(|u| nl(u)).count() as u32;
    let inner = units[r.start as usize..r.end as usize]
        .iter()
        .filter(|u| nl(u))
        .count() as u32;
    (start, start + inner + 1)
}

fn check_lines(name: &str, doc: &Document) {
    let total = doc.main.text.encode_utf16().count() as u32;
    for n in walk(&doc.tree) {
        let Some(r) = n.main else { continue };
        assert!(r.start <= r.end && r.end <= total, "{name}: {} {r:?}", n.id);
        let (ls, le) = lines_of(&doc.main.text, r);
        assert_eq!((r.line_start, r.line_end), (ls, le), "{name}: {}", n.id);
    }
    let lines = doc.main.text.split('\n').count() as u32;
    assert_eq!(doc.main.line_count, lines, "{name}");
}

/// COSE/CBOR: EDN of the main slice encodes to exactly the raw bytes.
fn check_hex(name: &str, doc: &Document) {
    let RawView::Hex { bytes, rows } = &doc.raw else {
        panic!("{name}: not a hex view")
    };
    let mut checked = 0;
    for n in walk(&doc.tree) {
        let (Some(main), Some(raw)) = (n.main, n.raw) else {
            continue;
        };
        let text = slice16(&doc.main.text, main);
        let want = &bytes[raw.start as usize..raw.end as usize];
        let item = tokenator_edn::parse(&text)
            .unwrap_or_else(|err| panic!("{name}: {} {text:?}: {err}", n.id));
        let got = tokenator_cbor::encode(&item, tokenator_cbor::EncodeMode::Preserve).unwrap();
        assert_eq!(got, want, "{name}: {} {text:?}", n.id);
        checked += 1;
        // Rows: the first row starts the node, all rows lie inside it.
        assert!(raw.row_start < raw.row_end, "{name}: {}", n.id);
        let first = &rows[raw.row_start as usize];
        assert_eq!(first.head.start, raw.start, "{name}: {}", n.id);
        for row in &rows[raw.row_start as usize..raw.row_end as usize] {
            assert!(
                row.head.start >= raw.start && row.payload.end.max(row.head.end) <= raw.end,
                "{name}: {} row {row:?} outside {raw:?}",
                n.id
            );
        }
    }
    assert!(checked >= 5, "{name}: only {checked} nodes checked");
}

#[test]
fn cose_main_and_raw_ranges_agree() {
    let e = engine();
    for name in COSE_FIXTURES {
        let doc = open_token(&e, name);
        check_hex(name, &doc);
        check_lines(name, &doc);
    }
}

#[test]
fn cbor_and_edn_claim_ranges_agree() {
    let e = engine();
    for name in ["rfc8392-a1-claims.cbor", "sd-cwt-08-fig4-claims.edn"] {
        let doc = open_token(&e, name);
        check_hex(name, &doc);
        check_lines(name, &doc);
    }
    let odd = render(
        &e,
        Kind::CborClaims,
        &hexd("bf 01 18 01 02 7f 61 61 61 62 ff 03 f9 7e 01 ff"),
    );
    check_hex("odd encodings", &odd);
}

#[test]
fn hex_rows_cover_the_buffer_in_order() {
    let e = engine();
    for name in COSE_FIXTURES {
        let doc = open_token(&e, name);
        let RawView::Hex { bytes, rows } = &doc.raw else {
            panic!()
        };
        assert_eq!(
            &bytes[..],
            &doc.bytes[..],
            "{name}: COSE rows index the credential"
        );
        let mut at = 0;
        for row in rows {
            assert!(row.head.start >= at, "{name}: rows out of order at {row:?}");
            at = row.head.end;
            if row.payload.start != row.payload.end {
                assert_eq!(row.payload.start, row.head.end, "{name}");
                at = row.payload.end;
            }
            assert!(
                has_node(&doc, row.node_id.as_str()),
                "{name}: {}",
                row.node_id
            );
            if row.kind == HexRowKind::Break {
                assert_eq!(bytes[row.head.start as usize], 0xff);
            }
        }
        assert_eq!(at as usize, bytes.len(), "{name}: every byte has a row");
    }
}

#[test]
fn envelope_tag_rows_belong_to_the_root() {
    let e = engine();
    let doc = open_token(&e, CWT_TAG61);
    let RawView::Hex { rows, .. } = &doc.raw else {
        panic!()
    };
    // d8 3d (tag 61), d2 (tag 18), 84 (array): all root rows.
    assert!(
        rows[..3].iter().all(|r| r.node_id.is_root()),
        "{:?}",
        &rows[..3]
    );
    assert_eq!(rows[0].head.start..rows[0].head.end, 0..2);
    assert_eq!(rows[0].description, "tag(61)");
}

#[test]
fn decoded_views_point_at_bstr_contents() {
    let e = engine();
    let doc = open_token(&e, CWT_TAGGED);
    let bstr = find(&doc, "protected").raw.unwrap();
    let decoded = find(&doc, "protected/~e").raw.unwrap();
    // 43 a1 01 26: the content starts after the one-byte head.
    assert_eq!(decoded.start, bstr.start + 1);
    assert_eq!(decoded.end, bstr.end);
    assert_eq!(raw_bytes(&doc, "protected/~e"), hexd("a1 01 26"));
    assert_eq!(main_text(&doc, "protected/~e/1"), "-7");
}

/// JOSE: a node inside a decoded part covers the base64url characters that
/// encode its bytes; decoding them gives bytes containing the main slice.
fn check_segments(name: &str, doc: &Document) {
    let RawView::Segments { segments } = &doc.raw else {
        panic!("{name}: not a segment view")
    };
    let token = &doc.bytes[..];
    for (i, s) in segments.iter().enumerate() {
        let part = find(doc, s.node_id.as_str());
        let raw = part.raw.unwrap();
        assert_eq!((raw.start, raw.end), (s.range.start, s.range.end), "{name}");
        assert_eq!(
            (raw.row_start, raw.row_end),
            (i as u32, i as u32 + 1),
            "{name}"
        );
        assert_eq!(
            &token[s.range.start as usize..s.range.end as usize],
            s.text.as_bytes(),
            "{name}"
        );
    }
    let decoded_nodes = walk(&doc.tree)
        .into_iter()
        .filter(|n| n.id.as_str().contains("~e"))
        .collect::<Vec<&Node>>();
    assert!(!decoded_nodes.is_empty(), "{name}");
    for n in decoded_nodes {
        let (Some(main), Some(raw)) = (n.main, n.raw) else {
            panic!("{name}: {} lacks a range", n.id)
        };
        let seg = segments
            .iter()
            .find(|s| s.range.start <= raw.start && raw.end <= s.range.end)
            .unwrap_or_else(|| panic!("{name}: {} not inside a segment", n.id));
        assert_eq!(
            (raw.start - seg.range.start) % 4,
            0,
            "{name}: {} unaligned",
            n.id
        );
        let chars = std::str::from_utf8(&token[raw.start as usize..raw.end as usize]).unwrap();
        let decoded = Base64UrlUnpadded::decode_vec(chars)
            .or_else(|_| Base64UrlUnpadded::decode_vec(&chars[..chars.len() / 4 * 4]))
            .unwrap();
        let text = slice16(&doc.main.text, main);
        assert!(
            decoded
                .windows(text.len().max(1))
                .any(|w| w == text.as_bytes())
                || text.is_empty(),
            "{name}: {} {text:?} not in {:?}",
            n.id,
            String::from_utf8_lossy(&decoded)
        );
    }
}

#[test]
fn jose_main_and_raw_ranges_agree() {
    let e = engine();
    for name in JOSE_FIXTURES {
        let doc = open_token(&e, name);
        check_segments(name, &doc);
        check_lines(name, &doc);
    }
}

#[test]
fn jose_decoded_parts_are_verbatim() {
    let e = engine();
    let doc = open_token(&e, "rfc7515-a3-jws-es256.txt");
    let payload = main_text(&doc, "payload/~e");
    assert_eq!(
        payload,
        "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
    );
    assert_eq!(main_text(&doc, "protected/~e"), r#"{"alg":"ES256"}"#);
    let sig = segment_texts(&doc)[2].clone();
    assert_eq!(main_text(&doc, "signature"), format!("\"{sig}\""));
}

#[test]
fn non_ascii_text_ranges_are_utf16() {
    // Ranges are UTF-16 code units: an astral character before a node
    // shifts it by two units, a Latin-1 one by one.
    let e = engine();
    let json = render(
        &e,
        Kind::JsonClaims,
        "{\"name\": \"M\u{f6}bius \u{1f600}\", \"x\": \"y\"}".as_bytes(),
    );
    assert_eq!(main_text(&json, "name"), "\"M\u{f6}bius \u{1f600}\"");
    assert_eq!(main_text(&json, "x"), "\"y\"");
    let r = find(&json, "x").main.unwrap();
    assert_eq!(r.start as usize, json.main.text.encode_utf16().count() - 4);
    check_lines("non-ASCII JSON", &json);

    let cbor = render(
        &e,
        Kind::CborClaims,
        &edn("{1: \"M\u{f6}bius \u{1f600}\", 2: \"y\"}"),
    );
    assert_eq!(main_text(&cbor, "2"), "\"y\"");
    check_hex("non-ASCII CBOR", &cbor);
}

#[test]
fn json_claims_ranges_slice_the_document_text() {
    let e = engine();
    let doc = open_token(&e, "rfc9901-s5.1-input-claims.json");
    assert_eq!(main_text(&doc, "address/locality"), r#""Anytown""#);
    assert_eq!(main_text(&doc, "nationalities/1"), r#""DE""#);
    assert_eq!(main_text(&doc, "updated_at"), "1570000000");
    assert!(walk(&doc.tree).iter().all(|n| n.raw.is_none()));
    check_lines("s5.1 claims", &doc);
}
