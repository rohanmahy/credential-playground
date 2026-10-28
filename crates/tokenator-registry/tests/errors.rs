//! Malformed IANA XML yields errors, never panics.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use tokenator_registry::{Label, RegistryError, RegistryId, parse_iana};

fn assert_xml_err(xml: &[u8], which: RegistryId) {
    match parse_iana(xml, which) {
        Err(RegistryError::Xml { registry, message }) => {
            assert_eq!(registry, which);
            assert!(!message.is_empty());
        }
        other => panic!(
            "{:?}: expected Xml error, got {other:?}",
            String::from_utf8_lossy(xml)
        ),
    }
}

#[test]
fn empty_and_non_xml() {
    for which in RegistryId::ALL {
        assert_xml_err(b"", which);
        assert_xml_err(b"   \n", which);
        assert_xml_err(b"hello, world", which);
        assert_xml_err(b"{\"json\": true}", which);
    }
}

#[test]
fn non_utf8() {
    assert_xml_err(b"\xff\xfe<\x00r\x00", RegistryId::Cose);
    assert_xml_err(
        b"<registry id=\"cose\"><record><name>\xff\xff</name></record></registry>",
        RegistryId::Cose,
    );
}

#[test]
fn truncated_fixtures() {
    for which in RegistryId::ALL {
        let xml = common::xml(which);
        for frac in [10, 3, 2] {
            assert_xml_err(&xml[..xml.len() / frac], which);
        }
        assert_xml_err(&xml[..xml.len() - 12], which);
    }
}

#[test]
fn mismatched_tags() {
    assert_xml_err(
        br#"<registry id="cose"><registry id="algorithms"><record><name>X</value></record></registry></registry>"#,
        RegistryId::Cose,
    );
    assert_xml_err(
        br#"<registry id="cose"></registry></registry>"#,
        RegistryId::Cose,
    );
}

#[test]
fn root_is_not_a_registry() {
    assert_xml_err(
        br#"<?xml version="1.0"?><html><body/></html>"#,
        RegistryId::Jose,
    );
    assert_xml_err(
        br#"<registry><title>no id</title></registry>"#,
        RegistryId::Jose,
    );
}

#[test]
fn bad_entities_and_unterminated_constructs() {
    assert_xml_err(
        br#"<registry id="cose"><!-- unterminated comment"#,
        RegistryId::Cose,
    );
    assert_xml_err(br#"<registry id="cose"><![CDATA[ nope"#, RegistryId::Cose);
    assert_xml_err(
        br#"<registry id="cose" attr="unterminated></registry>"#,
        RegistryId::Cose,
    );
}

#[test]
fn deeply_nested_junk_does_not_overflow() {
    let mut s = String::from(r#"<registry id="cwt">"#);
    for _ in 0..50_000 {
        s.push_str("<a>");
    }
    // Unclosed: must be an error, and must not blow the stack.
    assert_xml_err(s.as_bytes(), RegistryId::Cwt);
    for _ in 0..50_000 {
        s.push_str("</a>");
    }
    s.push_str("</registry>");
    // Well-formed but no records: fine, just empty.
    let p = parse_iana(s.as_bytes(), RegistryId::Cwt).unwrap();
    assert!(p.entries.is_empty());
}

#[test]
fn minimal_valid_document() {
    let xml = br#"<?xml version='1.0' encoding='UTF-8'?>
<registry xmlns="http://www.iana.org/assignments" id="cose">
  <updated>2030-01-01</updated>
  <registry id="algorithms">
    <record><name>X-ALG</name><value>-70000</value><description>d</description></record>
  </registry>
  <registry id="some-future-subregistry">
    <record><name>ignored</name><value>1</value></record>
  </registry>
</registry>"#;
    let p = parse_iana(xml, RegistryId::Cose).unwrap();
    assert_eq!(p.updated.as_deref(), Some("2030-01-01"));
    assert_eq!(p.entries.len(), 1, "unknown sub-registries are ignored");
    assert_eq!(p.entries[0].label, Label::Int(-70000));
    assert_eq!(p.entries[0].reference, vec![]);
    assert_eq!(p.entries[0].value_type, None);
}

#[test]
fn records_with_odd_labels_are_skipped_not_errors() {
    let xml = br#"<registry id="cose">
  <registry id="header-parameters">
    <record><name>ok</name><label>9999</label><description>fine</description></record>
    <record><name>range</name><label>18-21</label></record>
    <record><name>words</name><label>less than -65536</label></record>
    <record><name>huge</name><label>99999999999999999999999</label></record>
    <record><name>nolabel</name></record>
    <record><label>7777</label></record>
  </registry>
</registry>"#;
    let p = parse_iana(xml, RegistryId::Cose).unwrap();
    let names: Vec<_> = p.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["ok"]);
}

#[test]
fn entities_are_decoded() {
    let xml = br#"<registry id="jose">
  <registry id="web-signature-encryption-header-parameters">
    <record><value>a&amp;b</value><description>x &lt; y &#65;</description></record>
  </registry>
</registry>"#;
    let p = parse_iana(xml, RegistryId::Jose).unwrap();
    assert_eq!(p.entries[0].label, Label::from("a&b"));
    assert_eq!(p.entries[0].name, "a&b");
    assert_eq!(p.entries[0].description, "x < y A");
}

#[test]
fn errors_display_without_panicking() {
    let e = parse_iana(b"", RegistryId::Cwt).unwrap_err();
    assert!(e.to_string().contains("cwt"));
    let e = parse_iana(common::COSE_XML, RegistryId::Jwt).unwrap_err();
    assert!(e.to_string().contains("cose"));
}
