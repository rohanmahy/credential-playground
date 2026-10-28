//! `SpecRef::display_text` omits draft revision numbers (issue #5).

use tokenator_registry::{EntryKind, Registry, SpecRef};

fn display(text: &str) -> String {
    SpecRef {
        text: text.into(),
        url: None,
    }
    .display_text()
}

#[test]
fn strips_draft_revision() {
    assert_eq!(
        display("draft-ietf-spice-sd-cwt-08, Section 3.3"),
        "draft-ietf-spice-sd-cwt, Section 3.3"
    );
    assert_eq!(
        display("draft-ietf-spice-sd-cwt-06"),
        "draft-ietf-spice-sd-cwt"
    );
}

#[test]
fn strips_rfc_editor_placeholder_revision() {
    assert_eq!(
        display("RFC-ietf-spice-sd-cwt-06, Section 4"),
        "RFC-ietf-spice-sd-cwt, Section 4"
    );
}

#[test]
fn strips_every_draft_in_text() {
    assert_eq!(
        display("draft-a-b-01 and draft-c-d-12; RFC 9052"),
        "draft-a-b and draft-c-d; RFC 9052"
    );
}

#[test]
fn leaves_other_text_alone() {
    for text in [
        "RFC 7519, Section 4.1.1",
        "RFC 9964",
        "draft-ietf-cose-hash-envelope",
        "draft-foo-2024",
        "draft-",
        "",
        "Section 3.3 of draft-x-1",
    ] {
        assert_eq!(display(text), text);
    }
}

#[test]
fn url_keeps_exact_revision() {
    let r = SpecRef {
        text: "draft-ietf-spice-sd-cwt-08".into(),
        url: Some("https://datatracker.ietf.org/doc/html/draft-ietf-spice-sd-cwt-08".into()),
    };
    assert_eq!(r.display_text(), "draft-ietf-spice-sd-cwt");
    assert!(r.url.as_deref().is_some_and(|u| u.ends_with("-08")));
}

#[test]
fn bundled_sd_claims_hover_text_has_no_revision() {
    let reg = Registry::shared().unwrap();
    let entry = reg.by_name(EntryKind::CoseHeader, "sd_claims").unwrap();
    let texts: Vec<String> = entry.reference.iter().map(SpecRef::display_text).collect();
    assert!(!texts.is_empty());
    for t in texts {
        assert!(t.starts_with("draft-ietf-spice-sd-cwt") || t.starts_with("RFC-ietf-spice-sd-cwt"));
        assert!(!t.contains("-06") && !t.contains("-08"), "{t}");
    }
}
