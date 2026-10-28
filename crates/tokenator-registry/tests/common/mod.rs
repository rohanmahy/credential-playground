//! Shared fixtures for the tokenator-registry integration tests.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#![allow(dead_code)] // each test crate uses a subset

use tokenator_registry::{Entry, LocalAdditions, ParsedRegistry, Registry, RegistryId, parse_iana};

pub const CWT_XML: &[u8] = include_bytes!("../../../../testdata/iana/cwt.xml");
pub const COSE_XML: &[u8] = include_bytes!("../../../../testdata/iana/cose.xml");
pub const JWT_XML: &[u8] = include_bytes!("../../../../testdata/iana/jwt.xml");
pub const JOSE_XML: &[u8] = include_bytes!("../../../../testdata/iana/jose.xml");

pub fn xml(which: RegistryId) -> &'static [u8] {
    match which {
        RegistryId::Cwt => CWT_XML,
        RegistryId::Cose => COSE_XML,
        RegistryId::Jwt => JWT_XML,
        RegistryId::Jose => JOSE_XML,
    }
}

pub fn xml_str(which: RegistryId) -> &'static str {
    std::str::from_utf8(xml(which)).unwrap()
}

pub fn fixtures() -> Vec<(RegistryId, &'static [u8])> {
    RegistryId::ALL.iter().map(|&id| (id, xml(id))).collect()
}

pub fn parsed(which: RegistryId) -> ParsedRegistry {
    parse_iana(xml(which), which).unwrap()
}

/// Registry built from the four fixtures plus the bundled local additions.
pub fn registry() -> Registry {
    Registry::build(&fixtures(), LocalAdditions::bundled().unwrap()).unwrap()
}

/// Registry built from the given XML overrides (others from fixtures).
pub fn registry_with(overrides: &[(RegistryId, &[u8])], local: LocalAdditions) -> Registry {
    let inputs: Vec<(RegistryId, &[u8])> = RegistryId::ALL
        .iter()
        .map(|&id| {
            let x = overrides
                .iter()
                .find(|(o, _)| *o == id)
                .map_or(xml(id), |(_, x)| *x);
            (id, x)
        })
        .collect();
    Registry::build(&inputs, local).unwrap()
}

/// Removes the first `<record>…</record>` containing `needle`.
pub fn remove_record(xml: &str, needle: &str) -> String {
    let at = xml
        .find(needle)
        .unwrap_or_else(|| panic!("{needle} not in fixture"));
    let start = xml[..at].rfind("<record").unwrap();
    let end = at + xml[at..].find("</record>").unwrap() + "</record>".len();
    format!("{}{}", &xml[..start], &xml[end..])
}

/// Inserts `record` just before the first `<record` after `<registry id="sub_id">`.
pub fn insert_record(xml: &str, sub_id: &str, record: &str) -> String {
    let reg = xml
        .find(&format!("<registry id=\"{sub_id}\">"))
        .unwrap_or_else(|| panic!("no sub-registry {sub_id}"));
    let at = reg + xml[reg..].find("<record").unwrap();
    format!("{}{}\n    {}", &xml[..at], record, &xml[at..])
}

pub fn find<'a>(entries: &'a [Entry], name: &str) -> Vec<&'a Entry> {
    entries.iter().filter(|e| e.name == name).collect()
}
