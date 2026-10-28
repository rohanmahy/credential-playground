//! IANA XML and local-additions parsing.

use std::collections::HashSet;

use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use serde::Deserialize;

use crate::registry::{Identity, identity};
use crate::{Entry, EntryKind, Label, RegistryError, RegistryId, Source, SpecRef};

/// The entries parsed from one IANA registry XML document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedRegistry {
    /// Which registry this is.
    pub which: RegistryId,
    /// The root `<updated>` date (`YYYY-MM-DD`), if present.
    pub updated: Option<String>,
    /// Entries, all with [`crate::Source::Iana`], in document order. Ranges,
    /// `Unassigned`, `Reserved…`, and `delegated…` records are skipped.
    pub entries: Vec<Entry>,
}

/// Parses one IANA registry XML document (e.g. `cose.xml`).
///
/// Returns [`RegistryError::WrongRegistry`] if the root `<registry id>` isn't
/// `which.xml_id()`, and [`RegistryError::Xml`] if the document is malformed.
/// Never panics on bad input.
///
/// ```
/// use tokenator_registry::{EntryKind, Label, RegistryId, parse_iana};
///
/// let xml = br#"<registry xmlns="http://www.iana.org/assignments" id="cose">
///   <updated>2026-08-25</updated>
///   <registry id="algorithms">
///     <record>
///       <name>ES256</name><value>-7</value>
///       <description>ECDSA w/ SHA-256</description>
///       <xref type="rfc" data="rfc9053" section="2.1"/>
///     </record>
///     <record><name>Unassigned</name><value>-6 to -5</value></record>
///   </registry>
/// </registry>"#;
/// let parsed = parse_iana(xml, RegistryId::Cose)?;
/// assert_eq!(parsed.updated.as_deref(), Some("2026-08-25"));
/// assert_eq!(parsed.entries.len(), 1); // the range is skipped
/// let es256 = &parsed.entries[0];
/// assert_eq!((es256.kind, &es256.label), (EntryKind::CoseAlg, &Label::Int(-7)));
/// assert_eq!(es256.reference[0].text, "RFC 9053, Section 2.1");
/// # Ok::<(), tokenator_registry::RegistryError>(())
/// ```
pub fn parse_iana(xml: &[u8], which: RegistryId) -> Result<ParsedRegistry, RegistryError> {
    let err = |message: String| RegistryError::Xml {
        registry: which,
        message,
    };
    let text = std::str::from_utf8(xml).map_err(|e| err(format!("not UTF-8: {e}")))?;
    let mut reader = Reader::from_str(text);
    reader.config_mut().expand_empty_elements = true;
    let mut doc = Doc::new(which);
    loop {
        let event = reader
            .read_event()
            .map_err(|e| err(format!("at byte {}: {e}", reader.error_position())))?;
        match event {
            Event::Start(s) => doc.start(&s)?,
            // Not produced with `expand_empty_elements`, but equivalent anyway.
            Event::Empty(s) => {
                doc.start(&s)?;
                doc.end()?;
            }
            Event::End(_) => doc.end()?,
            Event::Text(t) => doc.text(&t.xml10_content())?,
            Event::CData(t) => doc.text(&t.xml10_content())?,
            Event::GeneralRef(r) => doc.text(&resolve_ref(&r).map_err(err)?)?,
            Event::Eof => break,
            Event::Comment(_) | Event::Decl(_) | Event::PI(_) | Event::DocType(_) => {}
        }
    }
    doc.finish()
}

/// Resolves `&name;` or `&#N;` to its text.
fn resolve_ref(r: &BytesRef<'_>) -> Result<String, String> {
    if r.is_char_ref() {
        return match r.resolve_char_ref() {
            Ok(Some(c)) => Ok(c.to_string()),
            Ok(None) | Err(_) => Err(format!("invalid character reference &{};", &**r)),
        };
    }
    quick_xml::escape::resolve_predefined_entity(r)
        .map(str::to_owned)
        .ok_or_else(|| format!("unknown entity &{};", &**r))
}

/// The entry kind of sub-registry `id` in registry `which`. Unknown
/// sub-registries are ignored.
fn sub_registry_kind(which: RegistryId, id: &str) -> Option<EntryKind> {
    use EntryKind::*;
    Some(match (which, id) {
        (RegistryId::Cwt, "claims-registry") => CwtClaim,
        (RegistryId::Cwt, "confirmation-methods") => CwtCnfMethod,
        (RegistryId::Cose, "header-parameters") => CoseHeader,
        (RegistryId::Cose, "header-algorithm-parameters") => CoseHeaderAlgParam,
        (RegistryId::Cose, "algorithms") => CoseAlg,
        (RegistryId::Cose, "key-common-parameters") => CoseKeyParam,
        (RegistryId::Cose, "key-type-parameters") => CoseKeyTypeParam,
        (RegistryId::Cose, "key-type") => CoseKty,
        (RegistryId::Cose, "elliptic-curves") => CoseCrv,
        (RegistryId::Jwt, "claims") => JwtClaim,
        (RegistryId::Jwt, "confirmation-methods") => JwtCnfMethod,
        (RegistryId::Jose, "web-signature-encryption-header-parameters") => JoseHeader,
        (RegistryId::Jose, "web-signature-encryption-algorithms") => JoseAlg,
        (RegistryId::Jose, "web-key-types") => JwkKty,
        (RegistryId::Jose, "web-key-elliptic-curve") => JwkCrv,
        (RegistryId::Jose, "web-key-parameters") => JwkParam,
        _ => return None,
    })
}

/// Attributes of an `<xref>` element.
#[derive(Clone, Debug, Default)]
struct Xref {
    kind: String,
    data: String,
    section: Option<String>,
}

impl Xref {
    fn from_start(s: &BytesStart<'_>) -> Result<Self, String> {
        let attr = |name: &str| -> Result<Option<String>, String> {
            match s.try_get_attribute(name) {
                Ok(Some(a)) => a
                    .normalized_value(XmlVersion::Implicit1_0)
                    .map(|v| Some(v.into_owned()))
                    .map_err(|e| e.to_string()),
                Ok(None) => Ok(None),
                Err(e) => Err(e.to_string()),
            }
        };
        Ok(Self {
            kind: attr("type")?.unwrap_or_default(),
            data: attr("data")?.unwrap_or_default(),
            section: attr("section")?,
        })
    }

    /// The reference this xref denotes, given its (flattened) text content.
    /// `person` and `registry` xrefs are not specification references.
    fn spec_ref(&self, text: &str) -> Option<SpecRef> {
        match self.kind.as_str() {
            "rfc" => {
                let digits = self
                    .data
                    .get(..3)
                    .filter(|p| p.eq_ignore_ascii_case("rfc"))
                    .and(self.data.get(3..))
                    .filter(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()));
                Some(match digits {
                    Some(n) => self.with_section(
                        format!("RFC {n}"),
                        Some(format!("https://www.rfc-editor.org/rfc/rfc{n}")),
                    ),
                    None => self.with_section(self.data.clone(), None),
                })
            }
            "draft" => {
                let name = match self.data.strip_prefix("RFC-") {
                    Some(rest) => format!("draft-{rest}"),
                    None => self.data.clone(),
                };
                let url = format!("https://datatracker.ietf.org/doc/html/{name}");
                Some(self.with_section(name, Some(url)))
            }
            "uri" => Some(SpecRef {
                text: if text.is_empty() {
                    self.data.clone()
                } else {
                    text.to_owned()
                },
                url: Some(self.data.clone()),
            }),
            _ => None,
        }
    }

    /// Appends `, Section S` to the text and `#section-S` to the URL.
    fn with_section(&self, mut text: String, mut url: Option<String>) -> SpecRef {
        if let Some(section) = self.section.as_deref().map(str::trim) {
            if section.starts_with(|c: char| c.is_ascii_digit()) {
                text.push_str(", Section ");
                text.push_str(section);
                if let Some(u) = url.as_mut() {
                    u.push_str("#section-");
                    u.push_str(section);
                }
            } else if !section.is_empty() {
                text.push_str(", ");
                text.push_str(section);
            }
        }
        SpecRef { text, url }
    }

    /// How the xref reads when inlined in a description.
    fn inline_text(&self) -> String {
        self.spec_ref("")
            .map_or_else(|| self.data.clone(), |r| r.text)
    }
}

/// A direct child element of a `<record>` being collected.
#[derive(Debug, Default)]
struct Field {
    name: String,
    text: String,
    /// Set when the field itself is an `<xref>` (a reference of the record).
    xref: Option<Xref>,
    /// An `<xref>` nested in the field, with the text length at its start.
    nested_xref: Option<(Xref, usize)>,
}

/// One `<record>`: its fields (flattened text) and references.
#[derive(Debug, Default)]
struct Record {
    fields: Vec<(String, String)>,
    reference: Vec<SpecRef>,
    current: Option<Field>,
}

impl Record {
    /// The flattened, non-empty text of the first field called `name`.
    fn field(&self, name: &str) -> Option<String> {
        self.fields
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, t)| collapse_whitespace(t))
            .filter(|t| !t.is_empty())
    }
}

// Element depths: 1 root `<registry>`, 2 `<updated>` / sub-`<registry>`,
// 3 `<record>`, 4 record fields, 5 markup inside a field.
const ROOT: usize = 1;
const SUB: usize = 2;
const RECORD: usize = 3;
const FIELD: usize = 4;
const IN_FIELD: usize = 5;

/// Streaming parser state.
struct Doc {
    which: RegistryId,
    /// Number of open elements.
    depth: usize,
    root_closed: bool,
    sub: Option<EntryKind>,
    in_updated: bool,
    updated: Option<String>,
    record: Option<Record>,
    entries: Vec<Entry>,
    seen: HashSet<Identity>,
}

impl Doc {
    fn new(which: RegistryId) -> Self {
        Self {
            which,
            depth: 0,
            root_closed: false,
            sub: None,
            in_updated: false,
            updated: None,
            record: None,
            entries: Vec::new(),
            seen: HashSet::new(),
        }
    }

    fn err(&self, message: impl Into<String>) -> RegistryError {
        RegistryError::Xml {
            registry: self.which,
            message: message.into(),
        }
    }

    fn start(&mut self, s: &BytesStart<'_>) -> Result<(), RegistryError> {
        let name = s.local_name().into_inner();
        self.depth += 1;
        match self.depth {
            ROOT => {
                if self.root_closed {
                    return Err(self.err("content after the root element"));
                }
                if name != "registry" {
                    return Err(self.err(format!("root element is <{name}>, not <registry>")));
                }
                match self.id_attr(s)? {
                    Some(id) if id == self.which.xml_id() => {}
                    Some(id) => {
                        return Err(RegistryError::WrongRegistry {
                            expected: self.which,
                            found: id,
                        });
                    }
                    None => return Err(self.err("root <registry> has no id")),
                }
            }
            SUB => match name {
                "registry" => {
                    self.sub = self
                        .id_attr(s)?
                        .and_then(|id| sub_registry_kind(self.which, &id));
                }
                "updated" => self.in_updated = true,
                _ => {}
            },
            RECORD => {
                if self.sub.is_some() && name == "record" {
                    self.record = Some(Record::default());
                }
            }
            FIELD if self.record.is_some() => {
                let xref = if name == "xref" {
                    Some(Xref::from_start(s).map_err(|m| self.err_at(m))?)
                } else {
                    None
                };
                if let Some(rec) = self.record.as_mut() {
                    rec.current = Some(Field {
                        name: name.to_owned(),
                        xref,
                        ..Field::default()
                    });
                }
            }
            IN_FIELD
                if name == "xref" && self.record.as_ref().is_some_and(|r| r.current.is_some()) =>
            {
                let xref = Xref::from_start(s).map_err(|m| self.err_at(m))?;
                if let Some(field) = self.record.as_mut().and_then(|r| r.current.as_mut()) {
                    field.nested_xref = Some((xref, field.text.len()));
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn err_at(&self, message: String) -> RegistryError {
        self.err(format!("bad attribute: {message}"))
    }

    fn id_attr(&self, s: &BytesStart<'_>) -> Result<Option<String>, RegistryError> {
        match s.try_get_attribute("id") {
            Ok(Some(a)) => a
                .normalized_value(XmlVersion::Implicit1_0)
                .map(|v| Some(v.into_owned()))
                .map_err(|e| self.err_at(e.to_string())),
            Ok(None) => Ok(None),
            Err(e) => Err(self.err_at(e.to_string())),
        }
    }

    fn end(&mut self) -> Result<(), RegistryError> {
        match self.depth {
            0 => return Err(self.err("unmatched end tag")),
            ROOT => self.root_closed = true,
            SUB => {
                self.sub = None;
                self.in_updated = false;
            }
            RECORD => {
                if let (Some(rec), Some(kind)) = (self.record.take(), self.sub) {
                    self.push_record(kind, &rec);
                }
            }
            FIELD => {
                if let Some(rec) = self.record.as_mut()
                    && let Some(field) = rec.current.take()
                {
                    match field.xref {
                        Some(x) => {
                            if let Some(r) = x.spec_ref(&collapse_whitespace(&field.text)) {
                                rec.reference.push(r);
                            }
                        }
                        None => rec.fields.push((field.name, field.text)),
                    }
                }
            }
            IN_FIELD => {
                if let Some(field) = self.record.as_mut().and_then(|r| r.current.as_mut())
                    && let Some((xref, len)) = field.nested_xref.take()
                    && field.text.len() == len
                {
                    // An empty inline xref reads as what it points to.
                    field.text.push_str(&xref.inline_text());
                }
            }
            _ => {}
        }
        self.depth -= 1;
        Ok(())
    }

    fn text(&mut self, text: &str) -> Result<(), RegistryError> {
        if self.depth == 0 {
            if text.trim().is_empty() {
                return Ok(());
            }
            return Err(self.err("text outside the root element"));
        }
        if self.in_updated && self.depth == SUB {
            self.updated
                .get_or_insert_with(String::new)
                .push_str(text.trim());
        } else if let Some(field) = self.record.as_mut().and_then(|r| r.current.as_mut()) {
            field.text.push_str(text);
        }
        Ok(())
    }

    fn finish(self) -> Result<ParsedRegistry, RegistryError> {
        if self.depth > 0 {
            return Err(self.err(format!(
                "unexpected end of document: {} unclosed element(s)",
                self.depth
            )));
        }
        if !self.root_closed {
            return Err(self.err("no <registry> root element"));
        }
        Ok(ParsedRegistry {
            which: self.which,
            updated: self.updated.filter(|u| !u.is_empty()),
            entries: self.entries,
        })
    }

    /// Converts a record and appends it, unless it is a placeholder, a range,
    /// or a duplicate (the first record with an identity wins).
    fn push_record(&mut self, kind: EntryKind, rec: &Record) {
        if let Some(entry) = record_to_entry(kind, rec)
            && self.seen.insert(identity(&entry))
        {
            self.entries.push(entry);
        }
    }
}

/// Field names per kind: (name, label, value type). For JOSE/JWT kinds the
/// `value` column is both the label and the name.
fn columns(kind: EntryKind) -> (&'static str, &'static str, Option<&'static str>) {
    use EntryKind::*;
    match kind {
        CoseHeader | CoseHeaderAlgParam => ("name", "label", Some("value")),
        CoseAlg | CoseKty | CoseCrv => ("name", "value", None),
        CoseKeyParam | CoseKeyTypeParam => ("name", "label", Some("cbor-type")),
        CwtClaim => ("claim", "key", Some("value")),
        CwtCnfMethod => ("confirmation", "key", Some("value")),
        JoseHeader | JoseAlg | JwkKty | JwkCrv | JwkParam | JwtClaim | JwtCnfMethod | CborTag
        | CborSimple => ("value", "value", None),
    }
}

fn is_text_kind(kind: EntryKind) -> bool {
    use EntryKind::*;
    matches!(
        kind,
        JoseHeader | JoseAlg | JwkKty | JwkCrv | JwkParam | JwtClaim | JwtCnfMethod
    )
}

fn record_to_entry(kind: EntryKind, rec: &Record) -> Option<Entry> {
    let (name_col, label_col, type_col) = columns(kind);
    let raw_name = rec.field(name_col)?;
    if ["Unassigned", "Reserved", "delegated"]
        .iter()
        .any(|p| raw_name.starts_with(p))
    {
        return None;
    }
    let (name, temporary) = strip_parenthetical(&raw_name);
    let label = if is_text_kind(kind) {
        Label::Text(name.clone())
    } else {
        Label::Int(rec.field(label_col)?.parse().ok()?)
    };
    let key_type = match kind {
        EntryKind::CoseKeyTypeParam => Some(Label::Int(rec.field("keytype")?.parse().ok()?)),
        EntryKind::JwkParam => rec.field("usage").map(Label::Text),
        _ => None,
    };
    let jwt_name = match kind {
        EntryKind::CwtClaim | EntryKind::CwtCnfMethod => rec.field("jwt").filter(|j| j != "N/A"),
        _ => None,
    };
    Some(Entry {
        kind,
        label,
        name,
        description: rec.field("description").unwrap_or_default(),
        value_type: type_col.and_then(|c| rec.field(c)),
        reference: rec.reference.clone(),
        source: Source::Iana,
        temporary,
        key_type,
        jwt_name,
    })
}

/// `typ (type)` → (`typ`, false); `sd_claims (TEMPORARY - …)` → (`sd_claims`, true).
fn strip_parenthetical(name: &str) -> (String, bool) {
    if let Some((base, inner)) = name
        .strip_suffix(')')
        .and_then(|n| n.rsplit_once(" ("))
        .filter(|(base, _)| !base.trim().is_empty())
    {
        return (base.trim().to_owned(), inner.starts_with("TEMPORARY"));
    }
    (name.to_owned(), false)
}

fn collapse_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for word in s.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    out
}

/// The contents of `data/local-additions.json`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalAdditions {
    /// The SD-CWT draft revision the codepoints come from, e.g.
    /// `draft-ietf-spice-sd-cwt-08`.
    pub sd_cwt_revision: String,
    /// Entries, all with [`crate::Source::Local`].
    pub entries: Vec<Entry>,
}

#[derive(Deserialize)]
struct LocalAdditionsRepr {
    sd_cwt_revision: String,
    entries: Vec<Entry>,
}

impl LocalAdditions {
    /// The local-additions file shipped with this crate.
    pub const BUNDLED: &'static str = include_str!("../data/local-additions.json");

    /// Parses a local-additions document: a JSON object with
    /// `sd_cwt_revision` and `entries` (see [`Entry`] for the entry form).
    /// Every entry gets [`Source::Local`].
    pub fn parse(text: &str) -> Result<Self, RegistryError> {
        let repr: LocalAdditionsRepr =
            serde_json::from_str(text).map_err(|e| RegistryError::LocalAdditions(e.to_string()))?;
        let entries = repr
            .entries
            .into_iter()
            .map(|e| Entry {
                source: Source::Local,
                ..e
            })
            .collect();
        Ok(Self {
            sd_cwt_revision: repr.sd_cwt_revision,
            entries,
        })
    }

    /// Parses [`Self::BUNDLED`].
    pub fn bundled() -> Result<Self, RegistryError> {
        Self::parse(Self::BUNDLED)
    }
}
