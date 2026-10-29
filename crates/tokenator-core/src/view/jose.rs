//! The JOSE view object: one JSON document showing every part, decoded
//! parts embedded verbatim (TEST-PLAN §3), plus the segment raw pane and
//! the SD view.

use base64ct::{Base64UrlUnpadded, Encoding};
use tokenator_crypto::HashAlg;
use tokenator_jose as tj;
use tokenator_json::{Node as JNode, ParseOptions, PrintStyle};

use crate::annotate::Notes;
use crate::dto::common::{ByteRange, NodeId, RawRange};
use crate::dto::detect::Kind;
use crate::dto::document::{
    Diagnostic, DisclosureInfo, DisclosureStatus, JsonLayout, Layout, Node, NodeKind, SdMark,
    Segment, Severity, SlotInfo, ViewOptions,
};
use crate::dto::error::{EngineError, ErrorCode};
use crate::util::{TextIndex, json_string, u32_of};
use crate::view::json::{JRole, JsonWalk};

/// Which part of a token a [`PartLoc`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PartWhich {
    Protected(usize),
    Unprotected(usize),
    Payload,
    Signature(usize),
    Disclosure(usize),
    KbProtected,
    KbPayload,
    KbSignature,
}

/// Where a part is in the token and in the main text.
#[derive(Clone, Debug)]
pub(crate) struct PartLoc {
    pub(crate) which: PartWhich,
    pub(crate) id: NodeId,
    /// The base64url text (or unprotected header JSON) in the token.
    pub(crate) source: Option<(usize, usize)>,
    /// The value's byte range in the main text.
    pub(crate) value: (usize, usize),
    /// Shown as decoded JSON (else as a string, or verbatim JSON for an
    /// unprotected header).
    pub(crate) decoded: bool,
    /// The original encoded text (or header JSON).
    pub(crate) text: String,
}

/// A rendered JOSE token.
pub(crate) struct JoseView {
    pub(crate) kind: Kind,
    pub(crate) tree: Node,
    pub(crate) text: String,
    pub(crate) segments: Vec<Segment>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) disclosures: Vec<DisclosureInfo>,
    pub(crate) undisclosed: Vec<SlotInfo>,
    pub(crate) parts: Vec<PartLoc>,
    /// `(start, end, id)` of node byte spans in the main text.
    pub(crate) index: Vec<(usize, usize, NodeId)>,
}

enum Content {
    /// Decoded JSON text, shown as is (or re-indented).
    Json(String),
    /// A JSON string (the base64url text).
    Str(String),
    /// JSON from the envelope, verbatim (unprotected headers).
    Raw(String),
}

struct PartSpec {
    loc: PartLoc,
    content: Content,
    role: JRole,
    label: &'static str,
}

enum Spec {
    Part(usize),
    Obj(Vec<(&'static str, Spec)>),
    Arr(Vec<Spec>),
}

/// Parses token text, reading text without any `.` or `~` as a compact JWS
/// with one segment (a truncated token stays readable).
pub(crate) fn with_parsed<R>(
    text: &str,
    f: impl FnOnce(&tj::Parsed<'_>, bool) -> R,
) -> Result<R, tj::ParseError> {
    let trimmed = text.trim_matches([' ', '\t', '\n', '\r']);
    if !trimmed.is_empty() && !trimmed.starts_with('{') && !trimmed.contains(['.', '~']) {
        let padded = format!("{text}..");
        let parsed = tj::parse(&padded)?;
        return Ok(f(&parsed, true));
    }
    let parsed = tj::parse(text)?;
    Ok(f(&parsed, false))
}

/// The kind a parsed token has.
pub(crate) fn kind_of(token: &tj::Token<'_>) -> Kind {
    let jws = token.jws();
    let general = jws.serialization == tj::Serialization::JsonGeneral;
    let compact = jws.serialization == tj::Serialization::Compact;
    match token {
        tj::Token::Jws(j) if compact => {
            let object = j.claims().is_ok_and(|c| c.members().is_some());
            if object { Kind::Jwt } else { Kind::JwsCompact }
        }
        tj::Token::Jws(_) => Kind::JwsJson { general },
        tj::Token::SdJwt(sd) if compact => Kind::SdJwt {
            kb: sd.kb_jwt.is_some(),
        },
        tj::Token::SdJwt(sd) => Kind::SdJwtJson {
            general,
            kb: sd.kb_jwt.is_some(),
        },
    }
}

/// `kind` unless the token's structure says otherwise (JWT vs JWS compact
/// is kept as requested: a tampered payload stays a JWT).
pub(crate) fn settle_kind(requested: &Kind, found: Kind) -> Kind {
    match (requested, &found) {
        (Kind::Jwt | Kind::JwsCompact, Kind::Jwt | Kind::JwsCompact) => requested.clone(),
        _ => found,
    }
}

fn part_node_id(which: PartWhich, general: bool) -> NodeId {
    let root = NodeId::root();
    let sig = |n: usize, name: &str| {
        if general {
            root.child("signatures").index(n).child(name)
        } else {
            root.child(name)
        }
    };
    match which {
        PartWhich::Protected(n) => sig(n, "protected"),
        PartWhich::Unprotected(n) => sig(n, "unprotected"),
        PartWhich::Payload => root.child("payload"),
        PartWhich::Signature(n) => sig(n, "signature"),
        PartWhich::Disclosure(n) => root.child("disclosures").index(n),
        PartWhich::KbProtected => root.child("kb").child("protected"),
        PartWhich::KbPayload => root.child("kb").child("payload"),
        PartWhich::KbSignature => root.child("kb").child("signature"),
    }
}

/// The node of a `tokenator-jose` part.
pub(crate) fn part_ref_id(part: tj::PartRef, general: bool) -> NodeId {
    match part {
        tj::PartRef::Envelope => NodeId::root(),
        tj::PartRef::ProtectedHeader(n) => part_node_id(PartWhich::Protected(n), general),
        tj::PartRef::UnprotectedHeader(n) => part_node_id(PartWhich::Unprotected(n), general),
        tj::PartRef::Payload => part_node_id(PartWhich::Payload, general),
        tj::PartRef::Signature(n) => part_node_id(PartWhich::Signature(n), general),
        tj::PartRef::Disclosure(n) => part_node_id(PartWhich::Disclosure(n), general),
        tj::PartRef::KbJwt => NodeId::root().child("kb"),
        tj::PartRef::KbProtectedHeader => part_node_id(PartWhich::KbProtected, general),
        tj::PartRef::KbPayload => part_node_id(PartWhich::KbPayload, general),
        tj::PartRef::KbSignature => part_node_id(PartWhich::KbSignature, general),
    }
}

fn diag_code(kind: &tj::DiagnosticKind) -> &'static str {
    match kind {
        tj::DiagnosticKind::Base64(_) => "jose.base64",
        tj::DiagnosticKind::Json(_) => "jose.not_json",
        tj::DiagnosticKind::NotAnObject => "jose.not_object",
        tj::DiagnosticKind::Disclosure(_) => "jose.disclosure",
        tj::DiagnosticKind::SegmentCount { .. } => "jose.segment_count",
        tj::DiagnosticKind::EmptyDisclosure => "jose.empty_disclosure",
        tj::DiagnosticKind::MissingMember(_) => "jose.missing_member",
        tj::DiagnosticKind::WrongType(_) => "jose.wrong_type",
        tj::DiagnosticKind::MixedSerialization => "jose.mixed_serialization",
        tj::DiagnosticKind::MisplacedSdMember(_) => "jose.misplaced_sd_member",
        _ => "jose.diagnostic",
    }
}

/// How a decoded part is shown: verbatim JSON when it is UTF-8 JSON.
fn content_of(part: &tj::B64Part<'_>, view: &ViewOptions) -> Content {
    let json = part
        .decoded()
        .ok()
        .and_then(|b| std::str::from_utf8(b).ok())
        .filter(|t| tokenator_json::parse(t.as_bytes()).is_ok());
    match json {
        Some(t) if view.json_layout == JsonLayout::Pretty => {
            match tokenator_json::parse(t.as_bytes()) {
                Ok(node) => Content::Json(tokenator_json::print(&node, PrintStyle::Pretty)),
                Err(_) => Content::Json(t.to_owned()),
            }
        }
        Some(t) => Content::Json(t.to_owned()),
        None => Content::Str(part.text().to_owned()),
    }
}

fn span_pair(s: tj::Span) -> (usize, usize) {
    (s.start, s.end)
}

struct Builder<'v> {
    parts: Vec<PartSpec>,
    view: &'v ViewOptions,
    general: bool,
}

impl Builder<'_> {
    fn b64(
        &mut self,
        which: PartWhich,
        part: &tj::B64Part<'_>,
        role: JRole,
        label: &'static str,
    ) -> Spec {
        let content = if matches!(which, PartWhich::Signature(_) | PartWhich::KbSignature) {
            Content::Str(part.text().to_owned())
        } else {
            content_of(part, self.view)
        };
        self.push(
            which,
            Some(span_pair(part.span())),
            content,
            role,
            label,
            part.text().to_owned(),
        )
    }

    fn push(
        &mut self,
        which: PartWhich,
        source: Option<(usize, usize)>,
        content: Content,
        role: JRole,
        label: &'static str,
        text: String,
    ) -> Spec {
        let decoded = matches!(content, Content::Json(_));
        self.parts.push(PartSpec {
            loc: PartLoc {
                which,
                id: part_node_id(which, self.general),
                source,
                value: (0, 0),
                decoded,
                text,
            },
            content,
            role,
            label,
        });
        Spec::Part(self.parts.len() - 1)
    }

    fn signature(
        &mut self,
        i: usize,
        sig: &tj::JwsSignature<'_>,
        members: &mut Vec<(&'static str, Spec)>,
    ) {
        if let Some(p) = &sig.protected {
            let s = self.b64(
                PartWhich::Protected(i),
                p,
                JRole::Header,
                "Protected header",
            );
            members.push(("protected", s));
        }
        if let Some(h) = &sig.unprotected {
            let raw = h.raw().unwrap_or("{}").to_owned();
            let s = self.push(
                PartWhich::Unprotected(i),
                h.span().map(span_pair),
                Content::Raw(raw.clone()),
                JRole::Header,
                "Unprotected header",
                raw,
            );
            members.push(("unprotected", s));
        }
    }

    fn token(&mut self, token: &tj::Token<'_>) -> Spec {
        let jws = token.jws();
        let mut root: Vec<(&'static str, Spec)> = Vec::new();
        if self.general {
            let payload = self.b64(PartWhich::Payload, &jws.payload, JRole::Claims, "Payload");
            root.push(("payload", payload));
            let mut sigs = Vec::new();
            for (i, sig) in jws.signatures.iter().enumerate() {
                let mut members = Vec::new();
                self.signature(i, sig, &mut members);
                let s = self.b64(
                    PartWhich::Signature(i),
                    &sig.signature,
                    JRole::Plain,
                    "Signature",
                );
                members.push(("signature", s));
                sigs.push(Spec::Obj(members));
            }
            root.push(("signatures", Spec::Arr(sigs)));
        } else if let Some(sig) = jws.signatures.first() {
            self.signature(0, sig, &mut root);
            let payload = self.b64(PartWhich::Payload, &jws.payload, JRole::Claims, "Payload");
            root.push(("payload", payload));
            let s = self.b64(
                PartWhich::Signature(0),
                &sig.signature,
                JRole::Plain,
                "Signature",
            );
            root.push(("signature", s));
        }
        if let Some(sd) = token.sd_jwt() {
            let ds = sd
                .disclosures
                .iter()
                .enumerate()
                .map(|(i, d)| {
                    self.b64(
                        PartWhich::Disclosure(i),
                        d.part(),
                        JRole::Plain,
                        "Disclosure",
                    )
                })
                .collect();
            root.push(("disclosures", Spec::Arr(ds)));
            if let Some(kb) = &sd.kb_jwt {
                let mut members = Vec::new();
                if let Some(p) = kb.signatures.first().and_then(|s| s.protected.as_ref()) {
                    members.push((
                        "protected",
                        self.b64(PartWhich::KbProtected, p, JRole::Header, "KB-JWT header"),
                    ));
                }
                members.push((
                    "payload",
                    self.b64(
                        PartWhich::KbPayload,
                        &kb.payload,
                        JRole::Plain,
                        "KB-JWT payload",
                    ),
                ));
                if let Some(s) = kb.signatures.first() {
                    members.push((
                        "signature",
                        self.b64(
                            PartWhich::KbSignature,
                            &s.signature,
                            JRole::Plain,
                            "KB-JWT signature",
                        ),
                    ));
                }
                root.push(("kb", Spec::Obj(members)));
            }
        }
        Spec::Obj(root)
    }
}

struct Emitter<'a> {
    out: String,
    parts: &'a mut [PartSpec],
    compact: bool,
    /// Re-indent decoded JSON (`JsonLayout::Pretty`); otherwise verbatim.
    pretty: bool,
    unit: usize,
}

impl Emitter<'_> {
    fn newline(&mut self, depth: usize) {
        if !self.compact {
            self.out.push('\n');
            self.out.push_str(&" ".repeat(depth * self.unit));
        }
    }

    fn emit(&mut self, spec: &Spec, depth: usize) {
        match spec {
            Spec::Part(i) => {
                let start = self.out.len();
                let pad = " ".repeat(depth * self.unit);
                if let Some(p) = self.parts.get(*i) {
                    let text = match &p.content {
                        Content::Json(t) if self.pretty => t.replace('\n', &format!("\n{pad}")),
                        Content::Json(t) | Content::Raw(t) => t.clone(),
                        Content::Str(s) => json_string(s),
                    };
                    self.out.push_str(&text);
                }
                let end = self.out.len();
                if let Some(p) = self.parts.get_mut(*i) {
                    p.loc.value = (start, end);
                }
            }
            Spec::Obj(members) => {
                self.out.push('{');
                for (k, (name, sub)) in members.iter().enumerate() {
                    if k > 0 {
                        self.out.push(',');
                        if self.compact {
                            self.out.push(' ');
                        }
                    }
                    self.newline(depth + 1);
                    self.out.push_str(&json_string(name));
                    self.out.push_str(": ");
                    self.emit(sub, depth + 1);
                }
                if !members.is_empty() {
                    self.newline(depth);
                }
                self.out.push('}');
            }
            Spec::Arr(items) => {
                self.out.push('[');
                for (k, sub) in items.iter().enumerate() {
                    if k > 0 {
                        self.out.push(',');
                        if self.compact {
                            self.out.push(' ');
                        }
                    }
                    self.newline(depth + 1);
                    self.emit(sub, depth + 1);
                }
                if !items.is_empty() {
                    self.newline(depth);
                }
                self.out.push(']');
            }
        }
    }
}

/// Renders token text as the view object.
pub(crate) fn build(
    text: &str,
    requested: &Kind,
    notes: Notes<'_>,
    view: &ViewOptions,
) -> Result<JoseView, EngineError> {
    with_parsed(text, |parsed, padded| {
        build_parsed(text, parsed, padded, requested, notes, view)
    })
    .map_err(|e| EngineError::new(ErrorCode::Parse, format!("not a JOSE token: {e}")))?
}

#[allow(clippy::too_many_lines)]
fn build_parsed(
    text: &str,
    parsed: &tj::Parsed<'_>,
    padded: bool,
    requested: &Kind,
    notes: Notes<'_>,
    view: &ViewOptions,
) -> Result<JoseView, EngineError> {
    let token = &parsed.token;
    let general = token.jws().serialization == tj::Serialization::JsonGeneral;
    let mut b = Builder {
        parts: Vec::new(),
        view,
        general,
    };
    let spec = b.token(token);
    let mut parts = b.parts;
    // In a padded (one-segment) token only the header exists.
    if padded {
        for p in &mut parts {
            if p.loc.source.is_some_and(|(s, _)| s >= text.len()) {
                p.loc.source = None;
            }
        }
    }
    let pretty = view.json_layout == JsonLayout::Pretty;
    let mut em = Emitter {
        out: String::new(),
        parts: &mut parts,
        compact: view.layout == Layout::Compact,
        pretty,
        unit: usize::try_from(view.indent).unwrap_or(2),
    };
    em.emit(&spec, 0);
    let main = em.out;
    let parsed_view =
        tokenator_json::parse_with_options(main.as_bytes(), &ParseOptions { max_depth: 1024 })
            .map_err(|e| EngineError::new(ErrorCode::Parse, format!("cannot show the token: {e}")))?
            .node;

    // Segments: every part with base64url text in the token, in display order.
    let mut segments = Vec::new();
    let mut seg_of = vec![None; parts.len()];
    for (i, p) in parts.iter().enumerate() {
        if matches!(p.loc.which, PartWhich::Unprotected(_)) {
            continue;
        }
        let Some((s, e)) = p.loc.source else { continue };
        let Some(seg_text) = text.get(s..e) else {
            continue;
        };
        if let Some(slot) = seg_of.get_mut(i) {
            *slot = Some(segments.len());
        }
        let separator = match p.loc.which {
            PartWhich::Protected(_)
            | PartWhich::Payload
            | PartWhich::KbProtected
            | PartWhich::KbPayload => Some("."),
            PartWhich::Signature(_) | PartWhich::Disclosure(_) if token.sd_jwt().is_some() => {
                Some("~")
            }
            _ => None,
        };
        segments.push(crate::dto::document::Segment {
            node_id: p.loc.id.clone(),
            label: match p.loc.which {
                PartWhich::Disclosure(n) => format!("Disclosure {n}"),
                PartWhich::Signature(n) if general => format!("Signature {n}"),
                PartWhich::Protected(n) if general => format!("Protected header {n}"),
                _ => p.label.to_owned(),
            },
            range: ByteRange {
                start: u32_of(s),
                end: u32_of(e),
            },
            text: seg_text.to_owned(),
            separator: separator.map(str::to_owned),
        });
    }

    let index = TextIndex::new(&main);
    let locs: Vec<(PartLoc, Option<usize>)> = parts
        .iter()
        .zip(&seg_of)
        .map(|(p, s)| (p.loc.clone(), *s))
        .collect();
    let raw_of = |s: usize, e: usize| -> Option<RawRange> {
        let (loc, seg) = locs
            .iter()
            .find(|(l, seg)| seg.is_some() && l.decoded && l.value.0 <= s && e <= l.value.1)?;
        let seg = (*seg)?;
        let (src_s, src_e) = loc.source?;
        let len = src_e - src_s;
        let (start, end) = if pretty {
            (src_s, src_e)
        } else {
            let (a, b) = (s - loc.value.0, e - loc.value.0);
            (src_s + 4 * (a / 3), src_s + (4 * b.div_ceil(3)).min(len))
        };
        Some(RawRange {
            start: u32_of(start),
            end: u32_of(end),
            row_start: u32_of(seg),
            row_end: u32_of(seg + 1),
        })
    };
    let mut walk = JsonWalk {
        notes,
        now: view.now,
        text: &index,
        raw: &raw_of,
        index: Vec::new(),
    };
    let mut tree = assemble(
        &spec,
        &parsed_view,
        NodeId::root(),
        String::new(),
        &parts,
        &seg_of,
        &mut walk,
        view,
    );
    tree.kind = NodeKind::Document;
    let mut idx = walk.index;
    union_raw(&mut tree);

    let mut diagnostics: Vec<Diagnostic> = parsed
        .diagnostics
        .iter()
        .map(|d| Diagnostic {
            severity: Severity::Warning,
            code: diag_code(&d.kind).to_owned(),
            message: format!("{:?}", d.kind),
            node_id: Some(part_ref_id(d.part, general)),
            main: None,
            raw: d.span.map(|s| ByteRange {
                start: u32_of(s.start.min(text.len())),
                end: u32_of(s.end.min(text.len())),
            }),
        })
        .collect();
    if padded {
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            code: "jose.segment_count".to_owned(),
            message: "1 segment instead of 3".to_owned(),
            node_id: Some(NodeId::root()),
            main: None,
            raw: None,
        });
    }

    let (disclosures, undisclosed) = match token.sd_jwt() {
        Some(sd) => sd_view(sd, &mut tree),
        None => (Vec::new(), Vec::new()),
    };
    idx.sort_by_key(|(s, e, _)| (*s, std::cmp::Reverse(*e)));
    Ok(JoseView {
        kind: settle_kind(requested, kind_of(token)),
        tree,
        text: main,
        segments,
        diagnostics,
        disclosures,
        undisclosed,
        parts: parts.into_iter().map(|p| p.loc).collect(),
        index: idx,
    })
}

#[allow(clippy::too_many_arguments)]
fn assemble(
    spec: &Spec,
    jnode: &JNode<'_>,
    id: NodeId,
    label: String,
    parts: &[PartSpec],
    seg_of: &[Option<usize>],
    walk: &mut JsonWalk<'_>,
    view: &ViewOptions,
) -> Node {
    let main = jnode.span().map(|s| walk.text.range(s.start..s.end));
    if let Some(s) = jnode.span() {
        walk.index.push((s.start, s.end, id.clone()));
    }
    let mut n = Node {
        id,
        kind: NodeKind::Part,
        label,
        annotation: None,
        main,
        raw: None,
        key: None,
        time: None,
        sd: None,
        children: Vec::new(),
    };
    match spec {
        Spec::Obj(members) => {
            let values: Vec<&JNode<'_>> = jnode
                .members()
                .unwrap_or_default()
                .iter()
                .map(|m| m.value())
                .collect();
            for ((name, sub), v) in members.iter().zip(values) {
                let c = assemble(
                    sub,
                    v,
                    n.id.child(name),
                    (*name).to_owned(),
                    parts,
                    seg_of,
                    walk,
                    view,
                );
                n.children.push(c);
            }
        }
        Spec::Arr(items) => {
            n.kind = NodeKind::Array;
            for (i, (sub, v)) in items
                .iter()
                .zip(jnode.elements().unwrap_or_default())
                .enumerate()
            {
                let c = assemble(
                    sub,
                    v,
                    n.id.index(i),
                    i.to_string(),
                    parts,
                    seg_of,
                    walk,
                    view,
                );
                n.children.push(c);
            }
        }
        Spec::Part(i) => {
            let (Some(p), seg) = (parts.get(*i), seg_of.get(*i).copied().flatten()) else {
                return n;
            };
            n.raw = match (p.loc.source, seg) {
                (Some((s, e)), Some(seg)) => Some(RawRange {
                    start: u32_of(s),
                    end: u32_of(e),
                    row_start: u32_of(seg),
                    row_end: u32_of(seg + 1),
                }),
                _ => None,
            };
            match &p.content {
                Content::Raw(_) if matches!(p.loc.which, PartWhich::Unprotected(_)) => {
                    let t = walk.tree(jnode, n.id.clone(), n.label.clone(), JRole::Header);
                    n.children = t.children;
                }
                Content::Raw(_) => {}
                Content::Json(_) => {
                    let show = !view.hide_decoded.contains(&n.id) && view.decoded_views;
                    if show {
                        let mut d = walk.tree(jnode, n.id.decoded(0), "decoded".to_owned(), p.role);
                        d.kind = NodeKind::Decoded;
                        n.children.push(d);
                    }
                }
                Content::Str(_) => {}
            }
        }
    }
    n
}

/// Container nodes get the union of their children's raw ranges.
fn union_raw(n: &mut Node) -> Option<RawRange> {
    let mut acc: Option<RawRange> = None;
    for c in &mut n.children {
        if let Some(r) = union_raw(c) {
            acc = Some(match acc {
                None => r,
                Some(a) => RawRange {
                    start: a.start.min(r.start),
                    end: a.end.max(r.end),
                    row_start: a.row_start.min(r.row_start),
                    row_end: a.row_end.max(r.row_end),
                },
            });
        }
    }
    if n.raw.is_none() && n.kind != NodeKind::Decoded {
        n.raw = acc;
    }
    n.raw.or(acc)
}

/// The NodeId of a digest slot.
fn slot_id(slot: &tj::DigestSlot) -> NodeId {
    let base = match slot.container {
        tj::Container::Payload => NodeId::root().child("payload").decoded(0),
        tj::Container::Disclosure(n) => NodeId::root().child("disclosures").index(n).decoded(0),
    };
    if slot.pointer.is_empty() {
        base
    } else {
        base.push_raw(slot.pointer.trim_start_matches('/'))
    }
}

/// Disclosure infos and SD marks.
fn sd_view(sd: &tj::SdJwt<'_>, tree: &mut Node) -> (Vec<DisclosureInfo>, Vec<SlotInfo>) {
    let report = match sd.process() {
        Ok(p) => p.report,
        Err(_) => tj::SdReport {
            sd_alg: tj::SdAlg::Default,
            digests: Vec::new(),
            disclosures: Vec::new(),
            findings: Vec::new(),
        },
    };
    let mut status = vec![None; sd.disclosures.len()];
    let mut set = |i: usize, s: DisclosureStatus| {
        if let Some(slot) = status.get_mut(i)
            && slot.is_none()
        {
            *slot = Some(s);
        }
    };
    for f in &report.findings {
        match f {
            tj::SdFinding::MalformedDisclosure { disclosure, .. } => {
                set(*disclosure, DisclosureStatus::Malformed)
            }
            tj::SdFinding::ForbiddenName { disclosure, .. } => {
                set(*disclosure, DisclosureStatus::ForbiddenName)
            }
            tj::SdFinding::KindMismatch { disclosure, .. } => {
                set(*disclosure, DisclosureStatus::KindMismatch)
            }
            tj::SdFinding::NameCollision { disclosure, .. } => {
                set(*disclosure, DisclosureStatus::NameCollision)
            }
            _ => {}
        }
    }
    for f in &report.findings {
        match f {
            tj::SdFinding::DuplicateDisclosure { disclosures } => {
                for d in disclosures.iter().skip(1) {
                    set(*d, DisclosureStatus::Duplicate);
                }
            }
            tj::SdFinding::UnmatchedDisclosure { disclosure } => {
                set(*disclosure, DisclosureStatus::Unmatched)
            }
            _ => {}
        }
    }
    let mut marks: Vec<(NodeId, SdMark)> = Vec::new();
    for slot in &report.digests {
        marks.push((
            slot_id(slot),
            SdMark::Slot {
                digest: slot.digest.clone(),
                disclosure: slot.disclosure.map(u32_of),
            },
        ));
    }
    let mut infos = Vec::with_capacity(sd.disclosures.len());
    for (i, d) in sd.disclosures.iter().enumerate() {
        let m = report.disclosures.get(i);
        let digest = m
            .and_then(|m| m.digest.clone())
            .unwrap_or_else(|| d.digest(HashAlg::Sha256));
        let slot = m
            .and_then(|m| m.slot)
            .and_then(|s| report.digests.get(s))
            .filter(|s| s.disclosure == Some(i))
            .map(slot_id);
        let (salt, claim, value) = match d.view() {
            Ok(v) => (
                v.salt().to_owned(),
                v.name().map(str::to_owned),
                tokenator_json::print(v.value(), PrintStyle::Compact),
            ),
            Err(_) => (String::new(), None, String::new()),
        };
        let st = status
            .get(i)
            .copied()
            .flatten()
            .unwrap_or(if slot.is_some() {
                DisclosureStatus::Matched
            } else {
                DisclosureStatus::Unmatched
            });
        let node_id = NodeId::root().child("disclosures").index(i);
        marks.push((node_id.clone(), SdMark::Disclosure { index: u32_of(i) }));
        infos.push(DisclosureInfo {
            index: u32_of(i),
            node_id,
            digest,
            salt,
            claim,
            value,
            decoy: false,
            status: st,
            slot,
        });
    }
    let undisclosed = report
        .findings
        .iter()
        .filter_map(|f| match f {
            tj::SdFinding::DigestWithoutDisclosure { slot } => report.digests.get(*slot),
            _ => None,
        })
        .map(|s| SlotInfo {
            node_id: slot_id(s),
            digest: s.digest.clone(),
            array_element: s.kind == tj::SlotKind::ArrayElement,
        })
        .collect();
    crate::view::apply_marks(tree, &marks, |n| {
        n.label == "_sd" && n.kind == NodeKind::Array
    });
    (infos, undisclosed)
}

/// Base64url text of decoded bytes.
pub(crate) fn b64u(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}
