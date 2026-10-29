//! The CBOR tree: NodeIds, kinds, annotations, decoded views, main-pane
//! ranges (from the EDN printer's span map), and hex rows.
//!
//! One walk over the decoded item decides everything that depends on the
//! format: which byte strings are decoded (only at defined locations,
//! #15), which keys are registered, and how paths become NodeIds. The EDN
//! printer and `annotated_hex` then get the same embedded paths and
//! comments, so the two panes line up row for row.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use tokenator_cbor::{Item, MAX_DEPTH, Value, Width};
use tokenator_edn::{
    Annotator, EmbeddedCbor, EmbeddedWarning, HexOptions, Path, PathSegment, PrintOptions, SpanMap,
};
use tokenator_registry::{Context, Family, Label};

use crate::annotate::Notes;
use crate::cbor::{
    abs_span, bstr_contents, compact_edn, exact_sequence, int_of, label_of, map_get,
};
use crate::datetime::cbor_hint;
use crate::dto::common::{ByteRange, NodeId, RawRange};
use crate::dto::document::{
    ByteStyle, Diagnostic, HexRow, HexRowKind, Layout, Node, NodeKind, Severity, ViewOptions,
};
use crate::util::{TextIndex, u32_of};

/// Where an item sits, as far as the format defines it.
#[derive(Clone, Debug)]
pub(crate) enum Role {
    /// No format meaning.
    Plain,
    /// A COSE_Sign1, maybe inside envelope tags (61, 18), which fold into
    /// this node.
    Sign1,
    /// A header map (protected or unprotected).
    Header(Context),
    /// A top-level claims map (CWT/KBT payload, claim set).
    Claims,
    /// A `cnf` map.
    Cnf,
    /// A COSE_Key map.
    Key,
    /// A COSE_KeySet array.
    KeySet,
    /// `sd_claims`: an array of disclosure byte strings.
    SdClaims,
    /// A byte string whose content is CBOR at a defined location; the first
    /// embedded item gets the inner role.
    Embedded(Box<Role>),
}

/// The result of a walk plus rendering.
pub(crate) struct CborView {
    /// The tree.
    pub(crate) tree: Node,
    /// The main pane text.
    pub(crate) text: String,
    /// Hex rows over the raw buffer.
    pub(crate) rows: Vec<HexRow>,
    /// Problems found while walking (manual decodes).
    pub(crate) diagnostics: Vec<Diagnostic>,
    /// `(start, end, id)` of every node with a raw range, in pre-order.
    pub(crate) index: Vec<(usize, usize, NodeId)>,
}

/// Comments by path, for the printer and the hex view.
struct Comments<'c>(&'c BTreeMap<Path, String>);

impl Annotator for Comments<'_> {
    fn comment(&self, path: &Path, _item: &Item<'_>) -> Option<Cow<'_, str>> {
        self.0.get(path).map(|s| Cow::Borrowed(s.as_str()))
    }
}

/// Decoded views nest at most this deep (an SD-KBT nests two levels).
const MAX_EMBEDDED: usize = 16;

/// One node to visit.
struct Task<'i, 'a> {
    item: &'i Item<'a>,
    path: Path,
    id: NodeId,
    label: String,
    /// The offset the item's spans are relative to.
    base: usize,
    role: Role,
    /// The arena index of the parent.
    parent: Option<usize>,
    /// This is the key node of the parent.
    is_key: bool,
    /// For a map value: its key, the key's path, and its label.
    key: Option<(&'i Item<'a>, Path, String)>,
    annotation: Option<crate::dto::document::Annotation>,
    time: Option<crate::dto::document::TimeHint>,
    /// A COSE_Sign1 part.
    part: bool,
    /// The span with envelope tags folded into this node.
    outer: Option<(usize, usize)>,
}

impl<'i, 'a> Task<'i, 'a> {
    fn new(
        item: &'i Item<'a>,
        path: Path,
        id: NodeId,
        label: String,
        base: usize,
        role: Role,
        parent: Option<usize>,
    ) -> Self {
        Task {
            item,
            path,
            id,
            label,
            base,
            role,
            parent,
            is_key: false,
            key: None,
            annotation: None,
            time: None,
            part: false,
            outer: None,
        }
    }
}

struct Walker<'v> {
    notes: Notes<'v>,
    view: &'v ViewOptions,
    /// For EDN claim sets: the user's own text decides what is embedded.
    edn_spans: Option<&'v SpanMap>,
    /// The whole raw buffer.
    bytes: &'v [u8],
    /// Every path to the node id it belongs to (rows).
    ids: BTreeMap<Path, NodeId>,
    /// The outermost path of each node (main ranges).
    primary: BTreeMap<NodeId, Path>,
    comments: BTreeMap<Path, String>,
    embedded: Vec<Path>,
    diagnostics: Vec<Diagnostic>,
    index: Vec<(usize, usize, NodeId)>,
    /// How many decoded views enclose the current walk.
    embedded_depth: usize,
}

fn kind_of(item: &Item<'_>) -> NodeKind {
    match item.value {
        Value::Uint(_) | Value::Nint(_) => NodeKind::Integer,
        Value::Bytes(_) => NodeKind::Bytes,
        Value::Text(_) => NodeKind::Text,
        Value::Array(_) => NodeKind::Array,
        Value::Map(_) => NodeKind::Map,
        Value::Tag(..) => NodeKind::Tag,
        Value::Bool(_) => NodeKind::Bool,
        Value::Null => NodeKind::Null,
        Value::Undefined => NodeKind::Undefined,
        Value::Simple(_) => NodeKind::Simple,
        Value::Float(..) => NodeKind::Float,
    }
}

fn leaf(id: NodeId, kind: NodeKind, label: String) -> Node {
    Node {
        id,
        kind,
        label,
        annotation: None,
        main: None,
        raw: None,
        key: None,
        time: None,
        sd: None,
        children: Vec::new(),
    }
}

/// The NodeId segment of map entry `i` with key `k` (TEST-PLAN §4).
fn key_segment(k: &Item<'_>, i: usize, seen: &mut BTreeSet<String>) -> (String, String) {
    let edn = compact_edn(k);
    let fallback = format!("~i{i}");
    if matches!(k.value, Value::Array(_) | Value::Map(_)) || edn.chars().count() > 64 {
        return (fallback, edn);
    }
    let seg = crate::dto::common::escape_segment(&edn);
    if seen.insert(seg.clone()) {
        (seg, edn)
    } else {
        (fallback, edn)
    }
}

fn registry_context(role: &Role, map: &Item<'_>) -> Option<Context> {
    match role {
        Role::Header(c) => Some(c.clone()),
        Role::Claims => Some(Context::Claims),
        Role::Cnf => Some(Context::Cnf),
        Role::Key => Some(Context::Key {
            kty: map_get(map, 1).and_then(int_of).map(Label::Int),
        }),
        _ => None,
    }
}

/// The role of the value of entry `key` in a map with `role`.
fn entry_role(role: &Role, key: &Item<'_>) -> Role {
    match (role, int_of(key)) {
        (Role::Header(Context::ProtectedHeader), Some(13)) => Role::Sign1,
        (Role::Header(Context::UnprotectedHeader), Some(17)) => Role::SdClaims,
        (Role::Claims, Some(8)) => Role::Cnf,
        (Role::Cnf, Some(1)) => Role::Key,
        _ => Role::Plain,
    }
}

const PARTS: [&str; 4] = ["protected", "unprotected", "payload", "signature"];

impl Walker<'_> {
    fn register(&mut self, path: &Path, id: &NodeId) {
        self.ids.insert(path.clone(), id.clone());
        self.primary
            .entry(id.clone())
            .or_insert_with(|| path.clone());
    }

    /// Walks the item of `root` and everything under it. CBOR nesting is
    /// handled with an explicit task stack (so deep items cost heap, not
    /// stack); only decoded views recurse, at most [`MAX_EMBEDDED`] deep.
    fn walk(&mut self, root: Task<'_, '_>) -> Node {
        let mut arena: Vec<Option<Node>> = Vec::new();
        let mut links: Vec<(Option<usize>, bool)> = Vec::new();
        let mut kids: Vec<Vec<Node>> = Vec::new();
        let mut tasks = vec![root];
        while let Some(t) = tasks.pop() {
            let item = t.item;
            if let (Role::Sign1, Value::Tag(18 | 61, inner)) = (&t.role, &item.value) {
                // Envelope tags fold into the token's node.
                self.register(&t.path, &t.id);
                let outer = t.outer.or_else(|| abs_span(item, t.base));
                tasks.push(Task {
                    item: inner,
                    path: t.path.child(PathSegment::TagContent),
                    outer,
                    ..t
                });
                continue;
            }
            self.register(&t.path, &t.id);
            let span = t.outer.or_else(|| abs_span(item, t.base));
            if let Some((s, e)) = span {
                self.index.push((s, e, t.id.clone()));
            }
            let mut n = leaf(t.id.clone(), kind_of(item), t.label.clone());
            if t.part {
                n.kind = NodeKind::Part;
            }
            n.annotation = t.annotation.clone();
            n.time = t.time.clone();
            n.raw = span.map(|(s, e)| RawRange {
                start: u32_of(s),
                end: u32_of(e),
                ..RawRange::default()
            });
            let me = arena.len();
            let mut children: Vec<Task<'_, '_>> = Vec::new();
            match &item.value {
                Value::Array(items) => {
                    let sign1 = matches!(t.role, Role::Sign1) && items.len() >= 4;
                    for (i, child) in items.iter().enumerate() {
                        let (name, role) = match (sign1, i) {
                            (true, 0) => (
                                PARTS[0],
                                Role::Embedded(Box::new(Role::Header(Context::ProtectedHeader))),
                            ),
                            (true, 1) => (PARTS[1], Role::Header(Context::UnprotectedHeader)),
                            (true, 2) => (PARTS[2], Role::Embedded(Box::new(Role::Claims))),
                            (true, 3) => (PARTS[3], Role::Plain),
                            _ => (
                                "",
                                match t.role {
                                    Role::KeySet => Role::Key,
                                    Role::SdClaims => Role::Embedded(Box::new(Role::Plain)),
                                    _ => Role::Plain,
                                },
                            ),
                        };
                        let (id, label) = if name.is_empty() {
                            (t.id.index(i), i.to_string())
                        } else {
                            (t.id.child(name), name.to_owned())
                        };
                        children.push(Task {
                            part: !name.is_empty(),
                            ..Task::new(
                                child,
                                t.path.child(PathSegment::Index(i)),
                                id,
                                label,
                                t.base,
                                role,
                                Some(me),
                            )
                        });
                    }
                }
                Value::Map(entries) => {
                    let ctx = registry_context(&t.role, item);
                    let mut seen = BTreeSet::new();
                    for (i, (k, v)) in entries.iter().enumerate() {
                        let (seg, edn) = key_segment(k, i, &mut seen);
                        let kpath = t.path.child(PathSegment::Key(i));
                        let vpath = t.path.child(PathSegment::Value(i));
                        let mut task = Task::new(
                            v,
                            vpath.clone(),
                            t.id.push_raw(&seg),
                            edn.clone(),
                            t.base,
                            entry_role(&t.role, k),
                            Some(me),
                        );
                        if let (Some(ctx), Some(label)) = (&ctx, label_of(k))
                            && let Some(note) =
                                self.notes
                                    .lookup(Family::Cose, ctx, &label, label_of(v).as_ref())
                        {
                            task.annotation = Some(note.annotation);
                            self.comments.insert(kpath.clone(), note.key_comment);
                            if let Some(c) = note.value_comment {
                                self.comments.insert(vpath, c);
                            }
                        }
                        if matches!(t.role, Role::Claims) && matches!(int_of(k), Some(4..=6)) {
                            task.time = cbor_hint(v, self.view.now);
                        }
                        task.key = Some((k, kpath, edn));
                        children.push(task);
                    }
                }
                Value::Tag(tag, inner) => {
                    let tagged = self.edn_spans.is_none() && self.view.decoded_views;
                    let role = match (tagged, tag) {
                        (true, 24 | 63) => Role::Embedded(Box::new(Role::Plain)),
                        _ => Role::Plain,
                    };
                    if matches!(tag, 0 | 1) {
                        n.time = cbor_hint(item, self.view.now);
                    }
                    children.push(Task::new(
                        inner,
                        t.path.child(PathSegment::TagContent),
                        t.id.push_raw("~t"),
                        "content".to_owned(),
                        t.base,
                        role,
                        Some(me),
                    ));
                }
                Value::Bytes(_) => {
                    n.children = self.decoded_views(item, &t.path, &t.id, t.base, &t.role);
                }
                _ => {}
            }
            if item.width == Width::Indefinite
                && matches!(item.value, Value::Bytes(_) | Value::Text(_))
            {
                for (i, chunk) in item.chunks.iter().enumerate() {
                    children.push(Task::new(
                        chunk,
                        t.path.child(PathSegment::Chunk(i)),
                        t.id.push_raw(&format!("~c{i}")),
                        format!("chunk {i}"),
                        t.base,
                        Role::Plain,
                        Some(me),
                    ));
                }
            }
            arena.push(Some(n));
            links.push((t.parent, t.is_key));
            kids.push(Vec::new());
            // Children in order, then the key first (it is visited next).
            tasks.extend(children.into_iter().rev());
            if let Some((k, kpath, label)) = t.key {
                tasks.push(Task {
                    is_key: true,
                    ..Task::new(k, kpath, t.id.key(), label, t.base, Role::Plain, Some(me))
                });
            }
        }
        // Assemble: every node comes after its parent, so in reverse order
        // each node is complete when it is moved into its parent.
        for i in (1..arena.len()).rev() {
            let Some(mut n) = arena.get_mut(i).and_then(Option::take) else {
                continue;
            };
            if let Some(mine) = kids.get_mut(i) {
                n.children.extend(std::mem::take(mine).into_iter().rev());
            }
            let Some(&(Some(parent), is_key)) = links.get(i) else {
                continue;
            };
            if is_key {
                if let Some(Some(p)) = arena.get_mut(parent) {
                    p.key = Some(Box::new(n));
                }
            } else if let Some(siblings) = kids.get_mut(parent) {
                siblings.push(n);
            }
        }
        let mut root = arena
            .first_mut()
            .and_then(Option::take)
            .unwrap_or_else(|| leaf(NodeId::root(), NodeKind::Null, String::new()));
        if let Some(mine) = kids.first_mut() {
            root.children.extend(std::mem::take(mine).into_iter().rev());
        }
        root
    }

    /// Decoded views of a byte string: at defined locations, on request
    /// (`manual_decode`), or where the user wrote `<<…>>` (EDN claim sets).
    fn decoded_views(
        &mut self,
        item: &Item<'_>,
        path: &Path,
        id: &NodeId,
        base: usize,
        role: &Role,
    ) -> Vec<Node> {
        let Some((start, end)) = bstr_contents(item, base) else {
            return Vec::new();
        };
        let Some(content) = self.bytes.get(start..end) else {
            return Vec::new();
        };
        let manual = self.view.manual_decode.contains(id);
        if manual {
            self.manual_diagnostics(start, end, id);
        }
        let expand = match self.edn_spans {
            Some(spans) => spans.get(&path.child(PathSegment::Embedded(0))).is_some(),
            None => {
                manual
                    || (matches!(role, Role::Embedded(_))
                        && self.view.decoded_views
                        && !self.view.hide_decoded.contains(id))
            }
        };
        // The printer shows no embedded CBOR beyond MAX_DEPTH either.
        if !expand || self.embedded_depth >= MAX_EMBEDDED || path.depth() >= MAX_DEPTH {
            return Vec::new();
        }
        let Some(items) = exact_sequence(content) else {
            return Vec::new();
        };
        let inner = match role {
            Role::Embedded(inner) => inner.as_ref().clone(),
            _ => Role::Plain,
        };
        self.embedded.push(path.clone());
        self.embedded_depth += 1;
        let mut out = Vec::with_capacity(items.len());
        for (j, child) in items.iter().enumerate() {
            let role = if j == 0 { inner.clone() } else { Role::Plain };
            out.push(self.walk(Task::new(
                child,
                path.child(PathSegment::Embedded(j)),
                id.decoded(j),
                "decoded".to_owned(),
                start,
                role,
                None,
            )));
        }
        self.embedded_depth -= 1;
        out
    }

    fn manual_diagnostics(&mut self, start: usize, end: usize, id: &NodeId) {
        let range = |s: usize, e: usize| ByteRange {
            start: u32_of(s),
            end: u32_of(e),
        };
        match tokenator_edn::decode_embedded(self.bytes, start..end) {
            Ok(view) => {
                for w in view.warnings {
                    let EmbeddedWarning::TrailingBytes { offset, len } = w else {
                        continue;
                    };
                    self.diagnostics.push(Diagnostic {
                        severity: Severity::Warning,
                        code: "cbor.trailing_bytes".to_owned(),
                        message: format!("{len} byte(s) after the first item"),
                        node_id: Some(id.clone()),
                        main: None,
                        raw: Some(range(offset, offset + len)),
                    });
                }
            }
            Err(e) => self.diagnostics.push(Diagnostic {
                severity: Severity::Warning,
                code: "cbor.decode".to_owned(),
                message: format!("not CBOR: {:?} at byte {}", e.kind, e.offset),
                node_id: Some(id.clone()),
                main: None,
                raw: Some(range(start, end)),
            }),
        }
    }
}

/// The text and span map of the main pane.
pub(crate) enum MainText<'t> {
    /// Print the item as EDN.
    Print,
    /// The user's EDN text and its parse spans (EDN claim sets).
    Given { text: &'t str, spans: &'t SpanMap },
}

/// Walks `item` (decoded from `bytes`) with `role` at the root and renders
/// both panes.
pub(crate) fn build(
    item: &Item<'_>,
    bytes: &[u8],
    role: &Role,
    notes: Notes<'_>,
    view: &ViewOptions,
    main: &MainText<'_>,
) -> CborView {
    let edn_spans = match main {
        MainText::Given { spans, .. } => Some(*spans),
        MainText::Print => None,
    };
    let mut w = Walker {
        notes,
        view,
        edn_spans,
        bytes,
        ids: BTreeMap::new(),
        primary: BTreeMap::new(),
        comments: BTreeMap::new(),
        embedded: Vec::new(),
        diagnostics: Vec::new(),
        index: Vec::new(),
        embedded_depth: 0,
    };
    let mut tree = w.walk(Task::new(
        item,
        Path::root(),
        NodeId::root(),
        String::new(),
        0,
        role.clone(),
        None,
    ));
    let tagged = edn_spans.is_none() && view.decoded_views;
    let embedded = EmbeddedCbor {
        paths: &w.embedded,
        tagged,
    };
    let comments = Comments(&w.comments);
    let annotator: Option<&dyn Annotator> = if w.comments.is_empty() {
        None
    } else {
        Some(&comments)
    };
    let printed;
    let (text, spans) = match main {
        MainText::Given { text, spans } => (*text, *spans),
        MainText::Print => {
            let opts = PrintOptions {
                layout: match view.layout {
                    Layout::Indented => tokenator_edn::Layout::Indented {
                        indent: usize::try_from(view.indent).unwrap_or(2),
                    },
                    Layout::Compact => tokenator_edn::Layout::Compact,
                },
                embedded_cbor: embedded,
                bytes: match view.byte_style {
                    ByteStyle::Hex => tokenator_edn::ByteStyle::Hex,
                    ByteStyle::Base64 => tokenator_edn::ByteStyle::Base64,
                },
                dt_literals: view.dt_literals,
                annotator,
                ..PrintOptions::new()
            };
            printed = tokenator_edn::print(item, &opts);
            (printed.text.as_str(), &printed.spans)
        }
    };
    let hex = tokenator_edn::annotated_hex(
        item,
        bytes,
        &HexOptions {
            embedded_cbor: embedded,
            annotator,
        },
    );
    let rows: Vec<HexRow> = hex
        .rows
        .iter()
        .map(|r| HexRow {
            node_id: nearest_id(&w.ids, &r.path),
            kind: match r.kind {
                tokenator_edn::HexRowKind::Item => HexRowKind::Item,
                tokenator_edn::HexRowKind::Break => HexRowKind::Break,
            },
            depth: u32_of(r.depth),
            head: ByteRange {
                start: u32_of(r.head.start),
                end: u32_of(r.head.end),
            },
            payload: ByteRange {
                start: u32_of(r.payload.start),
                end: u32_of(r.payload.end),
            },
            description: r.description.clone(),
            comment: r.comment.clone(),
        })
        .collect();
    let index = TextIndex::new(text);
    fill_ranges(&mut tree, &w.primary, spans, &index, &rows);
    CborView {
        tree,
        text: text.to_owned(),
        rows,
        diagnostics: w.diagnostics,
        index: w.index,
    }
}

/// The node id of a path, or of its nearest registered ancestor.
fn nearest_id(ids: &BTreeMap<Path, NodeId>, path: &Path) -> NodeId {
    let mut segs = path.segments().to_vec();
    loop {
        if let Some(id) = ids.get(&Path(segs.clone())) {
            return id.clone();
        }
        if segs.pop().is_none() {
            return NodeId::root();
        }
    }
}

/// Sets main ranges from the span map and row ranges from the rows.
fn fill_ranges(
    tree: &mut Node,
    primary: &BTreeMap<NodeId, Path>,
    spans: &SpanMap,
    index: &TextIndex,
    rows: &[HexRow],
) {
    let mut stack: Vec<&mut Node> = vec![tree];
    while let Some(n) = stack.pop() {
        if let Some(span) = primary.get(&n.id).and_then(|p| spans.get(p)) {
            n.main = Some(index.range(span.text.clone()));
        }
        if let Some(raw) = n.raw.as_mut() {
            raw.row_start = u32_of(rows.partition_point(|r| r.head.start < raw.start));
            raw.row_end = u32_of(rows.partition_point(|r| r.head.start < raw.end));
        }
        if let Some(k) = n.key.as_deref_mut() {
            stack.push(k);
        }
        stack.extend(n.children.iter_mut());
    }
}
