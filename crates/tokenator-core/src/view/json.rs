//! JSON trees for JSON claim sets and decoded JOSE parts.

use std::collections::BTreeSet;

use tokenator_json::{Node as JNode, Value as JValue};
use tokenator_registry::{Context, Family, Label};

use crate::annotate::Notes;
use crate::datetime::json_hint;
use crate::dto::common::{NodeId, RawRange, escape_segment};
use crate::dto::document::{Node, NodeKind};
use crate::util::TextIndex;

/// Where a JSON value sits, as far as JOSE defines it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JRole {
    Plain,
    Header,
    Claims,
    Cnf,
    Key,
}

/// Inputs shared by one JSON tree walk.
pub(crate) struct JsonWalk<'a> {
    pub(crate) notes: Notes<'a>,
    pub(crate) now: Option<i64>,
    pub(crate) text: &'a TextIndex,
    /// The raw range of a byte span of the main text, if the tree has one.
    pub(crate) raw: &'a dyn Fn(usize, usize) -> Option<RawRange>,
    /// `(start, end, id)` of every node's byte span in the main text.
    pub(crate) index: Vec<(usize, usize, NodeId)>,
}

fn context(role: JRole) -> Option<Context> {
    match role {
        JRole::Header => Some(Context::ProtectedHeader),
        JRole::Claims => Some(Context::Claims),
        JRole::Cnf => Some(Context::Cnf),
        JRole::Key => Some(Context::Key { kty: None }),
        JRole::Plain => None,
    }
}

fn member_role(role: JRole, name: &str) -> JRole {
    match (role, name) {
        (JRole::Claims, "cnf") => JRole::Cnf,
        (JRole::Cnf, "jwk") => JRole::Key,
        _ => JRole::Plain,
    }
}

impl JsonWalk<'_> {
    fn base(&mut self, node: &JNode<'_>, id: NodeId, kind: NodeKind, label: String) -> Node {
        let (main, raw) = match node.span() {
            Some(s) => {
                self.index.push((s.start, s.end, id.clone()));
                (
                    Some(self.text.range(s.start..s.end)),
                    (self.raw)(s.start, s.end),
                )
            }
            None => (None, None),
        };
        Node {
            id,
            kind,
            label,
            annotation: None,
            main,
            raw,
            key: None,
            time: None,
            sd: None,
            children: Vec::new(),
        }
    }

    /// The node for `node` and its subtree.
    pub(crate) fn tree(
        &mut self,
        node: &JNode<'_>,
        id: NodeId,
        label: String,
        role: JRole,
    ) -> Node {
        let kind = match node.value() {
            JValue::Null => NodeKind::Null,
            JValue::Bool(_) => NodeKind::Bool,
            JValue::Number(_) => NodeKind::Number,
            JValue::String(_) => NodeKind::Text,
            JValue::Array(_) => NodeKind::Array,
            JValue::Object(_) => NodeKind::Map,
        };
        let mut n = self.base(node, id, kind, label);
        match node.value() {
            JValue::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    let c = self.tree(item, n.id.index(i), i.to_string(), JRole::Plain);
                    n.children.push(c);
                }
            }
            JValue::Object(members) => {
                let ctx = context(role);
                let mut seen = BTreeSet::new();
                for (i, m) in members.iter().enumerate() {
                    let name = m.key().as_ref();
                    let seg = escape_segment(name);
                    let eid = if seen.insert(seg.clone()) {
                        n.id.push_raw(&seg)
                    } else {
                        n.id.push_raw(&format!("~i{i}"))
                    };
                    let kid = eid.key();
                    let mut knode = Node {
                        main: m.key_span().map(|s| self.text.range(s.start..s.end)),
                        raw: m.key_span().and_then(|s| (self.raw)(s.start, s.end)),
                        ..self.base(
                            &JNode::new(JValue::Null),
                            kid.clone(),
                            NodeKind::Text,
                            name.to_owned(),
                        )
                    };
                    if let Some(s) = m.key_span() {
                        self.index.push((s.start, s.end, kid));
                    }
                    knode.kind = NodeKind::Text;
                    let mut v = self.tree(m.value(), eid, name.to_owned(), member_role(role, name));
                    if let Some(ctx) = &ctx {
                        let value = match m.value().value() {
                            JValue::String(s) => Some(Label::Text(s.to_string())),
                            _ => None,
                        };
                        if let Some(note) = self.notes.lookup(
                            Family::Jose,
                            ctx,
                            &Label::Text(name.to_owned()),
                            value.as_ref(),
                        ) {
                            v.annotation = Some(note.annotation);
                        }
                    }
                    if role == JRole::Claims
                        && matches!(name, "exp" | "nbf" | "iat")
                        && let JValue::Number(lexeme) = m.value().value()
                    {
                        v.time = json_hint(lexeme, self.now);
                    }
                    v.key = Some(Box::new(knode));
                    n.children.push(v);
                }
            }
            _ => {}
        }
        n
    }
}
