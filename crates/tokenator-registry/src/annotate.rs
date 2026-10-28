//! Display-name annotation for EDN comments and JSON hovers.

use crate::{Entry, EntryKind, Label, Registry};

/// Token family of the document being annotated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    /// JWT / SD-JWT: text keys.
    Jose,
    /// CWT / SD-CWT: mostly integer keys.
    Cose,
}

/// Where in the document a key appears.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Context {
    /// Protected header map / JOSE header.
    ProtectedHeader,
    /// Unprotected header map (COSE only; for JOSE treated like a header).
    UnprotectedHeader,
    /// Claims set (CWT/JWT payload, also SD-KBT/KB-JWT claims).
    Claims,
    /// Inside a `cnf` claim.
    Cnf,
    /// Inside a COSE_Key or JWK; `kty` selects the type-specific parameters.
    Key {
        /// The key's `kty`, if known (`Int` for COSE, `Text` for JOSE).
        kty: Option<Label>,
    },
}

/// Supplies short names for keys and values. `tokenator-edn` takes a
/// `&dyn Annotator` for `/ comment /` annotations.
///
/// # Examples
///
/// ```
/// use tokenator_registry::{Annotator, Context, Family, Label, Registry};
///
/// let reg = Registry::shared()?;
/// // COSE: integer labels get their registered names.
/// let alg = Label::Int(1);
/// assert_eq!(reg.display_name(Family::Cose, &Context::ProtectedHeader, &alg), Some("alg"));
/// assert_eq!(reg.display_name(Family::Cose, &Context::Claims, &alg), Some("iss"));
/// assert_eq!(
///     reg.value_name(Family::Cose, &Context::ProtectedHeader, &alg, &Label::Int(-7)),
///     Some("ES256")
/// );
/// // JOSE: the key already is the name, so the description is shown.
/// let iss = Label::from("iss");
/// assert_eq!(reg.display_name(Family::Jose, &Context::Claims, &iss), Some("Issuer"));
/// # Ok::<(), tokenator_registry::RegistryError>(())
/// ```
///
/// Type-specific COSE_Key parameters need the key's `kty`:
///
/// ```
/// use tokenator_registry::{Annotator, Context, Family, Label, Registry};
///
/// let reg = Registry::shared()?;
/// let annotator: &dyn Annotator = reg;
/// let ec2 = Context::Key { kty: Some(Label::Int(2)) };
/// let akp = Context::Key { kty: Some(Label::Int(7)) };
/// let minus_one = Label::Int(-1);
/// assert_eq!(annotator.display_name(Family::Cose, &ec2, &minus_one), Some("crv"));
/// assert_eq!(annotator.display_name(Family::Cose, &akp, &minus_one), Some("pub"));
/// // crv 1 in an EC2 key is P-256
/// assert_eq!(
///     annotator.value_name(Family::Cose, &ec2, &minus_one, &Label::Int(1)),
///     Some("P-256")
/// );
/// // without a kty, negative labels are ambiguous
/// let unknown = Context::Key { kty: None };
/// assert_eq!(annotator.display_name(Family::Cose, &unknown, &minus_one), None);
/// # Ok::<(), tokenator_registry::RegistryError>(())
/// ```
pub trait Annotator {
    /// The registry entry for `key` in `ctx`, if registered.
    fn entry(&self, family: Family, ctx: &Context, key: &Label) -> Option<&Entry>;

    /// The registry entry for a *value* whose meaning is registered: `alg`
    /// (header or key), `kty`, and `crv` (in a key). `None` otherwise.
    fn value_entry(
        &self,
        family: Family,
        ctx: &Context,
        key: &Label,
        value: &Label,
    ) -> Option<&Entry>;

    /// Short display name for `key`: the registered name for COSE
    /// (`1` → `"alg"`), the description for JOSE (`"iss"` → `"Issuer"`),
    /// since the JOSE key already is the name.
    fn display_name(&self, family: Family, ctx: &Context, key: &Label) -> Option<&str> {
        self.entry(family, ctx, key).map(|e| short_name(family, e))
    }

    /// Short display name for a value, with the same COSE-name / JOSE-description
    /// rule as [`Annotator::display_name`] (COSE alg `-7` → `"ES256"`).
    fn value_name(
        &self,
        family: Family,
        ctx: &Context,
        key: &Label,
        value: &Label,
    ) -> Option<&str> {
        self.value_entry(family, ctx, key, value)
            .map(|e| short_name(family, e))
    }
}

/// The registered name for COSE, the description (if any) for JOSE.
fn short_name(family: Family, e: &Entry) -> &str {
    match family {
        Family::Jose if !e.description.is_empty() => &e.description,
        _ => &e.name,
    }
}

impl Annotator for Registry {
    fn entry(&self, family: Family, ctx: &Context, key: &Label) -> Option<&Entry> {
        match family {
            Family::Cose => match ctx {
                Context::ProtectedHeader | Context::UnprotectedHeader => {
                    self.cose_header(key.clone()).or_else(|| match key {
                        // Algorithm-specific parameters use negative labels.
                        Label::Int(n) if *n < 0 => self.get(EntryKind::CoseHeaderAlgParam, *n),
                        _ => None,
                    })
                }
                Context::Claims => self.cwt_claim(key.clone()),
                Context::Cnf => self.get(EntryKind::CwtCnfMethod, key.clone()),
                Context::Key { kty } => match key {
                    Label::Int(label) => {
                        let kty = match kty {
                            Some(Label::Int(k)) => Some(*k),
                            _ => None,
                        };
                        self.cose_key_param(kty, *label)
                    }
                    Label::Text(_) => self.get(EntryKind::CoseKeyParam, key.clone()),
                },
            },
            Family::Jose => {
                let kind = match ctx {
                    Context::ProtectedHeader | Context::UnprotectedHeader => EntryKind::JoseHeader,
                    Context::Claims => EntryKind::JwtClaim,
                    Context::Cnf => EntryKind::JwtCnfMethod,
                    Context::Key { .. } => EntryKind::JwkParam,
                };
                match key {
                    Label::Text(_) => self.get(kind, key.clone()),
                    Label::Int(_) => None,
                }
            }
        }
    }

    fn value_entry(
        &self,
        family: Family,
        ctx: &Context,
        key: &Label,
        value: &Label,
    ) -> Option<&Entry> {
        let key_name = self.entry(family, ctx, key)?.name.as_str();
        let kind = match (family, ctx, key_name) {
            (Family::Cose, Context::ProtectedHeader | Context::UnprotectedHeader, "alg") => {
                EntryKind::CoseAlg
            }
            (Family::Cose, Context::ProtectedHeader | Context::UnprotectedHeader, "sd_alg") => {
                EntryKind::CoseAlg
            }
            (Family::Cose, Context::Key { .. }, "alg") => EntryKind::CoseAlg,
            (Family::Cose, Context::Key { .. }, "kty") => EntryKind::CoseKty,
            (Family::Cose, Context::Key { .. }, "crv") => EntryKind::CoseCrv,
            (
                Family::Jose,
                Context::ProtectedHeader | Context::UnprotectedHeader,
                "alg" | "enc",
            ) => EntryKind::JoseAlg,
            (Family::Jose, Context::Key { .. }, "alg") => EntryKind::JoseAlg,
            (Family::Jose, Context::Key { .. }, "kty") => EntryKind::JwkKty,
            (Family::Jose, Context::Key { .. }, "crv") => EntryKind::JwkCrv,
            _ => return None,
        };
        self.get(kind, value.clone())
    }
}
