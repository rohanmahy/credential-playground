//! Display-name annotation for EDN comments and JSON hovers.

use crate::{Entry, Label, Registry};

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
        let _ = (family, ctx, key);
        unimplemented!()
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
        let _ = (family, ctx, key, value);
        unimplemented!()
    }
}

impl Annotator for Registry {
    fn entry(&self, family: Family, ctx: &Context, key: &Label) -> Option<&Entry> {
        let _ = (family, ctx, key);
        unimplemented!()
    }

    fn value_entry(
        &self,
        family: Family,
        ctx: &Context,
        key: &Label,
        value: &Label,
    ) -> Option<&Entry> {
        let _ = (family, ctx, key, value);
        unimplemented!()
    }
}
