# tokenator-registry test plan

Covers `crates/tokenator-registry` (library) and `tools/registry-gen`
(build-time generator). Fixtures: `testdata/iana/{cwt,cose,jwt,jose}.xml`,
fetched 2026-10-28 (see `testdata/iana/README.md`). No test touches the
network or the filesystem outside `include_bytes!`/`include_str!`.

## Design under test

- **Parsing lives in the library**, not the generator: `parse_iana` is needed
  at build time (generator) and at run time (`merge_iana`). `registry-gen` is a
  thin file-I/O wrapper around `Registry::build` + `Registry::to_snapshot`.
- **Snapshot** (`data/snapshot.json`, embedded with `include_bytes!`):
  proposed format is JSON: `{ "format": 1, "sd_cwt_revision": "...",
  "iana_updated": {"cwt": "YYYY-MM-DD", ...}, "entries": [Entry...] }`, with
  entries sorted by (kind, label). It must be deterministic: no wall-clock
  timestamp, only the IANA `<updated>` dates. The checked-in file is a
  placeholder until the generator is run.
- **Local additions** (`data/local-additions.json`, hand-maintained): the
  pinned SD-CWT revision plus entries for codepoints not (yet) in the four
  IANA registries: SD-CWT CBOR tags 58/60/62 and simple value 59, the SD-CWT
  header parameters and `vct` (in case their TEMPORARY registrations
  lapse), and the token-relevant CBOR tags (16, 17, 18, 61, 96, 97, 98, and
  date tags 0, 1, 100, 1004), because the CBOR tags registry is not fetched.
- **Entry identity** is `(EntryKind, Label)`. COSE key-type parameters also
  carry `key_type` (the kty value), so `(CoseKeyTypeParam, kty, label)` is unique.
- **IANA record normalisation**:
  - Records whose label/value is a range (`18-21`, `12 to 37`, `less than
    -65536`) or whose name is `Unassigned`, `Reserved…`, or `delegated…` are skipped.
  - A trailing parenthetical is stripped from names (`typ (type)` → `typ`).
    If it starts with `TEMPORARY`, `temporary = true`.
  - Descriptions are flattened to plain text, with nested `<xref>` rendered
    as text (e.g. `RFC 8392`) and whitespace collapsed.
  - References come from `<xref>` children of `<record>` only. `rfc` gives
    `RFC NNNN[, Section S]` and `https://www.rfc-editor.org/rfc/rfcNNNN[#section-S]`.
    `draft` gives a datatracker URL (an `RFC-` prefix is mapped back to `draft-`).
    `uri` gives the text plus that URL. `person` is ignored.
  - JOSE header parameters are listed once for JWS and once for JWE, and JWK
    `x`/`d`/`crv` once per key type. The first record wins (JWS / EC).
- **Precedence**: Refreshed > Iana snapshot > Local. This applies at
  generation time (an IANA entry replaces a Local one with the same identity)
  and at merge time. `merge_iana` is authoritative for the kinds of the
  registry it parses: snapshot Iana/Refreshed entries of those kinds that are
  missing from the refresh are removed (expired temporary registrations).
  Local entries are never discarded. A superseded one is *shadowed* (kept,
  including in the snapshot, but invisible to lookups, `entries`, and `len`)
  and resurfaces if IANA drops the codepoint. On error the registry is unchanged.
- Value types are whitespace-collapsed like descriptions.
- `parse_iana` errors: `WrongRegistry` when the root id names another
  registry; `Xml` for everything else, including a missing root id, a non-registry
  root, truncation (unclosed elements at EOF), and non-UTF-8 text. Unknown
  sub-registries are ignored.

## Test files

| File | Area |
|---|---|
| `tests/parse_iana.rs` | `parse_iana` per fixture: counts, spot-checks, normalisation, refs |
| `tests/lookup.rs` | `Registry::build` from fixtures; every lookup kind, by label and by name |
| `tests/claim_mapping.rs` | JWT name ↔ CWT key mapping |
| `tests/local_additions.rs` | local-additions file, SD-CWT revision, precedence at build time |
| `tests/snapshot.rs` | to/from snapshot round-trip, bundled snapshot, malformed snapshot |
| `tests/merge.rs` | `merge_iana` semantics, stats, precedence, atomicity, wrong registry |
| `tests/errors.rs` | malformed XML returns errors, never panics |
| `tests/annotator.rs` | `Annotator` for JOSE/COSE × header/claims/key/cnf; value annotation |
| `tools/registry-gen/tests/generate.rs` | generator over fixtures; determinism; checked-in snapshot in sync |

## Cases

### parse_iana (fixtures)
- COSE: alg -7 `ES256`, -8 `EdDSA`, -19 `Ed25519`, -9 `ESP256`, -35/-36 ES384/ES512,
  -37 `PS256`, -257 `RS256`, -48/-49/-50 ML-DSA-44/65/87; header 1 `alg`,
  2 `crit`, 3 `content type`, 4 `kid`, 13 `kcwt`, 15 `CWT Claims`, 16 `typ`
  (stripped), 17 `sd_claims` (temporary), 33 `x5chain`; kty 1 OKP, 2 EC2,
  3 RSA, 7 AKP; crv 1 P-256, 6 Ed25519; key common 1 kty, 2 kid, 3 alg;
  key type param (kty 2, -1) crv, (kty 7, -1) pub, (kty 7, -2) priv; value
  types (`kid` → `bstr`, key `kty` → `tstr / int`).
- CWT: 1..8 iss/sub/aud/exp/nbf/iat/cti/cnf with JWT names, 10 `Nonce`↔`eat_nonce`,
  11 `vct` temporary, -260 `hcert`; cnf methods 1 COSE_Key↔jwk, 2, 3 kid.
- JWT: iss, sub, jti, cnf, `_sd`, `...`, `_sd_alg`, `sd_hash`; `vct` absent;
  cnf methods jwk, jwe, kid, jkt.
- JOSE: headers alg, jwk, kid, x5c, typ, crit, `x5t#S256`; algs ES256, EdDSA,
  Ed25519, ML-DSA-44, RS256, PS256, `none`; kty EC/RSA/OKP/AKP; crv P-256,
  Ed25519; JWK params kty, x, crv, pub, priv.
- No ranges/Unassigned/Reserved entries; no `<` in descriptions; flattened
  `kcwt` description mentions 8392; all entries have source `Iana`.
- References: `iss` → RFC 7519, Section 4.1.1 + rfc-editor URL with
  fragment; `sd_claims` → datatracker URL; `hcert` → uri reference.
- Feeding XML for the wrong `RegistryId` is an error.

### Lookups (Registry::build over all four fixtures + local additions)
`jose_header`, `jose_alg`, `jwk_kty`, `jwk_crv`, `jwk_param`, `jwt_claim`,
`jwt_cnf_method`, `cose_header` (int and text label; text label not found
→ None), `cose_alg` (by value and `by_name`), `cose_kty`, `cose_crv`,
`cose_key_param` (common and kty-specific), `cwt_claim`, `cwt_cnf_method`,
`cbor_tag`, `cbor_simple`, generic `get`/`by_name`/`entries`, `search`
prefix (case-insensitive, optional kind filter). Unknown keys give None, never panic.

### Claim mapping
iss↔1 … cnf↔8, jti↔7 (CWT name `cti`), eat_nonce↔10, vct↔11, hcert↔-260.
No counterpart: `_sd` (JWT only); -261 (JWT column `N/A`); unknown names/keys.
Round-trip `cwt_to_jwt(jwt_to_cwt(x)) == x` for all mapped claims.

### Local additions
File parses; revision is `draft-ietf-spice-sd-cwt-08`, exposed through
`Registry::sd_cwt_revision()` and `SnapshotInfo`. Tags 58/60/62 and simple 59
are Local, with a reference pointing at the pinned revision. Token tags 18 and 61 are present.
Built with stock fixtures, `sd_claims` is Iana (IANA wins). Built with the
`sd_claims` record removed from cose.xml, `sd_claims` is Local. Malformed
local-additions gives an error.

### Snapshot
Round-trip preserves every entry, the revision, and the IANA dates.
`to_snapshot` is deterministic. Bundled snapshot loads, contains entries of
every kind, and equals `Registry::build(fixtures)`. Garbage/empty/truncated
snapshot bytes give an error.

### merge_iana
Same fixture: 0 added/updated/removed, all unchanged, sources become
Refreshed. Edited description: updated=1. New record: added=1, findable.
Removed record: removed=1, gone. Local entry at a newly registered codepoint:
superseded_local=1, entry now Refreshed, `len` unchanged. Expired temporary
(`sd_claims` dropped from cose.xml): the shadowed Local entry resurfaces, also
after a snapshot round-trip. New `<updated>` date is recorded in stats and `info()`. Local entries in other kinds are
untouched. Merging cose.xml leaves CWT entries alone. Malformed XML or the
wrong registry gives Err and leaves the registry unchanged. Merging twice is
idempotent. Merged registry survives a snapshot round-trip with sources intact.

### Errors (no panics)
Empty input, non-XML, truncated document, mismatched tags, a record with a
non-integer label where an integer is required (skipped, not an error),
non-UTF-8 bytes, a root that is not `<registry>`, deeply nested junk.

### Annotator
COSE protected/unprotected header 1 → `alg`, 4 → `kid`, 33 → `x5chain`;
claims 1 → `iss`, 8 → `cnf`; COSE_Key (kty 2) -1 → `crv`, (kty 7) -1 → `pub`;
cnf 1 → `COSE_Key`. JOSE header `alg` → `Algorithm`, claims `iss` → `Issuer`,
JWK `kty` → `Key Type`. Unknown → None. Value annotation: COSE alg -7 →
`ES256`, kty 2 → `EC2`, crv 1 (kty 2) → `P-256`; JOSE alg `ES256` → its
description. Works through `&dyn Annotator`.

### Generator
`generate` over the fixtures + local additions succeeds, is byte-for-byte
deterministic, the output loads with `Registry::from_snapshot`, and equals the
checked-in `crates/tokenator-registry/data/snapshot.json`. A bad input file
gives an error that names the registry. CLI arg parsing: defaults, `--out`,
`--input-dir`, unknown flag.

## Open questions

GitHub issues #5 (SD-CWT revision and codepoints) and #6 (annotation and data-model defaults).

## Counts

89 tests in `tokenator-registry` (parse_iana 24, lookup 13, claim_mapping 6,
local_additions 8, snapshot 6, merge 13, errors 11, annotator 8) and 12 in
`registry-gen`. They all fail (`unimplemented!`) until the implementation lands.
`snapshot.rs` and `checked_in_snapshot_is_up_to_date` also need
`data/snapshot.json`, which is generated by `cargo run -p registry-gen`.
