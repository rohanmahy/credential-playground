# registry-gen

Build-time generator for `crates/tokenator-registry/data/snapshot.json`. It
reads the four IANA registry XML files and the local additions, builds a
`tokenator_registry::Registry`, and writes its deterministic snapshot. All
parsing lives in `tokenator-registry`; this crate only does file I/O.

```sh
cargo run -p registry-gen                       # defaults below
cargo run -p registry-gen -- --input-dir DIR --local FILE --out FILE
```

| Flag | Default |
|---|---|
| `--input-dir` | `testdata/iana/` (`cwt.xml`, `cose.xml`, `jwt.xml`, `jose.xml`) |
| `--local` | `crates/tokenator-registry/data/local-additions.json` |
| `--out` | `crates/tokenator-registry/data/snapshot.json` |

## Refreshing the bundled snapshot

1. Download the four files over the fixtures:
   ```sh
   for r in cwt cose jwt jose; do
     curl -fsSo testdata/iana/$r.xml https://www.iana.org/assignments/$r/$r.xml
   done
   ```
2. Update the dates and SHA-256 table in `testdata/iana/README.md`.
3. If the pinned SD-CWT draft changed, edit `local-additions.json`.
4. Run `cargo run -p registry-gen` and commit the fixtures and the snapshot together.
5. Run `cargo test -p tokenator-registry -p registry-gen`. Fixture spot-checks
   may need updating if IANA changed an entry they assert on.
   `checked_in_snapshot_is_up_to_date` fails whenever the snapshot is stale.
