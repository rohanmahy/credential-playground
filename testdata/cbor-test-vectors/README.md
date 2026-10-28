# cbor-test-vectors (vendored)

Copied verbatim from <https://github.com/hildjj/cbor-test-vectors>.

- Source commit: `7e84843b646676a715d4da21c719f263e4c43440` (2026-01-25)
- License: see `LICENSE` (upstream license, kept unchanged)
- Upstream README: `README.upstream.md`

Only `tests/` (the `.edn` sources and their generated `.cbor` twins) was
copied; the upstream JavaScript tooling was left out. The `.cbor` files are
what `crates/tokenator-cbor/tests/vectors.rs` reads.

To refresh: clone the upstream repo, copy `tests/` and `LICENSE` here, and
update the commit hash above.
