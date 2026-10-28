# JSONTestSuite (vendored)

`test_parsing/` and `LICENSE` are copied verbatim from
<https://github.com/nst/JSONTestSuite> at commit
`1ef36fa01286573e846ac449e8683f8833c5b26a` (2024-11-22). MIT licensed, see `LICENSE`.

File prefixes: `y_` must be accepted, `n_` must be rejected, `i_` is
implementation-defined. The choices for `i_` files made by `tokenator-json`
are listed in `crates/tokenator-json/TEST-PLAN.md` and enforced by
`crates/tokenator-json/tests/json_test_suite.rs`.

Files are marked `-text` in `.gitattributes` so git never rewrites their bytes.
