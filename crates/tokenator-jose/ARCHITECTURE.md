# tokenator-jose

JWS, JWT, SD-JWT, and KB-JWT. See the top-level `ARCHITECTURE.md` for where
this fits and `TEST-PLAN.md` for the decisions the tests encode.

| file | contents |
|---|---|
| `b64.rs` | strict unpadded base64url |
| `parse.rs` | `Token`, `Jws`, `SdJwt`, `B64Part`, `Disclosure`, diagnostics, `parse` |
| `sd.rs` | disclosure views, `_sd_alg`, digests, `process` and `SdReport` |
| `issue.rs` | `IssueOptions`, `JsonStyle`, `issue` |
| `present.rs` | `select`, `present`, KB-JWT creation |
| `verify.rs` | `verify_signature`, `check_time_claims`, `check_kb_jwt` |
| `manipulate.rs` | `resign`, `assemble_compact`, `tamper`, `edit_disclosures`, conversions |
| `lint.rs` | header facts, duplicate members, `cnf`, key findings |
| `error.rs` | `JoseError` |

## Design

- Parsed parts borrow the input; each `B64Part` owns only its decoded
  bytes. JSON trees are parsed on demand from those bytes, so they borrow
  the token and their spans are relative to the decoded part.
- Signatures, digests, and `sd_hash` are always computed over the original
  encoded text, never re-serialized.
- Status: skeleton; every body is `unimplemented!()`.
