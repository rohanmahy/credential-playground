# tokenator-crypto

Signing, verification, digests, and algorithm/key requirements. See the
top-level `ARCHITECTURE.md` for where this fits; `TEST-PLAN.md` lists the
codepoints, vectors, and policy defaults (#9, #10, #11).

| file | contents |
|---|---|
| `alg.rs` | `Alg`, `HashAlg`, `Curve`, `KeyType`, `MlDsaParams` and their JOSE/COSE tables |
| `requirements.rs` | `requirements`, `check_key`, `algs_for_key`, `KeyParams` |
| `key.rs` | material types, `PrivateKey`/`PublicKey`, generation |
| `ops.rs` | `sign`, `sign_deterministic`, `verify`, `digest` |
| `error.rs` | `CryptoError` |

## Design

- `PrivateKey`/`PublicKey` wrap a private enum of backend keys (one variant
  per curve / ML-DSA parameter set). The `with_ec!` / `with_ml_dsa!` macros
  write per-curve code once. Large keys are boxed.
- `sign`/`verify` first call `check_key` on the key's own `params()`. Any
  finding other than `RsaTooSmall` becomes `KeyNotSuitable` with exactly
  those findings. After that, the key alone picks the backend.
- `sign` and `sign_deterministic` share one path. The RNG is an
  `Option<&mut dyn CryptoRng>`, and `None` selects RFC 6979 / ML-DSA
  `rnd = 0`. PSS with `None` returns `RandomnessRequired`.
- RSA integers have leading zeros stripped before they become `BoxedUint`,
  since `rsa` sizes integers by input length. Supplied `dp`/`dq`/`qi` are
  checked against the values computed from the primes.
- ML-DSA keeps the seed when it's known. Expanded-only import checks the
  s1/s2 coefficient ranges first, because the backend's deprecated
  `from_expanded` asserts on them. `tr` isn't cross-checked against the
  public key.

## Caveats

- **RSA timing (RUSTSEC-2023-0071, Marvin).** The `rsa` crate's private-key
  operation isn't constant-time. Every RSA signature is blinded: with the
  caller's RNG, or, for `sign_deterministic`, with a ChaCha20 RNG keyed by
  SHA-256(d ‖ digest). That reduces the leak but doesn't remove it.
- `rsa` is pinned to `=0.10.0-rc.19` (#9), so EC/RSA `generate_from_seed`
  output is only stable for this dependency set.
- Unoptimized ML-DSA keys are large on the stack (~100 KiB for an
  expanded ML-DSA-87 key). Keep constructors in small frames.
