# Token fixtures

Credentials copied byte-for-byte from published specifications. Line breaks
that the RFCs add "for display purposes only" have been removed. JSON examples
whose string values were wrapped have been re-joined, but keep the RFC's
indentation and member order. Text files end with a single `\n`.

Files named `derived-*` are not in the source document. Each is a mechanical
transformation of a published example, described below.

| File | Source |
|---|---|
| `rfc7519-s3.1-jwt-hs256.txt` | RFC 7519 §3.1, example JWT (HS256) |
| `rfc7519-s3.1-claims.json` | RFC 7519 §3.1, example JWT Claims Set (unsigned JSON claim set) |
| `rfc7519-s6.1-unsecured-jwt.txt` | RFC 7519 §6.1, Unsecured JWT (`alg: none`, empty signature) |
| `rfc7515-a1-jws-hs256.txt` | RFC 7515 A.1, JWS Compact (HS256) |
| `rfc7515-a2-jws-rs256.txt` | RFC 7515 A.2, JWS Compact (RS256) |
| `rfc7515-a3-jws-es256.txt` | RFC 7515 A.3, JWS Compact (ES256) |
| `rfc7515-a4-jws-es512-nonjson-payload.txt` | RFC 7515 A.4, JWS Compact (ES512) whose payload is the text `Payload` (not a JWT) |
| `rfc7515-a5-unsecured-jws.txt` | RFC 7515 A.5, Unsecured JWS |
| `rfc7515-a6-jws-json-general.json` | RFC 7515 A.6.4, General JWS JSON Serialization (two signatures) |
| `rfc7515-a7-jws-json-flattened.json` | RFC 7515 A.7, Flattened JWS JSON Serialization |
| `rfc9901-s5.1-input-claims.json` | RFC 9901 §5.1, input JWT Claims Set (unsigned JSON claim set) |
| `rfc9901-s5.1-issuer-signed-jwt.txt` | RFC 9901 §5.1, Issuer-signed JWT (with `_sd`, before disclosures are appended) |
| `rfc9901-s5.1-sd-jwt.txt` | RFC 9901 §5.1, SD-JWT with all ten disclosures, no KB-JWT (ends with `~`) |
| `rfc9901-s5.2-sd-jwt-kb.txt` | RFC 9901 §5.2, SD-JWT+KB presentation (four disclosures and a KB-JWT) |
| `rfc9901-s8.2-sd-jwt-json-flattened.json` | RFC 9901 §8.2, Flattened JWS JSON SD-JWT (no KB-JWT) |
| `rfc9901-s8.2-sd-jwt-kb-json-flattened.json` | RFC 9901 §8.2, Flattened JWS JSON SD-JWT+KB |
| `rfc9901-s8.3-sd-jwt-kb-json-general.json` | RFC 9901 §8.3, General JWS JSON SD-JWT+KB (two signatures) |
| `rfc9901-s5.2-processed-payload.json` | RFC 9901 §5.2, Processed SD-JWT Payload of the §5.2 presentation |
| `rfc9901-a1-presentation.txt` | RFC 9901 A.1, SD-JWT presentation (region and country only, no KB-JWT); the payload has decoy digests |
| `rfc9901-a1-processed-payload.json` | RFC 9901 A.1, its Processed SD-JWT Payload |
| `rfc9901-a2-presentation.txt` | RFC 9901 A.2, SD-JWT presentation with recursive disclosures inside an array element (no KB-JWT) |
| `rfc9901-a2-processed-payload.json` | RFC 9901 A.2, its Processed SD-JWT Payload |
| `rfc9901-a3-sd-jwt.txt` | RFC 9901 A.3, issued SD-JWT VC (`typ: dc+sd-jwt`, 27 disclosures) |
| `rfc9901-a3-sd-jwt-kb.txt` | RFC 9901 A.3, SD-JWT+KB disclosing `nationalities` and `age_equal_or_over/18` |
| `rfc9901-a3-processed-payload.json` | RFC 9901 A.3, Processed SD-JWT Payload of the SD-JWT+KB |
| `rfc9901-a4-sd-jwt.txt` | RFC 9901 A.4, issued SD-JWT (W3C VC data model, 14 disclosures) |
| `rfc9901-a4-sd-jwt-kb.txt` | RFC 9901 A.4, SD-JWT+KB with four disclosures |
| `rfc9901-a4-processed-payload.json` | RFC 9901 A.4, Processed SD-JWT Payload of the SD-JWT+KB |
| `rfc9901-s6-input-claims.json` | RFC 9901 §6, input claims for the nested-data examples |
| `rfc9901-s6.1-payload.json`, `rfc9901-s6.2-payload.json`, `rfc9901-s6.3-payload.json` | RFC 9901 §6.1–6.3, SD-JWT payloads (flat, structured, recursive); the RFC gives no signed JWT for these |
| `rfc9901-s6.2-payload-country-plain.json` | RFC 9901 §6.2, the variant with `country` permanently disclosed |
| `rfc9901-disclosures.json` | Every "SHA-256 Hash" / "Disclosure" pair listed in RFC 9901 §5.1, §6.1–6.3 and A.1–A.4 (87 entries: `section`, `claim` label, `digest`, `disclosure`) |

The `rfc9901-s5.2-*`, `rfc9901-s6*`, `rfc9901-a*` and `rfc9901-disclosures.json` files were extracted by
`python3 -I crates/tokenator-jose/scripts/extract_rfc9901.py rfc9901.txt testdata/tokens`
and cross-checked with OpenSSL: every issuer signature verifies with the A.5
key (`testdata/keys/rfc9901-a5-ec-p256-public.jwk.json`), every disclosure
digest appears in the payload or another disclosure, every listed digest is the SHA-256 of its disclosure, and every KB-JWT
verifies with the `cnf` key and has a matching `sd_hash`. In
`rfc9901-s8.3-sd-jwt-kb-json-general.json` only the first signature
(`kid: issuer-key-1`) verifies with the A.5 key; the key for the second
(`issuer-key-2`) is not published.
| `rfc8392-a1-claims.cbor` | RFC 8392 A.1, CWT Claims Set (binary CBOR map) |
| `rfc8392-a3-signed-cwt.cbor` | RFC 8392 A.3, signed CWT: COSE_Sign1 with tag 18 (binary) |
| `rfc8392-a3-signed-cwt.hex` | RFC 8392 A.3, the same as hex text, with the RFC's line breaks (65 hex digits per line, breaking mid-byte) |
| `rfc8392-a4-maced-cwt-tag61.cbor` | RFC 8392 A.4, MACed CWT: tag 61 + tag 17 COSE_Mac0 (unsupported, must not be classified as COSE_Sign1) |
| `derived-rfc8392-a3-untagged.cbor` | RFC 8392 A.3 with the leading tag-18 byte `d2` removed (untagged COSE_Sign1) |
| `derived-rfc8392-a3-tag61.cbor` | RFC 8392 A.3 with the CWT tag head `d8 3d` prepended (tag 61 + tag 18) |
| `rfc9052-c2.1-sign1.cbor` | RFC 9052 C.2.1, COSE_Sign1 whose payload is the text `This is the content.` (not a CWT). Encoded from the RFC's EDN; 98 bytes as the RFC states |
| `sd-cwt-08-issuer-sd-cwt.cbor` | draft-ietf-spice-sd-cwt-08 §14.1, issuer SD-CWT (all disclosures in `sd_claims`), from `examples/issuer_cwt.cbor` in [the draft repository](https://github.com/ietf-wg-spice/draft-ietf-spice-sd-cwt) |
| `sd-cwt-08-sd-kbt.cbor` | draft-ietf-spice-sd-cwt-08 §14.1 Figure 26, SD-KBT wrapping the SD-CWT in `kcwt`, from `examples/kbt.cbor`. Both signatures match the -08 text |
| `sd-cwt-08-nested-issuer-sd-cwt.cbor` | draft-ietf-spice-sd-cwt-08 §14.2, nested issuer SD-CWT, from `examples/nested_issuer_cwt.cbor` |
| `sd-cwt-08-nested-sd-kbt.cbor` | draft-ietf-spice-sd-cwt-08 §14.2, nested SD-KBT, from `examples/nested_kbt.cbor` |
| `sd-cwt-08-fig4-claims.edn` | draft-ietf-spice-sd-cwt-08 §3.1 Figure 4, CWT claims set in EDN (comments, integer keys, `h''`, trailing commas) |

The draft repository has no `-08` tag. The CBOR files were taken from `main`
and checked against the `-08` text: the SD-KBT's issuer and KBT signatures
(`12bdb013…`, `ca38c411…`) match Figure 26.
