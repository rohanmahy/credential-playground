# RFC known-answer vectors

| File | Source | How |
|---|---|---|
| `rfc7515-jws.json` | RFC 7515 Appendix A.2 (RS256), A.3 (ES256), A.4 (ES512) | transcribed by hand; JWK fields base64url, `signing_input` ASCII |
| `rfc8037-ed25519.json` | RFC 8037 Appendix A.1 and A.4 | transcribed by hand |
| `rfc6979-ecdsa.json` | RFC 6979 Appendix A.2.5–A.2.7, only P-256/SHA-256, P-384/SHA-384, P-521/SHA-512 | `crates/tokenator-crypto/scripts/extract_rfc_kat.py`; P-521 values left-padded to 66 bytes |
| `rfc8032-ed25519.json` | RFC 8032 Section 7.1 (TEST 1, 2, 3, 1024, SHA(abc)) | `extract_rfc_kat.py` |

RFC text from <https://www.rfc-editor.org/rfc/rfcNNNN.txt>.
