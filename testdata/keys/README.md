# Key fixtures

Keys copied from published specifications. These are public test keys. Never
use them for anything real. Wrapped JSON string values have been re-joined.
Text files end with a single `\n`.

| File | Source |
|---|---|
| `rfc7517-a1-public.jwks.json` | RFC 7517 A.1, JWK Set with EC and RSA public keys |
| `rfc7517-a2-private.jwks.json` | RFC 7517 A.2, JWK Set with EC and RSA private keys |
| `rfc7517-a3-symmetric.jwks.json` | RFC 7517 A.3, JWK Set with two `oct` keys |
| `rfc9901-a5-ec-p256-public.jwk.json` | RFC 9901 A.5, issuer EC P-256 public JWK |
| `sd-cwt-08-c1-holder-private.jwk.json` | draft-ietf-spice-sd-cwt-08 C.1, holder EC P-256 private JWK |
| `sd-cwt-08-c1-holder-private.cosekey.cbor` | draft-ietf-spice-sd-cwt-08 C.1, holder COSE_Key, encoded from the EDN in arrival order |
| `rfc8392-a2.1-symmetric128.cosekey.cbor` | RFC 8392 A.2.1, symmetric COSE_Key. Its last byte is `0x0a` (alg 10), which a naive whitespace trim would strip |
| `rfc8392-a2.3-ec-p256.cosekey.cbor` | RFC 8392 A.2.3, EC2 P-256 private COSE_Key |
| `rfc8152-c7.1-public.cosekeyset.cbor` | RFC 8152 / RFC 9052 C.7.1, public COSE_KeySet (four EC2 keys), encoded from the EDN; 481 bytes as the RFC states |
| `sd-cwt-08-c1-holder-public.pem` | draft-ietf-spice-sd-cwt-08 C.1, `PUBLIC KEY` (SPKI, P-256) |
| `sd-cwt-08-c1-holder-private.pem` | draft-ietf-spice-sd-cwt-08 C.1, `PRIVATE KEY` (PKCS#8, P-256) |
| `derived-sd-cwt-08-c1-holder-private.sec1.pem` | The C.1 holder key converted to SEC1 `EC PRIVATE KEY` with `openssl ec` |
| `rfc8410-s10.1-ed25519-public.pem` | RFC 8410 §10.1, Ed25519 `PUBLIC KEY` |
| `rfc8410-s10.2-x25519-cert.pem` | RFC 8410 §10.2, `CERTIFICATE` |
| `rfc8410-s10.3-ed25519-private.pem` | RFC 8410 §10.3, Ed25519 `PRIVATE KEY` (first example, without the public key) |
