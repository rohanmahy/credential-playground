#!/bin/sh
# Regenerates testdata/keys/openssl/ with OpenSSL (>= 3.5 for ML-DSA).
# Run from the repository root:
#   sh crates/tokenator-keys/scripts/make_openssl_fixtures.sh
# The fixtures are committed; tokenator-keys itself never uses OpenSSL.
# EC and RSA keys are random, so rerunning changes every file except ML-DSA.
set -eu

OPENSSL=${OPENSSL:-openssl}
OUT=testdata/keys/openssl
SCRIPTS=crates/tokenator-keys/scripts
UNS="$OUT/unsupported"
mkdir -p "$OUT" "$UNS"

for curve in P-256 P-384 P-521; do
  n=$(echo "$curve" | tr -d '-' | tr 'P' 'p')
  "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:"$curve" -out "$OUT/$n-pkcs8.pem"
  "$OPENSSL" ec -in "$OUT/$n-pkcs8.pem" -out "$OUT/$n-sec1.pem"
  "$OPENSSL" ec -in "$OUT/$n-pkcs8.pem" -no_public -out "$OUT/$n-sec1-nopub.pem"
  "$OPENSSL" pkey -in "$OUT/$n-pkcs8.pem" -pubout -out "$OUT/$n-spki.pem"
  "$OPENSSL" pkey -in "$OUT/$n-pkcs8.pem" -text -noout > "$OUT/$n.txt"
done
# Unsupported: explicit curve parameters instead of a named curve.
"$OPENSSL" ec -in "$OUT/p256-pkcs8.pem" -param_enc explicit -out "$UNS/p256-sec1-explicit.pem"

"$OPENSSL" genpkey -algorithm ED25519 -out "$OUT/ed25519-pkcs8.pem"
"$OPENSSL" pkey -in "$OUT/ed25519-pkcs8.pem" -pubout -out "$OUT/ed25519-spki.pem"
"$OPENSSL" pkey -in "$OUT/ed25519-pkcs8.pem" -text -noout > "$OUT/ed25519.txt"

for bits in 2048 3072 4096; do
  "$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:"$bits" -out "$OUT/rsa$bits-pkcs8.pem"
  "$OPENSSL" rsa -in "$OUT/rsa$bits-pkcs8.pem" -traditional -out "$OUT/rsa$bits-pkcs1.pem"
  "$OPENSSL" rsa -in "$OUT/rsa$bits-pkcs8.pem" -RSAPublicKey_out -out "$OUT/rsa$bits-pkcs1-pub.pem"
  "$OPENSSL" pkey -in "$OUT/rsa$bits-pkcs8.pem" -pubout -out "$OUT/rsa$bits-spki.pem"
  "$OPENSSL" pkey -in "$OUT/rsa$bits-pkcs8.pem" -text -noout > "$OUT/rsa$bits.txt"
done
# Unsupported: an encrypted PKCS#8 private key (password "tokenator").
"$OPENSSL" pkcs8 -topk8 -in "$OUT/p256-pkcs8.pem" -v2 aes-128-cbc -passout pass:tokenator \
  -out "$UNS/p256-pkcs8-encrypted.pem"

# ML-DSA seeds are SHA-256("tokenator ml-dsa-NN") so these files are stable.
for p in 44 65 87; do
  seed=$(printf 'tokenator ml-dsa-%s' "$p" | "$OPENSSL" dgst -sha256 -r | cut -d' ' -f1)
  "$OPENSSL" genpkey -algorithm "ML-DSA-$p" -pkeyopt hexseed:"$seed" -out "$OUT/mldsa$p-tmp.pem"
  "$OPENSSL" pkey -in "$OUT/mldsa$p-tmp.pem" -provparam ml-dsa.output_formats=seed-only -out "$OUT/mldsa$p-seed.pem"
  "$OPENSSL" pkey -in "$OUT/mldsa$p-tmp.pem" -provparam ml-dsa.output_formats=priv-only -out "$OUT/mldsa$p-expanded.pem"
  "$OPENSSL" pkey -in "$OUT/mldsa$p-tmp.pem" -provparam ml-dsa.output_formats=seed-priv -out "$OUT/mldsa$p-both.pem"
  "$OPENSSL" pkey -in "$OUT/mldsa$p-tmp.pem" -pubout -out "$OUT/mldsa$p-spki.pem"
  "$OPENSSL" pkey -in "$OUT/mldsa$p-tmp.pem" -text -noout > "$OUT/mldsa$p.txt"
  rm "$OUT/mldsa$p-tmp.pem"
done

# Keys tokenator-keys must reject or treat specially.
"$OPENSSL" genpkey -algorithm X25519 -out "$UNS/x25519-pkcs8.pem"
"$OPENSSL" genpkey -algorithm ED448 -out "$UNS/ed448-pkcs8.pem"
"$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp256k1 -out "$UNS/secp256k1-pkcs8.pem"
"$OPENSSL" pkey -in "$UNS/secp256k1-pkcs8.pem" -pubout -out "$UNS/secp256k1-spki.pem"
"$OPENSSL" req -x509 -key "$OUT/p256-pkcs8.pem" -subj /CN=tokenator -days 1 -out "$UNS/p256-cert.pem"
# Accepted as plain RSA: an RSASSA-PSS (id-RSASSA-PSS OID) key.
"$OPENSSL" genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -out "$OUT/rsapss2048-pkcs8.pem"
"$OPENSSL" pkey -in "$OUT/rsapss2048-pkcs8.pem" -pubout -out "$OUT/rsapss2048-spki.pem"
# "EC PARAMETERS" block followed by "EC PRIVATE KEY" (openssl ecparam -genkey).
"$OPENSSL" ecparam -name prime256v1 -genkey -out "$OUT/p256-ecparam-genkey.pem"

# Turn the -text dumps into <name>.json files of hex components.
python3 -I "$SCRIPTS/openssl_text_to_json.py" "$OUT"
rm "$OUT"/*.txt
