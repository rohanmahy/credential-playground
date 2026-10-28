"""Converts `openssl pkey -text -noout` dumps (<name>.txt) into <name>.json.

Usage: python3 -I openssl_text_to_json.py testdata/keys/openssl

Every output value is lowercase hex. EC public points are split into
fixed-width x and y; RSA integers have leading zero bytes removed.
"""

import json
import pathlib
import re
import sys

FIELD = re.compile(r"^([A-Za-z0-9]+):\s*(.*)$")


def sections(text):
    """Maps each `name:` header to the hex bytes listed under it."""
    out = {}
    name = None
    for line in text.splitlines():
        if line.startswith("    ") and name:
            out[name] += line.strip().replace(":", "")
            continue
        m = FIELD.match(line)
        name = None
        if m:
            name, rest = m.group(1), m.group(2)
            out[name] = ""
            # e.g. "publicExponent: 65537 (0x10001)"
            hx = re.search(r"\(0x([0-9a-f]+)\)", rest)
            if hx:
                v = hx.group(1)
                out[name] = ("0" * (len(v) % 2)) + v
    return out


def strip(h):
    b = bytes.fromhex(h).lstrip(b"\0")
    return b.hex()


def convert(path):
    text = path.read_text()
    s = sections(text)
    stem = path.stem
    if stem.startswith("p"):
        curve = {"p256": "P-256", "p384": "P-384", "p521": "P-521"}[stem]
        flen = {"p256": 32, "p384": 48, "p521": 66}[stem]
        pub = bytes.fromhex(s["pub"])
        assert pub[0] == 4 and len(pub) == 1 + 2 * flen
        d = bytes.fromhex(s["priv"]).rjust(flen, b"\0")
        return {
            "kty": "EC",
            "crv": curve,
            "d": d.hex(),
            "x": pub[1 : 1 + flen].hex(),
            "y": pub[1 + flen :].hex(),
        }
    if stem == "ed25519":
        return {"kty": "OKP", "crv": "Ed25519", "d": s["priv"], "x": s["pub"]}
    if stem.startswith("rsa"):
        names = {
            "modulus": "n",
            "publicExponent": "e",
            "privateExponent": "d",
            "prime1": "p",
            "prime2": "q",
            "exponent1": "dp",
            "exponent2": "dq",
            "coefficient": "qi",
        }
        out = {"kty": "RSA", "bits": int(stem[3:])}
        for k, v in names.items():
            out[v] = strip(s[k])
        return out
    if stem.startswith("mldsa"):
        return {
            "kty": "AKP",
            "alg": "ML-DSA-" + stem[5:],
            "seed": s["seed"],
            "expanded": s["priv"],
            "pub": s["pub"],
        }
    raise ValueError(stem)


def main():
    out = pathlib.Path(sys.argv[1])
    for txt in sorted(out.glob("*.txt")):
        data = convert(txt)
        txt.with_suffix(".json").write_text(json.dumps(data, indent=1) + "\n")


if __name__ == "__main__":
    main()
