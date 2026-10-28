"""Extracts the RFC key examples used by the tokenator-keys tests.

Usage (from the repository root, RFC texts from
https://www.rfc-editor.org/rfc/rfcNNNN.txt in RFCDIR):

    python3 -I crates/tokenator-keys/scripts/make_rfc_fixtures.py RFCDIR testdata/keys

Writes:
  rfc9881/   PEM examples of RFC 9881 Appendix C.1 (seed / expanded / both),
             C.2 (public keys), and C.4 (inconsistent private keys).
  rfc7517/   JWK Sets of RFC 7517 Appendix A.1-A.3 and the JWK of Appendix B.
  rfc7638/   the RFC 7638 Section 3.1 JWK.
  rfc8037/   the RFC 8037 Appendix A.1 / A.2 JWKs.
  rfc8152/   the COSE_KeySets of RFC 8152 Appendix C.7.1 / C.7.2 (binary CBOR).
  rfc9679/   the RFC 9679 Section 6 COSE_Key (binary CBOR).
  rfc9964/   the RFC 9964 Appendix A JWKs (private and public) and COSE_Keys
             (binary CBOR, private and public), built from testdata/rfc9964.
"""

import json
import pathlib
import re
import sys

PAGE_LINE = re.compile(r"^(RFC \d{4} .*|.*\[Page \d+\])$")


def rfc_lines(rfcdir, n):
    text = (rfcdir / f"rfc{n}.txt").read_text()
    return [l for l in text.replace("\f", "").splitlines() if not PAGE_LINE.match(l)]


def pem_blocks(lines, start, end):
    """All PEM blocks between the first line equal to `start` and `end`."""
    blocks, cur = [], None
    body = lines[lines.index(start) : lines.index(end)] if end else lines[lines.index(start) :]
    for l in body:
        s = l.strip()
        if s.startswith("-----BEGIN "):
            cur = [s]
        elif cur is not None and s:
            cur.append(s)
            if s.startswith("-----END "):
                blocks.append("\n".join(cur) + "\n")
                cur = None
    return blocks


def json_block(lines, first, last):
    """Joins the lines from `first` through `last` (prefix matches), each
    stripped, which undoes the RFC's line breaks inside values."""
    i = next(k for k, l in enumerate(lines) if l.strip().startswith(first))
    j = next(k for k in range(i, len(lines)) if lines[k].strip().startswith(last))
    return "".join(l.strip() for l in lines[i : j + 1])


# --- minimal deterministic CBOR encoder for maps of int -> int/bytes ---


def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | ai]) + n.to_bytes(size, "big")
    raise ValueError(n)


def cbor(v):
    if isinstance(v, bool):
        return b"\xf5" if v else b"\xf4"
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode()
        return head(3, len(b)) + b
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):  # insertion order is kept (arrival order)
        return head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())
    raise TypeError(v)


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data)
    else:
        path.write_bytes(data)


def rfc9881(rfcdir, out):
    lines = rfc_lines(rfcdir, 9881)
    names = []
    for p in ("44", "65", "87"):
        names += [f"ml-dsa-{p}-seed", f"ml-dsa-{p}-expanded", f"ml-dsa-{p}-both"]
    priv = pem_blocks(lines, "C.1.  Example Private Keys", "C.2.  Example Public Keys")
    assert len(priv) == 9, len(priv)
    for name, pem in zip(names, priv):
        write(out / "rfc9881" / f"{name}.pem", pem)
    pub = pem_blocks(lines, "C.2.  Example Public Keys", "C.3.  Example Certificates")
    assert len(pub) == 3, len(pub)
    for p, pem in zip(("44", "65", "87"), pub):
        write(out / "rfc9881" / f"ml-dsa-{p}-public.pem", pem)
    bad = pem_blocks(lines, "C.4.  Example Inconsistent Seed and Expanded Private Keys", None)
    bad = [b for b in bad if "PRIVATE KEY" in b][:3]
    assert len(bad) == 3, len(bad)
    for i, pem in enumerate(bad, 1):
        write(out / "rfc9881" / f"ml-dsa-44-inconsistent-{i}.pem", pem)


def rfc7517(rfcdir, out):
    lines = rfc_lines(rfcdir, 7517)
    a1 = lines.index("A.1.  Example Public Keys")
    a2 = lines.index("A.2.  Example Private Keys")
    a3 = lines.index("A.3.  Example Symmetric Keys")
    b = lines.index('Appendix B.  Example Use of "x5c" (X.509 Certificate Chain) Parameter')
    for name, sub, end in (
        ("a1-public-set", lines[a1:a2], "}"),
        ("a2-private-set", lines[a2:a3], "}"),
        ("a3-symmetric-set", lines[a3:b], "}"),
    ):
        text = json_block(sub, '{"keys":', "]") + "}"
        json.loads(text)
        write(out / "rfc7517" / f"{name}.json", text + "\n")
    text = json_block(lines[b:], '{"kty":"RSA",', '"e":"AQAB",')
    sub = lines[b:]
    k = next(i for i, l in enumerate(sub) if l.strip().startswith('"x5c":'))
    rest = "".join(l.strip() for l in sub[k : k + 40])
    rest = rest[: rest.index('=="]') + 4] + "}"
    text += rest
    json.loads(text)
    write(out / "rfc7517" / "b-x5c.json", text + "\n")


def rfc7638(rfcdir, out):
    lines = rfc_lines(rfcdir, 7638)
    s = lines.index("3.1.  Example JWK Thumbprint Computation")
    sub = lines[s:]
    i = next(k for k, l in enumerate(sub) if l.strip() == "{")
    j = next(k for k in range(i, len(sub)) if sub[k].strip() == "}")
    # Keep the RFC's member order and spacing style, minus the line breaks.
    text = "".join(l.strip() for l in sub[i : j + 1])
    text = text.replace('":"', '": "').replace('","', '", "')
    json.loads(text)
    write(out / "rfc7638" / "rsa.json", text + "\n")


def rfc8037(rfcdir, out):
    lines = rfc_lines(rfcdir, 8037)
    a1 = lines.index("A.1.  Ed25519 Private Key")
    a2 = lines.index("A.2.  Ed25519 Public Key")
    priv = json_block(lines[a1:], '{"kty":"OKP"', '"x":')
    pub = json_block(lines[a2:], '{"kty":"OKP"', '"x":')
    json.loads(priv)
    json.loads(pub)
    write(out / "rfc8037" / "ed25519-private.json", priv + "\n")
    write(out / "rfc8037" / "ed25519-public.json", pub + "\n")


def h(s):
    return bytes.fromhex(s)


RFC8152_X = {
    "meriadoc": (
        "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d",
        "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c",
        "aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf",
    ),
    "11": (
        "bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff",
        "20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e",
        "57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3",
    ),
    "bilbo": (
        "0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad",
        "01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475",
        "00085138ddabf5ca975f5860f91a08e91d6d5f9a76ad4018766a476680b55cd339e8ab6c72b5facdb2a2a50ac25bd086647dd3e2e6e99e84ca2c3609fdf177feb26d",
    ),
    "peregrin": (
        "98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280",
        "f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb",
        "02d1f7e6f26c43d4868d87ceb2353161740aacf1f7163647984b522a848df1c3",
    ),
}


def rfc8152(rfcdir, out):
    # Transcribed from RFC 8152 Appendix C.7 (same text in the RFC 9052
    # examples repository); the map entry order follows the RFC.
    lines = rfc_lines(rfcdir, 8152)
    assert "C.7.1.  Public Keys" in lines
    m, e, b, p = (RFC8152_X[k] for k in ("meriadoc", "11", "bilbo", "peregrin"))
    public = [
        {-1: 1, -2: h(m[0]), -3: h(m[1]), 1: 2, 2: b"meriadoc.brandybuck@buckland.example"},
        {-1: 1, -2: h(e[0]), -3: h(e[1]), 1: 2, 2: b"11"},
        {-1: 3, -2: h(b[0]), -3: h(b[1]), 1: 2, 2: b"bilbo.baggins@hobbiton.example"},
        {-1: 1, -2: h(p[0]), -3: h(p[1]), 1: 2, 2: b"peregrin.took@tuckborough.example"},
    ]
    data = cbor(public)
    assert len(data) == 481, len(data)
    write(out / "rfc8152" / "c7-1-public-keyset.cbor", data)
    secret = "849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188"
    private = [
        {1: 2, 2: b"meriadoc.brandybuck@buckland.example", -1: 1, -2: h(m[0]), -3: h(m[1]), -4: h(m[2])},
        {1: 2, 2: b"11", -1: 1, -2: h(e[0]), -3: h(e[1]), -4: h(e[2])},
        {1: 2, 2: b"bilbo.baggins@hobbiton.example", -1: 3, -2: h(b[0]), -3: h(b[1]), -4: h(b[2])},
        {1: 4, 2: b"our-secret", -1: h(secret)},
        {1: 2, -1: 1, 2: b"peregrin.took@tuckborough.example", -2: h(p[0]), -3: h(p[1]), -4: h(p[2])},
        {1: 4, 2: b"our-secret2", -1: h("849b5786457c1491be3a76dcea6c4271")},
        {1: 4, 2: b"018c0ae5-4d9b-471b-bfd6-eef314bc7037", -1: h(secret)},
    ]
    data = cbor(private)
    assert len(data) == 816, len(data)
    write(out / "rfc8152" / "c7-2-private-keyset.cbor", data)


def rfc9679(rfcdir, out):
    lines = rfc_lines(rfcdir, 9679)
    i = next(k for k, l in enumerate(lines) if l.strip().startswith("A50102200121582065EDA5A1"))
    hexs = "".join(l.strip() for l in lines[i : i + 4])
    data = bytes.fromhex(hexs)
    assert data[0] == 0xA5 and len(data) == 110, len(data)
    write(out / "rfc9679" / "ec2-p256.cbor", data)


def rfc9964(src, out):
    import base64

    def b64u(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    for p, label in (("44", -48), ("65", -49), ("87", -50)):
        jose = json.loads((src / f"ml-dsa-{p}-jose.json").read_text())
        cose = json.loads((src / f"ml-dsa-{p}-cose.json").read_text())
        pub = bytes.fromhex(jose["raw_public_key"])
        seed = bytes.fromhex(jose["priv"])
        hdr = json.loads(base64.urlsafe_b64decode(jose["jws"].split(".")[0] + "=="))
        jwk = {"kid": hdr["kid"], "kty": "AKP", "alg": f"ML-DSA-{p}", "pub": b64u(pub), "priv": b64u(seed)}
        write(out / "rfc9964" / f"ml-dsa-{p}-private.jwk.json", json.dumps(jwk, indent=2) + "\n")
        del jwk["priv"]
        write(out / "rfc9964" / f"ml-dsa-{p}-public.jwk.json", json.dumps(jwk, indent=2) + "\n")
        key = bytes.fromhex(cose["key"])
        # The RFC's COSE_Key is the private key {2: kid, 1: 7, 3: alg, -1: pub, -2: priv}.
        kid = key[4:36]
        assert key == cbor({2: kid, 1: 7, 3: label, -1: pub, -2: seed})
        write(out / "rfc9964" / f"ml-dsa-{p}-private.cbor", key)
        write(out / "rfc9964" / f"ml-dsa-{p}-public.cbor", cbor({2: kid, 1: 7, 3: label, -1: pub}))


def main():
    rfcdir = pathlib.Path(sys.argv[1])
    out = pathlib.Path(sys.argv[2])
    rfc9881(rfcdir, out)
    rfc7517(rfcdir, out)
    rfc7638(rfcdir, out)
    rfc8037(rfcdir, out)
    rfc8152(rfcdir, out)
    rfc9679(rfcdir, out)
    rfc9964(out.parent / "rfc9964", out)


if __name__ == "__main__":
    main()
