#!/usr/bin/env python3
"""Extract known-answer vectors from RFC 6979 (A.2.5-A.2.7) and RFC 8032 (7.1).

Usage: python3 -I extract_rfc_kat.py RFC6979_TXT RFC8032_TXT OUT_DIR

Only the curve/hash pairings used by JOSE/COSE are kept for RFC 6979:
P-256/SHA-256 (ES256), P-384/SHA-384 (ES384), P-521/SHA-512 (ES512).
"""
import json
import re
import sys

PAGE_NOISE = re.compile(r"^(RFC \d+|Pornin|Josefsson & Liusvaara) .*|^\f")


def clean(path):
    return [l for l in open(path, encoding="utf-8").read().splitlines()
            if not PAGE_NOISE.match(l)]


def hex_after(lines, i):
    """Collect a hex value starting on line i after '=' and continuing."""
    first = lines[i].split("=", 1)[1].strip()
    out = first
    j = i + 1
    while j < len(lines) and re.fullmatch(r"\s+[0-9A-F]+", lines[j]) and "=" not in lines[j]:
        out += lines[j].strip()
        j += 1
    return out.lower()


def rfc6979(path):
    lines = clean(path)
    sections = {"A.2.5.": ("P-256", "SHA-256", "ES256"),
                "A.2.6.": ("P-384", "SHA-384", "ES384"),
                "A.2.7.": ("P-521", "SHA-512", "ES512")}
    out = []
    cur = None
    key = {}
    want_hash = None
    msg = None
    sig = {}
    for i, l in enumerate(lines):
        m = re.match(r"^(A\.2\.\d+\.)", l)
        if m:
            cur = sections.get(m.group(1))
            key = {}
            continue
        if cur is None:
            continue
        s = l.strip()
        if s.startswith("x = "):
            key["d"] = hex_after(lines, i)
        elif s.startswith("Ux = "):
            key["x"] = hex_after(lines, i)
        elif s.startswith("Uy = "):
            key["y"] = hex_after(lines, i)
        m = re.match(r'With (SHA-\d+), message = "(\w+)":', s)
        if m:
            want_hash = m.group(1)
            msg = m.group(2)
            sig = {}
            continue
        if want_hash == cur[1] and re.match(r"^[krs] = ", s):
            sig[s[0]] = hex_after(lines, i)
            if len(sig) == 3:
                # JOSE/COSE use fixed-width big-endian values (66 bytes for P-521).
                width = {"P-256": 64, "P-384": 96, "P-521": 132}[cur[0]]
                pad = lambda h: h.rjust(width, "0")
                out.append({"alg": cur[2], "curve": cur[0], "hash": want_hash,
                            "d": pad(key["d"]), "x": pad(key["x"]), "y": pad(key["y"]),
                            "msg": msg, "k": sig["k"], "r": pad(sig["r"]), "s": pad(sig["s"])})
                want_hash = None
    return out


def rfc8032(path):
    lines = clean(path)
    start = next(i for i, l in enumerate(lines) if l.startswith("7.1.  Test Vectors for Ed25519"))
    end = next(i for i, l in enumerate(lines) if l.startswith("7.2."))
    out = []
    cur = None
    field = None
    for l in lines[start:end]:
        s = l.strip()
        if s.startswith("-----TEST"):
            if cur:
                out.append(cur)
            cur = {"name": s[len("-----TEST "):], "secret": "", "public": "", "msg": "", "sig": ""}
            field = None
            continue
        if s == "-----" and cur:
            out.append(cur)
            cur = None
            continue
        if cur is None:
            continue
        if s.startswith("SECRET KEY"):
            field = "secret"
        elif s.startswith("PUBLIC KEY"):
            field = "public"
        elif s.startswith("MESSAGE"):
            field = "msg"
        elif s.startswith("SIGNATURE"):
            field = "sig"
        elif s.startswith("ALGORITHM") or s == "Ed25519":
            field = None
        elif field and re.fullmatch(r"[0-9a-f]+", s):
            cur[field] += s
    return out


def main(r6979, r8032, out_dir):
    a = rfc6979(r6979)
    b = rfc8032(r8032)
    assert len(a) == 6, a
    assert len(b) == 5, b
    with open(f"{out_dir}/rfc6979-ecdsa.json", "w") as f:
        json.dump({"source": "RFC 6979 Appendix A.2.5-A.2.7 (JOSE curve/hash pairs)",
                   "vectors": a}, f, indent=1)
        f.write("\n")
    with open(f"{out_dir}/rfc8032-ed25519.json", "w") as f:
        json.dump({"source": "RFC 8032 Section 7.1", "vectors": b}, f, indent=1)
        f.write("\n")
    for v in a:
        print(v["alg"], v["msg"], len(v["d"]), len(v["r"]), len(v["s"]))
    for v in b:
        print(v["name"], len(v["secret"]), len(v["public"]), len(v["msg"]), len(v["sig"]))


if __name__ == "__main__":
    main(*sys.argv[1:4])
