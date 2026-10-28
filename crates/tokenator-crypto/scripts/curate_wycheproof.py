#!/usr/bin/env python3
"""Curate a subset of Wycheproof testvectors_v1 files for tokenator-crypto.

Usage: python3 -I curate_wycheproof.py SRC_DIR OUT_DIR

- Drops the DER/PEM/ASN.1/PKCS#8 encodings (tokenator-crypto takes raw keys).
- ML-DSA: keeps only tests usable through JOSE/COSE, i.e. with an absent or
  empty context, no external-mu-only tests, and at most PER_KIND tests per
  (flags, result) pair to keep the repository small.
- Rewrites numberOfTests to match the kept tests.
"""
import collections
import json
import os
import sys

DROP = {"publicKeyDer", "publicKeyPem", "publicKeyAsn", "privateKeyPkcs8"}
PER_KIND = 4


def curate(path):
    d = json.load(open(path))
    mldsa = os.path.basename(path).startswith("mldsa_")
    seen = collections.Counter()
    total = 0
    groups = []
    for g in d["testGroups"]:
        for k in DROP:
            g.pop(k, None)
        tests = []
        for t in g["tests"]:
            if mldsa:
                if t.get("ctx", "") != "" or "msg" not in t:
                    continue
                kind = (tuple(t["flags"]), t["result"])
                if seen[kind] >= PER_KIND:
                    continue
                seen[kind] += 1
            tests.append(t)
        if tests:
            g["tests"] = tests
            groups.append(g)
            total += len(tests)
    d["testGroups"] = groups
    d["numberOfTests"] = total
    return d


def main(src, out):
    for name in sorted(os.listdir(src)):
        if not name.endswith(".json"):
            continue
        d = curate(os.path.join(src, name))
        with open(os.path.join(out, name), "w") as f:
            json.dump(d, f, indent=1)
            f.write("\n")
        print(name, d["numberOfTests"])


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
