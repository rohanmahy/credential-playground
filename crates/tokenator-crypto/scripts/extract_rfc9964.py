#!/usr/bin/env python3
"""Extract the ML-DSA examples of RFC 9964 Appendix A into JSON test vectors.

Usage: python3 -I extract_rfc9964.py rfc9964.txt OUT_DIR

Each example is a JSON object whose long strings are wrapped across lines with
no indentation, so joining the lines of a figure reconstructs valid JSON.
"""
import json
import re
import sys


def main(src, out_dir):
    lines = open(src, encoding="utf-8-sig").read().splitlines()
    section = None
    block = None
    for line in lines:
        if line.startswith("A.1.  JOSE"):
            section = "jose"
        elif line.startswith("A.2.  COSE"):
            section = "cose"
        if section is None:
            continue
        if line == "{":
            block = []
        if block is not None:
            block.append(line)
        if line == "}" and block is not None:
            text = "".join(block)
            obj = json.loads(text)
            block = None
            pending = obj
            continue
        m = re.match(r"\s+Figure \d+: ML_DSA_(\d+)", line)
        if m:
            name = f"ml-dsa-{m.group(1)}-{section}.json"
            keep = {k: v for k, v in pending.items()
                    if k in ("priv", "raw_public_key", "raw_to_be_signed",
                             "raw_signature", "jws", "sign1", "key")}
            keep["source"] = f"RFC 9964 Appendix A ({section.upper()}), ML-DSA-{m.group(1)}"
            with open(f"{out_dir}/{name}", "w") as f:
                json.dump(keep, f, indent=1)
                f.write("\n")
            print(name, {k: len(v) for k, v in keep.items()})


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
