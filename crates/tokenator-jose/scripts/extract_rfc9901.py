"""Extract RFC 9901 examples into testdata/tokens/.

Usage (from the repository root):

    python3 -I crates/tokenator-jose/scripts/extract_rfc9901.py RFC9901.TXT testdata/tokens

RFC9901.TXT is https://www.rfc-editor.org/rfc/rfc9901.txt. Tokens are
re-joined (the RFC breaks base64url "for display purposes only"); JSON
examples keep the RFC's indentation minus the 3-space margin. Every file
ends with a single newline.
"""

import os
import sys


def find(lines, needle, start):
    for i in range(start, len(lines)):
        if needle in lines[i]:
            return i
    raise SystemExit(f"not found after line {start}: {needle!r}")


def token_after(lines, i):
    """The first run of non-blank lines after line i, joined without spaces."""
    i += 1
    while not lines[i].strip():
        i += 1
    out = []
    while i < len(lines) and lines[i].strip():
        out.append(lines[i].strip())
        i += 1
    return "".join(out)


def json_after(lines, i):
    """The first `{ ... }` block after line i, dedented by its own indent."""
    i += 1
    while lines[i].strip() != "{":
        i += 1
    indent = len(lines[i]) - len(lines[i].lstrip())
    out = []
    while True:
        out.append(lines[i][indent:])
        if lines[i].rstrip() == " " * indent + "}":
            break
        i += 1
    return "\n".join(out)


def main():
    src, outdir = sys.argv[1], sys.argv[2]
    with open(src, encoding="utf-8") as f:
        lines = f.read().split("\n")

    files = {}
    s52 = find(lines, "5.2.  Presentation", 1000)
    files["rfc9901-s5.2-processed-payload.json"] = json_after(
        lines, find(lines, "the following Processed SD-", s52))

    a1 = find(lines, "A.1.  Simple Structured SD-JWT", 2900)
    files["rfc9901-a1-presentation.txt"] = token_after(
        lines, find(lines, "presentation of the SD-JWT that discloses only", a1) + 1)
    files["rfc9901-a1-processed-payload.json"] = json_after(
        lines, find(lines, "the following Processed SD-", a1))

    a2 = find(lines, "A.2.  Complex Structured SD-JWT", a1)
    files["rfc9901-a2-presentation.txt"] = token_after(
        lines, find(lines, "The following is a presentation of the SD-JWT:", a2))
    files["rfc9901-a2-processed-payload.json"] = json_after(
        lines, find(lines, "this Processed SD-JWT Payload available after", a2))

    a3 = find(lines, "A.3.  SD-JWT-Based Verifiable Credentials", a2)
    files["rfc9901-a3-sd-jwt.txt"] = token_after(
        lines, find(lines, "The following is the issued SD-JWT:", a3))
    files["rfc9901-a3-sd-jwt-kb.txt"] = token_after(
        lines, find(lines, "SD-JWT+KB that discloses only", a3) + 1)
    files["rfc9901-a3-processed-payload.json"] = json_after(
        lines, find(lines, "the following Processed SD-", a3))

    a4 = find(lines, "A.4.  W3C Verifiable Credentials", a3)
    files["rfc9901-a4-sd-jwt.txt"] = token_after(
        lines, find(lines, "The following is the issued SD-JWT:", a4))
    files["rfc9901-a4-sd-jwt-kb.txt"] = token_after(
        lines, find(lines, "SD-JWT+KB that discloses only type,", a4) + 2)
    files["rfc9901-a4-processed-payload.json"] = json_after(
        lines, find(lines, "the following Processed", a4))

    s6 = find(lines, "6.  Considerations on Nested Data", s52)
    s61 = find(lines, "6.1.  Example: Flat SD-JWT", s6)
    s62 = find(lines, "6.2.  Example: Structured SD-JWT", s61)
    s63 = find(lines, "6.3.  Example: SD-JWT with Recursive", s62)
    s7 = find(lines, "7.  Verification and Processing", s63)
    files["rfc9901-s6-input-claims.json"] = json_after(lines, s6)
    files["rfc9901-s6.1-payload.json"] = json_after(lines, s61)
    files["rfc9901-s6.2-payload.json"] = json_after(lines, s62)
    files["rfc9901-s6.2-payload-country-plain.json"] = json_after(
        lines, find(lines, "disclosed and hide only the other sub-claims", s62))
    files["rfc9901-s6.3-payload.json"] = json_after(lines, s63)

    files["rfc9901-a1-input-claims.json"] = json_after(
        lines, find(lines, "comprises the input JWT Claims Set", a1))
    files["rfc9901-a2-input-claims.json"] = json_after(
        lines, find(lines, "following user data as the input JWT Claims", a2))
    files["rfc9901-a3-input-claims.json"] = json_after(
        lines, find(lines, "citizen data is the input JWT Claims Set", a3))
    files["rfc9901-a4-input-claims.json"] = json_after(
        lines, find(lines, "The following is the input JWT Claims Set", a4))

    s51 = find(lines, "5.1.  Issuance", 980)
    a5 = find(lines, "A.5.  Elliptic Curve Key", a4)
    sections = [("5.1", s51, s52), ("6.1", s61, s62), ("6.2", s62, s63),
                ("6.3", s63, s7), ("A.1", a1, a2), ("A.2", a2, a3),
                ("A.3", a3, a4), ("A.4", a4, a5)]
    entries = []
    for sec, start, end in sections:
        label = None
        for i in range(start, end):
            t = lines[i].strip()
            if t.startswith("*  Claim ") or t == "*  Array Entry:":
                label = t[3:].rstrip(":")
            elif t == "-  SHA-256 Hash:":
                digest = token_after(lines, i)
                j = find(lines, "-  Disclosure:", i)
                entries.append({"section": sec, "claim": label, "digest": digest,
                                "disclosure": token_after(lines, j)})
    rows = ",\n".join(
        "  {" + ", ".join(f'"{k}": "{v}"' for k, v in e.items()) + "}" for e in entries)
    files["rfc9901-disclosures.json"] = "[\n" + rows + "\n]"

    for name, text in files.items():
        with open(os.path.join(outdir, name), "w", encoding="utf-8", newline="\n") as f:
            f.write(text + "\n")
        print(name, len(text))


main()
