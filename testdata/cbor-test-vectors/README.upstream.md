# CBOR Test Vectors

Test vectors for [CBOR](https://datatracker.ietf.org/wg/cbor/documents/).  See
[RFC 8949](https://www.rfc-editor.org/rfc/rfc8949) for a starting point.

## Intent

Ensure full coverage of a typical CBOR implementation, including failing in
all of the correct places.  Different libraries may make different choices, or
have configurable options to act in different modes.

## Format

Multiple JSON files in the tests directory.  Each file is [EDN](https://www.ietf.org/archive/id/draft-ietf-cbor-edn-literals-19.html) of the form:

```cbor-edn
{
  "title": "mt0-good",
  "description": "Plain CBOR integers storable as major type 0 (mt0), from RFC 8949 appendix A",
  "fail": false, # Fail all tests in file?
  "tests": [
    {
      "description": "mt0 zero",
      "encoded": h'00',
      "decoded": 0,
      "roundtrip": true, # optional, true is the default
      "fail": false, # optional, false is the default
    },
  ],
}
```

## Processing

- Parse the whole .edn file as CBOR-EDN, generating a CBOR byte string.
- Alternately, read the .cbor file which should always match the .edn file, but not require an EDN parser.
- Decode the byte string to your internal representation of CBOR.
- For each test in tests:
  - "encoded" will now be a CBOR byte string.
  - "decoded" will now be your internal representation of an item.
  - Unless roundtrip is false, encode "decoded", and ensure you get "encoded".  If roundtrip is not specified, it defaults to true.
  - Decode "encoded", and ensure you get "decoded".
  - If "fail" is true, ensure that the above steps throw an error (there may be only one of "encoded" or "decoded" if "fail" is true).  "roundtrip" is ignored if "fail" is true.

## Checking the tests with nodejs and cbor2

- Install [nodejs](https://nodejs.org/)
- Install [pnpm](https://pnpm.io/)
- Install dependencies with `pnpm install`
- Run checks with `npm test`
- If you modify any .js file, run lint checks with `npm run lint`
- If you modify any .edn file, regenerate the .cbor files with
  `VECTOR_MODE=gen npm test`, then run `npm test` to ensure that all of the
  .cbor files match their .edn equivalents.
