A credential playground called "The Tokenator".

Features:
- A web and macOS desktop tool (with Tauri) to issue, present, validate, view, and manipulate credentials.

- Some technical product guidelines:
    - write the parsers and crypto in Rust.
    - write the UI in Javascript.
    - on the web, only the application is loaded from the web server. No data is sent to the server for processing
- Have a part of the UI that represents keys for the Issue and Holder. The UI should be able to create, read from disk or clipboard, write to disk or clipboard, and convert keys among various forms:
    - PEM, JSON Web Key, CBOR Web Key formats initially
    - Can convert a private key to a public key
    - Can create JSON key thumbprints and CBOR key thumbprints
    - Can try to fetch any of these from a URL (for example from the URL in the `kid` header)
- Support for multiple types of credentials, initially with JWT, SD-JWT (RFC9901, including the compact serialized format), CWT, and SD-CWT (draft-ietf-spice-sd-cwt)
    - for CBOR-based web token, display in Extended Diagnostic Notation (draft-ietf-cbor-edn) and/or annotated hex.
    - automatically decode CBOR-encoded byte strings
    - try to detect the type of credential automatically
    - Bearer tokens are often base64url or base64 classic encodings of standard token types
    - Use a local database of claims and headers for decoding and encoding. Also be able to lookup claims and headers from the IANA registries when internet access is available:
        - https://www.iana.org/assignments/cwt
        - https://www.iana.org/assignments/cose
        - https://www.iana.org/assignments/jwt
        - https://www.iana.org/assignments/jose
- Signature validation and disclosure to redacted claim matching for SD-JWT and SD-CWT
- Provide tree-view controls to descend into nested levels of claims
- Support for at least NIST curves, Ed25519 curve, RSA, and ML-DSA signature types.

Future features
- CDDL validation and/or additional decoding for CBOR-based credentials and JSON Schema validation for JSON-based credentials
    - Could identify specific variants like WIMSE and SCITT
- CLI to do the basic operations, especially to parse and optionally validate a credential and output an easier to read version in JSON or EDN.
- Additional formats as plugins
    - Webauthn
    - Privacy pass
    - EUID wallet
    - ISO mDoc / mID
    - W3C Verifiable Credentials / Verifiable Presentations
- Eventually add Linux desktop and Windows desktop version
