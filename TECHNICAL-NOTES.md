# Technical Notes

## Breaking down the problem

- First propose small encapsulated interfaces between the major components of the code.
    - Write a concise description of the major components and libraries you will write,
    - write a small spec with the API signatures or endpoints involved.
    - Ask your human to review the spec. Keep it concise. Explain potential side effects that aren't obvious.
    - In the README.md file write a set of checkboxes for the
    - Once the human has given the OK, spawn two separate subagents for each major component:
        - one subagent to write a test plan and extensive tests to test the libraries / modules. If you encounter non-critical questions when writing the tests, write one Issue for each set of related questions asking for clarification; label the issue with `ai-needs-clarification`.
        - the second agent writes the code and makes it pass the tests.
            - if the code requires a server or testing between or among multiple instances of the same code, write end-to-end tests. It is fine to spin up Docker containers on this system for such tests.
            - if the library/crate/module is likely to be accessed by human programmer, write documentation with both easy and non-trivial examples of how to use the module. Regardless, add or update the ARCHITECTURE.md in each directory. Be concise.
    - check off each module in the README as it is completed.
- As large portions of functionality come together, feel free to create a subtask to make a short demo. For servers or libraries, a CLI example with before and after data structures or files is appropriate. If there is a UI a short video is fine, but keep it short.
- Once the bulk of the initial functionality is present, build the CI.

## Commits

- Create one commit anytime the human asks you to write something, or anytime a subagent starts a new module, library, or phase of development. Use conventional commit naming.
- When spawning subagents consider creating a new branch.
- `jj` is available on the system if that is useful for keeping worktree or branches independent.

## Dependencies

## CBOR-specific

- Watch out for libraries that do not work in WASM (like openssl) and no-longer maintained libraries (like ring).
- There are lots of missing features in various CBOR libraries. Using the esdicawt library is acceptable, but it might need to use an outdated private branch of ciborium to support a custom CBOR simple type. The library `seabored` is fast but has a lot of unsafe code. An excellent set of test vectors for CBOR is available at: https://github.com/hildjj/cbor-test-vectors
- You may need to write an EDN library from scratch.
- The `coset` COSE library had a PR or a branch with support for ML-DSA signatures. If it is not yet in the main branch, get basic functionality working, and create an issue to come back and try with the `coset` branch once singing and validation are working on basic CBOR Web Tokens.

## Memory management

- Be miserly with making copies of data in these credentials unless necessary. Use slices when possible and feel free to use `Cow`.


## Rust conventions

- Use rustfmt and respect the .clippy.toml file

