//! `ts-bindings`: print every `tokenator-core` DTO declaration as one
//! TypeScript module on stdout. `app/scripts/gen-types.mjs` writes it to
//! `app/src/lib/engine/types/index.ts` (and checks it is up to date).

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut out = String::from(
        "// Generated from tokenator-core (feature `ts`) by tools/ts-bindings.\n\
         // Do not edit: run `pnpm gen:types` in app/.\n",
    );
    for (_, decl) in tokenator_core::ts::bindings() {
        out.push('\n');
        out.push_str(decl.trim_end());
        out.push('\n');
    }
    match std::io::stdout().write_all(out.as_bytes()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ts-bindings: {e}");
            ExitCode::FAILURE
        }
    }
}
