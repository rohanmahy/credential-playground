//! `registry-gen`: regenerate `crates/tokenator-registry/data/snapshot.json`.

use std::process::ExitCode;

fn main() -> ExitCode {
    let result =
        registry_gen::Args::parse(std::env::args().skip(1)).and_then(|a| registry_gen::run(&a));
    match result {
        Ok(n) => {
            println!("wrote {n} entries");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("registry-gen: {e}");
            ExitCode::FAILURE
        }
    }
}
