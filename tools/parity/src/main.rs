//! `parity regen`: rebuilds `testdata/parity/` (cases and native goldens).
//! `parity check`: fails if the committed corpus is stale or a golden
//! differs from the native engine's output.
//!
//! Run in release mode (`cargo run --release -p parity -- regen`): the
//! corpus generates RSA and ML-DSA keys and walks max-depth documents.

use std::collections::BTreeMap;
use std::process::ExitCode;

use parity::{
    Case, Golden, case_text, corpus, parity_dir, read_cases, read_expected, testdata,
    with_big_stack,
};
use tokenator_core::Engine;

fn build() -> Result<Vec<(String, Case, String)>, String> {
    with_big_stack(|| {
        let e = Engine::new().map_err(|e| e.to_string())?;
        let cases = corpus::build(&e, &testdata())?;
        cases
            .into_iter()
            .map(|(id, case)| {
                let out = case.run(&e).map_err(|err| format!("{id}: {err}"))?;
                Ok((id, case, out))
            })
            .collect()
    })?
}

fn regen() -> Result<(), String> {
    let dir = parity_dir();
    for sub in ["cases", "expected"] {
        let p = dir.join(sub);
        if p.exists() {
            std::fs::remove_dir_all(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        }
        std::fs::create_dir_all(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    }
    let all = build()?;
    let mut bytes = 0usize;
    for (id, case, out) in &all {
        std::fs::write(
            dir.join("cases").join(format!("{id}.json")),
            case_text(case)?,
        )
        .map_err(|e| e.to_string())?;
        let (name, text) = Golden::of(out).file(id);
        std::fs::write(dir.join("expected").join(name), text).map_err(|e| e.to_string())?;
        bytes += out.len();
    }
    println!(
        "wrote {} cases ({} KiB of goldens) to {}",
        all.len(),
        bytes / 1024,
        dir.display()
    );
    Ok(())
}

fn check() -> Result<(), String> {
    let dir = parity_dir();
    let cases = read_cases(&dir)?;
    let expected = read_expected(&dir)?;
    let built: BTreeMap<String, (Case, String)> = build()?
        .into_iter()
        .map(|(id, c, o)| (id, (c, o)))
        .collect();
    let mut problems = Vec::new();
    for id in built.keys().filter(|id| !cases.contains_key(*id)) {
        problems.push(format!("{id}: missing from testdata/parity/cases"));
    }
    for (id, case) in &cases {
        match built.get(id) {
            None => problems.push(format!("{id}: no longer built by the corpus")),
            Some((c, out)) => {
                if c != case {
                    problems.push(format!("{id}: request differs from the corpus builder"));
                }
                match expected.get(id) {
                    None => problems.push(format!("{id}: no golden")),
                    Some(golden) if *golden != Golden::of(out) => {
                        problems.push(format!("{id}: native output differs from the golden"));
                    }
                    Some(_) => {}
                }
            }
        }
    }
    if problems.is_empty() {
        println!("{} parity cases match their native goldens", cases.len());
        Ok(())
    } else {
        Err(format!(
            "{}\nrun `pnpm parity:regen` in app/ (or `cargo run --release -p parity -- regen`)",
            problems.join("\n")
        ))
    }
}

fn main() -> ExitCode {
    let result = match std::env::args().nth(1).as_deref() {
        Some("regen") => regen(),
        Some("check") => check(),
        _ => Err("usage: parity regen|check".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("parity: {e}");
            ExitCode::FAILURE
        }
    }
}
