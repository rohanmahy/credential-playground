//! Sets the wasm stack size explicitly (#27). The default rustc gives
//! wasm32 is 1 MiB; the stack audit in `testdata/parity` (cases tagged
//! `stack`) must pass in the release build with this value, and
//! `app/src/test/wasm/binary.test.ts` reads it back from the built module.

/// 2 MiB: twice the rustc default. Measured needs at the limits are below
/// 256 KiB for a render (tokenator-core ARCHITECTURE.md) plus the
/// recursion in tokenator-jose and serde for deep documents; the headroom
/// is cheap because linear memory is allocated in 64 KiB pages anyway.
const STACK_SIZE: u32 = 2 * 1024 * 1024;

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("wasm32") {
        println!("cargo::rustc-link-arg-cdylib=-zstack-size={STACK_SIZE}");
    }
}
