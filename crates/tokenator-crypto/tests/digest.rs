//! digest(): FIPS 180-4 example messages (values cross-checked with Python hashlib).

// Test crate: panicking helpers are intended.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use tokenator_crypto::{HashAlg, digest};

const TWO_BLOCK: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

fn check(h: HashAlg, msg: &[u8], expected_hex: &str) {
    let out = digest(h, msg);
    assert_eq!(hex::encode(&out), expected_hex, "{h:?} len {}", msg.len());
    assert_eq!(out.len(), h.output_len());
}

#[test]
fn sha256() {
    check(
        HashAlg::Sha256,
        b"",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    check(
        HashAlg::Sha256,
        b"abc",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    check(
        HashAlg::Sha256,
        TWO_BLOCK,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    );
}

#[test]
fn sha384() {
    check(
        HashAlg::Sha384,
        b"",
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
    );
    check(
        HashAlg::Sha384,
        b"abc",
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    );
    check(
        HashAlg::Sha384,
        TWO_BLOCK,
        "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
    );
}

#[test]
fn sha512() {
    check(
        HashAlg::Sha512,
        b"",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
         47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    );
    check(
        HashAlg::Sha512,
        b"abc",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    );
    check(
        HashAlg::Sha512,
        TWO_BLOCK,
        "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335\
         96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
    );
}

#[test]
fn million_a() {
    let msg = vec![b'a'; 1_000_000];
    check(
        HashAlg::Sha256,
        &msg,
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    );
    check(
        HashAlg::Sha384,
        &msg,
        "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
    );
    check(
        HashAlg::Sha512,
        &msg,
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb\
         de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
    );
}
