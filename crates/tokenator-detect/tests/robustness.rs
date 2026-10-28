//! Garbage, empty, truncated, mutated, huge, and deeply nested inputs: no
//! panics, invariants hold, and the work stays bounded.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::time::{Duration, Instant};

use common::*;
use tokenator_detect::{Kind, MAX_LAYERS};

/// Generous bound that only catches super-linear blowups (debug builds).
const SLOW: Duration = Duration::from_secs(30);

fn timed(input: &[u8]) -> Vec<tokenator_detect::Candidate> {
    let t = Instant::now();
    let cands = run(input);
    assert!(
        t.elapsed() < SLOW,
        "detect took {:?} on {} bytes",
        t.elapsed(),
        input.len()
    );
    cands
}

#[test]
fn empty_input() {
    assert!(run(b"").is_empty());
}

#[test]
fn whitespace_only() {
    for input in [&b" "[..], b"\n", b"\r\n\t  ", b"\x0c\x0b"] {
        assert!(run(input).is_empty(), "{input:?}");
    }
}

#[test]
fn tiny_inputs() {
    for input in [
        &b"\""[..],
        b"\"\"",
        b"''",
        b"{",
        b"}",
        b"[",
        b"~",
        b".",
        b"..",
        b"%",
        b"%%",
        b"=",
        b"ey",
        b"eyJ",
        b"Bearer",
        b"Bearer ",
        b"Authorization:",
        b"Authorization: Bearer ",
        b"-----BEGIN",
        b"\x00",
        b"\xff",
        b"\xd2",
        b"\xd8\x3d",
        b"\x84",
    ] {
        run(input);
    }
}

#[test]
fn bearer_with_nothing_after_is_empty() {
    assert!(run(b"Bearer ").is_empty());
    assert!(run(b"Authorization: Bearer  \r\n").is_empty());
}

#[test]
fn invalid_utf8_and_nul_bytes() {
    let mut input = token_text(JWT).into_bytes();
    input.insert(5, 0x00);
    run(&input);
    input[5] = 0xc3; // lone UTF-8 lead byte
    run(&input);
    run(b"\xef\xbb\xbf"); // BOM only
    run(&[0xfe, 0xff, 0x00, 0x7b]); // UTF-16 BOM
}

#[test]
fn utf8_bom_before_a_token_does_not_panic() {
    let mut input = b"\xef\xbb\xbf".to_vec();
    input.extend(token_text(JWT).into_bytes());
    run(&input);
}

#[test]
fn every_prefix_of_a_jwt() {
    let t = token(SD_JWT_KB);
    for n in 0..=t.len() {
        run(&t[..n]);
    }
}

#[test]
fn every_prefix_of_a_cwt_and_kbt() {
    for name in [CWT_TAG18, SD_KBT] {
        let t = token(name);
        for n in 0..t.len() {
            let cands = run(&t[..n]);
            for k in [Kind::Cwt, Kind::SdCwt, Kind::SdKbt, Kind::CoseSign1] {
                assert!(
                    find(&cands, &k).is_none(),
                    "{name} truncated to {n} still {k:?}"
                );
            }
        }
    }
}

#[test]
fn single_bit_flips_in_binary_fixtures() {
    for name in [CWT_TAG18, SD_CWT, SD_KBT] {
        let t = token(name);
        for i in (0..t.len()).step_by(7) {
            for bit in [0, 3, 7] {
                let mut m = t.clone();
                m[i] ^= 1 << bit;
                run(&m);
            }
        }
    }
}

#[test]
fn single_byte_changes_in_text_fixtures() {
    for name in [SD_JWT_KB, "rfc9901-s8.3-sd-jwt-kb-json-general.json"] {
        let t = token(name);
        for i in (0..t.len()).step_by(13) {
            for b in [b'.', b'~', b'"', b'{', b'%', b' ', 0x00, 0xff] {
                let mut m = t.clone();
                m[i] = b;
                run(&m);
            }
        }
    }
}

#[test]
fn large_base64_alphabet_input() {
    let input = vec![b'A'; 4 << 20];
    timed(&input);
}

#[test]
fn large_hex_input() {
    let input: Vec<u8> = b"a0".iter().copied().cycle().take(4 << 20).collect();
    timed(&input);
}

#[test]
fn large_random_looking_text() {
    let mut x: u32 = 0x1234_5678;
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";
    let input: Vec<u8> = (0..(2 << 20))
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            alphabet[(x as usize) % alphabet.len()]
        })
        .collect();
    timed(&input);
}

#[test]
fn json_depth_bomb() {
    let mut input = vec![b'['; 1 << 20];
    input.extend(vec![b']'; 1 << 20]);
    timed(&input);
    let input = vec![b'{'; 4 << 20];
    timed(&input);
    let nested_objects = "{\"a\":".repeat(100_000) + "1" + &"}".repeat(100_000);
    timed(nested_objects.as_bytes());
}

#[test]
fn cbor_depth_bomb() {
    let input = vec![0x81; 4 << 20];
    timed(&input);
    let tags: Vec<u8> = std::iter::repeat_n([0xd8, 0x3d], 1 << 20)
        .flatten()
        .collect();
    timed(&tags);
}

#[test]
fn many_nested_tags_around_a_cwt_are_bounded() {
    let mut input = Vec::new();
    for _ in 0..(MAX_LAYERS * 4) {
        input.extend([0xd8, 0x3d]);
    }
    input.extend(token(CWT_TAG18));
    let cands = timed(&input);
    assert!(cands.iter().all(|c| c.layers.len() <= MAX_LAYERS));
}

#[test]
fn deep_base64_nesting_is_capped() {
    let mut s = token_text(JWT).into_bytes();
    for _ in 0..20 {
        s = b64url(&s).into_bytes();
    }
    let cands = timed(&s);
    assert!(cands.iter().all(|c| c.layers.len() <= MAX_LAYERS));
}

#[test]
fn many_json_fields() {
    let jwt = token_text(JWT);
    let mut doc = String::from("{");
    for i in 0..300 {
        if i > 0 {
            doc.push(',');
        }
        doc.push_str(&format!("\"f{i}\":\"{jwt}\""));
    }
    doc.push('}');
    let cands = timed(doc.as_bytes());
    assert!(cands.iter().filter(|c| c.kind == Kind::Jwt).count() >= 1);
}

#[test]
fn huge_declared_cbor_lengths_fail_fast() {
    // bstr of length 2^63, array of 2^32 items, map of 2^64-1 pairs.
    for input in [
        h("5b 80 00 00 00 00 00 00 00 00"),
        h("9a ff ff ff ff 00"),
        h("bb ff ff ff ff ff ff ff ff"),
        h("d2 9b 00 00 00 01 00 00 00 00"),
    ] {
        timed(&input);
        timed(hex(&input).as_bytes());
        timed(b64url(&input).as_bytes());
    }
}

#[test]
fn indefinite_length_cose_sign1_does_not_panic() {
    // 18([_ h'a10126', {}, h'', h''])
    let input = h("d2 9f 43 a1 01 26 a0 40 40 ff");
    run(&input);
}

#[test]
fn control_characters_and_lone_separators() {
    for input in [
        "\u{7f}\u{1}\u{2}".as_bytes(),
        "eyJ\u{0}.eyJ.".as_bytes(),
        "....~~~~".as_bytes(),
        "%00%00%00".as_bytes(),
        "%".repeat(10_000).as_bytes(),
        "~".repeat(10_000).as_bytes(),
        ".".repeat(10_000).as_bytes(),
    ] {
        run(input);
    }
}

#[test]
fn adversarial_1mb_inputs_are_fast() {
    // About 1 MB each. Release builds must stay under a second per input
    // (including `run`'s second detect call and an unwrap per candidate).
    let limit = if cfg!(debug_assertions) {
        SLOW
    } else {
        Duration::from_secs(1)
    };
    let jwt = token_text(JWT).into_bytes();
    let grow = |f: &dyn Fn(&[u8]) -> Vec<u8>| {
        let mut s = jwt.clone();
        while s.len() < 1 << 20 {
            s = f(&s);
        }
        s
    };
    let fields = {
        let mut doc = String::from("{");
        let mut i = 0;
        while doc.len() < 1 << 20 {
            doc.push_str(&format!("\"f{i}\":\"a0a0\","));
            i += 1;
        }
        doc.push_str("\"end\":\"a0\"}");
        doc.into_bytes()
    };
    let inputs = [
        // Hex of hex of ...: every level is also valid base64.
        grow(&|s| hex(s).into_bytes()),
        // Percent-encoding of percent-encoding of ...
        grow(&|s| pct_all(s).into_bytes()),
        // Alternating base64url and hex.
        grow(&|s| {
            if s.len() % 2 == 0 {
                hex(s).into_bytes()
            } else {
                b64url(s).into_bytes()
            }
        }),
        // Many short fields, each hex for a CBOR map (and valid base64).
        fields,
        // A JSON array of the same JWT, many times.
        format!(
            "[{}]",
            vec![format!("\"{}\"", token_text(JWT)); 5000].join(",")
        )
        .into_bytes(),
    ];
    for input in inputs {
        let t = Instant::now();
        let cands = run(&input);
        assert!(
            t.elapsed() < limit,
            "detect took {:?} on {} bytes",
            t.elapsed(),
            input.len()
        );
        assert!(cands.len() <= 64);
    }
}
