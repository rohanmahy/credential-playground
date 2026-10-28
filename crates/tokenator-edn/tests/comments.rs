//! Comments (draft-ietf-cbor-edn-literals-28 §2.1): `/ … /`, `/* … */`,
//! `#` and `//` end-of-line comments, wherever blank space is allowed.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::assert_enc;
use tokenator_edn::{EdnErrorKind, parse};

#[test]
fn grasp_example() {
    assert_enc(
        "/grasp-message/ [/M_DISCOVERY/ 1, /session-id/ 10584416,\n                 \
         /objective/ [/objective-name/ \"opsonize\",\n                              \
         /D, N, S/ 7, /loop-count/ 105]]",
        "83 01 1a00a18160 83 686f70736f6e697a65 07 1869",
    );
}

#[test]
fn cose_key_example() {
    assert_enc(
        "{\n /kty/ 1 : 4, # Symmetric\n /alg/ 3 : 5, # HMAC 256-256\n  /k/ -1 : \
         h'6684523ab17337f173500e5728c628547cb37df\n             e68449c65f885d1b73b49eae1'\n}",
        "a3 0104 0305 20 5820 6684523ab17337f173500e5728c628547cb37dfe68449c65f885d1b73b49eae1",
    );
}

#[test]
fn config_file_example() {
    assert_enc(
        "/* ### MyApp Configuration\n * John Example, 2026-06-09\n */\n{\n  \
         // Top-level config for the app\n  \"appName\": \"MyApp\", // short name shown in UI\n  \
         \"version\": \"1.2.0\",\n}\n",
        "a2 67617070 4e616d65 654d79417070 6776657273696f6e 65312e322e30",
    );
}

#[test]
fn c_style_comments() {
    assert_enc("4 /* HMAC 256/64 */", "04");
    assert_enc("4 / HMAC 256//64 /", "04");
    assert_enc("[1, /* a * b ** c **/ 2]", "82 0102");
    assert_enc("/**/ 1", "01");
    assert_enc("/***/ 1", "01");
    assert_enc("/* multi\nline */ 1", "01");
    // "/*foo/" no longer ends at the slash.
    assert_enc("/*foo/ still a comment */ 1", "01");
}

#[test]
fn end_of_line_comments() {
    assert_enc("# c\n1", "01");
    assert_enc("// c\n1", "01");
    assert_enc("1 # c", "01");
    assert_enc("1 // c", "01");
    assert_enc("1 # c\r\n", "01");
    assert_enc("[1, # c / not inline\n 2]", "82 0102");
    assert_enc("[1, // c /* not c-style\n 2]", "82 0102");
}

#[test]
fn double_slash_is_not_an_empty_comment() {
    // "//" starts an end-of-line comment, so "2" below is commented out.
    assert_enc("[1, // 2\n 3]", "82 0103");
    assert!(parse("[1 // 2]").is_err());
}

#[test]
fn comments_are_separators() {
    assert_enc("[1/c/2]", "82 0102");
    assert_enc("[1/*c*/2]", "82 0102");
    assert_enc("[1#c\n2]", "82 0102");
    assert_enc("{1/c/:/c/2}", "a1 0102");
    assert_enc("1(/c/2)", "c1 02");
    assert_enc("simple(/c/16/c/)", "f0");
    assert_enc("[_/c/1]", "9f 01 ff");
    assert_enc("<</c/1/c/>>", "41 01");
    assert_enc("(_/c/\"a\")", "7f 6161 ff");
}

#[test]
fn comments_are_not_allowed_inside_tokens() {
    assert!(parse("1/c/2").is_err(), "two items");
    assert!(parse("1/c/.5").is_err());
    assert!(parse("1/c/(2)").is_err());
    assert!(parse("simple/c/(1)").is_err());
    assert!(parse("1/c/_1").is_err());
}

#[test]
fn comment_like_text_inside_strings_is_content() {
    assert_enc("\"/not a comment/\"", "6f 2f6e6f74206120636f6d6d656e742f");
    assert_enc("\"# not\"", "65 23206e6f74");
    assert_enc("'// x'", "44 2f2f2078");
    assert_enc("`/* x */`", "67 2f2a2078202a2f");
}

#[test]
fn unterminated_comments() {
    assert_eq!(parse("1 /c").unwrap_err().kind, EdnErrorKind::UnexpectedEnd);
    assert_eq!(
        parse("1 /* c").unwrap_err().kind,
        EdnErrorKind::UnexpectedEnd
    );
    assert_eq!(
        parse("1 /* c *").unwrap_err().kind,
        EdnErrorKind::UnexpectedEnd
    );
    assert_eq!(
        parse("[1 /c ]").unwrap_err().kind,
        EdnErrorKind::UnexpectedEnd
    );
}

#[test]
fn non_ascii_in_comments() {
    assert_enc("/ \u{fc}\u{1F600} / 1 # \u{2318}", "01");
    assert_enc("/* \u{fc} */ 1", "01");
}
