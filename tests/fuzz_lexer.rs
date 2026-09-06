//! Lexer + parser fuzz harness. Reuses `cargo-fuzz` style structure but runs under
//! the regular `cargo test` infrastructure so it doesn't need extra dependencies.
//!
//! The harness generates random short strings and confirms the lexer + parser either
//! succeeds or returns an error — they must not panic. Run with:
//!
//! ```bash
//! cargo test --test fuzz_lexer -- --nocapture
//! ```

use tracescript::lexer::Lexer;
use tracescript::parser::Parser;

fn check_no_panic(input: &str) {
    let _ = Lexer::new(input).tokenize();
    let p = Parser::from_source(input);
    if let Ok(mut p) = p {
        let _ = p.parse_program();
    }
}

#[test]
fn fuzz_random_byte_sequences() {
    let mut buf = vec![0u8; 64];
    let mut state: u64 = 0xdead_beef_cafe_babe;
    let next = |s: &mut u64| -> u8 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        (*s & 0xff) as u8
    };
    for _ in 0..512 {
        for b in buf.iter_mut() {
            *b = next(&mut state);
        }
        // Filter out 0x00 (null bytes cause Rust string truncation issues).
        let s: String = buf
            .iter()
            .filter(|&&b| b != 0)
            .map(|&b| b as char)
            .collect();
        check_no_panic(&s);
    }
}

#[test]
fn fuzz_realistic_scripts() {
    // Seed with patterns likely to expose parser edge cases.
    let templates = [
        "let x = @@@",
        "function f( { }",
        "if x > { }",
        "table t { a: badtype }",
        "on e() { insert t(",
        "insert t 1, 2, 3)",
        "alert(\"unterminated",
        "{ let = }",
        "function",
        "let x = + - * /",
        "source pcap",
        "source jsonl",
        "source csv \"x\"",
        "after finish { show ",
        "export t to",
    ];
    for t in templates {
        check_no_panic(t);
    }
}

#[test]
fn fuzz_deeply_nested_blocks() {
    let mut s = String::new();
    for _ in 0..50 {
        s.push_str("if x { ");
    }
    for _ in 0..50 {
        s.push_str(" }");
    }
    check_no_panic(&s);
}

#[test]
fn fuzz_long_identifier() {
    let s = "let ".to_string() + &"a".repeat(10_000) + " = 1";
    check_no_panic(&s);
}

#[test]
fn fuzz_long_string_literal() {
    let s = "let x = \"".to_string() + &"a".repeat(10_000) + "\"";
    check_no_panic(&s);
}