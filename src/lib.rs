//! TraceScript library crate.
//!
//! The `tracescript` binary in `src/main.rs` is a thin CLI wrapper around the modules
//! below. Exposing them here lets integration tests in `tests/` link against the
//! compiled crate directly, instead of spawning the binary.

pub mod bytecode;
pub mod error;
pub mod filter;
pub mod host;
pub mod interp;
pub mod lexer;
pub mod output;
pub mod parser;
pub mod runtime;
pub mod sema;
pub mod sha256;
pub mod tables;