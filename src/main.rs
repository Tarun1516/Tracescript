//! TraceScript CLI entry point.
//!
//! See the per-module documentation for details on each subsystem.

use std::process::ExitCode;

mod bytecode;
mod cli;
mod error;
mod filter;
mod host;
mod interp;
mod lexer;
mod output;
mod parser;
mod runtime;
mod sema;
mod sha256;
mod tables;

fn main() -> ExitCode {
    match cli::run(std::env::args().collect()) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {:#}", err);
            ExitCode::from(2)
        }
    }
}

/// Build metadata. Captured at compile time via `env!`/`option_env!` so it
/// appears in `--version` output.
pub const BUILD_INFO: &str = concat!(
    "TraceScript ",
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("TRACESCRIPT_GIT_SHA"),
    ", built ",
    env!("TRACESCRIPT_BUILD_DATE"),
    ")"
);