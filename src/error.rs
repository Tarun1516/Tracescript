//! Centralised error type for the TraceScript toolchain.
//!
//! Every component (lexer, parser, semantic analyzer, interpreter, runtime) reports
//! errors through `TraceError`. The CLI wraps these into `anyhow::Error` so error
//! chains render nicely.

use std::fmt;
use std::result;

pub type Result<T> = result::Result<T, TraceError>;

#[derive(Debug, Clone, PartialEq)]
pub struct SourcePos {
    pub line: usize,
    pub col: usize,
    pub offset: usize,
}

impl SourcePos {
    pub fn new(line: usize, col: usize, offset: usize) -> Self {
        Self { line, col, offset }
    }
}

impl fmt::Display for SourcePos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}, column {}", self.line, self.col)
    }
}

#[derive(Debug, Clone)]
pub enum TraceError {
    Lex { msg: String, pos: SourcePos },
    Parse { msg: String, pos: SourcePos },
    Semantic { msg: String, pos: SourcePos },
    Runtime { msg: String, pos: Option<SourcePos> },
    /// Internal control-flow signal used by the interpreter to short-circuit out of a
    /// block on `return`. Never surfaced to the user; callers in the interpreter catch
    /// it explicitly via `match`.
    ReturnSignal { value: Option<crate::interp::value::Value> },
    Io { msg: String },
}

impl fmt::Display for TraceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraceError::Lex { msg, pos } => write!(f, "[lex] {} at {}", msg, pos),
            TraceError::Parse { msg, pos } => write!(f, "[parse] {} at {}", msg, pos),
            TraceError::Semantic { msg, pos } => write!(f, "[sema] {} at {}", msg, pos),
            TraceError::Runtime { msg, pos } => {
                if let Some(p) = pos {
                    write!(f, "[runtime] {} at {}", msg, p)
                } else {
                    write!(f, "[runtime] {}", msg)
                }
            }
            TraceError::ReturnSignal { .. } => write!(f, "<return-signal>"),
            TraceError::Io { msg } => write!(f, "[io] {}", msg),
        }
    }
}

impl std::error::Error for TraceError {}

impl From<std::io::Error> for TraceError {
    fn from(err: std::io::Error) -> Self {
        TraceError::Io { msg: err.to_string() }
    }
}