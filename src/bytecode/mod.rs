//! Bytecode compiler + virtual machine for TraceScript.
//!
//! - [`opcode`] — instruction set, instruction stream, and serialised module format.
//! - [`codegen`] — AST → bytecode compiler.
//! - [`vm`] — stack-based VM that executes a `BytecodeModule`.

pub mod codegen;
pub mod opcode;
pub mod vm;

pub use opcode::{BytecodeModule, Instr};