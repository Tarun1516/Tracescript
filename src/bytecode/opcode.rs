//! Bytecode instruction set and module format for the TraceScript VM.
//!
//! The VM is a small stack machine. Most instructions pop their operands and push
//! results. `STORE_VAR`/`LOAD_VAR` are indexed into a locals table; `LOAD_CONST`
//! indexes into the constant pool. Control flow uses absolute `u32` jumps so the
//! compiler doesn't have to patch offsets.

use serde::{Deserialize, Serialize};

use crate::interp::value::Value;

/// A single bytecode instruction. The `arg` is `u32` everywhere — for opcodes that
/// need a smaller value we just don't use the upper bits.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Opcode {
    // Stack
    LoadConst,
    Pop,

    // Variables
    LoadVar,
    StoreVar,

    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Mod,

    // Comparison / logic
    Eq,
    NotEq,
    Lt,
    Gt,
    LtEq,
    GtEq,
    And,
    Or,
    Not,
    Neg,
    Contains,

    // Control flow
    Jump,
    JumpIfFalse,
    JumpIfTrue,
    Call,
    Return,

    // Event / runtime
    GetEventField,
    DispatchEvent,
    InsertTable,
    ShowTable,
    ExportTable,
    Alert,
    Print,

    // For loop and indexing
    IndexGet,
    IndexAssign,
    ForInit,
    ForNext,

    Halt,
}

/// A compiled instruction with its argument.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Instr {
    pub op: Opcode,
    pub arg: u32,
}

impl Instr {
    pub fn new(op: Opcode, arg: u32) -> Self {
        Self { op, arg }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledFunction {
    pub name: String,
    pub arity: u16,
    pub locals: Vec<String>,
    pub code: Vec<Instr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledEventHandler {
    pub event_name: String,
    pub param_name: String,
    pub code: Vec<Instr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledTable {
    pub name: String,
    pub columns: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BytecodeModule {
    pub version: u32,
    pub constants: Vec<Value>,
    pub functions: Vec<CompiledFunction>,
    pub event_handlers: Vec<CompiledEventHandler>,
    pub finish_handlers: Vec<CompiledFunction>,
    pub tables: Vec<CompiledTable>,
    pub source_path: Option<String>,
    pub entry: Vec<Instr>,
}

impl BytecodeModule {
    pub fn current_version() -> u32 {
        1
    }

    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| e.to_string())
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| e.to_string())
    }

    /// Save this module to disk as a `.traceb` file (JSON-serialised bytecode).
    pub fn save(&self, path: &std::path::Path) -> Result<(), String> {
        let bytes = self.serialize()?;
        std::fs::write(path, bytes).map_err(|e| e.to_string())
    }

    /// Load a module from disk. Returns the parsed module or a human-readable error.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
        Self::deserialize(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_module() {
        let module = BytecodeModule {
            version: BytecodeModule::current_version(),
            constants: vec![Value::Int(42), Value::Str("hi".into())],
            functions: vec![CompiledFunction {
                name: "f".into(),
                arity: 1,
                locals: vec!["x".into()],
                code: vec![Instr::new(Opcode::LoadConst, 0), Instr::new(Opcode::Halt, 0)],
            }],
            event_handlers: vec![],
            finish_handlers: vec![],
            tables: vec![],
            source_path: None,
            entry: vec![],
        };
        let bytes = module.serialize().unwrap();
        let parsed = BytecodeModule::deserialize(&bytes).unwrap();
        assert_eq!(parsed.constants.len(), 2);
        assert_eq!(parsed.functions.len(), 1);
    }
}