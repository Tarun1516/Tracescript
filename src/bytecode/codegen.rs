//! AST → bytecode compiler.
//!
//! The compiler walks the parsed AST and emits a `BytecodeModule` containing:
//!
//! - a constant pool (numbers, strings, bools)
//! - one `CompiledFunction` per user-defined function, plus a synthesised main
//! - one `CompiledEventHandler` per `on ...` declaration
//! - one `CompiledFunction` per `after finish` block
//! - one `CompiledTable` per table declaration
//!
//! Compilation errors are surfaced as `String` for the prototype; a richer error type
//! could be added later. The compiler does **not** evaluate anything — it only emits
//! instructions.

use std::collections::HashMap;

use crate::bytecode::opcode::{BytecodeModule, CompiledEventHandler, CompiledFunction, CompiledTable, Instr, Opcode};
use crate::interp::value::Value;
use crate::parser::*;

/// Compiles a parsed program into a bytecode module.
///
/// The returned module is self-contained: executing it from a cold start requires
/// only the constant pool, function table, and event-handler table.
pub fn compile(program: &Program) -> Result<BytecodeModule, String> {
    let mut cx = Compiler::new();
    for decl in &program.declarations {
        cx.collect(decl)?;
    }
    let module = cx.finish(program);
    Ok(module)
}

struct FunctionCtx {
    name: String,
    arity: u16,
    locals: Vec<String>,
    code: Vec<Instr>,
}

struct Compiler {
    constants: Vec<Value>,
    const_index: HashMap<String, u32>,
    functions: Vec<FunctionCtx>,
    event_handlers: Vec<(String, String, Vec<String>, Vec<Instr>)>,
    finish_handlers: Vec<FunctionCtx>,
    tables: Vec<CompiledTable>,
    source_path: Option<String>,
}

impl Compiler {
    fn new() -> Self {
        Self {
            constants: Vec::new(),
            const_index: HashMap::new(),
            functions: Vec::new(),
            event_handlers: Vec::new(),
            finish_handlers: Vec::new(),
            tables: Vec::new(),
            source_path: None,
        }
    }

    fn intern_const(&mut self, v: Value) -> u32 {
        let key = format!("{:?}", v);
        if let Some(idx) = self.const_index.get(&key) {
            return *idx;
        }
        let idx = self.constants.len() as u32;
        self.constants.push(v);
        self.const_index.insert(key, idx);
        idx
    }

    fn collect(&mut self, decl: &Decl) -> Result<(), String> {
        match decl {
            Decl::Source(s) => {
                if self.source_path.is_some() {
                    return Err("duplicate source declaration".into());
                }
                self.source_path = Some(s.path.clone());
            }
            Decl::Table(t) => {
                let columns = t
                    .fields
                    .iter()
                    .map(|f| (f.name.clone(), f.field_type.as_str().to_string()))
                    .collect();
                self.tables.push(CompiledTable {
                    name: t.name.clone(),
                    columns,
                });
            }
            Decl::Function(f) => {
                let locals = f.params.clone();
                self.functions.push(FunctionCtx {
                    name: f.name.clone(),
                    arity: f.params.len() as u16,
                    locals,
                    code: Vec::new(),
                });
            }
            Decl::EventHandler(h) => {
                self.event_handlers.push((
                    h.event_name.clone(),
                    h.param_name.clone(),
                    h.body.iter()
                        .map(|s| matches!(s, Stmt::Let { .. }).then(|| "x".to_string()).unwrap_or_default())
                        .collect(),
                    Vec::new(),
                ));
            }
            Decl::FinishHandler(_) => {
                self.finish_handlers.push(FunctionCtx {
                    name: "finish".into(),
                    arity: 0,
                    locals: Vec::new(),
                    code: Vec::new(),
                });
            }
        }
        Ok(())
    }

    fn finish(mut self, program: &Program) -> BytecodeModule {
        let mut compiled_functions = Vec::new();
        let mut compiled_event_handlers = Vec::new();
        let mut compiled_finish_handlers = Vec::new();
        let mut entry = Vec::new();

        for decl in &program.declarations {
            match decl {
                Decl::Function(f) => {
                    let idx = self
                        .functions
                        .iter()
                        .position(|fc| fc.name == f.name)
                        .expect("function collected in pass 1");
                    let FunctionCtx {
                        name,
                        arity,
                        mut locals,
                        mut code,
                    } = std::mem::replace(
                        &mut self.functions[idx],
                        FunctionCtx {
                            name: String::new(),
                            arity: 0,
                            locals: Vec::new(),
                            code: Vec::new(),
                        },
                    );
                    Self::compile_block(&mut code, &mut locals, &f.body, &mut self);
                    let unit_idx = self.intern_const(Value::Unit);
                    code.push(Instr::new(Opcode::LoadConst, unit_idx));
                    code.push(Instr::new(Opcode::Return, 0));
                    compiled_functions.push(CompiledFunction { name, arity, locals, code });
                }
                Decl::EventHandler(h) => {
                    let mut locals = vec![h.param_name.clone()];
                    let mut code = Vec::new();
                    Self::compile_block(&mut code, &mut locals, &h.body, &mut self);
                    code.push(Instr::new(Opcode::Return, 0));
                    compiled_event_handlers.push(CompiledEventHandler {
                        event_name: h.event_name.clone(),
                        param_name: h.param_name.clone(),
                        code,
                    });
                }
                Decl::FinishHandler(f) => {
                    let mut locals = Vec::new();
                    let mut code = Vec::new();
                    Self::compile_block(&mut code, &mut locals, &f.body, &mut self);
                    code.push(Instr::new(Opcode::Return, 0));
                    compiled_finish_handlers.push(CompiledFunction {
                        name: "finish".into(),
                        arity: 0,
                        locals,
                        code,
                    });
                }
                _ => {}
            }
        }

        // entry point: do nothing on its own. The VM drives execution through event
        // handlers and finish handlers. We still emit Halt so the VM has a defined
        // exit if it runs the entry stream.
        entry.push(Instr::new(Opcode::Halt, 0));

        BytecodeModule {
            version: BytecodeModule::current_version(),
            constants: std::mem::take(&mut self.constants),
            functions: compiled_functions,
            event_handlers: compiled_event_handlers,
            finish_handlers: compiled_finish_handlers,
            tables: std::mem::take(&mut self.tables),
            source_path: self.source_path.take(),
            entry,
        }
    }

    fn compile_block(
        code: &mut Vec<Instr>,
        locals: &mut Vec<String>,
        body: &[Stmt],
        cx: &mut Compiler,
    ) {
        for stmt in body {
            Self::compile_stmt(code, locals, stmt, cx);
        }
    }

    fn compile_stmt(
        code: &mut Vec<Instr>,
        locals: &mut Vec<String>,
        stmt: &Stmt,
        cx: &mut Compiler,
    ) {
        match stmt {
            Stmt::Let { name, value, .. } => {
                Self::compile_expr(code, locals, value, cx);
                let idx = Self::ensure_local(locals, name);
                code.push(Instr::new(Opcode::StoreVar, idx));
            }
            Stmt::Assign { name, value, .. } => {
                Self::compile_expr(code, locals, value, cx);
                let idx = Self::ensure_local(locals, name);
                code.push(Instr::new(Opcode::StoreVar, idx));
            }
            Stmt::IndexAssign { table, index, field, value, .. } => {
                // Stack: ... -> [value, idx]
                Self::compile_expr(code, locals, value, cx);
                Self::compile_expr(code, locals, index, cx);
                let tbl_idx = cx.intern_const(Value::Str(table.clone()));
                let fld_idx = cx.intern_const(Value::Str(field.clone()));
                code.push(Instr::new(Opcode::IndexAssign, tbl_idx));
                code.push(Instr::new(Opcode::Pop, fld_idx));
            }
            Stmt::If { condition, then_branch, else_branch, .. } => {
                Self::compile_expr(code, locals, condition, cx);
                let jump_to_else = code.len();
                code.push(Instr::new(Opcode::JumpIfFalse, 0));
                let then_start = code.len();
                Self::compile_block(code, locals, then_branch, cx);
                let jump_to_end = code.len();
                code.push(Instr::new(Opcode::Jump, 0));
                let else_start = code.len();
                if let Some(else_branch) = else_branch {
                    Self::compile_block(code, locals, else_branch, cx);
                }
                let end = code.len();
                code[jump_to_else].arg = else_start as u32;
                code[jump_to_end].arg = end as u32;
                let _ = then_start;
            }
            Stmt::For { var, table, body, .. } => {
                let tbl_idx = cx.intern_const(Value::Str(table.clone()));
                // Init iterator; pushes a table snapshot onto a hidden runtime slot.
                code.push(Instr::new(Opcode::ForInit, tbl_idx));
                let var_idx = Self::ensure_local(locals, var);
                // ForNext either pushes the next row value (and continues) or jumps
                // to its arg if exhausted.
                let for_next_pos = code.len();
                code.push(Instr::new(Opcode::ForNext, 0));
                // Body starts here. We store the value to var_idx.
                code.push(Instr::new(Opcode::StoreVar, var_idx));
                Self::compile_block(code, locals, body, cx);
                code.push(Instr::new(Opcode::Jump, 0));
                let exit = code.len();
                // Patch ForNext's arg to point to exit (when exhausted).
                code[for_next_pos].arg = exit as u32;
                // Patch the trailing Jump back to ForNext.
                code[exit - 1].arg = for_next_pos as u32;
            }
            Stmt::Insert { table_name, values, .. } => {
                // stack: [..., v_n, ..., v_1]
                for v in values {
                    Self::compile_expr(code, locals, v, cx);
                }
                let tbl_idx = cx.intern_const(Value::Str(table_name.clone()));
                code.push(Instr::new(Opcode::InsertTable, tbl_idx));
            }
            Stmt::Alert { values, .. } => {
                for v in values {
                    Self::compile_expr(code, locals, v, cx);
                }
                let n = values.len() as u32;
                code.push(Instr::new(Opcode::Alert, n));
            }
            Stmt::Show { table_name, .. } => {
                let idx = cx.intern_const(Value::Str(table_name.clone()));
                code.push(Instr::new(Opcode::ShowTable, idx));
            }
            Stmt::Export { table_name, path, .. } => {
                Self::compile_expr(code, locals, &Expr::Str(path.clone()), cx);
                let tbl_idx = cx.intern_const(Value::Str(table_name.clone()));
                code.push(Instr::new(Opcode::ExportTable, tbl_idx));
            }
            Stmt::Print { value, .. } => {
                Self::compile_expr(code, locals, value, cx);
                code.push(Instr::new(Opcode::Print, 0));
            }
            Stmt::CallStmt { name, args, .. } => {
                for a in args {
                    Self::compile_expr(code, locals, a, cx);
                }
                let fn_idx = cx.intern_const(Value::Str(name.clone()));
                code.push(Instr::new(Opcode::Call, fn_idx));
                code.push(Instr::new(Opcode::Pop, 0));
            }
            Stmt::Return { value, .. } => {
                if let Some(v) = value {
                    Self::compile_expr(code, locals, v, cx);
                } else {
                    code.push(Instr::new(Opcode::LoadConst, cx.intern_const(Value::Unit)));
                }
                code.push(Instr::new(Opcode::Return, 0));
            }
        }
    }

    fn ensure_local(locals: &mut Vec<String>, name: &str) -> u32 {
        if let Some(idx) = locals.iter().position(|l| l == name) {
            return idx as u32;
        }
        let idx = locals.len() as u32;
        locals.push(name.to_string());
        idx
    }

    fn compile_expr(
        code: &mut Vec<Instr>,
        locals: &mut Vec<String>,
        expr: &Expr,
        cx: &mut Compiler,
    ) {
        match expr {
            Expr::Integer(n) => {
                code.push(Instr::new(Opcode::LoadConst, cx.intern_const(Value::Int(*n))));
            }
            Expr::Float(n) => {
                code.push(Instr::new(Opcode::LoadConst, cx.intern_const(Value::Float(*n))));
            }
            Expr::Str(s) => {
                code.push(Instr::new(Opcode::LoadConst, cx.intern_const(Value::Str(s.clone()))));
            }
            Expr::Bool(b) => {
                code.push(Instr::new(Opcode::LoadConst, cx.intern_const(Value::Bool(*b))));
            }
            Expr::Identifier(name) => {
                if let Some(idx) = locals.iter().position(|l| l == name) {
                    code.push(Instr::new(Opcode::LoadVar, idx as u32));
                } else {
                    // late-bound: function / event-table / etc. Push the identifier
                    // string; the VM looks it up at call time.
                    let idx = cx.intern_const(Value::Str(name.clone()));
                    code.push(Instr::new(Opcode::LoadConst, idx));
                }
            }
            Expr::Binary { left, operator, right, .. } => {
                Self::compile_expr(code, locals, left, cx);
                Self::compile_expr(code, locals, right, cx);
                let op = match operator {
                    BinOp::Add => Opcode::Add,
                    BinOp::Sub => Opcode::Sub,
                    BinOp::Mul => Opcode::Mul,
                    BinOp::Div => Opcode::Div,
                    BinOp::Mod => Opcode::Mod,
                    BinOp::Eq => Opcode::Eq,
                    BinOp::NotEq => Opcode::NotEq,
                    BinOp::Lt => Opcode::Lt,
                    BinOp::Gt => Opcode::Gt,
                    BinOp::LtEq => Opcode::LtEq,
                    BinOp::GtEq => Opcode::GtEq,
                    BinOp::And => Opcode::And,
                    BinOp::Or => Opcode::Or,
                    BinOp::Contains => Opcode::Contains,
                };
                code.push(Instr::new(op, 0));
            }
            Expr::Unary { operator, operand, .. } => {
                Self::compile_expr(code, locals, operand, cx);
                let op = match operator {
                    UnOp::Not => Opcode::Not,
                    UnOp::Neg => Opcode::Neg,
                };
                code.push(Instr::new(op, 0));
            }
            Expr::Call { name, args, .. } => {
                for a in args {
                    Self::compile_expr(code, locals, a, cx);
                }
                let fn_idx = cx.intern_const(Value::Str(name.clone()));
                code.push(Instr::new(Opcode::Call, fn_idx));
            }
            Expr::FieldAccess { object, field, .. } => {
                Self::compile_expr(code, locals, object, cx);
                let field_idx = cx.intern_const(Value::Str(field.clone()));
                code.push(Instr::new(Opcode::GetEventField, field_idx));
            }
            Expr::Index { table, index, .. } => {
                Self::compile_expr(code, locals, index, cx);
                let tbl_idx = cx.intern_const(Value::Str(table.clone()));
                code.push(Instr::new(Opcode::IndexGet, tbl_idx));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_simple_let_and_print() {
        let src = "function f() { let x = 1 + 2 print x }";
        let prog = crate::parser::Parser::from_source(src).unwrap().parse_program().unwrap();
        let module = compile(&prog).unwrap();
        assert_eq!(module.functions.len(), 1);
        let f = &module.functions[0];
        assert!(f.code.iter().any(|i| i.op == Opcode::Add));
        assert!(f.code.iter().any(|i| i.op == Opcode::Print));
    }

    #[test]
    fn compiles_event_handler_and_insert() {
        let src = "table t { a: string } on dns_query(e) { insert t(\"x\") }";
        let prog = crate::parser::Parser::from_source(src).unwrap().parse_program().unwrap();
        let module = compile(&prog).unwrap();
        assert_eq!(module.tables.len(), 1);
        assert_eq!(module.event_handlers.len(), 1);
        assert!(module.event_handlers[0].code.iter().any(|i| i.op == Opcode::InsertTable));
    }

    #[test]
    fn compiles_finish_handler() {
        let src = "after finish { show t }";
        let prog = crate::parser::Parser::from_source(src).unwrap().parse_program().unwrap();
        let module = compile(&prog).unwrap();
        assert_eq!(module.finish_handlers.len(), 1);
        assert!(module.finish_handlers[0].code.iter().any(|i| i.op == Opcode::ShowTable));
    }
}