//! Stack-based virtual machine for TraceScript bytecode.
//!
//! The VM executes a `BytecodeModule` produced by `bytecode::codegen`. The execution
//! model is a single big `match` over opcodes; the call stack is an explicit
//! `Vec<CallFrame>`. Built-in calls are dispatched by name through `interp::builtins`.
//!
//! Public interface:
//!
//! - [`VM::new`] — build a VM from a bytecode module, populating tables.
//! - [`VM::dispatch_event`] — fire a runtime event into a matching handler.
//! - [`VM::run_finish`] — run every `after finish` handler.
//! - [`VM::tables`] / [`VM::alerts`] — read-only views for the runner.
//!
//! Everything else is internal.

use std::collections::HashMap;

use crate::bytecode::opcode::{BytecodeModule, Instr, Opcode};
use crate::error::{Result, TraceError};
use crate::host;
use crate::interp::builtins;
use crate::interp::value::Value;
use crate::parser::{TableField, TypeName};
use crate::tables::TableStore;

pub struct VM {
    module: BytecodeModule,
    pub tables: TableStore,
    pub alerts: Vec<Vec<Value>>,
    stack: Vec<Value>,
    frames: Vec<CallFrame>,
    iterators: Vec<(u32, std::vec::IntoIter<Vec<Value>>)>,
}

#[derive(Debug, Clone)]
struct CallFrame {
    #[allow(dead_code)]
    function: String,
    locals: Vec<Value>,
    ip: usize,
}

impl VM {
    pub fn new(module: BytecodeModule) -> Result<Self> {
        let mut tables = TableStore::new();
        for ct in &module.tables {
            let fields: Vec<TableField> = ct
                .columns
                .iter()
                .map(|(name, ty)| TableField {
                    name: name.clone(),
                    field_type: TypeName::from_str(ty).unwrap_or(TypeName::Str),
                })
                .collect();
            tables.create(ct.name.clone(), fields).map_err(|e| match e {
                TraceError::Runtime { msg, .. } => TraceError::Runtime { msg, pos: None },
                other => other,
            })?;
        }
        Ok(Self {
            module,
            tables,
            alerts: Vec::new(),
            stack: Vec::new(),
            frames: Vec::new(),
            iterators: Vec::new(),
        })
    }

    pub fn module(&self) -> &BytecodeModule {
        &self.module
    }

    pub fn source_path(&self) -> Option<&str> {
        self.module.source_path.as_deref()
    }

    pub fn dispatch_event(&mut self, name: &str, fields: HashMap<String, Value>) -> Result<()> {
        let handler = self
            .module
            .event_handlers
            .iter()
            .find(|h| h.event_name == name)
            .cloned();
        let Some(handler) = handler else {
            return Ok(());
        };
        self.frames.push(CallFrame {
            function: format!("on_{}", name),
            locals: vec![Value::Event(fields)],
            ip: 0,
        });
        let code = handler.code.clone();
        self.run_until_return(&code)?;
        self.frames.pop();
        Ok(())
    }

    pub fn run_finish(&mut self) -> Result<()> {
        for handler in self.module.finish_handlers.clone() {
            self.frames.push(CallFrame {
                function: "finish".into(),
                locals: Vec::new(),
                ip: 0,
            });
            let code = handler.code.clone();
            self.run_until_return(&code)?;
            self.frames.pop();
        }
        Ok(())
    }

    pub fn run(&mut self) -> Result<()> {
        let code = self.module.entry.clone();
        self.frames.push(CallFrame {
            function: "<entry>".into(),
            locals: Vec::new(),
            ip: 0,
        });
        self.run_until_return(&code)?;
        self.frames.pop();
        Ok(())
    }

    /// Drive the VM through `code` until the innermost frame returns. Used for both
    /// top-level execution and per-handler / per-finish execution.
    fn run_until_return(&mut self, code: &[Instr]) -> Result<()> {
        loop {
            let frame_ip = {
                let frame = self
                    .frames
                    .last_mut()
                    .ok_or_else(|| TraceError::Runtime {
                        msg: "no active frame".into(),
                        pos: None,
                    })?;
                frame.ip
            };
            let Some(instr) = code.get(frame_ip) else {
                // Past the end of the code segment: implicit return Unit.
                self.frames.pop();
                return Ok(());
            };
            {
                let frame = self.frames.last_mut().unwrap();
                frame.ip += 1;
            }
            match instr.op {
                Opcode::LoadConst => {
                    let v = self
                        .module
                        .constants
                        .get(instr.arg as usize)
                        .cloned()
                        .ok_or_else(|| TraceError::Runtime {
                            msg: format!("LoadConst: out-of-range constant {}", instr.arg),
                            pos: None,
                        })?;
                    self.stack.push(v);
                }
                Opcode::Pop => {
                    self.stack.pop();
                }
                Opcode::LoadVar => {
                    let frame = self.frames.last().unwrap();
                    let v = frame.locals[instr.arg as usize].clone();
                    self.stack.push(v);
                }
                Opcode::StoreVar => {
                    let v = self.stack.last().cloned().ok_or_else(|| TraceError::Runtime {
                        msg: "STORE_VAR: empty stack".into(),
                        pos: None,
                    })?;
                    let frame = self.frames.last_mut().unwrap();
                    let idx = instr.arg as usize;
                    if idx >= frame.locals.len() {
                        frame.locals.resize(idx + 1, Value::Unit);
                    }
                    frame.locals[idx] = v;
                }
                Opcode::Add => self.arith(
                    |a, b| a + b,
                    |a, b| a + b,
                    Some::<fn(&str, &str) -> String>(|a, b| format!("{}{}", a, b)),
                )?,
                Opcode::Sub => self.arith(|a, b| a - b, |a, b| a - b, None::<fn(&str, &str) -> String>)?,
                Opcode::Mul => self.arith(|a, b| a * b, |a, b| a * b, None::<fn(&str, &str) -> String>)?,
                Opcode::Div => {
                    let r = self.pop()?;
                    let l = self.pop()?;
                    let v = match (l, r) {
                        (Value::Int(a), Value::Int(b)) => {
                            if b == 0 {
                                return Err(TraceError::Runtime {
                                    msg: "division by zero".into(),
                                    pos: None,
                                });
                            }
                            Value::Int(a / b)
                        }
                        (Value::Float(a), Value::Float(b)) => {
                            if b == 0.0 {
                                return Err(TraceError::Runtime {
                                    msg: "division by zero".into(),
                                    pos: None,
                                });
                            }
                            Value::Float(a / b)
                        }
                        (Value::Int(a), Value::Float(b)) => Value::Float(a as f64 / b),
                        (Value::Float(a), Value::Int(b)) => Value::Float(a / b as f64),
                        _ => {
                            return Err(TraceError::Runtime {
                                msg: "DIV: type error".into(),
                                pos: None,
                            })
                        }
                    };
                    self.stack.push(v);
                }
                Opcode::Mod => {
                    let r = self.pop()?;
                    let l = self.pop()?;
                    let v = match (l, r) {
                        (Value::Int(a), Value::Int(b)) => Value::Int(a % b),
                        (Value::Float(a), Value::Float(b)) => Value::Float(a % b),
                        _ => {
                            return Err(TraceError::Runtime {
                                msg: "MOD: type error".into(),
                                pos: None,
                            })
                        }
                    };
                    self.stack.push(v);
                }
                Opcode::Eq => {
                    let r = self.pop()?;
                    let l = self.pop()?;
                    self.stack.push(Value::Bool(values_equal(&l, &r)));
                }
                Opcode::NotEq => {
                    let r = self.pop()?;
                    let l = self.pop()?;
                    self.stack.push(Value::Bool(!values_equal(&l, &r)));
                }
                Opcode::Lt => {
                    let r = self.pop()?;
                    let l = self.pop()?;
                    self.stack.push(Value::Bool(
                        values_compare(&l, &r) == std::cmp::Ordering::Less,
                    ));
                }
                Opcode::Gt => {
                    let r = self.pop()?;
                    let l = self.pop()?;
                    self.stack.push(Value::Bool(
                        values_compare(&l, &r) == std::cmp::Ordering::Greater,
                    ));
                }
                Opcode::LtEq => {
                    let r = self.pop()?;
                    let l = self.pop()?;
                    self.stack.push(Value::Bool(
                        values_compare(&l, &r) != std::cmp::Ordering::Greater,
                    ));
                }
                Opcode::GtEq => {
                    let r = self.pop()?;
                    let l = self.pop()?;
                    self.stack.push(Value::Bool(
                        values_compare(&l, &r) != std::cmp::Ordering::Less,
                    ));
                }
                Opcode::And => {
                    let r = self.pop()?;
                    let l = self.pop()?;
                    self.stack.push(Value::Bool(l.is_truthy() && r.is_truthy()));
                }
                Opcode::Or => {
                    let r = self.pop()?;
                    let l = self.pop()?;
                    self.stack.push(Value::Bool(l.is_truthy() || r.is_truthy()));
                }
                Opcode::Not => {
                    let v = self.pop()?;
                    self.stack.push(Value::Bool(!v.is_truthy()));
                }
                Opcode::Neg => {
                    let v = self.pop()?;
                    let r = match v {
                        Value::Int(n) => Value::Int(-n),
                        Value::Float(n) => Value::Float(-n),
                        _ => {
                            return Err(TraceError::Runtime {
                                msg: "NEG: type error".into(),
                                pos: None,
                            })
                        }
                    };
                    self.stack.push(r);
                }
                Opcode::Contains => {
                    let r = self.pop()?;
                    let l = self.pop()?;
                    let res = match (l, r) {
                        (Value::Str(h), Value::Str(n)) => Value::Bool(h.contains(&n)),
                        (Value::Str(h), other) => Value::Bool(h.contains(&other.to_string())),
                        _ => {
                            return Err(TraceError::Runtime {
                                msg: "CONTAINS: type error".into(),
                                pos: None,
                            })
                        }
                    };
                    self.stack.push(res);
                }
                Opcode::Jump => {
                    let frame = self.frames.last_mut().unwrap();
                    frame.ip = instr.arg as usize;
                }
                Opcode::JumpIfFalse => {
                    let v = self.pop()?;
                    if !v.is_truthy() {
                        let frame = self.frames.last_mut().unwrap();
                        frame.ip = instr.arg as usize;
                    }
                }
                Opcode::JumpIfTrue => {
                    let v = self.pop()?;
                    if v.is_truthy() {
                        let frame = self.frames.last_mut().unwrap();
                        frame.ip = instr.arg as usize;
                    }
                }
                Opcode::Call => {
                    let name = self.const_str(instr.arg, "CALL")?.to_string();
                    self.do_call(&name)?;
                }
                Opcode::Return => {
                    let v = self.stack.pop().unwrap_or(Value::Unit);
                    self.frames.pop();
                    if !self.frames.is_empty() {
                        self.stack.push(v);
                    }
                    return Ok(());
                }
                Opcode::GetEventField => {
                    let field = self.const_str(instr.arg, "GETFIELD")?.to_string();
                    let v = self.pop()?;
                    let res = match v {
                        Value::Event(m) => m.get(&field).cloned().unwrap_or(Value::Unit),
                        _ => {
                            return Err(TraceError::Runtime {
                                msg: format!("GETFIELD: cannot read field '{}'", field),
                                pos: None,
                            })
                        }
                    };
                    self.stack.push(res);
                }
                Opcode::DispatchEvent => {
                    // Reserved for future scripts that explicitly emit events.
                }
                Opcode::InsertTable => {
                    let name = self.const_str(instr.arg, "INSERT")?.to_string();
                    let t = self.tables.get(&name).ok_or_else(|| TraceError::Runtime {
                        msg: format!("unknown table '{}'", name),
                        pos: None,
                    })?;
                    let ncols = t.fields.len();
                    let mut row = Vec::with_capacity(ncols);
                    for _ in 0..ncols {
                        row.push(self.pop()?);
                    }
                    row.reverse();
                    self.tables.insert(&name, row).map_err(|e| match e {
                        TraceError::Runtime { msg, .. } => TraceError::Runtime { msg, pos: None },
                        other => other,
                    })?;
                }
                Opcode::ShowTable => {
                    let name = self.const_str(instr.arg, "SHOW")?.to_string();
                    self.tables.show(&name).map_err(|e| match e {
                        TraceError::Runtime { msg, .. } => TraceError::Runtime { msg, pos: None },
                        other => other,
                    })?;
                }
                Opcode::ExportTable => {
                    let name = self.const_str(instr.arg, "EXPORT")?.to_string();
                    let path_v = self.pop()?;
                    let path_str = path_v.as_str().unwrap_or("").to_string();
                    self.tables.export(&name, &path_str).map_err(|e| match e {
                        TraceError::Runtime { msg, .. } => TraceError::Runtime { msg, pos: None },
                        other => other,
                    })?;
                }
                Opcode::Alert => {
                    let n = instr.arg as usize;
                    let mut parts = Vec::with_capacity(n);
                    for _ in 0..n {
                        parts.push(self.pop()?);
                    }
                    parts.reverse();
                    self.alerts.push(parts.clone());
                    let msg: Vec<String> = parts.iter().map(|v| v.to_string()).collect();
                    eprintln!("[ALERT] {}", msg.join(" "));
                }
                Opcode::Print => {
                    let v = self.pop()?;
                    println!("{}", v);
                }
                Opcode::IndexGet => {
                    let tbl = self.const_str(instr.arg, "INDEXGET")?.to_string();
                    let idx_v = self.pop()?;
                    let idx = match idx_v {
                        Value::Int(n) if n >= 0 => n as usize,
                        other => {
                            return Err(TraceError::Runtime {
                                msg: format!(
                                    "index for '{}' must be a non-negative integer, got {}",
                                    tbl,
                                    value_type_name(&other)
                                ),
                                pos: None,
                            });
                        }
                    };
                    let t = self.tables.get(&tbl).ok_or_else(|| TraceError::Runtime {
                        msg: format!("unknown table '{}'", tbl),
                        pos: None,
                    })?;
                    let row = t.rows.get(idx).ok_or_else(|| TraceError::Runtime {
                        msg: format!(
                            "table '{}' has {} rows, index {} is out of range",
                            tbl,
                            t.rows.len(),
                            idx
                        ),
                        pos: None,
                    })?;
                    self.stack.push(Value::Str(row_to_string(row)));
                }
                Opcode::IndexAssign => {
                    let tbl = self.const_str(instr.arg, "INDEXASSIGN")?.to_string();
                    let idx_v = self.pop()?;
                    let value = self.pop()?;
                    let idx = match idx_v {
                        Value::Int(n) if n >= 0 => n as usize,
                        other => {
                            return Err(TraceError::Runtime {
                                msg: format!(
                                    "index for '{}' must be a non-negative integer, got {}",
                                    tbl,
                                    value_type_name(&other)
                                ),
                                pos: None,
                            });
                        }
                    };
                    let t = self.tables.get_mut(&tbl).ok_or_else(|| TraceError::Runtime {
                        msg: format!("unknown table '{}'", tbl),
                        pos: None,
                    })?;
                    // We need the field name. The codegen encodes it via a Pop
                    // instruction with the field-constant index right after the
                    // IndexAssign. Look it up:
                    let next = code
                        .get(self.frames.last().unwrap().ip)
                        .cloned()
                        .ok_or_else(|| TraceError::Runtime {
                            msg: "INDEXASSIGN: missing field operand".into(),
                            pos: None,
                        })?;
                    let field = if let (Opcode::Pop, Instr { op: Opcode::Pop, arg }) = (next.op, next) {
                        match self
                            .module
                            .constants
                            .get(arg as usize)
                            .cloned()
                            .ok_or_else(|| TraceError::Runtime {
                                msg: "INDEXASSIGN: bad field constant".into(),
                                pos: None,
                            })? {
                            Value::Str(s) => s,
                            _ => {
                                return Err(TraceError::Runtime {
                                    msg: "INDEXASSIGN: field constant is not a string".into(),
                                    pos: None,
                                });
                            }
                        }
                    } else {
                        return Err(TraceError::Runtime {
                            msg: format!(
                                "INDEXASSIGN: expected Pop(field), found {:?}",
                                next
                            ),
                            pos: None,
                        });
                    };
                    // Advance past the Pop.
                    self.frames.last_mut().unwrap().ip += 1;
                    let field_idx = t
                        .fields
                        .iter()
                        .position(|f| f.name == field)
                        .ok_or_else(|| TraceError::Runtime {
                            msg: format!("unknown field '{}' on table '{}'", field, tbl),
                            pos: None,
                        })?;
                    let n_rows = t.rows.len();
                    let row = t.rows.get_mut(idx).ok_or_else(|| TraceError::Runtime {
                        msg: format!(
                            "table '{}' has {} rows, index {} is out of range",
                            tbl,
                            n_rows,
                            idx
                        ),
                        pos: None,
                    })?;
                    row[field_idx] = value;
                }
                Opcode::ForInit => {
                    let tbl = self.const_str(instr.arg, "FORINIT")?.to_string();
                    let rows = self
                        .tables
                        .get(&tbl)
                        .ok_or_else(|| TraceError::Runtime {
                            msg: format!("unknown table '{}'", tbl),
                            pos: None,
                        })?
                        .rows
                        .clone();
                    self.iterators
                        .retain(|(k, _)| *k != instr.arg);
                    self.iterators.push((instr.arg, rows.into_iter()));
                }
                Opcode::ForNext => {
                    let exit_at = instr.arg as usize;
                    let next_row = if let Some((_, it)) = self.iterators.last_mut() {
                        it.next()
                    } else {
                        None
                    };
                    match next_row {
                        Some(row) => {
                            self.stack.push(Value::Str(row_to_string(&row)));
                        }
                        None => {
                            self.iterators.pop();
                            // Skip past the trailing back-edge Jump; the next
                            // iteration will execute the statement after the for-loop.
                            self.frames.last_mut().unwrap().ip = exit_at;
                            continue;
                        }
                    }
                }
                Opcode::Halt => {
                    return Ok(());
                }
            }
        }
    }

    fn pop(&mut self) -> Result<Value> {
        self.stack.pop().ok_or_else(|| TraceError::Runtime {
            msg: "stack underflow".into(),
            pos: None,
        })
    }

    fn const_str(&self, idx: u32, op: &str) -> Result<&str> {
        match self
            .module
            .constants
            .get(idx as usize)
            .ok_or_else(|| TraceError::Runtime {
                msg: format!("{}: out-of-range constant {}", op, idx),
                pos: None,
            })? {
            Value::Str(s) => Ok(s.as_str()),
            _ => Err(TraceError::Runtime {
                msg: format!("{}: constant is not a string", op),
                pos: None,
            }),
        }
    }

    fn arith<FInt, FFloat, FStr>(&mut self, int_op: FInt, float_op: FFloat, str_op: Option<FStr>) -> Result<()>
    where
        FInt: Fn(i64, i64) -> i64,
        FFloat: Fn(f64, f64) -> f64,
        FStr: Fn(&str, &str) -> String,
    {
        let r = self.pop()?;
        let l = self.pop()?;
        let v = match (l, r) {
            (Value::Int(a), Value::Int(b)) => Value::Int(int_op(a, b)),
            (Value::Float(a), Value::Float(b)) => Value::Float(float_op(a, b)),
            (Value::Int(a), Value::Float(b)) => Value::Float(float_op(a as f64, b)),
            (Value::Float(a), Value::Int(b)) => Value::Float(float_op(a, b as f64)),
            (Value::Str(a), Value::Str(b)) => {
                if let Some(op) = str_op {
                    Value::Str(op(&a, &b))
                } else {
                    return Err(TraceError::Runtime {
                        msg: "operator does not support strings".into(),
                        pos: None,
                    });
                }
            }
            _ => {
                return Err(TraceError::Runtime {
                    msg: "arithmetic: type error".into(),
                    pos: None,
                })
            }
        };
        self.stack.push(v);
        Ok(())
    }

    fn do_call(&mut self, name: &str) -> Result<()> {
        // Try built-in first — it knows its own arity by name.
        if let Some(arity) = builtins::arity(name) {
            let mut args = Vec::with_capacity(arity);
            for _ in 0..arity {
                args.push(self.pop()?);
            }
            args.reverse();
            let result = builtins::try_call(name, &args);
            match result {
                Some(Ok(v)) => {
                    self.stack.push(v);
                    return Ok(());
                }
                Some(Err(e)) => return Err(e),
                None => unreachable!("builtins::arity returned Some but try_call returned None"),
            }
        }

        // Host functions that need table access.
        match name {
            "count" => {
                let name_v = self.pop()?;
                let name = name_v.as_str().unwrap_or("").to_string();
                let v = host::count(&self.tables, &name)?;
                self.stack.push(v);
                return Ok(());
            }
            "filter" => {
                let needle_v = self.pop()?;
                let field_v = self.pop()?;
                let name_v = self.pop()?;
                let needle = needle_v.as_str().unwrap_or("").to_string();
                let field = field_v.as_str().unwrap_or("").to_string();
                let name = name_v.as_str().unwrap_or("").to_string();
                let v = host::filter(&mut self.tables, &name, &field, &needle)?;
                self.stack.push(v);
                return Ok(());
            }
            "sort" => {
                let field_v = self.pop()?;
                let name_v = self.pop()?;
                let field = field_v.as_str().unwrap_or("").to_string();
                let name = name_v.as_str().unwrap_or("").to_string();
                let v = host::sort(&mut self.tables, &name, &field)?;
                self.stack.push(v);
                return Ok(());
            }
            _ => {}
        }

        // User-defined function.
        let func = self
            .module
            .functions
            .iter()
            .find(|f| f.name == name)
            .cloned()
            .ok_or_else(|| TraceError::Runtime {
                msg: format!("undefined function '{}'", name),
                pos: None,
            })?;
        let arity = func.arity as usize;
        let mut locals = Vec::with_capacity(arity);
        for _ in 0..arity {
            locals.push(self.pop()?);
        }
        locals.reverse();

        self.frames.push(CallFrame {
            function: name.to_string(),
            locals,
            ip: 0,
        });
        let code = func.code.clone();
        self.run_until_return(&code)?;
        Ok(())
    }
}

fn value_type_name(v: &Value) -> &'static str {
    match v {
        Value::Int(_) => "int",
        Value::Float(_) => "float",
        Value::Str(_) => "string",
        Value::Bool(_) => "bool",
        Value::Event(_) => "event",
        Value::Unit => "unit",
    }
}

fn row_to_string(row: &[Value]) -> String {
    let mut s = String::from("{");
    for (i, v) in row.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        s.push_str(&v.to_string());
    }
    s.push('}');
    s
}

fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Int(a), Value::Int(b)) => a == b,
        (Value::Float(a), Value::Float(b)) => a == b,
        (Value::Str(a), Value::Str(b)) => a == b,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Unit, Value::Unit) => true,
        _ => false,
    }
}

fn values_compare(a: &Value, b: &Value) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (a, b) {
        (Value::Int(a), Value::Int(b)) => a.cmp(b),
        (Value::Float(a), Value::Float(b)) => a.partial_cmp(b).unwrap_or(Ordering::Equal),
        (Value::Int(a), Value::Float(b)) => (*a as f64).partial_cmp(b).unwrap_or(Ordering::Equal),
        (Value::Float(a), Value::Int(b)) => a.partial_cmp(&(*b as f64)).unwrap_or(Ordering::Equal),
        (Value::Str(a), Value::Str(b)) => a.cmp(b),
        (Value::Bool(a), Value::Bool(b)) => a.cmp(b),
        _ => Ordering::Equal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::codegen::compile;
    use crate::parser::Parser;

    fn compile_src(src: &str) -> BytecodeModule {
        let prog = Parser::from_source(src).unwrap().parse_program().unwrap();
        compile(&prog).unwrap()
    }

    #[test]
    fn dispatch_event_inserts_row() {
        let module = compile_src("table t { a: string } on e(x) { insert t(\"hello\") }");
        let mut vm = VM::new(module).unwrap();
        let mut fields = HashMap::new();
        fields.insert("anything".into(), Value::Int(1));
        vm.dispatch_event("e", fields).unwrap();
        let t = vm.tables.get("t").unwrap();
        assert_eq!(t.rows.len(), 1);
    }

    #[test]
    fn finish_handler_runs() {
        let module = compile_src(
            "table t { a: string } on e(x) { insert t(\"x\") } after finish { show t }",
        );
        let mut vm = VM::new(module).unwrap();
        let mut fields = HashMap::new();
        fields.insert("k".into(), Value::Int(0));
        vm.dispatch_event("e", fields).unwrap();
        vm.run_finish().unwrap();
        let t = vm.tables.get("t").unwrap();
        assert_eq!(t.rows.len(), 1);
    }

    #[test]
    fn user_function_call() {
        let module = compile_src(
            "function double(n) { return n * 2 } on e(x) { print double(5) }",
        );
        let mut vm = VM::new(module).unwrap();
        let mut fields = HashMap::new();
        fields.insert("k".into(), Value::Int(0));
        vm.dispatch_event("e", fields).unwrap();
    }

    #[test]
    fn alert_fires() {
        let module = compile_src("on e(x) { alert(\"hi\", x) }");
        let mut vm = VM::new(module).unwrap();
        let mut fields = HashMap::new();
        fields.insert("k".into(), Value::Str("v".into()));
        vm.dispatch_event("e", fields).unwrap();
        assert_eq!(vm.alerts.len(), 1);
    }
}