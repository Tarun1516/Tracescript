//! Tree-walking interpreter for TraceScript.

use std::collections::HashMap;

use crate::error::{Result, SourcePos, TraceError};
use crate::host;
use crate::parser::*;
use crate::sema::SymbolTable;
use crate::tables::TableStore;

pub mod builtins;
use builtins::try_call as builtin_call;
pub mod value;
pub use value::Value;

pub struct Interpreter {
    pub tables: TableStore,
    pub alerts: Vec<Vec<Value>>,
    functions: HashMap<String, FunctionDecl>,
    event_handlers: HashMap<String, EventHandlerDecl>,
    finish_handlers: Vec<FinishHandlerDecl>,
    source: Option<String>,
    repl_locals: HashMap<String, Value>,
}

impl Interpreter {
    pub fn new(program: &Program, _symbols: &SymbolTable) -> Result<Self> {
        let mut tables = TableStore::new();
        let mut functions = HashMap::new();
        let mut event_handlers = HashMap::new();
        let mut finish_handlers = Vec::new();
        let mut source = None;
        for decl in &program.declarations {
            match decl {
                Decl::Source(s) => source = Some(s.path.clone()),
                Decl::Table(t) => tables.create(t.name.clone(), t.fields.clone())?,
                Decl::Function(f) => {
                    functions.insert(f.name.clone(), f.clone());
                }
                Decl::EventHandler(e) => {
                    event_handlers.insert(e.event_name.clone(), e.clone());
                }
                Decl::FinishHandler(f) => finish_handlers.push(f.clone()),
            }
        }
        Ok(Self {
            tables,
            alerts: Vec::new(),
            functions,
            event_handlers,
            finish_handlers,
            source,
            repl_locals: HashMap::new(),
        })
    }

    /// Seed the interpreter with a pre-existing set of locals before running a
    /// REPL block. Used so that `let x = 5` in one line is visible to subsequent
    /// expressions.
    pub fn preload_locals(&mut self, locals: HashMap<String, Value>) {
        self.repl_locals = locals;
    }

    /// Snapshot the current locals for persistence across REPL invocations.
    pub fn snapshot_locals(&self) -> HashMap<String, Value> {
        self.repl_locals.clone()
    }

    /// Run a block of statements under the REPL's saved locals, returning the
    /// value of the last expression-evaluating statement (if any).
    pub fn eval_repl_block(&mut self, body: &[Stmt]) -> Result<Value> {
        let mut last = Value::Unit;
        let mut locals = self.repl_locals.clone();
        for stmt in body {
            match self.exec_stmt_with_return(stmt, &mut locals) {
                Ok(Some(v)) => last = v,
                Ok(None) => {}
                Err(e) => {
                    self.repl_locals = locals;
                    return Err(e);
                }
            }
        }
        self.repl_locals = locals;
        Ok(last)
    }

    /// Like `exec_stmt` but captures the value of `let` / assignment / expression-
    /// evaluating statements.
    fn exec_stmt_with_return(
        &mut self,
        stmt: &Stmt,
        locals: &mut HashMap<String, Value>,
    ) -> Result<Option<Value>> {
        match stmt {
            Stmt::Let { name, value, pos } => {
                let v = self.eval_expr(value, locals, pos)?;
                locals.insert(name.clone(), v.clone());
                Ok(Some(v))
            }
            Stmt::Assign { name, value, pos } => {
                let v = self.eval_expr(value, locals, pos)?;
                locals.insert(name.clone(), v.clone());
                Ok(Some(v))
            }
            Stmt::Print { value, pos } => {
                let v = self.eval_expr(value, locals, pos)?;
                println!("{}", v);
                Ok(Some(v))
            }
            Stmt::Return { value, pos } => {
                let v = if let Some(v) = value {
                    Some(self.eval_expr(v, locals, pos)?)
                } else {
                    Some(Value::Unit)
                };
                if let Some(v) = v {
                    Ok(Some(v))
                } else {
                    Ok(None)
                }
            }
            other => {
                self.exec_stmt(other, locals)?;
                Ok(None)
            }
        }
    }

    /// Register a synthetic event source. The runner opens the file specified in the
    /// `source pcap "..."` declaration and emits events into this interpreter.
    pub fn source_path(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// Dispatch an event by name. Returns Ok even if no handler exists, so missing
    /// handlers are silent (matches Zeek semantics).
    pub fn dispatch_event(&mut self, name: &str, fields: HashMap<String, Value>) -> Result<()> {
        if let Some(handler) = self.event_handlers.get(name).cloned() {
            let event = Value::Event(fields);
            let mut locals = HashMap::new();
            locals.insert(handler.param_name.clone(), event);
            for stmt in handler.body {
                self.exec_stmt(&stmt, &mut locals)?;
            }
        }
        Ok(())
    }

    /// Run the `after finish` handlers.
    pub fn run_finish(&mut self) -> Result<()> {
        for handler in self.finish_handlers.clone() {
            let mut locals = HashMap::new();
            for stmt in handler.body {
                self.exec_stmt(&stmt, &mut locals)?;
            }
        }
        Ok(())
    }

    fn exec_block(&mut self, body: &[Stmt], locals: &mut HashMap<String, Value>) -> Result<()> {
        for stmt in body {
            self.exec_stmt(stmt, locals)?;
        }
        Ok(())
    }

    fn exec_stmt(&mut self, stmt: &Stmt, locals: &mut HashMap<String, Value>) -> Result<()> {
        match stmt {
            Stmt::Let { name, value, pos } => {
                let v = self.eval_expr(value, locals, pos)?;
                locals.insert(name.clone(), v);
            }
            Stmt::Assign { name, value, pos } => {
                let v = self.eval_expr(value, locals, pos)?;
                if !locals.contains_key(name) {
                    return Err(TraceError::Runtime {
                        msg: format!("assign to undefined variable '{}'", name),
                        pos: Some(pos.clone()),
                    });
                }
                locals.insert(name.clone(), v);
            }
            Stmt::IndexAssign { table, index, field, value, pos } => {
                let idx_v = self.eval_expr(index, locals, pos)?;
                let idx = match idx_v {
                    Value::Int(n) if n >= 0 => n as usize,
                    other => {
                        return Err(TraceError::Runtime {
                            msg: format!(
                                "index for '{}' must be a non-negative integer, got {}",
                                table,
                                type_name(&other)
                            ),
                            pos: Some(pos.clone()),
                        });
                    }
                };
                let new_val = self.eval_expr(value, locals, pos)?;
                let field_idx = self
                    .tables
                    .get(&table)
                    .and_then(|t| t.fields.iter().position(|f| f.name == *field))
                    .ok_or_else(|| TraceError::Runtime {
                        msg: format!("unknown field '{}' on table '{}'", field, table),
                        pos: Some(pos.clone()),
                    })?;
                let t = self.tables.get_mut(&table).ok_or_else(|| TraceError::Runtime {
                    msg: format!("unknown table '{}'", table),
                    pos: Some(pos.clone()),
                })?;
                let n_rows = t.rows.len();
                let row = t.rows.get_mut(idx).ok_or_else(|| TraceError::Runtime {
                    msg: format!(
                        "table '{}' has {} rows, index {} is out of range",
                        table,
                        n_rows,
                        idx
                    ),
                    pos: Some(pos.clone()),
                })?;
                row[field_idx] = new_val;
            }
            Stmt::If { condition, then_branch, else_branch, pos } => {
                let cond = self.eval_expr(condition, locals, pos)?;
                if cond.is_truthy() {
                    self.exec_block(then_branch, locals)?;
                } else if let Some(else_branch) = else_branch {
                    self.exec_block(else_branch, locals)?;
                }
            }
            Stmt::For { var, table, body, pos } => {
                // Snapshot the rows so an `insert` inside the body doesn't extend the
                // iteration.
                let snapshot: Vec<Vec<Value>> = self
                    .tables
                    .get(&table)
                    .ok_or_else(|| TraceError::Runtime {
                        msg: format!("unknown table '{}'", table),
                        pos: Some(pos.clone()),
                    })?
                    .rows
                    .clone();
                for row in snapshot {
                    // Bind the loop variable to a JSON-shaped snapshot of the row.
                    locals.insert(var.clone(), Value::Str(row_to_string(&row)));
                    self.exec_block(body, locals)?;
                }
            }
            Stmt::Insert { table_name, values, pos } => {
                let mut row = Vec::with_capacity(values.len());
                for v in values {
                    row.push(self.eval_expr(v, locals, pos)?);
                }
                self.tables.insert(table_name, row).map_err(|e| match e {
                    TraceError::Runtime { msg, .. } => TraceError::Runtime {
                        msg,
                        pos: Some(pos.clone()),
                    },
                    other => other,
                })?;
            }
            Stmt::Alert { values, pos } => {
                let mut parts = Vec::with_capacity(values.len());
                for v in values {
                    parts.push(self.eval_expr(v, locals, pos)?);
                }
                self.alerts.push(parts.clone());
                // also print to stderr so the analyst sees it immediately
                let msg: Vec<String> = parts.iter().map(|v| v.to_string()).collect();
                eprintln!("[ALERT] {}", msg.join(" "));
            }
            Stmt::Show { table_name, pos } => {
                self.tables.show(table_name).map_err(|e| match e {
                    TraceError::Runtime { msg, .. } => TraceError::Runtime {
                        msg,
                        pos: Some(pos.clone()),
                    },
                    other => other,
                })?;
            }
            Stmt::Export { table_name, path, pos } => {
                self.tables
                    .export(table_name, path)
                    .map_err(|e| match e {
                        TraceError::Runtime { msg, .. } => TraceError::Runtime {
                            msg,
                            pos: Some(pos.clone()),
                        },
                        other => other,
                    })?;
                eprintln!("Exported table {} to {}", table_name, path);
            }
            Stmt::Print { value, pos } => {
                let v = self.eval_expr(value, locals, pos)?;
                println!("{}", v);
            }
            Stmt::CallStmt { name, args, pos } => {
                let _ = self.eval_call(name, args, locals, pos)?;
            }
            Stmt::Return { value, pos } => {
                let v = if let Some(v) = value {
                    Some(self.eval_expr(v, locals, pos)?)
                } else {
                    None
                };
                return Err(TraceError::ReturnSignal { value: v });
            }
        }
        Ok(())
    }

    fn eval_expr(
        &mut self,
        expr: &Expr,
        locals: &mut HashMap<String, Value>,
        pos: &SourcePos,
    ) -> Result<Value> {
        match expr {
            Expr::Integer(n) => Ok(Value::Int(*n)),
            Expr::Float(n) => Ok(Value::Float(*n)),
            Expr::Str(s) => Ok(Value::Str(s.clone())),
            Expr::Bool(b) => Ok(Value::Bool(*b)),
            Expr::Identifier(name) => {
                if let Some(v) = locals.get(name) {
                    Ok(v.clone())
                } else {
                    Err(TraceError::Runtime {
                        msg: format!("undefined identifier '{}'", name),
                        pos: Some(pos.clone()),
                    })
                }
            }
            Expr::Binary { left, operator, right, pos } => {
                let l = self.eval_expr(left, locals, pos)?;
                let r = self.eval_expr(right, locals, pos)?;
                self.eval_binop(operator.clone(), l, r, pos)
            }
            Expr::Unary { operator, operand, pos } => {
                let v = self.eval_expr(operand, locals, pos)?;
                match operator {
                    UnOp::Not => Ok(Value::Bool(!v.is_truthy())),
                    UnOp::Neg => match v {
                        Value::Int(n) => Ok(Value::Int(-n)),
                        Value::Float(n) => Ok(Value::Float(-n)),
                        other => Err(TraceError::Runtime {
                            msg: format!("cannot negate value of type {}", type_name(&other)),
                            pos: Some(pos.clone()),
                        }),
                    },
                }
            }
            Expr::Call { name, args, pos } => self.eval_call(name, args, locals, pos),
            Expr::FieldAccess { object, field, pos } => {
                let v = self.eval_expr(object, locals, pos)?;
                match v {
                    Value::Event(map) => {
                        if let Some(val) = map.get(field) {
                            Ok(val.clone())
                        } else {
                            Err(TraceError::Runtime {
                                msg: format!("event has no field '{}'", field),
                                pos: Some(pos.clone()),
                            })
                        }
                    }
                    other => Err(TraceError::Runtime {
                        msg: format!("cannot access field on value of type {}", type_name(&other)),
                        pos: Some(pos.clone()),
                    }),
                }
            }
            Expr::Index { table, index, pos } => {
                let idx_v = self.eval_expr(index, locals, pos)?;
                let idx = match idx_v {
                    Value::Int(n) if n >= 0 => n as usize,
                    other => {
                        return Err(TraceError::Runtime {
                            msg: format!(
                                "index for '{}' must be a non-negative integer, got {}",
                                table,
                                type_name(&other)
                            ),
                            pos: Some(pos.clone()),
                        });
                    }
                };
                let t = self.tables.get(&table).ok_or_else(|| TraceError::Runtime {
                    msg: format!("unknown table '{}'", table),
                    pos: Some(pos.clone()),
                })?;
                let row = t.rows.get(idx).ok_or_else(|| TraceError::Runtime {
                    msg: format!(
                        "table '{}' has {} rows, index {} is out of range",
                        table,
                        t.rows.len(),
                        idx
                    ),
                    pos: Some(pos.clone()),
                })?;
                Ok(Value::Str(row_to_string(row)))
            }
        }
    }

    fn eval_call(
        &mut self,
        name: &str,
        args: &[Expr],
        locals: &mut HashMap<String, Value>,
        pos: &SourcePos,
    ) -> Result<Value> {
        let mut evaluated = Vec::with_capacity(args.len());
        for a in args {
            evaluated.push(self.eval_expr(a, locals, pos)?);
        }
        if let Some(result) = builtin_call(name, &evaluated) {
            return result;
        }
        // Host functions that need access to the table store.
        match name {
            "count" => {
                let n = evaluated
                    .get(0)
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| TraceError::Runtime {
                        msg: "count: expected a table name".into(),
                        pos: Some(pos.clone()),
                    })?;
                return host::count(&self.tables, n);
            }
            "filter" => {
                let name = evaluated.get(0).and_then(|v| v.as_str()).unwrap_or("").to_string();
                let field = evaluated.get(1).and_then(|v| v.as_str()).unwrap_or("").to_string();
                let needle = evaluated.get(2).and_then(|v| v.as_str()).unwrap_or("").to_string();
                return host::filter(&mut self.tables, &name, &field, &needle);
            }
            "sort" => {
                let name = evaluated.get(0).and_then(|v| v.as_str()).unwrap_or("").to_string();
                let field = evaluated.get(1).and_then(|v| v.as_str()).unwrap_or("").to_string();
                return host::sort(&mut self.tables, &name, &field);
            }
            _ => {}
        }
        // user-defined function
        let func = self
            .functions
            .get(name)
            .cloned()
            .ok_or_else(|| TraceError::Runtime {
                msg: format!("undefined function '{}'", name),
                pos: Some(pos.clone()),
            })?;
        if func.params.len() != evaluated.len() {
            return Err(TraceError::Runtime {
                msg: format!(
                    "function '{}' expects {} args, got {}",
                    name,
                    func.params.len(),
                    evaluated.len()
                ),
                pos: Some(pos.clone()),
            });
        }
        let mut frame: HashMap<String, Value> = HashMap::new();
        for (p, v) in func.params.iter().zip(evaluated.into_iter()) {
            frame.insert(p.clone(), v);
        }
        match self.exec_block(&func.body, &mut frame) {
            Ok(_) => Ok(Value::Unit),
            Err(TraceError::ReturnSignal { value }) => Ok(value.unwrap_or(Value::Unit)),
            Err(other) => Err(other),
        }
    }

    fn eval_binop(
        &self,
        op: BinOp,
        l: Value,
        r: Value,
        pos: &SourcePos,
    ) -> Result<Value> {
        let rt = || TraceError::Runtime { msg: "type error in binary expression".into(), pos: Some(pos.clone()) };
        match op {
            BinOp::Add => match (l, r) {
                (Value::Int(a), Value::Int(b)) => Ok(Value::Int(a + b)),
                (Value::Float(a), Value::Float(b)) => Ok(Value::Float(a + b)),
                (Value::Int(a), Value::Float(b)) => Ok(Value::Float(a as f64 + b)),
                (Value::Float(a), Value::Int(b)) => Ok(Value::Float(a + b as f64)),
                (Value::Str(a), Value::Str(b)) => Ok(Value::Str(format!("{}{}", a, b))),
                _ => Err(rt()),
            },
            BinOp::Sub => match (l, r) {
                (Value::Int(a), Value::Int(b)) => Ok(Value::Int(a - b)),
                (Value::Float(a), Value::Float(b)) => Ok(Value::Float(a - b)),
                (Value::Int(a), Value::Float(b)) => Ok(Value::Float(a as f64 - b)),
                (Value::Float(a), Value::Int(b)) => Ok(Value::Float(a - b as f64)),
                _ => Err(rt()),
            },
            BinOp::Mul => match (l, r) {
                (Value::Int(a), Value::Int(b)) => Ok(Value::Int(a * b)),
                (Value::Float(a), Value::Float(b)) => Ok(Value::Float(a * b)),
                (Value::Int(a), Value::Float(b)) => Ok(Value::Float(a as f64 * b)),
                (Value::Float(a), Value::Int(b)) => Ok(Value::Float(a * b as f64)),
                _ => Err(rt()),
            },
            BinOp::Div => match (l, r) {
                (Value::Int(a), Value::Int(b)) => {
                    if b == 0 {
                        Err(TraceError::Runtime { msg: "division by zero".into(), pos: Some(pos.clone()) })
                    } else {
                        Ok(Value::Int(a / b))
                    }
                }
                (Value::Float(a), Value::Float(b)) => {
                    if b == 0.0 {
                        Err(TraceError::Runtime { msg: "division by zero".into(), pos: Some(pos.clone()) })
                    } else {
                        Ok(Value::Float(a / b))
                    }
                }
                (Value::Int(a), Value::Float(b)) => Ok(Value::Float(a as f64 / b)),
                (Value::Float(a), Value::Int(b)) => Ok(Value::Float(a / b as f64)),
                _ => Err(rt()),
            },
            BinOp::Mod => match (l, r) {
                (Value::Int(a), Value::Int(b)) => Ok(Value::Int(a % b)),
                (Value::Float(a), Value::Float(b)) => Ok(Value::Float(a % b)),
                _ => Err(rt()),
            },
            BinOp::Eq => Ok(Value::Bool(values_eq(&l, &r))),
            BinOp::NotEq => Ok(Value::Bool(!values_eq(&l, &r))),
            BinOp::Lt => compare_values(&l, &r, pos, |o| o == std::cmp::Ordering::Less),
            BinOp::Gt => compare_values(&l, &r, pos, |o| o == std::cmp::Ordering::Greater),
            BinOp::LtEq => compare_values(&l, &r, pos, |o| o != std::cmp::Ordering::Greater),
            BinOp::GtEq => compare_values(&l, &r, pos, |o| o != std::cmp::Ordering::Less),
            BinOp::And => Ok(Value::Bool(l.is_truthy() && r.is_truthy())),
            BinOp::Or => Ok(Value::Bool(l.is_truthy() || r.is_truthy())),
            BinOp::Contains => match (l, r) {
                (Value::Str(hay), Value::Str(needle)) => Ok(Value::Bool(hay.contains(&needle))),
                (Value::Str(hay), other) => Ok(Value::Bool(hay.contains(&other.to_string()))),
                _ => Err(rt()),
            },
        }
    }
}

fn values_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Int(a), Value::Int(b)) => a == b,
        (Value::Float(a), Value::Float(b)) => a == b,
        (Value::Str(a), Value::Str(b)) => a == b,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Unit, Value::Unit) => true,
        _ => false,
    }
}

fn compare_values<F: FnOnce(std::cmp::Ordering) -> bool>(
    l: &Value,
    r: &Value,
    pos: &SourcePos,
    f: F,
) -> Result<Value> {
    use std::cmp::Ordering;
    let ord = match (l, r) {
        (Value::Int(a), Value::Int(b)) => a.cmp(b),
        (Value::Float(a), Value::Float(b)) => a.partial_cmp(b).unwrap_or(Ordering::Equal),
        (Value::Int(a), Value::Float(b)) => (*a as f64).partial_cmp(b).unwrap_or(Ordering::Equal),
        (Value::Float(a), Value::Int(b)) => a.partial_cmp(&(*b as f64)).unwrap_or(Ordering::Equal),
        (Value::Str(a), Value::Str(b)) => a.cmp(b),
        _ => {
            return Err(TraceError::Runtime {
                msg: "type error in comparison".into(),
                pos: Some(pos.clone()),
            })
        }
    };
    Ok(Value::Bool(f(ord)))
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Int(_) => "int",
        Value::Float(_) => "float",
        Value::Str(_) => "string",
        Value::Bool(_) => "bool",
        Value::Event(_) => "event",
        Value::Unit => "unit",
    }
}

/// Render a row as a JSON-shaped string. Used by `Expr::Index` so that a script
/// can `print rows[i]` for diagnostic dumps.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::Parser;
    use crate::sema::Analyzer;

    fn run(src: &str) -> Interpreter {
        let prog = Parser::from_source(src).unwrap().parse_program().unwrap();
        let mut analyzer = Analyzer::new();
        analyzer.analyze(&prog).unwrap();
        let symbols = analyzer.into_symbols();
        Interpreter::new(&prog, &symbols).unwrap()
    }

    #[test]
    fn simple_print() {
        let mut interp = run("function f() { print 1 + 2 } on e(x) { f() }");
        let mut fields = HashMap::new();
        fields.insert("a".into(), Value::Int(1));
        interp.dispatch_event("e", fields).unwrap();
    }

    #[test]
    fn table_insert_show() {
        let mut interp = run(
            "table t { a: string } on e(x) { insert t(\"hello\") } after finish { show t }",
        );
        let mut fields = HashMap::new();
        fields.insert("a".into(), Value::Int(0));
        interp.dispatch_event("e", fields).unwrap();
        interp.run_finish().unwrap();
    }

    #[test]
    fn if_else_branch() {
        let mut interp = run(
            "function f(n) { if n > 5 { return 1 } else { return 0 } } on e(x) { let r = f(10) print r }",
        );
        let mut fields = HashMap::new();
        fields.insert("x".into(), Value::Int(0));
        interp.dispatch_event("e", fields).unwrap();
    }

    #[test]
    fn repl_persists_let_bindings() {
        use crate::sema::SymbolTable;
        let prog1 = Parser::from_source("function __r() { let x = 5 }")
            .unwrap()
            .parse_program()
            .unwrap();
        let mut a1 = Analyzer::new();
        a1.analyze(&prog1).unwrap();
        let mut interp1 = Interpreter::new(&prog1, &a1.into_symbols()).unwrap();
        let body1 = match &prog1.declarations[0] {
            Decl::Function(f) => f.body.clone(),
            _ => unreachable!(),
        };
        interp1.eval_repl_block(&body1).unwrap();
        let snap = interp1.snapshot_locals();
        assert_eq!(snap.get("x"), Some(&Value::Int(5)));

        let prog2 = Parser::from_source("function __r() { let y = x + 1 }")
            .unwrap()
            .parse_program()
            .unwrap();
        let mut interp2 = Interpreter::new(&prog2, &SymbolTable::default()).unwrap();
        interp2.preload_locals(snap);
        let body2 = match &prog2.declarations[0] {
            Decl::Function(f) => f.body.clone(),
            _ => unreachable!(),
        };
        let v = interp2.eval_repl_block(&body2).unwrap();
        assert_eq!(v, Value::Int(6));
    }
}