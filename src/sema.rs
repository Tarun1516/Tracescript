//! Semantic analyzer for TraceScript.
//!
//! Walks the AST and validates that names resolve, table inserts have the right arity,
//! event handler parameters are well-formed, and so on. Pure: produces diagnostics, never
//! executes anything.

use std::collections::{HashMap, HashSet};

use crate::error::{Result, SourcePos, TraceError};
use crate::parser::*;

#[derive(Debug, Clone)]
pub struct TableInfo {
    pub name: String,
    pub fields: Vec<TableField>,
    pub pos: SourcePos,
}

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub arity: usize,
    pub pos: SourcePos,
}

#[derive(Debug, Clone)]
pub struct EventHandlerInfo {
    pub event_name: String,
    pub param_name: String,
    pub pos: SourcePos,
}

#[derive(Debug, Clone, Default)]
pub struct SymbolTable {
    pub tables: HashMap<String, TableInfo>,
    pub functions: HashMap<String, FunctionInfo>,
    pub event_handlers: HashMap<String, EventHandlerInfo>,
    pub finish_handlers: Vec<SourcePos>,
    pub source: Option<String>,
}

pub struct Analyzer {
    symbols: SymbolTable,
    diagnostics: Vec<TraceError>,
}

impl Analyzer {
    pub fn new() -> Self {
        Self {
            symbols: SymbolTable::default(),
            diagnostics: Vec::new(),
        }
    }

    pub fn into_symbols(self) -> SymbolTable {
        self.symbols
    }

    pub fn analyze(&mut self, program: &Program) -> Result<()> {
        // Pass 1: collect declarations
        for decl in &program.declarations {
            self.collect_decl(decl)?;
        }

        // Pass 2: validate bodies
        for decl in &program.declarations {
            self.validate_decl(decl)?;
        }

        if !self.diagnostics.is_empty() {
            return Err(self.diagnostics.remove(0));
        }
        Ok(())
    }

    fn table_exists(&self, name: &str) -> bool {
        self.symbols.tables.contains_key(name)
    }

    fn err_unknown(&mut self, table: &str) {
        self.err(
            format!("unknown table '{}'", table),
            SourcePos::new(0, 0, 0),
        );
    }

    fn err(&mut self, msg: impl Into<String>, pos: SourcePos) {
        self.diagnostics.push(TraceError::Semantic {
            msg: msg.into(),
            pos,
        });
    }

    fn collect_decl(&mut self, decl: &Decl) -> Result<()> {
        match decl {
            Decl::Source(s) => {
                if !matches!(s.source_type.as_str(), "pcap" | "jsonl" | "csv") {
                    self.err(
                        format!("unsupported source type '{}'", s.source_type),
                        s.pos.clone(),
                    );
                }
                if self.symbols.source.is_some() {
                    self.err("duplicate source declaration", s.pos.clone());
                } else {
                    self.symbols.source = Some(s.path.clone());
                }
            }
            Decl::Table(t) => {
                if self.symbols.tables.contains_key(&t.name) {
                    self.err(
                        format!("duplicate table '{}'", t.name),
                        t.pos.clone(),
                    );
                } else {
                    self.symbols.tables.insert(
                        t.name.clone(),
                        TableInfo {
                            name: t.name.clone(),
                            fields: t.fields.clone(),
                            pos: t.pos.clone(),
                        },
                    );
                }
            }
            Decl::EventHandler(h) => {
                if self.symbols.event_handlers.contains_key(&h.event_name) {
                    self.err(
                        format!("duplicate event handler '{}'", h.event_name),
                        h.pos.clone(),
                    );
                } else {
                    self.symbols.event_handlers.insert(
                        h.event_name.clone(),
                        EventHandlerInfo {
                            event_name: h.event_name.clone(),
                            param_name: h.param_name.clone(),
                            pos: h.pos.clone(),
                        },
                    );
                }
            }
            Decl::FinishHandler(f) => {
                if !self.symbols.finish_handlers.is_empty() {
                    self.err("duplicate 'after finish' handler", f.pos.clone());
                } else {
                    self.symbols.finish_handlers.push(f.pos.clone());
                }
            }
            Decl::Function(f) => {
                if self.symbols.functions.contains_key(&f.name) {
                    self.err(
                        format!("duplicate function '{}'", f.name),
                        f.pos.clone(),
                    );
                } else {
                    self.symbols.functions.insert(
                        f.name.clone(),
                        FunctionInfo {
                            name: f.name.clone(),
                            arity: f.params.len(),
                            pos: f.pos.clone(),
                        },
                    );
                }
            }
        }
        Ok(())
    }

    fn validate_decl(&mut self, decl: &Decl) -> Result<()> {
        match decl {
            Decl::Source(_) | Decl::Table(_) => {}
            Decl::EventHandler(h) => {
                let mut locals = HashSet::new();
                locals.insert(h.param_name.clone());
                self.validate_block(&h.body, &mut locals)?;
            }
            Decl::FinishHandler(f) => self.validate_block(&f.body, &mut HashSet::new())?,
            Decl::Function(f) => {
                let mut locals = HashSet::new();
                for p in &f.params {
                    locals.insert(p.clone());
                }
                self.validate_block(&f.body, &mut locals)?;
            }
        }
        Ok(())
    }

    fn validate_block(&mut self, body: &[Stmt], locals: &mut HashSet<String>) -> Result<()> {
        for stmt in body {
            self.validate_stmt(stmt, locals)?;
        }
        Ok(())
    }

    fn validate_stmt(&mut self, stmt: &Stmt, locals: &mut HashSet<String>) -> Result<()> {
        match stmt {
            Stmt::Let { name, value, pos: _ } => {
                self.validate_expr(value, locals)?;
                locals.insert(name.clone());
            }
            Stmt::Assign { name, value, pos } => {
                if !locals.contains(name) {
                    self.err(format!("assign to undefined variable '{}'", name), pos.clone());
                }
                self.validate_expr(value, locals)?;
            }
            Stmt::If { condition, then_branch, else_branch, pos: _ } => {
                self.validate_expr(condition, locals)?;
                let mut then_locals = locals.clone();
                self.validate_block(then_branch, &mut then_locals)?;
                if let Some(else_branch) = else_branch {
                    let mut else_locals = locals.clone();
                    self.validate_block(else_branch, &mut else_locals)?;
                }
            }
            Stmt::For { var, table, body, pos: _ } => {
                if !self.table_exists(table) {
                    self.err_unknown(table);
                }
                let mut body_locals = locals.clone();
                body_locals.insert(var.clone());
                self.validate_block(body, &mut body_locals)?;
            }
            Stmt::IndexAssign { table, index, field, value, pos: _ } => {
                if !self.table_exists(table) {
                    self.err_unknown(table);
                }
                self.validate_expr(index, locals)?;
                self.validate_expr(value, locals)?;
                let _ = field; // field validity is checked at runtime
            }
            Stmt::Insert { table_name, values, pos } => {
                let info = self.symbols.tables.get(table_name).cloned();
                match info {
                    Some(t) => {
                        if t.fields.len() != values.len() {
                            self.err(
                                format!(
                                    "table '{}' expects {} values, but insert provides {}",
                                    table_name,
                                    t.fields.len(),
                                    values.len()
                                ),
                                pos.clone(),
                            );
                        }
                    }
                    None => self.err(format!("unknown table '{}'", table_name), pos.clone()),
                }
                for v in values {
                    self.validate_expr(v, locals)?;
                }
            }
            Stmt::Alert { values, pos: _ } => {
                for v in values {
                    self.validate_expr(v, locals)?;
                }
            }
            Stmt::Show { table_name, pos } => {
                if !self.symbols.tables.contains_key(table_name) {
                    self.err(format!("unknown table '{}'", table_name), pos.clone());
                }
            }
            Stmt::Export { table_name, pos, .. } => {
                if !self.symbols.tables.contains_key(table_name) {
                    self.err(format!("unknown table '{}'", table_name), pos.clone());
                }
            }
            Stmt::Print { value, pos: _ } => {
                self.validate_expr(value, locals)?;
            }
            Stmt::CallStmt { name, args, pos } => {
                self.validate_call(name, args.len(), pos, locals)?;
                for a in args {
                    self.validate_expr(a, locals)?;
                }
            }
            Stmt::Return { value, pos: _ } => {
                if let Some(v) = value {
                    self.validate_expr(v, locals)?;
                }
            }
        }
        Ok(())
    }

    fn validate_call(
        &mut self,
        name: &str,
        arity: usize,
        pos: &SourcePos,
        locals: &mut HashSet<String>,
    ) -> Result<()> {
        // Built-ins are validated separately at call-time by the interpreter; only
        // user-defined functions need arity checks here.
        match name {
            "len" | "contains" | "starts_with" | "ends_with" | "to_string" | "now" | "count"
            | "filter" | "sort" | "hash_sha256" | "substring" | "lower" | "upper" | "trim" => {
                return Ok(());
            }
            _ => {}
        }
        match self.symbols.functions.get(name) {
            Some(f) => {
                if f.arity != arity {
                    self.err(
                        format!("function '{}' expects {} args, got {}", name, f.arity, arity),
                        pos.clone(),
                    );
                }
            }
            None => {
                if !locals.contains(name) {
                    self.err(format!("undefined function '{}'", name), pos.clone());
                }
            }
        }
        Ok(())
    }

    fn validate_expr(&mut self, expr: &Expr, locals: &mut HashSet<String>) -> Result<()> {
        match expr {
            Expr::Integer(_) | Expr::Float(_) | Expr::Str(_) | Expr::Bool(_) => {}
            Expr::Identifier(name) => {
                if !self.is_known(name, locals) {
                    self.err(format!("undefined identifier '{}'", name), SourcePos::new(0, 0, 0));
                }
            }
            Expr::Binary { left, right, .. } => {
                self.validate_expr(left, locals)?;
                self.validate_expr(right, locals)?;
            }
            Expr::Unary { operand, .. } => {
                self.validate_expr(operand, locals)?;
            }
            Expr::Call { name, args, pos } => {
                self.validate_call(name, args.len(), pos, locals)?;
                for a in args {
                    self.validate_expr(a, locals)?;
                }
            }
            Expr::FieldAccess { object, .. } => {
                self.validate_expr(object, locals)?;
            }
            Expr::Index { table, index, .. } => {
                if !self.table_exists(table) {
                    self.err_unknown(table);
                }
                self.validate_expr(index, locals)?;
            }
        }
        Ok(())
    }

    fn is_known(&self, name: &str, locals: &HashSet<String>) -> bool {
        locals.contains(name)
            || self.symbols.functions.contains_key(name)
            || self.symbols.tables.contains_key(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::Parser;

    #[test]
    fn ok_program() {
        let src = r#"
            source pcap "x.pcap"
            table t { a: string, b: int }
            function f(d) { return len(d) }
            on dns_query(event) { insert t("x", 1) }
            after finish { show t }
        "#;
        let prog = Parser::from_source(src).unwrap().parse_program().unwrap();
        let mut a = Analyzer::new();
        a.analyze(&prog).unwrap();
    }

    #[test]
    fn undefined_function() {
        let src = r#"
            on e(x) { missing() }
        "#;
        let prog = Parser::from_source(src).unwrap().parse_program().unwrap();
        let mut a = Analyzer::new();
        assert!(a.analyze(&prog).is_err());
    }

    #[test]
    fn wrong_insert_arity() {
        let src = r#"
            table t { a: string, b: int }
            on e(x) { insert t("only-one") }
        "#;
        let prog = Parser::from_source(src).unwrap().parse_program().unwrap();
        let mut a = Analyzer::new();
        assert!(a.analyze(&prog).is_err());
    }

    #[test]
    fn unknown_table() {
        let src = r#"
            on e(x) { insert missing("a") }
        "#;
        let prog = Parser::from_source(src).unwrap().parse_program().unwrap();
        let mut a = Analyzer::new();
        assert!(a.analyze(&prog).is_err());
    }
}