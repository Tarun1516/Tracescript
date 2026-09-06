//! Recursive-descent parser for TraceScript.
//!
//! Implements the EBNF grammar from the project document. Operator precedence
//! follows C/Python: or < and < equality < comparison < additive < multiplicative < unary.

use crate::error::{Result, SourcePos, TraceError};
use crate::lexer::{Lexer, Spanned, Token};

pub mod ast_inline {
    //! AST types for TraceScript. Inlined here so they live in the same module as the
    //! parser; consumers should `use crate::parser::*` rather than reaching in.

    use crate::error::SourcePos;

    #[derive(Debug, Clone)]
    pub struct Program {
        pub declarations: Vec<Decl>,
    }

    #[derive(Debug, Clone)]
    pub enum Decl {
        Source(SourceDecl),
        Table(TableDecl),
        EventHandler(EventHandlerDecl),
        FinishHandler(FinishHandlerDecl),
        Function(FunctionDecl),
    }

    #[derive(Debug, Clone)]
    pub struct SourceDecl {
        pub source_type: String,
        pub path: String,
        pub pos: SourcePos,
    }

    #[derive(Debug, Clone)]
    pub struct TableDecl {
        pub name: String,
        pub fields: Vec<TableField>,
        pub pos: SourcePos,
    }

    #[derive(Debug, Clone)]
    pub struct TableField {
        pub name: String,
        pub field_type: TypeName,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum TypeName {
        Int,
        Float,
        Str,
        Bool,
        Time,
        Ip,
    }

    impl TypeName {
        pub fn from_str(s: &str) -> Option<Self> {
            match s {
                "int" => Some(Self::Int),
                "float" => Some(Self::Float),
                "string" => Some(Self::Str),
                "bool" => Some(Self::Bool),
                "time" => Some(Self::Time),
                "ip" => Some(Self::Ip),
                _ => None,
            }
        }

        pub fn as_str(&self) -> &'static str {
            match self {
                Self::Int => "int",
                Self::Float => "float",
                Self::Str => "string",
                Self::Bool => "bool",
                Self::Time => "time",
                Self::Ip => "ip",
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct EventHandlerDecl {
        pub event_name: String,
        pub param_name: String,
        pub body: Vec<Stmt>,
        pub pos: SourcePos,
    }

    #[derive(Debug, Clone)]
    pub struct FinishHandlerDecl {
        pub body: Vec<Stmt>,
        pub pos: SourcePos,
    }

    #[derive(Debug, Clone)]
    pub struct FunctionDecl {
        pub name: String,
        pub params: Vec<String>,
        pub body: Vec<Stmt>,
        pub pos: SourcePos,
    }

    #[derive(Debug, Clone)]
    pub enum Stmt {
        Let {
            name: String,
            value: Expr,
            pos: SourcePos,
        },
        Assign {
            name: String,
            value: Expr,
            pos: SourcePos,
        },
        IndexAssign {
            table: String,
            index: Expr,
            field: String,
            value: Expr,
            pos: SourcePos,
        },
        If {
            condition: Expr,
            then_branch: Vec<Stmt>,
            else_branch: Option<Vec<Stmt>>,
            pos: SourcePos,
        },
        For {
            var: String,
            table: String,
            body: Vec<Stmt>,
            pos: SourcePos,
        },
        Insert {
            table_name: String,
            values: Vec<Expr>,
            pos: SourcePos,
        },
        Alert {
            values: Vec<Expr>,
            pos: SourcePos,
        },
        Show {
            table_name: String,
            pos: SourcePos,
        },
        Export {
            table_name: String,
            path: String,
            pos: SourcePos,
        },
        Print {
            value: Expr,
            pos: SourcePos,
        },
        CallStmt {
            name: String,
            args: Vec<Expr>,
            pos: SourcePos,
        },
        Return {
            value: Option<Box<Expr>>,
            pos: SourcePos,
        },
    }

    #[derive(Debug, Clone)]
    pub enum Expr {
        Integer(i64),
        Float(f64),
        Str(String),
        Bool(bool),
        Identifier(String),

        Binary {
            left: Box<Expr>,
            operator: BinOp,
            right: Box<Expr>,
            pos: SourcePos,
        },

        Unary {
            operator: UnOp,
            operand: Box<Expr>,
            pos: SourcePos,
        },

        Call {
            name: String,
            args: Vec<Expr>,
            pos: SourcePos,
        },

        FieldAccess {
            object: Box<Expr>,
            field: String,
            pos: SourcePos,
        },

        Index {
            table: String,
            index: Box<Expr>,
            pos: SourcePos,
        },
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
    pub enum BinOp {
        Add,
        Sub,
        Mul,
        Div,
        Mod,
        Eq,
        NotEq,
        Lt,
        Gt,
        LtEq,
        GtEq,
        And,
        Or,
        Contains,
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
    pub enum UnOp {
        Not,
        Neg,
    }
}

pub use ast_inline::*;

pub struct Parser {
    tokens: Vec<Spanned>,
    pos: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Spanned>) -> Self {
        Self { tokens, pos: 0 }
    }

    pub fn from_source(source: &str) -> Result<Self> {
        let tokens = Lexer::new(source).tokenize()?;
        Ok(Self::new(tokens))
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos).map(|s| &s.token)
    }

    fn peek_pos(&self) -> SourcePos {
        self.tokens
            .get(self.pos)
            .map(|s| s.pos.clone())
            .unwrap_or_else(|| SourcePos::new(0, 0, 0))
    }

    fn advance(&mut self) -> Option<Spanned> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn current(&self) -> Option<&Spanned> {
        self.tokens.get(self.pos)
    }

    fn expect(&mut self, expected: Token, label: &str) -> Result<Spanned> {
        match self.current() {
            Some(s) if std::mem::discriminant(&s.token) == std::mem::discriminant(&expected) => {
                let s = s.clone();
                self.pos += 1;
                Ok(s)
            }
            Some(s) => Err(TraceError::Parse {
                msg: format!("expected {}, found {}", label, s.token),
                pos: s.pos.clone(),
            }),
            None => Err(TraceError::Parse {
                msg: format!("expected {}, found end of file", label),
                pos: SourcePos::new(0, 0, 0),
            }),
        }
    }

    fn skip_newlines(&mut self) {
        while matches!(self.peek(), Some(Token::Newline)) {
            self.pos += 1;
        }
    }

    pub fn parse_program(&mut self) -> Result<Program> {
        let mut decls = Vec::new();
        self.skip_newlines();
        while let Some(tok) = self.peek() {
            if matches!(tok, Token::Eof) {
                break;
            }
            decls.push(self.parse_declaration()?);
            self.skip_newlines();
        }
        Ok(Program { declarations: decls })
    }

    fn parse_declaration(&mut self) -> Result<Decl> {
        let span = self
            .current()
            .ok_or_else(|| TraceError::Parse {
                msg: "unexpected end of file, expected declaration".into(),
                pos: self.peek_pos(),
            })?
            .clone();
        match &span.token {
            Token::KeywordSource => self.parse_source_decl().map(Decl::Source),
            Token::KeywordTable => self.parse_table_decl().map(Decl::Table),
            Token::KeywordOn => self.parse_event_handler().map(Decl::EventHandler),
            Token::KeywordAfter => self.parse_finish_handler().map(Decl::FinishHandler),
            Token::KeywordFunction => self.parse_function_decl().map(Decl::Function),
            other => Err(TraceError::Parse {
                msg: format!("expected declaration keyword, found {}", other),
                pos: span.pos.clone(),
            }),
        }
    }

    fn parse_source_decl(&mut self) -> Result<SourceDecl> {
        let span = self.advance().unwrap(); // KeywordSource
        let pos = span.pos.clone();
        // Source type: `pcap`, `jsonl`, `csv`. Default to "pcap" if a string follows
        // directly (so `source "foo.pcap"` keeps working — but we accept the
        // keyword form here for clarity).
        let source_type = match self.peek() {
            Some(Token::KeywordPcap) => {
                self.pos += 1;
                "pcap".to_string()
            }
            Some(Token::Identifier(s)) if s == "jsonl" || s == "ndjson" => {
                let t = self.advance().unwrap();
                if let Token::Identifier(name) = t.token {
                    if name == "ndjson" { "jsonl".to_string() } else { name }
                } else {
                    unreachable!()
                }
            }
            Some(Token::Identifier(s)) if s == "csv" => {
                self.pos += 1;
                "csv".to_string()
            }
            _ => {
                return Err(TraceError::Parse {
                    msg: "expected source type ('pcap', 'jsonl', or 'csv')".into(),
                    pos: self.peek_pos(),
                });
            }
        };
        let path_tok = self.expect(Token::Str(String::new()), "string path")?;
        if let Token::Str(s) = path_tok.token {
            if matches!(self.peek(), Some(Token::Newline)) {
                self.pos += 1;
            }
            Ok(SourceDecl { source_type, path: s, pos })
        } else {
            unreachable!()
        }
    }

    fn parse_table_decl(&mut self) -> Result<TableDecl> {
        let span = self.advance().unwrap(); // KeywordTable
        let pos = span.pos.clone();
        let name_tok = self.expect(Token::Identifier(String::new()), "table name")?;
        let name = if let Token::Identifier(n) = name_tok.token {
            n
        } else {
            unreachable!()
        };
        self.expect(Token::LeftBrace, "'{'")?;
        let mut fields = Vec::new();
        self.skip_newlines();
        while !matches!(self.peek(), Some(Token::RightBrace) | Some(Token::Eof)) {
            let fname = match self.advance() {
                Some(s) => match s.token {
                    Token::Identifier(n) => n,
                    other => {
                        return Err(TraceError::Parse {
                            msg: format!("expected field name, found {}", other),
                            pos: s.pos,
                        });
                    }
                },
                None => {
                    return Err(TraceError::Parse {
                        msg: "expected field name, found end of file".into(),
                        pos: self.peek_pos(),
                    });
                }
            };
            self.expect(Token::Colon, "':'")?;
            let tname = match self.advance() {
                Some(s) => match s.token {
                    Token::Identifier(n) => n,
                    other => {
                        return Err(TraceError::Parse {
                            msg: format!("expected field type, found {}", other),
                            pos: s.pos,
                        });
                    }
                },
                None => {
                    return Err(TraceError::Parse {
                        msg: "expected field type, found end of file".into(),
                        pos: self.peek_pos(),
                    });
                }
            };
            let ftype = TypeName::from_str(&tname).ok_or_else(|| TraceError::Parse {
                msg: format!("unknown field type '{}'", tname),
                pos: self.peek_pos(),
            })?;
            fields.push(TableField { name: fname, field_type: ftype });
            self.skip_newlines();
            if matches!(self.peek(), Some(Token::Comma)) {
                self.pos += 1;
                self.skip_newlines();
            }
        }
        self.expect(Token::RightBrace, "'}'")?;
        if matches!(self.peek(), Some(Token::Newline)) {
            self.pos += 1;
        }
        Ok(TableDecl { name, fields, pos })
    }

    fn parse_event_handler(&mut self) -> Result<EventHandlerDecl> {
        let span = self.advance().unwrap(); // KeywordOn
        let pos = span.pos.clone();
        let name_tok = self.expect(Token::Identifier(String::new()), "event name")?;
        let event_name = if let Token::Identifier(n) = name_tok.token {
            n
        } else {
            unreachable!()
        };
        self.expect(Token::LeftParen, "'('")?;
        let param_tok = self.expect(Token::Identifier(String::new()), "parameter name")?;
        let param_name = if let Token::Identifier(n) = param_tok.token {
            n
        } else {
            unreachable!()
        };
        self.expect(Token::RightParen, "')'")?;
        let body = self.parse_block()?;
        Ok(EventHandlerDecl { event_name, param_name, body, pos })
    }

    fn parse_finish_handler(&mut self) -> Result<FinishHandlerDecl> {
        let span = self.advance().unwrap(); // KeywordAfter
        let pos = span.pos.clone();
        self.expect(Token::KeywordFinish, "'finish'")?;
        let body = self.parse_block()?;
        Ok(FinishHandlerDecl { body, pos })
    }

    fn parse_function_decl(&mut self) -> Result<FunctionDecl> {
        let span = self.advance().unwrap(); // KeywordFunction
        let pos = span.pos.clone();
        let name_tok = self.expect(Token::Identifier(String::new()), "function name")?;
        let name = if let Token::Identifier(n) = name_tok.token {
            n
        } else {
            unreachable!()
        };
        self.expect(Token::LeftParen, "'('")?;
        let mut params = Vec::new();
        if !matches!(self.peek(), Some(Token::RightParen)) {
            loop {
                let p = match self.advance() {
                    Some(s) => match s.token {
                        Token::Identifier(n) => n,
                        other => {
                            return Err(TraceError::Parse {
                                msg: format!("expected parameter name, found {}", other),
                                pos: s.pos,
                            });
                        }
                    },
                    None => {
                        return Err(TraceError::Parse {
                            msg: "expected parameter name, found end of file".into(),
                            pos: self.peek_pos(),
                        });
                    }
                };
                params.push(p);
                if matches!(self.peek(), Some(Token::Comma)) {
                    self.pos += 1;
                } else {
                    break;
                }
            }
        }
        self.expect(Token::RightParen, "')'")?;
        let body = self.parse_block()?;
        Ok(FunctionDecl { name, params, body, pos })
    }

    fn parse_block(&mut self) -> Result<Vec<Stmt>> {
        self.expect(Token::LeftBrace, "'{'")?;
        self.skip_newlines();
        let mut stmts = Vec::new();
        while !matches!(self.peek(), Some(Token::RightBrace) | Some(Token::Eof)) {
            stmts.push(self.parse_statement()?);
            self.skip_newlines();
        }
        self.expect(Token::RightBrace, "'}'")?;
        if matches!(self.peek(), Some(Token::Newline)) {
            self.pos += 1;
        }
        Ok(stmts)
    }

    fn parse_statement(&mut self) -> Result<Stmt> {
        let cur = self
            .current()
            .ok_or_else(|| TraceError::Parse {
                msg: "expected statement, found end of file".into(),
                pos: self.peek_pos(),
            })?
            .clone();
        match &cur.token {
            Token::KeywordLet => self.parse_let(),
            Token::KeywordIf => self.parse_if(),
            Token::KeywordFor => self.parse_for(),
            Token::KeywordInsert => self.parse_insert(),
            Token::KeywordAlert => self.parse_alert(),
            Token::KeywordShow => self.parse_show(),
            Token::KeywordExport => self.parse_export(),
            Token::KeywordPrint => self.parse_print(),
            Token::KeywordReturn => self.parse_return(),
            Token::Identifier(_) => {
                // could be assignment, call statement, index assignment, or
                // expression-like. Disambiguate by peeking past the identifier.
                let id_pos = cur.pos.clone();
                let name = if let Token::Identifier(n) = &cur.token {
                    n.clone()
                } else {
                    unreachable!()
                };
                if let Some(next) = self.tokens.get(self.pos + 1) {
                    match &next.token {
                        Token::Assign => {
                            self.pos += 1;
                            self.pos += 1;
                            let value = self.parse_expression()?;
                            Ok(Stmt::Assign { name, value, pos: id_pos })
                        }
                        Token::LeftParen => {
                            self.pos += 1;
                            let args = self.parse_arg_list()?;
                            Ok(Stmt::CallStmt { name, args, pos: id_pos })
                        }
                        Token::LeftBracket => {
                            // table[i].field = expr
                            self.pos += 1;
                            self.pos += 1; // consume identifier
                            let index = self.parse_expression()?;
                            self.expect(Token::RightBracket, "']'")?;
                            self.expect(Token::Dot, "'.'")?;
                            let field_tok = self.expect(
                                Token::Identifier(String::new()),
                                "field name",
                            )?;
                            let field = if let Token::Identifier(n) = field_tok.token {
                                n
                            } else {
                                unreachable!()
                            };
                            self.expect(Token::Assign, "'='")?;
                            let value = self.parse_expression()?;
                            Ok(Stmt::IndexAssign {
                                table: name,
                                index,
                                field,
                                value,
                                pos: id_pos,
                            })
                        }
                        _ => Err(TraceError::Parse {
                            msg: format!("unexpected token after identifier '{}'", name),
                            pos: next.pos.clone(),
                        }),
                    }
                } else {
                    Err(TraceError::Parse {
                        msg: "unexpected end of file after identifier".into(),
                        pos: id_pos,
                    })
                }
            }
            other => Err(TraceError::Parse {
                msg: format!("expected statement, found {}", other),
                pos: cur.pos,
            }),
        }
    }

    fn parse_let(&mut self) -> Result<Stmt> {
        let span = self.advance().unwrap(); // KeywordLet
        let pos = span.pos.clone();
        let name_tok = self.expect(Token::Identifier(String::new()), "variable name")?;
        let name = if let Token::Identifier(n) = name_tok.token {
            n
        } else {
            unreachable!()
        };
        self.expect(Token::Assign, "'='")?;
        let value = self.parse_expression()?;
        Ok(Stmt::Let { name, value, pos })
    }

    fn parse_if(&mut self) -> Result<Stmt> {
        let span = self.advance().unwrap(); // KeywordIf
        let pos = span.pos.clone();
        let condition = self.parse_expression()?;
        let then_branch = self.parse_block()?;
        let else_branch = if matches!(self.peek(), Some(Token::KeywordElse)) {
            self.pos += 1;
            Some(self.parse_block()?)
        } else {
            None
        };
        Ok(Stmt::If {
            condition,
            then_branch,
            else_branch,
            pos,
        })
    }

    fn parse_for(&mut self) -> Result<Stmt> {
        let span = self.advance().unwrap(); // KeywordFor
        let pos = span.pos.clone();
        let var_tok = self.expect(Token::Identifier(String::new()), "loop variable")?;
        let var = if let Token::Identifier(n) = var_tok.token {
            n
        } else {
            unreachable!()
        };
        self.expect(Token::KeywordIn, "'in'")?;
        let table_tok = self.expect(Token::Identifier(String::new()), "table name")?;
        let table = if let Token::Identifier(n) = table_tok.token {
            n
        } else {
            unreachable!()
        };
        let body = self.parse_block()?;
        Ok(Stmt::For { var, table, body, pos })
    }

    fn parse_insert(&mut self) -> Result<Stmt> {
        let span = self.advance().unwrap(); // KeywordInsert
        let pos = span.pos.clone();
        let name_tok = self.expect(Token::Identifier(String::new()), "table name")?;
        let table_name = if let Token::Identifier(n) = name_tok.token {
            n
        } else {
            unreachable!()
        };
        self.expect(Token::LeftParen, "'('")?;
        let values = if matches!(self.peek(), Some(Token::RightParen)) {
            Vec::new()
        } else {
            self.parse_expression_list()?
        };
        self.expect(Token::RightParen, "')'")?;
        Ok(Stmt::Insert { table_name, values, pos })
    }

    fn parse_alert(&mut self) -> Result<Stmt> {
        let span = self.advance().unwrap(); // KeywordAlert
        let pos = span.pos.clone();
        self.expect(Token::LeftParen, "'('")?;
        let values = if matches!(self.peek(), Some(Token::RightParen)) {
            Vec::new()
        } else {
            self.parse_expression_list()?
        };
        self.expect(Token::RightParen, "')'")?;
        Ok(Stmt::Alert { values, pos })
    }

    fn parse_show(&mut self) -> Result<Stmt> {
        let span = self.advance().unwrap(); // KeywordShow
        let pos = span.pos.clone();
        let name_tok = self.expect(Token::Identifier(String::new()), "table name")?;
        let table_name = if let Token::Identifier(n) = name_tok.token {
            n
        } else {
            unreachable!()
        };
        Ok(Stmt::Show { table_name, pos })
    }

    fn parse_export(&mut self) -> Result<Stmt> {
        let span = self.advance().unwrap(); // KeywordExport
        let pos = span.pos.clone();
        let name_tok = self.expect(Token::Identifier(String::new()), "table name")?;
        let table_name = if let Token::Identifier(n) = name_tok.token {
            n
        } else {
            unreachable!()
        };
        self.expect(Token::KeywordTo, "'to'")?;
        let path_tok = self.expect(Token::Str(String::new()), "export path")?;
        let path = if let Token::Str(s) = path_tok.token {
            s
        } else {
            unreachable!()
        };
        Ok(Stmt::Export { table_name, path, pos })
    }

    fn parse_print(&mut self) -> Result<Stmt> {
        let span = self.advance().unwrap(); // KeywordPrint
        let pos = span.pos.clone();
        let value = self.parse_expression()?;
        Ok(Stmt::Print { value, pos })
    }

    fn parse_return(&mut self) -> Result<Stmt> {
        let span = self.advance().unwrap(); // KeywordReturn
        let pos = span.pos.clone();
        // optional expression
        if matches!(self.peek(), Some(Token::Newline) | Some(Token::RightBrace) | Some(Token::Eof)) {
            Ok(Stmt::Return { value: None, pos })
        } else {
            let value = self.parse_expression()?;
            Ok(Stmt::Return { value: Some(Box::new(value)), pos })
        }
    }

    fn parse_arg_list(&mut self) -> Result<Vec<Expr>> {
        self.expect(Token::LeftParen, "'('")?;
        let args = if matches!(self.peek(), Some(Token::RightParen)) {
            Vec::new()
        } else {
            self.parse_expression_list()?
        };
        self.expect(Token::RightParen, "')'")?;
        Ok(args)
    }

    fn parse_expression_list(&mut self) -> Result<Vec<Expr>> {
        let mut exprs = Vec::new();
        exprs.push(self.parse_expression()?);
        while matches!(self.peek(), Some(Token::Comma)) {
            self.pos += 1;
            exprs.push(self.parse_expression()?);
        }
        Ok(exprs)
    }

    pub fn parse_expression(&mut self) -> Result<Expr> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Expr> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Token::KeywordOr)) {
            let pos = self.advance().unwrap().pos;
            let right = self.parse_and()?;
            left = Expr::Binary {
                left: Box::new(left),
                operator: BinOp::Or,
                right: Box::new(right),
                pos,
            };
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr> {
        let mut left = self.parse_equality()?;
        while matches!(self.peek(), Some(Token::KeywordAnd)) {
            let pos = self.advance().unwrap().pos;
            let right = self.parse_equality()?;
            left = Expr::Binary {
                left: Box::new(left),
                operator: BinOp::And,
                right: Box::new(right),
                pos,
            };
        }
        Ok(left)
    }

    fn parse_equality(&mut self) -> Result<Expr> {
        let mut left = self.parse_comparison()?;
        loop {
            let op = match self.peek() {
                Some(Token::Equal) => BinOp::Eq,
                Some(Token::NotEqual) => BinOp::NotEq,
                _ => break,
            };
            let pos = self.advance().unwrap().pos;
            let right = self.parse_comparison()?;
            left = Expr::Binary {
                left: Box::new(left),
                operator: op,
                right: Box::new(right),
                pos,
            };
        }
        Ok(left)
    }

    fn parse_comparison(&mut self) -> Result<Expr> {
        let mut left = self.parse_additive()?;
        loop {
            let op = match self.peek() {
                Some(Token::Less) => BinOp::Lt,
                Some(Token::Greater) => BinOp::Gt,
                Some(Token::LessEqual) => BinOp::LtEq,
                Some(Token::GreaterEqual) => BinOp::GtEq,
                Some(Token::KeywordContains) => BinOp::Contains,
                _ => break,
            };
            let pos = self.advance().unwrap().pos;
            let right = self.parse_additive()?;
            left = Expr::Binary {
                left: Box::new(left),
                operator: op,
                right: Box::new(right),
                pos,
            };
        }
        Ok(left)
    }

    fn parse_additive(&mut self) -> Result<Expr> {
        let mut left = self.parse_multiplicative()?;
        loop {
            let op = match self.peek() {
                Some(Token::Plus) => BinOp::Add,
                Some(Token::Minus) => BinOp::Sub,
                _ => break,
            };
            let pos = self.advance().unwrap().pos;
            let right = self.parse_multiplicative()?;
            left = Expr::Binary {
                left: Box::new(left),
                operator: op,
                right: Box::new(right),
                pos,
            };
        }
        Ok(left)
    }

    fn parse_multiplicative(&mut self) -> Result<Expr> {
        let mut left = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                Some(Token::Star) => BinOp::Mul,
                Some(Token::Slash) => BinOp::Div,
                Some(Token::Percent) => BinOp::Mod,
                _ => break,
            };
            let pos = self.advance().unwrap().pos;
            let right = self.parse_unary()?;
            left = Expr::Binary {
                left: Box::new(left),
                operator: op,
                right: Box::new(right),
                pos,
            };
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Expr> {
        if matches!(self.peek(), Some(Token::Not)) {
            let pos = self.advance().unwrap().pos;
            let operand = self.parse_unary()?;
            return Ok(Expr::Unary {
                operator: UnOp::Not,
                operand: Box::new(operand),
                pos,
            });
        }
        if matches!(self.peek(), Some(Token::Minus)) {
            let pos = self.advance().unwrap().pos;
            let operand = self.parse_unary()?;
            return Ok(Expr::Unary {
                operator: UnOp::Neg,
                operand: Box::new(operand),
                pos,
            });
        }
        self.parse_call_or_field()
    }

    fn parse_call_or_field(&mut self) -> Result<Expr> {
        // Look for table-name[expr] which is `Index`, only valid on bare identifiers
        // (table handles, not arbitrary expressions).
        if let Some(Token::Identifier(_)) = self.peek() {
            if let Some(Token::LeftBracket) = self.tokens.get(self.pos + 1).map(|s| &s.token) {
                let name_tok = self.advance().unwrap();
                let name = if let Token::Identifier(n) = name_tok.token {
                    n
                } else {
                    unreachable!()
                };
                let pos = name_tok.pos.clone();
                self.pos += 1; // consume '['
                let index = self.parse_expression()?;
                self.expect(Token::RightBracket, "']'")?;
                let mut expr: Expr = Expr::Index {
                    table: name,
                    index: Box::new(index),
                    pos,
                };
                // Allow .field access on the indexed result.
                while let Some(Token::Dot) = self.peek() {
                    let p = self.advance().unwrap().pos;
                    let field_tok = self
                        .advance()
                        .ok_or_else(|| TraceError::Parse {
                            msg: "expected field name after '.'".into(),
                            pos: self.peek_pos(),
                        })?;
                    let field = if let Token::Identifier(n) = field_tok.token {
                        n
                    } else {
                        return Err(TraceError::Parse {
                            msg: format!("expected field name, found {}", field_tok.token),
                            pos: field_tok.pos,
                        });
                    };
                    expr = Expr::FieldAccess {
                        object: Box::new(expr),
                        field,
                        pos: p,
                    };
                }
                return Ok(expr);
            }
        }
        let mut expr = self.parse_primary()?;
        loop {
            match self.peek() {
                Some(Token::Dot) => {
                    let pos = self.advance().unwrap().pos;
                    let field_tok = self
                        .advance()
                        .ok_or_else(|| TraceError::Parse {
                            msg: "expected field name after '.'".into(),
                            pos: self.peek_pos(),
                        })?;
                    let field = if let Token::Identifier(n) = field_tok.token {
                        n
                    } else {
                        return Err(TraceError::Parse {
                            msg: format!("expected field name, found {}", field_tok.token),
                            pos: field_tok.pos,
                        });
                    };
                    expr = Expr::FieldAccess {
                        object: Box::new(expr),
                        field,
                        pos,
                    };
                }
                Some(Token::LeftParen) => {
                    let pos = expr_pos(&expr);
                    let args = self.parse_arg_list()?;
                    let name = if let Expr::Identifier(n) = expr {
                        n
                    } else {
                        return Err(TraceError::Parse {
                            msg: "only identifier calls are supported".into(),
                            pos,
                        });
                    };
                    expr = Expr::Call { name, args, pos };
                }
                _ => break,
            }
        }
        Ok(expr)
    }

    fn parse_primary(&mut self) -> Result<Expr> {
        let cur = self
            .current()
            .ok_or_else(|| TraceError::Parse {
                msg: "expected expression, found end of file".into(),
                pos: self.peek_pos(),
            })?
            .clone();
        match cur.token {
            Token::Integer(n) => {
                self.pos += 1;
                Ok(Expr::Integer(n))
            }
            Token::Float(n) => {
                self.pos += 1;
                Ok(Expr::Float(n))
            }
            Token::Str(s) => {
                self.pos += 1;
                Ok(Expr::Str(s))
            }
            Token::Bool(b) => {
                self.pos += 1;
                Ok(Expr::Bool(b))
            }
            Token::Identifier(name) => {
                self.pos += 1;
                Ok(Expr::Identifier(name))
            }
            Token::LeftParen => {
                self.pos += 1;
                let e = self.parse_expression()?;
                self.expect(Token::RightParen, "')'")?;
                Ok(e)
            }
            other => Err(TraceError::Parse {
                msg: format!("expected expression, found {}", other),
                pos: cur.pos,
            }),
        }
    }
}

fn expr_pos(e: &Expr) -> SourcePos {
    match e {
        Expr::Integer(_) | Expr::Float(_) | Expr::Str(_) | Expr::Bool(_) | Expr::Identifier(_) => {
            SourcePos::new(0, 0, 0)
        }
        Expr::Binary { pos, .. }
        | Expr::Unary { pos, .. }
        | Expr::Call { pos, .. }
        | Expr::FieldAccess { pos, .. }
        | Expr::Index { pos, .. } => pos.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(src: &str) -> Program {
        Parser::from_source(src).unwrap().parse_program().unwrap()
    }

    #[test]
    fn parse_source_decl() {
        let p = parse("source pcap \"lab.pcap\"\n");
        assert_eq!(p.declarations.len(), 1);
        match &p.declarations[0] {
            Decl::Source(s) => {
                assert_eq!(s.source_type, "pcap");
                assert_eq!(s.path, "lab.pcap");
            }
            _ => panic!("expected source"),
        }
    }

    #[test]
    fn parse_table_decl() {
        let p = parse("table t { a: string, b: int }\n");
        match &p.declarations[0] {
            Decl::Table(t) => {
                assert_eq!(t.name, "t");
                assert_eq!(t.fields.len(), 2);
                assert_eq!(t.fields[0].name, "a");
                assert_eq!(t.fields[0].field_type, TypeName::Str);
            }
            _ => panic!("expected table"),
        }
    }

    #[test]
    fn parse_event_handler_and_function() {
        let src = r#"
            function is_bad(d) { return ends_with(d, ".xyz") }
            on dns_query(event) { if is_bad(event.query) { alert("bad", event.query) } }
            after finish { show t }
        "#;
        let p = parse(src);
        assert_eq!(p.declarations.len(), 3);
    }

    #[test]
    fn parse_if_and_arithmetic() {
        let src = "function f(x) { if x > 1 + 2 { return x * 3 } else { return 0 } }";
        let p = Parser::from_source(src).unwrap();
        let mut p = p;
        let program = p.parse_program().unwrap();
        assert_eq!(program.declarations.len(), 1);
    }

    #[test]
    fn parse_field_access() {
        let src = "function f(e) { let q = e.query }";
        let mut p = Parser::from_source(src).unwrap();
        let prog = p.parse_program().unwrap();
        assert_eq!(prog.declarations.len(), 1);
    }
}