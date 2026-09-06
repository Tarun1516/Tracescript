//! Simple BPF-style packet filter for trace filtering.
//!
//! Grammar (case-insensitive keywords, whitespace tolerant):
//!
//! ```text
//! expr      := or_expr
//! or_expr   := and_expr ("or" and_expr)*
//! and_expr  := not_expr ("and" not_expr)*
//! not_expr  := "not" not_expr | atom
//! atom      := "(" expr ")" | predicate
//! predicate := "tcp"
//!            | "udp"
//!            | "icmp"
//!            | "port" <int>
//!            | "src"  <ip>
//!            | "dst"  <ip>
//!            | "host" <ip>
//!            | "len"  <op> <int>
//!            | "ip" <ip>
//! <op>      := "==" | "!=" | "<" | ">" | "<=" | ">="
//! ```
//!
//! The grammar is intentionally restricted — enough to express the common lab
//! cases (`tcp port 80`, `host 192.168.1.1 and tcp`) without pulling in a full BPF
//! compiler.
//!
//! Public interface: [`Filter::parse`] builds a [`Filter`] from a string;
//! [`Filter::matches`] evaluates it against a [`PktInfo`] describing one frame.

use crate::error::{Result, TraceError};
use crate::runtime::PktInfo;

#[derive(Debug, Clone)]
pub enum Predicate {
    Tcp,
    Udp,
    Icmp,
    Port(u16),
    Src(IpAddr),
    Dst(IpAddr),
    Host(IpAddr),
    Ip(IpAddr),
    Len(CompareOp, u32),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompareOp {
    Eq,
    Ne,
    Lt,
    Gt,
    LtEq,
    GtEq,
}

#[derive(Debug, Clone)]
pub enum Expr {
    Atom(Predicate),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone)]
pub struct Filter {
    root: Expr,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IpAddr {
    V4([u8; 4]),
}

impl IpAddr {
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return Err(TraceError::Runtime {
                msg: format!("invalid IPv4 address '{}'", s),
                pos: None,
            });
        }
        let mut out = [0u8; 4];
        for (i, p) in parts.iter().enumerate() {
            let v: u32 = p.parse().map_err(|_| TraceError::Runtime {
                msg: format!("invalid IPv4 octet '{}'", p),
                pos: None,
            })?;
            if v > 255 {
                return Err(TraceError::Runtime {
                    msg: format!("IPv4 octet {} out of range", v),
                    pos: None,
                });
            }
            out[i] = v as u8;
        }
        Ok(IpAddr::V4(out))
    }
}

impl Filter {
    pub fn parse(src: &str) -> Result<Self> {
        let mut p = Parser::new(src);
        let root = p.parse_or()?;
        p.skip_ws();
        if p.pos < p.tokens.len() {
            return Err(TraceError::Runtime {
                msg: format!("unexpected token at position {}", p.pos),
                pos: None,
            });
        }
        Ok(Filter { root })
    }

    pub fn matches(&self, info: &PktInfo) -> bool {
        eval(&self.root, info)
    }
}

fn eval(e: &Expr, info: &PktInfo) -> bool {
    match e {
        Expr::Atom(p) => match p {
            Predicate::Tcp => info.l4_proto == Some(6),
            Predicate::Udp => info.l4_proto == Some(17),
            Predicate::Icmp => info.l4_proto == Some(1),
            Predicate::Port(n) => info.src_port == Some(*n) || info.dst_port == Some(*n),
            Predicate::Src(ip) => info.src_ip.as_ref() == Some(&ip_v4_to_array(*ip)),
            Predicate::Dst(ip) => info.dst_ip.as_ref() == Some(&ip_v4_to_array(*ip)),
            Predicate::Host(ip) => {
                info.src_ip.as_ref() == Some(&ip_v4_to_array(*ip))
                    || info.dst_ip.as_ref() == Some(&ip_v4_to_array(*ip))
            }
            Predicate::Ip(ip) => {
                info.src_ip.as_ref() == Some(&ip_v4_to_array(*ip))
                    || info.dst_ip.as_ref() == Some(&ip_v4_to_array(*ip))
            }
            Predicate::Len(op, n) => match op {
                    CompareOp::Eq => info.length == *n,
                    CompareOp::Ne => info.length != *n,
                    CompareOp::Lt => info.length < *n,
                    CompareOp::Gt => info.length > *n,
                    CompareOp::LtEq => info.length <= *n,
                    CompareOp::GtEq => info.length >= *n,
                },
        },
        Expr::Not(e) => !eval(e, info),
        Expr::And(a, b) => eval(a, info) && eval(b, info),
        Expr::Or(a, b) => eval(a, info) || eval(b, info),
    }
}

fn ip_v4_to_array(ip: IpAddr) -> [u8; 4] {
    match ip {
        IpAddr::V4(a) => a,
    }
}

// ---------------------------------------------------------------------------
// Parser

struct Token<'a> {
    text: &'a str,
    kind: TokenKind,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum TokenKind {
    Ident,
    Number,
    LParen,
    RParen,
    Op,
}

struct Parser<'a> {
    src: &'a str,
    tokens: Vec<Token<'a>>,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(src: &'a str) -> Self {
        let tokens = tokenize(src);
        Self {
            src,
            tokens,
            pos: 0,
        }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.tokens.len() {
            let t = &self.tokens[self.pos];
            if t.text.chars().all(|c| c.is_whitespace()) {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&mut self) -> Option<&'a str> {
        self.skip_ws();
        self.tokens.get(self.pos).map(|t| t.text)
    }

    fn eat_keyword(&mut self, kw: &str) -> bool {
        self.skip_ws();
        if let Some(t) = self.tokens.get(self.pos) {
            if t.text.eq_ignore_ascii_case(kw) && t.kind == TokenKind::Ident {
                self.pos += 1;
                return true;
            }
        }
        false
    }

    fn parse_or(&mut self) -> Result<Expr> {
        let mut left = self.parse_and()?;
        loop {
            if self.eat_keyword("or") {
                let right = self.parse_and()?;
                left = Expr::Or(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr> {
        let mut left = self.parse_not()?;
        loop {
            if self.eat_keyword("and") {
                let right = self.parse_not()?;
                left = Expr::And(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expr> {
        if self.eat_keyword("not") {
            let inner = self.parse_not()?;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.parse_atom()
    }

    fn parse_atom(&mut self) -> Result<Expr> {
        self.skip_ws();
        if self.peek() == Some("(") {
            self.pos += 1;
            let e = self.parse_or()?;
            self.skip_ws();
            if self.peek() != Some(")") {
                return Err(TraceError::Runtime {
                    msg: "expected ')'".into(),
                    pos: None,
                });
            }
            self.pos += 1;
            return Ok(e);
        }
        let kw = match self.peek() {
            Some(s) => s.to_string(),
            None => {
                return Err(TraceError::Runtime {
                    msg: "unexpected end of filter expression".into(),
                    pos: None,
                });
            }
        };
        if kw.eq_ignore_ascii_case("tcp") {
            self.pos += 1;
            if self.eat_keyword("port") {
                let n = self.parse_u16()?;
                return Ok(Expr::And(
                    Box::new(Expr::Atom(Predicate::Tcp)),
                    Box::new(Expr::Atom(Predicate::Port(n))),
                ));
            }
            return Ok(Expr::Atom(Predicate::Tcp));
        }
        if kw.eq_ignore_ascii_case("udp") {
            self.pos += 1;
            if self.eat_keyword("port") {
                let n = self.parse_u16()?;
                return Ok(Expr::And(
                    Box::new(Expr::Atom(Predicate::Udp)),
                    Box::new(Expr::Atom(Predicate::Port(n))),
                ));
            }
            return Ok(Expr::Atom(Predicate::Udp));
        }
        if kw.eq_ignore_ascii_case("icmp") {
            self.pos += 1;
            return Ok(Expr::Atom(Predicate::Icmp));
        }
        if kw.eq_ignore_ascii_case("port") {
            self.pos += 1;
            let n = self.parse_u16()?;
            return Ok(Expr::Atom(Predicate::Port(n)));
        }
        if kw.eq_ignore_ascii_case("src") {
            self.pos += 1;
            let ip = self.parse_ip()?;
            return Ok(Expr::Atom(Predicate::Src(ip)));
        }
        if kw.eq_ignore_ascii_case("dst") {
            self.pos += 1;
            let ip = self.parse_ip()?;
            return Ok(Expr::Atom(Predicate::Dst(ip)));
        }
        if kw.eq_ignore_ascii_case("host") {
            self.pos += 1;
            let ip = self.parse_ip()?;
            return Ok(Expr::Atom(Predicate::Host(ip)));
        }
        if kw.eq_ignore_ascii_case("ip") {
            self.pos += 1;
            let ip = self.parse_ip()?;
            return Ok(Expr::Atom(Predicate::Ip(ip)));
        }
        if kw.eq_ignore_ascii_case("len") {
            self.pos += 1;
            let op = self.parse_cmp_op()?;
            let n = self.parse_u32()?;
            return Ok(Expr::Atom(Predicate::Len(op, n)));
        }
        Err(TraceError::Runtime {
            msg: format!("unknown filter token '{}'", kw),
            pos: None,
        })
    }

    fn parse_u16(&mut self) -> Result<u16> {
        let s = self.parse_number_token()?;
        s.parse::<u16>().map_err(|_| TraceError::Runtime {
            msg: format!("invalid u16 '{}'", s),
            pos: None,
        })
    }

    fn parse_u32(&mut self) -> Result<u32> {
        let s = self.parse_number_token()?;
        s.parse::<u32>().map_err(|_| TraceError::Runtime {
            msg: format!("invalid u32 '{}'", s),
            pos: None,
        })
    }

    fn parse_ip(&mut self) -> Result<IpAddr> {
        self.skip_ws();
        let t = self
            .tokens
            .get(self.pos)
            .ok_or_else(|| TraceError::Runtime {
                msg: "expected IP address".into(),
                pos: None,
            })?;
        let result = IpAddr::parse(t.text);
        if result.is_ok() {
            self.pos += 1;
        }
        result
    }

    fn parse_cmp_op(&mut self) -> Result<CompareOp> {
        self.skip_ws();
        let t = match self.tokens.get(self.pos) {
            Some(t) => t,
            None => {
                return Err(TraceError::Runtime {
                    msg: "expected comparison operator".into(),
                    pos: None,
                });
            }
        };
        let op = match t.text {
            "==" => CompareOp::Eq,
            "!=" => CompareOp::Ne,
            "<" => CompareOp::Lt,
            ">" => CompareOp::Gt,
            "<=" => CompareOp::LtEq,
            ">=" => CompareOp::GtEq,
            _ => {
                return Err(TraceError::Runtime {
                    msg: format!("expected comparison operator, got '{}'", t.text),
                    pos: None,
                });
            }
        };
        self.pos += 1;
        Ok(op)
    }

    fn parse_number_token(&mut self) -> Result<&'a str> {
        self.skip_ws();
        let t = self
            .tokens
            .get(self.pos)
            .ok_or_else(|| TraceError::Runtime {
                msg: "expected number".into(),
                pos: None,
            })?;
        if t.kind != TokenKind::Number {
            return Err(TraceError::Runtime {
                msg: format!("expected number, got '{}'", t.text),
                pos: None,
            });
        }
        self.pos += 1;
        Ok(t.text)
    }
}

fn tokenize(src: &str) -> Vec<Token<'_>> {
    let mut out = Vec::new();
    let bytes = src.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if b == b'(' || b == b')' {
            let start = i;
            i += 1;
            out.push(Token {
                text: &src[start..i],
                kind: if b == b'(' {
                    TokenKind::LParen
                } else {
                    TokenKind::RParen
                },
            });
            continue;
        }
        // Operators
        if matches!(b, b'=' | b'!' | b'<' | b'>') {
            let start = i;
            i += 1;
            if i < bytes.len() && bytes[i] == b'=' {
                i += 1;
            }
            out.push(Token {
                text: &src[start..i],
                kind: TokenKind::Op,
            });
            continue;
        }
        // Number
        if b.is_ascii_digit() {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
            out.push(Token {
                text: &src[start..i],
                kind: TokenKind::Number,
            });
            continue;
        }
        // Identifier (alpha + digits/_)
        if b.is_ascii_alphabetic() || b == b'_' {
            let start = i;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'.')
            {
                i += 1;
            }
            out.push(Token {
                text: &src[start..i],
                kind: TokenKind::Ident,
            });
            continue;
        }
        // Anything else: skip one char.
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_info(tcp: bool, src_port: Option<u16>, dst_port: Option<u16>, src: [u8;4], dst: [u8;4], length: u32) -> PktInfo {
        PktInfo {
            l4_proto: if tcp { Some(6) } else { Some(17) },
            src_port,
            dst_port,
            src_ip: Some(src),
            dst_ip: Some(dst),
            length,
        }
    }

    #[test]
    fn parse_tcp_port() {
        let f = Filter::parse("tcp port 80").unwrap();
        let mut info = make_info(true, Some(54321), Some(80), [10,0,0,1], [192,168,1,1], 100);
        assert!(f.matches(&info));
        info.dst_port = Some(443);
        assert!(!f.matches(&info));
    }

    #[test]
    fn parse_host_and_proto() {
        let f = Filter::parse("host 192.168.1.1 and tcp").unwrap();
        let info = make_info(true, Some(22), Some(1024), [192,168,1,1], [10,0,0,1], 60);
        assert!(f.matches(&info));
        let info2 = make_info(false, Some(53), Some(1024), [192,168,1,1], [10,0,0,1], 60);
        assert!(!f.matches(&info2));
    }

    #[test]
    fn parse_or() {
        let f = Filter::parse("port 80 or port 443").unwrap();
        let info = make_info(true, Some(80), Some(1024), [10,0,0,1], [10,0,0,2], 100);
        assert!(f.matches(&info));
        let info2 = make_info(true, Some(443), Some(1024), [10,0,0,1], [10,0,0,2], 100);
        assert!(f.matches(&info2));
        let info3 = make_info(true, Some(22), Some(1024), [10,0,0,1], [10,0,0,2], 100);
        assert!(!f.matches(&info3));
    }

    #[test]
    fn parse_not() {
        let f = Filter::parse("not tcp").unwrap();
        let info = make_info(false, None, None, [10,0,0,1], [10,0,0,2], 100);
        assert!(f.matches(&info));
        let info2 = make_info(true, Some(22), None, [10,0,0,1], [10,0,0,2], 100);
        assert!(!f.matches(&info2));
    }

    #[test]
    fn parse_len_compare() {
        let f = Filter::parse("len > 100").unwrap();
        let mut info = make_info(true, Some(22), None, [10,0,0,1], [10,0,0,2], 200);
        assert!(f.matches(&info));
        info.length = 50;
        assert!(!f.matches(&info));
    }

    #[test]
    fn parse_parens() {
        let f = Filter::parse("(tcp or udp) and port 53").unwrap();
        let info = make_info(false, Some(53), Some(1024), [10,0,0,1], [10,0,0,2], 100);
        assert!(f.matches(&info));
    }
}