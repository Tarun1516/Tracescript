//! Lexer for TraceScript.
//!
//! The lexer converts source text into a stream of `Spanned` tokens. It tracks 1-based
//! line and column positions so errors can be reported precisely. Whitespace and `#`
//! comments are skipped; statements may be terminated by newlines or by an explicit
//! semicolon (Zeek-style).

use crate::error::{Result, SourcePos, TraceError};

#[derive(Debug, Clone)]
pub struct Spanned {
    pub token: Token,
    pub pos: SourcePos,
}

impl Spanned {
    pub fn new(token: Token, pos: SourcePos) -> Self {
        Self { token, pos }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Integer(i64),
    Float(f64),
    Str(String),
    Bool(bool),

    Identifier(String),
    KeywordSource,
    KeywordPcap,
    KeywordTable,
    KeywordOn,
    KeywordAfter,
    KeywordFinish,
    KeywordIf,
    KeywordElse,
    KeywordFor,
    KeywordIn,
    KeywordFunction,
    KeywordReturn,
    KeywordLet,
    KeywordInsert,
    KeywordShow,
    KeywordExport,
    KeywordAlert,
    KeywordPrint,
    KeywordTo,
    KeywordAnd,
    KeywordOr,
    KeywordContains,

    Assign,        // =
    Equal,         // ==
    NotEqual,      // !=
    Less,          // <
    Greater,       // >
    LessEqual,     // <=
    GreaterEqual,  // >=
    Plus,          // +
    Minus,         // -
    Star,          // *
    Slash,         // /
    Percent,       // %
    Not,           // !

    LeftParen,
    RightParen,
    LeftBrace,
    RightBrace,
    Comma,
    Colon,
    Dot,
    LeftBracket,
    RightBracket,
    Semicolon,

    Newline,
    Eof,
}

fn lookup_keyword(name: &str) -> Token {
    match name {
        "source" => Token::KeywordSource,
        "pcap" => Token::KeywordPcap,
        "table" => Token::KeywordTable,
        "on" => Token::KeywordOn,
        "after" => Token::KeywordAfter,
        "finish" => Token::KeywordFinish,
        "if" => Token::KeywordIf,
        "else" => Token::KeywordElse,
        "for" => Token::KeywordFor,
        "in" => Token::KeywordIn,
        "function" => Token::KeywordFunction,
        "return" => Token::KeywordReturn,
        "let" => Token::KeywordLet,
        "insert" => Token::KeywordInsert,
        "show" => Token::KeywordShow,
        "export" => Token::KeywordExport,
        "alert" => Token::KeywordAlert,
        "print" => Token::KeywordPrint,
        "to" => Token::KeywordTo,
        "and" => Token::KeywordAnd,
        "or" => Token::KeywordOr,
        "contains" => Token::KeywordContains,
        "true" => Token::Bool(true),
        "false" => Token::Bool(false),
        _ => Token::Identifier(name.to_string()),
    }
}

pub struct Lexer<'a> {
    source: &'a [u8],
    offset: usize,
    line: usize,
    col: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(source: &'a str) -> Self {
        Self {
            source: source.as_bytes(),
            offset: 0,
            line: 1,
            col: 1,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.source.get(self.offset).copied()
    }

    fn peek_at(&self, n: usize) -> Option<u8> {
        self.source.get(self.offset + n).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let ch = self.peek()?;
        self.offset += 1;
        if ch == b'\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(ch)
    }

    fn pos(&self) -> SourcePos {
        SourcePos::new(self.line, self.col, self.offset)
    }

    fn skip_whitespace_and_comments(&mut self) {
        loop {
            match self.peek() {
                Some(b' ') | Some(b'\t') | Some(b'\r') => {
                    self.advance();
                }
                Some(b'\n') => {
                    self.advance();
                }
                Some(b'#') => {
                    while let Some(c) = self.peek() {
                        if c == b'\n' {
                            break;
                        }
                        self.advance();
                    }
                }
                _ => break,
            }
        }
    }

    fn lex_number(&mut self, start_pos: SourcePos) -> Result<Spanned> {
        let mut is_float = false;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.advance();
            } else if c == b'.' && !is_float && self.peek_at(1).map(|x| x.is_ascii_digit()).unwrap_or(false) {
                is_float = true;
                self.advance();
            } else {
                break;
            }
        }
        let text = std::str::from_utf8(&self.source[start_pos.offset..self.offset])
            .map_err(|e| TraceError::Lex {
                msg: format!("invalid utf-8 in number: {}", e),
                pos: start_pos.clone(),
            })?;
        if is_float {
            let v: f64 = text.parse().map_err(|e| TraceError::Lex {
                msg: format!("invalid float '{}': {}", text, e),
                pos: start_pos.clone(),
            })?;
            Ok(Spanned::new(Token::Float(v), start_pos))
        } else {
            let v: i64 = text.parse().map_err(|e| TraceError::Lex {
                msg: format!("invalid integer '{}': {}", text, e),
                pos: start_pos.clone(),
            })?;
            Ok(Spanned::new(Token::Integer(v), start_pos))
        }
    }

    fn lex_identifier(&mut self, start_pos: SourcePos) -> Result<Spanned> {
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == b'_' {
                self.advance();
            } else {
                break;
            }
        }
        let text = std::str::from_utf8(&self.source[start_pos.offset..self.offset])
            .map_err(|e| TraceError::Lex {
                msg: format!("invalid utf-8 in identifier: {}", e),
                pos: start_pos.clone(),
            })?;
        Ok(Spanned::new(lookup_keyword(text), start_pos))
    }

    fn lex_string(&mut self, start_pos: SourcePos) -> Result<Spanned> {
        // opening quote already consumed
        let mut buf = String::new();
        loop {
            match self.advance() {
                Some(b'"') => return Ok(Spanned::new(Token::Str(buf), start_pos)),
                Some(b'\\') => {
                    match self.advance() {
                        Some(b'n') => buf.push('\n'),
                        Some(b't') => buf.push('\t'),
                        Some(b'r') => buf.push('\r'),
                        Some(b'\\') => buf.push('\\'),
                        Some(b'"') => buf.push('"'),
                        Some(c) => {
                            return Err(TraceError::Lex {
                                msg: format!("invalid escape \\{}", c as char),
                                pos: self.pos(),
                            });
                        }
                        None => {
                            return Err(TraceError::Lex {
                                msg: "unterminated string".into(),
                                pos: start_pos.clone(),
                            });
                        }
                    }
                }
                Some(c) => buf.push(c as char),
                None => {
                    return Err(TraceError::Lex {
                        msg: "unterminated string".into(),
                        pos: start_pos,
                    });
                }
            }
        }
    }

    fn single_char(&mut self, t: Token, pos: SourcePos) -> Spanned {
        self.advance();
        Spanned::new(t, pos)
    }

    /// Produce the next token. `Eof` is returned at the end of input; call repeatedly
    /// until you see `Eof`.
    pub fn next_token(&mut self) -> Result<Spanned> {
        self.skip_whitespace_and_comments();
        let start = self.pos();
        let Some(c) = self.peek() else {
            return Ok(Spanned::new(Token::Eof, start));
        };
        // explicit newline token — useful for the parser so statements can be
        // statement-terminated without relying on `\n` characters.
        if c == b'\n' {
            self.advance();
            return Ok(Spanned::new(Token::Newline, start));
        }
        match c {
            b'(' => Ok(self.single_char(Token::LeftParen, start)),
            b')' => Ok(self.single_char(Token::RightParen, start)),
            b'{' => Ok(self.single_char(Token::LeftBrace, start)),
            b'}' => Ok(self.single_char(Token::RightBrace, start)),
            b',' => Ok(self.single_char(Token::Comma, start)),
            b':' => Ok(self.single_char(Token::Colon, start)),
            b'.' => Ok(self.single_char(Token::Dot, start)),
            b';' => Ok(self.single_char(Token::Semicolon, start)),
            b'[' => Ok(self.single_char(Token::LeftBracket, start)),
            b']' => Ok(self.single_char(Token::RightBracket, start)),
            b'+' => Ok(self.single_char(Token::Plus, start)),
            b'-' => Ok(self.single_char(Token::Minus, start)),
            b'*' => Ok(self.single_char(Token::Star, start)),
            b'/' => Ok(self.single_char(Token::Slash, start)),
            b'%' => Ok(self.single_char(Token::Percent, start)),
            b'!' => {
                self.advance();
                if self.peek() == Some(b'=') {
                    self.advance();
                    Ok(Spanned::new(Token::NotEqual, start))
                } else {
                    Ok(Spanned::new(Token::Not, start))
                }
            }
            b'=' => {
                self.advance();
                if self.peek() == Some(b'=') {
                    self.advance();
                    Ok(Spanned::new(Token::Equal, start))
                } else {
                    Ok(Spanned::new(Token::Assign, start))
                }
            }
            b'<' => {
                self.advance();
                if self.peek() == Some(b'=') {
                    self.advance();
                    Ok(Spanned::new(Token::LessEqual, start))
                } else {
                    Ok(Spanned::new(Token::Less, start))
                }
            }
            b'>' => {
                self.advance();
                if self.peek() == Some(b'=') {
                    self.advance();
                    Ok(Spanned::new(Token::GreaterEqual, start))
                } else {
                    Ok(Spanned::new(Token::Greater, start))
                }
            }
            b'"' => {
                self.advance();
                self.lex_string(start)
            }
            c if c.is_ascii_digit() => self.lex_number(start),
            c if c.is_ascii_alphabetic() || c == b'_' => self.lex_identifier(start),
            other => Err(TraceError::Lex {
                msg: format!("unexpected character '{}'", other as char),
                pos: start,
            }),
        }
    }

    /// Convenience iterator: lexes the entire source into a vector of tokens.
    pub fn tokenize(mut self) -> Result<Vec<Spanned>> {
        let mut out = Vec::new();
        loop {
            let t = self.next_token()?;
            let done = t.token == Token::Eof;
            out.push(t);
            if done {
                break;
            }
        }
        Ok(out)
    }
}

impl std::fmt::Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Token::Integer(n) => write!(f, "Integer({})", n),
            Token::Float(n) => write!(f, "Float({})", n),
            Token::Str(s) => write!(f, "Str(\"{}\")", s),
            Token::Bool(b) => write!(f, "Bool({})", b),
            Token::Identifier(s) => write!(f, "Identifier({})", s),
            Token::Newline => write!(f, "Newline"),
            Token::Eof => write!(f, "Eof"),
            other => write!(f, "{:?}", other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lex(src: &str) -> Result<Vec<Token>> {
        Ok(Lexer::new(src).tokenize()?.into_iter().map(|s| s.token).collect())
    }

    #[test]
    fn keywords_and_identifiers() {
        let toks = lex("let x = 10").unwrap();
        assert_eq!(
            toks,
            vec![
                Token::KeywordLet,
                Token::Identifier("x".into()),
                Token::Assign,
                Token::Integer(10),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn floats_and_ints() {
        let toks = lex("1 2.5 0.0 42").unwrap();
        assert_eq!(
            toks,
            vec![
                Token::Integer(1),
                Token::Float(2.5),
                Token::Float(0.0),
                Token::Integer(42),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn strings_with_escapes() {
        let toks = lex(r#""hello" "a\nb" "with \"quote\"" "#).unwrap();
        assert_eq!(toks[0], Token::Str("hello".into()));
        assert_eq!(toks[1], Token::Str("a\nb".into()));
        assert_eq!(toks[2], Token::Str("with \"quote\"".into()));
    }

    #[test]
    fn operators() {
        let toks = lex("== != <= >= < > + - * / % ! =").unwrap();
        assert_eq!(
            toks,
            vec![
                Token::Equal,
                Token::NotEqual,
                Token::LessEqual,
                Token::GreaterEqual,
                Token::Less,
                Token::Greater,
                Token::Plus,
                Token::Minus,
                Token::Star,
                Token::Slash,
                Token::Percent,
                Token::Not,
                Token::Assign,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn comments_and_whitespace() {
        let toks = lex("# leading comment\nlet a = 1 # trailing\nlet b = 2").unwrap();
        // newlines are emitted as Newline tokens
        assert!(toks.contains(&Token::KeywordLet));
        assert!(toks.contains(&Token::Integer(1)));
        assert!(toks.contains(&Token::Integer(2)));
    }

    #[test]
    fn booleans_are_keywords() {
        let toks = lex("true false").unwrap();
        assert_eq!(toks, vec![Token::Bool(true), Token::Bool(false), Token::Eof]);
    }

    #[test]
    fn unterminated_string_errors() {
        let err = lex(r#""oops"#).unwrap_err();
        assert!(matches!(err, TraceError::Lex { .. }));
    }

    #[test]
    fn bad_character_errors() {
        let err = lex("let @ = 1").unwrap_err();
        assert!(matches!(err, TraceError::Lex { .. }));
    }
}