//! Lexer for the Malleable C2 profile language.
//!
//! Tokens: `{`, `}`, `;`, bare words (`[A-Za-z0-9_:+\-.]+`, covers block names
//! like `http-get`, `uri-append`, `transform-x86`), and double-quoted string
//! literals with C-style escapes — including `\xNN` byte escapes used heavily in
//! `prepend`/`append` transforms. Comments start with `#` (CS) or `//`.

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    LBrace,
    RBrace,
    Semi,
    /// A bare word (block name, keyword, or unquoted option key/value).
    Word(String),
    /// A quoted string literal, decoded to raw bytes (escapes processed).
    Str(Vec<u8>),
}

#[derive(Debug, Error)]
pub enum LexError {
    #[error("line {line}: {message}")]
    Token { line: u32, message: String },
}

impl LexError {
    pub fn line(&self) -> u32 {
        match self {
            LexError::Token { line, .. } => *line,
        }
    }
}

/// Tokenize, returning each token alongside its starting line number.
pub fn tokenize(src: &str) -> Result<Vec<(Tok, u32)>, LexError> {
    let b = src.as_bytes();
    let mut i = 0;
    let mut line = 1u32;
    let mut out = Vec::new();

    while i < b.len() {
        let c = b[i];
        match c {
            b'\n' => {
                line += 1;
                i += 1;
            }
            b' ' | b'\t' | b'\r' => i += 1,
            // Line comments: `#` (Cobalt Strike) and `//` (some community profiles).
            b'#' => skip_line(b, &mut i),
            b'/' if b.get(i + 1) == Some(&b'/') => skip_line(b, &mut i),
            b'{' => {
                out.push((Tok::LBrace, line));
                i += 1;
            }
            b'}' => {
                out.push((Tok::RBrace, line));
                i += 1;
            }
            b';' => {
                out.push((Tok::Semi, line));
                i += 1;
            }
            b'"' => {
                let start_line = line;
                i += 1;
                out.push((Tok::Str(scan_string(b, &mut i, &mut line)?), start_line));
            }
            _ => {
                let start_line = line;
                let start = i;
                while i < b.len() && !is_delim(b[i]) {
                    i += 1;
                }
                if i == start {
                    return Err(LexError::Token {
                        line,
                        message: format!("unexpected byte {:#x}", c),
                    });
                }
                let word = std::str::from_utf8(&b[start..i])
                    .map_err(|_| LexError::Token {
                        line: start_line,
                        message: "non-utf8 word".into(),
                    })?
                    .to_string();
                out.push((Tok::Word(word), start_line));
            }
        }
    }
    Ok(out)
}

/// Advance `i` past the remainder of the current line.
fn skip_line(b: &[u8], i: &mut usize) {
    while *i < b.len() && b[*i] != b'\n' {
        *i += 1;
    }
}

/// A byte terminates a bare word.
fn is_delim(c: u8) -> bool {
    matches!(
        c,
        b' ' | b'\t' | b'\r' | b'\n' | b'{' | b'}' | b';' | b'"' | b'#'
    )
}

/// Scan a quoted string starting just after the opening `"`, processing escapes.
fn scan_string(b: &[u8], i: &mut usize, line: &mut u32) -> Result<Vec<u8>, LexError> {
    let mut buf = Vec::new();
    loop {
        if *i >= b.len() {
            return Err(LexError::Token {
                line: *line,
                message: "unterminated string literal".into(),
            });
        }
        match b[*i] {
            b'"' => {
                *i += 1;
                break;
            }
            b'\\' => {
                *i += 1;
                if *i >= b.len() {
                    return Err(LexError::Token {
                        line: *line,
                        message: "trailing backslash in string".into(),
                    });
                }
                match b[*i] {
                    b'n' => {
                        buf.push(b'\n');
                        *i += 1;
                    }
                    b't' => {
                        buf.push(b'\t');
                        *i += 1;
                    }
                    b'r' => {
                        buf.push(b'\r');
                        *i += 1;
                    }
                    b'0' => {
                        buf.push(0);
                        *i += 1;
                    }
                    b'\\' => {
                        buf.push(b'\\');
                        *i += 1;
                    }
                    b'"' => {
                        buf.push(b'"');
                        *i += 1;
                    }
                    b'x' => {
                        // \xNN — two hex digits → one byte.
                        if *i + 2 >= b.len() {
                            return Err(LexError::Token {
                                line: *line,
                                message: "truncated \\x escape".into(),
                            });
                        }
                        let v = hex_pair(b[*i + 1], b[*i + 2]).ok_or_else(|| LexError::Token {
                            line: *line,
                            message: "invalid \\xNN hex escape".into(),
                        })?;
                        buf.push(v);
                        *i += 3;
                    }
                    other => {
                        // Unknown escape: keep the char literally (lenient).
                        buf.push(other);
                        *i += 1;
                    }
                }
            }
            b'\n' => {
                *line += 1;
                buf.push(b'\n');
                *i += 1;
            }
            other => {
                buf.push(other);
                *i += 1;
            }
        }
    }
    Ok(buf)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn hex_pair(hi: u8, lo: u8) -> Option<u8> {
    Some((hex_val(hi)? << 4) | hex_val(lo)?)
}
