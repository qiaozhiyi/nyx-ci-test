//! Recursive-descent parser: tokens → [`Profile`].
//!
//! Top level: a sequence of `set <key> <value>;` options and named blocks.
//! Inside a block: `set`, keyword statements (`header "N" "V";`, `base64;`,
//! `prepend "x";`, ...), and nested blocks (`client { ... }`, `output { ... }`).
//! A nested block's name is immediately followed by `{`; anything else after a
//! keyword is a statement (args until `;`). This single rule disambiguates the
//! context-sensitive `header "Cookie";` (one-arg terminator inside a data
//! block) from `header "Server" "Apache";` (two-arg statement) without the
//! parser needing to know which block it is in.

use thiserror::Error;

use crate::ast::{Block, Item, Profile, Setting, Str};
use crate::lexer::{tokenize, Tok};

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("line {line}: {message}")]
    Syntax { line: u32, message: String },
}

/// Maximum block-nesting depth. Real Malleable C2 profiles nest ≤ 5 deep
/// (http-get → client/server → metadata/output → transform statements). The
/// cap exists to stop an unbounded `items()` recursion from blowing the stack
/// on a hostile profile (a few-hundred-KB profile of nested blocks → SIGSEGV,
/// uncatchable, kills the process under panic=abort). 64 is far above any
/// legitimate profile but well below the default 8 MiB thread stack.
const MAX_DEPTH: u32 = 64;

/// Parse a profile from source text.
pub fn parse(src: &str) -> Result<Profile, ParseError> {
    let toks = tokenize(src).map_err(|e| ParseError::Syntax {
        line: e.line(),
        message: e.to_string(),
    })?;
    let mut p = Parser { toks, pos: 0 };
    let mut options = Vec::new();
    let mut blocks = Vec::new();
    while let Some((tok, line)) = p.peek_tok().cloned() {
        match &tok {
            Tok::Word(w) if w.as_str() == "set" => {
                p.bump();
                let (key, _) = p.word()?;
                let value = p.value()?;
                p.eat(&Tok::Semi)?;
                options.push(Setting { key, value, line });
            }
            Tok::Word(_) => {
                blocks.push(p.block(0)?);
            }
            other => {
                return Err(ParseError::Syntax {
                    line,
                    message: format!("expected `set` or block, found {other:?}"),
                })
            }
        }
    }
    Ok(Profile { options, blocks })
}

struct Parser {
    toks: Vec<(Tok, u32)>,
    pos: usize,
}

impl Parser {
    fn peek_tok(&self) -> Option<&(Tok, u32)> {
        self.toks.get(self.pos)
    }
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos).map(|(t, _)| t)
    }
    fn bump(&mut self) -> Option<(Tok, u32)> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }
    fn eat(&mut self, expect: &Tok) -> Result<u32, ParseError> {
        match self.bump() {
            Some((t, l)) if &t == expect => Ok(l),
            Some((t, l)) => Err(ParseError::Syntax {
                line: l,
                message: format!("expected {expect:?}, found {t:?}"),
            }),
            None => Err(ParseError::Syntax {
                line: 0,
                message: format!("expected {expect:?}, found EOF"),
            }),
        }
    }

    fn word(&mut self) -> Result<(String, u32), ParseError> {
        match self.bump() {
            Some((Tok::Word(w), l)) => Ok((w, l)),
            Some((t, l)) => Err(ParseError::Syntax {
                line: l,
                message: format!("expected word, found {t:?}"),
            }),
            None => Err(ParseError::Syntax {
                line: 0,
                message: "expected word, found EOF".into(),
            }),
        }
    }

    /// A value: a quoted string (raw bytes) or a bare word.
    fn value(&mut self) -> Result<Str, ParseError> {
        match self.bump() {
            Some((Tok::Str(b), _)) => Ok(Str(b)),
            Some((Tok::Word(w), _)) => Ok(Str(w.into_bytes())),
            Some((t, l)) => Err(ParseError::Syntax {
                line: l,
                message: format!("expected value, found {t:?}"),
            }),
            None => Err(ParseError::Syntax {
                line: 0,
                message: "expected value, found EOF".into(),
            }),
        }
    }

    /// Parse `name [variant] { items }`. `depth` is the current nesting depth
    /// (0 at top-level blocks); each nested block increments it.
    fn block(&mut self, depth: u32) -> Result<Block, ParseError> {
        let (name, line) = self.word()?;
        let variant = match self.peek() {
            Some(Tok::Str(_)) => Some(self.value()?),
            _ => None,
        };
        self.eat(&Tok::LBrace)?;
        let items = self.items(depth)?;
        self.eat(&Tok::RBrace)?;
        Ok(Block {
            name,
            variant,
            items,
            line,
        })
    }

    /// Parse block items until the matching `}`. `depth` is the nesting depth of
    /// the enclosing block; a nested block increments it and rejects past
    /// [`MAX_DEPTH`] so a hostile profile can't overflow the stack.
    fn items(&mut self, depth: u32) -> Result<Vec<Item>, ParseError> {
        let mut out = Vec::new();
        loop {
            let (is_rbrace, line) = match self.peek_tok() {
                None => {
                    return Err(ParseError::Syntax {
                        line: 0,
                        message: "unexpected EOF inside block (missing `}`)".into(),
                    })
                }
                Some((Tok::RBrace, l)) => (true, *l),
                Some((_, l)) => (false, *l),
            };
            if is_rbrace {
                break;
            }
            match self.peek() {
                Some(Tok::Word(w)) if w.as_str() == "set" => {
                    self.bump();
                    let (key, _) = self.word()?;
                    let value = self.value()?;
                    self.eat(&Tok::Semi)?;
                    out.push(Item::Set(Setting { key, value, line }));
                }
                Some(Tok::Word(_)) => {
                    let (kw, kwline) = self.word()?;
                    match self.peek() {
                        Some(Tok::LBrace) => {
                            // Depth cap: reject before recursing so a profile
                            // of N nested blocks can't grow the stack by N frames.
                            let nested =
                                depth.checked_add(1).ok_or_else(|| ParseError::Syntax {
                                    line: kwline,
                                    message: "block nesting depth overflowed u32".into(),
                                })?;
                            if nested > MAX_DEPTH {
                                return Err(ParseError::Syntax {
                                    line: kwline,
                                    message: format!(
                                        "block nesting depth {nested} exceeds limit {MAX_DEPTH}"
                                    ),
                                });
                            }
                            self.eat(&Tok::LBrace)?;
                            let inner = self.items(nested)?;
                            self.eat(&Tok::RBrace)?;
                            out.push(Item::Block(Block {
                                name: kw,
                                variant: None,
                                items: inner,
                                line: kwline,
                            }));
                        }
                        _ => {
                            // Statement: collect args (words/strings) until `;`.
                            let mut args = Vec::new();
                            while !matches!(self.peek(), Some(Tok::Semi) | None) {
                                args.push(self.value()?);
                            }
                            self.eat(&Tok::Semi)?;
                            out.push(Item::Stmt {
                                keyword: kw,
                                args,
                                line: kwline,
                            });
                        }
                    }
                }
                other => {
                    return Err(ParseError::Syntax {
                        line,
                        message: format!("unexpected {other:?} inside block"),
                    })
                }
            }
        }
        Ok(out)
    }
}
