//! Typed AST for a parsed Malleable C2 profile.
//!
//! The grammar is modelled generically — a profile is a sequence of top-level
//! `set` options and named blocks, where blocks contain `set` options, keyword
//! statements (e.g. `header "N" "V";`, `base64;`, `CreateThread "...";`), and
//! nested blocks. Typed accessors on [`Profile`] / [`Block`] then extract the
//! CS-specific structure (http-get/post transactions, data transforms,
//! terminators) that `c2lint` and the transform engine care about.

use std::borrow::Cow;

/// A decoded profile string literal. CS strings may carry `\xNN` byte escapes
/// (e.g. `prepend "\x1F\x8B"`) that are not valid UTF-8, so the value is held
/// as raw bytes; use [`Str::as_str`] for text contexts (lossy).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Str(pub Vec<u8>);

impl Str {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Lossy UTF-8 view. Fine for linting/comparing textual options; never
    /// panics even when the literal held raw `\xNN` bytes.
    pub fn as_str(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.0)
    }
}

impl From<&str> for Str {
    fn from(s: &str) -> Self {
        Str(s.as_bytes().to_vec())
    }
}

/// `set <key> <value>;`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    pub key: String,
    pub value: Str,
    pub line: u32,
}

/// A generic block: `name [variant] { items }`.
///
/// `variant` is the optional string after the block name, e.g.
/// `http-get "web" { ... }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub name: String,
    pub variant: Option<Str>,
    pub items: Vec<Item>,
    pub line: u32,
}

/// One element inside a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// `set key value;`
    Set(Setting),
    /// A keyword statement with string arguments: `header "N" "V";`,
    /// `base64;`, `prepend "x";`, `CreateThread "ntdll!X";`, `print;`, ...
    Stmt {
        keyword: String,
        args: Vec<Str>,
        line: u32,
    },
    /// A nested block (e.g. `client { ... }`, `output { ... }`).
    Block(Block),
}

impl Block {
    /// First `set <key>` value in this block, if present.
    pub fn get(&self, key: &str) -> Option<&Str> {
        self.items.iter().find_map(|i| match i {
            Item::Set(s) if s.key == key => Some(&s.value),
            _ => None,
        })
    }

    /// First nested block named `name`.
    pub fn sub(&self, name: &str) -> Option<&Block> {
        self.items.iter().find_map(|i| match i {
            Item::Block(b) if b.name == name => Some(b),
            _ => None,
        })
    }

    /// All nested blocks named `name`.
    pub fn subs<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Block> {
        self.items.iter().filter_map(move |i| match i {
            Item::Block(b) if b.name == name => Some(b),
            _ => None,
        })
    }

    /// All keyword statements with this keyword, returning their args.
    pub fn stmts<'a>(&'a self, keyword: &'a str) -> impl Iterator<Item = &'a [Str]> {
        self.items.iter().filter_map(move |i| match i {
            Item::Stmt {
                keyword: k, args, ..
            } if k == keyword => Some(args.as_slice()),
            _ => None,
        })
    }
}

/// The parsed profile.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Profile {
    /// Top-level `set ...;` options, in source order.
    pub options: Vec<Setting>,
    /// Top-level blocks (`http-get`, `http-post`, `http-stager`, `stage`, ...).
    pub blocks: Vec<Block>,
}

impl Profile {
    /// First top-level `set <key>` value.
    pub fn option(&self, key: &str) -> Option<&Str> {
        self.options.iter().find(|o| o.key == key).map(|o| &o.value)
    }

    /// First top-level block named `name`.
    pub fn block(&self, name: &str) -> Option<&Block> {
        self.blocks.iter().find(|b| b.name == name)
    }

    /// All top-level blocks named `name` (CS permits named transaction variants).
    pub fn blocks<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Block> + 'a {
        self.blocks.iter().filter(move |b| b.name == name)
    }

    // CS-specific convenience accessors used by c2lint / the transport layer.
    pub fn http_get(&self) -> Option<&Block> {
        self.block("http-get")
    }
    pub fn http_post(&self) -> Option<&Block> {
        self.block("http-post")
    }
    pub fn http_stager(&self) -> Option<&Block> {
        self.block("http-stager")
    }
}
