/*
    marty_dasm token system for disassembly formatting
*/
use std::fmt::{Display, Formatter, Result as FmtResult};

use super::FormatterOutput;

/// Marker trait for all tokens; requires Display for rendering to text.
pub trait Token: Display {}

/// Tokens with semantic meaning (mnemonic, register, immediate, displacement, prefix, operand)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SemanticToken {
    Mnemonic(String),
    Register(String),
    Immediate(String),
    Displacement(String),
    Pointer(String),
    Prefix(String),
    Operand(String),
}

impl Display for SemanticToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            SemanticToken::Mnemonic(s)
            | SemanticToken::Register(s)
            | SemanticToken::Immediate(s)
            | SemanticToken::Displacement(s)
            | SemanticToken::Pointer(s)
            | SemanticToken::Prefix(s)
            | SemanticToken::Operand(s) => f.write_str(s),
        }
    }
}
impl Token for SemanticToken {}

/// Tokens describing presentation/decoration (punctuation, whitespace, raw text, numbers)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecoratorToken {
    OpenBracket,
    CloseBracket,
    Plus,
    Minus,
    Multiply,
    Comma,
    Colon,
    Whitespace(String),
    Text(String),
    Number(String),
}

impl Display for DecoratorToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            DecoratorToken::OpenBracket => f.write_str("["),
            DecoratorToken::CloseBracket => f.write_str("]"),
            DecoratorToken::Plus => f.write_str("+"),
            DecoratorToken::Minus => f.write_str("-"),
            DecoratorToken::Multiply => f.write_str("*"),
            DecoratorToken::Comma => f.write_str(","),
            DecoratorToken::Colon => f.write_str(":"),
            DecoratorToken::Whitespace(s) => f.write_str(s),
            DecoratorToken::Text(s) => f.write_str(s),
            DecoratorToken::Number(s) => f.write_str(s),
        }
    }
}
impl Token for DecoratorToken {}

/// Unified token stream item
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenItem {
    Semantic(SemanticToken),
    Decorator(DecoratorToken),
}

impl Display for TokenItem {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            TokenItem::Semantic(t) => Display::fmt(t, f),
            TokenItem::Decorator(t) => Display::fmt(t, f),
        }
    }
}
impl Token for TokenItem {}

/// A simple collector of tokens that can also be rendered to a flat string
#[derive(Default, Debug)]
pub struct TokenStream {
    pub tokens: Vec<TokenItem>,
}

impl TokenStream {
    pub fn new() -> Self { Self { tokens: Vec::new() } }

    /// Iterate over collected tokens
    pub fn iter(&self) -> impl Iterator<Item = &TokenItem> { self.tokens.iter() }

    /// Render collected tokens into a single String
    pub fn to_string_flat(&self) -> String {
        let mut s = String::new();
        for t in &self.tokens { s.push_str(&t.to_string()); }
        s
    }

    /// Helper to push a whitespace token
    pub fn ws(&mut self) { self.tokens.push(TokenItem::Decorator(DecoratorToken::Whitespace(" ".into()))); }
}

impl FormatterOutput for TokenStream {
    fn write_text(&mut self, s: &str) {
        self.tokens.push(TokenItem::Decorator(DecoratorToken::Text(s.to_string())));
    }

    fn write_prefix(&mut self, s: &str) {
        self.tokens.push(TokenItem::Semantic(SemanticToken::Prefix(s.to_string())));
    }

    fn write_register(&mut self, s: &str) {
        self.tokens.push(TokenItem::Semantic(SemanticToken::Register(s.to_string())));
    }

    fn write_mnemonic(&mut self, s: &str) {
        self.tokens.push(TokenItem::Semantic(SemanticToken::Mnemonic(s.to_string())));
    }

    fn write_operand(&mut self, s: &str) {
        // Without deeper semantic context, treat as a generic operand token
        self.tokens.push(TokenItem::Semantic(SemanticToken::Operand(s.to_string())));
    }

    fn write_displacement(&mut self, s: &str) {
        self.tokens.push(TokenItem::Semantic(SemanticToken::Displacement(s.to_string())));
    }

    fn write_separator(&mut self, s: &str) {
        // Heuristic mapping of separators to decorator tokens
        match s {
            "[" => self.tokens.push(TokenItem::Decorator(DecoratorToken::OpenBracket)),
            "]" => self.tokens.push(TokenItem::Decorator(DecoratorToken::CloseBracket)),
            "," => self.tokens.push(TokenItem::Decorator(DecoratorToken::Comma)),
            ":" => self.tokens.push(TokenItem::Decorator(DecoratorToken::Colon)),
            ws if ws.trim().is_empty() => self.tokens.push(TokenItem::Decorator(DecoratorToken::Whitespace(ws.to_string()))),
            other if other.chars().all(|c| c.is_ascii_hexdigit()) => self.tokens.push(TokenItem::Decorator(DecoratorToken::Number(other.to_string()))),
            other => self.tokens.push(TokenItem::Decorator(DecoratorToken::Text(other.to_string()))),
        }
    }

    fn write_symbol(&mut self, s: &str) {
        match s {
            "+" => self.tokens.push(TokenItem::Decorator(DecoratorToken::Plus)),
            "-" => self.tokens.push(TokenItem::Decorator(DecoratorToken::Minus)),
            "*" => self.tokens.push(TokenItem::Decorator(DecoratorToken::Multiply)),
            other => self.tokens.push(TokenItem::Decorator(DecoratorToken::Text(other.to_string()))),
        }
    }
}
