/*
    marty_dasm
    Copyright 2022-2025 Daniel Balsom
    https://github.com/dbalsom/marty_dasm

    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the “Software”),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.
*/

pub mod nasm_formatter;
pub mod tokens;

use crate::formatter::nasm_formatter::NasmFormatter;
/// Re-export token types at the formatter module root for convenient access
pub use tokens::{DecoratorToken, SemanticToken, Token, TokenItem, TokenStream};

use crate::{instruction::Instruction, mnemonic::Mnemonic};

/// Options controlling disassembly formatting
#[derive(Copy, Clone, Debug)]
pub struct FormatOptions {
    /// If true, render mnemonic in uppercase; otherwise lowercase.
    pub uppercase_mnemonic: bool,
    /// If true, use iced mnemonics where there are alias differences (ja vs jnbe, etc.)
    pub iced_mnemonics: bool,
    /// If true, only output the mnemonic, no operands
    pub mnemonic_only: bool,
}

impl Default for FormatOptions {
    fn default() -> Self {
        Self {
            uppercase_mnemonic: false,
            iced_mnemonics: false,
            mnemonic_only: false,
        }
    }
}

/// Output sink for formatting tokens. Implement this to capture rich tokens
/// (e.g., for colorizing) or to accumulate plain text.
pub trait FormatterOutput {
    /// Fallback text writer for any token type
    fn write_text(&mut self, s: &str);

    /// Specific token helpers (default to write_text)
    fn write_prefix(&mut self, s: &str) {
        self.write_text(s)
    }

    fn write_register(&mut self, s: &str) {
        self.write_text(s)
    }
    fn write_mnemonic(&mut self, s: &str) {
        self.write_text(s)
    }
    fn write_operand(&mut self, s: &str) {
        self.write_text(s)
    }

    fn write_immediate(&mut self, s: &str) {
        self.write_text(s)
    }

    fn write_relative(&mut self, s: &str) {
        self.write_text(s)
    }
    fn write_displacement(&mut self, s: &str) {
        self.write_text(s)
    }
    fn write_separator(&mut self, s: &str) {
        self.write_text(s)
    }

    fn write_symbol(&mut self, s: &str) {
        self.write_text(s)
    }

    fn write_error(&mut self) {
        self.write_text("** ERROR **")
    }
}

/// Provide a basic String sink implementation
impl FormatterOutput for String {
    fn write_text(&mut self, s: &str) {
        self.push_str(s);
    }
}

/// Trait for disassembly formatting styles
pub trait Format {
    /// Emit any instruction prefixes (e.g., lock/rep/segment overrides). Should not add trailing spaces.
    fn format_prefixes(&self, inst: &Instruction, opts: &FormatOptions, out: &mut dyn FormatterOutput);
    /// Emit the mnemonic token without leading/trailing spaces.
    fn format_mnemonic(&self, inst: &Instruction, opts: &FormatOptions, out: &mut dyn FormatterOutput);
    /// Emit operands; include any leading separators (e.g., leading space before first operand).
    fn format_operands(&self, inst: &Instruction, opts: &FormatOptions, out: &mut dyn FormatterOutput);

    fn operands_suppressed(&self, inst: &Instruction) -> bool {
        inst.hide_operands
    }

    /// Compose the full instruction from parts (default behavior)
    fn format_instruction(&self, inst: &Instruction, opts: &FormatOptions, out: &mut dyn FormatterOutput) {
        if opts.mnemonic_only {
            // if only the mnemonic is requested, suppress operands
            self.format_mnemonic(inst, opts, out);
            return;
        }

        if matches!(inst.mnemonic, Mnemonic::Invalid) || !inst.is_complete || !inst.is_valid {
            out.write_text("(bad)");
            if matches!(inst.mnemonic, Mnemonic::Invalid) {
                return;
            }
            out.write_separator(" ");
        }

        // prefixes
        self.format_prefixes(inst, opts, out);

        // space between prefixes and mnemonic if prefixes emitted any visible output is left to implementations;
        // minimal NASM implementation emits no prefixes for now, so we don't add spaces here.
        // mnemonic
        self.format_mnemonic(inst, opts, out);

        if inst.has_operands() && !self.operands_suppressed(inst) {
            out.write_separator(" ");
            self.format_operands(inst, opts, out);
        }
    }
}

/// Convenience helper using NASM-style by default; returns a flat String
pub fn format_instruction(inst: &Instruction, opts: &FormatOptions) -> String {
    let mut s = String::new();
    NasmFormatter.format_instruction(inst, opts, &mut s);
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::{CpuType, DecoderOptions, decode_one};
    use std::io::Cursor;

    #[test]
    fn format_nop_lowercase() {
        let bytes = [0x90u8];
        let opts = DecoderOptions {
            cpu: CpuType::Intel808x,
            ..Default::default()
        };
        let inst = decode_one(Cursor::new(&bytes[..]), opts).expect("decode ok");
        let mut s = String::new();
        NasmFormatter.format_instruction(&inst, &FormatOptions::default(), &mut s);
        assert_eq!(s, "nop");
    }

    #[test]
    fn format_nop_uppercase() {
        let bytes = [0x90u8];
        let opts = DecoderOptions {
            cpu: CpuType::Intel808x,
            ..Default::default()
        };
        let inst = decode_one(Cursor::new(&bytes[..]), opts).expect("decode ok");
        let mut s = String::new();
        NasmFormatter.format_instruction(
            &inst,
            &FormatOptions {
                uppercase_mnemonic: true,
                ..Default::default()
            },
            &mut s,
        );
        assert_eq!(s, "NOP");
    }
}
