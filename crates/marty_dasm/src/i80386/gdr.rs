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
#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(dead_code)]

use crate::cpu_common::OperandSize;

/// Technically a PLA, the Group Decode ROM emits 15 signals given an 8-bit opcode for output.
/// These signals are encoded as a bitfield.
pub const GDR_IO: u16               = 0b0000_0000_0000_0001; // Instruction is an I/O instruction
pub const GDR_NO_LOAD_EA: u16       = 0b0000_0000_0000_0010; // Instruction does not load its EA (write-only)
pub const GDR_REG_0: u16            = 0b0000_0000_0000_0100; // Instruction must use REG == 0
pub const GDR_PREFIX: u16           = 0b0000_0000_0000_1000; // Instruction is a prefix byte
pub const GDR_NO_MODRM: u16         = 0b0000_0000_0001_0000; // Instruction does not have a modrm byte

pub const GDR_CAN_HAVE_ADDRESS_SIZE: u16 = 0b0000_0000_0010_0000;
pub const GDR_CAN_HAVE_OPERAND_SIZE: u16 = 0b0000_0000_0100_0000;

pub const GDR_USES_AREG: u16        = 0b0000_0000_1000_0000; // Instruction uses the AL or AX register specifically
pub const GDR_USES_SREG: u16        = 0b0000_0001_0000_0000; // Instruction uses a segment register
pub const GDR_D_VALID: u16          = 0b0000_0010_0000_0000; // 'D' bit is valid for instruction
pub const GRD_NO_MC: u16            = 0b0000_0100_0000_0000; // Instruction has no microcode
pub const GDR_W_VALID: u16          = 0b0000_1000_0000_0000; // 'W' bit is valid for instruction
pub const GDR_FORCE_BYTE: u16       = 0b0001_0000_0000_0000; // Instruction forces a byte operation

pub const GDR_NO_REG_FORM: u16      = 0b0010_0000_0000_0000; // Instruction has no register form
pub const GDR_ALWAYS_REGISTER: u16  = 0b0100_0000_0000_0000; // Instruction ignores mod bits
pub const GDR_DISAMBIGUATE: u16     = 0b1000_0000_0000_0000; // Instruction needs disambiguation

#[derive(Copy, Clone, Default)]
pub struct GdrEntry(pub u16);

impl GdrEntry {
    pub fn new(data: u16) -> Self {
        Self(data)
    }
    #[inline(always)]
    pub fn get(&self) -> u16 {
        self.0
    }
    #[inline(always)]
    pub fn has_modrm(&self) -> bool {
        self.0 & GDR_NO_MODRM == 0
    }
    #[inline(always)]
    pub fn loads_ea(&self) -> bool {
        self.0 & GDR_NO_LOAD_EA == 0
    }
    #[inline(always)]
    pub fn w_valid(&self) -> bool {
        self.0 & GDR_W_VALID != 0
    }
    #[inline(always)]
    pub fn width(&self, opcode: u8) -> OperandSize {
        if self.w_valid() && opcode & 1 != 0 {
            OperandSize::Operand16
        }
        else {
            OperandSize::Operand8
        }
    }
    #[inline(always)]
    pub fn can_have_operand_size(&self) -> bool {
        self.0 & GDR_CAN_HAVE_OPERAND_SIZE != 0
    }
    #[inline(always)]
    pub fn can_have_address_size(&self) -> bool {
        self.0 & GDR_CAN_HAVE_ADDRESS_SIZE != 0
    }
    #[inline(always)]
    pub fn d_valid(&self) -> bool {
        self.0 & GDR_D_VALID != 0
    }
    #[inline(always)]
    pub fn force_byte(&self) -> bool {
        self.0 & GDR_FORCE_BYTE != 0
    }
    #[inline(always)]
    pub fn has_reg_form(&self) -> bool {
        self.0 & GDR_NO_REG_FORM == 0
    }
    #[inline(always)]
    pub fn must_use_reg0(&self) -> bool {
        self.0 & GDR_REG_0 != 0
    }
    #[inline(always)]
    pub fn uses_segment_reg(&self) -> bool {
        self.0 & GDR_USES_SREG != 0
    }

    #[inline(always)]
    pub fn is_always_register(&self) -> bool {
        self.0 & GDR_ALWAYS_REGISTER != 0
    }
    #[inline(always)]
    pub fn needs_disambiguation(&self) -> bool {
        self.0 & GDR_DISAMBIGUATE != 0
    }
}