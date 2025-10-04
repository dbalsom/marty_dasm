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

use crate::{
    SegmentSize,
    cpu_common::{AddressSize, OperandSize, OperandType, Register16},
    mnemonic::Mnemonic,
};

#[derive(Clone, Debug)]
pub struct Instruction {
    pub is_valid: bool,
    pub is_complete: bool,
    pub opcode: u16,
    pub instruction_bytes: Vec<u8>,
    pub displacement_bytes: Vec<u8>,
    pub immediate_bytes: Vec<u8>,
    pub prefix_bytes: Vec<u8>,
    pub has_modrm: bool,
    pub has_sib: bool,
    pub has_immediate: bool,
    pub immediate_size: OperandSize,
    pub has_displacement: bool,
    pub displacement_size: OperandSize,
    pub opcode_offset: usize,
    pub modrm_offset: usize,
    pub sib_offset: usize,
    pub prefix_flags: u32,
    pub prefix_ct: u32,
    pub address: u32,
    pub segment_size: SegmentSize,
    pub operand_size: OperandSize,
    pub address_size: AddressSize,
    pub mnemonic: Mnemonic,
    pub segment_override: Option<Register16>,
    pub disambiguate: bool,
    pub hide_operands: bool,
    pub operand1_type: OperandType,
    pub operand2_type: OperandType,
    pub operand3_type: OperandType,
}

impl Default for Instruction {
    fn default() -> Self {
        Self {
            is_valid: false,
            is_complete: false,
            opcode: 0,
            instruction_bytes: Vec::new(),
            displacement_bytes: Vec::new(),
            immediate_bytes: Vec::new(),
            prefix_bytes: Vec::new(),
            has_modrm: false,
            has_sib: false,
            has_immediate: false,
            immediate_size: Default::default(),
            has_displacement: false,
            displacement_size: Default::default(),
            opcode_offset: 0,
            modrm_offset: 0,
            sib_offset: 0,
            prefix_flags: 0,
            prefix_ct: 0,
            address: 0,
            segment_size: SegmentSize::Segment16,
            operand_size: OperandSize::NoOperand,
            address_size: AddressSize::Address16,
            mnemonic: Mnemonic::NOP,
            segment_override: None,
            disambiguate: false,
            hide_operands: false,
            operand1_type: OperandType::NoOperand,
            operand2_type: OperandType::NoOperand,
            operand3_type: OperandType::NoOperand,
        }
    }
}

impl Instruction {
    pub fn has_operands(&self) -> bool {
        self.operand1_type != OperandType::NoOperand
            || self.operand2_type != OperandType::NoOperand
            || self.operand3_type != OperandType::NoOperand
    }

    pub fn has_operand_size_override(&self) -> bool {
        match self.segment_size {
            SegmentSize::Segment16 => self.operand_size == OperandSize::Operand32,
            SegmentSize::Segment32 => self.operand_size == OperandSize::Operand16,
        }
    }

    pub fn has_address_size_override(&self) -> bool {
        match self.segment_size {
            SegmentSize::Segment16 => self.address_size == AddressSize::Address32,
            SegmentSize::Segment32 => self.address_size == AddressSize::Address16,
        }
    }

    pub fn operand_ct(&self) -> u32 {
        let mut ct = 0;
        if self.operand1_type != OperandType::NoOperand {
            ct += 1;
        }
        if self.operand2_type != OperandType::NoOperand {
            ct += 1;
        }
        if self.operand3_type != OperandType::NoOperand {
            ct += 1;
        }
        ct
    }
}
