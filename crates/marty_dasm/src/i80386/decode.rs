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
#![allow(clippy::bool_assert_comparison)]

use std::{error::Error, fmt::Display, io};

use crate::{
    byte_reader::ByteReader,
    cpu_common::{
        AddressSize,
        Displacement,
        OperandSize,
        OperandType,
        OperandType::{AddressingMode16, AddressingMode32},
        PrefixFlags,
        Register8,
        Register16,
        Register32,
        SegmentSize,
    },
    error::DecodeError,
    i80386::{Intel80386, gdr::GdrEntry},
    instruction::Instruction,
    mnemonic::Mnemonic,
    modrm16::ModRmByte16,
    modrm32::ModRmByte32,
    sib::SibByte,
};

pub const MAX_INSTRUCTION_LENGTH: usize = 15;

#[allow(dead_code)]
#[derive(Copy, Clone, Default)]
pub struct InstTemplate {
    pub grp: u8,
    pub gdr: GdrEntry,
    pub mc: u16,
    pub mnemonic: Mnemonic,
    pub operand1: OperandTemplate,
    pub operand2: OperandTemplate,
    pub operand3: OperandTemplate,
}
impl InstTemplate {
    pub(crate) const fn constdefault() -> Self {
        Self {
            grp: 0,
            gdr: GdrEntry(0),
            mc: 0,
            mnemonic: Mnemonic::Invalid,
            operand1: OperandTemplate::NoOperand,
            operand2: OperandTemplate::NoOperand,
            operand3: OperandTemplate::NoOperand,
        }
    }
}

#[derive(Copy, Clone, Default, PartialEq)]
pub enum OperandTemplate {
    #[default]
    NoTemplate,
    NoOperand,
    ModRM8,
    ModRM16,
    ModRM16or32,
    ModRM16orR32,
    ModRM32,
    Register8,
    Register16,
    Register16or32,
    SegmentRegister,
    ControlRegister,
    DebugRegister,
    FixedImmediate8(u8),
    Immediate8,
    Immediate16,
    Immediate16or32,
    Immediate8SignExtended16,
    Immediate8SignExtended16or32,
    Relative8,
    Relative16,
    Relative16or32,
    Offset8,
    Offset16or32,
    FixedRegister8(Register8),
    FixedRegister16(Register16),
    FixedRegister16or32(Register16),
    FarPointer,
}

impl OperandTemplate {
    #[inline(always)]
    pub fn resolve_operand_a16(
        &self,
        bytes: &mut impl ByteReader,
        operand_size: OperandSize,
        modrm: &Option<ModRmByte16>,
        displacement: Displacement,
        instruction: &mut Instruction,
        force_reg: bool,
    ) -> io::Result<OperandType> {
        match (self, operand_size) {
            (OperandTemplate::ModRM8, _) => {
                let addr_mode = modrm.unwrap().address_offset(displacement);
                match modrm.unwrap().is_addressing_mode() {
                    true => Ok(AddressingMode16(addr_mode, OperandSize::Operand8)),
                    false => Ok(OperandType::Register8(modrm.unwrap().op1_reg8())),
                }
            }
            (OperandTemplate::ModRM16, _) => {
                let addr_mode = modrm.unwrap().address_offset(displacement);
                match modrm.unwrap().is_addressing_mode() {
                    true => Ok(AddressingMode16(addr_mode, OperandSize::Operand16)),
                    false => Ok(OperandType::Register16(modrm.unwrap().op1_reg16())),
                }
            }
            (OperandTemplate::ModRM16or32, _) => {
                let addr_mode = modrm.unwrap().address_offset(displacement);
                match modrm.unwrap().is_addressing_mode() && !force_reg {
                    true => Ok(AddressingMode16(addr_mode, operand_size)),
                    false => Ok(OperandType::Register16(modrm.unwrap().op1_reg16())),
                }
            }
            (OperandTemplate::ModRM16orR32, op) => {
                // This mode is either a 16-bit addressing mode or either a 16 or 32-bit register.
                let addr_mode = modrm.unwrap().address_offset(displacement);
                match modrm.unwrap().is_addressing_mode() && !force_reg {
                    true => Ok(AddressingMode16(addr_mode, OperandSize::Operand16)),
                    false => match op {
                        OperandSize::Operand16 => Ok(OperandType::Register16(modrm.unwrap().op1_reg16())),
                        OperandSize::Operand32 => Ok(OperandType::Register32(modrm.unwrap().op1_reg32())),
                        _ => panic!("Unexpected operand size in ModRM16orR32"),
                    },
                }
            }
            (OperandTemplate::ModRM32, _) => {
                let addr_mode = modrm.unwrap().address_offset(displacement);
                match modrm.unwrap().is_addressing_mode() && !force_reg {
                    true => Ok(AddressingMode16(addr_mode, operand_size)),
                    false => Ok(OperandType::Register32(modrm.unwrap().op1_reg32())),
                }
            }
            (OperandTemplate::Register8, _) => Ok(OperandType::Register8(modrm.unwrap().op2_reg8())),
            (OperandTemplate::Register16, _) => Ok(OperandType::Register16(modrm.unwrap().op2_reg16())),
            (OperandTemplate::Register16or32, OperandSize::Operand16) => {
                Ok(OperandType::Register16(modrm.unwrap().op2_reg16()))
            }
            (OperandTemplate::Register16or32, OperandSize::Operand32) => {
                Ok(OperandType::Register32(modrm.unwrap().op2_reg32()))
            }
            (OperandTemplate::SegmentRegister, _) => {
                Ok(OperandType::Register16(modrm.unwrap().op2_segment_reg16_386()))
            }
            (OperandTemplate::ControlRegister, _) => Ok(OperandType::ControlRegister(modrm.unwrap().op2_reg_ctrl())),
            (OperandTemplate::DebugRegister, _) => Ok(OperandType::DebugRegister(modrm.unwrap().op2_reg_dbg())),
            (OperandTemplate::FixedImmediate8(val), _) => {
                // Fixed immediate is assumed, no bytes read.
                instruction.disambiguate = true;
                Ok(OperandType::Immediate8(*val))
            }
            (OperandTemplate::Immediate8, _) => {
                let operand = bytes.read_u8()?;
                instruction.instruction_bytes.push(operand);
                instruction.immediate_bytes.push(operand);
                instruction.disambiguate = true;
                Ok(OperandType::Immediate8(operand))
            }
            (OperandTemplate::Immediate16, _) => {
                let operand = bytes.read_u16()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.disambiguate = true;
                Ok(OperandType::Immediate16(operand))
            }
            (OperandTemplate::Immediate16or32, OperandSize::Operand16) => {
                let operand = bytes.read_u16()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.disambiguate = true;
                Ok(OperandType::Immediate16(operand))
            }
            (OperandTemplate::Immediate16or32, OperandSize::Operand32) => {
                let operand = bytes.read_u32()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.disambiguate = true;
                Ok(OperandType::Immediate32(operand))
            }
            (OperandTemplate::Immediate8SignExtended16, _) => {
                let operand = bytes.read_i8()?;
                instruction.instruction_bytes.push(operand as u8);
                instruction.immediate_bytes.push(operand as u8);
                instruction.disambiguate = true;
                Ok(OperandType::Immediate8s(operand))
            }
            (OperandTemplate::Immediate8SignExtended16or32, _) => {
                let operand = bytes.read_i8()?;
                instruction.instruction_bytes.push(operand as u8);
                instruction.immediate_bytes.push(operand as u8);
                instruction.disambiguate = true;
                Ok(OperandType::Immediate8s(operand))
            }
            (OperandTemplate::Relative8, _) => {
                let operand = bytes.read_i8()?;
                instruction.instruction_bytes.push(operand as u8);
                instruction.immediate_bytes.push(operand as u8);
                Ok(OperandType::Relative8(operand))
            }
            (OperandTemplate::Relative16, _) => {
                let operand = bytes.read_i16()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                Ok(OperandType::Relative16(operand))
            }
            (OperandTemplate::Relative16or32, OperandSize::Operand16) => {
                let operand = bytes.read_i16()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                Ok(OperandType::Relative16(operand))
            }
            (OperandTemplate::Relative16or32, OperandSize::Operand32) => {
                let operand = bytes.read_i32()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                Ok(OperandType::Relative32(operand))
            }
            (OperandTemplate::Offset8, _) => {
                let operand = bytes.read_u16()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                Ok(OperandType::Offset8_16(operand))
            }
            (OperandTemplate::Offset16or32, OperandSize::Operand16) => {
                let operand = bytes.read_u16()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                Ok(OperandType::Offset16_16(operand))
            }
            (OperandTemplate::Offset16or32, OperandSize::Operand32) => {
                let operand = bytes.read_u16()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                Ok(OperandType::Offset32_16(operand))
            }
            (OperandTemplate::FixedRegister8(r8), _) => {
                instruction.disambiguate = true;
                Ok(OperandType::Register8(*r8))
            }
            (OperandTemplate::FixedRegister16(r16), _) => {
                instruction.disambiguate = true;
                Ok(OperandType::Register16(*r16))
            }
            (OperandTemplate::FixedRegister16or32(r16), OperandSize::Operand16) => Ok(OperandType::Register16(*r16)),
            (OperandTemplate::FixedRegister16or32(r16), OperandSize::Operand32) => {
                Ok(OperandType::Register32(Register32::from(*r16)))
            }
            (OperandTemplate::FarPointer, _) => {
                let (segment, offset) = bytes.peek_farptr16()?;
                instruction.instruction_bytes.extend_from_slice(&offset.to_le_bytes());
                instruction.instruction_bytes.extend_from_slice(&segment.to_le_bytes());

                instruction.immediate_bytes.extend_from_slice(&offset.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&segment.to_le_bytes());
                Ok(OperandType::FarPointer16(segment, offset))
            }
            _ => Ok(OperandType::NoOperand),
        }
    }

    pub fn resolve_operand_a32(
        &self,
        bytes: &mut impl ByteReader,
        operand_size: OperandSize,
        modrm: &Option<ModRmByte32>,
        sib_option: &Option<SibByte>,
        displacement: Displacement,
        instruction: &mut Instruction,
        force_reg: bool,
    ) -> io::Result<OperandType> {
        match (self, operand_size) {
            (OperandTemplate::ModRM8, _) => {
                if let Some(sib) = sib_option {
                    Ok(AddressingMode32(sib.address_offset(), OperandSize::Operand8))
                }
                else {
                    let addr_mode = modrm.unwrap().address_offset(displacement);
                    match modrm.unwrap().is_addressing_mode() {
                        true => Ok(AddressingMode32(addr_mode, OperandSize::Operand8)),
                        false => Ok(OperandType::Register8(modrm.unwrap().op1_reg8())),
                    }
                }
            }
            (OperandTemplate::ModRM16, _) => {
                if let Some(sib) = sib_option {
                    Ok(AddressingMode32(sib.address_offset(), OperandSize::Operand16))
                }
                else {
                    let addr_mode = modrm.unwrap().address_offset(displacement);
                    match modrm.unwrap().is_addressing_mode() {
                        true => Ok(AddressingMode32(addr_mode, OperandSize::Operand16)),
                        false => Ok(OperandType::Register16(modrm.unwrap().op1_reg16())),
                    }
                }
            }
            (OperandTemplate::ModRM16orR32, _) => {
                match (sib_option, force_reg) {
                    (Some(sib), false) => {
                        // Force 16-bit operand size.
                        Ok(AddressingMode32(sib.address_offset(), OperandSize::Operand16))
                    }
                    _ => {
                        let modrm = modrm.unwrap();
                        let addr_mode = modrm.address_offset(displacement);
                        if modrm.is_addressing_mode() && !force_reg {
                            // Force 16-bit operand size.
                            Ok(AddressingMode32(addr_mode, OperandSize::Operand16))
                        }
                        else {
                            Ok(OperandType::Register32(modrm.op1_reg32()))
                        }
                    }
                }
            }
            (OperandTemplate::ModRM16or32 | OperandTemplate::ModRM32, _) => match (sib_option, force_reg) {
                (Some(sib), false) => Ok(AddressingMode32(sib.address_offset(), operand_size)),
                _ => {
                    let modrm = modrm.unwrap();
                    let addr_mode = modrm.address_offset(displacement);
                    if modrm.is_addressing_mode() && !force_reg {
                        Ok(AddressingMode32(addr_mode, operand_size))
                    }
                    else {
                        Ok(OperandType::Register32(modrm.op1_reg32()))
                    }
                }
            },
            (OperandTemplate::Register8, _) => Ok(OperandType::Register8(modrm.unwrap().op2_reg8())),
            (OperandTemplate::Register16, _) => Ok(OperandType::Register16(modrm.unwrap().op2_reg16())),
            (OperandTemplate::Register16or32, OperandSize::Operand16) => {
                Ok(OperandType::Register16(modrm.unwrap().op2_reg16()))
            }
            (OperandTemplate::Register16or32, OperandSize::Operand32) => {
                Ok(OperandType::Register32(modrm.unwrap().op2_reg32()))
            }
            (OperandTemplate::SegmentRegister, _) => {
                Ok(OperandType::Register16(modrm.unwrap().op2_segment_reg16_386()))
            }
            (OperandTemplate::ControlRegister, _) => Ok(OperandType::ControlRegister(modrm.unwrap().op2_reg_ctrl())),
            (OperandTemplate::DebugRegister, _) => Ok(OperandType::DebugRegister(modrm.unwrap().op2_reg_dbg())),
            (OperandTemplate::FixedImmediate8(val), _) => {
                // Fixed immediate is assumed, no bytes read.
                instruction.disambiguate = true;
                Ok(OperandType::Immediate8(*val))
            }
            (OperandTemplate::Immediate8, _) => {
                let operand = bytes.read_u8()?;
                instruction.instruction_bytes.push(operand);
                instruction.immediate_bytes.push(operand);
                instruction.disambiguate = true;
                Ok(OperandType::Immediate8(operand))
            }
            (OperandTemplate::Immediate16, _) => {
                let operand = bytes.read_u16()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.disambiguate = true;
                Ok(OperandType::Immediate16(operand))
            }
            (OperandTemplate::Immediate16or32, OperandSize::Operand16) => {
                let operand = bytes.read_u16()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.disambiguate = true;
                Ok(OperandType::Immediate16(operand))
            }
            (OperandTemplate::Immediate16or32, OperandSize::Operand32) => {
                let operand = bytes.read_u32()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.disambiguate = true;
                Ok(OperandType::Immediate32(operand))
            }
            (OperandTemplate::Immediate8SignExtended16, _) => {
                let operand = bytes.read_i8()?;
                instruction.instruction_bytes.push(operand as u8);
                instruction.immediate_bytes.push(operand as u8);
                instruction.disambiguate = true;
                Ok(OperandType::Immediate8s(operand))
            }
            (OperandTemplate::Immediate8SignExtended16or32, _) => {
                let operand = bytes.read_i8()?;
                instruction.instruction_bytes.push(operand as u8);
                instruction.immediate_bytes.push(operand as u8);
                instruction.disambiguate = true;
                Ok(OperandType::Immediate8s(operand))
            }
            (OperandTemplate::Relative8, _) => {
                let operand = bytes.read_i8()?;
                instruction.instruction_bytes.push(operand as u8);
                instruction.immediate_bytes.push(operand as u8);
                Ok(OperandType::Relative8(operand))
            }
            (OperandTemplate::Relative16, OperandSize::Operand16) => {
                let operand = bytes.read_i16()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                Ok(OperandType::Relative16(operand))
            }
            (OperandTemplate::Relative16, OperandSize::Operand32) => {
                let operand = bytes.read_i32()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                Ok(OperandType::Relative32(operand))
            }
            (OperandTemplate::Relative16or32, OperandSize::Operand16) => {
                let operand = bytes.read_i16()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                Ok(OperandType::Relative16(operand))
            }
            (OperandTemplate::Relative16or32, OperandSize::Operand32) => {
                let operand = bytes.read_i32()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                Ok(OperandType::Relative32(operand))
            }
            (OperandTemplate::Offset8, _) => {
                let operand = bytes.read_u32()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                Ok(OperandType::Offset8_32(operand))
            }
            (OperandTemplate::Offset16or32, OperandSize::Operand16) => {
                let operand = bytes.read_u32()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                Ok(OperandType::Offset16_32(operand))
            }
            (OperandTemplate::Offset16or32, OperandSize::Operand32) => {
                let operand = bytes.read_u32()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                Ok(OperandType::Offset32_32(operand))
            }
            (OperandTemplate::FixedRegister8(r8), _) => {
                instruction.disambiguate = true;
                Ok(OperandType::Register8(*r8))
            }
            (OperandTemplate::FixedRegister16(r16), _) => {
                instruction.disambiguate = true;
                Ok(OperandType::Register16(*r16))
            }
            (OperandTemplate::FixedRegister16or32(r16), OperandSize::Operand16) => Ok(OperandType::Register16(*r16)),
            (OperandTemplate::FixedRegister16or32(r16), OperandSize::Operand32) => {
                Ok(OperandType::Register32(Register32::from(*r16)))
            }
            (OperandTemplate::FarPointer, _) => {
                let (segment, offset) = bytes.read_farptr32()?;
                instruction.instruction_bytes.extend_from_slice(&offset.to_le_bytes());
                instruction.instruction_bytes.extend_from_slice(&segment.to_le_bytes());

                instruction.immediate_bytes.extend_from_slice(&offset.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&segment.to_le_bytes());
                Ok(OperandType::FarPointer32(segment, offset))
            }
            _ => Ok(OperandType::NoOperand),
        }
    }
}

type Ot = OperandTemplate;

#[allow(dead_code)]
#[derive(Debug)]
pub enum InstructionDecodeError {
    UnsupportedOpcode(u8),
    InvalidSegmentRegister,
    ReadOutOfBounds,
    GeneralDecodeError(u8),
    Unimplemented(u8),
}

impl Error for InstructionDecodeError {}
impl Display for InstructionDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            InstructionDecodeError::UnsupportedOpcode(o) => {
                write!(f, "An unsupported opcode was encountered: {:#2x}.", o)
            }
            InstructionDecodeError::InvalidSegmentRegister => {
                write!(f, "An invalid segment register was specified.")
            }
            InstructionDecodeError::ReadOutOfBounds => {
                write!(f, "Unexpected buffer exhaustion while decoding instruction.")
            }
            InstructionDecodeError::GeneralDecodeError(o) => {
                write!(f, "General error decoding opcode {:#2x}.", o)
            }
            InstructionDecodeError::Unimplemented(o) => {
                write!(f, "Decoding of instruction {:#2x} not implemented.", o)
            }
        }
    }
}

macro_rules! inst_skip {
    ($init:ident, $ct:literal) => {
        $init.idx += $ct;
    };
}
macro_rules! inst {
    ($opcode:literal, $init:ident,  $grp:literal, $gdr:literal, $mc:literal, $m:ident, $o1:expr, $o2:expr) => {
        $init.table[$init.idx] = InstTemplate {
            grp: $grp,
            gdr: GdrEntry($gdr),
            mc: $mc,
            mnemonic: Mnemonic::$m,
            operand1: $o1,
            operand2: $o2,
            operand3: OperandTemplate::NoOperand,
        };
        // if $init.idx >= REGULAR_OPS_LEN {
        //     assert!($opcode == ($init.idx - REGULAR_OPS_LEN) as u8);
        // }
        $init.idx += 1;
    };

    ($opcode:literal, $init:ident,  $grp:literal, $gdr:literal, $mc:literal, $m:ident, $o1:expr, $o2:expr, $o3:expr) => {
        $init.table[$init.idx] = InstTemplate {
            grp: $grp,
            gdr: GdrEntry($gdr),
            mc: $mc,
            mnemonic: Mnemonic::$m,
            operand1: $o1,
            operand2: $o2,
            operand3: $o3,
        };
        $init.idx += 1;
    };
}

pub const REGULAR_OPS_LEN: usize = 256 + (14 * 8); // 256 opcodes + 14 groups of 8
pub const EXTENDED_OPS_LEN: usize = 256 + (3 * 8); // 256 opcodes + 3 groups of 8
pub const TOTAL_OPS_LEN: usize = REGULAR_OPS_LEN + EXTENDED_OPS_LEN;

pub struct TableInitializer {
    pub idx:   usize,
    pub table: [InstTemplate; TOTAL_OPS_LEN],
}

impl TableInitializer {
    const fn new() -> Self {
        Self {
            idx:   0,
            table: [InstTemplate::constdefault(); TOTAL_OPS_LEN],
        }
    }
}

//noinspection RsAssertEqual
#[rustfmt::skip]
pub static DECODE: [InstTemplate; TOTAL_OPS_LEN] = {
    let mut o: TableInitializer = TableInitializer::new();
    inst!( 0x00, o, 0, 0b0000_1010_0000_0000, 0x008, ADD,     Ot::ModRM8,                             Ot::Register8);
    inst!( 0x01, o, 0, 0b0000_1010_0000_0000, 0x008, ADD,     Ot::ModRM16or32,                        Ot::Register16or32);
    inst!( 0x02, o, 0, 0b0000_1010_0000_0000, 0x008, ADD,     Ot::Register8,                          Ot::ModRM8);
    inst!( 0x03, o, 0, 0b0000_1010_0000_0000, 0x008, ADD,     Ot::Register16or32,                     Ot::ModRM16or32);
    inst!( 0x04, o, 0, 0b0000_1000_1001_0010, 0x018, ADD,     Ot::FixedRegister8(Register8::AL),      Ot::Immediate8);
    inst!( 0x05, o, 0, 0b0000_1000_1001_0010, 0x018, ADD,     Ot::FixedRegister16or32(Register16::AX),Ot::Immediate16or32);
    inst!( 0x06, o, 0, 0b0000_0000_0011_0010, 0x02c, PUSH,    Ot::FixedRegister16(Register16::ES),    Ot::NoOperand);
    inst!( 0x07, o, 0, 0b0000_0000_0011_0010, 0x038, POP,     Ot::FixedRegister16(Register16::ES),    Ot::NoOperand);
    inst!( 0x08, o, 0, 0b0000_1010_0000_0000, 0x008, OR,      Ot::ModRM8,                             Ot::Register8);
    inst!( 0x09, o, 0, 0b0000_1010_0000_0000, 0x008, OR,      Ot::ModRM16or32,                        Ot::Register16or32);
    inst!( 0x0A, o, 0, 0b0000_1010_0000_0000, 0x008, OR,      Ot::Register8,                          Ot::ModRM8);
    inst!( 0x0B, o, 0, 0b0000_1010_0000_0000, 0x008, OR,      Ot::Register16or32,                     Ot::ModRM16or32);
    inst!( 0x0C, o, 0, 0b0000_1000_1001_0010, 0x018, OR,      Ot::FixedRegister8(Register8::AL),      Ot::Immediate8);
    inst!( 0x0D, o, 0, 0b0000_1000_1001_0010, 0x018, OR,      Ot::FixedRegister16or32(Register16::AX),Ot::Immediate16or32);
    inst!( 0x0E, o, 0, 0b0000_0000_0011_0010, 0x02c, PUSH,    Ot::FixedRegister16(Register16::CS),    Ot::NoOperand);
    inst!( 0x0F, o, 0, 0b0000_0000_0000_0000, 0x038, Extension,Ot::NoOperand,                         Ot::NoOperand);
    inst!( 0x10, o, 0, 0b0000_1010_0000_0000, 0x008, ADC,     Ot::ModRM8,                             Ot::Register8);
    inst!( 0x11, o, 0, 0b0000_1010_0000_0000, 0x008, ADC,     Ot::ModRM16or32,                        Ot::Register16or32);
    inst!( 0x12, o, 0, 0b0000_1010_0000_0000, 0x008, ADC,     Ot::Register8,                          Ot::ModRM8);
    inst!( 0x13, o, 0, 0b0000_1010_0000_0000, 0x008, ADC,     Ot::Register16or32,                     Ot::ModRM16or32);
    inst!( 0x14, o, 0, 0b0000_1000_1001_0010, 0x018, ADC,     Ot::FixedRegister8(Register8::AL),      Ot::Immediate8);
    inst!( 0x15, o, 0, 0b0000_1000_1001_0010, 0x018, ADC,     Ot::FixedRegister16or32(Register16::AX),Ot::Immediate16or32);
    inst!( 0x16, o, 0, 0b0000_0000_0011_0010, 0x02c, PUSH,    Ot::FixedRegister16(Register16::SS),    Ot::NoOperand);
    inst!( 0x17, o, 0, 0b0000_0000_0011_0010, 0x038, POP,     Ot::FixedRegister16(Register16::SS),    Ot::NoOperand);
    inst!( 0x18, o, 0, 0b0000_1010_0000_0000, 0x008, SBB,     Ot::ModRM8,                             Ot::Register8);
    inst!( 0x19, o, 0, 0b0000_1010_0000_0000, 0x008, SBB,     Ot::ModRM16or32,                        Ot::Register16or32);
    inst!( 0x1A, o, 0, 0b0000_1010_0000_0000, 0x008, SBB,     Ot::Register8,                          Ot::ModRM8);
    inst!( 0x1B, o, 0, 0b0000_1010_0000_0000, 0x008, SBB,     Ot::Register16or32,                     Ot::ModRM16or32);
    inst!( 0x1C, o, 0, 0b0000_1000_1001_0010, 0x018, SBB,     Ot::FixedRegister8(Register8::AL),      Ot::Immediate8);
    inst!( 0x1D, o, 0, 0b0000_1000_1001_0010, 0x018, SBB,     Ot::FixedRegister16or32(Register16::AX),Ot::Immediate16or32);
    inst!( 0x1E, o, 0, 0b0000_0000_0011_0010, 0x02c, PUSH,    Ot::FixedRegister16(Register16::DS),    Ot::NoOperand);
    inst!( 0x1F, o, 0, 0b0000_0000_0011_0010, 0x038, POP,     Ot::FixedRegister16(Register16::DS),    Ot::NoOperand);
    inst!( 0x20, o, 0, 0b0000_1010_0000_0000, 0x008, AND,     Ot::ModRM8,                             Ot::Register8);
    inst!( 0x21, o, 0, 0b0000_1010_0000_0000, 0x008, AND,     Ot::ModRM16or32,                        Ot::Register16or32);
    inst!( 0x22, o, 0, 0b0000_1010_0000_0000, 0x008, AND,     Ot::Register8,                          Ot::ModRM8);
    inst!( 0x23, o, 0, 0b0000_1010_0000_0000, 0x008, AND,     Ot::Register16or32,                     Ot::ModRM16or32);
    inst!( 0x24, o, 0, 0b0000_1000_1001_0010, 0x018, AND,     Ot::FixedRegister8(Register8::AL),      Ot::Immediate8);
    inst!( 0x25, o, 0, 0b0000_1000_1001_0010, 0x018, AND,     Ot::FixedRegister16or32(Register16::AX),Ot::Immediate16or32);
    inst!( 0x26, o, 0, 0b0000_0100_0011_1010, 0x1FF, Prefix,  Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x27, o, 0, 0b0001_0000_0011_0010, 0x144, DAA,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x28, o, 0, 0b0000_1010_0000_0000, 0x008, SUB,     Ot::ModRM8,                             Ot::Register8);
    inst!( 0x29, o, 0, 0b0000_1010_0000_0000, 0x008, SUB,     Ot::ModRM16or32,                        Ot::Register16or32);
    inst!( 0x2A, o, 0, 0b0000_1010_0000_0000, 0x008, SUB,     Ot::Register8,                          Ot::ModRM8);
    inst!( 0x2B, o, 0, 0b0000_1010_0000_0000, 0x008, SUB,     Ot::Register16or32,                     Ot::ModRM16or32);
    inst!( 0x2C, o, 0, 0b0000_1000_1001_0010, 0x018, SUB,     Ot::FixedRegister8(Register8::AL),      Ot::Immediate8);
    inst!( 0x2D, o, 0, 0b0000_1000_1001_0010, 0x018, SUB,     Ot::FixedRegister16or32(Register16::AX),Ot::Immediate16or32);
    inst!( 0x2E, o, 0, 0b0000_0100_0011_1010, 0x1FF, Prefix,  Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x2F, o, 0, 0b0001_0000_0011_0010, 0x144, DAS,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x30, o, 0, 0b0000_1010_0000_0000, 0x008, XOR,     Ot::ModRM8,                             Ot::Register8);
    inst!( 0x31, o, 0, 0b0000_1010_0000_0000, 0x008, XOR,     Ot::ModRM16or32,                        Ot::Register16or32);
    inst!( 0x32, o, 0, 0b0000_1010_0000_0000, 0x008, XOR,     Ot::Register8,                          Ot::ModRM8);
    inst!( 0x33, o, 0, 0b0000_1010_0000_0000, 0x008, XOR,     Ot::Register16or32,                     Ot::ModRM16or32);
    inst!( 0x34, o, 0, 0b0000_1000_1001_0010, 0x018, XOR,     Ot::FixedRegister8(Register8::AL),      Ot::Immediate8);
    inst!( 0x35, o, 0, 0b0000_1000_1001_0010, 0x018, XOR,     Ot::FixedRegister16or32(Register16::AX),Ot::Immediate16or32);
    inst!( 0x36, o, 0, 0b0000_0100_0011_1010, 0x1FF, Prefix,  Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x37, o, 0, 0b0001_0000_0011_0010, 0x148, AAA,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x38, o, 0, 0b0000_1010_0000_0000, 0x008, CMP,     Ot::ModRM8,                             Ot::Register8);
    inst!( 0x39, o, 0, 0b0000_1010_0000_0000, 0x008, CMP,     Ot::ModRM16or32,                        Ot::Register16or32);
    inst!( 0x3A, o, 0, 0b0000_1010_0000_0000, 0x008, CMP,     Ot::Register8,                          Ot::ModRM8);
    inst!( 0x3B, o, 0, 0b0000_1010_0000_0000, 0x008, CMP,     Ot::Register16or32,                     Ot::ModRM16or32);
    inst!( 0x3C, o, 0, 0b0000_1000_1001_0010, 0x018, CMP,     Ot::FixedRegister8(Register8::AL),      Ot::Immediate8);
    inst!( 0x3D, o, 0, 0b0000_1000_1001_0010, 0x018, CMP,     Ot::FixedRegister16or32(Register16::AX),Ot::Immediate16or32);
    inst!( 0x3E, o, 0, 0b0000_0100_0011_1010, 0x1FF, Prefix,  Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x3F, o, 0, 0b0001_0000_0011_0010, 0x148, AAS,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x40, o, 0, 0b0000_0000_0011_0010, 0x17c, INC,     Ot::FixedRegister16or32(Register16::AX),Ot::NoOperand);
    inst!( 0x41, o, 0, 0b0000_0000_0011_0010, 0x17c, INC,     Ot::FixedRegister16or32(Register16::CX),Ot::NoOperand);
    inst!( 0x42, o, 0, 0b0000_0000_0011_0010, 0x17c, INC,     Ot::FixedRegister16or32(Register16::DX),Ot::NoOperand);
    inst!( 0x43, o, 0, 0b0000_0000_0011_0010, 0x17c, INC,     Ot::FixedRegister16or32(Register16::BX),Ot::NoOperand);
    inst!( 0x44, o, 0, 0b0000_0000_0011_0010, 0x17c, INC,     Ot::FixedRegister16or32(Register16::SP),Ot::NoOperand);
    inst!( 0x45, o, 0, 0b0000_0000_0011_0010, 0x17c, INC,     Ot::FixedRegister16or32(Register16::BP),Ot::NoOperand);
    inst!( 0x46, o, 0, 0b0000_0000_0011_0010, 0x17c, INC,     Ot::FixedRegister16or32(Register16::SI),Ot::NoOperand);
    inst!( 0x47, o, 0, 0b0000_0000_0011_0010, 0x17c, INC,     Ot::FixedRegister16or32(Register16::DI),Ot::NoOperand);
    inst!( 0x48, o, 0, 0b0000_0000_0011_0010, 0x17c, DEC,     Ot::FixedRegister16or32(Register16::AX),Ot::NoOperand);
    inst!( 0x49, o, 0, 0b0000_0000_0011_0010, 0x17c, DEC,     Ot::FixedRegister16or32(Register16::CX),Ot::NoOperand);
    inst!( 0x4A, o, 0, 0b0000_0000_0011_0010, 0x17c, DEC,     Ot::FixedRegister16or32(Register16::DX),Ot::NoOperand);
    inst!( 0x4B, o, 0, 0b0000_0000_0011_0010, 0x17c, DEC,     Ot::FixedRegister16or32(Register16::BX),Ot::NoOperand);
    inst!( 0x4C, o, 0, 0b0000_0000_0011_0010, 0x17c, DEC,     Ot::FixedRegister16or32(Register16::SP),Ot::NoOperand);
    inst!( 0x4D, o, 0, 0b0000_0000_0011_0010, 0x17c, DEC,     Ot::FixedRegister16or32(Register16::BP),Ot::NoOperand);
    inst!( 0x4E, o, 0, 0b0000_0000_0011_0010, 0x17c, DEC,     Ot::FixedRegister16or32(Register16::SI),Ot::NoOperand);
    inst!( 0x4F, o, 0, 0b0000_0000_0011_0010, 0x17c, DEC,     Ot::FixedRegister16or32(Register16::DI),Ot::NoOperand);
    inst!( 0x50, o, 0, 0b0000_0000_0011_0010, 0x028, PUSH,    Ot::FixedRegister16or32(Register16::AX),Ot::NoOperand);
    inst!( 0x51, o, 0, 0b0000_0000_0011_0010, 0x028, PUSH,    Ot::FixedRegister16or32(Register16::CX),Ot::NoOperand);
    inst!( 0x52, o, 0, 0b0000_0000_0011_0010, 0x028, PUSH,    Ot::FixedRegister16or32(Register16::DX),Ot::NoOperand);
    inst!( 0x53, o, 0, 0b0000_0000_0011_0010, 0x028, PUSH,    Ot::FixedRegister16or32(Register16::BX),Ot::NoOperand);
    inst!( 0x54, o, 0, 0b0000_0000_0011_0010, 0x028, PUSH,    Ot::FixedRegister16or32(Register16::SP),Ot::NoOperand);
    inst!( 0x55, o, 0, 0b0000_0000_0011_0010, 0x028, PUSH,    Ot::FixedRegister16or32(Register16::BP),Ot::NoOperand);
    inst!( 0x56, o, 0, 0b0000_0000_0011_0010, 0x028, PUSH,    Ot::FixedRegister16or32(Register16::SI),Ot::NoOperand);
    inst!( 0x57, o, 0, 0b0000_0000_0011_0010, 0x028, PUSH,    Ot::FixedRegister16or32(Register16::DI),Ot::NoOperand);
    inst!( 0x58, o, 0, 0b0000_0000_0011_0010, 0x034, POP,     Ot::FixedRegister16or32(Register16::AX),Ot::NoOperand);
    inst!( 0x59, o, 0, 0b0000_0000_0011_0010, 0x034, POP,     Ot::FixedRegister16or32(Register16::CX),Ot::NoOperand);
    inst!( 0x5A, o, 0, 0b0000_0000_0011_0010, 0x034, POP,     Ot::FixedRegister16or32(Register16::DX),Ot::NoOperand);
    inst!( 0x5B, o, 0, 0b0000_0000_0011_0010, 0x034, POP,     Ot::FixedRegister16or32(Register16::BX),Ot::NoOperand);
    inst!( 0x5C, o, 0, 0b0000_0000_0011_0010, 0x034, POP,     Ot::FixedRegister16or32(Register16::SP),Ot::NoOperand);
    inst!( 0x5D, o, 0, 0b0000_0000_0011_0010, 0x034, POP,     Ot::FixedRegister16or32(Register16::BP),Ot::NoOperand);
    inst!( 0x5E, o, 0, 0b0000_0000_0011_0010, 0x034, POP,     Ot::FixedRegister16or32(Register16::SI),Ot::NoOperand);
    inst!( 0x5F, o, 0, 0b0000_0000_0011_0010, 0x034, POP,     Ot::FixedRegister16or32(Register16::DI),Ot::NoOperand);
    inst!( 0x60, o, 0, 0b0000_0000_0001_0000, 0x0e8, PUSHA,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x61, o, 0, 0b0000_0000_0001_0000, 0x0e8, POPA,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x62, o, 0, 0b0010_0000_0000_0000, 0x0e8, BOUND,   Ot::Register16or32,                     Ot::ModRM16or32);
    inst!( 0x63, o, 0, 0b0000_0000_0000_0000, 0x0e8, ARPL,    Ot::ModRM16,                            Ot::Register16);
    inst!( 0x64, o, 0, 0b0000_0000_0001_1000, 0x0e8, Prefix,  Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x65, o, 0, 0b0000_0000_0001_1000, 0x0e8, Prefix,  Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x66, o, 0, 0b0000_0000_0000_0000, 0x0e8, Prefix,  Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x67, o, 0, 0b0000_0000_0000_0000, 0x0e8, Prefix,  Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x68, o, 0, 0b0000_0000_0001_0000, 0x0e8, PUSH,    Ot::Immediate16or32,                    Ot::NoOperand);
    inst!( 0x69, o, 0, 0b0000_0000_0000_0000, 0x0e8, IMUL,    Ot::Register16or32,                     Ot::ModRM16or32, Ot::Immediate16or32);
    inst!( 0x6A, o, 0, 0b0000_0000_0001_0000, 0x0e8, PUSH,    Ot::Immediate8SignExtended16,           Ot::NoOperand);
    inst!( 0x6B, o, 0, 0b0000_0000_0000_0000, 0x0e8, IMUL,    Ot::Register16or32,                     Ot::ModRM16or32, Ot::Immediate8SignExtended16or32);
    inst!( 0x6C, o, 0, 0b0000_0000_0001_0000, 0x0e8, INSB,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x6D, o, 0, 0b0000_0000_0001_0000, 0x0e8, INSW,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x6E, o, 0, 0b0000_0000_0001_0000, 0x0e8, OUTSB,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x6F, o, 0, 0b0000_0000_0001_0000, 0x0e8, OUTSW,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x70, o, 0, 0b1000_0000_0011_0010, 0x0e8, JO,      Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x71, o, 0, 0b1000_0000_0011_0010, 0x0e8, JNO,     Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x72, o, 0, 0b1000_0000_0011_0010, 0x0e8, JB,      Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x73, o, 0, 0b1000_0000_0011_0010, 0x0e8, JNB,     Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x74, o, 0, 0b1000_0000_0011_0010, 0x0e8, JZ,      Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x75, o, 0, 0b1000_0000_0011_0010, 0x0e8, JNZ,     Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x76, o, 0, 0b1000_0000_0011_0010, 0x0e8, JBE,     Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x77, o, 0, 0b1000_0000_0011_0010, 0x0e8, JNBE,    Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x78, o, 0, 0b1000_0000_0011_0010, 0x0e8, JS,      Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x79, o, 0, 0b1000_0000_0011_0010, 0x0e8, JNS,     Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x7A, o, 0, 0b1000_0000_0011_0010, 0x0e8, JP,      Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x7B, o, 0, 0b1000_0000_0011_0010, 0x0e8, JNP,     Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x7C, o, 0, 0b1000_0000_0011_0010, 0x0e8, JL,      Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x7D, o, 0, 0b1000_0000_0011_0010, 0x0e8, JNL,     Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x7E, o, 0, 0b1000_0000_0011_0010, 0x0e8, JLE,     Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x7F, o, 0, 0b1000_0000_0011_0010, 0x0e8, JNLE,    Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x80, o, 1, 0b0000_1000_0000_0000, 0x00c, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x81, o, 2, 0b0000_1000_0000_0000, 0x00c, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x82, o, 3, 0b0000_1000_0000_0000, 0x00c, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x83, o, 4, 0b0000_1000_0000_0000, 0x00c, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x84, o, 0, 0b0000_1000_0000_0000, 0x094, TEST,    Ot::ModRM8,                             Ot::Register8);
    inst!( 0x85, o, 0, 0b0000_1000_0000_0000, 0x094, TEST,    Ot::ModRM16or32,                        Ot::Register16or32);
    inst!( 0x86, o, 0, 0b0000_1000_0000_0000, 0x0a4, XCHG,    Ot::Register8,                          Ot::ModRM8);
    inst!( 0x87, o, 0, 0b0000_1000_0000_0000, 0x0a4, XCHG,    Ot::Register16or32,                     Ot::ModRM16or32);
    inst!( 0x88, o, 0, 0b0000_1010_0010_0010, 0x000, MOV,     Ot::ModRM8,                             Ot::Register8);
    inst!( 0x89, o, 0, 0b0000_1010_0010_0010, 0x000, MOV,     Ot::ModRM16or32,                        Ot::Register16or32);
    inst!( 0x8A, o, 0, 0b0000_1010_0010_0000, 0x000, MOV,     Ot::Register8,                          Ot::ModRM8);
    inst!( 0x8B, o, 0, 0b0000_1010_0010_0000, 0x000, MOV,     Ot::Register16or32,                     Ot::ModRM16or32);
    inst!( 0x8C, o, 0, 0b0000_0011_0010_0010, 0x0ec, MOV,     Ot::ModRM16orR32,                       Ot::SegmentRegister);
    inst!( 0x8D, o, 0, 0b0010_0000_0010_0010, 0x004, LEA,     Ot::Register16or32,                     Ot::ModRM16or32);
    inst!( 0x8E, o, 0, 0b0000_0011_0010_0000, 0x0ec, MOV,     Ot::SegmentRegister,                    Ot::ModRM16orR32);
    inst!( 0x8F, o, 0, 0b1000_0000_0010_0110, 0x040, POP,     Ot::ModRM16or32,                        Ot::NoOperand);
    inst!( 0x90, o, 0, 0b0000_0000_0011_0010, 0x084, NOP,     Ot::FixedRegister16or32(Register16::AX),Ot::FixedRegister16or32(Register16::AX));
    inst!( 0x91, o, 0, 0b0000_0000_0011_0010, 0x084, XCHG,    Ot::FixedRegister16or32(Register16::CX),Ot::FixedRegister16or32(Register16::AX));
    inst!( 0x92, o, 0, 0b0000_0000_0011_0010, 0x084, XCHG,    Ot::FixedRegister16or32(Register16::DX),Ot::FixedRegister16or32(Register16::AX));
    inst!( 0x93, o, 0, 0b0000_0000_0011_0010, 0x084, XCHG,    Ot::FixedRegister16or32(Register16::BX),Ot::FixedRegister16or32(Register16::AX));
    inst!( 0x94, o, 0, 0b0000_0000_0011_0010, 0x084, XCHG,    Ot::FixedRegister16or32(Register16::SP),Ot::FixedRegister16or32(Register16::AX));
    inst!( 0x95, o, 0, 0b0000_0000_0011_0010, 0x084, XCHG,    Ot::FixedRegister16or32(Register16::BP),Ot::FixedRegister16or32(Register16::AX));
    inst!( 0x96, o, 0, 0b0000_0000_0011_0010, 0x084, XCHG,    Ot::FixedRegister16or32(Register16::SI),Ot::FixedRegister16or32(Register16::AX));
    inst!( 0x97, o, 0, 0b0000_0000_0011_0010, 0x084, XCHG,    Ot::FixedRegister16or32(Register16::DI),Ot::FixedRegister16or32(Register16::AX));
    inst!( 0x98, o, 0, 0b0000_0000_0011_0010, 0x054, CBW,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x99, o, 0, 0b0000_0000_0011_0010, 0x058, CWD,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x9A, o, 0, 0b0000_0000_0011_0010, 0x070, CALLF,   Ot::FarPointer,                         Ot::NoOperand);
    inst!( 0x9B, o, 0, 0b0000_0000_0011_0010, 0x0f8, WAIT,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x9C, o, 0, 0b0000_0000_0011_0010, 0x030, PUSHF,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x9D, o, 0, 0b0000_0000_0011_0010, 0x03c, POPF,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x9E, o, 0, 0b0000_0000_0011_0010, 0x100, SAHF,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x9F, o, 0, 0b0000_0000_0011_0010, 0x104, LAHF,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xA0, o, 0, 0b0000_1000_1011_0010, 0x060, MOV,     Ot::FixedRegister8(Register8::AL),      Ot::Offset8);
    inst!( 0xA1, o, 0, 0b0000_1000_1011_0010, 0x060, MOV,     Ot::FixedRegister16or32(Register16::AX),Ot::Offset16or32);
    inst!( 0xA2, o, 0, 0b0000_1000_1011_0010, 0x064, MOV,     Ot::Offset8,                            Ot::FixedRegister8(Register8::AL));
    inst!( 0xA3, o, 0, 0b0000_1000_1011_0010, 0x064, MOV,     Ot::Offset16or32,                       Ot::FixedRegister16or32(Register16::AX));
    inst!( 0xA4, o, 0, 0b0000_1000_1011_0010, 0x12c, MOVSB,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xA5, o, 0, 0b0000_1000_1011_0010, 0x12c, MOVSW,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xA6, o, 0, 0b0000_1000_1011_0010, 0x120, CMPSB,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xA7, o, 0, 0b0000_1000_1011_0010, 0x120, CMPSW,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xA8, o, 0, 0b0000_1000_1011_0010, 0x09C, TEST,    Ot::FixedRegister8(Register8::AL),      Ot::Immediate8);
    inst!( 0xA9, o, 0, 0b0000_1000_1011_0010, 0x09C, TEST,    Ot::FixedRegister16or32(Register16::AX),Ot::Immediate16or32);
    inst!( 0xAA, o, 0, 0b0000_1000_1011_0010, 0x11c, STOSB,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xAB, o, 0, 0b0000_1000_1011_0010, 0x11c, STOSW,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xAC, o, 0, 0b0000_1000_1011_0010, 0x12c, LODSB,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xAD, o, 0, 0b0000_1000_1011_0010, 0x12c, LODSW,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xAE, o, 0, 0b0000_1000_1011_0010, 0x120, SCASB,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xAF, o, 0, 0b0000_1000_1011_0010, 0x120, SCASW,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xB0, o, 0, 0b0000_0000_0011_0010, 0x01c, MOV,     Ot::FixedRegister8(Register8::AL),      Ot::Immediate8);
    inst!( 0xB1, o, 0, 0b0000_0000_0011_0010, 0x01c, MOV,     Ot::FixedRegister8(Register8::CL),      Ot::Immediate8);
    inst!( 0xB2, o, 0, 0b0000_0000_0011_0010, 0x01c, MOV,     Ot::FixedRegister8(Register8::DL),      Ot::Immediate8);
    inst!( 0xB3, o, 0, 0b0000_0000_0011_0010, 0x01c, MOV,     Ot::FixedRegister8(Register8::BL),      Ot::Immediate8);
    inst!( 0xB4, o, 0, 0b0000_0000_0011_0010, 0x01c, MOV,     Ot::FixedRegister8(Register8::AH),      Ot::Immediate8);
    inst!( 0xB5, o, 0, 0b0000_0000_0011_0010, 0x01c, MOV,     Ot::FixedRegister8(Register8::CH),      Ot::Immediate8);
    inst!( 0xB6, o, 0, 0b0000_0000_0011_0010, 0x01c, MOV,     Ot::FixedRegister8(Register8::DH),      Ot::Immediate8);
    inst!( 0xB7, o, 0, 0b0000_0000_0011_0010, 0x01c, MOV,     Ot::FixedRegister8(Register8::BH),      Ot::Immediate8);
    inst!( 0xB8, o, 0, 0b0000_0000_0011_0010, 0x01c, MOV,     Ot::FixedRegister16or32(Register16::AX),Ot::Immediate16or32);
    inst!( 0xB9, o, 0, 0b0000_0000_0011_0010, 0x01c, MOV,     Ot::FixedRegister16or32(Register16::CX),Ot::Immediate16or32);
    inst!( 0xBA, o, 0, 0b0000_0000_0011_0010, 0x01c, MOV,     Ot::FixedRegister16or32(Register16::DX),Ot::Immediate16or32);
    inst!( 0xBB, o, 0, 0b0000_0000_0011_0010, 0x01c, MOV,     Ot::FixedRegister16or32(Register16::BX),Ot::Immediate16or32);
    inst!( 0xBC, o, 0, 0b0000_0000_0011_0010, 0x01c, MOV,     Ot::FixedRegister16or32(Register16::SP),Ot::Immediate16or32);
    inst!( 0xBD, o, 0, 0b0000_0000_0011_0010, 0x01c, MOV,     Ot::FixedRegister16or32(Register16::BP),Ot::Immediate16or32);
    inst!( 0xBE, o, 0, 0b0000_0000_0011_0010, 0x01c, MOV,     Ot::FixedRegister16or32(Register16::SI),Ot::Immediate16or32);
    inst!( 0xBF, o, 0, 0b0000_0000_0011_0010, 0x01c, MOV,     Ot::FixedRegister16or32(Register16::DI),Ot::Immediate16or32);
    inst!( 0xC0, o, 5, 0b0000_0000_0011_0000, 0x0cc, Group,   Ot::Immediate16,                        Ot::NoOperand);
    inst!( 0xC1, o, 6, 0b0000_0000_0011_0000, 0x0bc, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xC2, o, 0, 0b0000_0000_0011_0000, 0x0cc, RET,     Ot::Immediate16,                        Ot::NoOperand);
    inst!( 0xC3, o, 0, 0b0000_0000_0011_0000, 0x0bc, RET,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xC4, o, 0, 0b0010_0000_0010_0000, 0x0f0, LES,     Ot::Register16or32,                     Ot::ModRM16);
    inst!( 0xC5, o, 0, 0b0010_0000_0010_0000, 0x0f4, LDS,     Ot::Register16or32,                     Ot::ModRM16);
    inst!( 0xC6, o, 0, 0b1000_1000_0010_0110, 0x014, MOV,     Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0xC7, o, 0, 0b1000_1000_0010_0110, 0x014, MOV,     Ot::ModRM16or32,                        Ot::Immediate16or32);
    inst!( 0xC8, o, 0, 0b0000_0000_0011_0000, 0x0cc, ENTER,   Ot::Immediate16,                        Ot::Immediate8);
    inst!( 0xC9, o, 0, 0b0000_0000_0011_0000, 0x0c0, LEAVE,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xCA, o, 0, 0b0000_0000_0011_0000, 0x0cc, RETF,    Ot::Immediate16,                        Ot::NoOperand);
    inst!( 0xCB, o, 0, 0b0000_0000_0011_0000, 0x0c0, RETF,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xCC, o, 0, 0b0000_0000_0011_0000, 0x1b0, INT3,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xCD, o, 0, 0b0000_0000_0011_0000, 0x1a8, INT,     Ot::Immediate8,                         Ot::NoOperand);
    inst!( 0xCE, o, 0, 0b0000_0000_0011_0000, 0x1ac, INTO,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xCF, o, 0, 0b0000_0000_0011_0000, 0x0c8, IRET,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xD0, o, 7, 0b0000_1000_0000_0000, 0x088, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xD1, o, 8, 0b0000_1000_0000_0000, 0x088, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xD2, o, 9, 0b0000_1000_0000_0000, 0x08c, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xD3, o,10, 0b0000_1000_0000_0000, 0x08c, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xD4, o, 0, 0b0001_0000_0011_0000, 0x174, AAM,     Ot::Immediate8,                         Ot::NoOperand);
    inst!( 0xD5, o, 0, 0b0001_0000_0011_0000, 0x170, AAD,     Ot::Immediate8,                         Ot::NoOperand);
    inst!( 0xD6, o, 0, 0b0001_0000_0011_0000, 0x0a0, SALC,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xD7, o, 0, 0b0001_0000_0011_0000, 0x10c, XLAT,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xD8, o, 0, 0b0000_0000_0010_0000, 0x108, ESC,     Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xD9, o, 0, 0b0000_0000_0010_0000, 0x108, ESC,     Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xDA, o, 0, 0b0000_0000_0010_0000, 0x108, ESC,     Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xDB, o, 0, 0b0000_0000_0010_0000, 0x108, ESC,     Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xDC, o, 0, 0b0000_0000_0010_0000, 0x108, ESC,     Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xDD, o, 0, 0b0000_0000_0010_0000, 0x108, ESC,     Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xDE, o, 0, 0b0000_0000_0010_0000, 0x108, ESC,     Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xDF, o, 0, 0b0000_0000_0010_0000, 0x108, ESC,     Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xE0, o, 0, 0b0000_0000_0011_0000, 0x138, LOOPNE,  Ot::Relative8,                          Ot::NoOperand);
    inst!( 0xE1, o, 0, 0b0000_0000_0011_0000, 0x138, LOOPE,   Ot::Relative8,                          Ot::NoOperand);
    inst!( 0xE2, o, 0, 0b0000_0000_0011_0000, 0x140, LOOP,    Ot::Relative8,                          Ot::NoOperand);
    inst!( 0xE3, o, 0, 0b0000_0000_0011_0000, 0x134, JCXZ,    Ot::Relative8,                          Ot::NoOperand);
    inst!( 0xE4, o, 0, 0b0000_1000_1011_0011, 0x0ac, IN,      Ot::FixedRegister8(Register8::AL),      Ot::Immediate8);
    inst!( 0xE5, o, 0, 0b0000_1000_1011_0011, 0x0ac, IN,      Ot::FixedRegister16or32(Register16::AX),Ot::Immediate8);
    inst!( 0xE6, o, 0, 0b0000_1000_1011_0011, 0x0b0, OUT,     Ot::Immediate8,                         Ot::FixedRegister8(Register8::AL));
    inst!( 0xE7, o, 0, 0b0000_1000_1011_0011, 0x0b0, OUT,     Ot::Immediate8,                         Ot::FixedRegister16or32(Register16::AX));
    inst!( 0xE8, o, 0, 0b0000_0000_0011_0000, 0x07c, CALL,    Ot::Relative16,                         Ot::NoOperand);
    inst!( 0xE9, o, 0, 0b0000_0000_0011_0000, 0x0d0, JMP,     Ot::Relative16,                         Ot::NoOperand);
    inst!( 0xEA, o, 0, 0b0000_0000_0011_0000, 0x0e0, JMPF,    Ot::FarPointer,                         Ot::NoOperand);
    inst!( 0xEB, o, 0, 0b1000_0000_0011_0000, 0x0d0, JMP,     Ot::Relative8,                          Ot::NoOperand);
    inst!( 0xEC, o, 0, 0b0000_1000_1011_0011, 0x0b4, IN,      Ot::FixedRegister8(Register8::AL),      Ot::FixedRegister16(Register16::DX));
    inst!( 0xED, o, 0, 0b0000_1000_1011_0011, 0x0b4, IN,      Ot::FixedRegister16or32(Register16::AX),Ot::FixedRegister16(Register16::DX));
    inst!( 0xEE, o, 0, 0b0000_1000_1011_0011, 0x0b8, OUT,     Ot::FixedRegister16(Register16::DX),    Ot::FixedRegister8(Register8::AL));
    inst!( 0xEF, o, 0, 0b0000_1000_1011_0011, 0x0b8, OUT,     Ot::FixedRegister16(Register16::DX),    Ot::FixedRegister16or32(Register16::AX));
    inst!( 0xF0, o, 0, 0b0000_0100_0011_1010, 0x1FF, LOCK,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xF1, o, 0, 0b0000_0100_0011_1010, 0x1FF, INT1,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xF2, o, 0, 0b0000_0100_0011_1010, 0x1FF, Prefix,  Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xF3, o, 0, 0b0000_0100_0011_1010, 0x1FF, Prefix,  Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xF4, o, 0, 0b0000_0100_0011_0010, 0x1FF, HLT,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xF5, o, 0, 0b0000_0100_0011_0010, 0x1FF, CMC,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xF6, o,11, 0b0000_1000_0010_0100, 0x098, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xF7, o,12, 0b0000_1000_0010_0100, 0x160, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xF8, o, 0, 0b0000_0100_0111_0010, 0x1FF, CLC,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xF9, o, 0, 0b0000_0100_0111_0010, 0x1FF, STC,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xFA, o, 0, 0b0000_0100_0111_0010, 0x1FF, CLI,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xFB, o, 0, 0b0000_0100_0111_0010, 0x1FF, STI,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xFC, o, 0, 0b0000_0100_0111_0010, 0x1FF, CLD,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xFD, o, 0, 0b0000_0100_0111_0010, 0x1FF, STD,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xFE, o,13, 0b0000_1000_0010_0000, 0x020, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xFF, o,14, 0b0000_1000_0010_0000, 0x026, Group,   Ot::NoOperand,                          Ot::NoOperand);
    // Group
    inst!( 0x80, o, 1, 0b1000_1000_0000_0000, 0x00c, ADD  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x80, o, 1, 0b1000_1000_0000_0000, 0x00c, OR   ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x80, o, 1, 0b1000_1000_0000_0000, 0x00c, ADC  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x80, o, 1, 0b1000_1000_0000_0000, 0x00c, SBB  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x80, o, 1, 0b1000_1000_0000_0000, 0x00c, AND  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x80, o, 1, 0b1000_1000_0000_0000, 0x00c, SUB  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x80, o, 1, 0b1000_1000_0000_0000, 0x00c, XOR  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x80, o, 1, 0b1000_1000_0000_0000, 0x00c, CMP  ,   Ot::ModRM8,                             Ot::Immediate8);
    // Group
    inst!( 0x81, o, 1, 0b1000_1000_0000_0000, 0x00c, ADD  ,   Ot::ModRM16or32,                        Ot::Immediate16or32);
    inst!( 0x81, o, 1, 0b1000_1000_0000_0000, 0x00c, OR   ,   Ot::ModRM16or32,                        Ot::Immediate16or32);
    inst!( 0x81, o, 1, 0b1000_1000_0000_0000, 0x00c, ADC  ,   Ot::ModRM16or32,                        Ot::Immediate16or32);
    inst!( 0x81, o, 1, 0b1000_1000_0000_0000, 0x00c, SBB  ,   Ot::ModRM16or32,                        Ot::Immediate16or32);
    inst!( 0x81, o, 1, 0b1000_1000_0000_0000, 0x00c, AND  ,   Ot::ModRM16or32,                        Ot::Immediate16or32);
    inst!( 0x81, o, 1, 0b1000_1000_0000_0000, 0x00c, SUB  ,   Ot::ModRM16or32,                        Ot::Immediate16or32);
    inst!( 0x81, o, 1, 0b1000_1000_0000_0000, 0x00c, XOR  ,   Ot::ModRM16or32,                        Ot::Immediate16or32);
    inst!( 0x81, o, 1, 0b1000_1000_0000_0000, 0x00c, CMP  ,   Ot::ModRM16or32,                        Ot::Immediate16or32);
    // Group,
    inst!( 0x82, o, 1, 0b1000_1000_0000_0000, 0x00c, ADD  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x82, o, 1, 0b1000_1000_0000_0000, 0x00c, OR   ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x82, o, 1, 0b1000_1000_0000_0000, 0x00c, ADC  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x82, o, 1, 0b1000_1000_0000_0000, 0x00c, SBB  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x82, o, 1, 0b1000_1000_0000_0000, 0x00c, AND  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x82, o, 1, 0b1000_1000_0000_0000, 0x00c, SUB  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x82, o, 1, 0b1000_1000_0000_0000, 0x00c, XOR  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x82, o, 1, 0b1000_1000_0000_0000, 0x00c, CMP  ,   Ot::ModRM8,                             Ot::Immediate8);
    // Group
    inst!( 0x83, o, 1, 0b1000_1000_0000_0000, 0x00c, ADD  ,   Ot::ModRM16or32,                        Ot::Immediate8SignExtended16);
    inst!( 0x83, o, 1, 0b1000_1000_0000_0000, 0x00c, OR   ,   Ot::ModRM16or32,                        Ot::Immediate8SignExtended16);
    inst!( 0x83, o, 1, 0b1000_1000_0000_0000, 0x00c, ADC  ,   Ot::ModRM16or32,                        Ot::Immediate8SignExtended16);
    inst!( 0x83, o, 1, 0b1000_1000_0000_0000, 0x00c, SBB  ,   Ot::ModRM16or32,                        Ot::Immediate8SignExtended16);
    inst!( 0x83, o, 1, 0b1000_1000_0000_0000, 0x00c, AND  ,   Ot::ModRM16or32,                        Ot::Immediate8SignExtended16);
    inst!( 0x83, o, 1, 0b1000_1000_0000_0000, 0x00c, SUB  ,   Ot::ModRM16or32,                        Ot::Immediate8SignExtended16);
    inst!( 0x83, o, 1, 0b1000_1000_0000_0000, 0x00c, XOR  ,   Ot::ModRM16or32,                        Ot::Immediate8SignExtended16);
    inst!( 0x83, o, 1, 0b1000_1000_0000_0000, 0x00c, CMP  ,   Ot::ModRM16or32,                        Ot::Immediate8SignExtended16);
    // Group
    inst!( 0xC0, o, 2, 0b1000_1000_0000_0000, 0x088, ROL  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0xC0, o, 2, 0b1000_1000_0000_0000, 0x088, ROR  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0xC0, o, 2, 0b1000_1000_0000_0000, 0x088, RCL  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0xC0, o, 2, 0b1000_1000_0000_0000, 0x088, RCR  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0xC0, o, 2, 0b1000_1000_0000_0000, 0x088, SHL  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0xC0, o, 2, 0b1000_1000_0000_0000, 0x088, SHR  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0xC0, o, 2, 0b1000_1000_0000_0000, 0x088, SAL  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0xC0, o, 2, 0b1000_1000_0000_0000, 0x088, SAR  ,   Ot::ModRM8,                             Ot::Immediate8);
    // Group
    inst!( 0xC1, o, 2, 0b1000_1000_0000_0000, 0x088, ROL  ,   Ot::ModRM16or32,                        Ot::Immediate8);
    inst!( 0xC1, o, 2, 0b1000_1000_0000_0000, 0x088, ROR  ,   Ot::ModRM16or32,                        Ot::Immediate8);
    inst!( 0xC1, o, 2, 0b1000_1000_0000_0000, 0x088, RCL  ,   Ot::ModRM16or32,                        Ot::Immediate8);
    inst!( 0xC1, o, 2, 0b1000_1000_0000_0000, 0x088, RCR  ,   Ot::ModRM16or32,                        Ot::Immediate8);
    inst!( 0xC1, o, 2, 0b1000_1000_0000_0000, 0x088, SHL  ,   Ot::ModRM16or32,                        Ot::Immediate8);
    inst!( 0xC1, o, 2, 0b1000_1000_0000_0000, 0x088, SHR  ,   Ot::ModRM16or32,                        Ot::Immediate8);
    inst!( 0xC1, o, 2, 0b1000_1000_0000_0000, 0x088, SAL  ,   Ot::ModRM16or32,                        Ot::Immediate8);
    inst!( 0xC1, o, 2, 0b1000_1000_0000_0000, 0x088, SAR  ,   Ot::ModRM16or32,                        Ot::Immediate8);
    // Group
    inst!( 0xD0, o, 3, 0b1000_1000_0000_0000, 0x088, ROL  ,   Ot::ModRM8,                             Ot::FixedImmediate8(1));
    inst!( 0xD0, o, 3, 0b1000_1000_0000_0000, 0x088, ROR  ,   Ot::ModRM8,                             Ot::FixedImmediate8(1));
    inst!( 0xD0, o, 3, 0b1000_1000_0000_0000, 0x088, RCL  ,   Ot::ModRM8,                             Ot::FixedImmediate8(1));
    inst!( 0xD0, o, 3, 0b1000_1000_0000_0000, 0x088, RCR  ,   Ot::ModRM8,                             Ot::FixedImmediate8(1));
    inst!( 0xD0, o, 3, 0b1000_1000_0000_0000, 0x088, SHL  ,   Ot::ModRM8,                             Ot::FixedImmediate8(1));
    inst!( 0xD0, o, 3, 0b1000_1000_0000_0000, 0x088, SHR  ,   Ot::ModRM8,                             Ot::FixedImmediate8(1));
    inst!( 0xD0, o, 3, 0b1000_1000_0000_0000, 0x088, SAL  ,   Ot::ModRM8,                             Ot::FixedImmediate8(1));
    inst!( 0xD0, o, 3, 0b1000_1000_0000_0000, 0x088, SAR  ,   Ot::ModRM8,                             Ot::FixedImmediate8(1));
    // Group
    inst!( 0xD1, o, 3, 0b1000_1000_0000_0000, 0x088, ROL  ,   Ot::ModRM16or32,                        Ot::FixedImmediate8(1));
    inst!( 0xD1, o, 3, 0b1000_1000_0000_0000, 0x088, ROR  ,   Ot::ModRM16or32,                        Ot::FixedImmediate8(1));
    inst!( 0xD1, o, 3, 0b1000_1000_0000_0000, 0x088, RCL  ,   Ot::ModRM16or32,                        Ot::FixedImmediate8(1));
    inst!( 0xD1, o, 3, 0b1000_1000_0000_0000, 0x088, RCR  ,   Ot::ModRM16or32,                        Ot::FixedImmediate8(1));
    inst!( 0xD1, o, 3, 0b1000_1000_0000_0000, 0x088, SHL  ,   Ot::ModRM16or32,                        Ot::FixedImmediate8(1));
    inst!( 0xD1, o, 3, 0b1000_1000_0000_0000, 0x088, SHR  ,   Ot::ModRM16or32,                        Ot::FixedImmediate8(1));
    inst!( 0xD1, o, 3, 0b1000_1000_0000_0000, 0x088, SAL  ,   Ot::ModRM16or32,                        Ot::FixedImmediate8(1));
    inst!( 0xD1, o, 3, 0b1000_1000_0000_0000, 0x088, SAR  ,   Ot::ModRM16or32,                        Ot::FixedImmediate8(1));
    // Group
    inst!( 0xD2, o, 4, 0b1000_1000_0000_0000, 0x08c, ROL   ,  Ot::ModRM8,                             Ot::FixedRegister8(Register8::CL));
    inst!( 0xD2, o, 4, 0b1000_1000_0000_0000, 0x08c, ROR   ,  Ot::ModRM8,                             Ot::FixedRegister8(Register8::CL));
    inst!( 0xD2, o, 4, 0b1000_1000_0000_0000, 0x08c, RCL   ,  Ot::ModRM8,                             Ot::FixedRegister8(Register8::CL));
    inst!( 0xD2, o, 4, 0b1000_1000_0000_0000, 0x08c, RCR   ,  Ot::ModRM8,                             Ot::FixedRegister8(Register8::CL));
    inst!( 0xD2, o, 4, 0b1000_1000_0000_0000, 0x08c, SHL   ,  Ot::ModRM8,                             Ot::FixedRegister8(Register8::CL));
    inst!( 0xD2, o, 4, 0b1000_1000_0000_0000, 0x08c, SHR   ,  Ot::ModRM8,                             Ot::FixedRegister8(Register8::CL));
    inst!( 0xD2, o, 4, 0b1000_1000_0000_0000, 0x08c, SAL   ,  Ot::ModRM8,                             Ot::FixedRegister8(Register8::CL));
    inst!( 0xD2, o, 4, 0b1000_1000_0000_0000, 0x08c, SAR   ,  Ot::ModRM8,                             Ot::FixedRegister8(Register8::CL));
    // Group
    inst!( 0xD3, o, 4, 0b1000_1000_0000_0000, 0x08c, ROL   ,  Ot::ModRM16or32,                        Ot::FixedRegister8(Register8::CL));
    inst!( 0xD3, o, 4, 0b1000_1000_0000_0000, 0x08c, ROR   ,  Ot::ModRM16or32,                        Ot::FixedRegister8(Register8::CL));
    inst!( 0xD3, o, 4, 0b1000_1000_0000_0000, 0x08c, RCL   ,  Ot::ModRM16or32,                        Ot::FixedRegister8(Register8::CL));
    inst!( 0xD3, o, 4, 0b1000_1000_0000_0000, 0x08c, RCR   ,  Ot::ModRM16or32,                        Ot::FixedRegister8(Register8::CL));
    inst!( 0xD3, o, 4, 0b1000_1000_0000_0000, 0x08c, SHL   ,  Ot::ModRM16or32,                        Ot::FixedRegister8(Register8::CL));
    inst!( 0xD3, o, 4, 0b1000_1000_0000_0000, 0x08c, SHR   ,  Ot::ModRM16or32,                        Ot::FixedRegister8(Register8::CL));
    inst!( 0xD3, o, 4, 0b1000_1000_0000_0000, 0x08c, SAL   ,  Ot::ModRM16or32,                        Ot::FixedRegister8(Register8::CL));
    inst!( 0xD3, o, 4, 0b1000_1000_0000_0000, 0x08c, SAR   ,  Ot::ModRM16or32,                        Ot::FixedRegister8(Register8::CL));
    // Group
    inst!( 0xF6, o, 5, 0b1000_1000_0010_0000, 0x098, TEST  ,  Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0xF6, o, 5, 0b1000_1000_0010_0000, 0x098, TEST  ,  Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0xF6, o, 5, 0b1000_1000_0010_0000, 0x098, NOT   ,  Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xF6, o, 5, 0b1000_1000_0010_0000, 0x098, NEG   ,  Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xF6, o, 5, 0b1000_1000_0010_0000, 0x098, MUL   ,  Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xF6, o, 5, 0b1000_1000_0010_0000, 0x098, IMUL  ,  Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xF6, o, 5, 0b1000_1000_0010_0000, 0x098, DIV   ,  Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xF6, o, 5, 0b1000_1000_0010_0000, 0x098, IDIV  ,  Ot::ModRM8,                             Ot::NoOperand);
    // Group
    inst!( 0xF7, o, 5, 0b1000_1000_0010_0000, 0x160, TEST  ,  Ot::ModRM16or32,                        Ot::Immediate16or32);
    inst!( 0xF7, o, 5, 0b1000_1000_0010_0000, 0x160, TEST  ,  Ot::ModRM16or32,                        Ot::Immediate16or32);
    inst!( 0xF7, o, 5, 0b1000_1000_0010_0000, 0x160, NOT   ,  Ot::ModRM16or32,                        Ot::NoOperand);
    inst!( 0xF7, o, 5, 0b1000_1000_0010_0000, 0x160, NEG   ,  Ot::ModRM16or32,                        Ot::NoOperand);
    inst!( 0xF7, o, 5, 0b1000_1000_0010_0000, 0x160, MUL   ,  Ot::ModRM16or32,                        Ot::NoOperand);
    inst!( 0xF7, o, 5, 0b1000_1000_0010_0000, 0x160, IMUL  ,  Ot::ModRM16or32,                        Ot::NoOperand);
    inst!( 0xF7, o, 5, 0b1000_1000_0010_0000, 0x160, DIV   ,  Ot::ModRM16or32,                        Ot::NoOperand);
    inst!( 0xF7, o, 5, 0b1000_1000_0010_0000, 0x160, IDIV  ,  Ot::ModRM16or32,                        Ot::NoOperand);
    // Group
    inst!( 0xFE, o, 6, 0b1000_1000_0010_0000, 0x020, INC   ,  Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xFE, o, 6, 0b1000_1000_0010_0000, 0x020, DEC   ,  Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xFE, o, 6, 0b0000_1000_0010_0000, 0x020, Invalid, Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xFE, o, 6, 0b0000_1000_0010_0000, 0x020, Invalid, Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xFE, o, 6, 0b0000_1000_0010_0000, 0x020, Invalid, Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xFE, o, 6, 0b0000_1000_0010_0000, 0x020, Invalid, Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xFE, o, 6, 0b0000_1000_0010_0000, 0x020, Invalid, Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xFE, o, 6, 0b0000_1000_0010_0000, 0x020, Invalid, Ot::ModRM8,                             Ot::NoOperand);
    // Group
    inst!( 0xFF, o, 6, 0b1000_1000_0010_0000, 0x026, INC   ,  Ot::ModRM16or32,                        Ot::NoOperand);
    inst!( 0xFF, o, 6, 0b1000_1000_0010_0000, 0x026, DEC   ,  Ot::ModRM16or32,                        Ot::NoOperand);
    inst!( 0xFF, o, 6, 0b1000_1000_0010_0000, 0x026, CALL  ,  Ot::ModRM16or32,                        Ot::NoOperand);
    inst!( 0xFF, o, 6, 0b1010_1000_0010_0000, 0x026, CALLF ,  Ot::ModRM16or32,                        Ot::NoOperand);
    inst!( 0xFF, o, 6, 0b1000_1000_0010_0000, 0x026, JMP   ,  Ot::ModRM16or32,                        Ot::NoOperand);
    inst!( 0xFF, o, 6, 0b1010_1000_0010_0000, 0x026, JMPF  ,  Ot::ModRM16or32,                        Ot::NoOperand);
    inst!( 0xFF, o, 6, 0b1000_1000_0010_0000, 0x026, PUSH  ,  Ot::ModRM16or32,                        Ot::NoOperand);
    inst!( 0xFF, o, 6, 0b1000_1000_0010_0000, 0x026, Invalid, Ot::ModRM16or32,                        Ot::NoOperand);
    // END OF REGULAR INTEL OPCODES (0-367)
    // 0F extended opcodes follow.
    inst!( 0x00, o, 1, 0b0000_1000_0001_0000, 0x000, Group ,  Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x01, o, 2, 0b0000_1000_0000_0000, 0x000, Group ,  Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x02, o, 0, 0b0000_1000_0000_0000, 0x000, LAR,     Ot::Register16,                         Ot::ModRM16);
    inst!( 0x03, o, 0, 0b0000_1000_0000_0000, 0x000, LSL,     Ot::Register16,                         Ot::ModRM16);
    inst_skip!(o, 2); // Skip 0x04 & 0x05
    inst!( 0x06, o, 0, 0b0000_1000_0000_0000, 0x000, CLTS,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x07, o, 0, 0b0000_1000_0000_0000, 0x000, LOADALL, Ot::NoOperand,                          Ot::NoOperand);
    inst_skip!(o, 24); // Skip 0x08-0x19
    inst!( 0x20, o, 0, 0b0100_1000_0000_0000, 0x000, MOV,     Ot::ModRM32,                            Ot::ControlRegister);
    inst!( 0x21, o, 0, 0b0100_1000_0000_0000, 0x000, MOV,     Ot::ModRM32,                            Ot::DebugRegister);
    inst!( 0x22, o, 0, 0b0100_1000_0000_0000, 0x000, MOV,     Ot::ControlRegister,                    Ot::ModRM32);
    inst!( 0x23, o, 0, 0b0100_1000_0000_0000, 0x000, MOV,     Ot::DebugRegister,                      Ot::ModRM32);
    inst_skip!(o, 92); // Skip 0x24-0x7F
    inst!( 0x80, o, 0, 0b1000_0000_0001_0000, 0x000, JO,      Ot::Relative16or32,                     Ot::NoOperand);
    inst!( 0x81, o, 0, 0b1000_0000_0001_0000, 0x000, JNO,     Ot::Relative16or32,                     Ot::NoOperand);
    inst!( 0x82, o, 0, 0b1000_0000_0001_0000, 0x000, JB,      Ot::Relative16or32,                     Ot::NoOperand);
    inst!( 0x83, o, 0, 0b1000_0000_0001_0000, 0x000, JNB,     Ot::Relative16or32,                     Ot::NoOperand);
    inst!( 0x84, o, 0, 0b1000_0000_0001_0000, 0x000, JZ,      Ot::Relative16or32,                     Ot::NoOperand);
    inst!( 0x85, o, 0, 0b1000_0000_0001_0000, 0x000, JNZ,     Ot::Relative16or32,                     Ot::NoOperand);
    inst!( 0x86, o, 0, 0b1000_0000_0001_0000, 0x000, JBE,     Ot::Relative16or32,                     Ot::NoOperand);
    inst!( 0x87, o, 0, 0b1000_0000_0001_0000, 0x000, JNBE,    Ot::Relative16or32,                     Ot::NoOperand);
    inst!( 0x88, o, 0, 0b1000_0000_0001_0000, 0x000, JS,      Ot::Relative16or32,                     Ot::NoOperand);
    inst!( 0x89, o, 0, 0b1000_0000_0001_0000, 0x000, JNS,     Ot::Relative16or32,                     Ot::NoOperand);
    inst!( 0x8A, o, 0, 0b1000_0000_0001_0000, 0x000, JP,      Ot::Relative16or32,                     Ot::NoOperand);
    inst!( 0x8B, o, 0, 0b1000_0000_0001_0000, 0x000, JNP,     Ot::Relative16or32,                     Ot::NoOperand);
    inst!( 0x8C, o, 0, 0b1000_0000_0001_0000, 0x000, JL,      Ot::Relative16or32,                     Ot::NoOperand);
    inst!( 0x8D, o, 0, 0b1000_0000_0001_0000, 0x000, JNL,     Ot::Relative16or32,                     Ot::NoOperand);
    inst!( 0x8E, o, 0, 0b1000_0000_0001_0000, 0x000, JLE,     Ot::Relative16or32,                     Ot::NoOperand);
    inst!( 0x8F, o, 0, 0b1000_0000_0001_0000, 0x000, JNLE,    Ot::Relative16or32,                     Ot::NoOperand);
    inst!( 0x90, o, 0, 0b0000_0000_0000_0000, 0x000, SETO,    Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0x91, o, 0, 0b0000_0000_0000_0000, 0x000, SETNO,   Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0x92, o, 0, 0b0000_0000_0000_0000, 0x000, SETB,    Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0x93, o, 0, 0b0000_0000_0000_0000, 0x000, SETNB,   Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0x94, o, 0, 0b0000_0000_0000_0000, 0x000, SETZ,    Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0x95, o, 0, 0b0000_0000_0000_0000, 0x000, SETNZ,   Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0x96, o, 0, 0b0000_0000_0000_0000, 0x000, SETBE,   Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0x97, o, 0, 0b0000_0000_0000_0000, 0x000, SETNBE,  Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0x98, o, 0, 0b0000_0000_0000_0000, 0x000, SETS,    Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0x99, o, 0, 0b0000_0000_0000_0000, 0x000, SETNS,   Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0x9A, o, 0, 0b0000_0000_0000_0000, 0x000, SETP,    Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0x9B, o, 0, 0b0000_0000_0000_0000, 0x000, SETNP,   Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0x9C, o, 0, 0b0000_0000_0000_0000, 0x000, SETL,    Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0x9D, o, 0, 0b0000_0000_0000_0000, 0x000, SETNL,   Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0x9E, o, 0, 0b0000_0000_0000_0000, 0x000, SETLE,   Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0x9F, o, 0, 0b0000_0000_0000_0000, 0x000, SETNLE,  Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xA0, o, 0, 0b0000_0000_0001_0000, 0x000, PUSH,    Ot::FixedRegister16or32(Register16::FS),Ot::NoOperand);
    inst!( 0xA1, o, 0, 0b0000_0000_0001_0000, 0x000, POP,     Ot::FixedRegister16or32(Register16::FS),Ot::NoOperand);
    inst_skip!(o, 1);
    inst!( 0xA3, o, 0, 0b0000_0000_0000_0000, 0x000, BT,      Ot::ModRM16or32,                        Ot::Register16or32);
    inst!( 0xA4, o, 0, 0b0000_0000_0000_0000, 0x000, SHLD,    Ot::ModRM16or32,                        Ot::Register16or32, Ot::Immediate8);
    inst!( 0xA5, o, 0, 0b0000_0000_0000_0000, 0x000, SHLD,    Ot::ModRM16or32,                        Ot::Register16or32, Ot::FixedRegister8(Register8::CL));
    inst_skip!(o, 2);
    inst!( 0xA8, o, 0, 0b0000_0000_0001_0000, 0x000, PUSH,    Ot::FixedRegister16or32(Register16::GS),Ot::NoOperand);
    inst!( 0xA9, o, 0, 0b0000_0000_0001_0000, 0x000, POP,     Ot::FixedRegister16or32(Register16::GS),Ot::NoOperand);
    inst!( 0xAA, o, 0, 0b0000_0000_0001_0000, 0x000, RSM,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xAB, o, 0, 0b0000_0000_0000_0000, 0x000, BTS,     Ot::ModRM16or32,                        Ot::Register16or32);
    inst!( 0xAC, o, 0, 0b0000_0000_0000_0000, 0x000, SHRD,    Ot::ModRM16or32,                        Ot::Register16or32, Ot::Immediate8);
    inst!( 0xAD, o, 0, 0b0000_0000_0000_0000, 0x000, SHRD,    Ot::ModRM16or32,                        Ot::Register16or32, Ot::FixedRegister8(Register8::CL));
    inst_skip!(o, 1);
    inst!( 0xAF, o, 0, 0b0000_0000_0000_0000, 0x000, IMUL,    Ot::Register16or32,                     Ot::ModRM16or32);
    inst_skip!(o, 2);
    inst!( 0xB2, o, 0, 0b0010_0000_0000_0000, 0x000, LSS,     Ot::Register16or32,                     Ot::ModRM16or32);
    inst!( 0xB3, o, 0, 0b0000_0000_0000_0000, 0x000, BTR,     Ot::ModRM16or32,                        Ot::Register16or32);
    inst!( 0xB4, o, 0, 0b0010_0000_0000_0000, 0x000, LFS,     Ot::Register16or32,                     Ot::ModRM16or32);
    inst!( 0xB5, o, 0, 0b0010_0000_0000_0000, 0x000, LGS,     Ot::Register16or32,                     Ot::ModRM16or32);
    inst!( 0xB6, o, 0, 0b1000_0000_0000_0000, 0x000, MOVZX,   Ot::Register16or32,                     Ot::ModRM8);
    inst!( 0xB7, o, 0, 0b1000_0000_0000_0000, 0x000, MOVZX,   Ot::Register16or32,                     Ot::ModRM16);
    inst_skip!(o, 2);
    inst!( 0xBA, o, 3, 0b0000_0000_0000_0000, 0x000, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xBB, o, 0, 0b0000_0000_0000_0000, 0x000, BTC,     Ot::ModRM16or32,                        Ot::Register16or32);
    inst!( 0xBC, o, 0, 0b0000_0000_0000_0000, 0x000, BSF,     Ot::Register16or32,                     Ot::ModRM16or32);
    inst!( 0xBD, o, 0, 0b0000_0000_0000_0000, 0x000, BSR,     Ot::Register16or32,                     Ot::ModRM16or32);
    inst!( 0xBE, o, 0, 0b1000_0000_0000_0000, 0x000, MOVSX,   Ot::Register16or32,                     Ot::ModRM8);
    inst!( 0xBF, o, 0, 0b1000_0000_0000_0000, 0x000, MOVSX,   Ot::Register16or32,                     Ot::ModRM16);
    inst_skip!(o, 63); // Skip 0xC0-0xFF
    inst!( 0xFF, o, 0, 0b0000_0000_0000_0000, 0x000, Invalid, Ot::NoOperand,                          Ot::NoOperand);
    // Group 6
    inst!( 0x00, o, 2, 0b0000_0000_0000_0000, 0x000, SLDT,    Ot::ModRM16or32,                        Ot::NoOperand);
    inst!( 0x00, o, 2, 0b0000_0000_0000_0000, 0x000, STR,     Ot::ModRM16or32,                        Ot::NoOperand);
    inst!( 0x00, o, 2, 0b0000_0000_0000_0000, 0x000, LLDT,    Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0x00, o, 2, 0b0000_0000_0000_0000, 0x000, LTR,     Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0x00, o, 2, 0b0000_0000_0000_0000, 0x000, VERR,    Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0x00, o, 2, 0b0000_0000_0000_0000, 0x000, VERW,    Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0x00, o, 2, 0b0000_0000_0000_0000, 0x000, Invalid, Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x00, o, 2, 0b0000_0000_0000_0000, 0x000, Invalid, Ot::NoOperand,                          Ot::NoOperand);
    // Group 7
    inst!( 0x01, o, 2, 0b0010_0000_0000_0000, 0x000, SGDT,    Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0x01, o, 2, 0b0010_0000_0000_0000, 0x000, SIDT,    Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0x01, o, 2, 0b0010_0000_0000_0000, 0x000, LGDT,    Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0x01, o, 2, 0b0010_0000_0000_0000, 0x000, LIDT,    Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0x01, o, 2, 0b0000_0000_0000_0000, 0x000, SMSW,    Ot::ModRM16or32,                        Ot::NoOperand);
    inst!( 0x01, o, 2, 0b0000_0000_0000_0000, 0x000, Invalid, Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x01, o, 2, 0b0000_0000_0000_0000, 0x000, LMSW,    Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0x01, o, 2, 0b0000_0000_0000_0000, 0x000, Invalid, Ot::NoOperand,                          Ot::NoOperand);
    // Group 8
    inst!( 0xBA, o, 3, 0b0000_0000_0000_0000, 0x000, Invalid, Ot::ModRM16or32,                        Ot::NoOperand);
    inst!( 0xBA, o, 3, 0b0000_0000_0000_0000, 0x000, Invalid, Ot::ModRM16or32,                        Ot::NoOperand);
    inst!( 0xBA, o, 3, 0b0000_0000_0000_0000, 0x000, Invalid, Ot::ModRM16or32,                        Ot::NoOperand);
    inst!( 0xBA, o, 3, 0b0000_0000_0000_0000, 0x000, Invalid, Ot::ModRM16or32,                        Ot::NoOperand);
    inst!( 0xBA, o, 3, 0b1000_0000_0000_0000, 0x000, BT,      Ot::ModRM16or32,                        Ot::Immediate8);
    inst!( 0xBA, o, 3, 0b1000_0000_0000_0000, 0x000, BTS,     Ot::ModRM16or32,                        Ot::Immediate8);
    inst!( 0xBA, o, 3, 0b1000_0000_0000_0000, 0x000, BTR,     Ot::ModRM16or32,                        Ot::Immediate8);
    inst!( 0xBA, o, 3, 0b1000_0000_0000_0000, 0x000, BTC,     Ot::ModRM16or32,                        Ot::Immediate8);

    assert!(o.idx == o.table.len());
    o.table
};

impl Intel80386 {
    pub const PREFIX_LIMIT: usize = 15;

    #[rustfmt::skip]
    pub fn decode(bytes: &mut impl ByteReader, segment_size: SegmentSize) -> Result<Instruction, DecodeError> {

        let mut instruction = Instruction::default();

        // Start out valid, we'll set to false if we encounter an issue
        instruction.is_valid = true;

        // Read an initial byte as our opcode or first prefix
        let mut opcode = match bytes.read_u8() {
            Ok(byte) => {
                instruction.instruction_bytes.push(byte);
                byte
            },
            Err(_e) => return Ok(instruction)
        };

        let mut op_prefixes: u32 = 0;
        let mut op_segment_override = None;
        let mut decode_idx_base= 0;

        let mut op_prefix_ct = 0;

        let (mut operand_size, mut address_size) = match segment_size {
            SegmentSize::Segment16 => (OperandSize::Operand16, AddressSize::Address16),
            SegmentSize::Segment32 => (OperandSize::Operand32, AddressSize::Address32),
        };

        // Read in opcode prefixes until exhausted
        loop {
            // Set flags for all prefixes encountered...
            op_prefixes |= match opcode {
                0x0F => {
                    op_prefixes |= PrefixFlags::EXTENDED_0F;
                    // 0F prefixed-instructions exist in table after all regular Intel instructions
                    // Nothing can follow an 0F prefix; so start instruction now. Fetching the
                    // extended opcode counts as a Subsequent write based on queue status flags.

                    opcode = match bytes.read_u8() {
                        Ok(byte) => {
                            instruction.instruction_bytes.push(byte);
                            byte
                        },
                        Err(_e) => return Ok(instruction)
                    };

                    decode_idx_base = REGULAR_OPS_LEN;
                    break;
                }
                0x26 => {
                    op_segment_override = Some(Register16::ES);
                    PrefixFlags::ES_OVERRIDE
                },
                0x2E => {
                    op_segment_override = Some(Register16::CS);
                    PrefixFlags::CS_OVERRIDE
                },
                0x36 => {
                    op_segment_override = Some(Register16::SS);
                    PrefixFlags::SS_OVERRIDE
                }
                0x3E => {
                    op_segment_override = Some(Register16::DS);
                    PrefixFlags::DS_OVERRIDE
                },
                0x64 => {
                    op_segment_override = Some(Register16::FS);
                    PrefixFlags::FS_OVERRIDE
                },
                0x65 => {
                    op_segment_override = Some(Register16::SS);
                    PrefixFlags::GS_OVERRIDE
                },
                0xF0 => PrefixFlags::LOCK,
                0xF2 => PrefixFlags::REP1,
                0xF3 => PrefixFlags::REP2,
                0x66 => {
                    operand_size = segment_size.operand_size_override();
                    PrefixFlags::OPERAND_SIZE
                },
                0x67 => {
                    address_size = segment_size.address_size_override();
                    PrefixFlags::ADDRESS_SIZE
                },
                _=> {
                    break;
                }
            };
            op_prefix_ct += 1;

            if op_prefix_ct >= Self::PREFIX_LIMIT {
                // Too many prefixes - abort instruction decode
                instruction.is_valid = false;
                instruction.is_complete = false;
                return Ok(instruction)
            }

            opcode = match bytes.read_u8() {
                Ok(byte) => {
                    instruction.instruction_bytes.push(byte);
                    byte
                },
                Err(_e) => return Ok(instruction)
            };
        }


        instruction.prefix_flags = op_prefixes;
        // Set the segment override
        instruction.segment_override = op_segment_override;

        // Lookup the opcode in the decode table
        let mut decode_idx = decode_idx_base + opcode as usize;
        let mut op_lu = &DECODE[decode_idx];

        let force_reg = op_lu.gdr.is_always_register();

        // Prepare to read Mod/RM
        let mut displacement = Displacement::NoDisp;

        match address_size {
            AddressSize::Address16 => {
                // Determine whether to load the Mod/RM byte.
                // If the GDR indicates this opcode is a group opcode, load the Mod/RM byte - all group
                // opcodes have a Mod/RM byte.
                // Otherwise, rely on the 'has_modrm' flag of the GDR to determine if we need to load it.
                let modrm = if op_lu.gdr.has_modrm() || (op_lu.grp != 0) {

                    let modrm_offset = instruction.instruction_bytes.len();
                    let inner_modrm = match ModRmByte16::read(bytes, &mut instruction.instruction_bytes) {
                        Ok(size) => size,
                        Err(_e) => return Ok(instruction)
                    };
                    displacement = inner_modrm.displacement();
                    instruction.has_modrm = true;
                    instruction.modrm_offset = modrm_offset;

                    if op_lu.grp != 0 {
                        // Perform secondary lookup of opcode group + extension.
                        decode_idx = decode_idx_base + 256 + ((op_lu.grp as usize - 1) * 8) + inner_modrm.op_extension() as usize;
                        op_lu = &DECODE[decode_idx];
                    }
                    Some(inner_modrm)
                }
                else {
                    None
                };

                // Validity check
                if let Some(modrm) = modrm {
                    if !op_lu.gdr.has_reg_form() && modrm.mod_value() == 0b11 {
                        // This instruction does not support the 'reg' form of ModRM, but the ModRM
                        // byte indicates a 'reg' form. Mark instruction as invalid.
                        instruction.is_valid = false;
                    }

                    if op_lu.gdr.must_use_reg0() && modrm.reg_value() != 0 {
                        // This instruction must use reg field value 0, but the ModRM byte
                        // indicates a different value. Mark instruction as invalid.
                        instruction.is_valid = false;
                    }

                    if op_lu.gdr.uses_segment_reg() && matches!(modrm.op2_segment_reg16_386(), Register16::InvalidRegister) {
                        // This instruction uses a segment register, but the ModRM byte
                        // indicates an invalid segment register. Mark instruction as invalid.
                        instruction.is_valid = false;
                    }
                }

                instruction.operand1_type = op_lu.operand1.resolve_operand_a16(bytes, operand_size, &modrm, displacement, &mut instruction, force_reg)?;
                instruction.operand2_type = op_lu.operand2.resolve_operand_a16(bytes, operand_size, &modrm, displacement, &mut instruction, force_reg)?;
                instruction.operand3_type = op_lu.operand3.resolve_operand_a16(bytes, operand_size, &modrm, displacement, &mut instruction, force_reg)?;
            }
            AddressSize::Address32 => {
                let (modrm32, sib) = if op_lu.gdr.has_modrm() || (op_lu.grp != 0) {

                    let modrm_offset = instruction.instruction_bytes.len();
                    let (inner_modrm, inner_sib) = match ModRmByte32::read(bytes, &mut instruction.instruction_bytes) {
                        Ok(result) => result,
                        Err(_e) => {
                            instruction.is_complete = false;
                            return Ok(instruction)
                        }
                    };
                    displacement = inner_modrm.displacement();
                    instruction.has_modrm = true;
                    instruction.modrm_offset = modrm_offset;

                    if op_lu.grp != 0 {
                        // Perform secondary lookup of opcode group + extension.
                        decode_idx = decode_idx_base + 256 + ((op_lu.grp as usize - 1) * 8) + inner_modrm.op_extension() as usize;
                        op_lu = &DECODE[decode_idx];
                    }

                    (Some(inner_modrm), inner_sib)
                }
                else {
                    (None, None)
                };

                if let Some(modrm) = modrm32 {
                    if !op_lu.gdr.has_reg_form() && modrm.mod_value() == 0b11 {
                        // This instruction does not support the 'reg' form of ModRM, but the ModRM
                        // byte indicates a 'reg' form. Mark instruction as invalid.
                        instruction.is_valid = false;
                    }

                    if op_lu.gdr.must_use_reg0() && modrm.reg_value() != 0 {
                        // This instruction must use reg field value 0, but the ModRM byte
                        // indicates a different value. Mark instruction as invalid.
                        instruction.is_valid = false;
                    }

                    if op_lu.gdr.uses_segment_reg() && matches!(modrm.op2_segment_reg16_386(), Register16::InvalidRegister) {
                        // This instruction uses a segment register, but the ModRM byte
                        // indicates an invalid segment register. Mark instruction as invalid.
                        instruction.is_valid = false;
                    }
                }

                instruction.operand1_type = op_lu.operand1.resolve_operand_a32(bytes, operand_size, &modrm32, &sib, displacement, &mut instruction, force_reg)?;
                instruction.operand2_type = op_lu.operand2.resolve_operand_a32(bytes, operand_size, &modrm32, &sib, displacement, &mut instruction, force_reg)?;
                instruction.operand3_type = op_lu.operand3.resolve_operand_a32(bytes, operand_size, &modrm32, &sib, displacement, &mut instruction, force_reg)?;
            }
        }

        // Set mnemonic from decode table
        instruction.is_complete = true;
        // Is instruction too long? Max length is 15 bytes.
        if instruction.instruction_bytes.len() > MAX_INSTRUCTION_LENGTH {
            instruction.is_valid = false;
        }
        instruction.operand_size = operand_size;
        instruction.address_size = address_size;
        instruction.mnemonic = match operand_size {
            OperandSize::Operand32 => op_lu.mnemonic.wide32(),
            _ => op_lu.mnemonic,
        };

        instruction.disambiguate = op_lu.gdr.needs_disambiguation();



        //println!("Operand count: {}", instruction.operand_ct());
        // let operand_ct = instruction.operand_ct();
        // if operand_ct == 3 {
        //     println!("Three-operand instruction found, op3 is {:?}", instruction.operand3_type);
        // }

        //println!("Decoded instruction: {:?}", instruction);
        Ok(instruction)
    }
}
