/*
    MartyPC
    https://github.com/dbalsom/martypc

    Copyright 2022-2025 Daniel Balsom

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

    ---------------------------------------------------------------------------

    cpu_vx0::decode.rs

    Opcode fetch and instruction decoding routines.

    This module is implemented as an associated function, decode(), which
    operates on implementors of ByteQueue. This allows instruction decoding
    from either the processor instruction queue emulation, or directly
    from emulator memory for our debug disassembly viewer.

*/

use crate::{
    VX0::{NecVx0, gdr::GdrEntry},
    byte_reader::ByteReader,
    cpu_common::{
        Displacement,
        OperandSize,
        OperandType,
        OperandType::AddressingMode16,
        PrefixFlags,
        Register8,
        Register16,
    },
    error::DecodeError,
    instruction::Instruction,
    mnemonic::Mnemonic,
    modrm16::ModRmByte16,
};
use std::{error::Error, fmt::Display, io};

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
    Register8,
    Register16,
    SegmentRegister,
    Register8Encoded,
    Register16Encoded,
    Immediate8,
    Immediate16,
    Immediate8SignExtended,
    Relative8,
    Relative16,
    Offset8,
    Offset16,
    FixedRegister8(Register8),
    FixedRegister16(Register16),
    Register16Indirect(Register16),
    FarAddress,
}

impl OperandTemplate {
    #[inline(always)]
    pub fn resolve_operand(
        &self,
        bytes: &mut impl ByteReader,
        modrm: &Option<ModRmByte16>,
        displacement: Displacement,
        instruction: &mut Instruction,
    ) -> io::Result<OperandType> {
        match self {
            OperandTemplate::ModRM8 => {
                let addr_mode = modrm.unwrap().address_offset(displacement);
                match modrm.unwrap().is_addressing_mode() {
                    true => Ok(AddressingMode16(addr_mode, OperandSize::Operand8)),
                    false => Ok(OperandType::Register8(modrm.unwrap().op1_reg8())),
                }
            }
            OperandTemplate::ModRM16 => {
                let addr_mode = modrm.unwrap().address_offset(displacement);
                match modrm.unwrap().is_addressing_mode() {
                    true => Ok(AddressingMode16(addr_mode, OperandSize::Operand16)),
                    false => Ok(OperandType::Register16(modrm.unwrap().op1_reg16())),
                }
            }
            OperandTemplate::Register8 => Ok(OperandType::Register8(modrm.unwrap().op2_reg8())),
            OperandTemplate::Register16 => Ok(OperandType::Register16(modrm.unwrap().op2_reg16())),
            OperandTemplate::SegmentRegister => Ok(OperandType::Register16(modrm.unwrap().op2_segment_reg16())),
            OperandTemplate::Immediate8 => {
                let operand = bytes.peek_u8()?;
                instruction.instruction_bytes.push(operand);
                instruction.immediate_bytes.push(operand);
                Ok(OperandType::Immediate8(operand))
            }
            OperandTemplate::Immediate16 => {
                let operand = bytes.peek_u16()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                Ok(OperandType::Immediate16(operand))
            }
            OperandTemplate::Immediate8SignExtended => {
                let operand = bytes.peek_i8()?;
                instruction.instruction_bytes.push(operand as u8);
                instruction.immediate_bytes.push(operand as u8);
                Ok(OperandType::Immediate8s(operand))
            }
            OperandTemplate::Relative8 => {
                let operand = bytes.peek_i8()?;
                instruction.instruction_bytes.push(operand as u8);
                instruction.immediate_bytes.push(operand as u8);
                Ok(OperandType::Relative8(operand))
            }
            OperandTemplate::Relative16 => {
                let operand = bytes.peek_i16()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                Ok(OperandType::Relative16(operand))
            }
            OperandTemplate::Offset8 => {
                let operand = bytes.peek_u16()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                Ok(OperandType::Offset8_16(operand))
            }
            OperandTemplate::Offset16 => {
                let operand = bytes.peek_u16()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                Ok(OperandType::Offset16_16(operand))
            }
            OperandTemplate::FixedRegister8(r8) => Ok(OperandType::Register8(*r8)),
            OperandTemplate::FixedRegister16(r16) => Ok(OperandType::Register16(*r16)),
            OperandTemplate::FarAddress => {
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

pub const REGULAR_OPS_LEN: usize = 368;
pub const TOTAL_OPS_LEN: usize = REGULAR_OPS_LEN + 256;

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

#[rustfmt::skip]
pub static DECODE: [InstTemplate; TOTAL_OPS_LEN] = {
    let mut o: TableInitializer = TableInitializer::new();
    inst!( 0x00, o, 0, 0b0100101000000000, 0x008, ADD,     Ot::ModRM8,                             Ot::Register8);
    inst!( 0x01, o, 0, 0b0100101000000000, 0x008, ADD,     Ot::ModRM16,                            Ot::Register16);
    inst!( 0x02, o, 0, 0b0100101000000000, 0x008, ADD,     Ot::Register8,                          Ot::ModRM8);
    inst!( 0x03, o, 0, 0b0100101000000000, 0x008, ADD,     Ot::Register16,                         Ot::ModRM16);
    inst!( 0x04, o, 0, 0b0100100010010010, 0x018, ADD,     Ot::FixedRegister8(Register8::AL),      Ot::Immediate8);
    inst!( 0x05, o, 0, 0b0100100010010010, 0x018, ADD,     Ot::FixedRegister16(Register16::AX),    Ot::Immediate16);
    inst!( 0x06, o, 0, 0b0100000000110010, 0x02c, PUSH,    Ot::FixedRegister16(Register16::ES),    Ot::NoOperand);
    inst!( 0x07, o, 0, 0b0100000000110010, 0x038, POP,     Ot::FixedRegister16(Register16::ES),    Ot::NoOperand);
    inst!( 0x08, o, 0, 0b0100101000000000, 0x008, OR,      Ot::ModRM8,                             Ot::Register8);
    inst!( 0x09, o, 0, 0b0100101000000000, 0x008, OR,      Ot::ModRM16,                            Ot::Register16);
    inst!( 0x0A, o, 0, 0b0100101000000000, 0x008, OR,      Ot::Register8,                          Ot::ModRM8);
    inst!( 0x0B, o, 0, 0b0100101000000000, 0x008, OR,      Ot::Register16,                         Ot::ModRM16);
    inst!( 0x0C, o, 0, 0b0100100010010010, 0x018, OR,      Ot::FixedRegister8(Register8::AL),      Ot::Immediate8);
    inst!( 0x0D, o, 0, 0b0100100010010010, 0x018, OR,      Ot::FixedRegister16(Register16::AX),    Ot::Immediate16);
    inst!( 0x0E, o, 0, 0b0100000000110010, 0x02c, PUSH,    Ot::FixedRegister16(Register16::CS),    Ot::NoOperand);
    inst!( 0x0F, o, 0, 0b0000000000000000, 0x038, Extension,    Ot::NoOperand,    Ot::NoOperand);
    inst!( 0x10, o, 0, 0b0100101000000000, 0x008, ADC,     Ot::ModRM8,                             Ot::Register8);
    inst!( 0x11, o, 0, 0b0100101000000000, 0x008, ADC,     Ot::ModRM16,                            Ot::Register16);
    inst!( 0x12, o, 0, 0b0100101000000000, 0x008, ADC,     Ot::Register8,                          Ot::ModRM8);
    inst!( 0x13, o, 0, 0b0100101000000000, 0x008, ADC,     Ot::Register16,                         Ot::ModRM16);
    inst!( 0x14, o, 0, 0b0100100010010010, 0x018, ADC,     Ot::FixedRegister8(Register8::AL),      Ot::Immediate8);
    inst!( 0x15, o, 0, 0b0100100010010010, 0x018, ADC,     Ot::FixedRegister16(Register16::AX),    Ot::Immediate16);
    inst!( 0x16, o, 0, 0b0100000000110010, 0x02c, PUSH,    Ot::FixedRegister16(Register16::SS),    Ot::NoOperand);
    inst!( 0x17, o, 0, 0b0100000000110010, 0x038, POP,     Ot::FixedRegister16(Register16::SS),    Ot::NoOperand);
    inst!( 0x18, o, 0, 0b0100101000000000, 0x008, SBB,     Ot::ModRM8,                             Ot::Register8);
    inst!( 0x19, o, 0, 0b0100101000000000, 0x008, SBB,     Ot::ModRM16,                            Ot::Register16);
    inst!( 0x1A, o, 0, 0b0100101000000000, 0x008, SBB,     Ot::Register8,                          Ot::ModRM8);
    inst!( 0x1B, o, 0, 0b0100101000000000, 0x008, SBB,     Ot::Register16,                         Ot::ModRM16);
    inst!( 0x1C, o, 0, 0b0100100010010010, 0x018, SBB,     Ot::FixedRegister8(Register8::AL),      Ot::Immediate8);
    inst!( 0x1D, o, 0, 0b0100100010010010, 0x018, SBB,     Ot::FixedRegister16(Register16::AX),    Ot::Immediate16);
    inst!( 0x1E, o, 0, 0b0100000000110010, 0x02c, PUSH,    Ot::FixedRegister16(Register16::DS),    Ot::NoOperand);
    inst!( 0x1F, o, 0, 0b0100000000110010, 0x038, POP,     Ot::FixedRegister16(Register16::DS),    Ot::NoOperand);
    inst!( 0x20, o, 0, 0b0100101000000000, 0x008, AND,     Ot::ModRM8,                             Ot::Register8);
    inst!( 0x21, o, 0, 0b0100101000000000, 0x008, AND,     Ot::ModRM16,                            Ot::Register16);
    inst!( 0x22, o, 0, 0b0100101000000000, 0x008, AND,     Ot::Register8,                          Ot::ModRM8);
    inst!( 0x23, o, 0, 0b0100101000000000, 0x008, AND,     Ot::Register16,                         Ot::ModRM16);
    inst!( 0x24, o, 0, 0b0100100010010010, 0x018, AND,     Ot::FixedRegister8(Register8::AL),      Ot::Immediate8);
    inst!( 0x25, o, 0, 0b0100100010010010, 0x018, AND,     Ot::FixedRegister16(Register16::AX),    Ot::Immediate16);
    inst!( 0x26, o, 0, 0b0100010000111010, 0x1FF, Prefix,  Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x27, o, 0, 0b0101000000110010, 0x144, DAA,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x28, o, 0, 0b0100101000000000, 0x008, SUB,     Ot::ModRM8,                             Ot::Register8);
    inst!( 0x29, o, 0, 0b0100101000000000, 0x008, SUB,     Ot::ModRM16,                            Ot::Register16);
    inst!( 0x2A, o, 0, 0b0100101000000000, 0x008, SUB,     Ot::Register8,                          Ot::ModRM8);
    inst!( 0x2B, o, 0, 0b0100101000000000, 0x008, SUB,     Ot::Register16,                         Ot::ModRM16);
    inst!( 0x2C, o, 0, 0b0100100010010010, 0x018, SUB,     Ot::FixedRegister8(Register8::AL),      Ot::Immediate8);
    inst!( 0x2D, o, 0, 0b0100100010010010, 0x018, SUB,     Ot::FixedRegister16(Register16::AX),    Ot::Immediate16);
    inst!( 0x2E, o, 0, 0b0100010000111010, 0x1FF, Prefix,  Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x2F, o, 0, 0b0101000000110010, 0x144, DAS,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x30, o, 0, 0b0100101000000000, 0x008, XOR,     Ot::ModRM8,                             Ot::Register8);
    inst!( 0x31, o, 0, 0b0100101000000000, 0x008, XOR,     Ot::ModRM16,                            Ot::Register16);
    inst!( 0x32, o, 0, 0b0100101000000000, 0x008, XOR,     Ot::Register8,                          Ot::ModRM8);
    inst!( 0x33, o, 0, 0b0100101000000000, 0x008, XOR,     Ot::Register16,                         Ot::ModRM16);
    inst!( 0x34, o, 0, 0b0100100010010010, 0x018, XOR,     Ot::FixedRegister8(Register8::AL),      Ot::Immediate8);
    inst!( 0x35, o, 0, 0b0100100010010010, 0x018, XOR,     Ot::FixedRegister16(Register16::AX),    Ot::Immediate16);
    inst!( 0x36, o, 0, 0b0100010000111010, 0x1FF, Prefix,  Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x37, o, 0, 0b0101000000110010, 0x148, AAA,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x38, o, 0, 0b0100101000000000, 0x008, CMP,     Ot::ModRM8,                             Ot::Register8);
    inst!( 0x39, o, 0, 0b0100101000000000, 0x008, CMP,     Ot::ModRM16,                            Ot::Register16);
    inst!( 0x3A, o, 0, 0b0100101000000000, 0x008, CMP,     Ot::Register8,                          Ot::ModRM8);
    inst!( 0x3B, o, 0, 0b0100101000000000, 0x008, CMP,     Ot::Register16,                         Ot::ModRM16);
    inst!( 0x3C, o, 0, 0b0100100010010010, 0x018, CMP,     Ot::FixedRegister8(Register8::AL),      Ot::Immediate8);
    inst!( 0x3D, o, 0, 0b0100100010010010, 0x018, CMP,     Ot::FixedRegister16(Register16::AX),    Ot::Immediate16);
    inst!( 0x3E, o, 0, 0b0100010000111010, 0x1FF, Prefix,  Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x3F, o, 0, 0b0101000000110010, 0x148, AAS,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x40, o, 0, 0b0000000000110010, 0x17c, INC,     Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x41, o, 0, 0b0000000000110010, 0x17c, INC,     Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x42, o, 0, 0b0000000000110010, 0x17c, INC,     Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x43, o, 0, 0b0000000000110010, 0x17c, INC,     Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x44, o, 0, 0b0000000000110010, 0x17c, INC,     Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x45, o, 0, 0b0000000000110010, 0x17c, INC,     Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x46, o, 0, 0b0000000000110010, 0x17c, INC,     Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x47, o, 0, 0b0000000000110010, 0x17c, INC,     Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x48, o, 0, 0b0000000000110010, 0x17c, DEC,     Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x49, o, 0, 0b0000000000110010, 0x17c, DEC,     Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x4A, o, 0, 0b0000000000110010, 0x17c, DEC,     Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x4B, o, 0, 0b0000000000110010, 0x17c, DEC,     Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x4C, o, 0, 0b0000000000110010, 0x17c, DEC,     Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x4D, o, 0, 0b0000000000110010, 0x17c, DEC,     Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x4E, o, 0, 0b0000000000110010, 0x17c, DEC,     Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x4F, o, 0, 0b0000000000110010, 0x17c, DEC,     Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x50, o, 0, 0b0000000000110010, 0x028, PUSH,    Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x51, o, 0, 0b0000000000110010, 0x028, PUSH,    Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x52, o, 0, 0b0000000000110010, 0x028, PUSH,    Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x53, o, 0, 0b0000000000110010, 0x028, PUSH,    Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x54, o, 0, 0b0000000000110010, 0x028, PUSH,    Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x55, o, 0, 0b0000000000110010, 0x028, PUSH,    Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x56, o, 0, 0b0000000000110010, 0x028, PUSH,    Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x57, o, 0, 0b0000000000110010, 0x028, PUSH,    Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x58, o, 0, 0b0000000000110010, 0x034, POP,     Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x59, o, 0, 0b0000000000110010, 0x034, POP,     Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x5A, o, 0, 0b0000000000110010, 0x034, POP,     Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x5B, o, 0, 0b0000000000110010, 0x034, POP,     Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x5C, o, 0, 0b0000000000110010, 0x034, POP,     Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x5D, o, 0, 0b0000000000110010, 0x034, POP,     Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x5E, o, 0, 0b0000000000110010, 0x034, POP,     Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x5F, o, 0, 0b0000000000110010, 0x034, POP,     Ot::Register16Encoded,                  Ot::NoOperand);
    inst!( 0x60, o, 0, 0b0000000000010000, 0x0e8, PUSHA,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x61, o, 0, 0b0000000000010000, 0x0e8, POPA,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x62, o, 0, 0b0000000000000000, 0x0e8, BOUND,   Ot::Register16,                         Ot::ModRM16);
    inst!( 0x63, o, 0, 0b0000000000000000, 0x0e8, UNDEF,   Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0x64, o, 0, 0b0000000000011000, 0x0e8, Prefix,  Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x65, o, 0, 0b0000000000011000, 0x0e8, Prefix,  Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x66, o, 0, 0b0000000000000000, 0x0e8, FPO2,    Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0x67, o, 0, 0b0000000000000000, 0x0e8, FPO2,    Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0x68, o, 0, 0b0000000000010000, 0x0e8, PUSH,    Ot::Immediate16,                        Ot::NoOperand);
    inst!( 0x69, o, 0, 0b0000000000010000, 0x0e8, IMUL,    Ot::Register16,                         Ot::ModRM16, Ot::Immediate16);
    inst!( 0x6A, o, 0, 0b0000000000010000, 0x0e8, PUSH,    Ot::Immediate8,                         Ot::NoOperand);
    inst!( 0x6B, o, 0, 0b0000000000000000, 0x0e8, IMUL,    Ot::Register16,                         Ot::ModRM16, Ot::Immediate8SignExtended);
    inst!( 0x6C, o, 0, 0b0000000000010000, 0x0e8, INSB,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x6D, o, 0, 0b0000000000010000, 0x0e8, INSW,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x6E, o, 0, 0b0000000000010000, 0x0e8, OUTSB,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x6F, o, 0, 0b0000000000010000, 0x0e8, OUTSW,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x70, o, 0, 0b0000000000110010, 0x0e8, JO,      Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x71, o, 0, 0b0000000000110010, 0x0e8, JNO,     Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x72, o, 0, 0b0000000000110010, 0x0e8, JB,      Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x73, o, 0, 0b0000000000110010, 0x0e8, JNB,     Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x74, o, 0, 0b0000000000110010, 0x0e8, JZ,      Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x75, o, 0, 0b0000000000110010, 0x0e8, JNZ,     Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x76, o, 0, 0b0000000000110010, 0x0e8, JBE,     Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x77, o, 0, 0b0000000000110010, 0x0e8, JNBE,    Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x78, o, 0, 0b0000000000110010, 0x0e8, JS,      Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x79, o, 0, 0b0000000000110010, 0x0e8, JNS,     Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x7A, o, 0, 0b0000000000110010, 0x0e8, JP,      Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x7B, o, 0, 0b0000000000110010, 0x0e8, JNP,     Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x7C, o, 0, 0b0000000000110010, 0x0e8, JL,      Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x7D, o, 0, 0b0000000000110010, 0x0e8, JNL,     Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x7E, o, 0, 0b0000000000110010, 0x0e8, JLE,     Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x7F, o, 0, 0b0000000000110010, 0x0e8, JNLE,    Ot::Relative8,                          Ot::NoOperand);
    inst!( 0x80, o, 1, 0b0110100000000000, 0x00c, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x81, o, 2, 0b0110100000000000, 0x00c, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x82, o, 3, 0b0110100000000000, 0x00c, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x83, o, 4, 0b0110100000000000, 0x00c, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x84, o, 0, 0b0110100000000000, 0x094, TEST,    Ot::ModRM8,                             Ot::Register8);
    inst!( 0x85, o, 0, 0b0110100000000000, 0x094, TEST,    Ot::ModRM16,                            Ot::Register16);
    inst!( 0x86, o, 0, 0b0110100000000000, 0x0a4, XCHG,    Ot::Register8,                          Ot::ModRM8);
    inst!( 0x87, o, 0, 0b0110100000000000, 0x0a4, XCHG,    Ot::Register16,                         Ot::ModRM16);
    inst!( 0x88, o, 0, 0b0100101000100010, 0x000, MOV,     Ot::ModRM8,                             Ot::Register8);
    inst!( 0x89, o, 0, 0b0100101000100010, 0x000, MOV,     Ot::ModRM16,                            Ot::Register16);
    inst!( 0x8A, o, 0, 0b0100101000100000, 0x000, MOV,     Ot::Register8,                          Ot::ModRM8);
    inst!( 0x8B, o, 0, 0b0100101000100000, 0x000, MOV,     Ot::Register16,                         Ot::ModRM16);
    inst!( 0x8C, o, 0, 0b0100001100100010, 0x0ec, MOV,     Ot::ModRM16,                            Ot::SegmentRegister);
    inst!( 0x8D, o, 0, 0b0100000000100010, 0x004, LEA,     Ot::Register16,                         Ot::ModRM16);
    inst!( 0x8E, o, 0, 0b0100001100100000, 0x0ec, MOV,     Ot::SegmentRegister,                    Ot::ModRM16);
    inst!( 0x8F, o, 0, 0b0100000000100010, 0x040, POP,     Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0x90, o, 0, 0b0100000000110010, 0x084, NOP,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x91, o, 0, 0b0100000000110010, 0x084, XCHG,    Ot::Register16Encoded,                  Ot::FixedRegister16(Register16::AX));
    inst!( 0x92, o, 0, 0b0100000000110010, 0x084, XCHG,    Ot::Register16Encoded,                  Ot::FixedRegister16(Register16::AX));
    inst!( 0x93, o, 0, 0b0100000000110010, 0x084, XCHG,    Ot::Register16Encoded,                  Ot::FixedRegister16(Register16::AX));
    inst!( 0x94, o, 0, 0b0100000000110010, 0x084, XCHG,    Ot::Register16Encoded,                  Ot::FixedRegister16(Register16::AX));
    inst!( 0x95, o, 0, 0b0100000000110010, 0x084, XCHG,    Ot::Register16Encoded,                  Ot::FixedRegister16(Register16::AX));
    inst!( 0x96, o, 0, 0b0100000000110010, 0x084, XCHG,    Ot::Register16Encoded,                  Ot::FixedRegister16(Register16::AX));
    inst!( 0x97, o, 0, 0b0100000000110010, 0x084, XCHG,    Ot::Register16Encoded,                  Ot::FixedRegister16(Register16::AX));
    inst!( 0x98, o, 0, 0b0100000000110010, 0x054, CBW,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x99, o, 0, 0b0100000000110010, 0x058, CWD,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x9A, o, 0, 0b0100000000110010, 0x070, CALLF,   Ot::FarAddress,                         Ot::NoOperand);
    inst!( 0x9B, o, 0, 0b0100000000110010, 0x0f8, WAIT,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x9C, o, 0, 0b0100000000110010, 0x030, PUSHF,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x9D, o, 0, 0b0100000000110010, 0x03c, POPF,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x9E, o, 0, 0b0100000000110010, 0x100, SAHF,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0x9F, o, 0, 0b0100000000110010, 0x104, LAHF,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xA0, o, 0, 0b0100100010110010, 0x060, MOV,     Ot::FixedRegister8(Register8::AL),      Ot::Offset8);
    inst!( 0xA1, o, 0, 0b0100100010110010, 0x060, MOV,     Ot::FixedRegister16(Register16::AX),    Ot::Offset16);
    inst!( 0xA2, o, 0, 0b0100100010110010, 0x064, MOV,     Ot::Offset8,                            Ot::FixedRegister8(Register8::AL));
    inst!( 0xA3, o, 0, 0b0100100010110010, 0x064, MOV,     Ot::Offset16,                           Ot::FixedRegister16(Register16::AX));
    inst!( 0xA4, o, 0, 0b0100100010110010, 0x12c, MOVSB,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xA5, o, 0, 0b0100100010110010, 0x12c, MOVSW,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xA6, o, 0, 0b0100100010110010, 0x120, CMPSB,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xA7, o, 0, 0b0100100010110010, 0x120, CMPSW,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xA8, o, 0, 0b0100100010110010, 0x09C, TEST,    Ot::FixedRegister8(Register8::AL),      Ot::Immediate8);
    inst!( 0xA9, o, 0, 0b0100100010110010, 0x09C, TEST,    Ot::FixedRegister16(Register16::AX),    Ot::Immediate16);
    inst!( 0xAA, o, 0, 0b0100100010110010, 0x11c, STOSB,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xAB, o, 0, 0b0100100010110010, 0x11c, STOSW,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xAC, o, 0, 0b0100100010110010, 0x12c, LODSB,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xAD, o, 0, 0b0100100010110010, 0x12c, LODSW,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xAE, o, 0, 0b0100100010110010, 0x120, SCASB,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xAF, o, 0, 0b0100100010110010, 0x120, SCASW,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xB0, o, 0, 0b0100000000110010, 0x01c, MOV,     Ot::Register8Encoded,                   Ot::Immediate8);
    inst!( 0xB1, o, 0, 0b0100000000110010, 0x01c, MOV,     Ot::Register8Encoded,                   Ot::Immediate8);
    inst!( 0xB2, o, 0, 0b0100000000110010, 0x01c, MOV,     Ot::Register8Encoded,                   Ot::Immediate8);
    inst!( 0xB3, o, 0, 0b0100000000110010, 0x01c, MOV,     Ot::Register8Encoded,                   Ot::Immediate8);
    inst!( 0xB4, o, 0, 0b0100000000110010, 0x01c, MOV,     Ot::Register8Encoded,                   Ot::Immediate8);
    inst!( 0xB5, o, 0, 0b0100000000110010, 0x01c, MOV,     Ot::Register8Encoded,                   Ot::Immediate8);
    inst!( 0xB6, o, 0, 0b0100000000110010, 0x01c, MOV,     Ot::Register8Encoded,                   Ot::Immediate8);
    inst!( 0xB7, o, 0, 0b0100000000110010, 0x01c, MOV,     Ot::Register8Encoded,                   Ot::Immediate8);
    inst!( 0xB8, o, 0, 0b0100000000110010, 0x01c, MOV,     Ot::Register16Encoded,                  Ot::Immediate16);
    inst!( 0xB9, o, 0, 0b0100000000110010, 0x01c, MOV,     Ot::Register16Encoded,                  Ot::Immediate16);
    inst!( 0xBA, o, 0, 0b0100000000110010, 0x01c, MOV,     Ot::Register16Encoded,                  Ot::Immediate16);
    inst!( 0xBB, o, 0, 0b0100000000110010, 0x01c, MOV,     Ot::Register16Encoded,                  Ot::Immediate16);
    inst!( 0xBC, o, 0, 0b0100000000110010, 0x01c, MOV,     Ot::Register16Encoded,                  Ot::Immediate16);
    inst!( 0xBD, o, 0, 0b0100000000110010, 0x01c, MOV,     Ot::Register16Encoded,                  Ot::Immediate16);
    inst!( 0xBE, o, 0, 0b0100000000110010, 0x01c, MOV,     Ot::Register16Encoded,                  Ot::Immediate16);
    inst!( 0xBF, o, 0, 0b0100000000110010, 0x01c, MOV,     Ot::Register16Encoded,                  Ot::Immediate16);
    inst!( 0xC0, o, 5, 0b0100000000110000, 0x0cc, Group,   Ot::Immediate16,                        Ot::NoOperand);
    inst!( 0xC1, o, 6, 0b0100000000110000, 0x0bc, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xC2, o, 0, 0b0100000000110000, 0x0cc, RET,    Ot::Immediate16,                        Ot::NoOperand);
    inst!( 0xC3, o, 0, 0b0100000000110000, 0x0bc, RET,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xC4, o, 0, 0b0100000000100000, 0x0f0, LES,     Ot::Register16,                         Ot::ModRM16);
    inst!( 0xC5, o, 0, 0b0100000000100000, 0x0f4, LDS,     Ot::Register16,                         Ot::ModRM16);
    inst!( 0xC6, o, 0, 0b0100100000100010, 0x014, MOV,     Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0xC7, o, 0, 0b0100100000100010, 0x014, MOV,     Ot::ModRM16,                            Ot::Immediate16);
    inst!( 0xC8, o, 0, 0b0100000000110000, 0x0cc, ENTER,   Ot::Immediate16,                        Ot::Immediate8);
    inst!( 0xC9, o, 0, 0b0100000000110000, 0x0c0, LEAVE,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xCA, o, 0, 0b0100000000110000, 0x0cc, RETF,    Ot::Immediate16,                        Ot::NoOperand);
    inst!( 0xCB, o, 0, 0b0100000000110000, 0x0c0, RETF,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xCC, o, 0, 0b0100000000110000, 0x1b0, INT3,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xCD, o, 0, 0b0100000000110000, 0x1a8, INT,     Ot::Immediate8,                         Ot::NoOperand);
    inst!( 0xCE, o, 0, 0b0100000000110000, 0x1ac, INTO,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xCF, o, 0, 0b0100000000110000, 0x0c8, IRET,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xD0, o, 7, 0b0100100000000000, 0x088, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xD1, o, 8, 0b0100100000000000, 0x088, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xD2, o, 9, 0b0100100000000000, 0x08c, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xD3, o,10, 0b0100100000000000, 0x08c, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xD4, o, 0, 0b0101000000110000, 0x174, AAM,     Ot::Immediate8,                         Ot::NoOperand);
    inst!( 0xD5, o, 0, 0b0101000000110000, 0x170, AAD,     Ot::Immediate8,                         Ot::NoOperand);
    inst!( 0xD6, o, 0, 0b0101000000110000, 0x0a0, XLAT,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xD7, o, 0, 0b0101000000110000, 0x10c, XLAT,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xD8, o, 0, 0b0100000000100000, 0x108, ESC,     Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xD9, o, 0, 0b0100000000100000, 0x108, ESC,     Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xDA, o, 0, 0b0100000000100000, 0x108, ESC,     Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xDB, o, 0, 0b0100000000100000, 0x108, ESC,     Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xDC, o, 0, 0b0100000000100000, 0x108, ESC,     Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xDD, o, 0, 0b0100000000100000, 0x108, ESC,     Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xDE, o, 0, 0b0100000000100000, 0x108, ESC,     Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xDF, o, 0, 0b0100000000100000, 0x108, ESC,     Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xE0, o, 0, 0b0110000000110000, 0x138, LOOPNE,  Ot::Relative8,                          Ot::NoOperand);
    inst!( 0xE1, o, 0, 0b0110000000110000, 0x138, LOOPE,   Ot::Relative8,                          Ot::NoOperand);
    inst!( 0xE2, o, 0, 0b0110000000110000, 0x140, LOOP,    Ot::Relative8,                          Ot::NoOperand);
    inst!( 0xE3, o, 0, 0b0110000000110000, 0x134, JCXZ,    Ot::Relative8,                          Ot::NoOperand);
    inst!( 0xE4, o, 0, 0b0100100010110011, 0x0ac, IN,      Ot::FixedRegister8(Register8::AL),      Ot::Immediate8);
    inst!( 0xE5, o, 0, 0b0100100010110011, 0x0ac, IN,      Ot::FixedRegister16(Register16::AX),    Ot::Immediate8);
    inst!( 0xE6, o, 0, 0b0100100010110011, 0x0b0, OUT,     Ot::Immediate8,                         Ot::FixedRegister8(Register8::AL));
    inst!( 0xE7, o, 0, 0b0100100010110011, 0x0b0, OUT,     Ot::Immediate8,                         Ot::FixedRegister16(Register16::AX));
    inst!( 0xE8, o, 0, 0b0110000000110000, 0x07c, CALL,    Ot::Relative16,                         Ot::NoOperand);
    inst!( 0xE9, o, 0, 0b0110000000110000, 0x0d0, JMP,     Ot::Relative16,                         Ot::NoOperand);
    inst!( 0xEA, o, 0, 0b0110000000110000, 0x0e0, JMPF,    Ot::FarAddress,                         Ot::NoOperand);
    inst!( 0xEB, o, 0, 0b0110000000110000, 0x0d0, JMP,     Ot::Relative8,                          Ot::NoOperand);
    inst!( 0xEC, o, 0, 0b0100100010110011, 0x0b4, IN,      Ot::FixedRegister8(Register8::AL),      Ot::FixedRegister16(Register16::DX));
    inst!( 0xED, o, 0, 0b0100100010110011, 0x0b4, IN,      Ot::FixedRegister16(Register16::AX),    Ot::FixedRegister16(Register16::DX));
    inst!( 0xEE, o, 0, 0b0100100010110011, 0x0b8, OUT,     Ot::FixedRegister16(Register16::DX),    Ot::FixedRegister8(Register8::AL));
    inst!( 0xEF, o, 0, 0b0100100010110011, 0x0b8, OUT,     Ot::FixedRegister16(Register16::DX),    Ot::FixedRegister16(Register16::AX));
    inst!( 0xF0, o, 0, 0b0100010000111010, 0x1FF, LOCK,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xF1, o, 0, 0b0100010000111010, 0x1FF, LOCK,    Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xF2, o, 0, 0b0100010000111010, 0x1FF, Prefix,  Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xF3, o, 0, 0b0100010000111010, 0x1FF, Prefix,  Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xF4, o, 0, 0b0100010000110010, 0x1FF, HLT,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xF5, o, 0, 0b0100010000110010, 0x1FF, CMC,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xF6, o,11, 0b0100100000100100, 0x098, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xF7, o,12, 0b0100100000100100, 0x160, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xF8, o, 0, 0b0100010001110010, 0x1FF, CLC,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xF9, o, 0, 0b0100010001110010, 0x1FF, STC,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xFA, o, 0, 0b0100010001110010, 0x1FF, CLI,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xFB, o, 0, 0b0100010001110010, 0x1FF, STI,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xFC, o, 0, 0b0100010001110010, 0x1FF, CLD,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xFD, o, 0, 0b0100010001110010, 0x1FF, STD,     Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xFE, o,13, 0b0000100000100100, 0x020, Group,   Ot::NoOperand,                          Ot::NoOperand);
    inst!( 0xFF, o,14, 0b0000100000100100, 0x026, Group,   Ot::NoOperand,                          Ot::NoOperand);
    // Group
    inst!( 0x80, o, 1, 0b0110100000000000, 0x00c, ADD  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x80, o, 1, 0b0110100000000000, 0x00c, OR   ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x80, o, 1, 0b0110100000000000, 0x00c, ADC  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x80, o, 1, 0b0110100000000000, 0x00c, SBB  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x80, o, 1, 0b0110100000000000, 0x00c, AND  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x80, o, 1, 0b0110100000000000, 0x00c, SUB  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x80, o, 1, 0b0110100000000000, 0x00c, XOR  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x80, o, 1, 0b0110100000000000, 0x00c, CMP  ,   Ot::ModRM8,                             Ot::Immediate8);
    // Group
    inst!( 0x81, o, 1, 0b0110100000000000, 0x00c, ADD  ,   Ot::ModRM16,                            Ot::Immediate16);
    inst!( 0x81, o, 1, 0b0110100000000000, 0x00c, OR   ,   Ot::ModRM16,                            Ot::Immediate16);
    inst!( 0x81, o, 1, 0b0110100000000000, 0x00c, ADC  ,   Ot::ModRM16,                            Ot::Immediate16);
    inst!( 0x81, o, 1, 0b0110100000000000, 0x00c, SBB  ,   Ot::ModRM16,                            Ot::Immediate16);
    inst!( 0x81, o, 1, 0b0110100000000000, 0x00c, AND  ,   Ot::ModRM16,                            Ot::Immediate16);
    inst!( 0x81, o, 1, 0b0110100000000000, 0x00c, SUB  ,   Ot::ModRM16,                            Ot::Immediate16);
    inst!( 0x81, o, 1, 0b0110100000000000, 0x00c, XOR  ,   Ot::ModRM16,                            Ot::Immediate16);
    inst!( 0x81, o, 1, 0b0110100000000000, 0x00c, CMP  ,   Ot::ModRM16,                            Ot::Immediate16);
    // Group,
    inst!( 0x82, o, 1, 0b0110100000000000, 0x00c, ADD  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x82, o, 1, 0b0110100000000000, 0x00c, OR   ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x82, o, 1, 0b0110100000000000, 0x00c, ADC  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x82, o, 1, 0b0110100000000000, 0x00c, SBB  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x82, o, 1, 0b0110100000000000, 0x00c, AND  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x82, o, 1, 0b0110100000000000, 0x00c, SUB  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x82, o, 1, 0b0110100000000000, 0x00c, XOR  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x82, o, 1, 0b0110100000000000, 0x00c, CMP  ,   Ot::ModRM8,                             Ot::Immediate8);
    // Group
    inst!( 0x83, o, 1, 0b0110100000000000, 0x00c, ADD  ,   Ot::ModRM16,                            Ot::Immediate8SignExtended);
    inst!( 0x83, o, 1, 0b0110100000000000, 0x00c, OR   ,   Ot::ModRM16,                            Ot::Immediate8SignExtended);
    inst!( 0x83, o, 1, 0b0110100000000000, 0x00c, ADC  ,   Ot::ModRM16,                            Ot::Immediate8SignExtended);
    inst!( 0x83, o, 1, 0b0110100000000000, 0x00c, SBB  ,   Ot::ModRM16,                            Ot::Immediate8SignExtended);
    inst!( 0x83, o, 1, 0b0110100000000000, 0x00c, AND  ,   Ot::ModRM16,                            Ot::Immediate8SignExtended);
    inst!( 0x83, o, 1, 0b0110100000000000, 0x00c, SUB  ,   Ot::ModRM16,                            Ot::Immediate8SignExtended);
    inst!( 0x83, o, 1, 0b0110100000000000, 0x00c, XOR  ,   Ot::ModRM16,                            Ot::Immediate8SignExtended);
    inst!( 0x83, o, 1, 0b0110100000000000, 0x00c, CMP  ,   Ot::ModRM16,                            Ot::Immediate8SignExtended);
    // Group
    inst!( 0xC0, o, 2, 0b0100100000000000, 0x088, ROL  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0xC0, o, 2, 0b0100100000000000, 0x088, ROR  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0xC0, o, 2, 0b0100100000000000, 0x088, RCL  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0xC0, o, 2, 0b0100100000000000, 0x088, RCR  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0xC0, o, 2, 0b0100100000000000, 0x088, SHL  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0xC0, o, 2, 0b0100100000000000, 0x088, SHR  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0xC0, o, 2, 0b0100100000000000, 0x088, SHL  ,   Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0xC0, o, 2, 0b0100100000000000, 0x088, SAR  ,   Ot::ModRM8,                             Ot::Immediate8);
    // Group
    inst!( 0xC1, o, 2, 0b0100100000000000, 0x088, ROL  ,   Ot::ModRM16,                            Ot::Immediate8);
    inst!( 0xC1, o, 2, 0b0100100000000000, 0x088, ROR  ,   Ot::ModRM16,                            Ot::Immediate8);
    inst!( 0xC1, o, 2, 0b0100100000000000, 0x088, RCL  ,   Ot::ModRM16,                            Ot::Immediate8);
    inst!( 0xC1, o, 2, 0b0100100000000000, 0x088, RCR  ,   Ot::ModRM16,                            Ot::Immediate8);
    inst!( 0xC1, o, 2, 0b0100100000000000, 0x088, SHL  ,   Ot::ModRM16,                            Ot::Immediate8);
    inst!( 0xC1, o, 2, 0b0100100000000000, 0x088, SHR  ,   Ot::ModRM16,                            Ot::Immediate8);
    inst!( 0xC1, o, 2, 0b0100100000000000, 0x088, SHL  ,   Ot::ModRM16,                            Ot::Immediate8);
    inst!( 0xC1, o, 2, 0b0100100000000000, 0x088, SAR  ,   Ot::ModRM16,                            Ot::Immediate8);
    // Group
    inst!( 0xD0, o, 3, 0b0100100000000000, 0x088, ROL  ,   Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xD0, o, 3, 0b0100100000000000, 0x088, ROR  ,   Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xD0, o, 3, 0b0100100000000000, 0x088, RCL  ,   Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xD0, o, 3, 0b0100100000000000, 0x088, RCR  ,   Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xD0, o, 3, 0b0100100000000000, 0x088, SHL  ,   Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xD0, o, 3, 0b0100100000000000, 0x088, SHR  ,   Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xD0, o, 3, 0b0100100000000000, 0x088, SHL  ,   Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xD0, o, 3, 0b0100100000000000, 0x088, SAR  ,   Ot::ModRM8,                             Ot::NoOperand);
    // Group
    inst!( 0xD1, o, 3, 0b0100100000000000, 0x088, ROL  ,   Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xD1, o, 3, 0b0100100000000000, 0x088, ROR  ,   Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xD1, o, 3, 0b0100100000000000, 0x088, RCL  ,   Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xD1, o, 3, 0b0100100000000000, 0x088, RCR  ,   Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xD1, o, 3, 0b0100100000000000, 0x088, SHL  ,   Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xD1, o, 3, 0b0100100000000000, 0x088, SHR  ,   Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xD1, o, 3, 0b0100100000000000, 0x088, SHL  ,   Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xD1, o, 3, 0b0100100000000000, 0x088, SAR  ,   Ot::ModRM16,                            Ot::NoOperand);
    // Group
    inst!( 0xD2, o, 4, 0b0100100000000000, 0x08c, ROL   ,  Ot::ModRM8,                             Ot::FixedRegister8(Register8::CL));
    inst!( 0xD2, o, 4, 0b0100100000000000, 0x08c, ROR   ,  Ot::ModRM8,                             Ot::FixedRegister8(Register8::CL));
    inst!( 0xD2, o, 4, 0b0100100000000000, 0x08c, RCL   ,  Ot::ModRM8,                             Ot::FixedRegister8(Register8::CL));
    inst!( 0xD2, o, 4, 0b0100100000000000, 0x08c, RCR   ,  Ot::ModRM8,                             Ot::FixedRegister8(Register8::CL));
    inst!( 0xD2, o, 4, 0b0100100000000000, 0x08c, SHL   ,  Ot::ModRM8,                             Ot::FixedRegister8(Register8::CL));
    inst!( 0xD2, o, 4, 0b0100100000000000, 0x08c, SHR   ,  Ot::ModRM8,                             Ot::FixedRegister8(Register8::CL));
    inst!( 0xD2, o, 4, 0b0100100000000000, 0x08c, SHL   ,  Ot::ModRM8,                             Ot::FixedRegister8(Register8::CL));
    inst!( 0xD2, o, 4, 0b0100100000000000, 0x08c, SAR   ,  Ot::ModRM8,                             Ot::FixedRegister8(Register8::CL));
    // Group
    inst!( 0xD3, o, 4, 0b0100100000000000, 0x08c, ROL   ,  Ot::ModRM16,                            Ot::FixedRegister8(Register8::CL));
    inst!( 0xD3, o, 4, 0b0100100000000000, 0x08c, ROR   ,  Ot::ModRM16,                            Ot::FixedRegister8(Register8::CL));
    inst!( 0xD3, o, 4, 0b0100100000000000, 0x08c, RCL   ,  Ot::ModRM16,                            Ot::FixedRegister8(Register8::CL));
    inst!( 0xD3, o, 4, 0b0100100000000000, 0x08c, RCR   ,  Ot::ModRM16,                            Ot::FixedRegister8(Register8::CL));
    inst!( 0xD3, o, 4, 0b0100100000000000, 0x08c, SHL   ,  Ot::ModRM16,                            Ot::FixedRegister8(Register8::CL));
    inst!( 0xD3, o, 4, 0b0100100000000000, 0x08c, SHR   ,  Ot::ModRM16,                            Ot::FixedRegister8(Register8::CL));
    inst!( 0xD3, o, 4, 0b0100100000000000, 0x08c, SHL   ,  Ot::ModRM16,                            Ot::FixedRegister8(Register8::CL));
    inst!( 0xD3, o, 4, 0b0100100000000000, 0x08c, SAR   ,  Ot::ModRM16,                            Ot::FixedRegister8(Register8::CL));
    // Group
    inst!( 0xF6, o, 5, 0b0100100000100100, 0x098, TEST  ,  Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0xF6, o, 5, 0b0100100000100100, 0x098, TEST  ,  Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0xF6, o, 5, 0b0100100000100100, 0x098, NOT   ,  Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xF6, o, 5, 0b0100100000100100, 0x098, NEG   ,  Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xF6, o, 5, 0b0100100000100100, 0x098, MUL   ,  Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xF6, o, 5, 0b0100100000100100, 0x098, IMUL  ,  Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xF6, o, 5, 0b0100100000100100, 0x098, DIV   ,  Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xF6, o, 5, 0b0100100000100100, 0x098, IDIV  ,  Ot::ModRM8,                             Ot::NoOperand);
    // Group
    inst!( 0xF7, o, 5, 0b0100100000100100, 0x160, TEST  ,  Ot::ModRM16,                            Ot::Immediate16);
    inst!( 0xF7, o, 5, 0b0100100000100100, 0x160, TEST  ,  Ot::ModRM16,                            Ot::Immediate16);
    inst!( 0xF7, o, 5, 0b0100100000100100, 0x160, NOT   ,  Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xF7, o, 5, 0b0100100000100100, 0x160, NEG   ,  Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xF7, o, 5, 0b0100100000100100, 0x160, MUL   ,  Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xF7, o, 5, 0b0100100000100100, 0x160, IMUL  ,  Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xF7, o, 5, 0b0100100000100100, 0x160, DIV   ,  Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xF7, o, 5, 0b0100100000100100, 0x160, IDIV  ,  Ot::ModRM16,                            Ot::NoOperand);
    // Group
    inst!( 0xFE, o, 6, 0b0000100000100100, 0x020, INC   ,  Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xFE, o, 6, 0b0000100000100100, 0x020, DEC   ,  Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xFE, o, 6, 0b0000100000100100, 0x020, CALL  ,  Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xFE, o, 6, 0b0000100000100100, 0x020, CALLF ,  Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xFE, o, 6, 0b0000100000100100, 0x020, JMP   ,  Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xFE, o, 6, 0b0000100000100100, 0x020, JMPF  ,  Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xFE, o, 6, 0b0000100000100100, 0x020, PUSH  ,  Ot::ModRM8,                             Ot::NoOperand);
    inst!( 0xFE, o, 6, 0b0000100000100100, 0x020, PUSH  ,  Ot::ModRM8,                             Ot::NoOperand);
    // Group
    inst!( 0xFF, o, 6, 0b0000100000100100, 0x026, INC   ,  Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xFF, o, 6, 0b0000100000100100, 0x026, DEC   ,  Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xFF, o, 6, 0b0000100000100100, 0x026, CALL  ,  Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xFF, o, 6, 0b0000100000100100, 0x026, CALLF ,  Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xFF, o, 6, 0b0000100000100100, 0x026, JMP   ,  Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xFF, o, 6, 0b0000100000100100, 0x026, JMPF  ,  Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xFF, o, 6, 0b0000100000100100, 0x026, PUSH  ,  Ot::ModRM16,                            Ot::NoOperand);
    inst!( 0xFF, o, 6, 0b0000100000100100, 0x026, PUSH  ,  Ot::ModRM16,                            Ot::NoOperand);
    // END OF REGULAR INTEL OPCODES (0-367)
    // FF extended opcodes follow. Thankfully, on V20 none of these are group opcodes.
    inst_skip!(o, 16); // Skip 0F00->0F0F
    inst!( 0x10, o, 0, 0b0000100000000000, 0x000, TEST1 ,  Ot::ModRM8,                             Ot::FixedRegister8(Register8::CL));
    inst!( 0x11, o, 0, 0b0000100000000000, 0x000, TEST1 ,  Ot::ModRM16,                            Ot::FixedRegister8(Register8::CL));
    inst!( 0x12, o, 0, 0b0000100000000000, 0x000, CLR1  ,  Ot::ModRM8,                             Ot::FixedRegister8(Register8::CL));
    inst!( 0x13, o, 0, 0b0000100000000000, 0x000, CLR1  ,  Ot::ModRM16,                            Ot::FixedRegister8(Register8::CL));
    inst!( 0x14, o, 0, 0b0000100000000000, 0x000, SET1  ,  Ot::ModRM8,                             Ot::FixedRegister8(Register8::CL));
    inst!( 0x15, o, 0, 0b0000100000000000, 0x000, SET1  ,  Ot::ModRM16,                            Ot::FixedRegister8(Register8::CL));
    inst!( 0x16, o, 0, 0b0000100000000000, 0x000, NOT1  ,  Ot::ModRM8,                             Ot::FixedRegister8(Register8::CL));
    inst!( 0x17, o, 0, 0b0000100000000000, 0x000, NOT1  ,  Ot::ModRM16,                            Ot::FixedRegister8(Register8::CL));
    inst!( 0x18, o, 0, 0b0000100000000000, 0x000, TEST1 ,  Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x19, o, 0, 0b0000100000000000, 0x000, TEST1 ,  Ot::ModRM16,                            Ot::Immediate8);
    inst!( 0x1A, o, 0, 0b0000100000000000, 0x000, CLR1  ,  Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x1B, o, 0, 0b0000100000000000, 0x000, CLR1  ,  Ot::ModRM16,                            Ot::Immediate8);
    inst!( 0x1C, o, 0, 0b0000100000000000, 0x000, SET1  ,  Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x1D, o, 0, 0b0000100000000000, 0x000, SET1  ,  Ot::ModRM16,                            Ot::Immediate8);
    inst!( 0x1E, o, 0, 0b0000100000000000, 0x000, NOT1  ,  Ot::ModRM8,                             Ot::Immediate8);
    inst!( 0x1F, o, 0, 0b0000100000000000, 0x000, NOT1  ,  Ot::ModRM16,                            Ot::Immediate8);
    inst!( 0x20, o, 0, 0b0000100000010000, 0x000, ADD4S ,  Ot::NoOperand,                          Ot::NoOperand);
    inst_skip!(o, 1); // Skip 0x21
    inst!( 0x22, o, 0, 0b0000100000010000, 0x000, SUB4S ,  Ot::NoOperand,                          Ot::NoOperand);
    inst_skip!(o, 3); // Skip 0x23-0x25
    inst!( 0x26, o, 0, 0b0000100000010000, 0x000, CMP4S ,  Ot::NoOperand,                          Ot::NoOperand);
    inst_skip!(o, 1); // Skip 0x27
    inst!( 0x28, o, 0, 0b0000100000000000, 0x000, ROL4  ,  Ot::ModRM8,                             Ot::NoOperand);
    inst_skip!(o, 1); // Skip 0x29
    inst!( 0x2A, o, 0, 0b0000100000000000, 0x000, ROR4  ,  Ot::ModRM8,                             Ot::NoOperand);
    inst_skip!(o, 6); // Skip 0x2B-0x30
    inst!( 0x31, o, 0, 0b0000100000000000, 0x000, BINS  ,  Ot::ModRM8,                             Ot::Register8);
    inst_skip!(o, 1); // Skip 0x32
    inst!( 0x33, o, 0, 0b0000100000000000, 0x000, BEXT  ,  Ot::ModRM8,                             Ot::Register8);
    inst_skip!(o, 5); // Skip 0x34-0x38
    inst!( 0x39, o, 0, 0b0000100000000000, 0x000, BINS  ,  Ot::ModRM8,                             Ot::Immediate8);
    inst_skip!(o, 1); // Skip 0x3A
    inst!( 0x3B, o, 0, 0b0000100000000000, 0x000, BEXT  ,  Ot::ModRM8,                             Ot::Immediate8);
    inst_skip!(o, 195); // Skip 0x3C-0xFE
    inst!( 0xFF, o, 0, 0b0000100000010000, 0x000, BRKEM ,  Ot::Immediate8,                         Ot::NoOperand);

    o.table
};

impl NecVx0 {
    #[rustfmt::skip]
    pub fn decode(bytes: &mut impl ByteReader) -> Result<Instruction, DecodeError> {

        let mut instruction = Instruction::default();

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
        let mut decode_idx: usize = 0;

        let mut op_prefix_ct = 0;
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

                    decode_idx = REGULAR_OPS_LEN;
                    break;
                }
                0x26 => PrefixFlags::ES_OVERRIDE,
                0x2E => PrefixFlags::CS_OVERRIDE,
                0x36 => PrefixFlags::SS_OVERRIDE,
                0x3E => PrefixFlags::DS_OVERRIDE,
                0xF0 => PrefixFlags::LOCK,
                0xF1 => PrefixFlags::LOCK,
                0xF2 => PrefixFlags::REP1,
                0xF3 => PrefixFlags::REP2,
                0x64 => PrefixFlags::REP3,
                0x65 => PrefixFlags::REP4,
                _=> {
                    break;
                }
            };
            op_prefix_ct += 1;

            // ... but only store the last segment override prefix seen
            op_segment_override = match opcode {
                0x26 => Some(Register16::ES),
                0x2E => Some(Register16::CS),
                0x36 => Some(Register16::SS),
                0x3E => Some(Register16::DS),
                _=> op_segment_override
            };

            opcode = match bytes.read_u8() {
                Ok(byte) => {
                    instruction.instruction_bytes.push(byte);
                    byte
                },
                Err(_e) => return Ok(instruction)
            };
        }

        // Lookup the opcode in the decode table
        decode_idx += opcode as usize;
        let mut op_lu = &DECODE[decode_idx];

        // Prepare to read Mod/RM
        let mut displacement = Displacement::NoDisp;

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
                decode_idx = 256 + ((op_lu.grp as usize - 1) * 8) + inner_modrm.op_extension() as usize;
                op_lu = &DECODE[decode_idx];
            }
            Some(inner_modrm)
        }
        else {
            None
        };

        instruction.operand1_type = op_lu.operand1.resolve_operand(bytes, &modrm, displacement, &mut instruction)?;
        instruction.operand2_type = op_lu.operand2.resolve_operand(bytes, &modrm, displacement, &mut instruction)?;
        instruction.operand3_type = op_lu.operand3.resolve_operand(bytes, &modrm, displacement, &mut instruction)?;

        // Set mnemonic from decode table
        instruction.mnemonic = op_lu.mnemonic;

        Ok(instruction)
    }
}
