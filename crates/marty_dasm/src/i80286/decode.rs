// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Daniel Balsom

//! Intel 80286 integer instruction decoder.

use std::io;

use crate::{
    Opcode,
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
    i80286::{Intel80286, gdr::*},
    instruction::Instruction,
    mnemonic::Mnemonic,
    modrm16::ModRmByte16,
};

// Intel 80286/80287 Programmer's Reference Manual, 8086 compatibility notes.
pub const MAX_INSTRUCTION_LENGTH: usize = 10;

#[derive(Copy, Clone, PartialEq)]
enum OperandTemplate {
    NoOperand,
    ModRM8,
    ModRM16,
    Register8,
    Register16,
    SegmentRegister,
    FixedImmediate8(u8),
    Immediate8,
    Immediate16,
    Immediate8SignExtended,
    Relative8,
    Relative16,
    Offset8,
    Offset16,
    FixedRegister8(Register8),
    FixedRegister16(Register16),
    FarAddress,
}

impl OperandTemplate {
    #[inline(always)]
    fn resolve_operand(
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
            OperandTemplate::SegmentRegister => {
                let modrm = modrm.unwrap();
                let reg = if modrm.reg_value() < 4 {
                    modrm.op2_segment_reg16()
                }
                else {
                    Register16::InvalidRegister
                };
                Ok(OperandType::Register16(reg))
            }
            OperandTemplate::FixedImmediate8(value) => Ok(OperandType::Immediate8(*value)),
            OperandTemplate::Immediate8 => {
                let operand = bytes.read_u8()?;
                instruction.instruction_bytes.push(operand);
                instruction.immediate_bytes.push(operand);
                Ok(OperandType::Immediate8(operand))
            }
            OperandTemplate::Immediate16 => {
                let operand = bytes.read_u16()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                Ok(OperandType::Immediate16(operand))
            }
            OperandTemplate::Immediate8SignExtended => {
                let operand = bytes.read_i8()?;
                instruction.instruction_bytes.push(operand as u8);
                instruction.immediate_bytes.push(operand as u8);
                Ok(OperandType::Immediate8s(operand))
            }
            OperandTemplate::Relative8 => {
                let operand = bytes.read_i8()?;
                instruction.instruction_bytes.push(operand as u8);
                instruction.immediate_bytes.push(operand as u8);
                Ok(OperandType::Relative8(operand))
            }
            OperandTemplate::Relative16 => {
                let operand = bytes.read_i16()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                Ok(OperandType::Relative16(operand))
            }
            OperandTemplate::Offset8 => {
                let operand = bytes.read_u16()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                Ok(OperandType::Offset8_16(operand))
            }
            OperandTemplate::Offset16 => {
                let operand = bytes.read_u16()?;
                instruction.instruction_bytes.extend_from_slice(&operand.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&operand.to_le_bytes());
                Ok(OperandType::Offset16_16(operand))
            }
            OperandTemplate::FixedRegister8(r8) => Ok(OperandType::Register8(*r8)),
            OperandTemplate::FixedRegister16(r16) => Ok(OperandType::Register16(*r16)),
            OperandTemplate::FarAddress => {
                let offset = bytes.read_u16()?;
                let segment = bytes.read_u16()?;
                instruction.instruction_bytes.extend_from_slice(&offset.to_le_bytes());
                instruction.instruction_bytes.extend_from_slice(&segment.to_le_bytes());

                instruction.immediate_bytes.extend_from_slice(&offset.to_le_bytes());
                instruction.immediate_bytes.extend_from_slice(&segment.to_le_bytes());
                Ok(OperandType::FarPointer16(segment, offset))
            }
            OperandTemplate::NoOperand => Ok(OperandType::NoOperand),
        }
    }
}

type Ot = OperandTemplate;

#[derive(Copy, Clone)]
struct InstTemplate {
    grp: u8,
    gdr: GdrEntry,
    mnemonic: Mnemonic,
    operand1: OperandTemplate,
    operand2: OperandTemplate,
    operand3: OperandTemplate,
}

const INVALID: InstTemplate = InstTemplate {
    grp: 0,
    gdr: GdrEntry(GDR_NO_MODRM),
    mnemonic: Mnemonic::Invalid,
    operand1: Ot::NoOperand,
    operand2: Ot::NoOperand,
    operand3: Ot::NoOperand,
};

macro_rules! inst {
    ($op:literal, $grp:literal, $gdr:expr, $m:ident, $o1:expr, $o2:expr) => {
        inst!($op, $grp, $gdr, $m, $o1, $o2, Ot::NoOperand)
    };
    ($op:literal, $grp:literal, $gdr:expr, $m:ident, $o1:expr, $o2:expr, $o3:expr) => {
        InstTemplate {
            grp: $grp,
            gdr: GdrEntry($gdr),
            mnemonic: Mnemonic::$m,
            operand1: $o1,
            operand2: $o2,
            operand3: $o3,
        }
    };
}

// The first 256 entries are indexed by opcode; each group adds eight entries
// indexed by the ModR/M reg field, following the 80386 table layout.
#[rustfmt::skip]
static DECODE: [InstTemplate; 256 + 14 * 8] = [
    inst!( 0x00,  0, 0,                                  ADD,       Ot::ModRM8,                          Ot::Register8),
    inst!( 0x01,  0, 0,                                  ADD,       Ot::ModRM16,                         Ot::Register16),
    inst!( 0x02,  0, 0,                                  ADD,       Ot::Register8,                       Ot::ModRM8),
    inst!( 0x03,  0, 0,                                  ADD,       Ot::Register16,                      Ot::ModRM16),
    inst!( 0x04,  0, GDR_NO_MODRM,                       ADD,       Ot::FixedRegister8(Register8::AL),   Ot::Immediate8),
    inst!( 0x05,  0, GDR_NO_MODRM,                       ADD,       Ot::FixedRegister16(Register16::AX), Ot::Immediate16),
    inst!( 0x06,  0, GDR_NO_MODRM,                       PUSH,      Ot::FixedRegister16(Register16::ES), Ot::NoOperand),
    inst!( 0x07,  0, GDR_NO_MODRM,                       POP,       Ot::FixedRegister16(Register16::ES), Ot::NoOperand),
    inst!( 0x08,  0, 0,                                  OR,        Ot::ModRM8,                          Ot::Register8),
    inst!( 0x09,  0, 0,                                  OR,        Ot::ModRM16,                         Ot::Register16),
    inst!( 0x0A,  0, 0,                                  OR,        Ot::Register8,                       Ot::ModRM8),
    inst!( 0x0B,  0, 0,                                  OR,        Ot::Register16,                      Ot::ModRM16),
    inst!( 0x0C,  0, GDR_NO_MODRM,                       OR,        Ot::FixedRegister8(Register8::AL),   Ot::Immediate8),
    inst!( 0x0D,  0, GDR_NO_MODRM,                       OR,        Ot::FixedRegister16(Register16::AX), Ot::Immediate16),
    inst!( 0x0E,  0, GDR_NO_MODRM,                       PUSH,      Ot::FixedRegister16(Register16::CS), Ot::NoOperand),
    inst!( 0x0F,  0, 0,                                  Extension, Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x10,  0, 0,                                  ADC,       Ot::ModRM8,                          Ot::Register8),
    inst!( 0x11,  0, 0,                                  ADC,       Ot::ModRM16,                         Ot::Register16),
    inst!( 0x12,  0, 0,                                  ADC,       Ot::Register8,                       Ot::ModRM8),
    inst!( 0x13,  0, 0,                                  ADC,       Ot::Register16,                      Ot::ModRM16),
    inst!( 0x14,  0, GDR_NO_MODRM,                       ADC,       Ot::FixedRegister8(Register8::AL),   Ot::Immediate8),
    inst!( 0x15,  0, GDR_NO_MODRM,                       ADC,       Ot::FixedRegister16(Register16::AX), Ot::Immediate16),
    inst!( 0x16,  0, GDR_NO_MODRM,                       PUSH,      Ot::FixedRegister16(Register16::SS), Ot::NoOperand),
    inst!( 0x17,  0, GDR_NO_MODRM,                       POP,       Ot::FixedRegister16(Register16::SS), Ot::NoOperand),
    inst!( 0x18,  0, 0,                                  SBB,       Ot::ModRM8,                          Ot::Register8),
    inst!( 0x19,  0, 0,                                  SBB,       Ot::ModRM16,                         Ot::Register16),
    inst!( 0x1A,  0, 0,                                  SBB,       Ot::Register8,                       Ot::ModRM8),
    inst!( 0x1B,  0, 0,                                  SBB,       Ot::Register16,                      Ot::ModRM16),
    inst!( 0x1C,  0, GDR_NO_MODRM,                       SBB,       Ot::FixedRegister8(Register8::AL),   Ot::Immediate8),
    inst!( 0x1D,  0, GDR_NO_MODRM,                       SBB,       Ot::FixedRegister16(Register16::AX), Ot::Immediate16),
    inst!( 0x1E,  0, GDR_NO_MODRM,                       PUSH,      Ot::FixedRegister16(Register16::DS), Ot::NoOperand),
    inst!( 0x1F,  0, GDR_NO_MODRM,                       POP,       Ot::FixedRegister16(Register16::DS), Ot::NoOperand),
    inst!( 0x20,  0, 0,                                  AND,       Ot::ModRM8,                          Ot::Register8),
    inst!( 0x21,  0, 0,                                  AND,       Ot::ModRM16,                         Ot::Register16),
    inst!( 0x22,  0, 0,                                  AND,       Ot::Register8,                       Ot::ModRM8),
    inst!( 0x23,  0, 0,                                  AND,       Ot::Register16,                      Ot::ModRM16),
    inst!( 0x24,  0, GDR_NO_MODRM,                       AND,       Ot::FixedRegister8(Register8::AL),   Ot::Immediate8),
    inst!( 0x25,  0, GDR_NO_MODRM,                       AND,       Ot::FixedRegister16(Register16::AX), Ot::Immediate16),
    inst!( 0x26,  0, GDR_NO_MODRM,                       Prefix,    Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x27,  0, GDR_NO_MODRM,                       DAA,       Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x28,  0, 0,                                  SUB,       Ot::ModRM8,                          Ot::Register8),
    inst!( 0x29,  0, 0,                                  SUB,       Ot::ModRM16,                         Ot::Register16),
    inst!( 0x2A,  0, 0,                                  SUB,       Ot::Register8,                       Ot::ModRM8),
    inst!( 0x2B,  0, 0,                                  SUB,       Ot::Register16,                      Ot::ModRM16),
    inst!( 0x2C,  0, GDR_NO_MODRM,                       SUB,       Ot::FixedRegister8(Register8::AL),   Ot::Immediate8),
    inst!( 0x2D,  0, GDR_NO_MODRM,                       SUB,       Ot::FixedRegister16(Register16::AX), Ot::Immediate16),
    inst!( 0x2E,  0, GDR_NO_MODRM,                       Prefix,    Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x2F,  0, GDR_NO_MODRM,                       DAS,       Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x30,  0, 0,                                  XOR,       Ot::ModRM8,                          Ot::Register8),
    inst!( 0x31,  0, 0,                                  XOR,       Ot::ModRM16,                         Ot::Register16),
    inst!( 0x32,  0, 0,                                  XOR,       Ot::Register8,                       Ot::ModRM8),
    inst!( 0x33,  0, 0,                                  XOR,       Ot::Register16,                      Ot::ModRM16),
    inst!( 0x34,  0, GDR_NO_MODRM,                       XOR,       Ot::FixedRegister8(Register8::AL),   Ot::Immediate8),
    inst!( 0x35,  0, GDR_NO_MODRM,                       XOR,       Ot::FixedRegister16(Register16::AX), Ot::Immediate16),
    inst!( 0x36,  0, GDR_NO_MODRM,                       Prefix,    Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x37,  0, GDR_NO_MODRM,                       AAA,       Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x38,  0, 0,                                  CMP,       Ot::ModRM8,                          Ot::Register8),
    inst!( 0x39,  0, 0,                                  CMP,       Ot::ModRM16,                         Ot::Register16),
    inst!( 0x3A,  0, 0,                                  CMP,       Ot::Register8,                       Ot::ModRM8),
    inst!( 0x3B,  0, 0,                                  CMP,       Ot::Register16,                      Ot::ModRM16),
    inst!( 0x3C,  0, GDR_NO_MODRM,                       CMP,       Ot::FixedRegister8(Register8::AL),   Ot::Immediate8),
    inst!( 0x3D,  0, GDR_NO_MODRM,                       CMP,       Ot::FixedRegister16(Register16::AX), Ot::Immediate16),
    inst!( 0x3E,  0, GDR_NO_MODRM,                       Prefix,    Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x3F,  0, GDR_NO_MODRM,                       AAS,       Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x40,  0, GDR_NO_MODRM,                       INC,       Ot::FixedRegister16(Register16::AX), Ot::NoOperand),
    inst!( 0x41,  0, GDR_NO_MODRM,                       INC,       Ot::FixedRegister16(Register16::CX), Ot::NoOperand),
    inst!( 0x42,  0, GDR_NO_MODRM,                       INC,       Ot::FixedRegister16(Register16::DX), Ot::NoOperand),
    inst!( 0x43,  0, GDR_NO_MODRM,                       INC,       Ot::FixedRegister16(Register16::BX), Ot::NoOperand),
    inst!( 0x44,  0, GDR_NO_MODRM,                       INC,       Ot::FixedRegister16(Register16::SP), Ot::NoOperand),
    inst!( 0x45,  0, GDR_NO_MODRM,                       INC,       Ot::FixedRegister16(Register16::BP), Ot::NoOperand),
    inst!( 0x46,  0, GDR_NO_MODRM,                       INC,       Ot::FixedRegister16(Register16::SI), Ot::NoOperand),
    inst!( 0x47,  0, GDR_NO_MODRM,                       INC,       Ot::FixedRegister16(Register16::DI), Ot::NoOperand),
    inst!( 0x48,  0, GDR_NO_MODRM,                       DEC,       Ot::FixedRegister16(Register16::AX), Ot::NoOperand),
    inst!( 0x49,  0, GDR_NO_MODRM,                       DEC,       Ot::FixedRegister16(Register16::CX), Ot::NoOperand),
    inst!( 0x4A,  0, GDR_NO_MODRM,                       DEC,       Ot::FixedRegister16(Register16::DX), Ot::NoOperand),
    inst!( 0x4B,  0, GDR_NO_MODRM,                       DEC,       Ot::FixedRegister16(Register16::BX), Ot::NoOperand),
    inst!( 0x4C,  0, GDR_NO_MODRM,                       DEC,       Ot::FixedRegister16(Register16::SP), Ot::NoOperand),
    inst!( 0x4D,  0, GDR_NO_MODRM,                       DEC,       Ot::FixedRegister16(Register16::BP), Ot::NoOperand),
    inst!( 0x4E,  0, GDR_NO_MODRM,                       DEC,       Ot::FixedRegister16(Register16::SI), Ot::NoOperand),
    inst!( 0x4F,  0, GDR_NO_MODRM,                       DEC,       Ot::FixedRegister16(Register16::DI), Ot::NoOperand),
    inst!( 0x50,  0, GDR_NO_MODRM,                       PUSH,      Ot::FixedRegister16(Register16::AX), Ot::NoOperand),
    inst!( 0x51,  0, GDR_NO_MODRM,                       PUSH,      Ot::FixedRegister16(Register16::CX), Ot::NoOperand),
    inst!( 0x52,  0, GDR_NO_MODRM,                       PUSH,      Ot::FixedRegister16(Register16::DX), Ot::NoOperand),
    inst!( 0x53,  0, GDR_NO_MODRM,                       PUSH,      Ot::FixedRegister16(Register16::BX), Ot::NoOperand),
    inst!( 0x54,  0, GDR_NO_MODRM,                       PUSH,      Ot::FixedRegister16(Register16::SP), Ot::NoOperand),
    inst!( 0x55,  0, GDR_NO_MODRM,                       PUSH,      Ot::FixedRegister16(Register16::BP), Ot::NoOperand),
    inst!( 0x56,  0, GDR_NO_MODRM,                       PUSH,      Ot::FixedRegister16(Register16::SI), Ot::NoOperand),
    inst!( 0x57,  0, GDR_NO_MODRM,                       PUSH,      Ot::FixedRegister16(Register16::DI), Ot::NoOperand),
    inst!( 0x58,  0, GDR_NO_MODRM,                       POP,       Ot::FixedRegister16(Register16::AX), Ot::NoOperand),
    inst!( 0x59,  0, GDR_NO_MODRM,                       POP,       Ot::FixedRegister16(Register16::CX), Ot::NoOperand),
    inst!( 0x5A,  0, GDR_NO_MODRM,                       POP,       Ot::FixedRegister16(Register16::DX), Ot::NoOperand),
    inst!( 0x5B,  0, GDR_NO_MODRM,                       POP,       Ot::FixedRegister16(Register16::BX), Ot::NoOperand),
    inst!( 0x5C,  0, GDR_NO_MODRM,                       POP,       Ot::FixedRegister16(Register16::SP), Ot::NoOperand),
    inst!( 0x5D,  0, GDR_NO_MODRM,                       POP,       Ot::FixedRegister16(Register16::BP), Ot::NoOperand),
    inst!( 0x5E,  0, GDR_NO_MODRM,                       POP,       Ot::FixedRegister16(Register16::SI), Ot::NoOperand),
    inst!( 0x5F,  0, GDR_NO_MODRM,                       POP,       Ot::FixedRegister16(Register16::DI), Ot::NoOperand),
    inst!( 0x60,  0, GDR_NO_MODRM,                       PUSHA,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x61,  0, GDR_NO_MODRM,                       POPA,      Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x62,  0, GDR_NO_REG_FORM,                    BOUND,     Ot::Register16,                      Ot::ModRM16),
    inst!( 0x63,  0, 0,                                  ARPL,      Ot::ModRM16,                         Ot::Register16),
    inst!( 0x64,  0, GDR_NO_MODRM,                       Invalid,   Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x65,  0, GDR_NO_MODRM,                       Invalid,   Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x66,  0, GDR_NO_MODRM,                       Invalid,   Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x67,  0, GDR_NO_MODRM,                       Invalid,   Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x68,  0, GDR_NO_MODRM,                       PUSH,      Ot::Immediate16,                     Ot::NoOperand),
    inst!( 0x69,  0, 0,                                  IMUL,      Ot::Register16,                      Ot::ModRM16,                         Ot::Immediate16),
    inst!( 0x6A,  0, GDR_NO_MODRM,                       PUSH,      Ot::Immediate8SignExtended,          Ot::NoOperand),
    inst!( 0x6B,  0, 0,                                  IMUL,      Ot::Register16,                      Ot::ModRM16,                         Ot::Immediate8SignExtended),
    inst!( 0x6C,  0, GDR_NO_MODRM,                       INSB,      Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x6D,  0, GDR_NO_MODRM,                       INSW,      Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x6E,  0, GDR_NO_MODRM,                       OUTSB,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x6F,  0, GDR_NO_MODRM,                       OUTSW,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x70,  0, GDR_NO_MODRM | GDR_DISAMBIGUATE,    JO,        Ot::Relative8,                       Ot::NoOperand),
    inst!( 0x71,  0, GDR_NO_MODRM | GDR_DISAMBIGUATE,    JNO,       Ot::Relative8,                       Ot::NoOperand),
    inst!( 0x72,  0, GDR_NO_MODRM | GDR_DISAMBIGUATE,    JB,        Ot::Relative8,                       Ot::NoOperand),
    inst!( 0x73,  0, GDR_NO_MODRM | GDR_DISAMBIGUATE,    JNB,       Ot::Relative8,                       Ot::NoOperand),
    inst!( 0x74,  0, GDR_NO_MODRM | GDR_DISAMBIGUATE,    JZ,        Ot::Relative8,                       Ot::NoOperand),
    inst!( 0x75,  0, GDR_NO_MODRM | GDR_DISAMBIGUATE,    JNZ,       Ot::Relative8,                       Ot::NoOperand),
    inst!( 0x76,  0, GDR_NO_MODRM | GDR_DISAMBIGUATE,    JBE,       Ot::Relative8,                       Ot::NoOperand),
    inst!( 0x77,  0, GDR_NO_MODRM | GDR_DISAMBIGUATE,    JNBE,      Ot::Relative8,                       Ot::NoOperand),
    inst!( 0x78,  0, GDR_NO_MODRM | GDR_DISAMBIGUATE,    JS,        Ot::Relative8,                       Ot::NoOperand),
    inst!( 0x79,  0, GDR_NO_MODRM | GDR_DISAMBIGUATE,    JNS,       Ot::Relative8,                       Ot::NoOperand),
    inst!( 0x7A,  0, GDR_NO_MODRM | GDR_DISAMBIGUATE,    JP,        Ot::Relative8,                       Ot::NoOperand),
    inst!( 0x7B,  0, GDR_NO_MODRM | GDR_DISAMBIGUATE,    JNP,       Ot::Relative8,                       Ot::NoOperand),
    inst!( 0x7C,  0, GDR_NO_MODRM | GDR_DISAMBIGUATE,    JL,        Ot::Relative8,                       Ot::NoOperand),
    inst!( 0x7D,  0, GDR_NO_MODRM | GDR_DISAMBIGUATE,    JNL,       Ot::Relative8,                       Ot::NoOperand),
    inst!( 0x7E,  0, GDR_NO_MODRM | GDR_DISAMBIGUATE,    JLE,       Ot::Relative8,                       Ot::NoOperand),
    inst!( 0x7F,  0, GDR_NO_MODRM | GDR_DISAMBIGUATE,    JNLE,      Ot::Relative8,                       Ot::NoOperand),
    inst!( 0x80,  1, 0,                                  Group,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x81,  2, 0,                                  Group,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x82,  3, 0,                                  Group,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x83,  4, 0,                                  Group,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x84,  0, 0,                                  TEST,      Ot::ModRM8,                          Ot::Register8),
    inst!( 0x85,  0, 0,                                  TEST,      Ot::ModRM16,                         Ot::Register16),
    inst!( 0x86,  0, 0,                                  XCHG,      Ot::Register8,                       Ot::ModRM8),
    inst!( 0x87,  0, 0,                                  XCHG,      Ot::Register16,                      Ot::ModRM16),
    inst!( 0x88,  0, 0,                                  MOV,       Ot::ModRM8,                          Ot::Register8),
    inst!( 0x89,  0, 0,                                  MOV,       Ot::ModRM16,                         Ot::Register16),
    inst!( 0x8A,  0, 0,                                  MOV,       Ot::Register8,                       Ot::ModRM8),
    inst!( 0x8B,  0, 0,                                  MOV,       Ot::Register16,                      Ot::ModRM16),
    inst!( 0x8C,  0, GDR_USES_SREG,                      MOV,       Ot::ModRM16,                         Ot::SegmentRegister),
    inst!( 0x8D,  0, GDR_NO_REG_FORM,                    LEA,       Ot::Register16,                      Ot::ModRM16),
    inst!( 0x8E,  0, GDR_USES_SREG,                      MOV,       Ot::SegmentRegister,                 Ot::ModRM16),
    inst!( 0x8F,  0, GDR_REG_0 | GDR_DISAMBIGUATE,       POP,       Ot::ModRM16,                         Ot::NoOperand),
    inst!( 0x90,  0, GDR_NO_MODRM,                       NOP,       Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x91,  0, GDR_NO_MODRM,                       XCHG,      Ot::FixedRegister16(Register16::CX), Ot::FixedRegister16(Register16::AX)),
    inst!( 0x92,  0, GDR_NO_MODRM,                       XCHG,      Ot::FixedRegister16(Register16::DX), Ot::FixedRegister16(Register16::AX)),
    inst!( 0x93,  0, GDR_NO_MODRM,                       XCHG,      Ot::FixedRegister16(Register16::BX), Ot::FixedRegister16(Register16::AX)),
    inst!( 0x94,  0, GDR_NO_MODRM,                       XCHG,      Ot::FixedRegister16(Register16::SP), Ot::FixedRegister16(Register16::AX)),
    inst!( 0x95,  0, GDR_NO_MODRM,                       XCHG,      Ot::FixedRegister16(Register16::BP), Ot::FixedRegister16(Register16::AX)),
    inst!( 0x96,  0, GDR_NO_MODRM,                       XCHG,      Ot::FixedRegister16(Register16::SI), Ot::FixedRegister16(Register16::AX)),
    inst!( 0x97,  0, GDR_NO_MODRM,                       XCHG,      Ot::FixedRegister16(Register16::DI), Ot::FixedRegister16(Register16::AX)),
    inst!( 0x98,  0, GDR_NO_MODRM,                       CBW,       Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x99,  0, GDR_NO_MODRM,                       CWD,       Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x9A,  0, GDR_NO_MODRM,                       CALLF,     Ot::FarAddress,                      Ot::NoOperand),
    inst!( 0x9B,  0, GDR_NO_MODRM,                       WAIT,      Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x9C,  0, GDR_NO_MODRM,                       PUSHF,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x9D,  0, GDR_NO_MODRM,                       POPF,      Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x9E,  0, GDR_NO_MODRM,                       SAHF,      Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0x9F,  0, GDR_NO_MODRM,                       LAHF,      Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xA0,  0, GDR_NO_MODRM,                       MOV,       Ot::FixedRegister8(Register8::AL),   Ot::Offset8),
    inst!( 0xA1,  0, GDR_NO_MODRM,                       MOV,       Ot::FixedRegister16(Register16::AX), Ot::Offset16),
    inst!( 0xA2,  0, GDR_NO_MODRM,                       MOV,       Ot::Offset8,                         Ot::FixedRegister8(Register8::AL)),
    inst!( 0xA3,  0, GDR_NO_MODRM,                       MOV,       Ot::Offset16,                        Ot::FixedRegister16(Register16::AX)),
    inst!( 0xA4,  0, GDR_NO_MODRM,                       MOVSB,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xA5,  0, GDR_NO_MODRM,                       MOVSW,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xA6,  0, GDR_NO_MODRM,                       CMPSB,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xA7,  0, GDR_NO_MODRM,                       CMPSW,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xA8,  0, GDR_NO_MODRM,                       TEST,      Ot::FixedRegister8(Register8::AL),   Ot::Immediate8),
    inst!( 0xA9,  0, GDR_NO_MODRM,                       TEST,      Ot::FixedRegister16(Register16::AX), Ot::Immediate16),
    inst!( 0xAA,  0, GDR_NO_MODRM,                       STOSB,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xAB,  0, GDR_NO_MODRM,                       STOSW,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xAC,  0, GDR_NO_MODRM,                       LODSB,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xAD,  0, GDR_NO_MODRM,                       LODSW,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xAE,  0, GDR_NO_MODRM,                       SCASB,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xAF,  0, GDR_NO_MODRM,                       SCASW,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xB0,  0, GDR_NO_MODRM,                       MOV,       Ot::FixedRegister8(Register8::AL),   Ot::Immediate8),
    inst!( 0xB1,  0, GDR_NO_MODRM,                       MOV,       Ot::FixedRegister8(Register8::CL),   Ot::Immediate8),
    inst!( 0xB2,  0, GDR_NO_MODRM,                       MOV,       Ot::FixedRegister8(Register8::DL),   Ot::Immediate8),
    inst!( 0xB3,  0, GDR_NO_MODRM,                       MOV,       Ot::FixedRegister8(Register8::BL),   Ot::Immediate8),
    inst!( 0xB4,  0, GDR_NO_MODRM,                       MOV,       Ot::FixedRegister8(Register8::AH),   Ot::Immediate8),
    inst!( 0xB5,  0, GDR_NO_MODRM,                       MOV,       Ot::FixedRegister8(Register8::CH),   Ot::Immediate8),
    inst!( 0xB6,  0, GDR_NO_MODRM,                       MOV,       Ot::FixedRegister8(Register8::DH),   Ot::Immediate8),
    inst!( 0xB7,  0, GDR_NO_MODRM,                       MOV,       Ot::FixedRegister8(Register8::BH),   Ot::Immediate8),
    inst!( 0xB8,  0, GDR_NO_MODRM,                       MOV,       Ot::FixedRegister16(Register16::AX), Ot::Immediate16),
    inst!( 0xB9,  0, GDR_NO_MODRM,                       MOV,       Ot::FixedRegister16(Register16::CX), Ot::Immediate16),
    inst!( 0xBA,  0, GDR_NO_MODRM,                       MOV,       Ot::FixedRegister16(Register16::DX), Ot::Immediate16),
    inst!( 0xBB,  0, GDR_NO_MODRM,                       MOV,       Ot::FixedRegister16(Register16::BX), Ot::Immediate16),
    inst!( 0xBC,  0, GDR_NO_MODRM,                       MOV,       Ot::FixedRegister16(Register16::SP), Ot::Immediate16),
    inst!( 0xBD,  0, GDR_NO_MODRM,                       MOV,       Ot::FixedRegister16(Register16::BP), Ot::Immediate16),
    inst!( 0xBE,  0, GDR_NO_MODRM,                       MOV,       Ot::FixedRegister16(Register16::SI), Ot::Immediate16),
    inst!( 0xBF,  0, GDR_NO_MODRM,                       MOV,       Ot::FixedRegister16(Register16::DI), Ot::Immediate16),
    inst!( 0xC0,  5, GDR_NO_MODRM,                       Group,     Ot::Immediate16,                     Ot::NoOperand),
    inst!( 0xC1,  6, GDR_NO_MODRM,                       Group,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xC2,  0, GDR_NO_MODRM,                       RET,       Ot::Immediate16,                     Ot::NoOperand),
    inst!( 0xC3,  0, GDR_NO_MODRM,                       RET,       Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xC4,  0, GDR_NO_REG_FORM,                    LES,       Ot::Register16,                      Ot::ModRM16),
    inst!( 0xC5,  0, GDR_NO_REG_FORM,                    LDS,       Ot::Register16,                      Ot::ModRM16),
    inst!( 0xC6,  0, GDR_REG_0 | GDR_DISAMBIGUATE,       MOV,       Ot::ModRM8,                          Ot::Immediate8),
    inst!( 0xC7,  0, GDR_REG_0 | GDR_DISAMBIGUATE,       MOV,       Ot::ModRM16,                         Ot::Immediate16),
    inst!( 0xC8,  0, GDR_NO_MODRM,                       ENTER,     Ot::Immediate16,                     Ot::Immediate8),
    inst!( 0xC9,  0, GDR_NO_MODRM,                       LEAVE,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xCA,  0, GDR_NO_MODRM,                       RETF,      Ot::Immediate16,                     Ot::NoOperand),
    inst!( 0xCB,  0, GDR_NO_MODRM,                       RETF,      Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xCC,  0, GDR_NO_MODRM,                       INT3,      Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xCD,  0, GDR_NO_MODRM,                       INT,       Ot::Immediate8,                      Ot::NoOperand),
    inst!( 0xCE,  0, GDR_NO_MODRM,                       INTO,      Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xCF,  0, GDR_NO_MODRM,                       IRET,      Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xD0,  7, 0,                                  Group,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xD1,  8, 0,                                  Group,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xD2,  9, 0,                                  Group,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xD3, 10, 0,                                  Group,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xD4,  0, GDR_NO_MODRM,                       AAM,       Ot::Immediate8,                      Ot::NoOperand),
    inst!( 0xD5,  0, GDR_NO_MODRM,                       AAD,       Ot::Immediate8,                      Ot::NoOperand),
    inst!( 0xD6,  0, GDR_NO_MODRM,                       SALC,      Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xD7,  0, GDR_NO_MODRM,                       XLAT,      Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xD8,  0, 0,                                  ESC,       Ot::ModRM16,                         Ot::NoOperand),
    inst!( 0xD9,  0, 0,                                  ESC,       Ot::ModRM16,                         Ot::NoOperand),
    inst!( 0xDA,  0, 0,                                  ESC,       Ot::ModRM16,                         Ot::NoOperand),
    inst!( 0xDB,  0, 0,                                  ESC,       Ot::ModRM16,                         Ot::NoOperand),
    inst!( 0xDC,  0, 0,                                  ESC,       Ot::ModRM16,                         Ot::NoOperand),
    inst!( 0xDD,  0, 0,                                  ESC,       Ot::ModRM16,                         Ot::NoOperand),
    inst!( 0xDE,  0, 0,                                  ESC,       Ot::ModRM16,                         Ot::NoOperand),
    inst!( 0xDF,  0, 0,                                  ESC,       Ot::ModRM16,                         Ot::NoOperand),
    inst!( 0xE0,  0, GDR_NO_MODRM,                       LOOPNE,    Ot::Relative8,                       Ot::NoOperand),
    inst!( 0xE1,  0, GDR_NO_MODRM,                       LOOPE,     Ot::Relative8,                       Ot::NoOperand),
    inst!( 0xE2,  0, GDR_NO_MODRM,                       LOOP,      Ot::Relative8,                       Ot::NoOperand),
    inst!( 0xE3,  0, GDR_NO_MODRM,                       JCXZ,      Ot::Relative8,                       Ot::NoOperand),
    inst!( 0xE4,  0, GDR_NO_MODRM,                       IN,        Ot::FixedRegister8(Register8::AL),   Ot::Immediate8),
    inst!( 0xE5,  0, GDR_NO_MODRM,                       IN,        Ot::FixedRegister16(Register16::AX), Ot::Immediate8),
    inst!( 0xE6,  0, GDR_NO_MODRM,                       OUT,       Ot::Immediate8,                      Ot::FixedRegister8(Register8::AL)),
    inst!( 0xE7,  0, GDR_NO_MODRM,                       OUT,       Ot::Immediate8,                      Ot::FixedRegister16(Register16::AX)),
    inst!( 0xE8,  0, GDR_NO_MODRM | GDR_DISAMBIGUATE,    CALL,      Ot::Relative16,                      Ot::NoOperand),
    inst!( 0xE9,  0, GDR_NO_MODRM | GDR_DISAMBIGUATE,    JMP,       Ot::Relative16,                      Ot::NoOperand),
    inst!( 0xEA,  0, GDR_NO_MODRM,                       JMPF,      Ot::FarAddress,                      Ot::NoOperand),
    inst!( 0xEB,  0, GDR_NO_MODRM | GDR_DISAMBIGUATE,    JMP,       Ot::Relative8,                       Ot::NoOperand),
    inst!( 0xEC,  0, GDR_NO_MODRM,                       IN,        Ot::FixedRegister8(Register8::AL),   Ot::FixedRegister16(Register16::DX)),
    inst!( 0xED,  0, GDR_NO_MODRM,                       IN,        Ot::FixedRegister16(Register16::AX), Ot::FixedRegister16(Register16::DX)),
    inst!( 0xEE,  0, GDR_NO_MODRM,                       OUT,       Ot::FixedRegister16(Register16::DX), Ot::FixedRegister8(Register8::AL)),
    inst!( 0xEF,  0, GDR_NO_MODRM,                       OUT,       Ot::FixedRegister16(Register16::DX), Ot::FixedRegister16(Register16::AX)),
    inst!( 0xF0,  0, GDR_NO_MODRM,                       LOCK,      Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xF1,  0, GDR_NO_MODRM,                       Prefix,    Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xF2,  0, GDR_NO_MODRM,                       Prefix,    Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xF3,  0, GDR_NO_MODRM,                       Prefix,    Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xF4,  0, GDR_NO_MODRM,                       HLT,       Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xF5,  0, GDR_NO_MODRM,                       CMC,       Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xF6, 11, GDR_REG_0,                          Group,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xF7, 12, GDR_REG_0,                          Group,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xF8,  0, GDR_NO_MODRM,                       CLC,       Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xF9,  0, GDR_NO_MODRM,                       STC,       Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xFA,  0, GDR_NO_MODRM,                       CLI,       Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xFB,  0, GDR_NO_MODRM,                       STI,       Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xFC,  0, GDR_NO_MODRM,                       CLD,       Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xFD,  0, GDR_NO_MODRM,                       STD,       Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xFE, 13, 0,                                  Group,     Ot::NoOperand,                       Ot::NoOperand),
    inst!( 0xFF, 14, 0,                                  Group,     Ot::NoOperand,                       Ot::NoOperand),
    // Group 1: 0x80 /0-/7
    inst!( 0x80,  0, GDR_DISAMBIGUATE,                   ADD,       Ot::ModRM8,                          Ot::Immediate8),
    inst!( 0x80,  0, GDR_DISAMBIGUATE,                   OR,        Ot::ModRM8,                          Ot::Immediate8),
    inst!( 0x80,  0, GDR_DISAMBIGUATE,                   ADC,       Ot::ModRM8,                          Ot::Immediate8),
    inst!( 0x80,  0, GDR_DISAMBIGUATE,                   SBB,       Ot::ModRM8,                          Ot::Immediate8),
    inst!( 0x80,  0, GDR_DISAMBIGUATE,                   AND,       Ot::ModRM8,                          Ot::Immediate8),
    inst!( 0x80,  0, GDR_DISAMBIGUATE,                   SUB,       Ot::ModRM8,                          Ot::Immediate8),
    inst!( 0x80,  0, GDR_DISAMBIGUATE,                   XOR,       Ot::ModRM8,                          Ot::Immediate8),
    inst!( 0x80,  0, GDR_DISAMBIGUATE,                   CMP,       Ot::ModRM8,                          Ot::Immediate8),
    // Group 2: 0x81 /0-/7
    inst!( 0x81,  0, GDR_DISAMBIGUATE,                   ADD,       Ot::ModRM16,                         Ot::Immediate16),
    inst!( 0x81,  0, GDR_DISAMBIGUATE,                   OR,        Ot::ModRM16,                         Ot::Immediate16),
    inst!( 0x81,  0, GDR_DISAMBIGUATE,                   ADC,       Ot::ModRM16,                         Ot::Immediate16),
    inst!( 0x81,  0, GDR_DISAMBIGUATE,                   SBB,       Ot::ModRM16,                         Ot::Immediate16),
    inst!( 0x81,  0, GDR_DISAMBIGUATE,                   AND,       Ot::ModRM16,                         Ot::Immediate16),
    inst!( 0x81,  0, GDR_DISAMBIGUATE,                   SUB,       Ot::ModRM16,                         Ot::Immediate16),
    inst!( 0x81,  0, GDR_DISAMBIGUATE,                   XOR,       Ot::ModRM16,                         Ot::Immediate16),
    inst!( 0x81,  0, GDR_DISAMBIGUATE,                   CMP,       Ot::ModRM16,                         Ot::Immediate16),
    // Group 3: 0x82 /0-/7
    inst!( 0x82,  0, GDR_DISAMBIGUATE,                   ADD,       Ot::ModRM8,                          Ot::Immediate8),
    inst!( 0x82,  0, GDR_DISAMBIGUATE,                   OR,        Ot::ModRM8,                          Ot::Immediate8),
    inst!( 0x82,  0, GDR_DISAMBIGUATE,                   ADC,       Ot::ModRM8,                          Ot::Immediate8),
    inst!( 0x82,  0, GDR_DISAMBIGUATE,                   SBB,       Ot::ModRM8,                          Ot::Immediate8),
    inst!( 0x82,  0, GDR_DISAMBIGUATE,                   AND,       Ot::ModRM8,                          Ot::Immediate8),
    inst!( 0x82,  0, GDR_DISAMBIGUATE,                   SUB,       Ot::ModRM8,                          Ot::Immediate8),
    inst!( 0x82,  0, GDR_DISAMBIGUATE,                   XOR,       Ot::ModRM8,                          Ot::Immediate8),
    inst!( 0x82,  0, GDR_DISAMBIGUATE,                   CMP,       Ot::ModRM8,                          Ot::Immediate8),
    // Group 4: 0x83 /0-/7
    inst!( 0x83,  0, GDR_DISAMBIGUATE,                   ADD,       Ot::ModRM16,                         Ot::Immediate8SignExtended),
    inst!( 0x83,  0, GDR_DISAMBIGUATE,                   OR,        Ot::ModRM16,                         Ot::Immediate8SignExtended),
    inst!( 0x83,  0, GDR_DISAMBIGUATE,                   ADC,       Ot::ModRM16,                         Ot::Immediate8SignExtended),
    inst!( 0x83,  0, GDR_DISAMBIGUATE,                   SBB,       Ot::ModRM16,                         Ot::Immediate8SignExtended),
    inst!( 0x83,  0, GDR_DISAMBIGUATE,                   AND,       Ot::ModRM16,                         Ot::Immediate8SignExtended),
    inst!( 0x83,  0, GDR_DISAMBIGUATE,                   SUB,       Ot::ModRM16,                         Ot::Immediate8SignExtended),
    inst!( 0x83,  0, GDR_DISAMBIGUATE,                   XOR,       Ot::ModRM16,                         Ot::Immediate8SignExtended),
    inst!( 0x83,  0, GDR_DISAMBIGUATE,                   CMP,       Ot::ModRM16,                         Ot::Immediate8SignExtended),
    // Group 5: 0xC0 /0-/7
    inst!( 0xC0,  0, GDR_DISAMBIGUATE,                   ROL,       Ot::ModRM8,                          Ot::Immediate8),
    inst!( 0xC0,  0, GDR_DISAMBIGUATE,                   ROR,       Ot::ModRM8,                          Ot::Immediate8),
    inst!( 0xC0,  0, GDR_DISAMBIGUATE,                   RCL,       Ot::ModRM8,                          Ot::Immediate8),
    inst!( 0xC0,  0, GDR_DISAMBIGUATE,                   RCR,       Ot::ModRM8,                          Ot::Immediate8),
    inst!( 0xC0,  0, GDR_DISAMBIGUATE,                   SHL,       Ot::ModRM8,                          Ot::Immediate8),
    inst!( 0xC0,  0, GDR_DISAMBIGUATE,                   SHR,       Ot::ModRM8,                          Ot::Immediate8),
    inst!( 0xC0,  0, GDR_DISAMBIGUATE,                   SAL,       Ot::ModRM8,                          Ot::Immediate8),
    inst!( 0xC0,  0, GDR_DISAMBIGUATE,                   SAR,       Ot::ModRM8,                          Ot::Immediate8),
    // Group 6: 0xC1 /0-/7
    inst!( 0xC1,  0, GDR_DISAMBIGUATE,                   ROL,       Ot::ModRM16,                         Ot::Immediate8),
    inst!( 0xC1,  0, GDR_DISAMBIGUATE,                   ROR,       Ot::ModRM16,                         Ot::Immediate8),
    inst!( 0xC1,  0, GDR_DISAMBIGUATE,                   RCL,       Ot::ModRM16,                         Ot::Immediate8),
    inst!( 0xC1,  0, GDR_DISAMBIGUATE,                   RCR,       Ot::ModRM16,                         Ot::Immediate8),
    inst!( 0xC1,  0, GDR_DISAMBIGUATE,                   SHL,       Ot::ModRM16,                         Ot::Immediate8),
    inst!( 0xC1,  0, GDR_DISAMBIGUATE,                   SHR,       Ot::ModRM16,                         Ot::Immediate8),
    inst!( 0xC1,  0, GDR_DISAMBIGUATE,                   SAL,       Ot::ModRM16,                         Ot::Immediate8),
    inst!( 0xC1,  0, GDR_DISAMBIGUATE,                   SAR,       Ot::ModRM16,                         Ot::Immediate8),
    // Group 7: 0xD0 /0-/7
    inst!( 0xD0,  0, GDR_DISAMBIGUATE,                   ROL,       Ot::ModRM8,                          Ot::FixedImmediate8(1)),
    inst!( 0xD0,  0, GDR_DISAMBIGUATE,                   ROR,       Ot::ModRM8,                          Ot::FixedImmediate8(1)),
    inst!( 0xD0,  0, GDR_DISAMBIGUATE,                   RCL,       Ot::ModRM8,                          Ot::FixedImmediate8(1)),
    inst!( 0xD0,  0, GDR_DISAMBIGUATE,                   RCR,       Ot::ModRM8,                          Ot::FixedImmediate8(1)),
    inst!( 0xD0,  0, GDR_DISAMBIGUATE,                   SHL,       Ot::ModRM8,                          Ot::FixedImmediate8(1)),
    inst!( 0xD0,  0, GDR_DISAMBIGUATE,                   SHR,       Ot::ModRM8,                          Ot::FixedImmediate8(1)),
    inst!( 0xD0,  0, GDR_DISAMBIGUATE,                   SAL,       Ot::ModRM8,                          Ot::FixedImmediate8(1)),
    inst!( 0xD0,  0, GDR_DISAMBIGUATE,                   SAR,       Ot::ModRM8,                          Ot::FixedImmediate8(1)),
    // Group 8: 0xD1 /0-/7
    inst!( 0xD1,  0, GDR_DISAMBIGUATE,                   ROL,       Ot::ModRM16,                         Ot::FixedImmediate8(1)),
    inst!( 0xD1,  0, GDR_DISAMBIGUATE,                   ROR,       Ot::ModRM16,                         Ot::FixedImmediate8(1)),
    inst!( 0xD1,  0, GDR_DISAMBIGUATE,                   RCL,       Ot::ModRM16,                         Ot::FixedImmediate8(1)),
    inst!( 0xD1,  0, GDR_DISAMBIGUATE,                   RCR,       Ot::ModRM16,                         Ot::FixedImmediate8(1)),
    inst!( 0xD1,  0, GDR_DISAMBIGUATE,                   SHL,       Ot::ModRM16,                         Ot::FixedImmediate8(1)),
    inst!( 0xD1,  0, GDR_DISAMBIGUATE,                   SHR,       Ot::ModRM16,                         Ot::FixedImmediate8(1)),
    inst!( 0xD1,  0, GDR_DISAMBIGUATE,                   SAL,       Ot::ModRM16,                         Ot::FixedImmediate8(1)),
    inst!( 0xD1,  0, GDR_DISAMBIGUATE,                   SAR,       Ot::ModRM16,                         Ot::FixedImmediate8(1)),
    // Group 9: 0xD2 /0-/7
    inst!( 0xD2,  0, GDR_DISAMBIGUATE,                   ROL,       Ot::ModRM8,                          Ot::FixedRegister8(Register8::CL)),
    inst!( 0xD2,  0, GDR_DISAMBIGUATE,                   ROR,       Ot::ModRM8,                          Ot::FixedRegister8(Register8::CL)),
    inst!( 0xD2,  0, GDR_DISAMBIGUATE,                   RCL,       Ot::ModRM8,                          Ot::FixedRegister8(Register8::CL)),
    inst!( 0xD2,  0, GDR_DISAMBIGUATE,                   RCR,       Ot::ModRM8,                          Ot::FixedRegister8(Register8::CL)),
    inst!( 0xD2,  0, GDR_DISAMBIGUATE,                   SHL,       Ot::ModRM8,                          Ot::FixedRegister8(Register8::CL)),
    inst!( 0xD2,  0, GDR_DISAMBIGUATE,                   SHR,       Ot::ModRM8,                          Ot::FixedRegister8(Register8::CL)),
    inst!( 0xD2,  0, GDR_DISAMBIGUATE,                   SAL,       Ot::ModRM8,                          Ot::FixedRegister8(Register8::CL)),
    inst!( 0xD2,  0, GDR_DISAMBIGUATE,                   SAR,       Ot::ModRM8,                          Ot::FixedRegister8(Register8::CL)),
    // Group 10: 0xD3 /0-/7
    inst!( 0xD3,  0, GDR_DISAMBIGUATE,                   ROL,       Ot::ModRM16,                         Ot::FixedRegister8(Register8::CL)),
    inst!( 0xD3,  0, GDR_DISAMBIGUATE,                   ROR,       Ot::ModRM16,                         Ot::FixedRegister8(Register8::CL)),
    inst!( 0xD3,  0, GDR_DISAMBIGUATE,                   RCL,       Ot::ModRM16,                         Ot::FixedRegister8(Register8::CL)),
    inst!( 0xD3,  0, GDR_DISAMBIGUATE,                   RCR,       Ot::ModRM16,                         Ot::FixedRegister8(Register8::CL)),
    inst!( 0xD3,  0, GDR_DISAMBIGUATE,                   SHL,       Ot::ModRM16,                         Ot::FixedRegister8(Register8::CL)),
    inst!( 0xD3,  0, GDR_DISAMBIGUATE,                   SHR,       Ot::ModRM16,                         Ot::FixedRegister8(Register8::CL)),
    inst!( 0xD3,  0, GDR_DISAMBIGUATE,                   SAL,       Ot::ModRM16,                         Ot::FixedRegister8(Register8::CL)),
    inst!( 0xD3,  0, GDR_DISAMBIGUATE,                   SAR,       Ot::ModRM16,                         Ot::FixedRegister8(Register8::CL)),
    // Group 11: 0xF6 /0-/7
    inst!( 0xF6,  0, GDR_DISAMBIGUATE,                   TEST,      Ot::ModRM8,                          Ot::Immediate8),
    inst!( 0xF6,  0, GDR_DISAMBIGUATE,                   TEST,      Ot::ModRM8,                          Ot::Immediate8),
    inst!( 0xF6,  0, GDR_DISAMBIGUATE,                   NOT,       Ot::ModRM8,                          Ot::NoOperand),
    inst!( 0xF6,  0, GDR_DISAMBIGUATE,                   NEG,       Ot::ModRM8,                          Ot::NoOperand),
    inst!( 0xF6,  0, GDR_DISAMBIGUATE,                   MUL,       Ot::ModRM8,                          Ot::NoOperand),
    inst!( 0xF6,  0, GDR_DISAMBIGUATE,                   IMUL,      Ot::ModRM8,                          Ot::NoOperand),
    inst!( 0xF6,  0, GDR_DISAMBIGUATE,                   DIV,       Ot::ModRM8,                          Ot::NoOperand),
    inst!( 0xF6,  0, GDR_DISAMBIGUATE,                   IDIV,      Ot::ModRM8,                          Ot::NoOperand),
    // Group 12: 0xF7 /0-/7
    inst!( 0xF7,  0, GDR_DISAMBIGUATE,                   TEST,      Ot::ModRM16,                         Ot::Immediate16),
    inst!( 0xF7,  0, GDR_DISAMBIGUATE,                   TEST,      Ot::ModRM16,                         Ot::Immediate16),
    inst!( 0xF7,  0, GDR_DISAMBIGUATE,                   NOT,       Ot::ModRM16,                         Ot::NoOperand),
    inst!( 0xF7,  0, GDR_DISAMBIGUATE,                   NEG,       Ot::ModRM16,                         Ot::NoOperand),
    inst!( 0xF7,  0, GDR_DISAMBIGUATE,                   MUL,       Ot::ModRM16,                         Ot::NoOperand),
    inst!( 0xF7,  0, GDR_DISAMBIGUATE,                   IMUL,      Ot::ModRM16,                         Ot::NoOperand),
    inst!( 0xF7,  0, GDR_DISAMBIGUATE,                   DIV,       Ot::ModRM16,                         Ot::NoOperand),
    inst!( 0xF7,  0, GDR_DISAMBIGUATE,                   IDIV,      Ot::ModRM16,                         Ot::NoOperand),
    // Group 13: 0xFE /0-/7
    inst!( 0xFE,  0, GDR_DISAMBIGUATE,                   INC,       Ot::ModRM8,                          Ot::NoOperand),
    inst!( 0xFE,  0, GDR_DISAMBIGUATE,                   DEC,       Ot::ModRM8,                          Ot::NoOperand),
    inst!( 0xFE,  0, 0,                                  Invalid,   Ot::ModRM8,                          Ot::NoOperand),
    inst!( 0xFE,  0, 0,                                  Invalid,   Ot::ModRM8,                          Ot::NoOperand),
    inst!( 0xFE,  0, 0,                                  Invalid,   Ot::ModRM8,                          Ot::NoOperand),
    inst!( 0xFE,  0, 0,                                  Invalid,   Ot::ModRM8,                          Ot::NoOperand),
    inst!( 0xFE,  0, 0,                                  Invalid,   Ot::ModRM8,                          Ot::NoOperand),
    inst!( 0xFE,  0, 0,                                  Invalid,   Ot::ModRM8,                          Ot::NoOperand),
    // Group 14: 0xFF /0-/7
    inst!( 0xFF,  0, GDR_DISAMBIGUATE,                   INC,       Ot::ModRM16,                         Ot::NoOperand),
    inst!( 0xFF,  0, GDR_DISAMBIGUATE,                   DEC,       Ot::ModRM16,                         Ot::NoOperand),
    inst!( 0xFF,  0, GDR_DISAMBIGUATE,                   CALL,      Ot::ModRM16,                         Ot::NoOperand),
    inst!( 0xFF,  0, GDR_NO_REG_FORM | GDR_DISAMBIGUATE, CALLF,     Ot::ModRM16,                         Ot::NoOperand),
    inst!( 0xFF,  0, GDR_DISAMBIGUATE,                   JMP,       Ot::ModRM16,                         Ot::NoOperand),
    inst!( 0xFF,  0, GDR_NO_REG_FORM | GDR_DISAMBIGUATE, JMPF,      Ot::ModRM16,                         Ot::NoOperand),
    inst!( 0xFF,  0, GDR_DISAMBIGUATE,                   PUSH,      Ot::ModRM16,                         Ot::NoOperand),
    inst!( 0xFF,  0, GDR_DISAMBIGUATE,                   Invalid,   Ot::ModRM16,                         Ot::NoOperand),
];

// Only 0F 00-06 exist on the 286. Unassigned entries must not consume a
// ModR/M byte belonging to the following instruction.
#[rustfmt::skip]
static EXTENDED_DECODE: [InstTemplate; 256 + 2 * 8] = {
    let mut table = [INVALID; 256 + 2 * 8];
    table[0x00] = inst!( 0x00,  1, 0,                                  Group,     Ot::NoOperand,                       Ot::NoOperand);
    table[0x01] = inst!( 0x01,  2, 0,                                  Group,     Ot::NoOperand,                       Ot::NoOperand);
    table[0x02] = inst!( 0x02,  0, 0,                                  LAR,       Ot::Register16,                      Ot::ModRM16);
    table[0x03] = inst!( 0x03,  0, 0,                                  LSL,       Ot::Register16,                      Ot::ModRM16);
    // STOREALL saves CPU state to ICE memory; F1 redirects it to user memory.
    // https://rep-lodsb.mataroa.blog/blog/intel-286-secrets-ice-mode-and-f1-0f-04/
    table[0x04] = inst!( 0x04,  0, GDR_NO_MODRM,                       STOREALL,  Ot::NoOperand,                       Ot::NoOperand);
    // https://www.pcjs.org/documents/manuals/intel/80286/loadall/
    table[0x05] = inst!( 0x05,  0, GDR_NO_MODRM,                       LOADALL,   Ot::NoOperand,                       Ot::NoOperand);
    table[0x06] = inst!( 0x06,  0, GDR_NO_MODRM,                       CLTS,      Ot::NoOperand,                       Ot::NoOperand);
    table[256]  = inst!( 0x00,  0, 0,                                  SLDT,      Ot::ModRM16,                         Ot::NoOperand);
    table[257]  = inst!( 0x00,  0, 0,                                  STR,       Ot::ModRM16,                         Ot::NoOperand);
    table[258]  = inst!( 0x00,  0, 0,                                  LLDT,      Ot::ModRM16,                         Ot::NoOperand);
    table[259]  = inst!( 0x00,  0, 0,                                  LTR,       Ot::ModRM16,                         Ot::NoOperand);
    table[260]  = inst!( 0x00,  0, 0,                                  VERR,      Ot::ModRM16,                         Ot::NoOperand);
    table[261]  = inst!( 0x00,  0, 0,                                  VERW,      Ot::ModRM16,                         Ot::NoOperand);
    table[262]  = inst!( 0x00,  0, 0,                                  Invalid,   Ot::NoOperand,                       Ot::NoOperand);
    table[263]  = inst!( 0x00,  0, 0,                                  Invalid,   Ot::NoOperand,                       Ot::NoOperand);
    table[264]  = inst!( 0x01,  0, GDR_NO_REG_FORM,                    SGDT,      Ot::ModRM16,                         Ot::NoOperand);
    table[265]  = inst!( 0x01,  0, GDR_NO_REG_FORM,                    SIDT,      Ot::ModRM16,                         Ot::NoOperand);
    table[266]  = inst!( 0x01,  0, GDR_NO_REG_FORM,                    LGDT,      Ot::ModRM16,                         Ot::NoOperand);
    table[267]  = inst!( 0x01,  0, GDR_NO_REG_FORM,                    LIDT,      Ot::ModRM16,                         Ot::NoOperand);
    table[268]  = inst!( 0x01,  0, 0,                                  SMSW,      Ot::ModRM16,                         Ot::NoOperand);
    table[269]  = inst!( 0x01,  0, 0,                                  Invalid,   Ot::NoOperand,                       Ot::NoOperand);
    table[270]  = inst!( 0x01,  0, 0,                                  LMSW,      Ot::ModRM16,                         Ot::NoOperand);
    table[271]  = inst!( 0x01,  0, 0,                                  Invalid,   Ot::NoOperand,                       Ot::NoOperand);
    table
};

impl Intel80286 {
    pub fn decode(bytes: &mut impl ByteReader) -> Result<Instruction, DecodeError> {
        // All 286 code uses 16-bit operands and addresses, including protected mode.
        let mut instruction = Instruction {
            is_valid: true,
            operand_size: OperandSize::Operand16,
            ..Instruction::default()
        };

        let mut opcode = bytes.read_u8()?;
        instruction.instruction_bytes.push(opcode);

        loop {
            let (flag, mask, segment) = match opcode {
                0x26 => (
                    PrefixFlags::ES_OVERRIDE,
                    PrefixFlags::SEG_OVERRIDE_MASK,
                    Some(Register16::ES),
                ),
                0x2E => (
                    PrefixFlags::CS_OVERRIDE,
                    PrefixFlags::SEG_OVERRIDE_MASK,
                    Some(Register16::CS),
                ),
                0x36 => (
                    PrefixFlags::SS_OVERRIDE,
                    PrefixFlags::SEG_OVERRIDE_MASK,
                    Some(Register16::SS),
                ),
                0x3E => (
                    PrefixFlags::DS_OVERRIDE,
                    PrefixFlags::SEG_OVERRIDE_MASK,
                    Some(Register16::DS),
                ),
                0xF0 => (PrefixFlags::LOCK, 0, None),
                // F1 selects user memory for ICE accesses. Preserve the byte;
                // it is neither the 8086 LOCK alias nor the 386 INT1 instruction.
                0xF1 => (0, 0, None),
                0xF2 => (PrefixFlags::REP1, PrefixFlags::REP_MASK, None),
                0xF3 => (PrefixFlags::REP2, PrefixFlags::REP_MASK, None),
                _ => break,
            };
            
            instruction.raw_prefix_flags |= flag;
            instruction.effective_prefix_flags = (instruction.effective_prefix_flags & !mask) | flag;

            if segment.is_some() {
                instruction.segment_override = segment;
            }
            
            instruction.prefix_bytes.push(opcode);
            instruction.prefix_ct += 1;

            if instruction.instruction_bytes.len() >= MAX_INSTRUCTION_LENGTH {
                instruction.is_valid = false;
                return Ok(instruction);
            }

            opcode = bytes.read_u8()?;
            instruction.instruction_bytes.push(opcode);
        }

        instruction.opcode_offset = instruction.prefix_bytes.len();
        
        let extended = opcode == 0x0F;
        let table = if extended {
            instruction.raw_prefix_flags |= PrefixFlags::EXTENDED_0F;
            instruction.effective_prefix_flags |= PrefixFlags::EXTENDED_0F;
            opcode = bytes.read_u8()?;
            instruction.instruction_bytes.push(opcode);
            &EXTENDED_DECODE[..]
        }
        else {
            &DECODE[..]
        };

        let opcode_value = if extended {
            0x0F00 | u16::from(opcode)
        }
        else {
            u16::from(opcode)
        };

        instruction.opcode = Opcode::new(opcode_value);
        
        let mut template = &table[opcode as usize];
        let mut displacement = Displacement::NoDisp;

        let modrm = if template.gdr.has_modrm() || template.grp != 0 {
            let modrm_offset = instruction.instruction_bytes.len();
            let modrm = ModRmByte16::read(bytes, &mut instruction.instruction_bytes)?;
            displacement = modrm.displacement();
            instruction.record_modrm(modrm_offset, displacement, false);

            if template.grp != 0 {
                let index = 256 + (usize::from(template.grp) - 1) * 8 + usize::from(modrm.op_extension());
                template = &table[index];
                instruction.opcode = Opcode::with_extension(opcode_value, modrm.op_extension());
            }
            else if template.gdr.must_use_reg0() {
                instruction.opcode = Opcode::with_extension(opcode_value, modrm.op_extension());
            }

            if (!template.gdr.has_reg_form() && !modrm.is_addressing_mode())
                || (template.gdr.must_use_reg0() && modrm.reg_value() != 0)
                || (template.gdr.uses_segment_reg() && modrm.reg_value() >= 4)
                // MOV CS,r/m16 is no longer permitted on the 286.
                || (!extended && opcode == 0x8E && modrm.reg_value() == 1)
            {
                instruction.is_valid = false;
            }
            Some(modrm)
        }
        else {
            None
        };

        instruction.operand1_type = template
            .operand1
            .resolve_operand(bytes, &modrm, displacement, &mut instruction)?;
        instruction.operand2_type = template
            .operand2
            .resolve_operand(bytes, &modrm, displacement, &mut instruction)?;
        instruction.operand3_type = template
            .operand3
            .resolve_operand(bytes, &modrm, displacement, &mut instruction)?;
        instruction.mnemonic = template.mnemonic;
        instruction.disambiguate = template.gdr.needs_disambiguation();
        instruction.record_immediates();
        instruction.is_complete = true;
        instruction.is_valid &=
            instruction.mnemonic != Mnemonic::Invalid && instruction.instruction_bytes.len() <= MAX_INSTRUCTION_LENGTH;
        Ok(instruction)
    }
}
