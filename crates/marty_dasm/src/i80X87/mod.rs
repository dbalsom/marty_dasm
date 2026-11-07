// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Daniel Balsom

//! Shared 8087, 80287, 80287XL and 80387 instruction formatting.
//!
//! The CPU decoder owns prefixes, instruction length, ModR/M, SIB and displacement
//! reads. This module only interprets the ESC opcode and the already-read ModR/M
//! byte.

mod tables;

use crate::{
    SegmentSize,
    cpu_common::{OperandSize, OperandType, PrefixFlags, Register16},
    instruction::Instruction,
    mnemonic::Mnemonic,
};

pub use marty_dasm_common::FpuType;

const fn has_32bit_environment(fpu: FpuType) -> bool {
    matches!(fpu, FpuType::Intel80287XL | FpuType::Intel80387)
}

const fn model_mask(fpu: FpuType) -> u8 {
    match fpu {
        FpuType::Intel8087 => 1,
        FpuType::Intel80287 => 2,
        FpuType::Intel80287XL => 8,
        FpuType::Intel80387 => 4,
    }
}

/// x87 storage formats are independent of CPU address size and scalar operand size.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FpuMemoryFormat {
    Float32,
    Float64,
    Float80,
    Int16,
    Int32,
    Int64,
    Bcd80,
    ControlWord,
    StatusWord,
    Env14,
    Env28,
    State94,
    State108,
}

impl FpuMemoryFormat {
    pub const fn byte_len(self) -> usize {
        match self {
            Self::Int16 | Self::ControlWord | Self::StatusWord => 2,
            Self::Float32 | Self::Int32 => 4,
            Self::Float64 | Self::Int64 => 8,
            Self::Float80 | Self::Bcd80 => 10,
            Self::Env14 => 14,
            Self::Env28 => 28,
            Self::State94 => 94,
            Self::State108 => 108,
        }
    }

    pub const fn is_environment_or_state(self) -> bool {
        matches!(self, Self::Env14 | Self::Env28 | Self::State94 | Self::State108)
    }

    pub(crate) const fn nasm_size(self) -> Option<&'static str> {
        match self {
            Self::Int16 | Self::ControlWord | Self::StatusWord => Some("word"),
            Self::Float32 | Self::Int32 => Some("dword"),
            Self::Float64 | Self::Int64 => Some("qword"),
            Self::Float80 | Self::Bcd80 => Some("tword"),
            _ => None,
        }
    }
}

/// Operand recipes, without CPU-specific effective addresses.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FpuOperands {
    None,
    St(u8),
    St0St(u8),
    StSt0(u8),
    Ax,
    Memory(FpuMemoryFormat),
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct FpuInstruction {
    pub mnemonic: Mnemonic,
    pub operands: FpuOperands,
    /// An alternate encoding or instruction outside the normal documented ISA.
    pub undocumented: bool,
    /// A legacy control instruction accepted as a no-op by this coprocessor.
    pub compatibility_nop: bool,
}

/// Decode an x87 instruction without reading bytes or resolving an address.
///
/// `operand_size` is the host CPU's effective 16/32-bit operand-size attribute.
/// It selects the 287XL/387 environment/save layout; the 8087 and 287 always use
/// the 14/94-byte layout. Unrecognized FPU encodings return `None`; this does
/// not indicate a CPU #UD. The CPU decoder determines instruction validity.
pub fn decode(opcode: u8, modrm: u8, fpu: FpuType, operand_size: OperandSize) -> Option<FpuInstruction> {
    let row = opcode.checked_sub(0xD8)? as usize;
    if row >= 8 {
        return None;
    }
    let entry = if modrm < 0xC0 {
        tables::MEMORY[row][((modrm >> 3) & 7) as usize]
    }
    else {
        tables::REGISTER[row][(modrm & 0x3F) as usize]
    };
    if entry.models & model_mask(fpu) == 0 {
        return None;
    }
    let mut operands = entry.operands;
    if has_32bit_environment(fpu) && operand_size == OperandSize::Operand32 {
        operands = match operands {
            FpuOperands::Memory(FpuMemoryFormat::Env14) => FpuOperands::Memory(FpuMemoryFormat::Env28),
            FpuOperands::Memory(FpuMemoryFormat::State94) => FpuOperands::Memory(FpuMemoryFormat::State108),
            other => other,
        };
    }
    Some(FpuInstruction {
        mnemonic: entry.mnemonic,
        operands,
        undocumented: entry.undocumented,
        compatibility_nop: entry.nop_models & model_mask(fpu) != 0,
    })
}

/// Refine the CPU's generic ESC after it has consumed the entire instruction.
pub(crate) fn apply(instruction: &mut Instruction, fpu: FpuType) {
    if !instruction.is_valid || instruction.mnemonic != Mnemonic::ESC || !instruction.has_modrm {
        return;
    }
    let modrm = instruction.instruction_bytes[instruction.modrm_offset];
    let opcode = instruction.instruction_bytes[instruction.modrm_offset - 1];
    let mut operand_size = OperandSize::from(instruction.segment_size);
    if instruction.has_operand_size_override_prefix() {
        operand_size = operand_size.with_override();
    }
    let Some(decoded) = decode(opcode, modrm, fpu, operand_size)
    else {
        // The CPU accepted this escape. Lack of an FPU mnemonic does not cause #UD;
        // retain its generic ESC operands, prefixes, validity and byte boundaries.
        return;
    };

    instruction.opcode_offset = instruction.modrm_offset - 1;
    instruction.opcode = crate::Opcode::with_extension(opcode as u16, (modrm >> 3) & 7);
    instruction.prefix_bytes = instruction.instruction_bytes[..instruction.opcode_offset].to_vec();
    instruction.prefix_ct = instruction.prefix_bytes.len() as u32;
    instruction.operand2_type = OperandType::NoOperand;
    instruction.operand3_type = OperandType::NoOperand;
    instruction.mnemonic = decoded.mnemonic;
    instruction.fpu = Some(decoded);
    instruction.disambiguate = true;
    instruction.operand1_type = match decoded.operands {
        FpuOperands::None => OperandType::NoOperand,
        FpuOperands::St(i) => OperandType::FpuRegister(i),
        FpuOperands::St0St(i) => {
            instruction.operand2_type = OperandType::FpuRegister(i);
            OperandType::FpuRegister(0)
        }
        FpuOperands::StSt0(i) => {
            instruction.operand2_type = OperandType::FpuRegister(0);
            OperandType::FpuRegister(i)
        }
        FpuOperands::Ax => OperandType::Register16(Register16::AX),
        FpuOperands::Memory(format) => {
            if format.is_environment_or_state() {
                instruction.operand_size = if has_32bit_environment(fpu) {
                    operand_size
                }
                else {
                    OperandSize::Operand16
                };
                if has_32bit_environment(fpu) && instruction.has_operand_size_override_prefix() {
                    instruction.effective_prefix_flags |= PrefixFlags::OPERAND_SIZE;
                }
            }
            match instruction.operand1_type {
                OperandType::AddressingMode16(address, _) => OperandType::FpuMemory16(address, format),
                OperandType::AddressingMode32(address, _) => OperandType::FpuMemory32(address, format),
                _ => unreachable!("CPU ESC decoder must supply a memory operand for mod != 3"),
            }
        }
    };
    // 67h cannot affect register-only x87 instructions.
    if modrm >= 0xC0 {
        instruction.effective_prefix_flags &= !PrefixFlags::ADDRESS_SIZE;
        instruction.address_size = match instruction.segment_size {
            SegmentSize::Segment16 => crate::AddressSize::Address16,
            SegmentSize::Segment32 => crate::AddressSize::Address32,
        };
    }
}
