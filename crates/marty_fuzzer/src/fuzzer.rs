/*
    ArduinoX86 Copyright 2022-2025 Daniel Balsom
    https://github.com/dbalsom/arduinoX86

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
use std::{
    collections::VecDeque,
    ops::{Range, RangeInclusive},
};

use marty_dasm::{decoder::CpuType, prelude::*};
use marty_isadb::{db::IterFilter, IsaDB, IsaRecord};
use rand::{prelude::StdRng, Rng};

use crate::{
    error::{FuzzerError, FuzzerError::InvalidOptions},
    modrm_fuzzer::ModRmFuzzer,
};

pub const INSTRUCTION_POST_LEN: usize = 10;

pub const PREFIXES_8088: [u8; 8] = [
    0xF0, // LOCK
    0xF1, // LOCK alias
    0xF2, // REPNE/REPNZ
    0xF3, // REP/REPE/REPZ
    0x2E, // CS segment override
    0x36, // SS segment override
    0x3E, // DS segment override
    0x26, // ES segment override
];

pub const PREFIXES_80386: [u8; 11] = [
    0xF0, // LOCK
    0xF2, // REPNE/REPNZ
    0xF3, // REP/REPE/REPZ
    0x2E, // CS segment override
    0x36, // SS segment override
    0x3E, // DS segment override
    0x26, // ES segment override
    0x64, // FS segment override
    0x65, // GS segment override
    0x66, // Operand-size override
    0x67, // Address-size override
];

pub struct FuzzerOptions {
    pub seed: u64,
    pub opcode_range: Option<RangeInclusive<u16>>,
    pub extension_range: Option<RangeInclusive<u8>>,
    pub allow_fpu: bool,
    pub allow_protected: bool,
    pub allow_undefined: bool,
    pub segment_size: SegmentSize,
}

pub struct InstructionFuzzer {
    pub cpu_type: CpuType,
    isa_db: IsaDB,
}

#[derive(Clone, Default)]
pub struct FuzzerInstruction {
    pub cpu_type: CpuType,
    pub bytes: Vec<u8>,
    pub prefix_range: Range<usize>,
    pub opcode_range: Range<usize>,
    pub modrm_range: Option<Range<usize>>, // Includes SIB if present
    pub displacement_range: Option<Range<usize>>,
    pub immediate_range: Option<Range<usize>>,
    pub relative_range: Option<Range<usize>>,
}

impl InstructionFuzzer {
    pub fn new(cpu_type: CpuType) -> Self {
        let isa_db = IsaDB::new(cpu_type).expect("Failed to load ISA database");

        InstructionFuzzer { cpu_type, isa_db }
    }

    pub fn random_instruction(
        &self,
        rng: &mut StdRng,
        options: &FuzzerOptions,
    ) -> Result<FuzzerInstruction, FuzzerError> {
        match self.cpu_type {
            CpuType::Intel808x => {
                unimplemented!("{:?}", self.cpu_type);
            }
            CpuType::Intel80286 => {
                unimplemented!("{:?}", self.cpu_type);
            }
            CpuType::Intel80386 => self.random_instruction_386(rng, options),
            _ => {
                unimplemented!("{:?}", self.cpu_type);
            }
        }
    }

    pub fn random_instruction_386(
        &self,
        rng: &mut StdRng,
        options: &FuzzerOptions,
    ) -> Result<FuzzerInstruction, FuzzerError> {
        let mut new_instruction = FuzzerInstruction {
            cpu_type: self.cpu_type,
            ..FuzzerInstruction::default()
        };
        let mut inst_bytes = VecDeque::new();

        let filter = IterFilter {
            accept_fpu: options.allow_fpu,
            accept_protected: options.allow_protected,
            accept_undefined: options.allow_undefined,
        };

        let isa_records: Vec<&IsaRecord> = self.isa_db.opcode_iter(filter).collect();

        if isa_records.is_empty() {
            return Err(InvalidOptions(
                "No ISA records match the provided filter options".into(),
            ));
        }

        let mut record = isa_records[rng.random_range(0..isa_records.len())];
        while record.is_prefix {
            record = isa_records[rng.random_range(0..isa_records.len())];
        }

        let address_size = match options.segment_size {
            SegmentSize::Segment16 => AddressSize::Address16,
            SegmentSize::Segment32 => AddressSize::Address32,
        };

        // Add opcode.  This may add one or two bytes, depending on extended opcode.
        let opcode_bytes = record.opcode.to_bytes();
        let opcode_range = 0..opcode_bytes.len();
        new_instruction.opcode_range = opcode_range;
        inst_bytes.extend(record.opcode.to_bytes());

        // Add modrm if instruction has a modrm.
        if record.has_modrm {
            let mut sib_byte: Option<u8> = None;

            let modrm = match address_size {
                AddressSize::Address16 => {
                    let mut modrm_fuzzer = ModRmFuzzer::new(address_size).with_reg_form(record.allow_reg_form);

                    if let Some(extension) = record.extension {
                        modrm_fuzzer = modrm_fuzzer.with_reg(extension);
                    }

                    modrm_fuzzer.build(rng)
                }
                AddressSize::Address32 => {
                    let mut modrm_fuzzer = ModRmFuzzer::new(address_size).with_reg_form(record.allow_reg_form);

                    if let Some(extension) = record.extension {
                        modrm_fuzzer = modrm_fuzzer.with_reg(extension);
                    }

                    let modrm = modrm_fuzzer.build(rng);

                    // Now we have a valid modrm byte - do we need a SIB byte?
                    if modrm.has_sib() {
                        // Generate random SIB byte.
                        let sib_byte_raw: u8 = rng.random();
                        sib_byte = Some(sib_byte_raw);
                    }

                    modrm
                }
            };

            // Push the modrm and optional SIB byte.
            let mut modrm_range = inst_bytes.len()..(inst_bytes.len() + 1);
            inst_bytes.push_back(modrm.raw_byte());

            if let Some(sib) = sib_byte {
                modrm_range.end += 1;
                inst_bytes.push_back(sib);
            }
            new_instruction.modrm_range = Some(modrm_range);
        }

        // Add enough bytes so we can have a possible 32-bit displacement + 32-bit immediate. (8)
        for _ in 0..INSTRUCTION_POST_LEN {
            inst_bytes.push_back(rng.random());
        }

        // Crate vec from deque
        let inst_bytes: Vec<u8> = inst_bytes.into_iter().collect();
        new_instruction.bytes = inst_bytes;

        Ok(new_instruction)
    }
}
