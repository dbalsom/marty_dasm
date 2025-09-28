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
use crate::byte_reader::ByteReader;
use crate::cpu_common::{AddressOffset32, BaseRegister, Displacement, ScaledIndex, SibScale, REGISTER32_LUT};
use crate::cpu_common::Register32;

pub const SIB_INDEX_MASK: u8 = 0b11_111_000;
pub const SIB_BASE_MASK: u8 = 0b00_000_111;
pub const SIB_DISPLACEMENT: u8 = 0b00_000_101;

// 32-bit SIB bitmasks
const SIB_EAX: u8 = 0b00_000_000;
const SIB_ECX: u8 = 0b00_001_000;
const SIB_EDX: u8 = 0b00_010_000;
const SIB_EBX: u8 = 0b00_011_000;
const SIB_NONE0: u8 = 0b00_100_000;
const SIB_EBP: u8 = 0b00_101_000;
const SIB_ESI: u8 = 0b00_110_000;
const SIB_EDI: u8 = 0b00_111_000;

const SIB_EAX_S2: u8 = 0b01_000_000;
const SIB_ECX_S2: u8 = 0b01_001_000;
const SIB_EDX_S2: u8 = 0b01_010_000;
const SIB_EBX_S2: u8 = 0b01_011_000;
const SIB_NONE1: u8 = 0b01_100_000;
const SIB_EBP_S2: u8 = 0b01_101_000;
const SIB_ESI_S2: u8 = 0b01_110_000;
const SIB_EDI_S2: u8 = 0b01_111_000;

const SIB_EAX_S4: u8 = 0b10_000_000;
const SIB_ECX_S4: u8 = 0b10_001_000;
const SIB_EDX_S4: u8 = 0b10_010_000;
const SIB_EBX_S4: u8 = 0b10_011_000;
const SIB_NONE2: u8 = 0b10_100_000;
const SIB_EBP_S4: u8 = 0b10_101_000;
const SIB_ESI_S4: u8 = 0b10_110_000;
const SIB_EDI_S4: u8 = 0b10_111_000;

const SIB_EAX_S8: u8 = 0b11_000_000;
const SIB_ECX_S8: u8 = 0b11_001_000;
const SIB_EDX_S8: u8 = 0b11_010_000;
const SIB_EBX_S8: u8 = 0b11_011_000;
const SIB_NONE3: u8 = 0b11_100_000;
const SIB_EBP_S8: u8 = 0b11_101_000;
const SIB_ESI_S8: u8 = 0b11_110_000;
const SIB_EDI_S8: u8 = 0b11_111_000;


#[derive(Copy, Clone)]
pub struct SibByte {
    _byte: u8,
    modrm_mod: u8,
    b_ss: u8,
    b_base: u8,
    b_idx: u8,
    addressing_mode: AddressOffset32,
}

const SIB_TABLE: [SibByte; 768] = {
    let mut table: [SibByte; 768] = [SibByte {
        _byte: 0,
        modrm_mod: 0,
        b_ss: 0,
        b_base: 0,
        b_idx: 0,
        addressing_mode: AddressOffset32::Eax,
    }; 768];
    let mut byte = 0;

    let mut modrm_mod = 0;

    loop {
        // Match the SIB scale factor
        let b_ss = (byte >> 6) & 0x03;

        let scaled_index = match byte & SIB_INDEX_MASK {
            SIB_EAX => ScaledIndex::EaxScaled(SibScale::One),
            SIB_ECX => ScaledIndex::EcxScaled(SibScale::One),
            SIB_EDX => ScaledIndex::EdxScaled(SibScale::One),
            SIB_EBX => ScaledIndex::EbxScaled(SibScale::One),
            SIB_NONE0 => ScaledIndex::None,
            SIB_EBP => ScaledIndex::EbpScaled(SibScale::One),
            SIB_ESI => ScaledIndex::EsiScaled(SibScale::One),
            SIB_EDI => ScaledIndex::EdiScaled(SibScale::One),

            SIB_EAX_S2 => ScaledIndex::EaxScaled(SibScale::Two),
            SIB_ECX_S2 => ScaledIndex::EcxScaled(SibScale::Two),
            SIB_EDX_S2 => ScaledIndex::EdxScaled(SibScale::Two),
            SIB_EBX_S2 => ScaledIndex::EbxScaled(SibScale::Two),
            SIB_NONE1 => ScaledIndex::None,
            SIB_EBP_S2 => ScaledIndex::EbpScaled(SibScale::Two),
            SIB_ESI_S2 => ScaledIndex::EsiScaled(SibScale::Two),
            SIB_EDI_S2 => ScaledIndex::EdiScaled(SibScale::Two),

            SIB_EAX_S4 => ScaledIndex::EaxScaled(SibScale::Four),
            SIB_ECX_S4 => ScaledIndex::EcxScaled(SibScale::Four),
            SIB_EDX_S4 => ScaledIndex::EdxScaled(SibScale::Four),
            SIB_EBX_S4 => ScaledIndex::EbxScaled(SibScale::Four),
            SIB_NONE2 => ScaledIndex::None,
            SIB_EBP_S4 => ScaledIndex::EbpScaled(SibScale::Four),
            SIB_ESI_S4 => ScaledIndex::EsiScaled(SibScale::Four),
            SIB_EDI_S4 => ScaledIndex::EdiScaled(SibScale::Four),

            SIB_EAX_S8 => ScaledIndex::EaxScaled(SibScale::Eight),
            SIB_ECX_S8 => ScaledIndex::EcxScaled(SibScale::Eight),
            SIB_EDX_S8 => ScaledIndex::EdxScaled(SibScale::Eight),
            SIB_EBX_S8 => ScaledIndex::EbxScaled(SibScale::Eight),
            SIB_NONE3 => ScaledIndex::None,
            SIB_EBP_S8 => ScaledIndex::EbpScaled(SibScale::Eight),
            SIB_ESI_S8 => ScaledIndex::EsiScaled(SibScale::Eight),
            SIB_EDI_S8 => ScaledIndex::EdiScaled(SibScale::Eight),
            _ => unreachable!(),
        };

        let b_base: u8 = byte & 0x07;
        let base_reg = REGISTER32_LUT[b_base as usize];
        let b_idx: u8 = (byte >> 3) & 0x07;

        let addressing_mode = if byte & SIB_BASE_MASK == SIB_DISPLACEMENT {
            match modrm_mod {
                0b00 => AddressOffset32::SibDisp32(BaseRegister::None, scaled_index, 0),
                0b01 => AddressOffset32::SibDisp8Ebp(BaseRegister::Some(Register32::EBP), scaled_index, 0),
                0b10 => AddressOffset32::SibDisp32Ebp(BaseRegister::Some(Register32::EBP), scaled_index, 0),
                _ => unreachable!(),
            }
        }
        else {
            AddressOffset32::Sib(BaseRegister::Some(base_reg), scaled_index)
        };

        table[((modrm_mod as usize) * 256) + byte as usize] = SibByte {
            _byte: byte,
            modrm_mod,
            b_ss,
            b_base,
            b_idx,
            addressing_mode,
        };

        if byte < 255 {
            byte += 1;
        }
        else {
            byte = 0;
            modrm_mod += 1;
            if modrm_mod > 2 {
                break;
            }
        }
    }

    table
};

impl SibByte {
    #[inline(always)]
    pub fn from_byte(byte: u8, modrm_mod: u8) -> SibByte {
        SIB_TABLE[((modrm_mod & 0x03) as usize * 256) + byte as usize].clone()
    }

    pub fn read(bytes: &mut impl ByteReader, modrm_mod: u8, displacement: Displacement, instruction_bytes: &mut Vec<u8>) -> Result<SibByte, Box<dyn std::error::Error>> {
        let raw_sib_byte = bytes.read_u8()?;
        let mut sib = SibByte::from_byte(raw_sib_byte, modrm_mod);
        instruction_bytes.push(raw_sib_byte);

        sib.set_displacement(displacement);

        Ok(sib)
    }

    pub fn dump(&self) {
        for i in 0..768 {
            println!("{:02X}: {}", SIB_TABLE[i]._byte, SIB_TABLE[i].addressing_mode);
        }
    }

    pub fn byte(&self) -> u8 {
        self._byte
    }

    #[inline(always)]
    pub fn is_addressing_mode(&self) -> bool {
        true
    }

    pub fn has_displacement(&self) -> Option<Displacement> {
        match self.addressing_mode {
            AddressOffset32::SibDisp8Ebp(_, _, d) => Some(Displacement::Disp8(d)),
            AddressOffset32::SibDisp32Ebp(_, _, d) => Some(Displacement::Disp32(d)),
            AddressOffset32::SibDisp32(_, _, d) => Some(Displacement::Disp32(d)),
            _ => None,
        }
    }

    pub fn has_disp32(&self) -> bool {
        matches!(
            self.addressing_mode,
            AddressOffset32::SibDisp32(_, _, _)
        )
    }

    pub fn set_displacement(&mut self, displacement: Displacement) {
        self.addressing_mode = match self.addressing_mode {
            AddressOffset32::Sib(base, idx) => match displacement {
                Displacement::Disp8(d) => AddressOffset32::SibDisp8(base, idx, d),
                Displacement::Disp32(d) => AddressOffset32::SibDisp32(base, idx, d),
                _ => self.addressing_mode,
            },
            AddressOffset32::SibDisp8Ebp(base, idx, _) => AddressOffset32::SibDisp8Ebp(base, idx, displacement.into()),
            AddressOffset32::SibDisp32Ebp(base, idx, _) => {
                AddressOffset32::SibDisp32Ebp(base, idx, displacement.into())
            }
            AddressOffset32::SibDisp32(base, idx, _) => AddressOffset32::SibDisp32(base, idx, displacement.into()),
            _ => self.addressing_mode,
        }
    }

    /// Produce an [AddressOffset32] enum with the provided [Displacement] inserted.
    #[inline(always)]
    pub fn address_offset(&self) -> AddressOffset32 {
        self.addressing_mode
    }
}
