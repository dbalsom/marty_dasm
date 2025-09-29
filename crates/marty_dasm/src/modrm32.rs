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
    byte_reader::ByteReader,
    cpu_common::{
        AddressOffset32,
        CREGISTER_LUT,
        ControlRegister,
        DREGISTER_LUT,
        DebugRegister,
        Displacement,
        REGISTER8_LUT,
        REGISTER16_LUT,
        REGISTER32_LUT,
        Register8,
        Register16,
        Register32,
        SREGISTER16_LUT,
        SREGISTER16_LUT_386,
        SREGISTER32_LUT,
    },
    sib::SibByte,
};

#[derive(Copy, Clone)]
pub struct ModRmByte32 {
    byte: u8,
    b_mod: u8,
    b_reg: u8,
    b_rm: u8,
    disp: Displacement,
    addressing_mode: AddressOffset32,
}

const MODRM32_TABLE: [ModRmByte32; 256] = {
    let mut table: [ModRmByte32; 256] = [ModRmByte32 {
        byte: 0,
        b_mod: 0,
        b_reg: 0,
        b_rm: 0,
        disp: Displacement::NoDisp,
        addressing_mode: AddressOffset32::Eax,
    }; 256];
    let mut byte = 0;

    loop {
        let mut displacement = Displacement::NoDisp;

        let b_mod = (byte >> 6) & 0x03;

        match b_mod {
            0b00 => {
                // Addressing mode [disp32] is a single mode of 0b00
                if byte & ModRmByte32::MODRM_ADDR_MASK == ModRmByte32::MODRM_ADDR_DISP32 {
                    displacement = Displacement::Disp32(0);
                }
            }
            0b01 => {
                // 0b01 signifies an 8 bit displacement (sign-extended to 16)
                displacement = Displacement::Disp8(0);
            }
            0b10 => {
                // 0b10 signifies a 32 bit displacement
                displacement = Displacement::Disp32(0);
            }
            _ => displacement = Displacement::NoDisp,
        }

        let addressing_mode = match byte & ModRmByte32::MODRM_ADDR_MASK {
            ModRmByte32::MODRM_ADDR_EAX => AddressOffset32::Eax,
            ModRmByte32::MODRM_ADDR_ECX => AddressOffset32::Ecx,
            ModRmByte32::MODRM_ADDR_EDX => AddressOffset32::Edx,
            ModRmByte32::MODRM_ADDR_EBX => AddressOffset32::Ebx,
            ModRmByte32::MODRM_ADDR_SIB0 => AddressOffset32::SibPending,
            ModRmByte32::MODRM_ADDR_DISP32 => AddressOffset32::Disp32(0),
            ModRmByte32::MODRM_ADDR_ESI => AddressOffset32::Esi,
            ModRmByte32::MODRM_ADDR_EDI => AddressOffset32::Edi,

            ModRmByte32::MODRM_ADDR_EAX_DISP8 => AddressOffset32::EaxDisp8(0),
            ModRmByte32::MODRM_ADDR_ECX_DISP8 => AddressOffset32::EcxDisp8(0),
            ModRmByte32::MODRM_ADDR_EDX_DISP8 => AddressOffset32::EdxDisp8(0),
            ModRmByte32::MODRM_ADDR_EBX_DISP8 => AddressOffset32::EbxDisp8(0),
            ModRmByte32::MODRM_ADDR_SIB1 => AddressOffset32::SibPending,
            ModRmByte32::MODRM_ADDR_EBP_DISP8 => AddressOffset32::EbpDisp8(0),
            ModRmByte32::MODRM_ADDR_ESI_DISP8 => AddressOffset32::EsiDisp8(0),
            ModRmByte32::MODRM_ADDR_EDI_DISP8 => AddressOffset32::EdiDisp8(0),

            ModRmByte32::MODRM_ADDR_EAX_DISP32 => AddressOffset32::EaxDisp32(0),
            ModRmByte32::MODRM_ADDR_ECX_DISP32 => AddressOffset32::EcxDisp32(0),
            ModRmByte32::MODRM_ADDR_EDX_DISP32 => AddressOffset32::EdxDisp32(0),
            ModRmByte32::MODRM_ADDR_EBX_DISP32 => AddressOffset32::EbxDisp32(0),
            ModRmByte32::MODRM_ADDR_SIB2 => AddressOffset32::SibPending,
            ModRmByte32::MODRM_ADDR_EBP_DISP32 => AddressOffset32::EbpDisp32(0),
            ModRmByte32::MODRM_ADDR_ESI_DISP32 => AddressOffset32::EsiDisp32(0),
            ModRmByte32::MODRM_ADDR_EDI_DISP32 => AddressOffset32::EdiDisp32(0),
            _ => AddressOffset32::None,
        };

        // 'REG' field specifies either register operand or opcode extension. There's no way
        // to know without knowing the opcode, which we don't
        let b_reg: u8 = (byte >> 3) & 0x07;

        // 'R/M' field is last three bits
        let b_rm: u8 = byte & 0x07;

        table[byte as usize] = ModRmByte32 {
            byte,
            b_mod,
            b_reg,
            b_rm,
            disp: displacement,
            addressing_mode,
        };

        if byte < 255 {
            byte += 1;
        }
        else {
            break;
        }
    }

    table
};

impl ModRmByte32 {
    const MODRM_ADDR_MASK: u8 = 0b11_000_111;

    // 32-bit modrm bitmasks
    const MODRM_ADDR_EAX: u8 = 0b00_000_000;
    const MODRM_ADDR_ECX: u8 = 0b00_000_001;
    const MODRM_ADDR_EDX: u8 = 0b00_000_010;
    const MODRM_ADDR_EBX: u8 = 0b00_000_011;
    const MODRM_ADDR_SIB0: u8 = 0b00_000_100;
    const MODRM_ADDR_DISP32: u8 = 0b00_000_101;
    const MODRM_ADDR_ESI: u8 = 0b00_000_110;
    const MODRM_ADDR_EDI: u8 = 0b00_000_111;

    const MODRM_ADDR_EAX_DISP8: u8 = 0b01_000_000;
    const MODRM_ADDR_ECX_DISP8: u8 = 0b01_000_001;
    const MODRM_ADDR_EDX_DISP8: u8 = 0b01_000_010;
    const MODRM_ADDR_EBX_DISP8: u8 = 0b01_000_011;
    const MODRM_ADDR_SIB1: u8 = 0b01_000_100;
    const MODRM_ADDR_EBP_DISP8: u8 = 0b01_000_101;
    const MODRM_ADDR_ESI_DISP8: u8 = 0b01_000_110;
    const MODRM_ADDR_EDI_DISP8: u8 = 0b01_000_111;

    const MODRM_ADDR_EAX_DISP32: u8 = 0b10_000_000;
    const MODRM_ADDR_ECX_DISP32: u8 = 0b10_000_001;
    const MODRM_ADDR_EDX_DISP32: u8 = 0b10_000_010;
    const MODRM_ADDR_EBX_DISP32: u8 = 0b10_000_011;
    const MODRM_ADDR_SIB2: u8 = 0b10_000_100;
    const MODRM_ADDR_EBP_DISP32: u8 = 0b10_000_101;
    const MODRM_ADDR_ESI_DISP32: u8 = 0b10_000_110;
    const MODRM_ADDR_EDI_DISP32: u8 = 0b10_000_111;
}

impl ModRmByte32 {
    pub fn default_ref() -> &'static ModRmByte32 {
        &MODRM32_TABLE[0]
    }

    /// Read the modrm byte and look up the appropriate value from the modrm table.
    /// Load any displacement, then return modrm struct and size of modrm + displacement.
    pub fn from_byte(byte: u8) -> ModRmByte32 {
        MODRM32_TABLE[byte as usize].clone()
    }

    /// Read the modrm byte and look up the appropriate value from the modrm table.
    pub fn read(
        bytes: &mut impl ByteReader,
        instruction_bytes: &mut Vec<u8>,
    ) -> Result<(ModRmByte32, Option<SibByte>), Box<dyn std::error::Error>> {
        let raw_modrm_byte = bytes.read_u8()?;
        let mut modrm = ModRmByte32::from_byte(raw_modrm_byte);
        instruction_bytes.push(raw_modrm_byte);

        let sib_byte_raw = if modrm.has_sib() {
            // SIB byte follows modrm byte
            let sib_byte = bytes.read_u8()?;
            instruction_bytes.push(sib_byte);
            Some(sib_byte)
        }
        else {
            None
        };

        // If modrm is an addressing mode, load any displacement bytes.
        let mut read_displacement = None;
        if modrm.b_mod != 0b11 {
            match modrm.disp {
                Displacement::Disp8(_) => {
                    let disp = bytes.read_u8()?;
                    instruction_bytes.push(disp);
                    read_displacement = Some(Displacement::Disp8(disp as i8));
                }
                Displacement::Disp16(_) => {
                    let disp = bytes.read_u16()?;
                    instruction_bytes.extend_from_slice(&disp.to_le_bytes());
                    read_displacement = Some(Displacement::Disp16(disp as i16));
                }
                Displacement::Disp32(_) => {
                    let disp = bytes.read_u32()?;
                    instruction_bytes.extend_from_slice(&disp.to_le_bytes());
                    read_displacement = Some(Displacement::Disp32(disp as i32));
                }
                _ => { /* No displacement to read */ }
            }
        }

        if let Some(disp) = read_displacement {
            modrm.disp = disp;
        }

        if let Some(sib_byte) = sib_byte_raw {
            let mut sib = SibByte::from_byte(sib_byte, modrm.b_mod);

            // Catch the special case of mod=00 and rm=100 (SIB) and base=101 (no base, disp32)
            if read_displacement.is_none() && sib.has_disp32() {
                let disp = bytes.read_u32()?;
                instruction_bytes.extend_from_slice(&disp.to_le_bytes());
                modrm.disp = Displacement::Disp32(disp as i32);
            }

            sib.set_displacement(modrm.disp);
            Ok((modrm, Some(sib)))
        }
        else {
            Ok((modrm, None))
        }
    }

    /// Return the 'mod' field (top two bits) of the modrm byte.
    #[inline(always)]
    pub fn mod_value(&self) -> u8 {
        self.b_mod
    }

    /// Set the 'mod' field (top two bits) of the modrm byte. The argument is assumed to be
    /// an un-shifted 2 bit value (0-3).
    pub fn set_mod(&mut self, m: u8) {
        let new_byte = (self.byte & 0b0011_1111) | ((m & 0x03) << 6);
        *self = ModRmByte32::from_byte(new_byte);
    }

    #[inline(always)]
    pub fn reg_value(&self) -> u8 {
        self.b_reg
    }

    /// Set the 'reg' field (middle three bits) of the modrm byte. The argument is assumed to be
    /// an un-shifted 3 bit value (0-7).
    pub fn set_reg(&mut self, reg: u8) {
        let new_byte = (self.byte & 0b1100_0111) | ((reg & 0x07) << 3);
        *self = ModRmByte32::from_byte(new_byte);
    }

    // Interpret the 'R/M' field as an 8 bit register selector
    #[inline(always)]
    pub fn op1_reg8(&self) -> Register8 {
        REGISTER8_LUT[self.b_rm as usize]
    }
    // Interpret the 'R/M' field as a 16 bit register selector
    #[inline(always)]
    pub fn op1_reg16(&self) -> Register16 {
        REGISTER16_LUT[self.b_rm as usize]
    }
    // Interpret the 'R/M' field as a 32 bit register selector
    #[inline(always)]
    pub fn op1_reg32(&self) -> Register32 {
        REGISTER32_LUT[self.b_rm as usize]
    }
    // Interpret the 'REG' field as an 8 bit register selector
    #[inline(always)]
    pub fn op2_reg8(&self) -> Register8 {
        REGISTER8_LUT[self.b_reg as usize]
    }
    // Interpret the 'REG' field as a 16 bit register selector
    #[inline(always)]
    pub fn op2_reg16(&self) -> Register16 {
        REGISTER16_LUT[self.b_reg as usize]
    }

    // Interpret the 'REG' field as a 32 bit register selector
    #[inline(always)]
    pub fn op2_reg32(&self) -> Register32 {
        REGISTER32_LUT[self.b_reg as usize]
    }
    // Interpret the 'REG' field as a 16 bit segment register selector
    #[inline(always)]
    pub fn op2_segmentreg16(&self) -> Register16 {
        SREGISTER16_LUT[self.b_reg as usize]
    }

    #[inline(always)]
    pub fn op2_segment_reg16_386(&self) -> Register16 {
        SREGISTER16_LUT_386[self.b_reg as usize]
    }

    #[inline(always)]
    pub fn op2_reg_ctrl(&self) -> ControlRegister {
        CREGISTER_LUT[self.b_reg as usize]
    }

    #[inline(always)]
    pub fn op2_reg_dbg(self) -> DebugRegister {
        DREGISTER_LUT[self.b_reg as usize]
    }
    // Interpret the 'REG' field as a 32 bit segment register selector
    #[inline(always)]
    pub fn op2_segmentreg32(&self) -> Register32 {
        SREGISTER32_LUT[self.b_reg as usize]
    }
    // Interpret the 'REG' field as a 3 bit opcode extension
    #[inline(always)]
    pub fn op_extension(&self) -> u8 {
        self.b_reg
    }
    // Return whether the modrm byte specifies a memory addressing mode
    #[inline(always)]
    pub fn is_addressing_mode(&self) -> bool {
        self.b_mod != 0b11
    }
    /// Produce an [AddressOffset32] enum with the provided [Displacement] inserted.
    #[inline(always)]
    pub fn address_offset(&self, displacement: Displacement) -> AddressOffset32 {
        match self.addressing_mode {
            AddressOffset32::Disp32(_) => AddressOffset32::Disp32(displacement.into()),
            AddressOffset32::EaxDisp8(_) => AddressOffset32::EaxDisp8(displacement.into()),
            AddressOffset32::EcxDisp8(_) => AddressOffset32::EcxDisp8(displacement.into()),
            AddressOffset32::EdxDisp8(_) => AddressOffset32::EdxDisp8(displacement.into()),
            AddressOffset32::EbxDisp8(_) => AddressOffset32::EbxDisp8(displacement.into()),
            AddressOffset32::EbpDisp8(_) => AddressOffset32::EbpDisp8(displacement.into()),
            AddressOffset32::EsiDisp8(_) => AddressOffset32::EsiDisp8(displacement.into()),
            AddressOffset32::EdiDisp8(_) => AddressOffset32::EdiDisp8(displacement.into()),
            AddressOffset32::EaxDisp32(_) => AddressOffset32::EaxDisp32(displacement.into()),
            AddressOffset32::EcxDisp32(_) => AddressOffset32::EcxDisp32(displacement.into()),
            AddressOffset32::EdxDisp32(_) => AddressOffset32::EdxDisp32(displacement.into()),
            AddressOffset32::EbxDisp32(_) => AddressOffset32::EbxDisp32(displacement.into()),
            AddressOffset32::EbpDisp32(_) => AddressOffset32::EbpDisp32(displacement.into()),
            AddressOffset32::EsiDisp32(_) => AddressOffset32::EsiDisp32(displacement.into()),
            AddressOffset32::EdiDisp32(_) => AddressOffset32::EdiDisp32(displacement.into()),
            _ => self.addressing_mode,
        }
    }

    #[inline(always)]
    pub fn displacement(&self) -> Displacement {
        self.disp
    }

    #[inline(always)]
    pub fn has_sib(&self) -> bool {
        matches!(self.addressing_mode, AddressOffset32::SibPending)
    }

    #[inline(always)]
    pub fn raw_byte(&self) -> u8 {
        self.byte
    }
}
