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
use crate::cpu_common::{AddressOffset16, ControlRegister, DebugRegister, Displacement, Register16, Register32, Register8, CREGISTER_LUT, DREGISTER_LUT, REGISTER16_LUT, REGISTER32_LUT, REGISTER8_LUT, SREGISTER16_LUT, SREGISTER16_LUT_386};

#[derive(Copy, Clone)]
pub struct ModRmByte16 {
    byte: u8,
    b_mod: u8,
    b_reg: u8,
    b_rm: u8,
    disp: Displacement,
    addressing_mode: AddressOffset16,
}


const MODRM16_TABLE: [ModRmByte16; 256] = {
    let mut table: [ModRmByte16; 256] = [ModRmByte16 {
        byte: 0,
        b_mod: 0,
        b_reg: 0,
        b_rm: 0,
        disp: Displacement::NoDisp,
        addressing_mode: AddressOffset16::BxSi,
    }; 256];
    let mut byte = 0;

    loop {
        let mut displacement = Displacement::NoDisp;

        let b_mod = (byte >> 6) & 0x03;

        match b_mod {
            0b00 => {
                // Addressing mode [disp16] is a single mode of 0b00
                if byte & ModRmByte16::MODRM_ADDR_MASK == ModRmByte16::MODRM_ADDR_DISP16 {
                    displacement = Displacement::Disp16(0);
                }
            }
            0b01 => {
                // 0b01 signifies an 8 bit displacement (sign-extended to 16)
                displacement = Displacement::Disp8(0);
            }
            0b10 => {
                // 0b10 signifies a 16 bit displacement
                displacement = Displacement::Disp16(0);
            }
            _ => displacement = Displacement::NoDisp,
        }

        // Set the addressing mode based on the combination of Mod and R/M bitfields + Displacement.
        let addressing_mode = match byte & ModRmByte16::MODRM_ADDR_MASK {
            ModRmByte16::MODRM_ADDR_BX_SI => AddressOffset16::BxSi,
            ModRmByte16::MODRM_ADDR_BX_DI => AddressOffset16::BxDi,
            ModRmByte16::MODRM_ADDR_BP_SI => AddressOffset16::BpSi,
            ModRmByte16::MODRM_ADDR_BP_DI => AddressOffset16::BpDi,
            ModRmByte16::MODRM_ADDR_SI => AddressOffset16::Si,
            ModRmByte16::MODRM_ADDR_DI => AddressOffset16::Di,
            ModRmByte16::MODRM_ADDR_DISP16 => AddressOffset16::Disp16(0),
            ModRmByte16::MODRM_ADDR_BX => AddressOffset16::Bx,
            ModRmByte16::MODRM_ADDR_BX_SI_DISP8 => AddressOffset16::BxSiDisp8(0),
            ModRmByte16::MODRM_ADDR_BX_DI_DISP8 => AddressOffset16::BxDiDisp8(0),
            ModRmByte16::MODRM_ADDR_BP_SI_DISP8 => AddressOffset16::BpSiDisp8(0),
            ModRmByte16::MODRM_ADDR_BP_DI_DISP8 => AddressOffset16::BpDiDisp8(0),
            ModRmByte16::MODRM_ADDR_SI_DISP8 => AddressOffset16::SiDisp8(0),
            ModRmByte16::MODRM_ADDR_DI_DISP8 => AddressOffset16::DiDisp8(0),
            ModRmByte16::MODRM_ADDR_BP_DISP8 => AddressOffset16::BpDisp8(0),
            ModRmByte16::MODRM_ADDR_BX_DISP8 => AddressOffset16::BxDisp8(0),
            ModRmByte16::MODRM_ADDR_BX_SI_DISP16 => AddressOffset16::BxSiDisp16(0),
            ModRmByte16::MODRM_ADDR_BX_DI_DISP16 => AddressOffset16::BxDiDisp16(0),
            ModRmByte16::MODRM_ADDR_BP_SI_DISP16 => AddressOffset16::BpSiDisp16(0),
            ModRmByte16::MODRM_ADDR_BP_DI_DISP16 => AddressOffset16::BpDiDisp16(0),
            ModRmByte16::MODRM_ADDR_SI_DISP16 => AddressOffset16::SiDisp16(0),
            ModRmByte16::MODRM_ADDR_DI_DISP16 => AddressOffset16::DiDisp16(0),
            ModRmByte16::MODRM_ADDR_BP_DISP16 => AddressOffset16::BpDisp16(0),
            ModRmByte16::MODRM_ADDR_BX_DISP16 => AddressOffset16::BxDisp16(0),
            _ => AddressOffset16::None,
        };

        // 'REG' field specifies either register operand or opcode extension. There's no way
        // to know without knowing the opcode, which we don't
        let b_reg: u8 = (byte >> 3) & 0x07;

        // 'R/M' field is last three bits
        let b_rm: u8 = byte & 0x07;

        table[byte as usize] = ModRmByte16 {
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


impl ModRmByte16 {

    const MODRM_ADDR_MASK: u8 = 0b11_000_111;

    // 16-bit modrm bitmasks
    const MODRM_ADDR_BX_SI: u8 = 0b00_000_000;
    const MODRM_ADDR_BX_DI: u8 = 0b00_000_001;
    const MODRM_ADDR_BP_SI: u8 = 0b00_000_010;
    const MODRM_ADDR_BP_DI: u8 = 0b00_000_011;
    const MODRM_ADDR_SI: u8 = 0b00_000_100;
    const MODRM_ADDR_DI: u8 = 0b00_000_101;
    const MODRM_ADDR_DISP16: u8 = 0b00_000_110;
    const MODRM_ADDR_BX: u8 = 0b00_000_111;

    const MODRM_ADDR_BX_SI_DISP8: u8 = 0b01_000_000;
    const MODRM_ADDR_BX_DI_DISP8: u8 = 0b01_000_001;
    const MODRM_ADDR_BP_SI_DISP8: u8 = 0b01_000_010;
    const MODRM_ADDR_BP_DI_DISP8: u8 = 0b01_000_011;
    const MODRM_ADDR_SI_DISP8: u8 = 0b01_000_100;
    const MODRM_ADDR_DI_DISP8: u8 = 0b01_000_101;
    const MODRM_ADDR_BP_DISP8: u8 = 0b01_000_110;
    const MODRM_ADDR_BX_DISP8: u8 = 0b01_000_111;

    const MODRM_ADDR_BX_SI_DISP16: u8 = 0b10_000_000;
    const MODRM_ADDR_BX_DI_DISP16: u8 = 0b10_000_001;
    const MODRM_ADDR_BP_SI_DISP16: u8 = 0b10_000_010;
    const MODRM_ADDR_BP_DI_DISP16: u8 = 0b10_000_011;
    const MODRM_ADDR_SI_DISP16: u8 = 0b10_000_100;
    const MODRM_ADDR_DI_DISP16: u8 = 0b10_000_101;
    const MODRM_ADDR_BP_DISP16: u8 = 0b10_000_110;
    const MODRM_ADDR_BX_DISP16: u8 = 0b10_000_111;

    #[inline(always)]
    pub fn default_ref() -> &'static ModRmByte16 {
        &MODRM16_TABLE[0]
    }

    #[inline(always)]
    pub fn from_byte(byte: u8) -> ModRmByte16 {
        MODRM16_TABLE[byte as usize].clone()
    }

    /// Read the modrm byte and look up the appropriate value from the modrm table.
    pub fn read(bytes: &mut impl ByteReader, instruction_bytes: &mut Vec<u8>) -> Result<ModRmByte16, Box<dyn std::error::Error>> {
        let raw_modrm_byte = bytes.read_u8()?;
        let mut modrm = ModRmByte16::from_byte(raw_modrm_byte);
        instruction_bytes.push(raw_modrm_byte);

        // If modrm is an addressing mode, load any displacement bytes.
        if modrm.b_mod != 0b11 {
            match modrm.disp {
                Displacement::Disp8(_) => {
                    let disp = bytes.read_u8()?;
                    instruction_bytes.push(disp);
                    modrm.disp = Displacement::Disp8(disp as i8);
                }
                Displacement::Disp16(_) => {
                    let disp = bytes.read_u16()?;
                    instruction_bytes.extend_from_slice(&disp.to_le_bytes());
                    modrm.disp = Displacement::Disp16(disp as i16);
                }
                _ => { /* No displacement to read */ },
            }
        }
        Ok(modrm)
    }

    /// Return the 'mod' field (top two bits) of the modrm byte.
    #[inline(always)]
    pub fn mod_value(&self) -> u8 {
        self.b_mod
    }

    #[inline(always)]
    pub fn reg_value(&self) -> u8 {
        self.b_reg
    }

    /// Set the 'reg' field (middle three bits) of the modrm byte. The argument is assumed to be
    /// an un-shifted 3 bit value (0-7).
    pub fn set_reg(&mut self, reg: u8) {
        self.byte = (self.byte & 0b1100_0111) | ((reg & 0x07) << 3);
        self.b_reg = reg & 0x07;
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

    #[inline(always)]
    pub fn op2_reg32(&self) -> Register32 {
        REGISTER32_LUT[self.b_reg as usize]
    }

    // Interpret the 'REG' field as a 16 bit segment register selector
    #[inline(always)]
    pub fn op2_segment_reg16(&self) -> Register16 {
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

    // Interpret the 'REG' field as a 3 bit opcode extension
    #[inline(always)]
    pub fn op_extension(&self) -> u8 { self.b_reg }

    // Return whether the modrm byte specifies a memory addressing mode
    #[inline(always)]
    pub fn is_addressing_mode(&self) -> bool {
        self.b_mod != 0b11
    }

    pub fn set_displacement(&mut self, displacement: Displacement) {
        self.disp = displacement;
        match &mut self.addressing_mode {
            AddressOffset16::Disp16(d) => *d = displacement.into(),
            AddressOffset16::BxSiDisp8(d) => *d = displacement.into(),
            AddressOffset16::BxDiDisp8(d) => *d = displacement.into(),
            AddressOffset16::BpSiDisp8(d) => *d = displacement.into(),
            AddressOffset16::BpDiDisp8(d) => *d = displacement.into(),
            AddressOffset16::SiDisp8(d) => *d = displacement.into(),
            AddressOffset16::DiDisp8(d) => *d = displacement.into(),
            AddressOffset16::BpDisp8(d) => *d = displacement.into(),
            AddressOffset16::BxDisp8(d) => *d = displacement.into(),
            AddressOffset16::BxSiDisp16(d) => *d = displacement.into(),
            AddressOffset16::BxDiDisp16(d) => *d = displacement.into(),
            AddressOffset16::BpSiDisp16(d) => *d = displacement.into(),
            AddressOffset16::BpDiDisp16(d) => *d = displacement.into(),
            AddressOffset16::SiDisp16(d) => *d = displacement.into(),
            AddressOffset16::DiDisp16(d) => *d = displacement.into(),
            AddressOffset16::BpDisp16(d) => *d = displacement.into(),
            AddressOffset16::BxDisp16(d) => *d = displacement.into(),
            _ => {}
        }
    }

    /// Produce an [AddressOffset16] enum with the provided [Displacement] inserted.
    #[inline(always)]
    pub fn address_offset(&self, displacement: Displacement) -> AddressOffset16 {
        match self.addressing_mode {
            AddressOffset16::Disp16(_) => AddressOffset16::Disp16(displacement.into()),
            AddressOffset16::BxSiDisp8(_) => AddressOffset16::BxSiDisp8(displacement.into()),
            AddressOffset16::BxDiDisp8(_) => AddressOffset16::BxDiDisp8(displacement.into()),
            AddressOffset16::BpSiDisp8(_) => AddressOffset16::BpSiDisp8(displacement.into()),
            AddressOffset16::BpDiDisp8(_) => AddressOffset16::BpDiDisp8(displacement.into()),
            AddressOffset16::SiDisp8(_) => AddressOffset16::SiDisp8(displacement.into()),
            AddressOffset16::DiDisp8(_) => AddressOffset16::DiDisp8(displacement.into()),
            AddressOffset16::BpDisp8(_) => AddressOffset16::BpDisp8(displacement.into()),
            AddressOffset16::BxDisp8(_) => AddressOffset16::BxDisp8(displacement.into()),
            AddressOffset16::BxSiDisp16(_) => AddressOffset16::BxSiDisp16(displacement.into()),
            AddressOffset16::BxDiDisp16(_) => AddressOffset16::BxDiDisp16(displacement.into()),
            AddressOffset16::BpSiDisp16(_) => AddressOffset16::BpSiDisp16(displacement.into()),
            AddressOffset16::BpDiDisp16(_) => AddressOffset16::BpDiDisp16(displacement.into()),
            AddressOffset16::SiDisp16(_) => AddressOffset16::SiDisp16(displacement.into()),
            AddressOffset16::DiDisp16(_) => AddressOffset16::DiDisp16(displacement.into()),
            AddressOffset16::BpDisp16(_) => AddressOffset16::BpDisp16(displacement.into()),
            AddressOffset16::BxDisp16(_) => AddressOffset16::BxDisp16(displacement.into()),
            _ => self.addressing_mode,
        }
    }

    #[inline(always)]
    pub fn displacement(&self) -> Displacement {
        self.disp
    }

    #[inline(always)]
    pub fn raw_byte(&self) -> u8 {
        self.byte
    }
}
