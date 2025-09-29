use marty_dasm::{modrm16::ModRmByte16, modrm32::ModRmByte32};

pub enum ModRm {
    ModRm16(ModRmByte16),
    ModRm32(ModRmByte32),
}

impl ModRm {
    pub fn has_sib(&self) -> bool {
        match self {
            ModRm::ModRm16(_) => false,
            ModRm::ModRm32(m) => m.has_sib(),
        }
    }

    pub fn raw_byte(&self) -> u8 {
        match self {
            ModRm::ModRm16(m) => m.raw_byte(),
            ModRm::ModRm32(m) => m.raw_byte(),
        }
    }
}
