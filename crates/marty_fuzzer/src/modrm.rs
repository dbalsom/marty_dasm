use std::ops::RangeInclusive;
use rand::prelude::StdRng;
use rand::Rng;
use marty_dasm::modrm16::ModRmByte16;
use marty_dasm::modrm32::ModRmByte32;
use marty_dasm::prelude::AddressSize;

pub enum ModRm {
    ModRm16(ModRmByte16),
    ModRm32(ModRmByte32),
}

#[derive(Default)]
pub struct ModRmFuzzer {
    address_size: AddressSize,
    //r#mod: Option<u8>,
    reg: Option<u8>,
    //rm: Option<u8>,
    extension_range: Option<RangeInclusive<u8>>
}

impl ModRmFuzzer {

    pub fn new(address_size: AddressSize) -> Self {
        Self {
            address_size,
            ..Default::default()
        }
    }

    // pub fn with_mod(mut self, r#mod: u8) -> Self {
    //     self.r#mod = Some(r#mod);
    //     self
    // }

    pub fn with_reg(mut self, reg: u8) -> Self {
        self.reg = Some(reg);
        self
    }

    // pub fn with_rm(mut self, rm: u8) -> Self {
    //     self.rm = Some(rm);
    //     self
    // }

    pub fn with_extension_range(mut self, range: RangeInclusive<u8>) -> Self {
        self.extension_range = Some(range);
        self
    }

    pub fn build(&self, rng: &mut StdRng) -> ModRm {
        let raw_byte: u8 = rng.random();

        match self.address_size {
            AddressSize::Address16 => {

                let mut modrm = ModRmByte16::from_byte(raw_byte);

                // If a reg value is specifically specified, it takes priority.
                // Otherwise, we'll use the extension range if provided.
                if let Some(reg) = self.reg {
                    modrm.set_reg(reg);
                }
                else if let Some(reg_range) = &self.extension_range {
                    let reg = rng.random_range(reg_range.clone());
                    modrm.set_reg(reg);
                }

                ModRm::ModRm16(modrm)

            },
            AddressSize::Address32 => {

                let mut modrm = ModRmByte32::from_byte(raw_byte);

                if let Some(reg) = self.reg {
                    modrm.set_reg(reg);
                }
                else if let Some(reg_range) = &self.extension_range {
                    let reg = rng.random_range(reg_range.clone());
                    modrm.set_reg(reg);
                }

                ModRm::ModRm32(modrm)
            },
        }
    }
}