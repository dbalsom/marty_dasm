use std::ops::RangeInclusive;

use crate::modrm::ModRm;
use marty_dasm::{modrm16::ModRmByte16, modrm32::ModRmByte32, prelude::AddressSize};
use rand::{prelude::StdRng, Rng};

pub struct ModRmFuzzer {
    address_size: AddressSize,
    allow_reg_form: bool,
    r#mod: Option<u8>,
    reg: Option<u8>,
    //rm: Option<u8>,
    extension_range: Option<RangeInclusive<u8>>,
}

impl Default for ModRmFuzzer {
    fn default() -> Self {
        Self {
            address_size: AddressSize::Address16,
            allow_reg_form: true,
            r#mod: None,
            reg: None,
            //rm: None,
            extension_range: None,
        }
    }
}

impl ModRmFuzzer {
    pub fn new(address_size: AddressSize) -> Self {
        Self {
            address_size,
            ..Default::default()
        }
    }

    pub fn with_reg_form(mut self, allow_reg_form: bool) -> Self {
        self.allow_reg_form = allow_reg_form;
        self
    }

    pub fn with_mod(mut self, r#mod: u8) -> Self {
        self.r#mod = Some(r#mod);
        self
    }

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

                if let Some(r#mod) = self.r#mod {
                    modrm.set_mod(r#mod);
                }
                else if !self.allow_reg_form {
                    // Ensure we don't generate a reg form (mod == 11)
                    modrm.set_mod(rng.random_range(0..=2));
                }
                else {
                    modrm.set_mod(rng.random_range(0..=3));
                }

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
            }
            AddressSize::Address32 => {
                let mut modrm = ModRmByte32::from_byte(raw_byte);

                if let Some(r#mod) = self.r#mod {
                    modrm.set_mod(r#mod);
                }
                else if !self.allow_reg_form {
                    // Ensure we don't generate a reg form (mod == 11)
                    modrm.set_mod(rng.random_range(0..=2));
                }
                else {
                    modrm.set_mod(rng.random_range(0..=3));
                }

                // If a reg value is specifically specified, it takes priority.
                // Otherwise, we'll use the extension range if provided.
                if let Some(reg) = self.reg {
                    modrm.set_reg(reg);
                }
                else if let Some(reg_range) = &self.extension_range {
                    let reg = rng.random_range(reg_range.clone());
                    modrm.set_reg(reg);
                }

                ModRm::ModRm32(modrm)
            }
        }
    }
}
