// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Daniel Balsom

// Decode flags use the same bit positions as the 80386 template. Only the
// properties needed by the 16-bit 80286 decoder are implemented.
pub const GDR_REG_0: u16 = 0x0004;
pub const GDR_NO_MODRM: u16 = 0x0010;
pub const GDR_USES_SREG: u16 = 0x0100;
pub const GDR_NO_REG_FORM: u16 = 0x2000;
pub const GDR_DISAMBIGUATE: u16 = 0x8000;

#[derive(Copy, Clone)]
pub struct GdrEntry(pub u16);

impl GdrEntry {
    pub fn has_modrm(self) -> bool {
        self.0 & GDR_NO_MODRM == 0
    }

    pub fn has_reg_form(self) -> bool {
        self.0 & GDR_NO_REG_FORM == 0
    }

    pub fn must_use_reg0(self) -> bool {
        self.0 & GDR_REG_0 != 0
    }

    pub fn uses_segment_reg(self) -> bool {
        self.0 & GDR_USES_SREG != 0
    }

    pub fn needs_disambiguation(self) -> bool {
        self.0 & GDR_DISAMBIGUATE != 0
    }
}
