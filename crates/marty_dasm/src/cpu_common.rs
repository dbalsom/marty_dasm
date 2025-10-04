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
    borrow::Borrow,
    fmt::{Display, Formatter},
};
// Instruction prefixes

pub struct PrefixFlags {}

impl PrefixFlags {
    pub const ES_OVERRIDE: u32 = 0b_0000_0000_0000_0100;
    pub const CS_OVERRIDE: u32 = 0b_0000_0000_0000_1000;
    pub const SS_OVERRIDE: u32 = 0b_0000_0000_0001_0000;
    pub const DS_OVERRIDE: u32 = 0b_0000_0000_0010_0000;
    pub const FS_OVERRIDE: u32 = 0b_0000_0000_0100_0000;
    pub const GS_OVERRIDE: u32 = 0b_0000_0000_1000_0000;
    pub const SEG_OVERRIDE_MASK: u32 = 0b_0000_0000_1111_1100;
    pub const LOCK: u32 = 0b_0000_0001_0000_0000;
    pub const REP1: u32 = 0b_0000_0010_0000_0000;
    pub const REP2: u32 = 0b_0000_0100_0000_0000;
    pub const REP3: u32 = 0b_0000_1000_0000_0000;
    pub const REP4: u32 = 0b_0001_0000_0000_0000;
    pub const REP_MASK: u32 = 0b_0001_1110_0000_0000;
    pub const OPERAND_SIZE: u32 = 0b_0010_0000_0000_0000;
    pub const ADDRESS_SIZE: u32 = 0b_0100_0000_0000_0000;
    pub const EXTENDED_0F: u32 = 0b_1000_0000_0000_0000;
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Register8 {
    AL,
    CL,
    DL,
    BL,
    AH,
    CH,
    DH,
    BH,
}

impl Display for Register8 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Register8::AL => write!(f, "al"),
            Register8::CL => write!(f, "cl"),
            Register8::DL => write!(f, "dl"),
            Register8::BL => write!(f, "bl"),
            Register8::AH => write!(f, "ah"),
            Register8::CH => write!(f, "ch"),
            Register8::DH => write!(f, "dh"),
            Register8::BH => write!(f, "bh"),
        }
    }
}

pub const REGISTER8_LUT: [Register8; 8] = [
    Register8::AL,
    Register8::CL,
    Register8::DL,
    Register8::BL,
    Register8::AH,
    Register8::CH,
    Register8::DH,
    Register8::BH,
];

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Register16 {
    AX,
    CX,
    DX,
    BX,
    SP,
    BP,
    SI,
    DI,
    ES,
    CS,
    SS,
    DS,
    FS,
    GS,
    PC,
    InvalidRegister,
}

impl Register16 {
    #[inline]
    pub fn is_segment_reg(&self) -> bool {
        matches!(
            self,
            Register16::ES | Register16::CS | Register16::SS | Register16::DS | Register16::FS | Register16::GS
        )
    }
}

pub const REGISTER16_LUT: [Register16; 8] = [
    Register16::AX,
    Register16::CX,
    Register16::DX,
    Register16::BX,
    Register16::SP,
    Register16::BP,
    Register16::SI,
    Register16::DI,
];

pub const SREGISTER16_LUT: [Register16; 8] = [
    Register16::ES,
    Register16::CS,
    Register16::SS,
    Register16::DS,
    Register16::ES,
    Register16::CS,
    Register16::SS,
    Register16::DS,
];

pub const SREGISTER16_LUT_386: [Register16; 8] = [
    Register16::ES,
    Register16::CS,
    Register16::SS,
    Register16::DS,
    Register16::FS,
    Register16::GS,
    Register16::InvalidRegister,
    Register16::InvalidRegister,
];

pub const CREGISTER_LUT: [ControlRegister; 8] = [
    ControlRegister::CR0,
    ControlRegister::CR1,
    ControlRegister::CR2,
    ControlRegister::CR3,
    ControlRegister::CR4,
    ControlRegister::CR5,
    ControlRegister::CR6,
    ControlRegister::CR7,
];

pub const DREGISTER_LUT: [DebugRegister; 8] = [
    DebugRegister::DR0,
    DebugRegister::DR1,
    DebugRegister::DR2,
    DebugRegister::DR3,
    DebugRegister::DR4,
    DebugRegister::DR5,
    DebugRegister::DR6,
    DebugRegister::DR7,
];

impl Register16 {
    pub fn is_segment(&self) -> bool {
        matches!(
            self,
            Register16::ES | Register16::CS | Register16::SS | Register16::DS | Register16::FS | Register16::GS
        )
    }
}

impl Display for Register16 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Register16::AX => write!(f, "ax"),
            Register16::CX => write!(f, "cx"),
            Register16::DX => write!(f, "dx"),
            Register16::BX => write!(f, "bx"),
            Register16::SP => write!(f, "sp"),
            Register16::BP => write!(f, "bp"),
            Register16::SI => write!(f, "si"),
            Register16::DI => write!(f, "di"),
            Register16::ES => write!(f, "es"),
            Register16::CS => write!(f, "cs"),
            Register16::SS => write!(f, "ss"),
            Register16::DS => write!(f, "ds"),
            Register16::FS => write!(f, "fs"),
            Register16::GS => write!(f, "gs"),
            Register16::PC => write!(f, "ip"),
            Register16::InvalidRegister => write!(f, "invalid"),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum DebugRegister {
    DR0,
    DR1,
    DR2,
    DR3,
    DR4,
    DR5,
    DR6,
    DR7,
    InvalidRegister,
}

impl Display for DebugRegister {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DebugRegister::DR0 => write!(f, "dr0"),
            DebugRegister::DR1 => write!(f, "dr1"),
            DebugRegister::DR2 => write!(f, "dr2"),
            DebugRegister::DR3 => write!(f, "dr3"),
            DebugRegister::DR4 => write!(f, "dr4"),
            DebugRegister::DR5 => write!(f, "dr5"),
            DebugRegister::DR6 => write!(f, "dr6"),
            DebugRegister::DR7 => write!(f, "dr7"),
            DebugRegister::InvalidRegister => write!(f, "invalid"),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ControlRegister {
    CR0,
    CR1,
    CR2,
    CR3,
    CR4,
    CR5,
    CR6,
    CR7,
    InvalidRegister,
}

impl Display for ControlRegister {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlRegister::CR0 => write!(f, "cr0"),
            ControlRegister::CR1 => write!(f, "cr1"),
            ControlRegister::CR2 => write!(f, "cr2"),
            ControlRegister::CR3 => write!(f, "cr3"),
            ControlRegister::CR4 => write!(f, "cr4"),
            ControlRegister::CR5 => write!(f, "cr5"),
            ControlRegister::CR6 => write!(f, "cr6"),
            ControlRegister::CR7 => write!(f, "cr7"),
            ControlRegister::InvalidRegister => write!(f, "invalid"),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Register32 {
    EAX,
    ECX,
    EDX,
    EBX,
    ESP,
    EBP,
    ESI,
    EDI,
    ES,
    CS,
    SS,
    DS,
    FS,
    GS,
    PC,
    InvalidRegister,
}

impl From<Register16> for Register32 {
    fn from(reg: Register16) -> Self {
        match reg {
            Register16::AX => Register32::EAX,
            Register16::CX => Register32::ECX,
            Register16::DX => Register32::EDX,
            Register16::BX => Register32::EBX,
            Register16::SP => Register32::ESP,
            Register16::BP => Register32::EBP,
            Register16::SI => Register32::ESI,
            Register16::DI => Register32::EDI,
            Register16::ES => Register32::ES,
            Register16::CS => Register32::CS,
            Register16::SS => Register32::SS,
            Register16::DS => Register32::DS,
            Register16::FS => Register32::FS,
            Register16::GS => Register32::GS,
            Register16::PC => Register32::PC,
            Register16::InvalidRegister => Register32::InvalidRegister,
        }
    }
}

pub const REGISTER32_LUT: [Register32; 8] = [
    Register32::EAX,
    Register32::ECX,
    Register32::EDX,
    Register32::EBX,
    Register32::ESP,
    Register32::EBP,
    Register32::ESI,
    Register32::EDI,
];

#[allow(dead_code)]
pub const SREGISTER32_LUT: [Register32; 8] = [
    Register32::ES,
    Register32::CS,
    Register32::SS,
    Register32::DS,
    Register32::ES,
    Register32::CS,
    Register32::SS,
    Register32::DS,
];

impl Display for Register32 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Register32::EAX => write!(f, "eax"),
            Register32::ECX => write!(f, "ecx"),
            Register32::EDX => write!(f, "edx"),
            Register32::EBX => write!(f, "ebx"),
            Register32::ESP => write!(f, "esp"),
            Register32::EBP => write!(f, "ebp"),
            Register32::ESI => write!(f, "esi"),
            Register32::EDI => write!(f, "edi"),
            Register32::ES => write!(f, "es"),
            Register32::CS => write!(f, "cs"),
            Register32::SS => write!(f, "ss"),
            Register32::DS => write!(f, "ds"),
            Register32::FS => write!(f, "fs"),
            Register32::GS => write!(f, "gs"),
            Register32::PC => write!(f, "eip"),
            Register32::InvalidRegister => write!(f, "invalid"),
        }
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub enum SegmentSize {
    #[default]
    Segment16,
    Segment32,
}

impl SegmentSize {
    pub fn operand_size_override(&self) -> OperandSize {
        match self {
            SegmentSize::Segment16 => OperandSize::Operand32,
            SegmentSize::Segment32 => OperandSize::Operand16,
        }
    }

    pub fn address_size_override(&self) -> AddressSize {
        match self {
            SegmentSize::Segment16 => AddressSize::Address32,
            SegmentSize::Segment32 => AddressSize::Address16,
        }
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub enum AddressSize {
    #[default]
    Address16,
    Address32,
}

impl AddressSize {
    pub fn with_override(&self) -> AddressSize {
        match self {
            AddressSize::Address16 => AddressSize::Address32,
            AddressSize::Address32 => AddressSize::Address16,
        }
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub enum OperandSize {
    #[default]
    NoOperand,
    Operand8,
    Operand16,
    Operand32,
}

impl OperandSize {
    pub fn with_override(&self) -> OperandSize {
        match self {
            OperandSize::Operand8 => OperandSize::Operand8,
            OperandSize::Operand16 => OperandSize::Operand32,
            OperandSize::Operand32 => OperandSize::Operand16,
            OperandSize::NoOperand => OperandSize::NoOperand,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Displacement {
    NoDisp,
    Disp8(i8),
    Disp16(i16),
    Disp32(i32),
}

impl Displacement {
    pub fn is_some(&self) -> bool {
        !matches!(self, Displacement::NoDisp)
    }
    pub fn len(&self) -> usize {
        match self {
            Displacement::NoDisp => 0,
            Displacement::Disp8(_) => 1,
            Displacement::Disp16(_) => 2,
            Displacement::Disp32(_) => 4,
        }
    }
}

impl Display for Displacement {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Displacement::NoDisp => write!(f, "[None]"),
            Displacement::Disp8(v) => {
                if *v < 0 {
                    write!(f, "-{:X}h", -(*v as i16))
                }
                else {
                    write!(f, "+{:X}h", v)
                }
            }
            Displacement::Disp16(v) => {
                if *v < 0 {
                    write!(f, "-{:X}h", -(*v as i32))
                }
                else {
                    write!(f, "+{:X}h", v)
                }
            }
            Displacement::Disp32(v) => {
                if *v < 0 {
                    write!(f, "-{:X}h", -(*v as i64))
                }
                else {
                    write!(f, "+{:X}h", v)
                }
            }
        }
    }
}

impl From<Displacement> for i8 {
    fn from(value: Displacement) -> Self {
        match value {
            Displacement::Disp8(v) => v,
            _ => 0,
        }
    }
}

impl From<Displacement> for i16 {
    fn from(value: Displacement) -> Self {
        match value {
            Displacement::Disp16(v) => v,
            _ => 0,
        }
    }
}

impl From<Displacement> for i32 {
    fn from(value: Displacement) -> Self {
        match value {
            Displacement::Disp32(v) => v,
            _ => 0,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AddressOffset16 {
    None,
    BxSi,
    BxDi,
    BpSi,
    BpDi,
    Si,
    Di,
    Disp16(i16),
    Bx,
    BxSiDisp8(i8),
    BxDiDisp8(i8),
    BpSiDisp8(i8),
    BpDiDisp8(i8),
    SiDisp8(i8),
    DiDisp8(i8),
    BpDisp8(i8),
    BxDisp8(i8),
    BxSiDisp16(i16),
    BxDiDisp16(i16),
    BpSiDisp16(i16),
    BpDiDisp16(i16),
    SiDisp16(i16),
    DiDisp16(i16),
    BpDisp16(i16),
    BxDisp16(i16),
}

impl AddressOffset16 {
    pub fn base_register(&self) -> Register16 {
        use AddressOffset16::*;
        match self {
            BpSi | BpSiDisp8(_) | BpSiDisp16(_) | BpDisp8(_) => Register16::SS,
            BpDi | BpDiDisp8(_) | BpDiDisp16(_) | BpDisp16(_) => Register16::SS,
            _ => Register16::DS,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum BaseRegister {
    None,
    Some(Register32),
}

impl BaseRegister {
    pub fn is_some(&self) -> bool {
        !matches!(self, BaseRegister::None)
    }
}

impl Display for BaseRegister {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            BaseRegister::None => write!(f, ""),
            BaseRegister::Some(reg) => write!(f, "{}", reg),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum SibScale {
    One,
    Two,
    Four,
    Eight,
}

impl Display for SibScale {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SibScale::One => write!(f, "*1"),
            SibScale::Two => write!(f, "*2"),
            SibScale::Four => write!(f, "*4"),
            SibScale::Eight => write!(f, "*8"),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ScaledIndex {
    None,
    EaxScaled(SibScale),
    EcxScaled(SibScale),
    EdxScaled(SibScale),
    EbxScaled(SibScale),
    EbpScaled(SibScale),
    EsiScaled(SibScale),
    EdiScaled(SibScale),
}

impl ScaledIndex {
    pub fn is_some(&self) -> bool {
        !matches!(self, ScaledIndex::None)
    }
}

impl Display for ScaledIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ScaledIndex::None => write!(f, ""),
            ScaledIndex::EaxScaled(scale) => write!(f, "eax{}", scale),
            ScaledIndex::EcxScaled(scale) => write!(f, "ecx{}", scale),
            ScaledIndex::EdxScaled(scale) => write!(f, "edx{}", scale),
            ScaledIndex::EbxScaled(scale) => write!(f, "ebx{}", scale),
            ScaledIndex::EbpScaled(scale) => write!(f, "ebp{}", scale),
            ScaledIndex::EsiScaled(scale) => write!(f, "esi{}", scale),
            ScaledIndex::EdiScaled(scale) => write!(f, "edi{}", scale),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AddressOffset32 {
    None,
    Eax,
    Ecx,
    Edx,
    Ebx,
    Disp32(i32),
    Ebp,
    Esi,
    Edi,
    EaxDisp8(i8),
    EcxDisp8(i8),
    EdxDisp8(i8),
    EbxDisp8(i8),
    EspDisp8(i8),
    EbpDisp8(i8),
    EsiDisp8(i8),
    EdiDisp8(i8),
    EaxDisp32(i32),
    EcxDisp32(i32),
    EdxDisp32(i32),
    EbxDisp32(i32),
    EspDisp32(i32),
    EbpDisp32(i32),
    EsiDisp32(i32),
    EdiDisp32(i32),
    SibPending,
    Sib(BaseRegister, ScaledIndex),
    SibDisp8(BaseRegister, ScaledIndex, i8),
    SibDisp32(BaseRegister, ScaledIndex, i32),
    SibDisp8Ebp(BaseRegister, ScaledIndex, i8),
    SibDisp32Ebp(BaseRegister, ScaledIndex, i32),
}

impl AddressOffset32 {
    pub fn base_register(&self) -> Register16 {
        use AddressOffset32::*;
        match self {
            Ebp | EbpDisp8(_) | EbpDisp32(_) => Register16::SS,
            SibDisp8Ebp(_, _, _) | SibDisp32Ebp(_, _, _) => Register16::SS,
            Sib(BaseRegister::Some(Register32::ESP), _) => Register16::SS,
            SibDisp8(BaseRegister::Some(Register32::ESP), _, _) => Register16::SS,
            SibDisp32(BaseRegister::Some(Register32::ESP), _, _) => Register16::SS,
            _ => Register16::DS,
        }
    }
}

macro_rules! disp_hex {
    ($t:ty, $x:expr) => {{
        // Accept value or reference: coerce to &T via Borrow, then copy out (Copy for ints).
        let v: $t = *<$t as Borrow<$t>>::borrow(&$x);
        format!("{v:X}h")
    }};
}

macro_rules! signed_hex {
    ($t:ty, $x:expr) => {{
        // Accept value or reference: coerce to &T via Borrow, then copy out (Copy for ints).
        let v: $t = *<$t as Borrow<$t>>::borrow(&$x);

        let neg = v < 0;
        let mag = v.unsigned_abs() as u32; // magnitude as unsigned

        // Print in decimal if small
        if mag < 10 {
            if mag == 0 {
                format!("")
            }
            else if neg {
                format!("-{}", mag)
            }
            else {
                format!("+{}", mag)
            }
        }
        else {
            // Hex without width
            let s = format!("{:X}", mag);

            if neg { format!("-{s}h") } else { format!("+{s}h") }
        }
    }};
}

impl Display for AddressOffset16 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use AddressOffset16::*;
        match self {
            None => write!(f, ""),
            BxSi => write!(f, "bx+si"),
            BxDi => write!(f, "bx+di"),
            BpSi => write!(f, "bp+si"),
            BpDi => write!(f, "bp+di"),
            Si => write!(f, "si"),
            Di => write!(f, "di"),
            Disp16(disp) => write!(f, "{}", disp_hex!(i16, disp)),
            Bx => write!(f, "bx"),
            BxSiDisp8(disp) => write!(f, "bx+si{}", signed_hex!(i8, disp)),
            BxDiDisp8(disp) => write!(f, "bx+di{}", signed_hex!(i8, disp)),
            BpSiDisp8(disp) => write!(f, "bp+si{}", signed_hex!(i8, disp)),
            BpDiDisp8(disp) => write!(f, "bp+di{}", signed_hex!(i8, disp)),
            SiDisp8(disp) => write!(f, "si{}", signed_hex!(i8, disp)),
            DiDisp8(disp) => write!(f, "di{}", signed_hex!(i8, disp)),
            BpDisp8(disp) => write!(f, "bp{}", signed_hex!(i8, disp)),
            BxDisp8(disp) => write!(f, "bx{}", signed_hex!(i8, disp)),
            BxSiDisp16(disp) => write!(f, "bx+si{}", signed_hex!(i16, disp)),
            BxDiDisp16(disp) => write!(f, "bx+di{}", signed_hex!(i16, disp)),
            BpSiDisp16(disp) => write!(f, "bp+si{}", signed_hex!(i16, disp)),
            BpDiDisp16(disp) => write!(f, "bp+di{}", signed_hex!(i16, disp)),
            SiDisp16(disp) => write!(f, "si{}", signed_hex!(i16, disp)),
            DiDisp16(disp) => write!(f, "di{}", signed_hex!(i16, disp)),
            BpDisp16(disp) => write!(f, "bp{}", signed_hex!(i16, disp)),
            BxDisp16(disp) => write!(f, "bx{}", signed_hex!(i16, disp)),
        }
    }
}

impl Display for AddressOffset32 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use AddressOffset32::*;

        match self {
            Eax => write!(f, "eax"),
            Ecx => write!(f, "ecx"),
            Edx => write!(f, "edx"),
            Ebx => write!(f, "ebx"),
            Disp32(disp) => write!(f, "{}", disp_hex!(i32, disp)),
            Ebp => write!(f, "ebp"),
            Esi => write!(f, "esi"),
            Edi => write!(f, "edi"),
            EaxDisp8(disp) => write!(f, "eax{}", signed_hex!(i8, disp)),
            EcxDisp8(disp) => write!(f, "ecx{}", signed_hex!(i8, disp)),
            EdxDisp8(disp) => write!(f, "edx{}", signed_hex!(i8, disp)),
            EbxDisp8(disp) => write!(f, "ebx{}", signed_hex!(i8, disp)),
            EspDisp8(disp) => write!(f, "esp{}", signed_hex!(i8, disp)),
            EbpDisp8(disp) => write!(f, "ebp{}", signed_hex!(i8, disp)),
            EsiDisp8(disp) => write!(f, "esi{}", signed_hex!(i8, disp)),
            EdiDisp8(disp) => write!(f, "edi{}", signed_hex!(i8, disp)),
            EaxDisp32(disp) => write!(f, "eax{}", signed_hex!(i32, disp)),
            EcxDisp32(disp) => write!(f, "ecx{}", signed_hex!(i32, disp)),
            EdxDisp32(disp) => write!(f, "edx{}", signed_hex!(i32, disp)),
            EbxDisp32(disp) => write!(f, "ebx{}", signed_hex!(i32, disp)),
            EspDisp32(disp) => write!(f, "esp{}", signed_hex!(i32, disp)),
            EbpDisp32(disp) => write!(f, "ebp{}", signed_hex!(i32, disp)),
            EsiDisp32(disp) => write!(f, "esi{}", signed_hex!(i32, disp)),
            EdiDisp32(disp) => write!(f, "edi{}", signed_hex!(i32, disp)),
            SibPending => write!(f, "**INVALID**"),
            Sib(base, scale) => {
                let plus = if base.is_some() && scale.is_some() { "+" } else { "" };
                write!(f, "{base}{plus}{scale}")
            }
            SibDisp8(base, scale, disp) => {
                let plus = if base.is_some() && scale.is_some() { "+" } else { "" };
                write!(f, "{base}{plus}{scale}{}", signed_hex!(i8, disp))
            }
            SibDisp32(BaseRegister::None, ScaledIndex::None, disp) => {
                write!(f, "{}", disp_hex!(i32, disp))
            }
            SibDisp32(base, scale, disp) => {
                let plus = if base.is_some() && scale.is_some() { "+" } else { "" };
                write!(f, "{base}{plus}{scale}{}", signed_hex!(i32, disp))
            }
            SibDisp8Ebp(base, scale, disp) => {
                let plus = if base.is_some() && scale.is_some() { "+" } else { "" };
                write!(f, "{base}{plus}{scale}{}", signed_hex!(i8, disp))
            }
            SibDisp32Ebp(base, scale, disp) => {
                let plus = if base.is_some() && scale.is_some() { "+" } else { "" };
                write!(f, "{base}{plus}{scale}{}", signed_hex!(i32, disp))
            }
            None => write!(f, ""),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum OperandType {
    Immediate8(u8),
    Immediate16(u16),
    Immediate32(u32),
    Immediate8s(i8),
    Relative8(i8),
    Relative16(i16),
    Relative32(i32),
    Offset8_16(u16),
    Offset8_32(u32),
    Offset16_16(u16),
    Offset16_32(u32),
    Offset32_16(u16),
    Offset32_32(u32),
    Register8(Register8),
    Register16(Register16),
    Register32(Register32),
    ControlRegister(ControlRegister),
    DebugRegister(DebugRegister),
    AddressingMode16(AddressOffset16, OperandSize),
    AddressingMode32(AddressOffset32, OperandSize),
    FarPointer16(u16, u16),
    FarPointer32(u16, u32),
    M16Pair(u16, u16),
    NoOperand,
    InvalidOperand,
}

impl OperandType {
    #[inline(always)]
    pub fn is_address(&self) -> bool {
        matches!(
            self,
            OperandType::AddressingMode16(_, _) | OperandType::AddressingMode32(_, _)
        )
    }
    #[inline(always)]
    pub fn is_register(&self) -> bool {
        matches!(self, OperandType::Register8(_) | OperandType::Register16(_))
    }
}

/// The ALU operation specifier 'Xi' determines the ALU operation by decoding 5 bits from the group
/// decode rom, opcode, and optionally modrm. We don't bother decoding Xi. Instead, Xi is stored
/// in the precalculated decode table.
#[allow(dead_code)]
#[derive(Copy, Clone, Default, Debug)]
pub enum Xi {
    #[default]
    ADD,
    ADC,
    OR,
    SBB,
    SUB,
    CMP,
    AND,
    XOR,
    ROL,
    ROR,
    RCL,
    RCR,
    SHL,
    SHR,
    SETMO,
    SETMOC,
    SAR,
    PASS,
    DAA,
    DAS,
    AAA,
    AAS,
    INC,
    DEC,
    NOT,
    NEG,
    INC2,
    DEC2,
}
