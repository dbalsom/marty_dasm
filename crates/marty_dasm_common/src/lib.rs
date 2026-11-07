// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Daniel Balsom

use std::fmt::{Display, UpperHex};

/// Supported x86 CPU families.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Hash)]
pub enum CpuType {
    /// Intel 8088/8086.
    #[default]
    Intel808x,
    /// NEC V20/V30.
    NecVx0,
    Intel8018x,
    Intel80286,
    Intel80386,
}

/// Intel math coprocessor models supported by the shared x87 decoder.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum FpuType {
    Intel8087,
    Intel80287,
    /// 387 instruction core with the 287 CPU interface and active mode controls.
    Intel80287XL,
    Intel80387,
}

impl CpuType {
    /// Coprocessors compatible with this CPU's interface.
    ///
    /// The 286 can use the 387 instruction set through a 287XL. A 386 can use
    /// either the 287 interface (287/287XL) or a 387, but cannot use an 8087.
    pub const fn compatible_fpus(self) -> &'static [FpuType] {
        match self {
            Self::Intel808x | Self::Intel8018x | Self::NecVx0 => &[FpuType::Intel8087],
            Self::Intel80286 => &[FpuType::Intel80287, FpuType::Intel80287XL],
            Self::Intel80386 => &[FpuType::Intel80287, FpuType::Intel80287XL, FpuType::Intel80387],
        }
    }

    pub fn is_fpu_compatible(self, fpu: FpuType) -> bool {
        self.compatible_fpus().contains(&fpu)
    }
}

/// An encoded opcode and, when applicable, its ModR/M group extension.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone, Default, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Opcode {
    value: u16,
    extension: Option<u8>,
}

impl Opcode {
    /// Construct an opcode without a ModR/M group extension.
    pub const fn new(value: u16) -> Self {
        Self { value, extension: None }
    }

    /// Construct an opcode with a three-bit ModR/M group extension.
    pub const fn with_extension(value: u16, extension: u8) -> Self {
        assert!(extension <= 7, "opcode extension must be between 0 and 7");
        Self {
            value,
            extension: Some(extension),
        }
    }

    /// Construct an opcode from its constituent parts.
    pub const fn from_parts(value: u16, extension: Option<u8>) -> Self {
        match extension {
            Some(extension) => Self::with_extension(value, extension),
            None => Self::new(value),
        }
    }

    pub const fn value(self) -> u16 {
        self.value
    }

    pub const fn extension(self) -> Option<u8> {
        self.extension
    }

    /// Return the bytes that encode the opcode itself, excluding any ModR/M byte.
    pub fn to_bytes(self) -> Vec<u8> {
        if self.value <= 0xFF {
            vec![self.value as u8]
        } else {
            vec![(self.value >> 8) as u8, (self.value & 0xFF) as u8]
        }
    }

    /// Return whether this is a multi-byte opcode.
    pub const fn is_extended(self) -> bool {
        self.value > 0xFF
    }

    pub const fn base_opcode(self) -> u8 {
        (self.value & 0xFF) as u8
    }
}

impl From<u8> for Opcode {
    fn from(value: u8) -> Self {
        Self::new(value as u16)
    }
}

impl From<u16> for Opcode {
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}

impl From<Opcode> for u16 {
    fn from(opcode: Opcode) -> Self {
        opcode.value
    }
}

impl From<Opcode> for u8 {
    fn from(opcode: Opcode) -> Self {
        opcode.value as u8
    }
}

impl Display for Opcode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.value <= 0xFF {
            write!(formatter, "{:02X}", self.value)?;
        } else {
            write!(formatter, "{:04X}", self.value)?;
        }
        if let Some(extension) = self.extension {
            write!(formatter, "/{extension}")?;
        }
        Ok(())
    }
}

impl UpperHex for Opcode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, formatter)
    }
}
