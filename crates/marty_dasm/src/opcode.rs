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
use std::fmt::{Display, UpperHex};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq, Hash)]
pub struct Opcode {
    extended: u16,
}

impl From<u8> for Opcode {
    fn from(value: u8) -> Self {
        Opcode { extended: value as u16 }
    }
}

impl From<u16> for Opcode {
    fn from(value: u16) -> Self {
        Opcode { extended: value }
    }
}

impl From<Opcode> for u16 {
    fn from(opcode: Opcode) -> Self {
        opcode.extended
    }
}

impl From<Opcode> for u8 {
    fn from(opcode: Opcode) -> Self {
        opcode.extended as u8
    }
}

impl Display for Opcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.extended <= 0xFF {
            write!(f, "{:02X}", self.extended)
        }
        else {
            write!(f, "{:04X}", self.extended)
        }
    }
}

impl UpperHex for Opcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl Opcode {
    pub fn to_bytes(&self) -> Vec<u8> {
        if self.extended <= 0xFF {
            vec![self.extended as u8]
        }
        else {
            vec![(self.extended >> 8) as u8, (self.extended & 0xFF) as u8]
        }
    }

    pub fn is_extended(&self) -> bool {
        self.extended > 0xFF
    }

    pub fn base_opcode(&self) -> u8 {
        (self.extended & 0xFF) as u8
    }
}
