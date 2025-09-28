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

use std::io::{BufReader, Read};
use crate::cpu_common::SegmentSize;
use crate::i80386::Intel80386;
use crate::instruction::Instruction;
use crate::i808X::Intel808x;
use crate::VX0::NecVx0;

/// Supported CPU families for decoding
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub enum CpuType {
    #[default]
    Intel808x, // 8088/8086
    NecVx0,    // V20/V30
    Intel8018x,
    Intel80286,
    Intel80386,
}

/// Options controlling decoding behavior
#[derive(Copy, Clone, Debug)]
pub struct DecoderOptions {
    pub cpu: CpuType,
    pub segment_size: SegmentSize,
}

impl Default for DecoderOptions {
    fn default() -> Self {
        Self { cpu: CpuType::Intel808x, segment_size: SegmentSize::Segment16 }
    }
}

/// A generic decoder that consumes bytes from any Read and produces Instructions
pub struct Decoder<R: Read> {
    reader: BufReader<R>,
    opts: DecoderOptions,
}

impl<R: Read> Decoder<R> {
    /// Create a new Decoder from any Read with the given options
    pub fn new(inner: R, opts: DecoderOptions) -> Self {
        Self { reader: BufReader::new(inner), opts }
    }

    /// Borrow the options
    pub fn options(&self) -> DecoderOptions { self.opts }

    /// Mutably update options
    pub fn set_options(&mut self, opts: DecoderOptions) { self.opts = opts; }

    /// Decode the next instruction from the stream according to the configured CPU
    pub fn decode_next(&mut self) -> Result<Instruction, Box<dyn std::error::Error>> {
        match self.opts.cpu {
            CpuType::Intel808x => Intel808x::decode(&mut self.reader),
            CpuType::NecVx0 => NecVx0::decode(&mut self.reader),
            CpuType::Intel8018x => unimplemented!("8018x decoding not implemented yet"),
            CpuType::Intel80286 => unimplemented!("80286 decoding not implemented yet"),
            CpuType::Intel80386 => Intel80386::decode(&mut self.reader, self.opts.segment_size)
        }
    }
}

/// Convenience helper to decode a single instruction from a Read with options
pub fn decode_one<R: Read>(reader: R, opts: DecoderOptions) -> Result<Instruction, Box<dyn std::error::Error>> {
    let mut dec = Decoder::new(reader, opts);
    dec.decode_next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use crate::mnemonic::Mnemonic;

    #[test]
    fn decode_nop_808x() {
        let bytes = [0x90u8]; // NOP
        let mut dec = Decoder::new(Cursor::new(&bytes[..]), DecoderOptions { cpu: CpuType::Intel808x, ..Default::default() });
        let ins = dec.decode_next().expect("decode ok");
        assert_eq!(ins.instruction_bytes, bytes);
        assert_eq!(ins.mnemonic, Mnemonic::NOP);
    }

    #[test]
    fn decode_nop_vx0() {
        let bytes = [0x90u8]; // NOP is common
        let mut dec = Decoder::new(Cursor::new(&bytes[..]), DecoderOptions { cpu: CpuType::NecVx0, ..Default::default() });
        let ins = dec.decode_next().expect("decode ok");
        assert_eq!(ins.instruction_bytes, bytes);
        assert_eq!(ins.mnemonic, Mnemonic::NOP);
    }

    #[test]
    fn decode_add32_386() {
        let bytes = [0x01u8, 0x00u8]; // ADD
        let mut dec = Decoder::new(Cursor::new(&bytes[..]), DecoderOptions { cpu: CpuType::Intel80386, ..Default::default() });
        let ins = dec.decode_next().expect("decode ok");
        assert_eq!(ins.instruction_bytes, bytes);
        assert_eq!(ins.mnemonic, Mnemonic::ADD);
    }
}
