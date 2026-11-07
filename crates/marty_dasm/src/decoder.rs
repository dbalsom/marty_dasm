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

use crate::{
    FpuType,
    VX0::NecVx0,
    cpu_common::SegmentSize,
    error::DecodeError,
    i808X::Intel808x,
    i80286::Intel80286,
    i80386::Intel80386,
    instruction::Instruction,
};
pub use marty_dasm_common::CpuType;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};

struct TrackedReader<R: Read> {
    inner:    BufReader<R>,
    position: u64,
}

impl<R: Read> TrackedReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner:    BufReader::new(inner),
            position: 0,
        }
    }

    fn position(&self) -> u64 {
        self.position
    }
}

impl<R: Read + Seek> TrackedReader<R> {
    fn set_position(&mut self, position: u64) -> io::Result<()> {
        let delta = i128::from(position) - i128::from(self.position);
        let delta = i64::try_from(delta).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "decoder-relative seek offset does not fit in i64",
            )
        })?;

        self.inner.seek(SeekFrom::Current(delta))?;
        self.position = position;
        Ok(())
    }
}

impl<R: Read> Read for TrackedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.position += read as u64;
        Ok(read)
    }
}

impl<R: Read> BufRead for TrackedReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.inner.fill_buf()
    }

    fn consume(&mut self, amount: usize) {
        let consumed = amount.min(self.inner.buffer().len());
        self.inner.consume(amount);
        self.position += consumed as u64;
    }
}

/// Options controlling decoding behavior
#[derive(Copy, Clone, Debug)]
pub struct DecoderOptions {
    pub cpu: CpuType,
    pub segment_size: SegmentSize,
    /// Select a coprocessor from `cpu.compatible_fpus()`. `None` preserves generic ESC decoding.
    pub fpu: Option<FpuType>,
}

impl Default for DecoderOptions {
    fn default() -> Self {
        Self {
            cpu: CpuType::Intel808x,
            segment_size: SegmentSize::Segment16,
            fpu: None,
        }
    }
}

impl DecoderOptions {
    /// Reject incompatible CPU/FPU selections without consuming input.
    pub fn validate(&self) -> Result<(), DecodeError> {
        if let Some(fpu) = self.fpu {
            if !self.cpu.is_fpu_compatible(fpu) {
                return Err(DecodeError::InvalidOptions(format!(
                    "{fpu:?} is not compatible with {:?}",
                    self.cpu
                )));
            }
        }
        Ok(())
    }
}

/// A generic decoder that consumes bytes from any Read and produces Instructions
pub struct Decoder<R: Read> {
    reader: TrackedReader<R>,
    opts:   DecoderOptions,
}

impl<R: Read> Decoder<R> {
    /// Create a new Decoder from any Read with the given options
    pub fn new(inner: R, opts: DecoderOptions) -> Self {
        Self {
            reader: TrackedReader::new(inner),
            opts,
        }
    }

    /// Return the number of bytes consumed since this decoder was created.
    pub fn position(&self) -> u64 {
        self.reader.position()
    }

    /// Return whether the decoder has reached the end of its input without consuming a byte.
    pub fn is_eof(&mut self) -> io::Result<bool> {
        Ok(self.reader.fill_buf()?.is_empty())
    }

    /// Borrow the options
    pub fn options(&self) -> DecoderOptions {
        self.opts
    }

    /// Mutably update options
    pub fn set_options(&mut self, opts: DecoderOptions) {
        self.opts = opts;
    }

    /// Decode the next instruction from the stream according to the configured CPU
    pub fn decode_next(&mut self) -> Result<Instruction, DecodeError> {
        self.opts.validate()?;
        let instruction_start = self.position();
        let result = match self.opts.cpu {
            CpuType::Intel808x => Intel808x::decode(&mut self.reader),
            CpuType::NecVx0 => NecVx0::decode(&mut self.reader),
            CpuType::Intel8018x => unimplemented!("8018x decoding not implemented yet"),
            CpuType::Intel80286 => Intel80286::decode(&mut self.reader),
            CpuType::Intel80386 => Intel80386::decode(&mut self.reader, self.opts.segment_size),
        };

        let result = result.map(|mut instruction| {
            if let Some(fpu) = self.opts.fpu {
                crate::i80X87::apply(&mut instruction, fpu);
            }
            instruction
        });

        match result {
            Err(DecodeError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
                if self.position() == instruction_start {
                    Err(DecodeError::Eof)
                }
                else {
                    Err(DecodeError::UnexpectedEof)
                }
            }
            result => result,
        }
    }
}

impl<R: Read + Seek> Decoder<R> {
    /// Seek to a byte position relative to where this decoder was created.
    pub fn set_position(&mut self, position: u64) -> io::Result<()> {
        self.reader.set_position(position)
    }

    /// Rewind to the position where this decoder was created.
    pub fn rewind(&mut self) -> io::Result<()> {
        self.set_position(0)
    }
}

/// Convenience helper to decode a single instruction from a Read with options
pub fn decode_one<R: Read>(reader: R, opts: DecoderOptions) -> Result<Instruction, DecodeError> {
    let mut dec = Decoder::new(reader, opts);
    dec.decode_next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mnemonic::Mnemonic;
    use std::io::Cursor;

    #[test]
    fn decode_nop_808x() {
        let bytes = [0x90u8]; // NOP
        let mut dec = Decoder::new(
            Cursor::new(&bytes[..]),
            DecoderOptions {
                cpu: CpuType::Intel808x,
                ..Default::default()
            },
        );
        let ins = dec.decode_next().expect("decode ok");
        assert_eq!(ins.instruction_bytes, bytes);
        assert_eq!(ins.mnemonic, Mnemonic::NOP);
    }

    #[test]
    fn decode_nop_vx0() {
        let bytes = [0x90u8]; // NOP is common
        let mut dec = Decoder::new(
            Cursor::new(&bytes[..]),
            DecoderOptions {
                cpu: CpuType::NecVx0,
                ..Default::default()
            },
        );
        let ins = dec.decode_next().expect("decode ok");
        assert_eq!(ins.instruction_bytes, bytes);
        assert_eq!(ins.mnemonic, Mnemonic::NOP);
    }

    #[test]
    fn decode_add32_386() {
        let bytes = [0x01u8, 0x00u8]; // ADD
        let mut dec = Decoder::new(
            Cursor::new(&bytes[..]),
            DecoderOptions {
                cpu: CpuType::Intel80386,
                ..Default::default()
            },
        );
        let ins = dec.decode_next().expect("decode ok");
        assert_eq!(ins.instruction_bytes, bytes);
        assert_eq!(ins.mnemonic, Mnemonic::ADD);
    }
}
