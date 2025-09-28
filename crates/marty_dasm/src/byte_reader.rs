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
use std::io::{self, BufRead};

/// The [ByteReader] trait extends [BufRead] with methods for reading and peeking fixed-length
/// little-endian values.
pub trait ByteReader: BufRead {
    // --- reading (advances the cursor) ---

    /// Reads a single u8 from the stream.
    fn read_u8(&mut self) -> io::Result<u8> {
        let buf = self.fill_buf()?;
        if buf.is_empty() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read_u8(): EOF"));
        }
        let b = buf[0];
        self.consume(1);
        Ok(b)
    }

    /// Reads a single i8 from the stream.
    fn read_i8(&mut self) -> io::Result<i8> {
        Ok(self.read_u8()? as i8)
    }

    /// Reads a little-endian u16 from the stream.
    fn read_u16(&mut self) -> io::Result<u16> {
        let lo = self.read_u8()?;
        let hi = self.read_u8()?;
        Ok(u16::from_le_bytes([lo, hi]))
    }

    /// Reads a little-endian i16 from the stream.
    fn read_i16(&mut self) -> io::Result<i16> {
        Ok(i16::from_le_bytes(self.read_u16()?.to_le_bytes()))
    }

    /// Reads a little-endian u32 from the stream.
    fn read_u32(&mut self) -> io::Result<u32> {
        let b0 = self.read_u8()?;
        let b1 = self.read_u8()?;
        let b2 = self.read_u8()?;
        let b3 = self.read_u8()?;
        Ok(u32::from_le_bytes([b0, b1, b2, b3]))
    }

    /// Reads a little-endian i32 from the stream.
    fn read_i32(&mut self) -> io::Result<i32> {
        Ok(i32::from_le_bytes(self.read_u32()?.to_le_bytes()))
    }

    // --- peeking (does NOT advance the cursor) ---

    /// Peeks a single u8 from the stream.
    fn peek_u8(&mut self) -> io::Result<u8> {
        let buf = self.fill_buf()?;
        if buf.is_empty() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peek_u8(): EOF"));
        }
        Ok(buf[0])
    }

    /// Peeks a single i8 from the stream.
    fn peek_i8(&mut self) -> io::Result<i8> {
        Ok(self.peek_u8()? as i8)
    }

    /// Peeks a little-endian u16 from the stream.
    fn peek_u16(&mut self) -> io::Result<u16> {
        let buf = self.fill_buf()?;
        match buf.len() {
            n if n >= 2 => Ok(u16::from_le_bytes([buf[0], buf[1]])),
            0 => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peek_u16(): EOF")),
            n => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("peek_u16(): insufficient bytes: {n} byte(s) buffered"),
            )),
        }
    }

    /// Peeks a little-endian i16 from the stream.
    fn peek_i16(&mut self) -> io::Result<i16> {
        Ok(i16::from_le_bytes(self.peek_u16()?.to_le_bytes()))
    }

    /// Peeks an x86 far pointer stored in memory as \[offset:u16\]\[segment:u16\] (both little-endian).
    /// Returns (segment, offset).
    fn peek_farptr16(&mut self) -> io::Result<(u16, u16)> {
        let buf = self.fill_buf()?;
        match buf.len() {
            n if n >= 4 => {
                let off = u16::from_le_bytes([buf[0], buf[1]]);
                let seg = u16::from_le_bytes([buf[2], buf[3]]);
                self.consume(4);
                Ok((seg, off))
            }
            0 => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peek_farptr16(): EOF")),
            n => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("peek_farptr16(): insufficient bytes: {n} byte(s) buffered")
            )),
        }
    }

    fn read_farptr16(&mut self) -> io::Result<(u16, u16)> {
        let buf = self.fill_buf()?;
        match buf.len() {
            n if n >= 4 => {
                let off = u16::from_le_bytes([buf[0], buf[1]]);
                let seg = u16::from_le_bytes([buf[2], buf[3]]);
                self.consume(4);
                Ok((seg, off))
            }
            0 => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read_farptr16(): EOF")),
            n => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("read_farptr16(): insufficient bytes: {n} byte(s) buffered")
            )),
        }
    }

    fn read_farptr32(&mut self) -> io::Result<(u16, u32)> {
        let buf = self.fill_buf()?;
        match buf.len() {
            n if n >= 6 => {
                let off = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                let seg = u16::from_le_bytes([buf[4], buf[5]]);
                self.consume(6);
                Ok((seg, off))
            }
            0 => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read_farptr32(): EOF")),
            n => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("read_farptr16(): insufficient bytes: {n} byte(s) buffered")
            )),
        }
    }
}

// Allow any BufRead to be used as a ByteReader
impl<T: BufRead + ?Sized> ByteReader for T {}
