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
use std::{collections::HashMap, path::Path, str::FromStr};

use crate::{error::IsaDbError, IsaRecord};
use marty_dasm::{decoder::CpuType, prelude::Opcode};

pub const ISA386: &[u8] = include_bytes!("../isa_db/80386.csv");

pub struct IsaDB {
    pub cpu_type: CpuType,
    pub records: Vec<IsaRecord>,
    pub record_hash: HashMap<Opcode, usize>,
}

#[derive(Copy, Clone)]
pub struct IterFilter {
    pub accept_fpu: bool,
    pub accept_protected: bool,
    pub accept_undefined: bool,
}

impl IsaDB {
    pub fn new(cpu_type: CpuType) -> Result<IsaDB, IsaDbError> {
        let mut csv_reader = match cpu_type {
            CpuType::Intel80386 => csv::Reader::from_reader(ISA386.as_ref()),
            _ => {
                return Err(IsaDbError::InvalidOptions(format!(
                    "Unsupported CPU type: {:?}",
                    cpu_type
                )))
            }
        };

        let mut records: Vec<IsaRecord> = Vec::new();
        let mut record_hash: HashMap<Opcode, usize> = HashMap::new();

        for result in csv_reader.deserialize::<IsaRecord>() {
            match result {
                Ok(mut record) => {
                    record.init();

                    let index = records.len();
                    records.push(record);
                    record_hash.insert(records[index].opcode, index);
                }
                Err(e) => {
                    return Err(IsaDbError::IoError(e.into()));
                }
            }
        }

        Ok(IsaDB {
            cpu_type,
            records,
            record_hash,
        })
    }

    pub fn from_file(cpu_type: CpuType, path: impl AsRef<Path>) -> Result<IsaDB, IsaDbError> {
        let mut csv_reader = csv::Reader::from_path(path.as_ref()).map_err(|e| IsaDbError::IoError(e.into()))?;

        let mut records: Vec<IsaRecord> = Vec::new();
        let mut record_hash: HashMap<Opcode, usize> = HashMap::new();

        for result in csv_reader.deserialize::<IsaRecord>() {
            match result {
                Ok(mut record) => {
                    record.init();

                    let index = records.len();
                    records.push(record);
                    record_hash.insert(records[index].opcode, index);
                }
                Err(e) => {
                    return Err(IsaDbError::IoError(e.into()));
                }
            }
        }

        Ok(IsaDB {
            cpu_type,
            records,
            record_hash,
        })
    }

    pub fn opcode(&self, opcode: Opcode) -> Option<&IsaRecord> {
        self.record_hash.get(&opcode).map(|&index| &self.records[index])
    }

    pub fn opcode_iter(&self, filter: IterFilter) -> impl Iterator<Item = &IsaRecord> {
        self.records.iter().filter(move |record| {
            (filter.accept_fpu || !record.is_fpu)
                && (filter.accept_undefined || !record.is_undefined)
                && (filter.accept_protected || !record.is_protected)
        })
    }
}
