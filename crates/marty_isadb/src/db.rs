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
use marty_dasm::{decoder::CpuType, prelude::Opcode};
use std::path::Path;

use crate::error::IsaDbError;

use std::{collections::HashMap, str::FromStr};

use serde::Deserialize;

pub const ISA386: &[u8] = include_bytes!("../isa_db/80386.csv");

fn de_hex_u16<'de, D>(de: D) -> Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(de)?;
    let s = s.trim();
    // Accept "0x1A", "1a", "1A", allow underscores
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let s = s.replace('_', "");
    u16::from_str_radix(&s, 16).map_err(serde::de::Error::custom)
}

fn de_ext_u8<'de, D>(de: D) -> Result<Option<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(de)?;
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    u8::from_str(&s).map(|v| Some(v)).map_err(serde::de::Error::custom)
}

fn de_bool<'de, D>(de: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(de)?;
    let s = s.trim().to_lowercase();
    // Assume empty is 'false'
    if s.is_empty() {
        return Ok(false);
    }
    match s.as_str() {
        "true" | "1" | "y" | "yes" => Ok(true),
        "false" | "0" | "n" | "no" => Ok(false),
        _ => Err(serde::de::Error::custom(format!("Invalid boolean value: {}", s))),
    }
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct IsaRecord {
    #[serde(skip)]
    pub opcode: Opcode,
    #[serde(rename = "op")]
    #[serde(deserialize_with = "de_hex_u16")]
    pub opcode_raw: u16,
    #[serde(rename = "pf")]
    #[serde(deserialize_with = "de_bool")]
    pub is_prefix: bool,
    #[serde(rename = "g")]
    #[serde(deserialize_with = "de_ext_u8")]
    pub group: Option<u8>,
    #[serde(rename = "ex")]
    #[serde(deserialize_with = "de_ext_u8")]
    pub extension: Option<u8>,
    #[serde(rename = "fpu")]
    #[serde(deserialize_with = "de_bool")]
    pub is_fpu: bool,
    #[serde(rename = "ud")]
    #[serde(deserialize_with = "de_bool")]
    pub is_undefined: bool,
    #[serde(rename = "pm")]
    #[serde(deserialize_with = "de_bool")]
    pub is_protected: bool,
    #[serde(rename = "m")]
    #[serde(deserialize_with = "de_bool")]
    pub has_modrm: bool,
    #[serde(rename = "reg")]
    #[serde(deserialize_with = "de_bool")]
    pub allow_reg_form: bool,
}

impl IsaRecord {
    pub fn init(&mut self) {
        self.opcode = Opcode::from(self.opcode_raw);
    }
}

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
