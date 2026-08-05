// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Daniel Balsom

use marty_dasm::{format_instruction, CpuType, Decoder, DecoderOptions, FormatOptions, SegmentSize};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WebCpu {
    Intel808x,
    NecVx0,
    Intel80386,
}

impl WebCpu {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "intel808x" => Ok(Self::Intel808x),
            "necvx0" => Ok(Self::NecVx0),
            "intel80386" => Ok(Self::Intel80386),
            _ => Err(format!("Unknown CPU type: {value}")),
        }
    }

    fn decoder_options(self, segment_size_value: &str) -> Result<DecoderOptions, String> {
        let (cpu, segment_size) = match self {
            Self::Intel808x => (CpuType::Intel808x, SegmentSize::Segment16),
            Self::NecVx0 => (CpuType::NecVx0, SegmentSize::Segment16),
            Self::Intel80386 => {
                let segment_size = match segment_size_value {
                    "16" => SegmentSize::Segment16,
                    "32" => SegmentSize::Segment32,
                    _ => return Err(format!("Unknown code segment size: {segment_size_value}")),
                };
                (CpuType::Intel80386, segment_size)
            }
        };

        Ok(DecoderOptions { cpu, segment_size })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DisassemblyRow {
    pub(crate) offset: String,
    pub(crate) bytes: String,
    pub(crate) instruction: String,
    pub(crate) is_error: bool,
}

pub(crate) fn parse_hex(input: &str) -> Result<Vec<u8>, String> {
    let normalized = input.replace([',', ';'], " ");
    let mut bytes = Vec::new();

    for raw_token in normalized.split_whitespace() {
        let token = raw_token
            .strip_prefix("0x")
            .or_else(|| raw_token.strip_prefix("0X"))
            .unwrap_or(raw_token);

        if token.is_empty() {
            return Err(format!("Expected hexadecimal digits after '{raw_token}'."));
        }
        if !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!("'{raw_token}' is not a hexadecimal byte."));
        }
        if token.len() % 2 != 0 {
            return Err(format!("'{raw_token}' must contain an even number of hex digits."));
        }

        for pair_start in (0..token.len()).step_by(2) {
            let pair = &token[pair_start..pair_start + 2];
            bytes.push(u8::from_str_radix(pair, 16).expect("validated hexadecimal pair"));
        }
    }

    Ok(bytes)
}

pub(crate) fn disassemble(
    input: &str,
    cpu_value: &str,
    segment_size_value: &str,
    offset_value: &str,
) -> Result<Vec<DisassemblyRow>, String> {
    let bytes = parse_hex(input)?;
    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    let options = WebCpu::parse(cpu_value)?.decoder_options(segment_size_value)?;
    let base_offset = parse_offset(offset_value)?;
    let mut offset = 0usize;
    let mut rows = Vec::new();

    while offset < bytes.len() {
        let mut decoder = Decoder::new(&bytes[offset..], options);
        match decoder.decode_next() {
            Ok(instruction) => {
                let consumed = instruction.instruction_bytes.len();
                if consumed == 0 {
                    return Err(format!("Decoder made no progress at offset {offset:04X}."));
                }
                let encoded = instruction
                    .instruction_bytes
                    .iter()
                    .map(|byte| format!("{byte:02X}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let assembly = format_instruction(
                    &instruction,
                    &FormatOptions {
                        ip: base_offset.wrapping_add(offset as u32),
                        ..Default::default()
                    },
                );
                rows.push(DisassemblyRow {
                    offset: format!("{:08X}", base_offset.wrapping_add(offset as u32)),
                    bytes: encoded,
                    instruction: assembly,
                    is_error: false,
                });
                offset += consumed;
            }
            Err(error) => {
                rows.push(DisassemblyRow {
                    offset: format!("{:08X}", base_offset.wrapping_add(offset as u32)),
                    bytes: format!("{:02X}", bytes[offset]),
                    instruction: format!("db 0x{:02X} ; {error}", bytes[offset]),
                    is_error: true,
                });
                offset += 1;
            }
        }
    }

    Ok(rows)
}

fn parse_offset(value: &str) -> Result<u32, String> {
    if value.is_empty() {
        return Ok(0);
    }
    if value.len() > 8 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Offset must contain no more than 8 hexadecimal digits.".to_owned());
    }
    u32::from_str_radix(value, 16).map_err(|_| "Offset is outside the 32-bit address range.".to_owned())
}

pub(crate) fn format_disassembly_text(rows: &[DisassemblyRow], include_offsets: bool, include_bytes: bool) -> String {
    let offset_width = rows.iter().map(|row| row.offset.len()).max().unwrap_or(0);
    let bytes_width = rows.iter().map(|row| row.bytes.len()).max().unwrap_or(0);
    rows.iter()
        .map(|row| {
            let mut fields = Vec::with_capacity(3);
            if include_offsets {
                fields.push(format!("{:<offset_width$}", row.offset));
            }
            if include_bytes {
                fields.push(format!("{:<bytes_width$}", row.bytes));
            }
            fields.push(row.instruction.clone());
            fields.join("  ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_spaced_prefixed_and_contiguous_hex() {
        assert_eq!(
            parse_hex("0x90, B83412; cd 20"),
            Ok(vec![0x90, 0xB8, 0x34, 0x12, 0xCD, 0x20])
        );
    }

    #[test]
    fn reports_bad_hex_without_panicking() {
        assert!(parse_hex("90 nope").unwrap_err().contains("not a hexadecimal byte"));
        assert!(parse_hex("909").unwrap_err().contains("even number"));
    }

    #[test]
    fn renders_disassembly() {
        let output = disassemble("90 90", "intel808x", "16", "7C00").unwrap();
        assert_eq!(output.len(), 2);
        assert_eq!(output[0].offset, "00007C00");
        assert_eq!(output[0].bytes, "90");
        assert_eq!(output[0].instruction, "nop");
    }

    #[test]
    fn v20_sample_disassembles_without_bad_markers() {
        let output = disassemble("B8 34 12 05 78 56 90", "necvx0", "16", "0").unwrap();
        assert_eq!(output.len(), 3);
        assert!(output.iter().all(|row| !row.instruction.contains("(bad)")));
        assert_eq!(output[0].instruction, "mov ax,1234h");
        assert_eq!(output[1].instruction, "add ax,5678h");
        assert_eq!(output[2].instruction, "nop");
    }

    #[test]
    fn segment_size_controls_386_defaults() {
        let bytes = "B8 34 12 00 00";
        let output_16 = disassemble(bytes, "intel80386", "16", "0").unwrap();
        let output_32 = disassemble(bytes, "intel80386", "32", "0").unwrap();

        assert_eq!(output_16[0].bytes, "B8 34 12");
        assert_eq!(output_16[0].instruction, "mov ax,1234h");
        assert_eq!(output_32[0].bytes, "B8 34 12 00 00");
        assert_eq!(output_32[0].instruction, "mov eax,1234h");
    }

    #[test]
    fn formats_selected_disassembly_fields_for_copying() {
        let rows = disassemble("90 B8 34 12", "intel808x", "16", "0").unwrap();
        assert_eq!(format_disassembly_text(&rows, false, false), "nop\nmov ax,1234h");
        assert_eq!(
            format_disassembly_text(&rows, true, true),
            "00000000  90        nop\n00000001  B8 34 12  mov ax,1234h"
        );
    }

    #[test]
    fn formatted_disassembly_never_uses_tabs() {
        let rows = disassemble("90 B8 34 12", "intel808x", "16", "0").unwrap();
        assert!(!format_disassembly_text(&rows, true, true).contains('\t'));
        assert!(!format_disassembly_text(&rows, false, true).contains('\t'));
        assert!(!format_disassembly_text(&rows, false, false).contains('\t'));
    }
}
