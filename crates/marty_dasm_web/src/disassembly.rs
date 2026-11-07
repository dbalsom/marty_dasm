// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Daniel Balsom

use marty_dasm::{CpuType, Decoder, DecoderOptions, FormatOptions, FpuType, SegmentSize, format_instruction};
use std::{fmt, io::Cursor};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WebCpu {
    Intel808x,
    NecVx0,
    Intel80286,
    Intel80386,
}

impl WebCpu {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "intel808x" => Ok(Self::Intel808x),
            "necvx0" => Ok(Self::NecVx0),
            "intel80286" => Ok(Self::Intel80286),
            "intel80386" => Ok(Self::Intel80386),
            _ => Err(format!("Unknown CPU type: {value}")),
        }
    }

    fn decoder_options(self, segment_size_value: &str, fpu_value: &str) -> Result<DecoderOptions, String> {
        let (cpu, segment_size) = match self {
            Self::Intel808x => (CpuType::Intel808x, SegmentSize::Segment16),
            Self::NecVx0 => (CpuType::NecVx0, SegmentSize::Segment16),
            Self::Intel80286 => (CpuType::Intel80286, SegmentSize::Segment16),
            Self::Intel80386 => {
                let segment_size = match segment_size_value {
                    "16" => SegmentSize::Segment16,
                    "32" => SegmentSize::Segment32,
                    _ => return Err(format!("Unknown code segment size: {segment_size_value}")),
                };
                (CpuType::Intel80386, segment_size)
            }
        };

        let fpu = match fpu_value {
            "disabled" => None,
            "intel8087" => Some(FpuType::Intel8087),
            "intel80287" => Some(FpuType::Intel80287),
            "intel80287xl" => Some(FpuType::Intel80287XL),
            "intel80387" => Some(FpuType::Intel80387),
            _ => return Err(format!("Unknown FPU type: {fpu_value}")),
        };
        let options = DecoderOptions { cpu, segment_size, fpu };
        options.validate().map_err(|error| error.to_string())?;
        Ok(options)
    }
}

/// Shared by the selector and input validation so the compatibility rules agree.
pub(crate) fn is_compatible_fpu(cpu_value: &str, fpu_value: &str) -> bool {
    WebCpu::parse(cpu_value)
        .and_then(|cpu| cpu.decoder_options("16", fpu_value))
        .is_ok()
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DisassemblyRow {
    pub(crate) offset: String,
    pub(crate) bytes: String,
    pub(crate) byte_count: usize,
    pub(crate) instruction: String,
    pub(crate) is_error: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum DisassemblyError {
    IncompleteHexByte(String),
    Message(String),
}

impl DisassemblyError {
    pub(crate) fn is_incomplete_hex_byte(&self) -> bool {
        matches!(self, Self::IncompleteHexByte(_))
    }
}

impl fmt::Display for DisassemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompleteHexByte(message) | Self::Message(message) => formatter.write_str(message),
        }
    }
}

impl From<String> for DisassemblyError {
    fn from(message: String) -> Self {
        Self::Message(message)
    }
}

pub(crate) fn parse_input(input: &str, expand_unicode: bool) -> Result<Vec<u8>, DisassemblyError> {
    let mut bytes = Vec::new();

    for line in input.lines() {
        let uncommented = line.split_once(';').map_or(line, |(hex, _)| hex);
        let mut hex_token = String::new();

        for character in uncommented.chars() {
            if character == ',' || character.is_whitespace() {
                append_hex_token(&hex_token, &mut bytes)?;
                hex_token.clear();
            }
            else if expand_unicode && !character.is_ascii() {
                append_hex_token(&hex_token, &mut bytes)?;
                hex_token.clear();

                let mut encoded = [0; 4];
                bytes.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
            }
            else {
                hex_token.push(character);
            }
        }

        append_hex_token(&hex_token, &mut bytes)?;
    }

    Ok(bytes)
}

fn append_hex_token(raw_token: &str, bytes: &mut Vec<u8>) -> Result<(), DisassemblyError> {
    if raw_token.is_empty() {
        return Ok(());
    }

    let token = raw_token
        .strip_prefix("0x")
        .or_else(|| raw_token.strip_prefix("0X"))
        .unwrap_or(raw_token);

    if token.is_empty() {
        return Err(DisassemblyError::Message(format!(
            "Expected hexadecimal digits after '{raw_token}'."
        )));
    }
    if let Some(invalid_character) = token.chars().find(|character| !character.is_ascii_hexdigit()) {
        return Err(DisassemblyError::Message(format!(
            "{invalid_character:?} is not a hexadecimal byte."
        )));
    }
    if token.len() % 2 != 0 {
        return Err(DisassemblyError::IncompleteHexByte(format!(
            "'{raw_token}' must contain an even number of hex digits."
        )));
    }

    for pair_start in (0..token.len()).step_by(2) {
        let pair = &token[pair_start..pair_start + 2];
        bytes.push(u8::from_str_radix(pair, 16).expect("validated hexadecimal pair"));
    }

    Ok(())
}

pub(crate) fn binary_md5(bytes: &[u8]) -> String {
    format!("{:x}", md5::compute(bytes))
}

pub(crate) fn compact_input(input: &str, expand_unicode: bool) -> Result<String, DisassemblyError> {
    let bytes = parse_input(input, expand_unicode)?;
    Ok(bytes.chunks(32).map(format_hex_bytes).collect::<Vec<_>>().join("\n"))
}

pub(crate) fn compact_url_input(input: &str, expand_unicode: bool) -> Result<String, DisassemblyError> {
    parse_input(input, expand_unicode).map(|bytes| format_hex_bytes(&bytes))
}

fn format_hex_bytes(bytes: &[u8]) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX_DIGITS[(byte >> 4) as usize] as char);
        output.push(HEX_DIGITS[(byte & 0x0F) as usize] as char);
    }
    output
}

pub(crate) fn disassemble(
    input: &str,
    cpu_value: &str,
    fpu_value: &str,
    segment_size_value: &str,
    offset_value: &str,
    expand_unicode: bool,
) -> Result<Vec<DisassemblyRow>, DisassemblyError> {
    let bytes = parse_input(input, expand_unicode)?;
    disassemble_bytes(&bytes, cpu_value, fpu_value, segment_size_value, offset_value)
}

pub(crate) fn disassemble_bytes(
    bytes: &[u8],
    cpu_value: &str,
    fpu_value: &str,
    segment_size_value: &str,
    offset_value: &str,
) -> Result<Vec<DisassemblyRow>, DisassemblyError> {
    let options = WebCpu::parse(cpu_value)?.decoder_options(segment_size_value, fpu_value)?;
    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    let base_offset = parse_offset(offset_value)?;
    let mut decoder = Decoder::new(Cursor::new(bytes), options);
    let mut offset = 0usize;
    let mut rows = Vec::new();

    while offset < bytes.len() {
        match decoder.decode_next() {
            Ok(instruction) => {
                let consumed = instruction.instruction_bytes.len();
                if consumed == 0 {
                    return Err(DisassemblyError::Message(format!(
                        "Decoder made no progress at offset {offset:04X}."
                    )));
                }
                let next_offset = usize::try_from(decoder.position()).map_err(|_| {
                    DisassemblyError::Message("Decoder position exceeds the platform address space.".to_owned())
                })?;
                if next_offset != offset + consumed {
                    return Err(DisassemblyError::Message(format!(
                        "Decoder position mismatch at offset {offset:04X}."
                    )));
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
                    byte_count: consumed,
                    instruction: assembly,
                    is_error: !instruction.is_valid,
                });
                offset = next_offset;
            }
            Err(error) if error.is_unexpected_eof() => {
                let remaining = &bytes[offset..];
                let encoded = remaining
                    .iter()
                    .map(|byte| format!("{byte:02X}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let data = remaining
                    .iter()
                    .map(|byte| format!("0x{byte:02X}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                rows.push(DisassemblyRow {
                    offset: format!("{:08X}", base_offset.wrapping_add(offset as u32)),
                    bytes: encoded,
                    byte_count: remaining.len(),
                    instruction: format!("db {data} ; Unexpected EOF"),
                    is_error: true,
                });
                break;
            }
            Err(error) => {
                rows.push(DisassemblyRow {
                    offset: format!("{:08X}", base_offset.wrapping_add(offset as u32)),
                    bytes: format!("{:02X}", bytes[offset]),
                    byte_count: 1,
                    instruction: format!("db 0x{:02X} ; {error}", bytes[offset]),
                    is_error: true,
                });
                offset += 1;
                decoder.set_position(offset as u64).map_err(|seek_error| {
                    DisassemblyError::Message(format!(
                        "Could not recover the decoder at offset {offset:04X}: {seek_error}"
                    ))
                })?;
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
    fn coprocessor_choices_follow_cpu_compatibility() {
        let fpus = ["disabled", "intel8087", "intel80287", "intel80287xl", "intel80387"];
        for (cpu, allowed) in [
            ("intel808x", [true, true, false, false, false]),
            ("necvx0", [true, true, false, false, false]),
            ("intel80286", [true, false, true, true, false]),
            ("intel80386", [true, false, true, true, true]),
        ] {
            for (fpu, compatible) in fpus.into_iter().zip(allowed) {
                assert_eq!(is_compatible_fpu(cpu, fpu), compatible);
                for input in ["", "D8 C0"] {
                    let result = disassemble(input, cpu, fpu, "16", "0", false);
                    assert_eq!(result.is_ok(), compatible, "{cpu} {fpu} {input}");
                    if !compatible {
                        assert!(result.unwrap_err().to_string().contains("not compatible"));
                    }
                }
            }
        }
        assert!(!is_compatible_fpu("unknown", "disabled"));
        assert!(!is_compatible_fpu("intel80386", "unknown"));
    }

    #[test]
    fn unrecognized_fpu_escapes_are_not_web_decode_errors() {
        for (cpu, fpu) in [("intel80286", "intel80287"), ("intel80386", "intel80387")] {
            let rows = disassemble("DB 36 34 12 D9 D1 90", cpu, fpu, "16", "100", false).unwrap();
            assert_eq!(rows.len(), 3);
            assert_eq!(rows[0].instruction, "esc [ds:1234h]");
            assert_eq!(rows[1].instruction, "esc cx");
            assert_eq!(rows[2].instruction, "nop");
            assert_eq!(rows[2].offset, "00000106");
            assert!(rows.iter().all(|row| !row.is_error));
        }
    }

    #[test]
    fn selects_a_coprocessor_independently_from_the_cpu() {
        let bytes = "D9 FE DF E0 DF C1 90";
        let i287 = disassemble(bytes, "intel80386", "intel80287", "16", "100", false).unwrap();
        assert_eq!(i287[0].instruction, "esc si");
        assert!(!i287[0].is_error);
        assert_eq!(i287[1].instruction, "fnstsw ax");
        assert_eq!(i287[2].instruction, "ffreep st1");
        assert_eq!(i287[3].offset, "00000106");
        let i387 = disassemble(bytes, "intel80386", "intel80387", "16", "100", false).unwrap();
        assert_eq!(i387[0].instruction, "fsin");
        assert!(i387.iter().all(|row| !row.is_error));
        let i8087 = disassemble(bytes, "intel808x", "intel8087", "16", "100", false).unwrap();
        assert!(
            i8087[..2]
                .iter()
                .all(|row| row.instruction.starts_with("esc ") && !row.is_error)
        );
        assert_eq!(i8087[2].instruction, "ffreep st1");
        let disabled = disassemble(bytes, "intel80386", "disabled", "16", "100", false).unwrap();
        assert!(
            disabled[..3]
                .iter()
                .all(|row| row.instruction.starts_with("esc ") && !row.is_error)
        );
    }

    #[test]
    fn selects_287xl_for_387_instructions_on_a_286() {
        let bytes = "D9 F5 D9 FB D9 FE D9 FF DD E7 DD EF DA E9 DB E4 DB F4 DB E5 90";
        let rows = disassemble(bytes, "intel80286", "intel80287xl", "32", "100", false).unwrap();
        assert_eq!(
            rows.iter().map(|row| row.instruction.as_str()).collect::<Vec<_>>(),
            [
                "fprem1",
                "fsincos",
                "fsin",
                "fcos",
                "fucom st7",
                "fucomp st7",
                "fucompp",
                "fsetpm",
                "frstpm",
                "frstpm",
                "nop",
            ]
        );
        assert!(rows.iter().all(|row| !row.is_error));
        assert_eq!(rows.last().unwrap().offset, "00000114");
        let i287 = disassemble(bytes, "intel80286", "intel80287", "16", "100", false).unwrap();
        assert!(i287.iter().all(|row| !row.is_error));
        assert!(i287[..7].iter().all(|row| row.instruction.starts_with("esc ")));
        assert!(i287[8..10].iter().all(|row| row.instruction.starts_with("esc ")));
        assert_eq!(i287[7].instruction, "fsetpm");
        assert_eq!(i287[10].instruction, "nop");
    }

    #[test]
    fn renders_fpu_memory_and_wait_without_merging_instructions() {
        let rows = disassemble(
            "9B DB E3 67 DD 44 8D F0 66 D9 20",
            "intel80386",
            "intel80387",
            "16",
            "0",
            false,
        )
        .unwrap();
        let assembly: Vec<_> = rows.iter().map(|row| row.instruction.as_str()).collect();
        assert_eq!(
            assembly,
            [
                "wait",
                "fninit",
                "fld qword [ss:ebp+ecx*4-10h]",
                "o32 fldenv [ds:bx+si]"
            ]
        );
        assert_eq!(rows.iter().map(|row| row.byte_count).sum::<usize>(), 11);
    }

    #[test]
    fn rejects_unknown_fpu_choices() {
        assert!(disassemble("90", "intel80386", "intel80487", "16", "0", false).is_err());
    }

    #[test]
    fn parses_spaced_prefixed_and_contiguous_hex() {
        assert_eq!(
            parse_input("0x90, B83412\ncd 20", false),
            Ok(vec![0x90, 0xB8, 0x34, 0x12, 0xCD, 0x20])
        );
    }

    #[test]
    fn ignores_semicolon_comments_to_end_of_line() {
        assert_eq!(
            parse_input("90 B8 ; ignored CC\n34 12; ignored\n; entire line\nCD20", false),
            Ok(vec![0x90, 0xB8, 0x34, 0x12, 0xCD, 0x20])
        );
    }

    #[test]
    fn hashes_the_parsed_binary_bytes() {
        let bytes = parse_input("0xB8, 34 12 ; ignored\n90", false).unwrap();
        assert_eq!(bytes, [0xB8, 0x34, 0x12, 0x90]);
        assert_eq!(binary_md5(&bytes), "8b482637c70369dd47d7725f964df219");
        assert_eq!(binary_md5(&[]), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn reports_bad_hex_without_panicking() {
        assert_eq!(
            parse_input("90 nope", false),
            Err(DisassemblyError::Message("'n' is not a hexadecimal byte.".to_owned()))
        );
    }

    #[test]
    fn reports_only_the_first_invalid_unicode_character() {
        assert_eq!(
            parse_input("🐸☺️😖🐰", false),
            Err(DisassemblyError::Message("'🐸' is not a hexadecimal byte.".to_owned()))
        );
    }

    #[test]
    fn distinguishes_an_incomplete_hex_byte_from_invalid_input() {
        assert!(matches!(
            parse_input("90 0", false),
            Err(DisassemblyError::IncompleteHexByte(_))
        ));
    }

    #[test]
    fn expands_non_ascii_unicode_as_utf8_when_enabled() {
        let input = "90😀CC é漢 ❤️ ; ignored 🐄\n0xB8";
        let mut expected = vec![0x90];
        expected.extend_from_slice("😀".as_bytes());
        expected.push(0xCC);
        expected.extend_from_slice("é漢".as_bytes());
        expected.extend_from_slice("❤️".as_bytes());
        expected.push(0xB8);

        assert_eq!(parse_input(input, true), Ok(expected));
    }

    #[test]
    fn rejects_unicode_when_expansion_is_disabled() {
        assert!(matches!(
            parse_input("90 😀 CC", false),
            Err(DisassemblyError::Message(_))
        ));
    }

    #[test]
    fn preserves_incomplete_hex_errors_at_unicode_boundaries() {
        assert!(matches!(
            parse_input("9😀", true),
            Err(DisassemblyError::IncompleteHexByte(_))
        ));
    }

    #[test]
    fn compacting_expands_unicode_before_formatting() {
        assert_eq!(compact_input("90😀CC", true), Ok("90F09F9880CC".to_owned()));
    }

    #[test]
    fn compacts_url_input_without_line_breaks_or_comments() {
        let input = format!("{} ; first line\n{}", "90 ".repeat(32), "0xCC,".repeat(33));
        let expected = format!("{}{}", "90".repeat(32), "CC".repeat(33));
        assert_eq!(compact_url_input(&input, false), Ok(expected));
    }

    #[test]
    fn renders_disassembly() {
        let output = disassemble("90 90", "intel808x", "disabled", "16", "7C00", false).unwrap();
        assert_eq!(output.len(), 2);
        assert_eq!(output[0].offset, "00007C00");
        assert_eq!(output[0].bytes, "90");
        assert_eq!(output[0].instruction, "nop");
    }

    #[test]
    fn reports_truncated_instructions_as_unexpected_eof() {
        let output = disassemble("05", "intel808x", "disabled", "16", "0", false).unwrap();

        assert_eq!(output[0].instruction, "db 0x05 ; Unexpected EOF");
    }

    #[test]
    fn stops_after_a_partial_decode_at_eof() {
        let output = disassemble("05 34", "intel808x", "disabled", "16", "0", false).unwrap();

        assert_eq!(output.len(), 1);
        assert_eq!(output[0].bytes, "05 34");
        assert_eq!(output[0].byte_count, 2);
        assert_eq!(output[0].instruction, "db 0x05, 0x34 ; Unexpected EOF");
    }

    #[test]
    fn does_not_restart_inside_a_truncated_instruction() {
        let output = disassemble("EC BB 93", "intel808x", "disabled", "16", "100", false).unwrap();

        assert_eq!(output.len(), 2);
        assert_eq!(output[0].instruction, "in al,dx");
        assert_eq!(output[1].offset, "00000101");
        assert_eq!(output[1].bytes, "BB 93");
        assert_eq!(output[1].instruction, "db 0xBB, 0x93 ; Unexpected EOF");
    }

    #[test]
    fn v20_sample_disassembles_without_bad_markers() {
        let output = disassemble("B8 34 12 05 78 56 90", "necvx0", "disabled", "16", "0", false).unwrap();
        assert_eq!(output.len(), 3);
        assert!(output.iter().all(|row| !row.instruction.contains("(bad)")));
        assert_eq!(output[0].instruction, "mov ax,1234h");
        assert_eq!(output[1].instruction, "add ax,5678h");
        assert_eq!(output[2].instruction, "nop");
    }

    #[test]
    fn renders_286_instructions_with_16_bit_defaults() {
        // A stale 386 segment setting must not affect 286 decoding.
        for segment in ["16", "32"] {
            let output = disassemble(
                "B8 34 12 0F 05 F1 0F 04 90",
                "intel80286",
                "disabled",
                segment,
                "100",
                false,
            )
            .unwrap();
            let rows: Vec<_> = output
                .iter()
                .map(|row| (row.offset.as_str(), row.bytes.as_str(), row.instruction.as_str()))
                .collect();
            assert_eq!(
                rows,
                [
                    ("00000100", "B8 34 12", "mov ax,1234h"),
                    ("00000103", "0F 05", "loadall"),
                    ("00000105", "F1 0F 04", "storeall"),
                    ("00000108", "90", "nop"),
                ]
            );
            assert!(output.iter().all(|row| !row.is_error));
        }
    }

    #[test]
    fn segment_size_controls_386_defaults() {
        let bytes = "B8 34 12 00 00";
        let output_16 = disassemble(bytes, "intel80386", "disabled", "16", "0", false).unwrap();
        let output_32 = disassemble(bytes, "intel80386", "disabled", "32", "0", false).unwrap();

        assert_eq!(output_16[0].bytes, "B8 34 12");
        assert_eq!(output_16[0].instruction, "mov ax,1234h");
        assert_eq!(output_32[0].bytes, "B8 34 12 00 00");
        assert_eq!(output_32[0].instruction, "mov eax,1234h");
    }

    #[test]
    fn formats_selected_disassembly_fields_for_copying() {
        let rows = disassemble("90 B8 34 12", "intel808x", "disabled", "16", "0", false).unwrap();
        assert_eq!(format_disassembly_text(&rows, false, false), "nop\nmov ax,1234h");
        assert_eq!(
            format_disassembly_text(&rows, true, true),
            "00000000  90        nop\n00000001  B8 34 12  mov ax,1234h"
        );
    }

    #[test]
    fn formatted_disassembly_never_uses_tabs() {
        let rows = disassemble("90 B8 34 12", "intel808x", "disabled", "16", "0", false).unwrap();
        assert!(!format_disassembly_text(&rows, true, true).contains('\t'));
        assert!(!format_disassembly_text(&rows, false, true).contains('\t'));
        assert!(!format_disassembly_text(&rows, false, false).contains('\t'));
    }
}
