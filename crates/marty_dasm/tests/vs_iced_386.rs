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

mod common;

use marty_fuzzer::fuzzer::{FuzzerOptions, InstructionFuzzer};
use std::io::Cursor;

use crate::common::{
    format::{format_iced_instruction, format_marty_instruction},
    init_tests,
    mnemonic_filter::is_valid_mnemonic,
};
use marty_dasm::prelude::*;
use rand::{Rng, SeedableRng};

pub const TEST_SEED: u64 = 0x12345678;
pub const FUZZ_TEST_COUNT: usize = 100_000;
pub const MAX_PREFIXES: usize = 2;
pub const PREFIXES_386: [u8; 11] = [
    0xF0, // LOCK
    0xF2, // REPNE/REPNZ
    0xF3, // REP/REPE/REPZ
    0x2E, // CS segment override
    0x36, // SS segment override
    0x3E, // DS segment override
    0x26, // ES segment override
    0x64, // FS segment override
    0x65, // GS segment override
    0x66, // Operand-size override
    0x67, // Address-size override
];

// There are an absolute ton of valid modern x86 instructions lurking in the undefined/invalid
// space of the 386. Here we try to filter them all out.

#[test]
fn fuzz_iced86_without_prefixes() -> Result<(), Box<dyn std::error::Error>> {
    fuzz_against_iced86(false, FUZZ_TEST_COUNT)
}

#[test]
fn fuzz_iced86_with_prefixes() -> Result<(), Box<dyn std::error::Error>> {
    fuzz_against_iced86(true, FUZZ_TEST_COUNT)
}

#[test]
fn compare_smsw_sldt() -> Result<(), Box<dyn std::error::Error>> {
    const HEX: &str = "660F01E00F01E0660F00C00F00C0660F01200F0120660F00000F0000";

    let bytes = HEX
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex pair"), 16).expect("valid hex pair"))
        .collect::<Vec<_>>();

    let mut iced_output = Vec::new();
    let mut marty_output = Vec::new();

    for (bitness, segment_size) in [(16, SegmentSize::Segment16), (32, SegmentSize::Segment32)] {
        iced_output.push(format!("{bitness}-bit segment"));
        marty_output.push(format!("{bitness}-bit segment"));

        let iced_options = iced_x86::DecoderOptions::NO_INVALID_CHECK | iced_x86::DecoderOptions::LOADALL386;
        let mut iced_decoder = iced_x86::Decoder::new(bitness, &bytes, iced_options);
        while iced_decoder.can_decode() {
            let instruction = iced_decoder.decode();
            let mut text = format_iced_instruction(&instruction);
            if !is_valid_mnemonic(instruction.mnemonic()) {
                text = "(bad)".to_owned();
            }
            iced_output.push(format!("{:04X}: {text}", instruction.ip()));
        }

        let mut offset = 0usize;
        while offset < bytes.len() {
            let mut decoder = Decoder::new(
                Cursor::new(&bytes[offset..]),
                DecoderOptions {
                    cpu: CpuType::Intel80386,
                    segment_size,
                    ..Default::default()
                },
            );
            let instruction = decoder.decode_next()?;
            let instruction_length = instruction.instruction_bytes.len();
            if instruction_length == 0 {
                return Err(format!("marty_dasm made no progress at offset {offset:04X}").into());
            }
            marty_output.push(format!(
                "{offset:04X}: {}",
                format_marty_instruction(&instruction, offset as u32)
            ));
            offset += instruction_length;
        }
    }

    assert_eq!(iced_output, marty_output);
    Ok(())
}

#[test]
fn compare_pushes() -> Result<(), Box<dyn std::error::Error>> {
    const HEX: &str = "6066606166619C669C9D669D";

    let bytes = HEX
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex pair"), 16).expect("valid hex pair"))
        .collect::<Vec<_>>();

    let mut iced_output = Vec::new();
    let mut marty_output = Vec::new();

    for (bitness, segment_size) in [(16, SegmentSize::Segment16), (32, SegmentSize::Segment32)] {
        iced_output.push(format!("{bitness}-bit segment"));
        marty_output.push(format!("{bitness}-bit segment"));

        let iced_options = iced_x86::DecoderOptions::NO_INVALID_CHECK | iced_x86::DecoderOptions::LOADALL386;
        let mut iced_decoder = iced_x86::Decoder::new(bitness, &bytes, iced_options);
        while iced_decoder.can_decode() {
            let instruction = iced_decoder.decode();
            let mut text = format_iced_instruction(&instruction);
            if !is_valid_mnemonic(instruction.mnemonic()) {
                text = "(bad)".to_owned();
            }
            iced_output.push(format!("{:04X}: {text}", instruction.ip()));
        }

        let mut offset = 0usize;
        while offset < bytes.len() {
            let mut decoder = Decoder::new(
                Cursor::new(&bytes[offset..]),
                DecoderOptions {
                    cpu: CpuType::Intel80386,
                    segment_size,
                    ..Default::default()
                },
            );
            let instruction = decoder.decode_next()?;
            let instruction_length = instruction.instruction_bytes.len();
            if instruction_length == 0 {
                return Err(format!("marty_dasm made no progress at offset {offset:04X}").into());
            }
            marty_output.push(format!(
                "{offset:04X}: {}",
                format_marty_instruction(&instruction, offset as u32)
            ));
            offset += instruction_length;
        }
    }

    println!("iced: {iced_output:#?}");
    println!("marty_dasm: {marty_output:#?}");
    assert_eq!(iced_output, marty_output);
    Ok(())
}

#[test]
fn test_lar_lsl() -> Result<(), Box<dyn std::error::Error>> {
    const HEX: &str = "0F02C1660F02C10F0207660F0207670F020066670F02000F03C1660F03C10F0307660F0307670F030066670F0300";

    let bytes = HEX
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex pair"), 16).expect("valid hex pair"))
        .collect::<Vec<_>>();

    let mut iced_output = Vec::new();
    let mut marty_output = Vec::new();

    for (bitness, segment_size) in [(16, SegmentSize::Segment16), (32, SegmentSize::Segment32)] {
        iced_output.push(format!("{bitness}-bit segment"));
        marty_output.push(format!("{bitness}-bit segment"));

        let iced_options = iced_x86::DecoderOptions::NO_INVALID_CHECK | iced_x86::DecoderOptions::LOADALL386;
        let mut iced_decoder = iced_x86::Decoder::new(bitness, &bytes, iced_options);
        while iced_decoder.can_decode() {
            let instruction = iced_decoder.decode();
            let mut text = format_iced_instruction(&instruction);
            if !is_valid_mnemonic(instruction.mnemonic()) {
                text = "(bad)".to_owned();
            }
            iced_output.push(format!("{:04X}: {text}", instruction.ip()));
        }

        let mut offset = 0usize;
        while offset < bytes.len() {
            let mut decoder = Decoder::new(
                Cursor::new(&bytes[offset..]),
                DecoderOptions {
                    cpu: CpuType::Intel80386,
                    segment_size,
                    ..Default::default()
                },
            );
            let instruction = decoder.decode_next()?;
            let instruction_length = instruction.instruction_bytes.len();
            if instruction_length == 0 {
                return Err(format!("marty_dasm made no progress at offset {offset:04X}").into());
            }
            marty_output.push(format!(
                "{offset:04X}: {}",
                format_marty_instruction(&instruction, offset as u32)
            ));
            offset += instruction_length;
        }
    }

    println!("iced: {iced_output:#?}");
    println!("marty_dasm: {marty_output:#?}");
    assert_eq!(iced_output, marty_output);
    Ok(())
}

fn fuzz_against_iced86(do_prefixes: bool, test_ct: usize) -> Result<(), Box<dyn std::error::Error>> {
    init_tests();
    let mut rng = rand::rngs::StdRng::seed_from_u64(TEST_SEED);
    let mut error_ct = 0;

    // Create the instruction fuzzer.
    let fuzzer = InstructionFuzzer::new(CpuType::Intel80386);
    let options = FuzzerOptions {
        segment_size: rng
            .random_bool(0.5)
            .then_some(SegmentSize::Segment32)
            .unwrap_or(SegmentSize::Segment16),
        seed: 0xDEADBEEF,
        opcode_range: Some(0x00u16..=0x0FFFu16),
        extension_range: Some(0..=7),
        allow_fpu: false,
        allow_protected: false,
        allow_undefined: false,
    };

    for run_no in 0..test_ct {
        // Get a random instruction for 386
        let instruction = fuzzer.random_instruction(&mut rng, &options)?;

        let iced_decoder_opts = iced_x86::DecoderOptions::NO_INVALID_CHECK | iced_x86::DecoderOptions::LOADALL386;

        let mut inst_bytes = instruction.bytes.clone();

        if do_prefixes {
            let num_prefixes = rng.random_range(0..=MAX_PREFIXES);
            for _ in 0..num_prefixes {
                let prefix = PREFIXES_386[rng.random_range(0..PREFIXES_386.len())];
                inst_bytes.insert(0, prefix);
            }
        }

        let iced_decode_buffer = inst_bytes.clone();
        let marty_decode_buffer = Cursor::new(inst_bytes.clone());

        // Coin toss between 16 and 32 bit mode
        let wide = rng.random_bool(0.5);
        let (bitness, segment_size) = if wide {
            (32, SegmentSize::Segment32)
        }
        else {
            (16, SegmentSize::Segment16)
        };

        // Decode instruction with iced.
        let mut decoder = iced_x86::Decoder::new(bitness, &iced_decode_buffer, iced_decoder_opts);
        // Set a random IP so that IP-relative displacements are decoded correctly.
        let random_ip: u64 = rng.random_range(0..0xFFFF);
        decoder.set_ip(random_ip);

        let iced_i = decoder.decode();

        // Get iced string.
        let mut iced_str = format_iced_instruction(&iced_i);
        // Replace certain funky mnemonics with "bad"
        if !is_valid_mnemonic(iced_i.mnemonic()) {
            iced_str = "(bad)".to_string();
        }

        // Decode instruction with Marty.
        let marty_decoder_opts = DecoderOptions {
            cpu: CpuType::Intel80386,
            segment_size,
            ..Default::default()
        };

        //println!("got iced disassembly: {:<40} bytes: {:X?}", iced_str, instruction_bytes);

        let mut marty_decoder = Decoder::new(marty_decode_buffer, marty_decoder_opts);
        let marty_i = marty_decoder.decode_next()?;
        let marty_str = format_marty_instruction(&marty_i, random_ip as u32);

        let iced_display = format!("'{}'", iced_str);
        let marty_display = format!("'{}'", marty_str);
        let marty_mnemonic = marty_i.mnemonic.to_string();
        let has_rep_prefix = marty_i
            .instruction_bytes
            .iter()
            .take_while(|&&byte| byte != 0x0F)
            .any(|&byte| matches!(byte, 0xF2 | 0xF3));
        let ignored_rep_bsf_bsr =
            iced_str == "(bad)" && matches!(marty_mnemonic.as_str(), "BSF" | "BSR") && has_rep_prefix;
        let ignored_pause_as_rep_nop = iced_i.mnemonic() == iced_x86::Mnemonic::Pause && marty_mnemonic == "NOP";

        if iced_str == "(bad)" && (marty_str.contains("(bad)") == true) {
            // Both decoders agree it's a bad instruction, all good.
        }
        else if ignored_rep_bsf_bsr {
            // The 80386 ignores REP prefixes on BSF and BSR. Iced interprets these byte sequences
            // using later instruction-set extensions, which this comparison intentionally rejects.
        }
        else if ignored_pause_as_rep_nop {
            // Iced decodes F3 90 as the later PAUSE instruction. On the 80386, it is REP NOP.
        }
        else if iced_str != marty_str {
            eprintln!(
                "Discrepancy found on run {:06}: {:<10?} {:<10?} {:<10?} iced: {:<40} marty: {:<40} op_ct: {} c: {:<5} d: {:<5} opcode: [{}] bytes: {:X?}",
                run_no,
                segment_size,
                marty_i.operand_size,
                marty_i.address_size,
                iced_display,
                marty_display,
                marty_i.operand_ct(),
                marty_i.is_complete,
                marty_i.disambiguate,
                marty_i.opcode,
                &inst_bytes
            );
            error_ct += 1;
        }
    }

    if error_ct == 0 {
        Ok(())
    }
    else {
        Err(format!("{}/{} discrepancies found", error_ct, FUZZ_TEST_COUNT).into())
    }
}
