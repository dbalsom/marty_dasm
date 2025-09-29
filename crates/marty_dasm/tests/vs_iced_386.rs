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
use marty_fuzzer::fuzzer::{FuzzerOptions, InstructionFuzzer};
use std::io::Cursor;

mod common;

use crate::common::{
    format::{format_iced_instruction, format_marty_instruction},
    init_tests,
    mnemonic_filter::is_valid_mnemonic,
};
use marty_dasm::prelude::*;
use rand::{Rng, SeedableRng};

pub const TEST_SEED: u64 = 0x12345678;
pub const FUZZ_TEST_COUNT: usize = 10_000_000;

// There are an absolute ton of valid modern x86 instructions lurking in the undefined/invalid
// space of the 386. Here we try to filter them all out.

#[test]
fn fuzz_against_iced86() -> Result<(), Box<dyn std::error::Error>> {
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

    for run_no in 0..FUZZ_TEST_COUNT {
        // Get a random instruction for 386
        let instruction = fuzzer.random_instruction(&mut rng, &options)?;

        let iced_decoder_opts = iced_x86::DecoderOptions::NO_INVALID_CHECK | iced_x86::DecoderOptions::LOADALL386;
        let iced_decode_buffer = instruction.bytes.clone();
        let marty_decode_buffer = Cursor::new(instruction.bytes.clone());

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
        let marty_str = format_marty_instruction(&marty_i);

        let iced_display = format!("'{}'", iced_str);
        let marty_display = format!("'{}'", marty_str);

        if iced_str == "(bad)" && (marty_str.contains("(bad)") == true) {
            // Both decoders agree it's a bad instruction, all good.
        }
        else if iced_str != marty_str {
            eprintln!(
                "Discrepancy found on run {:06}: segment_size: {:<10?} iced: {:<40} marty: {:<40} op_ct: {} c: {} d: {} as: {:?} opcodes: {:X?}",
                run_no,
                segment_size,
                iced_display,
                marty_display,
                marty_i.operand_ct(),
                marty_i.is_complete,
                marty_i.disambiguate,
                marty_i.address_size,
                &instruction.bytes
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
