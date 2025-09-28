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

use std::io::Cursor;

use colored::{Color, Colorize};
use rand::{Rng, SeedableRng};
use marty_dasm::prelude::*;
use marty_fuzzer::fuzzer::{FuzzerOptions, InstructionFuzzer};
use crate::common::format::format_marty_instruction;
use crate::common::init_tests;

pub const COLOR_TEST_COUNT: usize = 100;
pub const TEST_SEED: u64 = 0x12345678;

#[test]
fn colored_nop_tokenstream_integration() -> Result<(), Box<dyn std::error::Error>> {
    init_tests();
    let mut rng = rand::rngs::StdRng::seed_from_u64(TEST_SEED);

    // Create the instruction fuzzer.
    let mut fuzzer = InstructionFuzzer::new(CpuType::Intel80386);
    let options = FuzzerOptions {
        segment_size: rng.random_bool(0.5).then_some(SegmentSize::Segment32).unwrap_or(SegmentSize::Segment16),
        seed: 0xDEADBEEF,
        opcode_range: Some(0x00u16..=0x0FFFu16),
        extension_range: Some(0..=7),
        allow_fpu: false,
        allow_protected: false,
        allow_undefined: false,
    };



    for _ in 0..COLOR_TEST_COUNT {

        let instruction = fuzzer.random_instruction(&mut rng, &options)?;
        let marty_decode_buffer = Cursor::new(instruction.bytes.clone());

        // Coin toss between 16 and 32 bit mode
        let wide = rng.random_bool(0.5);
        let (_bitness, segment_size) = if wide { (32, SegmentSize::Segment32) } else { (16, SegmentSize::Segment16 ) };

        let marty_decoder_opts = DecoderOptions {
            cpu: CpuType::Intel80386,
            segment_size,
            ..Default::default()
        };

        let mut marty_decoder = Decoder::new(marty_decode_buffer, marty_decoder_opts);
        //let marty_str = format_marty_instruction(&marty_i);

        let inst = match marty_decoder.decode_next() {
            Ok(inst) => inst,
            Err(e) => {
                println!("Decoding error: {:?}", e);
                continue; // Skip to the next iteration on error
            }
        };

        let mut stream = TokenStream::new();
        NasmFormatter.format_instruction(&inst, &FormatOptions::default(), &mut stream);

        // Map tokens to colors and build a colored string for display
        let mut colored_out = String::new();
        for tok in stream.iter() {
            match tok {
                TokenItem::Decorator(DecoratorToken::OpenBracket) => colored_out.push_str("[".color(Color::BrightBlue).to_string().as_str()),
                TokenItem::Decorator(DecoratorToken::CloseBracket) => colored_out.push_str("]".color(Color::BrightBlue).to_string().as_str()),
                TokenItem::Decorator(DecoratorToken::Comma) => colored_out.push_str(",".color(Color::White).to_string().as_str()),
                TokenItem::Decorator(DecoratorToken::Plus) => colored_out.push_str("+".color(Color::White).to_string().as_str()),
                TokenItem::Decorator(DecoratorToken::Minus) => colored_out.push_str("-".color(Color::White).to_string().as_str()),
                TokenItem::Decorator(DecoratorToken::Multiply) => colored_out.push_str("*".color(Color::White).to_string().as_str()),
                TokenItem::Decorator(DecoratorToken::Colon) => colored_out.push_str(":".color(Color::White).to_string().as_str()),
                TokenItem::Decorator(DecoratorToken::Whitespace(ws)) => colored_out.push_str(ws),
                TokenItem::Decorator(DecoratorToken::Text(t)) => colored_out.push_str(t),
                TokenItem::Decorator(DecoratorToken::Number(n)) => colored_out.push_str(n),
                TokenItem::Semantic(SemanticToken::Mnemonic(m)) => colored_out.push_str(m.color(Color::Cyan).to_string().as_str()),
                TokenItem::Semantic(SemanticToken::Register(r)) => colored_out.push_str(r.color(Color::Green).to_string().as_str()),
                TokenItem::Semantic(SemanticToken::Displacement(d)) => colored_out.push_str(d.color(Color::Cyan).to_string().as_str()),
                TokenItem::Semantic(other) => colored_out.push_str(other.to_string().as_str()),
            }
        }
        // Optionally print to help visualize locally
        println!("{}", colored_out);
    }


    Ok(())
    // Assert flat render matches expected plain text
    //assert_eq!(stream.to_string_flat(), "nop");
}

