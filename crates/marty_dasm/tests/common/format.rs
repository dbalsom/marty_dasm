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

use iced_x86::Formatter;
use marty_dasm::prelude::*;

pub fn format_iced_instruction(iced_i: &iced_x86::Instruction) -> String {
    let mut instr_text = String::new();
    let mut formatter = iced_x86::NasmFormatter::new();

    formatter.options_mut().set_always_show_segment_register(true);
    formatter.options_mut().set_add_leading_zero_to_hex_numbers(false);
    formatter.options_mut().set_always_show_scale(true);
    formatter.options_mut().set_use_pseudo_ops(false);
    //formatter.options_mut().set_show_zero_displacements(true);

    formatter.format(&iced_i, &mut instr_text);

    // Remove spurious 'notrack' extension decoding.
    instr_text = instr_text.replace("notrack ", "");

    instr_text
}

pub fn format_marty_instruction(marty_i: &Instruction) -> String {

    let mut output = String::new();
    let mut options = FormatOptions::default();
    options.iced_mnemonics = true;

    NasmFormatter.format_instruction(&marty_i, &options, &mut output);

    output
}