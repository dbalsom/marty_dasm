use std::io::{self, Read};

use iced_x86::Formatter;
use marty_dasm::{
    AddressSize,
    CpuType,
    DecodeError,
    Decoder,
    DecoderOptions,
    FormatOptions,
    Instruction,
    Opcode,
    SegmentSize,
    decode_one,
    format_instruction,
};

fn options() -> DecoderOptions {
    DecoderOptions {
        cpu: CpuType::Intel80286,
        segment_size: SegmentSize::Segment16,
        ..Default::default()
    }
}

fn decode(bytes: &[u8]) -> Instruction {
    decode_one(bytes, options()).expect("decode 80286 instruction")
}

fn assert_instruction(bytes: &[u8], expected: &str) -> Instruction {
    let mut stream = bytes.to_vec();
    stream.push(0x90);
    let mut decoder = Decoder::new(stream.as_slice(), options());
    let instruction = decoder.decode_next().unwrap();
    assert!(
        instruction.is_valid && instruction.is_complete,
        "{bytes:02X?}: {instruction:?}"
    );
    assert_eq!(instruction.instruction_bytes, bytes);
    assert_eq!(format_instruction(&instruction, &FormatOptions::default()), expected);
    assert_eq!(decoder.position(), bytes.len() as u64);
    assert_eq!(decoder.decode_next().unwrap().mnemonic.to_str(), "NOP");
    assert!(matches!(decoder.decode_next(), Err(DecodeError::Eof)));
    instruction
}

#[test]
fn loadall_storeall_and_clts_have_no_modrm_or_operands() {
    for (bytes, name, opcode) in [
        (&[0x0F, 0x04][..], "storeall", 0x0F04),
        (&[0xF1, 0x0F, 0x04][..], "storeall", 0x0F04),
        (&[0x0F, 0x05][..], "loadall", 0x0F05),
        (&[0x0F, 0x06][..], "clts", 0x0F06),
    ] {
        let instruction = assert_instruction(bytes, name);
        assert_eq!(instruction.opcode, Opcode::new(opcode));
        assert!(!instruction.has_modrm);
        assert!(!instruction.has_operands());
        assert!(!instruction.has_immediate);
    }
}

#[test]
fn system_instructions_and_groups() {
    let cases: &[(&[u8], &str)] = &[
        (&[0x63, 0xC8], "arpl ax,cx"),
        (&[0x0F, 0x00, 0xC0], "sldt ax"),
        (&[0x0F, 0x00, 0xC8], "str ax"),
        (&[0x0F, 0x00, 0xD0], "lldt ax"),
        (&[0x0F, 0x00, 0xD8], "ltr ax"),
        (&[0x0F, 0x00, 0xE0], "verr ax"),
        (&[0x0F, 0x00, 0xE8], "verw ax"),
        (&[0x0F, 0x01, 0x00], "sgdt [ds:bx+si]"),
        (&[0x0F, 0x01, 0x08], "sidt [ds:bx+si]"),
        (&[0x0F, 0x01, 0x10], "lgdt [ds:bx+si]"),
        (&[0x0F, 0x01, 0x18], "lidt [ds:bx+si]"),
        (&[0x0F, 0x01, 0xE0], "smsw ax"),
        (&[0x0F, 0x01, 0xF0], "lmsw ax"),
        (&[0x0F, 0x02, 0xC1], "lar ax,cx"),
        (&[0x0F, 0x03, 0xC1], "lsl ax,cx"),
    ];
    for &(bytes, text) in cases {
        assert_instruction(bytes, text);
    }
}

#[test]
fn inherited_186_instructions() {
    let cases: &[(&[u8], &str)] = &[
        (&[0x60], "pusha"),
        (&[0x61], "popa"),
        (&[0x62, 0x00], "bound ax,[ds:bx+si]"),
        (&[0x68, 0x34, 0x12], "push 1234h"),
        (&[0x6A, 0xFE], "push FFFEh"),
        (&[0x69, 0xC1, 0x34, 0x12], "imul ax,cx,1234h"),
        (&[0x6B, 0xC1, 0xFE], "imul ax,cx,FFFEh"),
        (&[0x6C], "insb"),
        (&[0x6D], "insw"),
        (&[0x6E], "outsb"),
        (&[0x6F], "outsw"),
        (&[0xC0, 0xE0, 0x03], "shl al,3"),
        (&[0xC1, 0xE0, 0x03], "shl ax,3"),
        (&[0xC8, 0x34, 0x12, 0x02], "enter 1234h,2"),
        (&[0xC9], "leave"),
    ];
    for &(bytes, text) in cases {
        assert_instruction(bytes, text);
    }
}

#[test]
fn prefixes_and_operand_metadata() {
    let instruction = assert_instruction(&[0x26, 0x36, 0xC7, 0x46, 0xFE, 0x34, 0x12], "mov word [ss:bp-2],1234h");
    assert_eq!(instruction.prefix_bytes, [0x26, 0x36]);
    assert_eq!(instruction.prefix_ct, 2);
    assert_eq!(instruction.opcode_offset, 2);
    assert_eq!(instruction.modrm_offset, 3);
    assert_eq!(instruction.opcode, Opcode::with_extension(0xC7, 0));
    assert_eq!(instruction.displacement_bytes, [0xFE]);
    assert_eq!(instruction.immediate_bytes, [0x34, 0x12]);
    assert!(instruction.has_displacement && instruction.has_immediate);
    assert_ne!(instruction.raw_prefix_flags, instruction.effective_prefix_flags);

    assert_instruction(&[0xF2, 0xF3, 0xA4], "rep movsb");
    assert_instruction(&[0xF3, 0xF2, 0xA6], "repne cmpsb");
    assert_instruction(&[0xF0, 0x01, 0x00], "lock add [ds:bx+si],ax");
    let ice = assert_instruction(&[0xF1, 0x90], "nop");
    assert_eq!(ice.prefix_bytes, [0xF1]);
    assert_eq!(ice.raw_prefix_flags, 0);
}

#[test]
fn invalid_opcodes_do_not_consume_the_following_instruction() {
    for bytes in (0x64..=0x67)
        .map(|op| vec![op])
        .chain((0x07..=0xFF).map(|op| vec![0x0F, op]))
    {
        let mut stream = bytes.clone();
        stream.push(0x90);
        let mut decoder = Decoder::new(stream.as_slice(), options());
        let instruction = decoder.decode_next().unwrap();
        assert!(!instruction.is_valid, "{bytes:02X?}");
        assert!(instruction.is_complete);
        assert_eq!(instruction.mnemonic.to_str(), "INVALID");
        assert_eq!(instruction.instruction_bytes, bytes);
        assert_eq!(decoder.decode_next().unwrap().mnemonic.to_str(), "NOP");
    }
}

#[test]
fn invalid_modrm_forms() {
    let cases: &[&[u8]] = &[
        &[0x62, 0xC0],
        &[0x8D, 0xC0],
        &[0xC4, 0xC0],
        &[0xC5, 0xC0],
        &[0x8E, 0xC8],
        &[0x8C, 0xE0],
        &[0x8E, 0xE0],
        &[0x8F, 0xC8],
        &[0xC6, 0xC8, 0x12],
        &[0xC7, 0xC8, 0x34, 0x12],
        &[0xFE, 0xD0],
        &[0xFF, 0xD8],
        &[0xFF, 0xE8],
        &[0xFF, 0xF8],
        &[0x0F, 0x00, 0xF0],
        &[0x0F, 0x00, 0xF8],
        &[0x0F, 0x01, 0xC0],
        &[0x0F, 0x01, 0xC8],
        &[0x0F, 0x01, 0xD0],
        &[0x0F, 0x01, 0xD8],
        &[0x0F, 0x01, 0xE8],
        &[0x0F, 0x01, 0xF8],
    ];
    for &bytes in cases {
        let instruction = decode(bytes);
        assert!(!instruction.is_valid, "{bytes:02X?}: {instruction:?}");
        assert!(instruction.is_complete);
        assert_eq!(instruction.instruction_bytes, bytes);
    }
    assert_instruction(&[0x8C, 0xC8], "mov ax,cs");
    assert_instruction(&[0xD6], "salc");
    assert_instruction(&[0xF6, 0xC8, 0x12], "test al,12h");
    assert_instruction(&[0xF7, 0xC8, 0x34, 0x12], "test ax,1234h");
    assert_instruction(&[0x82, 0xC0, 0x12], "add al,12h");
}

#[test]
fn instruction_length_limit_is_ten_bytes() {
    for (prefix_count, body) in [(9, &[0x90][..]), (8, &[0x0F, 0x05][..]), (7, &[0xB8, 0x34, 0x12][..])] {
        let mut bytes = vec![0x26; prefix_count];
        bytes.extend_from_slice(body);
        assert!(decode(&bytes).is_valid, "{bytes:02X?}");
    }
    let mut bytes = vec![0x26; 8];
    bytes.extend_from_slice(&[0xB8, 0x34, 0x12]);
    let instruction = decode(&bytes);
    assert!(!instruction.is_valid);
    assert!(instruction.is_complete);

    let bytes = [vec![0x26; 10], vec![0x90]].concat();
    let mut decoder = Decoder::new(bytes.as_slice(), options());
    let instruction = decoder.decode_next().unwrap();
    assert!(!instruction.is_valid && !instruction.is_complete);
    assert_eq!(instruction.instruction_bytes.len(), 10);
    assert_eq!(decoder.decode_next().unwrap().mnemonic.to_str(), "NOP");
}

#[test]
fn remains_16_bit_with_32_bit_segment_option() {
    let instruction = decode_one(
        &[0xB8, 0x34, 0x12][..],
        DecoderOptions {
            segment_size: SegmentSize::Segment32,
            ..options()
        },
    )
    .unwrap();
    assert_eq!(instruction.segment_size, SegmentSize::Segment16);
    assert_eq!(instruction.address_size, AddressSize::Address16);
    assert_eq!(
        format_instruction(&instruction, &FormatOptions::default()),
        "mov ax,1234h"
    );
}

struct OneByteReader<'a>(&'a [u8]);

impl Read for OneByteReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = buffer.len().min(1);
        self.0.read(&mut buffer[..count])
    }
}

#[test]
fn operands_support_streaming_and_truncation() {
    let cases: &[&[u8]] = &[
        &[0xF1, 0x0F, 0x04],
        &[0x0F, 0x05],
        &[0x0F, 0x01, 0x96, 0x34, 0x12],
        &[0x69, 0x86, 0x34, 0x12, 0x78, 0x56],
        &[0xC8, 0x34, 0x12, 0x02],
        &[0xEA, 0x78, 0x56, 0x34, 0x12],
        &[0x9A, 0x78, 0x56, 0x34, 0x12],
        &[0xA1, 0x34, 0x12],
        &[0xE8, 0x34, 0x12],
    ];
    for &bytes in cases {
        let instruction = decode_one(OneByteReader(bytes), options()).unwrap();
        assert!(instruction.is_valid);
        assert_eq!(instruction.instruction_bytes, bytes);
        for length in 1..bytes.len() {
            let error = decode_one(OneByteReader(&bytes[..length]), options()).unwrap_err();
            assert!(
                matches!(error, DecodeError::UnexpectedEof),
                "{bytes:02X?}, length {length}: {error}"
            );
        }
    }
    assert!(matches!(decode_one(&[][..], options()), Err(DecodeError::Eof)));
}

#[test]
fn coprocessor_escapes_keep_their_16_bit_addressing() {
    for opcode in 0xD8..=0xDF {
        for bytes in [vec![opcode, 0xC0], vec![opcode, 0x86, 0x34, 0x12]] {
            let instruction = decode_one(&bytes[..], DecoderOptions { fpu: None, ..options() }).unwrap();
            assert!(instruction.is_valid && instruction.is_complete);
            assert_eq!(instruction.mnemonic.to_str(), "ESC");
            assert_eq!(instruction.instruction_bytes, bytes);
            assert!(instruction.has_modrm);
        }
    }
}

#[test]
fn documented_encodings_match_iced() {
    // Exercise every ModR/M value, including all displacement and group forms.
    // ICE, invalid 286 opcodes and coprocessor escapes have dedicated tests above.
    let mut formatter = iced_x86::NasmFormatter::new();
    formatter.options_mut().set_always_show_segment_register(true);
    formatter.options_mut().set_add_leading_zero_to_hex_numbers(false);
    formatter.options_mut().set_use_pseudo_ops(false);
    let format_options = FormatOptions {
        iced_mnemonics: true,
        ..FormatOptions::default()
    };
    let mut compared = 0;
    for extended in [false, true] {
        for opcode in 0..=255u8 {
            if (!extended
                && matches!(opcode, 0x0F | 0x26 | 0x2E | 0x36 | 0x3E | 0x64..=0x67 | 0xD8..=0xDF | 0xF0..=0xF3))
                || (extended && !matches!(opcode, 0x00..=0x03 | 0x06))
            {
                continue;
            }
            for modrm in 0..=255u8 {
                let mut bytes = Vec::new();
                if extended {
                    bytes.push(0x0F);
                }
                bytes.extend_from_slice(&[opcode, modrm, 0x34, 0x12, 0x78, 0x56, 0x90]);
                let instruction = decode(&bytes);
                if !instruction.is_valid {
                    continue;
                }
                let reference = iced_x86::Decoder::new(16, &bytes, iced_x86::DecoderOptions::NO_INVALID_CHECK).decode();
                assert!(!reference.is_invalid(), "{bytes:02X?}");
                assert_eq!(instruction.instruction_bytes.len(), reference.len(), "{bytes:02X?}");
                let mut expected = String::new();
                formatter.format(&reference, &mut expected);
                assert_eq!(
                    format_instruction(&instruction, &format_options),
                    expected,
                    "{bytes:02X?}"
                );
                compared += 1;
            }
        }
    }
    assert!(compared > 50_000);
}
