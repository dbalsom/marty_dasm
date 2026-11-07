use marty_dasm::{CpuType, DecoderOptions, FormatOptions, SegmentSize, decoder::Decoder, format_instruction};

#[test]
fn decode_umov_386() {
    let cases = [
        ([0x0F, 0x10, 0xC1], "umov cl,al"),
        ([0x0F, 0x11, 0xC1], "umov cx,ax"),
        ([0x0F, 0x12, 0xC1], "umov al,cl"),
        ([0x0F, 0x13, 0xC1], "umov ax,cx"),
    ];

    for (bytes, expected) in cases {
        let mut decoder = Decoder::new(
            bytes.as_slice(),
            DecoderOptions {
                cpu: CpuType::Intel80386,
                segment_size: SegmentSize::Segment16,
                ..Default::default()
            },
        );
        let instruction = decoder.decode_next().expect("decode UMOV");

        assert_eq!(instruction.instruction_bytes, bytes);
        assert_eq!(instruction.mnemonic.to_string(), "UMOV");
        assert_eq!(format_instruction(&instruction, &FormatOptions::default()), expected);
    }
}

#[test]
fn decode_test_register_moves_386() {
    let cases = [
        ([0x0F, 0x24, 0xE0], "mov eax,tr4"),
        ([0x0F, 0x26, 0xE0], "mov tr4,eax"),
        ([0x0F, 0x24, 0xE9], "mov ecx,tr5"),
        ([0x0F, 0x26, 0xE9], "mov tr5,ecx"),
        ([0x0F, 0x24, 0xF0], "mov eax,tr6"),
        ([0x0F, 0x26, 0xF0], "mov tr6,eax"),
        ([0x0F, 0x24, 0xF9], "mov ecx,tr7"),
        ([0x0F, 0x26, 0xF9], "mov tr7,ecx"),
    ];

    for (bytes, expected) in cases {
        let mut decoder = Decoder::new(
            bytes.as_slice(),
            DecoderOptions {
                cpu: CpuType::Intel80386,
                segment_size: SegmentSize::Segment16,
                ..Default::default()
            },
        );
        let instruction = decoder.decode_next().expect("decode test-register MOV");

        assert_eq!(instruction.instruction_bytes, bytes);
        assert_eq!(instruction.mnemonic.to_string(), "MOV");
        assert_eq!(format_instruction(&instruction, &FormatOptions::default()), expected);
    }
}

#[test]
fn decode_undefined_instructions_386_without_modrm() {
    let cases = [
        ([0x0F, 0x0B, 0x90], "UD2", "ud2"),
        ([0x0F, 0xB9, 0x90], "UD1", "ud1"),
        ([0x0F, 0xFF, 0x90], "UD0", "ud0"),
    ];

    for (bytes, mnemonic, expected) in cases {
        let mut decoder = Decoder::new(
            bytes.as_slice(),
            DecoderOptions {
                cpu: CpuType::Intel80386,
                segment_size: SegmentSize::Segment16,
                ..Default::default()
            },
        );
        let instruction = decoder.decode_next().expect("decode undefined instruction");

        assert_eq!(instruction.instruction_bytes, bytes[..2]);
        assert_eq!(instruction.mnemonic.to_string(), mnemonic);
        assert_eq!(format_instruction(&instruction, &FormatOptions::default()), expected);

        let following_instruction = decoder
            .decode_next()
            .expect("decode byte following undefined instruction");
        assert_eq!(following_instruction.mnemonic.to_string(), "NOP");
    }
}
