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
            },
        );
        let instruction = decoder.decode_next().expect("decode UMOV");

        assert_eq!(instruction.instruction_bytes, bytes);
        assert_eq!(instruction.mnemonic.to_string(), "UMOV");
        assert_eq!(format_instruction(&instruction, &FormatOptions::default()), expected);
    }
}
