use std::io::Cursor;

use marty_dasm::{CpuType, Decoder, DecoderOptions, SegmentSize};

fn assert_followed_by_nop(cpu: CpuType, segment_size: SegmentSize, encoded: &[u8], description: &str) {
    let mut stream = encoded.to_vec();
    stream.push(0x90);

    let mut decoder = Decoder::new(Cursor::new(stream), DecoderOptions { cpu, segment_size });
    let instruction = decoder.decode_next().expect(description);
    assert_eq!(instruction.instruction_bytes, encoded, "wrong length for {description}");

    let following = decoder.decode_next().expect("decode instruction following operand");
    assert_eq!(
        following.instruction_bytes,
        [0x90],
        "{description} did not consume its complete encoding"
    );
}

#[test]
fn intel808x_operand_reads_advance_the_stream() {
    let cases: &[(&[u8], &str)] = &[
        (&[0xB0, 0x12], "8-bit immediate"),
        (&[0xB8, 0x34, 0x12], "16-bit immediate"),
        (&[0x83, 0xC0, 0xFE], "sign-extended 8-bit immediate"),
        (&[0xEB, 0x00], "8-bit relative operand"),
        (&[0xE9, 0x00, 0x00], "16-bit relative operand"),
        (&[0xA0, 0x34, 0x12], "absolute offset"),
        (&[0xEA, 0x78, 0x56, 0x34, 0x12], "16:16 far pointer"),
    ];

    for (encoded, description) in cases {
        assert_followed_by_nop(CpuType::Intel808x, SegmentSize::Segment16, encoded, description);
    }
}

#[test]
fn nec_vx0_operand_reads_advance_the_stream() {
    let cases: &[(&[u8], &str)] = &[
        (&[0xB0, 0x12], "8-bit immediate"),
        (&[0xB8, 0x34, 0x12], "16-bit immediate"),
        (&[0x83, 0xC0, 0xFE], "sign-extended 8-bit immediate"),
        (&[0xEB, 0x00], "8-bit relative operand"),
        (&[0xE9, 0x00, 0x00], "16-bit relative operand"),
        (&[0xA0, 0x34, 0x12], "absolute offset"),
        (&[0xEA, 0x78, 0x56, 0x34, 0x12], "16:16 far pointer"),
        (&[0x69, 0xC0, 0x34, 0x12], "V20 three-operand immediate"),
    ];

    for (encoded, description) in cases {
        assert_followed_by_nop(CpuType::NecVx0, SegmentSize::Segment16, encoded, description);
    }
}

#[test]
fn intel80386_operand_reads_continue_to_advance_the_stream() {
    let cases_16: &[(&[u8], &str)] = &[
        (&[0xB8, 0x34, 0x12], "16-bit immediate"),
        (&[0xE9, 0x00, 0x00], "16-bit relative operand"),
        (&[0xA0, 0x34, 0x12], "16-bit absolute offset"),
        (&[0xEA, 0x78, 0x56, 0x34, 0x12], "16:16 far pointer"),
    ];
    let cases_32: &[(&[u8], &str)] = &[
        (&[0xB8, 0x78, 0x56, 0x34, 0x12], "32-bit immediate"),
        (&[0xE9, 0x00, 0x00, 0x00, 0x00], "32-bit relative operand"),
        (&[0xA0, 0x78, 0x56, 0x34, 0x12], "32-bit absolute offset"),
        (&[0xEA, 0x78, 0x56, 0x34, 0x12, 0xBC, 0x9A], "16:32 far pointer"),
    ];

    for (encoded, description) in cases_16 {
        assert_followed_by_nop(CpuType::Intel80386, SegmentSize::Segment16, encoded, description);
    }
    for (encoded, description) in cases_32 {
        assert_followed_by_nop(CpuType::Intel80386, SegmentSize::Segment32, encoded, description);
    }
}
