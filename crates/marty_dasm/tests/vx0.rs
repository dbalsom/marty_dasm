use std::{
    io::Cursor,
    panic::{catch_unwind, AssertUnwindSafe},
};

use marty_dasm::{decoder::Decoder, CpuType, DecoderOptions, Instruction};

fn decode_v20(bytes: &[u8]) -> Instruction {
    let mut decoder = Decoder::new(
        Cursor::new(bytes),
        DecoderOptions {
            cpu: CpuType::NecVx0,
            ..Default::default()
        },
    );
    decoder.decode_next().expect("V20 instruction should decode")
}

fn assert_decode_does_not_panic(bytes: &[u8], description: &str) {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut decoder = Decoder::new(
            Cursor::new(bytes),
            DecoderOptions {
                cpu: CpuType::NecVx0,
                ..Default::default()
            },
        );
        let _ = decoder.decode_next();
    }));
    assert!(result.is_ok(), "V20 decoder panicked for {description}");
}

#[test]
fn v20_register_encoded_operands_come_from_the_opcode() {
    let mov_ch = decode_v20(&[0xB5, 0x12]);
    assert!(!mov_ch.has_modrm);
    assert_eq!(format!("{:?}", mov_ch.operand1_type), "Register8(CH)");

    let mov_di = decode_v20(&[0xBF, 0x34, 0x12]);
    assert!(!mov_di.has_modrm);
    assert_eq!(format!("{:?}", mov_di.operand1_type), "Register16(DI)");
}

#[test]
fn v20_imul_69_has_a_modrm_byte() {
    let imul = decode_v20(&[0x69, 0xC0, 0x34, 0x12]);
    assert!(imul.has_modrm);
    assert_eq!(format!("{:?}", imul.operand1_type), "Register16(AX)");
    assert_eq!(format!("{:?}", imul.operand2_type), "Register16(AX)");
}

#[test]
fn every_v20_opcode_and_following_byte_decodes_without_panicking() {
    for opcode in 0u8..=u8::MAX {
        for following in 0u8..=u8::MAX {
            let regular = [opcode, following, 0, 0, 0, 0, 0, 0];
            assert_decode_does_not_panic(&regular, &format!("opcode {opcode:02X}, following {following:02X}"));

            let extended = [0x0F, opcode, following, 0, 0, 0, 0, 0];
            assert_decode_does_not_panic(
                &extended,
                &format!("extended opcode 0F {opcode:02X}, following {following:02X}"),
            );
        }
    }
}
