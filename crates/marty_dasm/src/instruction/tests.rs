use crate::{
    CpuType,
    DecodeError,
    Decoder,
    DecoderOptions,
    FormatOptions,
    Instruction,
    Opcode,
    OperandSize,
    SegmentSize,
    cpu_common::{PrefixFlags, Register16},
    decode_one,
    format_instruction,
};

const CPUS: [CpuType; 4] = [
    CpuType::Intel808x,
    CpuType::NecVx0,
    CpuType::Intel80286,
    CpuType::Intel80386,
];

fn decode(cpu: CpuType, bytes: &[u8]) -> Instruction {
    decode_in_segment(cpu, SegmentSize::Segment16, bytes)
}

fn decode_in_segment(cpu: CpuType, segment_size: SegmentSize, bytes: &[u8]) -> Instruction {
    let mut stream = bytes.to_vec();
    stream.push(0x90);
    let mut decoder = Decoder::new(
        stream.as_slice(),
        DecoderOptions {
            cpu,
            segment_size,
            ..Default::default()
        },
    );
    let instruction = decoder.decode_next().unwrap();
    assert!(
        instruction.is_valid && instruction.is_complete,
        "{cpu:?} {bytes:02X?}: {instruction:?}"
    );
    assert_eq!(instruction.instruction_bytes, bytes, "{cpu:?}");
    assert_eq!(decoder.position(), bytes.len() as u64);
    assert_eq!(decoder.decode_next().unwrap().mnemonic.to_str(), "NOP");
    assert!(matches!(decoder.decode_next(), Err(DecodeError::Eof)));
    instruction
}

#[test]
fn prefix_classes_replace_earlier_choices_in_every_core() {
    for cpu in CPUS {
        let instruction = decode(cpu, &[0x26, 0x2E, 0xC7, 0x47, 0xFE, 0x34, 0x12]);
        assert_eq!(
            instruction.raw_prefix_flags,
            PrefixFlags::ES_OVERRIDE | PrefixFlags::CS_OVERRIDE
        );
        assert_eq!(instruction.effective_prefix_flags, PrefixFlags::CS_OVERRIDE);
        assert_eq!(instruction.segment_override, Some(Register16::CS));
        assert_eq!(instruction.prefix_bytes, [0x26, 0x2E]);
        assert_eq!(instruction.prefix_ct, 2);
        assert_eq!(instruction.opcode_offset, 2);
        assert_eq!(instruction.opcode, Opcode::with_extension(0xC7, 0));
        assert!(instruction.has_modrm && instruction.has_displacement && instruction.has_immediate);
        assert_eq!(instruction.modrm_offset, 3);
        assert!(!instruction.has_sib);
        assert_eq!(instruction.displacement_bytes, [0xFE]);
        assert_eq!(instruction.displacement_size, OperandSize::Operand8);
        assert_eq!(instruction.immediate_bytes, [0x34, 0x12]);
        assert_eq!(instruction.immediate_size, OperandSize::Operand16);

        for (prefixes, effective, text) in [
            ([0xF2, 0xF3], PrefixFlags::REP2, "repe cmpsb"),
            ([0xF3, 0xF2], PrefixFlags::REP1, "repne cmpsb"),
        ] {
            let instruction = decode(cpu, &[prefixes[0], prefixes[1], 0xA6]);
            assert_eq!(instruction.raw_prefix_flags, PrefixFlags::REP1 | PrefixFlags::REP2);
            assert_eq!(instruction.effective_prefix_flags, effective);
            assert_eq!(
                format_instruction(&instruction, &FormatOptions::default()),
                text,
                "{cpu:?}"
            );
        }
    }
}

#[test]
fn prefixes_apply_to_integer_instructions_in_every_core() {
    let cases: &[(&[u8], &str)] = &[
        (&[0x26, 0x8B, 0x07], "mov ax,[es:bx]"),
        (&[0x26, 0xA1, 0x34, 0x12], "mov ax,[es:1234h]"),
        (&[0x26, 0xF3, 0xA4], "es rep movsb"),
        (&[0xF0, 0x01, 0x00], "lock add [ds:bx+si],ax"),
    ];
    for cpu in CPUS {
        for &(bytes, text) in cases {
            let instruction = decode(cpu, bytes);
            assert_eq!(
                format_instruction(&instruction, &FormatOptions::default()),
                text,
                "{cpu:?} {bytes:02X?}"
            );
        }
    }
}

#[test]
fn integer_memory_sizes_and_implicit_counts_are_consistent() {
    let cases: &[(&[u8], &str)] = &[
        (&[0xC7, 0x07, 0x34, 0x12], "mov word [ds:bx],1234h"),
        (&[0x80, 0x07, 0x02], "add byte [ds:bx],2"),
        (&[0xFE, 0x07], "inc byte [ds:bx]"),
        (&[0xF7, 0x17], "not word [ds:bx]"),
        (&[0x8F, 0x07], "pop word [ds:bx]"),
        (&[0xD3, 0x27], "shl word [ds:bx],cl"),
        (&[0xD1, 0x27], "shl word [ds:bx],1"),
        (&[0xD0, 0xC0], "rol al,1"),
        (&[0xD1, 0xE0], "shl ax,1"),
        // A register operand already determines the width of these memory forms.
        (&[0x01, 0x07], "add [ds:bx],ax"),
        (&[0xD8, 0x07], "esc [ds:bx]"),
    ];
    for cpu in CPUS {
        for &(bytes, text) in cases {
            let instruction = decode(cpu, bytes);
            assert_eq!(
                format_instruction(&instruction, &FormatOptions::default()),
                text,
                "{cpu:?} {bytes:02X?}"
            );
        }
        for opcode in [0xD0, 0xD1] {
            for extension in [0, 1, 2, 3, 4, 5, 7] {
                let instruction = decode(cpu, &[opcode, 0xC0 | (extension << 3)]);
                assert_eq!(instruction.operand2_type, crate::OperandType::Immediate8(1));
                assert!(!instruction.has_immediate);
                assert_eq!(instruction.immediate_size, OperandSize::NoOperand);
            }
        }
    }
}

#[test]
fn nec_carry_repeat_prefixes_share_the_repeat_class() {
    for (bytes, flag, text) in [
        (&[0xF3, 0x64, 0xA6][..], PrefixFlags::REP3, "repnc cmpsb"),
        (&[0x64, 0x65, 0xA6][..], PrefixFlags::REP4, "repc cmpsb"),
        (&[0x65, 0xF3, 0xA6][..], PrefixFlags::REP2, "repe cmpsb"),
    ] {
        let instruction = decode(CpuType::NecVx0, bytes);
        assert_eq!(instruction.effective_prefix_flags & PrefixFlags::REP_MASK, flag);
        assert_eq!(format_instruction(&instruction, &FormatOptions::default()), text);
    }
}

#[test]
fn opcode_escapes_are_not_counted_as_prefix_bytes() {
    for cpu in [CpuType::NecVx0, CpuType::Intel80286, CpuType::Intel80386] {
        let bytes = if cpu == CpuType::NecVx0 {
            [0x26, 0x0F, 0x10, 0x07]
        }
        else {
            [0x26, 0x0F, 0x00, 0x07]
        };
        let instruction = decode(cpu, &bytes);
        assert_eq!(instruction.prefix_bytes, [0x26]);
        assert_eq!(instruction.prefix_ct, 1);
        assert_eq!(instruction.opcode_offset, 1);
        assert_eq!(instruction.modrm_offset, 3);
        assert_eq!(instruction.opcode.to_bytes(), bytes[1..3]);
        assert_ne!(instruction.effective_prefix_flags & PrefixFlags::EXTENDED_0F, 0);
        assert_eq!(
            instruction.opcode.extension(),
            if cpu == CpuType::NecVx0 { None } else { Some(0) }
        );
    }
    let instruction = decode(CpuType::Intel808x, &[0x0F]);
    assert_eq!(instruction.opcode, Opcode::new(0x0F));
    assert!(instruction.prefix_bytes.is_empty());
    assert_eq!(instruction.effective_prefix_flags & PrefixFlags::EXTENDED_0F, 0);
}

#[test]
fn immediate_metadata_describes_encoded_fields_in_every_core() {
    let cases: &[(&[u8], &[u8], OperandSize)] = &[
        (&[0xB0, 0x12], &[0x12], OperandSize::Operand8),
        (&[0xB8, 0x34, 0x12], &[0x34, 0x12], OperandSize::Operand16),
        (&[0x83, 0xC0, 0xFE], &[0xFE], OperandSize::Operand8),
        (&[0xEB, 0xFE], &[0xFE], OperandSize::Operand8),
        (&[0xA0, 0x34, 0x12], &[0x34, 0x12], OperandSize::Operand16),
        (
            &[0xEA, 0x78, 0x56, 0x34, 0x12],
            &[0x78, 0x56, 0x34, 0x12],
            OperandSize::Operand16,
        ),
        (&[0x90], &[], OperandSize::NoOperand),
        (&[0xD1, 0xE0], &[], OperandSize::NoOperand),
    ];
    for cpu in CPUS {
        for &(bytes, immediate, size) in cases {
            let instruction = decode(cpu, bytes);
            assert_eq!(instruction.has_immediate, !immediate.is_empty(), "{cpu:?} {bytes:02X?}");
            assert_eq!(instruction.immediate_bytes, immediate, "{cpu:?} {bytes:02X?}");
            assert_eq!(instruction.immediate_size, size, "{cpu:?} {bytes:02X?}");
        }
    }
}

#[test]
fn i386_operand_and_address_sizes_describe_separate_fields() {
    let cases: &[(&[u8], OperandSize)] = &[
        (&[0x66, 0xB8, 0x78, 0x56, 0x34, 0x12], OperandSize::Operand32),
        (&[0x67, 0xA1, 0x78, 0x56, 0x34, 0x12], OperandSize::Operand32),
        (&[0x66, 0xA1, 0x34, 0x12], OperandSize::Operand16),
        (
            &[0x66, 0xEA, 0x78, 0x56, 0x34, 0x12, 0xBC, 0x9A],
            OperandSize::Operand32,
        ),
        (&[0x66, 0xC8, 0x34, 0x12, 0x02], OperandSize::Operand16),
    ];
    for &(bytes, size) in cases {
        let instruction = decode(CpuType::Intel80386, bytes);
        assert!(instruction.has_immediate);
        assert_eq!(instruction.immediate_size, size, "{bytes:02X?}");
        assert_eq!(instruction.immediate_bytes, bytes[2..]);
    }

    for (segment, prefix) in [(SegmentSize::Segment16, &[0x67][..]), (SegmentSize::Segment32, &[][..])] {
        let mut bytes = prefix.to_vec();
        bytes.extend_from_slice(&[0xC6, 0x84, 0x88, 0x78, 0x56, 0x34, 0x12, 0x7F]);
        let instruction = decode_in_segment(CpuType::Intel80386, segment, &bytes);
        assert_eq!(instruction.opcode, Opcode::with_extension(0xC6, 0));
        assert_eq!(instruction.modrm_offset, prefix.len() + 1);
        assert!(instruction.has_sib && instruction.has_displacement);
        assert_eq!(instruction.sib_offset, prefix.len() + 2);
        assert_eq!(instruction.displacement_size, OperandSize::Operand32);
        assert_eq!(instruction.displacement_bytes, [0x78, 0x56, 0x34, 0x12]);
        assert_eq!(instruction.immediate_size, OperandSize::Operand8);
        assert_eq!(instruction.immediate_bytes, [0x7F]);
    }
}

#[test]
fn invalid_table_entries_are_marked_invalid() {
    for cpu in [CpuType::NecVx0, CpuType::Intel80286, CpuType::Intel80386] {
        let instruction = decode_one(
            &[0x0F, 0x08, 0, 0, 0, 0, 0, 0][..],
            DecoderOptions {
                cpu,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(instruction.mnemonic, crate::Mnemonic::Invalid, "{cpu:?}");
        assert!(!instruction.is_valid, "{cpu:?}");
        assert!(instruction.is_complete, "{cpu:?}");
    }
}

#[test]
fn memory_detection_includes_moffs_and_excludes_immediate_far_pointers() {
    for cpu in CPUS {
        for bytes in [&[0xA1, 0x34, 0x12][..], &[0x8B, 0x07][..], &[0xFF, 0x1F][..]] {
            assert!(decode(cpu, bytes).has_memory_operand(), "{cpu:?} {bytes:02X?}");
        }
        for bytes in [
            &[0xEA, 0x78, 0x56, 0x34, 0x12][..],
            &[0x8B, 0xC3][..],
            &[0xB8, 0x34, 0x12][..],
        ] {
            let instruction = decode(cpu, bytes);
            assert!(!instruction.has_memory_operand(), "{cpu:?} {bytes:02X?}");
            assert!(!instruction.operand1_type.is_memory());
            assert!(!instruction.operand2_type.is_memory());
        }
    }
    let instruction = decode_in_segment(
        CpuType::Intel80386,
        SegmentSize::Segment32,
        &[0xA1, 0x78, 0x56, 0x34, 0x12],
    );
    assert!(instruction.has_memory_operand());
    let instruction = decode_in_segment(
        CpuType::Intel80386,
        SegmentSize::Segment32,
        &[0xEA, 0x78, 0x56, 0x34, 0x12, 0xBC, 0x9A],
    );
    assert!(!instruction.has_memory_operand());
}
