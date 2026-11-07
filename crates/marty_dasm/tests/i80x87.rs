// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Daniel Balsom

use iced_x86::Formatter;
use marty_dasm::{i80X87, *};
use std::io::{self, Read};

const FPUS: [FpuType; 4] = [
    FpuType::Intel8087,
    FpuType::Intel80287,
    FpuType::Intel80287XL,
    FpuType::Intel80387,
];
const CPUS: [CpuType; 4] = [
    CpuType::Intel808x,
    CpuType::NecVx0,
    CpuType::Intel80286,
    CpuType::Intel80386,
];

fn options(cpu: CpuType, fpu: FpuType, segment_size: SegmentSize) -> DecoderOptions {
    DecoderOptions {
        cpu,
        fpu: Some(fpu),
        segment_size,
    }
}

fn decode(bytes: &[u8], fpu: FpuType) -> Instruction {
    let cpu = if fpu == FpuType::Intel8087 {
        CpuType::Intel808x
    }
    else {
        CpuType::Intel80386
    };

    decode_one(bytes, options(cpu, fpu, SegmentSize::Segment16)).unwrap()
}

fn text(instruction: &Instruction) -> String {
    format_instruction(instruction, &FormatOptions::default())
}

#[test]
fn cpu_fpu_compatibility() {
    for (cpu, expected) in [
        (CpuType::Intel808x, &FPUS[..1]),
        (CpuType::NecVx0, &FPUS[..1]),
        (CpuType::Intel8018x, &FPUS[..1]),
        (CpuType::Intel80286, &FPUS[1..3]),
        (CpuType::Intel80386, &FPUS[1..]),
    ] {
        assert_eq!(cpu.compatible_fpus(), expected);

        for fpu in FPUS {
            assert_eq!(cpu.is_fpu_compatible(fpu), expected.contains(&fpu));
            let opts = options(cpu, fpu, SegmentSize::Segment16);
            assert_eq!(opts.validate().is_ok(), expected.contains(&fpu));

            if cpu == CpuType::Intel8018x {
                continue;
            } // CPU decoding is not implemented yet.

            let mut decoder = Decoder::new(OneByteReader(&[0xD8, 0xC0]), opts);

            if !expected.contains(&fpu) {
                assert!(matches!(decoder.decode_next(), Err(DecodeError::InvalidOptions(_))));
                assert_eq!(decoder.position(), 0);
                decoder.set_options(DecoderOptions {
                    cpu,
                    fpu: Some(expected[0]),
                    ..Default::default()
                });
            }

            assert_eq!(text(&decoder.decode_next().unwrap()), "fadd st0,st0");
            assert_eq!(decoder.position(), 2);
        }

        assert!(
            DecoderOptions {
                cpu,
                fpu: None,
                ..Default::default()
            }
            .validate()
            .is_ok()
        );
    }

    // An incompatible change must not consume the next instruction either.
    let mut decoder = Decoder::new(
        OneByteReader(&[0x90, 0xD9, 0xFE]),
        options(CpuType::Intel80386, FpuType::Intel80387, SegmentSize::Segment16),
    );
    assert_eq!(text(&decoder.decode_next().unwrap()), "nop");
    decoder.set_options(options(CpuType::Intel80386, FpuType::Intel8087, SegmentSize::Segment16));
    assert!(matches!(decoder.decode_next(), Err(DecodeError::InvalidOptions(_))));
    assert_eq!(decoder.position(), 1);
    decoder.set_options(options(
        CpuType::Intel80386,
        FpuType::Intel80287,
        SegmentSize::Segment16,
    ));
    assert_eq!(text(&decoder.decode_next().unwrap()), "esc si");
    assert_eq!(decoder.position(), 3);
}

#[test]
fn esc_cpu_validity() {
    // PLA01_DECODE.txt and decoder23.txt accept all ESC forms. The apparent
    // DB /6 memory hole is a transcription error: x86_microcode issue #5.
    for cpu in [CpuType::Intel80286, CpuType::Intel80386] {
        for segment_size in [SegmentSize::Segment16, SegmentSize::Segment32] {
            for prefix in [&[][..], &[0x26][..], &[0x66][..], &[0x67][..], &[0x26, 0x66, 0x67][..]] {
                if cpu == CpuType::Intel80286 && (prefix.contains(&0x66) || prefix.contains(&0x67)) {
                    continue;
                }

                let address32 =
                    cpu == CpuType::Intel80386 && ((segment_size == SegmentSize::Segment32) ^ prefix.contains(&0x67));

                for opcode in 0xD8..=0xDF {
                    for modrm in 0..=255u8 {
                        let mode = modrm >> 6;
                        let rm = modrm & 7;
                        let sib = address32 && mode != 3 && rm == 4;
                        let displacement = match mode {
                            0 if address32 && (rm == 5 || sib) => 4, // SIB below has base=5.
                            0 if !address32 && rm == 6 => 2,
                            1 => 1,
                            2 if address32 => 4,
                            2 => 2,
                            _ => 0,
                        };
                        let length = prefix.len() + 2 + usize::from(sib) + displacement;
                        let mut bytes = prefix.to_vec();
                        bytes.extend_from_slice(&[opcode, modrm, 0x8D, 0x78, 0x56, 0x34, 0x12]);
                        bytes.truncate(length);
                        let generic = decode_one(
                            OneByteReader(&bytes),
                            DecoderOptions {
                                cpu,
                                segment_size,
                                fpu: None,
                            },
                        )
                        .unwrap();
                        assert!(generic.is_valid && generic.is_complete, "{cpu:?} {bytes:02X?}");
                        assert_eq!(generic.mnemonic, Mnemonic::ESC);
                        assert_eq!(generic.instruction_bytes, bytes);
                        assert!(generic.has_modrm && generic.fpu.is_none());
                        assert_eq!(generic.has_sib, sib);

                        for fpu in std::iter::once(None).chain(cpu.compatible_fpus().iter().copied().map(Some)) {
                            let inst =
                                decode_one(OneByteReader(&bytes), DecoderOptions { cpu, segment_size, fpu }).unwrap();
                            assert!(inst.is_valid && inst.is_complete, "{cpu:?} {fpu:?} {bytes:02X?}");
                            assert_eq!(inst.instruction_bytes, bytes);

                            if inst.fpu.is_none() {
                                assert_eq!(inst.mnemonic, Mnemonic::ESC);
                                assert_eq!(inst.operand1_type, generic.operand1_type);
                                assert_eq!(inst.operand2_type, generic.operand2_type);
                                assert_eq!(inst.operand3_type, generic.operand3_type);
                                assert_eq!(inst.displacement_bytes, generic.displacement_bytes);
                                assert_eq!(inst.raw_prefix_flags, generic.raw_prefix_flags);
                                assert_eq!(inst.effective_prefix_flags, generic.effective_prefix_flags);
                                assert_eq!(inst.address_size, generic.address_size);
                                assert_eq!(inst.operand_size, generic.operand_size);
                                assert_eq!(text(&inst), text(&generic));
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn arithmetic_and_pops() {
    for (bytes, expected) in [
        ([0xD8, 0xC3], "fadd st0,st3"),
        ([0xDC, 0xC3], "fadd st3,st0"),
        ([0xDE, 0xC3], "faddp st3,st0"),
        ([0xD8, 0xE3], "fsub st0,st3"),
        ([0xD8, 0xEB], "fsubr st0,st3"),
        ([0xDC, 0xE3], "fsubr st3,st0"),
        ([0xDC, 0xEB], "fsub st3,st0"),
        ([0xDE, 0xE3], "fsubrp st3,st0"),
        ([0xDE, 0xEB], "fsubp st3,st0"),
        ([0xD8, 0xF3], "fdiv st0,st3"),
        ([0xD8, 0xFB], "fdivr st0,st3"),
        ([0xDC, 0xF3], "fdivr st3,st0"),
        ([0xDC, 0xFB], "fdiv st3,st0"),
        ([0xDE, 0xF3], "fdivrp st3,st0"),
        ([0xDE, 0xFB], "fdivp st3,st0"),
        ([0xDE, 0xD9], "fcompp"),
        ([0xD9, 0xCF], "fxch st7"),
    ] {
        for fpu in FPUS {
            let instruction = decode(&bytes, fpu);
            assert!(instruction.is_valid, "{bytes:02X?} {fpu:?}");
            assert_eq!(text(&instruction), expected);
        }
    }
}

#[test]
fn memory_formats() {
    use FpuMemoryFormat::*;

    for (opcode, extension, format, expected) in [
        (0xD9, 0, Float32, "fld dword [ds:bx+si]"),
        (0xDD, 0, Float64, "fld qword [ds:bx+si]"),
        (0xDB, 5, Float80, "fld tword [ds:bx+si]"),
        (0xDF, 0, Int16, "fild word [ds:bx+si]"),
        (0xDB, 0, Int32, "fild dword [ds:bx+si]"),
        (0xDF, 5, Int64, "fild qword [ds:bx+si]"),
        (0xDF, 4, Bcd80, "fbld tword [ds:bx+si]"),
        (0xDF, 6, Bcd80, "fbstp tword [ds:bx+si]"),
        (0xD9, 5, ControlWord, "fldcw word [ds:bx+si]"),
        (0xDD, 7, StatusWord, "fnstsw word [ds:bx+si]"),
        (0xD9, 4, Env14, "fldenv [ds:bx+si]"),
        (0xDD, 4, State94, "frstor [ds:bx+si]"),
    ] {
        for cpu in CPUS {
            for &fpu in cpu.compatible_fpus() {
                let inst =
                    decode_one(&[opcode, extension << 3][..], options(cpu, fpu, SegmentSize::Segment16)).unwrap();
                assert!(inst.is_valid && inst.has_memory_operand());
                assert!(inst.operand1_type.is_address());
                assert_eq!(inst.operand1_type.fpu_memory_format(), Some(format));
                assert_eq!(text(&inst), expected, "{cpu:?} {fpu:?}");
            }
        }
    }
}

#[test]
fn fpu_generations() {
    assert!(i80X87::decode(0xD7, 0xE0, FpuType::Intel80387, OperandSize::Operand16).is_none());
    assert!(i80X87::decode(0xE0, 0x00, FpuType::Intel80387, OperandSize::Operand16).is_none());
    let semantic = i80X87::decode(0xDF, 0xE0, FpuType::Intel80287, OperandSize::Operand32).unwrap();
    assert_eq!(semantic.mnemonic, Mnemonic::FNSTSW);
    assert_eq!(semantic.operands, FpuOperands::Ax);

    for (bytes, supported) in [
        ([0xDF, 0xE0], [false, true, true, true]),  // FNSTSW AX, 287/287XL/387
        ([0xDB, 0xE4], [false, true, true, true]),  // FSETPM, 287/287XL/387
        ([0xD9, 0xF5], [false, false, true, true]), // FPREM1, 287XL/387
        ([0xD9, 0xFB], [false, false, true, true]), // FSINCOS
        ([0xD9, 0xFE], [false, false, true, true]), // FSIN
        ([0xD9, 0xFF], [false, false, true, true]), // FCOS
        ([0xDD, 0xE7], [false, false, true, true]), // FUCOM ST7
        ([0xDD, 0xEF], [false, false, true, true]), // FUCOMP ST7
        ([0xDA, 0xE9], [false, false, true, true]), // FUCOMPP
    ] {
        for cpu in CPUS {
            for (fpu, recognized) in FPUS.into_iter().zip(supported) {
                if !cpu.is_fpu_compatible(fpu) {
                    continue;
                }

                let inst = decode_one(&bytes[..], options(cpu, fpu, SegmentSize::Segment16)).unwrap();
                assert!(inst.is_valid, "{cpu:?} {fpu:?} {bytes:02X?}");
                assert_eq!(inst.fpu.is_some(), recognized, "{cpu:?} {fpu:?} {bytes:02X?}");

                if !recognized {
                    assert_eq!(inst.mnemonic, Mnemonic::ESC);
                }

                assert_eq!(inst.instruction_bytes, bytes);
                assert!(inst.is_complete);
            }
        }
    }

    let mut decoder = Decoder::new(
        &[0xD9, 0xFE, 0xD9, 0xFE][..],
        options(CpuType::Intel80386, FpuType::Intel80287, SegmentSize::Segment16),
    );
    let escape = decoder.decode_next().unwrap();
    assert!(escape.is_valid && escape.fpu.is_none());
    assert_eq!(escape.mnemonic, Mnemonic::ESC);
    decoder.set_options(options(
        CpuType::Intel80386,
        FpuType::Intel80387,
        SegmentSize::Segment16,
    ));
    assert_eq!(text(&decoder.decode_next().unwrap()), "fsin");
}

#[test]
fn legacy_encodings() {
    for (opcode, base, mnemonic) in [
        (0xD9, 0xD8, "FSTPNCE"),
        (0xDC, 0xD0, "FCOM"),
        (0xDC, 0xD8, "FCOMP"),
        (0xDD, 0xC8, "FXCH"),
        (0xDE, 0xD0, "FCOMP"),
        (0xDF, 0xC0, "FFREEP"),
        (0xDF, 0xC8, "FXCH"),
        (0xDF, 0xD0, "FSTP"),
        (0xDF, 0xD8, "FSTP"),
    ] {
        for i in 0..8 {
            let i8087 = decode(&[opcode, base + i], FpuType::Intel8087);
            assert!(i8087.is_valid);
            assert_eq!(i8087.fpu.is_some(), mnemonic == "FFREEP");

            if i8087.fpu.is_some() {
                assert!(i8087.fpu.unwrap().undocumented);
                assert_eq!(i8087.mnemonic, Mnemonic::FFREEP);
                assert_eq!(i8087.operand1_type, OperandType::FpuRegister(i));
            }
            else {
                assert_eq!(i8087.mnemonic, Mnemonic::ESC);
            }

            for fpu in [FpuType::Intel80287, FpuType::Intel80287XL, FpuType::Intel80387] {
                let inst = decode(&[opcode, base + i], fpu);
                assert!(inst.is_valid && inst.fpu.unwrap().undocumented);
                assert_eq!(inst.mnemonic.to_str(), mnemonic);
                assert_eq!(inst.operand1_type, OperandType::FpuRegister(i));
            }
        }
    }

    for fpu in FPUS {
        for modrm in [0xE0, 0xE1] {
            let inst = decode(&[0xDB, modrm], fpu);
            assert!(inst.is_valid);
            assert_eq!(inst.fpu.unwrap().compatibility_nop, fpu != FpuType::Intel8087);
        }
    }

    for fpu in [FpuType::Intel80287, FpuType::Intel80287XL, FpuType::Intel80387] {
        assert_eq!(
            decode(&[0xDB, 0xE4], fpu).fpu.unwrap().compatibility_nop,
            fpu == FpuType::Intel80387
        );
    }
}

#[test]
fn i287xl_instructions() {
    // Intel 290376-003 documents DB F4; OPCODE.LST reports DB E5 instead.
    // Keep both XL-only, with the alternative marked undocumented.
    for (modrm, undocumented) in [(0xF4, false), (0xE5, true)] {
        for fpu in FPUS {
            let inst = decode(&[0xDB, modrm], fpu);
            assert!(inst.is_valid);
            assert_eq!(inst.fpu.is_some(), fpu == FpuType::Intel80287XL);
            assert!(inst.is_complete);
            assert_eq!(inst.instruction_bytes, [0xDB, modrm]);

            if inst.fpu.is_some() {
                assert_eq!(text(&inst), "frstpm");
                let semantic = inst.fpu.unwrap();
                assert_eq!(semantic.operands, FpuOperands::None);
                assert_eq!(semantic.undocumented, undocumented);
                assert!(!semantic.compatibility_nop);
            }
            else {
                assert_eq!(inst.mnemonic, Mnemonic::ESC);
            }
        }
    }

    let bytes = [
        0xD9, 0xF5, 0xD9, 0xFB, 0xD9, 0xFE, 0xD9, 0xFF, 0xDD, 0xE7, 0xDD, 0xEF, 0xDA, 0xE9, 0xDB, 0xE4, 0xDB, 0xF4,
        0xDB, 0xE5, 0x90,
    ];
    let mut decoder = Decoder::new(
        OneByteReader(&bytes),
        options(CpuType::Intel80286, FpuType::Intel80287XL, SegmentSize::Segment16),
    );

    for (index, expected) in [
        "fprem1",
        "fsincos",
        "fsin",
        "fcos",
        "fucom st7",
        "fucomp st7",
        "fucompp",
        "fsetpm",
        "frstpm",
        "frstpm",
    ]
    .into_iter()
    .enumerate()
    {
        let inst = decoder.decode_next().unwrap();
        assert!(inst.is_valid);
        assert_eq!(text(&inst), expected);
        assert_eq!(decoder.position(), (index as u64 + 1) * 2);
    }

    assert_eq!(text(&decoder.decode_next().unwrap()), "nop");
    assert!(matches!(decoder.decode_next(), Err(DecodeError::Eof)));
}

#[test]
fn unknown_esc_fallback() {
    for bytes in [
        [0xD9, 0xD1],
        [0xD9, 0xE2],
        [0xD9, 0xEF],
        [0xDE, 0xD8],
        [0xDE, 0xDA],
        [0xDB, 0xE6],
        [0xDB, 0xF3],
        [0xDB, 0xF5], // Do not extend FRSTPM to adjacent encodings.
        [0xDB, 0xF0],
        [0xDF, 0xF0], // FCOMI/FCOMIP
        [0xDA, 0xC0],
        [0xDB, 0xC0], // FCMOV
        [0xDB, 0x08],
        [0xDD, 0x08],
        [0xDF, 0x08], // FISTTP
    ] {
        for cpu in CPUS {
            let generic = decode_one(
                &bytes[..],
                DecoderOptions {
                    cpu,
                    fpu: None,
                    ..Default::default()
                },
            )
            .unwrap();

            for &fpu in cpu.compatible_fpus() {
                assert!(i80X87::decode(bytes[0], bytes[1], fpu, OperandSize::Operand16).is_none());
                let inst = decode_one(&bytes[..], options(cpu, fpu, SegmentSize::Segment16)).unwrap();
                assert!(inst.is_valid && inst.fpu.is_none(), "{cpu:?} {bytes:02X?} {fpu:?}");
                assert_eq!(inst.mnemonic, Mnemonic::ESC);
                assert_eq!(text(&inst), text(&generic));
                assert_eq!(inst.operand1_type, generic.operand1_type);
                assert_eq!(inst.instruction_bytes, bytes);
            }
        }
    }
}

#[test]
fn environment_sizes() {
    use FpuMemoryFormat::*;

    for segment in [SegmentSize::Segment16, SegmentSize::Segment32] {
        for &fpu in CpuType::Intel80386.compatible_fpus() {
            for operand_prefix in [false, true] {
                for address_prefix in [false, true] {
                    for (opcode, modrm, small, large) in [
                        (0xD9, 0x20, Env14, Env28),
                        (0xD9, 0x30, Env14, Env28),
                        (0xDD, 0x20, State94, State108),
                        (0xDD, 0x30, State94, State108),
                        (0xD9, 0x00, Float32, Float32),
                        (0xDD, 0x00, Float64, Float64),
                        (0xDB, 0x28, Float80, Float80),
                    ] {
                        let mut bytes = Vec::new();

                        if operand_prefix {
                            bytes.push(0x66);
                        }

                        if address_prefix {
                            bytes.push(0x67);
                        }

                        bytes.extend_from_slice(&[opcode, modrm]);
                        let inst = decode_one(&bytes[..], options(CpuType::Intel80386, fpu, segment)).unwrap();
                        let wide = (segment == SegmentSize::Segment32) ^ operand_prefix;
                        let has_wide_environment = matches!(fpu, FpuType::Intel80287XL | FpuType::Intel80387);
                        let expected = if has_wide_environment && wide { large } else { small };
                        assert!(inst.is_valid);
                        assert_eq!(inst.operand1_type.fpu_memory_format(), Some(expected));
                        assert_eq!(
                            inst.has_operand_size_override(),
                            operand_prefix && has_wide_environment && small.is_environment_or_state()
                        );
                        assert_eq!(
                            inst.address_size == AddressSize::Address32,
                            (segment == SegmentSize::Segment32) ^ address_prefix
                        );
                        assert_eq!(inst.instruction_bytes, bytes);
                    }
                }
            }
        }
    }

    assert_eq!(
        text(&decode(&[0x66, 0xD9, 0x20], FpuType::Intel80387)),
        "o32 fldenv [ds:bx+si]"
    );
    assert_eq!(
        text(&decode(&[0x66, 0xD9, 0x00], FpuType::Intel80387)),
        "fld dword [ds:bx+si]"
    );
    assert_eq!(Env28.byte_len(), 28);
    assert_eq!(State108.byte_len(), 108);
}

#[test]
fn i287xl_environment_sizes() {
    for (bytes, format, expected) in [
        ([0xD9, 0x20], FpuMemoryFormat::Env14, "fldenv [ds:bx+si]"),
        ([0xDD, 0x30], FpuMemoryFormat::State94, "fnsave [ds:bx+si]"),
    ] {
        // A stale 32-bit option cannot grant a 286 32-bit operands or addresses.
        let inst = decode_one(
            &bytes[..],
            options(CpuType::Intel80286, FpuType::Intel80287XL, SegmentSize::Segment32),
        )
        .unwrap();
        assert_eq!(inst.operand1_type.fpu_memory_format(), Some(format));
        assert_eq!(inst.address_size, AddressSize::Address16);
        assert_eq!(text(&inst), expected);
    }

    for (bytes, format, expected) in [
        ([0x66, 0xD9, 0x20], FpuMemoryFormat::Env28, "o32 fldenv [ds:bx+si]"),
        ([0x66, 0xDD, 0x30], FpuMemoryFormat::State108, "o32 fnsave [ds:bx+si]"),
    ] {
        let inst = decode(&bytes, FpuType::Intel80287XL);
        assert_eq!(inst.operand1_type.fpu_memory_format(), Some(format));
        assert!(inst.has_operand_size_override());
        assert_eq!(text(&inst), expected);
    }
}

#[test]
fn addressing_metadata() {
    for (cpu, fpu) in [
        (CpuType::Intel808x, FpuType::Intel8087),
        (CpuType::NecVx0, FpuType::Intel8087),
        (CpuType::Intel80286, FpuType::Intel80287),
        (CpuType::Intel80386, FpuType::Intel80387),
    ] {
        let inst = decode_one(&[0x26, 0xD9, 0x46, 0xFE][..], options(cpu, fpu, SegmentSize::Segment16)).unwrap();
        assert_eq!(text(&inst), "fld dword [es:bp-2]");
        assert_eq!(inst.opcode_offset, 1);
        assert_eq!(inst.modrm_offset, 2);
        assert_eq!(inst.prefix_bytes, [0x26]);
    }

    let bytes = [0x64, 0x67, 0xDD, 0x44, 0x8D, 0xF0];
    let inst = decode(&bytes, FpuType::Intel80387);
    assert_eq!(text(&inst), "fld qword [fs:ebp+ecx*4-10h]");
    assert_eq!(inst.instruction_bytes, bytes);
    assert!(inst.has_sib && inst.has_displacement);
    assert_eq!(inst.sib_offset, 4);
    assert_eq!(inst.displacement_bytes, [0xF0]);
    assert_eq!(inst.operand1_type.fpu_memory_format(), Some(FpuMemoryFormat::Float64));
    let reg = decode(&[0x66, 0x67, 0xD9, 0xC1], FpuType::Intel80387);
    assert!(!reg.has_operand_size_override() && !reg.has_address_size_override());
    assert_eq!(text(&reg), "fld st1");
}

struct OneByteReader<'a>(&'a [u8]);
impl Read for OneByteReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() || self.0.is_empty() {
            return Ok(0);
        }

        out[0] = self.0[0];
        self.0 = &self.0[1..];
        Ok(1)
    }
}

#[test]
fn standalone_wait() {
    for (cpu, fpu) in [
        (CpuType::Intel808x, FpuType::Intel8087),
        (CpuType::NecVx0, FpuType::Intel8087),
        (CpuType::Intel80286, FpuType::Intel80287),
        (CpuType::Intel80386, FpuType::Intel80387),
    ] {
        let bytes = [0x9B, 0xDB, 0xE3, 0x9B, 0xDF, 0xE0, 0x90, 0x9B];
        let mut decoder = Decoder::new(OneByteReader(&bytes), options(cpu, fpu, SegmentSize::Segment16));

        for (expected, end) in [
            ("wait", 1),
            ("fninit", 3),
            ("wait", 4),
            (
                if cpu.is_fpu_compatible(FpuType::Intel8087) {
                    "esc ax"
                }
                else {
                    "fnstsw ax"
                },
                6,
            ),
            ("nop", 7),
            ("wait", 8),
        ] {
            assert_eq!(text(&decoder.decode_next().unwrap()), expected);
            assert_eq!(decoder.position(), end);
        }

        assert!(matches!(decoder.decode_next(), Err(DecodeError::Eof)));
    }
}

#[test]
fn esc_stream_boundaries() {
    for (segment, bytes) in [
        (SegmentSize::Segment16, vec![0xD9, 0x86, 0x34, 0x12]),
        (SegmentSize::Segment32, vec![0xDD, 0x84, 0x8D, 0x78, 0x56, 0x34, 0x12]),
        // DB /6 is accepted by the CPU (the apparent 386 PLA gap was a transcription error).
        (SegmentSize::Segment16, vec![0xDB, 0xB6, 0x34, 0x12]),
        (SegmentSize::Segment32, vec![0xDB, 0xB4, 0x8D, 0x78, 0x56, 0x34, 0x12]),
        (
            SegmentSize::Segment16,
            vec![0x67, 0xDD, 0x04, 0x25, 0x78, 0x56, 0x34, 0x12],
        ),
    ] {
        let opts = options(CpuType::Intel80386, FpuType::Intel80387, segment);

        for length in 1..bytes.len() {
            assert!(
                matches!(
                    decode_one(OneByteReader(&bytes[..length]), opts),
                    Err(DecodeError::UnexpectedEof)
                ),
                "{bytes:02X?} length {length}"
            );
        }

        assert_eq!(
            decode_one(OneByteReader(&bytes), opts).unwrap().instruction_bytes,
            bytes
        );
    }

    for &fpu in CpuType::Intel80386.compatible_fpus() {
        let mut decoder = Decoder::new(
            OneByteReader(&[0xDB, 0x74, 0x8D, 0xF0, 0x90]),
            options(CpuType::Intel80386, fpu, SegmentSize::Segment32),
        );
        let escape = decoder.decode_next().unwrap(); // Unrecognized DB /6 with SIB + disp8
        assert!(escape.is_valid && escape.is_complete);
        assert_eq!(escape.mnemonic, Mnemonic::ESC);
        assert!(escape.fpu.is_none());
        assert_eq!(escape.instruction_bytes, [0xDB, 0x74, 0x8D, 0xF0]);
        assert_eq!(decoder.position(), 4);
        assert_eq!(text(&decoder.decode_next().unwrap()), "nop");
    }
}

#[test]
fn default_fpu_selection() {
    assert_eq!(DecoderOptions::default().fpu, None);

    for cpu in CPUS {
        for opcode in 0xD8..=0xDF {
            let inst = decode_one(
                &[opcode, 0xC0][..],
                DecoderOptions {
                    cpu,
                    ..Default::default()
                },
            )
            .unwrap();
            assert!(inst.is_valid && inst.fpu.is_none());
            assert_eq!(inst.mnemonic.to_str(), "ESC");
        }
    }

    let inst = decode_one(
        &[0x67, 0xD9, 0x04, 0x24][..],
        DecoderOptions {
            cpu: CpuType::Intel80386,
            fpu: None,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(inst.instruction_bytes.len(), 4);
    assert_eq!(inst.address_size, AddressSize::Address32);
}

#[test]
fn instruction_length_limits() {
    for (cpu, limit) in [(CpuType::Intel80286, 10), (CpuType::Intel80386, 15)] {
        for length in [limit, limit + 1] {
            let mut bytes = vec![0x26; length - 2];
            bytes.extend_from_slice(&[0xD9, 0xC0]);
            let inst = decode_one(&bytes[..], options(cpu, FpuType::Intel80287XL, SegmentSize::Segment16)).unwrap();
            assert_eq!(inst.is_valid, length == limit);
            assert_eq!(inst.fpu.is_some(), length == limit);
        }
    }
}

#[test]
fn i387_matches_iced() {
    let mut checked = 0;
    let mut formatter = iced_x86::NasmFormatter::new();
    formatter.options_mut().set_always_show_segment_register(true);
    formatter.options_mut().set_add_leading_zero_to_hex_numbers(false);
    formatter.options_mut().set_use_pseudo_ops(false);
    formatter
        .options_mut()
        .set_memory_size_options(iced_x86::MemorySizeOptions::Always);

    for fpu_type in [FpuType::Intel80287XL, FpuType::Intel80387] {
        for (bitness, segment) in [(16, SegmentSize::Segment16), (32, SegmentSize::Segment32)] {
            for prefix in [&[][..], &[0x67][..], &[0x66][..], &[0x66, 0x67][..]] {
                for opcode in 0xD8..=0xDF {
                    for modrm in 0..=255 {
                        let mut bytes = prefix.to_vec();
                        bytes.extend_from_slice(&[opcode, modrm, 0x8D, 0x78, 0x56, 0x34, 0x12, 0]);
                        let inst = decode_one(&bytes[..], options(CpuType::Intel80386, fpu_type, segment)).unwrap();
                        let Some(fpu) = inst.fpu
                        else {
                            continue;
                        };

                        // Iced targets later x87 ISAs, which do not have the XL mode controls.
                        if fpu.undocumented
                            || fpu.compatibility_nop
                            || matches!(fpu.mnemonic, Mnemonic::FSETPM | Mnemonic::FRSTPM)
                        {
                            continue;
                        }

                        let iced = iced_x86::Decoder::new(bitness, &bytes, iced_x86::DecoderOptions::NONE).decode();
                        assert!(inst.is_valid && !iced.is_invalid(), "{bytes:02X?}");
                        assert_eq!(inst.instruction_bytes.len(), iced.len(), "{bytes:02X?}");
                        assert_eq!(
                            inst.mnemonic.to_str(),
                            format!("{:?}", iced.mnemonic()).to_ascii_uppercase(),
                            "{bytes:02X?}"
                        );

                        if let Some(format) = inst.operand1_type.fpu_memory_format() {
                            assert_eq!(format.byte_len(), iced.memory_size().size(), "{bytes:02X?}");
                        }

                        let registers = [
                            iced_x86::Register::ST0,
                            iced_x86::Register::ST1,
                            iced_x86::Register::ST2,
                            iced_x86::Register::ST3,
                            iced_x86::Register::ST4,
                            iced_x86::Register::ST5,
                            iced_x86::Register::ST6,
                            iced_x86::Register::ST7,
                        ];
                        let pair = match fpu.operands {
                            FpuOperands::St0St(i) => Some((0, i)),
                            FpuOperands::StSt0(i) => Some((i, 0)),
                            _ => None,
                        };

                        if let Some((a, b)) = pair {
                            assert_eq!(iced.op0_register(), registers[a as usize], "{bytes:02X?}");
                            assert_eq!(iced.op1_register(), registers[b as usize], "{bytes:02X?}");
                        }

                        // Iced elides implicit ST0 operands. Compare memory formatting directly;
                        // register operand direction is checked above and by explicit fixtures.
                        if prefix.is_empty()
                            && modrm < 0xC0
                            && !inst
                                .operand1_type
                                .fpu_memory_format()
                                .is_some_and(|f| f.is_environment_or_state())
                        {
                            let mut expected = String::new();
                            formatter.format(&iced, &mut expected);
                            assert_eq!(text(&inst), expected, "{bitness}-bit {bytes:02X?}");
                        }

                        checked += 1;
                    }
                }
            }
        }
    }

    assert!(checked > 24_000);
}
