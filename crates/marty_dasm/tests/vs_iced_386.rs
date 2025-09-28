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

use rand::{Rng, SeedableRng};
use marty_dasm::prelude::*;
use crate::common::format::{format_iced_instruction, format_marty_instruction};
use crate::common::init_tests;

pub const TEST_SEED: u64 = 0x12345678;
pub const FUZZ_TEST_COUNT: usize = 10_000_000;

// There are an absolute ton of valid modern x86 instructions lurking in the undefined/invalid
// space of the 386. Here we try to filter them all out.
pub const REJECT_MNEMONICS: &[iced_x86::Mnemonic] = {
    use iced_x86::Mnemonic;
    &[
        Mnemonic::Andn,
        Mnemonic::Clac,
        Mnemonic::Clgi,
        Mnemonic::Clzero,
        Mnemonic::Encls,
        Mnemonic::Enclu,
        Mnemonic::Enclv,
        Mnemonic::Invd,
        Mnemonic::Invlpg,
        Mnemonic::Invlpga,
        Mnemonic::Invlpgb,
        Mnemonic::Kaddw,
        Mnemonic::Kandw,
        Mnemonic::Kmovb,
        Mnemonic::Kmovd,
        Mnemonic::Kmovw,
        Mnemonic::Knotb,
        Mnemonic::Korb,
        Mnemonic::Kortestb,
        Mnemonic::Korw,
        Mnemonic::Ktestw,
        Mnemonic::Kxnorb,
        Mnemonic::Kxnorw,
        Mnemonic::Kxorb,
        Mnemonic::Monitor,
        Mnemonic::Monitorx,
        Mnemonic::Mwait,
        Mnemonic::Mwaitx,
        Mnemonic::Pconfig,
        Mnemonic::Rdpkru,
        Mnemonic::Rdpru,
        Mnemonic::Rdtscp,
        Mnemonic::Serialize,
        Mnemonic::Skinit,
        Mnemonic::Stac,
        Mnemonic::Stgi,
        Mnemonic::Sysret,
        Mnemonic::Tlbsync,
        Mnemonic::Vaddpd,
        Mnemonic::Vaddps,
        Mnemonic::Vaddsd,
        Mnemonic::Vaddss,
        Mnemonic::Vaddsubpd,
        Mnemonic::Vaddsubps,
        Mnemonic::Vaesenclast,
        Mnemonic::Vaesimc,
        Mnemonic::Vandnpd,
        Mnemonic::Vandnps,
        Mnemonic::Vandpd,
        Mnemonic::Vandps,
        Mnemonic::Vblendmps,
        Mnemonic::Vblendpd,
        Mnemonic::Vcmppd,
        Mnemonic::Vcmpps,
        Mnemonic::Vcmpsd,
        Mnemonic::Vcmpss,
        Mnemonic::Vcomisd,
        Mnemonic::Vcomiss,
        Mnemonic::Vcvtdq2pd,
        Mnemonic::Vcvtdq2ps,
        Mnemonic::Vcvtpd2dq,
        Mnemonic::Vcvtpd2ps,
        Mnemonic::Vcvtps2dq,
        Mnemonic::Vcvtps2pd,
        Mnemonic::Vcvtsd2si,
        Mnemonic::Vcvtsd2ss,
        Mnemonic::Vcvtsi2sd,
        Mnemonic::Vcvtsi2ss,
        Mnemonic::Vcvtss2sd,
        Mnemonic::Vcvtss2si,
        Mnemonic::Vcvttpd2dq,
        Mnemonic::Vcvttps2dq,
        Mnemonic::Vcvttsd2si,
        Mnemonic::Vcvttsd2usi,
        Mnemonic::Vcvttss2si,
        Mnemonic::Vcvtudq2ph,
        Mnemonic::Vdivpd,
        Mnemonic::Vdivps,
        Mnemonic::Vdivsd,
        Mnemonic::Vdivss,
        Mnemonic::Vfmadd132pd,
        Mnemonic::Vfmaddcsh,
        Mnemonic::Vfmaddsub132ps,
        Mnemonic::Vfmaddsub231ph,
        Mnemonic::Vfmaddsubps,
        Mnemonic::Vfmsub132ps,
        Mnemonic::Vfmsub132sd,
        Mnemonic::Vfmsubadd231ps,
        Mnemonic::Vfmsubsd,
        Mnemonic::Vfnmadd213ps,
        Mnemonic::Vfnmsub213pd,
        Mnemonic::Vfrczpd,
        Mnemonic::Vfrczps,
        Mnemonic::Vfrczsd,
        Mnemonic::Vhaddpd,
        Mnemonic::Vhaddps,
        Mnemonic::Vhsubpd,
        Mnemonic::Vhsubps,
        Mnemonic::Vlddqu,
        Mnemonic::Vmaskmovdqu,
        Mnemonic::Vmaxpd,
        Mnemonic::Vmaxps,
        Mnemonic::Vmaxsd,
        Mnemonic::Vmaxss,
        Mnemonic::Vmcall,
        Mnemonic::Vmfunc,
        Mnemonic::Vminpd,
        Mnemonic::Vminps,
        Mnemonic::Vminsd,
        Mnemonic::Vminss,
        Mnemonic::Vmlaunch,
        Mnemonic::Vmload,
        Mnemonic::Vmmcall,
        Mnemonic::Vmovapd,
        Mnemonic::Vmovaps,
        Mnemonic::Vmovd,
        Mnemonic::Vmovddup,
        Mnemonic::Vmovdqa,
        Mnemonic::Vmovdqu,
        Mnemonic::Vmovhpd,
        Mnemonic::Vmovhps,
        Mnemonic::Vmovlpd,
        Mnemonic::Vmovlps,
        Mnemonic::Vmovmskpd,
        Mnemonic::Vmovmskps,
        Mnemonic::Vmovntdq,
        Mnemonic::Vmovntpd,
        Mnemonic::Vmovq,
        Mnemonic::Vmovsd,
        Mnemonic::Vmovshdup,
        Mnemonic::Vmovsldup,
        Mnemonic::Vmovss,
        Mnemonic::Vmovupd,
        Mnemonic::Vmovups,
        Mnemonic::Vmresume,
        Mnemonic::Vmrun,
        Mnemonic::Vmsave,
        Mnemonic::Vmulpd,
        Mnemonic::Vmulps,
        Mnemonic::Vmulsd,
        Mnemonic::Vmulss,
        Mnemonic::Vmxoff,
        Mnemonic::Vorpd,
        Mnemonic::Vorps,
        Mnemonic::Vpabsd,
        Mnemonic::Vpackssdw,
        Mnemonic::Vpacksswb,
        Mnemonic::Vpackuswb,
        Mnemonic::Vpaddb,
        Mnemonic::Vpaddd,
        Mnemonic::Vpaddq,
        Mnemonic::Vpaddsb,
        Mnemonic::Vpaddsw,
        Mnemonic::Vpaddusb,
        Mnemonic::Vpaddusw,
        Mnemonic::Vpaddw,
        Mnemonic::Vpand,
        Mnemonic::Vpandn,
        Mnemonic::Vpavgb,
        Mnemonic::Vpavgw,
        Mnemonic::Vpcmov,
        Mnemonic::Vpcmpeqb,
        Mnemonic::Vpcmpeqd,
        Mnemonic::Vpcmpeqw,
        Mnemonic::Vpcmpgtb,
        Mnemonic::Vpcmpgtd,
        Mnemonic::Vpcmpgtw,
        Mnemonic::Vpcomb,
        Mnemonic::Vpcomd,
        Mnemonic::Vpdpwusd,
        Mnemonic::Vpextrd,
        Mnemonic::Vphaddd,
        Mnemonic::Vphaddubq,
        Mnemonic::Vphaddubw,
        Mnemonic::Vpinsrw,
        Mnemonic::Vpmacsdd,
        Mnemonic::Vpmacsdql,
        Mnemonic::Vpmadcsswd,
        Mnemonic::Vpmadd52luq,
        Mnemonic::Vpmaddwd,
        Mnemonic::Vpmaxsb,
        Mnemonic::Vpmaxsw,
        Mnemonic::Vpmaxub,
        Mnemonic::Vpminsw,
        Mnemonic::Vpminub,
        Mnemonic::Vpminud,
        Mnemonic::Vpmovmskb,
        Mnemonic::Vpmovqw,
        Mnemonic::Vpmovsxbd,
        Mnemonic::Vpmovzxbq,
        Mnemonic::Vpmulhrsw,
        Mnemonic::Vpmulhuw,
        Mnemonic::Vpmulhw,
        Mnemonic::Vpmullw,
        Mnemonic::Vpmuludq,
        Mnemonic::Vpor,
        Mnemonic::Vpperm,
        Mnemonic::Vprolvd,
        Mnemonic::Vprotb,
        Mnemonic::Vprotd,
        Mnemonic::Vprotw,
        Mnemonic::Vpsadbw,
        Mnemonic::Vpshad,
        Mnemonic::Vpshaw,
        Mnemonic::Vpshlb,
        Mnemonic::Vpshld,
        Mnemonic::Vpshlq,
        Mnemonic::Vpshufd,
        Mnemonic::Vpshufhw,
        Mnemonic::Vpshuflw,
        Mnemonic::Vpsignd,
        Mnemonic::Vpslld,
        Mnemonic::Vpslldq,
        Mnemonic::Vpsllq,
        Mnemonic::Vpsllw,
        Mnemonic::Vpsrad,
        Mnemonic::Vpsraw,
        Mnemonic::Vpsrld,
        Mnemonic::Vpsrlq,
        Mnemonic::Vpsrlw,
        Mnemonic::Vpsubb,
        Mnemonic::Vpsubd,
        Mnemonic::Vpsubq,
        Mnemonic::Vpsubsb,
        Mnemonic::Vpsubsw,
        Mnemonic::Vpsubusb,
        Mnemonic::Vpsubusw,
        Mnemonic::Vpsubw,
        Mnemonic::Vptestmd,
        Mnemonic::Vpunpckhbw,
        Mnemonic::Vpunpckhdq,
        Mnemonic::Vpunpckhqdq,
        Mnemonic::Vpunpckhwd,
        Mnemonic::Vpunpcklbw,
        Mnemonic::Vpunpckldq,
        Mnemonic::Vpunpcklqdq,
        Mnemonic::Vpunpcklwd,
        Mnemonic::Vpxor,
        Mnemonic::Vrcpps,
        Mnemonic::Vrcpsh,
        Mnemonic::Vrcpss,
        Mnemonic::Vrsqrtps,
        Mnemonic::Vrsqrtss,
        Mnemonic::Vshufpd,
        Mnemonic::Vshufps,
        Mnemonic::Vsqrtpd,
        Mnemonic::Vsqrtps,
        Mnemonic::Vsqrtsd,
        Mnemonic::Vsqrtss,
        Mnemonic::Vsubpd,
        Mnemonic::Vsubps,
        Mnemonic::Vsubsd,
        Mnemonic::Vsubss,
        Mnemonic::Vtestpd,
        Mnemonic::Vucomisd,
        Mnemonic::Vucomiss,
        Mnemonic::Vunpckhpd,
        Mnemonic::Vunpckhps,
        Mnemonic::Vunpcklpd,
        Mnemonic::Vunpcklps,
        Mnemonic::Vxorpd,
        Mnemonic::Vxorps,
        Mnemonic::Vzeroall,
        Mnemonic::Vzeroupper,
        Mnemonic::Wrmsrns,
        Mnemonic::Wrpkru,
        Mnemonic::Xabort,
        Mnemonic::Xbegin,
        Mnemonic::Xend,
        Mnemonic::Xgetbv,
        Mnemonic::Xsetbv,
        Mnemonic::Xtest,

    ]
};

#[test]
fn fuzz_against_iced86() -> Result<(), Box<dyn std::error::Error>> {
    init_tests();
    let mut rng = rand::rngs::StdRng::seed_from_u64(TEST_SEED);
    let mut error_ct = 0;

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

    for run_no in 0..FUZZ_TEST_COUNT {

        // Get a random instruction for 386
        let instruction = fuzzer.random_instruction(&mut rng, &options)?;

        let iced_decoder_opts = iced_x86::DecoderOptions::NO_INVALID_CHECK | iced_x86::DecoderOptions::LOADALL386;
        let iced_decode_buffer = instruction.bytes.clone();
        let marty_decode_buffer = Cursor::new(instruction.bytes.clone());

        // Coin toss between 16 and 32 bit mode
        let wide = rng.random_bool(0.5);
        let (bitness, segment_size) = if wide { (32, SegmentSize::Segment32) } else { (16, SegmentSize::Segment16 ) };

        // Decode instruction with iced.
        let mut decoder = iced_x86::Decoder::new(bitness, &iced_decode_buffer, iced_decoder_opts);
        let iced_i = decoder.decode();

        // Get iced string.
        let mut iced_str = format_iced_instruction(&iced_i);
        // Replace certain funky mnemonics with "bad"
        if REJECT_MNEMONICS.contains(&iced_i.mnemonic()) {
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
                run_no, segment_size, iced_display, marty_display, marty_i.operand_ct(), marty_i.is_complete, marty_i.disambiguate, marty_i.address_size, &instruction.bytes
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