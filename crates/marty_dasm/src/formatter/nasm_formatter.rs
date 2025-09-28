/*
    marty_dasm
    Copyright 2022-2025 Daniel Balsom
    https://github.com/dbalsom/marty_dasm

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
use std::fmt::{Display, UpperHex};
use num_traits::{PrimInt, Signed, ToPrimitive};
use crate::cpu_common::{AddressOffset16, AddressOffset32, AddressSize, BaseRegister, OperandSize, OperandType, PrefixFlags, Register16, ScaledIndex, SibScale};
use crate::cpu_common::AddressOffset16::{BpDi, BpSi, BpSiDisp8, Bx, BxDi, BxDisp16, BxSi, BxSiDisp16, Di, Si, SiDisp8};
use crate::cpu_common::AddressOffset32::{Eax, EaxDisp8, Ebp, Ebx, Ecx, Edi, Edx, Esi, SibPending};
use crate::formatter::{Format, FormatOptions, FormatterOutput};
use crate::instruction::Instruction;
use crate::mnemonic::Mnemonic;

pub trait UnsignedAbsU32: Copy {
    fn unsigned_abs_u32(self) -> u32;
    fn is_negative(self) -> bool;
}

impl UnsignedAbsU32 for i8 {
    #[inline] fn unsigned_abs_u32(self) -> u32 { self.unsigned_abs() as u32 }
    #[inline] fn is_negative(self) -> bool { self < 0 }
}
impl UnsignedAbsU32 for i16 {
    #[inline] fn unsigned_abs_u32(self) -> u32 { self.unsigned_abs() as u32 }
    #[inline] fn is_negative(self) -> bool { self < 0 }
}
impl UnsignedAbsU32 for i32 {
    #[inline] fn unsigned_abs_u32(self) -> u32 { self.unsigned_abs() as u32 }
    #[inline] fn is_negative(self) -> bool { self < 0 }
}


/// NASM-style formatter
#[derive(Copy, Clone, Debug, Default)]
pub struct NasmFormatter;

impl Format for NasmFormatter {
    fn format_prefixes(&self, inst: &Instruction, _opts: &FormatOptions, out: &mut dyn FormatterOutput) {
        // Minimal: ignore prefixes for now. Extend later for lock/rep and seg overrides.

        if inst.prefix_flags & PrefixFlags::LOCK != 0 {
            out.write_prefix("lock");
            out.write_separator(" ");
        }
    }

    fn format_mnemonic(&self, inst: &Instruction, opts: &FormatOptions, out: &mut dyn FormatterOutput) {
        let m = if opts.iced_mnemonics {
            inst.mnemonic.to_iced_str().unwrap_or(inst.mnemonic.to_str())
        }
        else {
            inst.mnemonic.to_str()
        };

        if opts.uppercase_mnemonic {
            out.write_mnemonic(m);
        } else {
            out.write_mnemonic(&m.to_ascii_lowercase());
        }
    }

    fn format_operands(&self, inst: &Instruction, _opts: &FormatOptions, out: &mut dyn FormatterOutput) {

        // Print disambiguator ('byte', 'word', 'dword') if needed
        self.format_disambiguation(inst, _opts, inst.operand1_type, out);

        self.format_operand(inst, inst.operand1_type, inst.segment_override, _opts, out);
        if !matches!(inst.operand2_type, OperandType::NoOperand) {
            out.write_separator(",");
        }
        self.format_disambiguation(inst, _opts, inst.operand2_type, out);

        self.format_operand(inst, inst.operand2_type, inst.segment_override, _opts, out);
        if !matches!(inst.operand3_type, OperandType::NoOperand) {
            out.write_separator(",");
        }
        self.format_operand(inst, inst.operand3_type, inst.segment_override, _opts, out);
    }

    fn operands_suppressed(&self, inst: &Instruction) -> bool {
        match inst.mnemonic {
            Mnemonic::AAM | Mnemonic::AAD => {
                // The default operand for AAD & AAM is 0x0A, it is standard not to display it
                if let OperandType::Immediate8(imm) = inst.operand1_type {
                    imm == 0x0A
                } else {
                    false
                }
            },
            Mnemonic::NOP => {
                // NOP is often encoded as XCHG eAX, eAX, so suppress the operands
                true
            }
            _ => false
        }
    }
}

pub fn format_hex_or_decimal<T: PrimInt + Display + std::fmt::UpperHex>(value: T) -> String {
    if value < T::from(10).unwrap() {
        format!("{}", value)
    } else {
        format!("{:X}h", value)
    }
}

pub fn format_signed_hex_or_decimal<T: UnsignedAbsU32>(value: T) -> String {
    let neg = value.is_negative();
    let mag = value.unsigned_abs_u32(); // exact macro behavior

    if mag < 10 {
        if mag == 0 {
            String::new()
        } else if neg {
            format!("-{mag}")
        } else {
            format!("+{mag}")
        }
    } else {
        // hex from the *unsigned* magnitude
        let s = format!("{:X}", mag);
        if neg {
            format!("-{s}h")
        }
        else {
            format!("+{s}h")
        }
    }
}

pub fn format_hex_or_decimal_16<T: PrimInt + Display + std::fmt::UpperHex>(value: T) -> String {
    if value < T::from(10).unwrap() {
        format!("{}", value)
    } else {
        format!("{:04X}h", value)
    }
}

pub fn format_hex_or_decimal_32<T: PrimInt + Display + std::fmt::UpperHex>(value: T) -> String {
    if value < T::from(10).unwrap() {
        format!("{}", value)
    } else {
        format!("{:08X}h", value)
    }
}

impl NasmFormatter {

    fn format_disambiguation(&self, inst: &Instruction, _opts: &FormatOptions, operand_type: OperandType, out: &mut dyn FormatterOutput) {
        if inst.disambiguate {
            let operand_size = match operand_type {
                OperandType::AddressingMode16(_, size) => Some(size),
                OperandType::AddressingMode32(_, size) => Some(size),
                OperandType::Relative8(_) => {
                    out.write_text("short");
                    out.write_separator(" ");
                    return;
                }
                OperandType::Relative16(_) | OperandType::Relative32(_) => {
                    out.write_text("near");
                    out.write_separator(" ");
                    return;
                }
                _ => None
            };

            if let Some(size) = operand_size {
                if inst.mnemonic.is_far() {

                    out.write_text("far");
                    out.write_separator(" ");
                }
                else {
                    match size {
                        OperandSize::Operand8 => out.write_text("byte"),
                        OperandSize::Operand16 => out.write_text("word"),
                        OperandSize::Operand32 => out.write_text("dword"),
                        _ => {}
                    }
                    out.write_separator(" ");
                }
            }
        }
    }

    fn format_address_16(&self, mode: AddressOffset16, out: &mut dyn FormatterOutput) {
        use AddressOffset16::*;

        // Output registers
        match mode {
            None => {},
            BxSi | BxSiDisp8(_) | BxSiDisp16(_) => {
                out.write_register("bx");
                out.write_symbol("+");
                out.write_register("si");
            },
            BxDi | BxDiDisp8(_) | BxDiDisp16(_) => {
                out.write_register("bx");
                out.write_symbol("+");
                out.write_register("di");
            },
            BpSi | BpSiDisp8(_) | BpSiDisp16(_) => {
                out.write_register("bp");
                out.write_symbol("+");
                out.write_register("si");
            },
            BpDi | BpDiDisp8(_) | BpDiDisp16(_) => {
                out.write_register("bp");
                out.write_symbol("+");
                out.write_register("di");
            },
            Si | SiDisp8(_) | SiDisp16(_) => out.write_register("si"),
            Di | DiDisp8(_) | DiDisp16(_) => out.write_register("di"),
            Disp16(disp) => {
                out.write_displacement(&format_hex_or_decimal(disp as u16))
            },
            Bx | BxDisp8(_) | BxDisp16(_) => out.write_register("bx"),
            BpDisp8(_) | BpDisp16(_) => out.write_register("bp"),
        }

        // Output displacement
        match mode {
            BxSiDisp8(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            BxDiDisp8(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            BpSiDisp8(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            BpDiDisp8(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            SiDisp8(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            DiDisp8(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            BpDisp8(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            BxDisp8(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            BxSiDisp16(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            BxDiDisp16(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            BpSiDisp16(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            BpDiDisp16(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            SiDisp16(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            DiDisp16(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            BpDisp16(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            BxDisp16(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            _ => {}
        }
    }

    fn format_scale(out: &mut dyn FormatterOutput, scale: SibScale) {
        match scale {
            SibScale::One => {
                out.write_symbol("*");
                out.write_text("1");
            },
            SibScale::Two => {
                out.write_symbol("*");
                out.write_text("2");
            },
            SibScale::Four => {
                out.write_symbol("*");
                out.write_text("4");
            },
            SibScale::Eight => {
                out.write_symbol("*");
                out.write_text("8");
            },
        }
    }

    fn format_scaled_index(out: &mut dyn FormatterOutput, scale: ScaledIndex) {
        match scale {
            ScaledIndex::None => {},
            ScaledIndex::EaxScaled(scale) => {
                out.write_register("eax");
                Self::format_scale(out, scale)
            },
            ScaledIndex::EcxScaled(scale) => {
                out.write_register("ecx");
                Self::format_scale(out, scale)
            },
            ScaledIndex::EdxScaled(scale) => {
                out.write_register("edx");
                Self::format_scale(out, scale)
            },
            ScaledIndex::EbxScaled(scale) => {
                out.write_register("ebx");
                Self::format_scale(out, scale)
            }
            ScaledIndex::EbpScaled(scale) => {
                out.write_register("ebp");
                Self::format_scale(out, scale)
            },
            ScaledIndex::EsiScaled(scale) => {
                out.write_register("esi");
                Self::format_scale(out, scale)
            },
            ScaledIndex::EdiScaled(scale) => {
                out.write_register("edi");
                Self::format_scale(out, scale)
            },
        }
    }

    fn format_address_32(&self, mode: AddressOffset32, out: &mut dyn FormatterOutput) {
        use AddressOffset32::*;

        // Output registers
        match mode {
            Eax | EaxDisp8(_) | EaxDisp32(_) => out.write_register("eax"),
            Ecx | EcxDisp8(_) | EcxDisp32(_) => out.write_register("ecx"),
            Edx | EdxDisp8(_) | EdxDisp32(_) => out.write_register("edx"),
            Ebx | EbxDisp8(_) | EbxDisp32(_) => out.write_register("ebx"),
            Ebp | EbpDisp8(_) | EbpDisp32(_) => out.write_register("ebp"),
            Esi | EsiDisp8(_) | EsiDisp32(_) => out.write_register("esi"),
            Edi | EdiDisp8(_) | EdiDisp32(_) => out.write_register("edi"),
            _ => {}
        }

        match mode {
            Disp32(disp) => out.write_displacement(&format_hex_or_decimal(disp as u32)),
            EaxDisp8(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            EcxDisp8(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            EdxDisp8(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            EbxDisp8(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            EspDisp8(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            EbpDisp8(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            EsiDisp8(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            EdiDisp8(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            EaxDisp32(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            EcxDisp32(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            EdxDisp32(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            EbxDisp32(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            EspDisp32(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            EbpDisp32(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            EsiDisp32(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            EdiDisp32(disp) => out.write_displacement(&format_signed_hex_or_decimal(disp)),
            SibPending => out.write_error(),
            Sib(base, scale) => {
                out.write_register(&format!("{}", base));
                if base.is_some() && scale.is_some() {
                    out.write_symbol("+");
                }
                Self::format_scaled_index(out, scale);
            }
            SibDisp8(base, scale, disp) => {
                out.write_register(&format!("{}", base));
                if base.is_some() && scale.is_some() {
                    out.write_symbol("+");
                }
                Self::format_scaled_index(out, scale);
                out.write_displacement(&format_signed_hex_or_decimal(disp))
            }
            SibDisp32(BaseRegister::None, ScaledIndex::None, disp) => {
                out.write_displacement(&format_hex_or_decimal(disp as u32))
            }
            SibDisp32(base, scale, disp) => {
                out.write_register(&format!("{}", base));
                if base.is_some() && scale.is_some() {
                    out.write_symbol("+");
                }
                Self::format_scaled_index(out, scale);
                out.write_displacement(&format_signed_hex_or_decimal(disp))
            }
            SibDisp8Ebp(base, scale, disp) => {
                out.write_register(&format!("{}", base));
                if base.is_some() && scale.is_some() {
                    out.write_symbol("+");
                }
                Self::format_scaled_index(out, scale);
                out.write_displacement(&format_signed_hex_or_decimal(disp))
            }
            SibDisp32Ebp(base, scale, disp) => {
                out.write_register(&format!("{}", base));
                if base.is_some() && scale.is_some() {
                    out.write_symbol("+");
                }
                Self::format_scaled_index(out, scale);
                out.write_displacement(&format_signed_hex_or_decimal(disp))
            }
            _ => {}
        }
    }

    fn format_operand(&self, instruction: &Instruction, operand: OperandType, seg_override: Option<Register16>, _opts: &FormatOptions, out: &mut dyn FormatterOutput) {
        match operand {
            OperandType::Immediate8(imm) => { out.write_immediate(&format_hex_or_decimal(imm)); }
            OperandType::Immediate16(imm) => { out.write_immediate(&format_hex_or_decimal(imm)); }
            OperandType::Immediate32(imm) => { out.write_immediate(&format_hex_or_decimal(imm)); }
            OperandType::Immediate8s(imm) => {
                let display = match instruction.address_size {
                    AddressSize::Address16 => format_hex_or_decimal(imm as i16 as u16),
                    AddressSize::Address32 => format_hex_or_decimal(imm as i16 as i32 as u32),
                };
                out.write_immediate(&display);
            }
            OperandType::Relative8(num) => {
                let display = match instruction.address_size {
                    AddressSize::Address16 => {
                        let adjust_relative = (num as u16).wrapping_add(instruction.instruction_bytes.len() as u16);
                        out.write_relative(&format_hex_or_decimal_16(adjust_relative))
                    },
                    AddressSize::Address32 => {
                        let adjust_relative = (num as i16).wrapping_add(instruction.instruction_bytes.len() as i16);
                        out.write_relative(&format_hex_or_decimal_32(adjust_relative as u32))
                    },
                };
            }
            OperandType::Relative16(num) => {
                let display = (num as u16).wrapping_add(instruction.instruction_bytes.len() as u16);
                let width = match instruction.address_size {
                    AddressSize::Address16 => {
                        out.write_relative(&format_hex_or_decimal_16(display))
                    },
                    AddressSize::Address32 => {
                        out.write_relative(&format_hex_or_decimal_32(display))
                    },
                };
            }
            OperandType::Relative32(num ) => {
                let display = (num as u32).wrapping_add(instruction.instruction_bytes.len() as u32);
                out.write_relative(&format_hex_or_decimal_32(display))
            }
            OperandType::Offset8_16(offset) | OperandType::Offset16_16(offset) | OperandType::Offset32_16(offset) => {
                let base_register = if let Some(seg) = seg_override {
                    seg
                } else {
                    Register16::DS
                };
                out.write_separator("[");
                out.write_register(&format!("{}:", base_register));
                out.write_text(&format_hex_or_decimal(offset));
                out.write_separator("]");
            }
            OperandType::Offset8_32(offset) |  OperandType::Offset16_32(offset) | OperandType::Offset32_32(offset) => {
                let base_register = if let Some(seg) = seg_override {
                    seg
                } else {
                    Register16::DS
                };
                out.write_separator("[");
                out.write_register(&format!("{}:", base_register));
                out.write_text(&format_hex_or_decimal(offset));
                out.write_separator("]");
            }
            OperandType::Register8(reg) => { out.write_register(&reg.to_string()); }
            OperandType::Register16(reg) => { out.write_register(&reg.to_string()); }
            OperandType::Register32(reg) => { out.write_register(&reg.to_string()); }
            OperandType::ControlRegister(reg) => { out.write_register(&reg.to_string()); }
            OperandType::DebugRegister(reg) => { out.write_register(&reg.to_string()); }
            OperandType::AddressingMode16(mode, _) => {

                let base_register = if let Some(seg) = seg_override {
                    seg
                } else {
                    mode.base_register()
                };

                out.write_separator("[");
                out.write_register(&format!("{}:", base_register));
                self.format_address_16(mode, out);
                out.write_separator("]");
            }
            OperandType::AddressingMode32(mode, _) => {

                let base_register = if let Some(seg) = seg_override {
                    seg
                } else {
                    mode.base_register()
                };

                out.write_separator("[");
                out.write_register(&format!("{}:", base_register));
                self.format_address_32(mode, out);
                out.write_separator("]");
            }
            OperandType::FarPointer16(segment, offset) => {
                out.write_text(&format_hex_or_decimal_16(segment));
                out.write_separator(":");
                out.write_text(&format_hex_or_decimal_16(offset));
            }
            OperandType::FarPointer32(segment, offset) => {
                out.write_text(&format_hex_or_decimal_16(segment));
                out.write_separator(":");
                out.write_text(&format_hex_or_decimal_32(offset));
            }
            OperandType::M16Pair(_, _) => {}
            OperandType::NoOperand => {}
            OperandType::InvalidOperand => {}
        }
    }

}