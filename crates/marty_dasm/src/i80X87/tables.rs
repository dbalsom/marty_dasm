// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Daniel Balsom

use super::{FpuMemoryFormat as M, FpuOperands as O};
use crate::mnemonic::Mnemonic::{self, *};

const I287XL: u8 = 8;
const I387: u8 = 4;
const I387_CORE: u8 = I287XL | I387;
const POST_8087: u8 = 2 | I387_CORE;
const ALL: u8 = 1 | POST_8087;

#[derive(Copy, Clone)]
pub(super) struct Entry {
    pub mnemonic: Mnemonic,
    pub operands: O,
    pub models: u8,
    pub undocumented: bool,
    pub nop_models: u8,
}

const INVALID: Entry = Entry {
    mnemonic: Invalid,
    operands: O::None,
    models: 0,
    undocumented: false,
    nop_models: 0,
};

const fn entry(mnemonic: Mnemonic, operands: O) -> Entry {
    Entry {
        mnemonic,
        operands,
        models: ALL,
        undocumented: false,
        nop_models: 0,
    }
}

const fn models(mut entry: Entry, mask: u8) -> Entry {
    entry.models = mask;
    entry
}

const fn alias(mnemonic: Mnemonic, operands: O) -> Entry {
    Entry {
        models: POST_8087,
        undocumented: true,
        ..entry(mnemonic, operands)
    }
}

const fn mem(mnemonic: Mnemonic, format: M) -> Entry {
    entry(mnemonic, O::Memory(format))
}

// mod != 3: opcode D8..DF, then ModR/M.reg. R/M only specifies the CPU address.
#[rustfmt::skip]
pub(super) const MEMORY: [[Entry; 8]; 8] = [
    [mem(FADD, M::Float32), mem(FMUL, M::Float32),  mem(FCOM, M::Float32), mem(FCOMP, M::Float32),  mem(FSUB,   M::Float32),      mem(FSUBR, M::Float32),     mem(FDIV,   M::Float32), mem(FDIVR, M::Float32)],
    [mem(FLD,  M::Float32), INVALID,                mem(FST,  M::Float32), mem(FSTP,  M::Float32),  mem(FLDENV,M::Env14),         mem(FLDCW, M::ControlWord), mem(FNSTENV,M::Env14),   mem(FNSTCW,M::ControlWord)],
    [mem(FIADD,M::Int32),   mem(FIMUL,M::Int32),    mem(FICOM,M::Int32),   mem(FICOMP,M::Int32),    mem(FISUB, M::Int32),         mem(FISUBR,M::Int32),       mem(FIDIV,  M::Int32),   mem(FIDIVR,M::Int32)],
    [mem(FILD, M::Int32),   INVALID,                mem(FIST, M::Int32),   mem(FISTP, M::Int32),    INVALID,                      mem(FLD,   M::Float80),     INVALID,                 mem(FSTP,  M::Float80)],
    [mem(FADD, M::Float64), mem(FMUL, M::Float64),  mem(FCOM, M::Float64), mem(FCOMP, M::Float64),  mem(FSUB,  M::Float64),       mem(FSUBR, M::Float64),     mem(FDIV,   M::Float64), mem(FDIVR, M::Float64)],
    [mem(FLD,  M::Float64), INVALID,                mem(FST,  M::Float64), mem(FSTP,  M::Float64),  mem(FRSTOR,M::State94),       INVALID,                    mem(FNSAVE, M::State94), mem(FNSTSW,M::StatusWord)],
    [mem(FIADD,M::Int16),   mem(FIMUL,M::Int16),    mem(FICOM,M::Int16),   mem(FICOMP,M::Int16),    mem(FISUB, M::Int16),         mem(FISUBR,M::Int16),       mem(FIDIV,  M::Int16),   mem(FIDIVR,M::Int16)],
    [mem(FILD, M::Int16),   INVALID,                mem(FIST, M::Int16),   mem(FISTP, M::Int16),    mem(FBLD,  M::Bcd80),         mem(FILD,  M::Int64),       mem(FBSTP,  M::Bcd80),   mem(FISTP, M::Int64)],
];

// mod == 3: all SIX low ModR/M bits select the operation; /reg alone is insufficient.
pub(super) const REGISTER: [[Entry; 64]; 8] = {
    let mut t = [[INVALID; 64]; 8];
    let mut i = 0;
    while i < 8 {
        let st = O::St(i as u8);
        let st0_st = O::St0St(i as u8);
        let st_st0 = O::StSt0(i as u8);
        t[0][i] = entry(FADD, st0_st);
        t[0][8 + i] = entry(FMUL, st0_st);
        t[0][16 + i] = entry(FCOM, st);
        t[0][24 + i] = entry(FCOMP, st);
        t[0][32 + i] = entry(FSUB, st0_st);
        t[0][40 + i] = entry(FSUBR, st0_st);
        t[0][48 + i] = entry(FDIV, st0_st);
        t[0][56 + i] = entry(FDIVR, st0_st);

        t[1][i] = entry(FLD, st);
        t[1][8 + i] = entry(FXCH, st);
        t[1][24 + i] = alias(FSTPNCE, st);

        t[4][i] = entry(FADD, st_st0);
        t[4][8 + i] = entry(FMUL, st_st0);
        t[4][16 + i] = alias(FCOM, st);
        t[4][24 + i] = alias(FCOMP, st);
        // The reverse-operation bit changes meaning when the destination is ST(i).
        t[4][32 + i] = entry(FSUBR, st_st0);
        t[4][40 + i] = entry(FSUB, st_st0);
        t[4][48 + i] = entry(FDIVR, st_st0);
        t[4][56 + i] = entry(FDIV, st_st0);

        t[5][i] = entry(FFREE, st);
        t[5][8 + i] = alias(FXCH, st);
        t[5][16 + i] = entry(FST, st);
        t[5][24 + i] = entry(FSTP, st);
        t[5][32 + i] = models(entry(FUCOM, st), I387_CORE);
        t[5][40 + i] = models(entry(FUCOMP, st), I387_CORE);

        t[6][i] = entry(FADDP, st_st0);
        t[6][8 + i] = entry(FMULP, st_st0);
        t[6][16 + i] = alias(FCOMP, st);
        t[6][32 + i] = entry(FSUBRP, st_st0);
        t[6][40 + i] = entry(FSUBP, st_st0);
        t[6][48 + i] = entry(FDIVRP, st_st0);
        t[6][56 + i] = entry(FDIVP, st_st0);

        // Unlike the other alternate families, FFREEP also exists on the 8087.
        t[7][i] = models(alias(FFREEP, st), ALL);
        t[7][8 + i] = alias(FXCH, st);
        t[7][16 + i] = alias(FSTP, st);
        t[7][24 + i] = alias(FSTP, st);
        i += 1;
    }

    t[1][0x10] = entry(FNOP, O::None);
    t[1][0x20] = entry(FCHS, O::None);
    t[1][0x21] = entry(FABS, O::None);
    t[1][0x24] = entry(FTST, O::None);
    t[1][0x25] = entry(FXAM, O::None);
    t[1][0x28] = entry(FLD1, O::None);
    t[1][0x29] = entry(FLDL2T, O::None);
    t[1][0x2A] = entry(FLDL2E, O::None);
    t[1][0x2B] = entry(FLDPI, O::None);
    t[1][0x2C] = entry(FLDLG2, O::None);
    t[1][0x2D] = entry(FLDLN2, O::None);
    t[1][0x2E] = entry(FLDZ, O::None);
    t[1][0x30] = entry(F2XM1, O::None);
    t[1][0x31] = entry(FYL2X, O::None);
    t[1][0x32] = entry(FPTAN, O::None);
    t[1][0x33] = entry(FPATAN, O::None);
    t[1][0x34] = entry(FXTRACT, O::None);
    t[1][0x35] = models(entry(FPREM1, O::None), I387_CORE);
    t[1][0x36] = entry(FDECSTP, O::None);
    t[1][0x37] = entry(FINCSTP, O::None);
    t[1][0x38] = entry(FPREM, O::None);
    t[1][0x39] = entry(FYL2XP1, O::None);
    t[1][0x3A] = entry(FSQRT, O::None);
    t[1][0x3B] = models(entry(FSINCOS, O::None), I387_CORE);
    t[1][0x3C] = entry(FRNDINT, O::None);
    t[1][0x3D] = entry(FSCALE, O::None);
    t[1][0x3E] = models(entry(FSIN, O::None), I387_CORE);
    t[1][0x3F] = models(entry(FCOS, O::None), I387_CORE);

    t[2][0x29] = models(entry(FUCOMPP, O::None), I387_CORE);
    t[3][0x20] = Entry {
        nop_models: POST_8087,
        ..entry(FNENI, O::None)
    };
    t[3][0x21] = Entry {
        nop_models: POST_8087,
        ..entry(FNDISI, O::None)
    };
    t[3][0x22] = entry(FNCLEX, O::None);
    t[3][0x23] = entry(FNINIT, O::None);
    t[3][0x24] = Entry {
        nop_models: I387,
        ..models(entry(FSETPM, O::None), POST_8087)
    };
    // Intel 290376-003 lists DB F4. OPCODE.LST instead reports DB E5; accept
    // the latter as an undocumented alias until hardware validation can confirm it.
    t[3][0x34] = models(entry(FRSTPM, O::None), I287XL);
    t[3][0x25] = models(alias(FRSTPM, O::None), I287XL);
    t[6][0x19] = entry(FCOMPP, O::None);
    t[7][0x20] = models(entry(FNSTSW, O::Ax), POST_8087);
    t
};
