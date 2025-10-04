use crate::cpu_common::OperandSize;
use std::fmt;

//noinspection ALL
/// Mnemonics for x86 instructions
#[allow(dead_code)]
#[derive(PartialEq, Copy, Clone, Debug, Default)]
pub enum Mnemonic {
    #[default]
    Invalid,
    NoOpcode,
    Group,
    Extension,
    Prefix,
    NOP,
    AAA,
    AAD,
    AAM,
    AAS,
    ADC,
    ADD,
    AND,
    CALL,
    CALLF,
    CBW,
    CLC,
    CLD,
    CLI,
    CMC,
    CMP,
    CMPSB,
    CMPSW,
    CMPSD,
    CWD,
    CDQ,
    CWDE,
    DAA,
    DAS,
    DEC,
    DIV,
    ESC,
    WAIT,
    HLT,
    IDIV,
    IMUL,
    IN,
    INC,
    INT,
    INT1,
    INT3,
    INTO,
    IRET,
    JB,
    JBE,
    JCXZ,
    JECXZ,
    JL,
    JLE,
    JMP,
    JMPF,
    JNB,
    JNBE,
    JNL,
    JNLE,
    JNO,
    JNP,
    JNS,
    JNZ,
    JO,
    JP,
    JS,
    JZ,
    LAHF,
    LDS,
    LEA,
    LES,
    LOCK,
    LODSB,
    LODSW,
    LODSD,
    LOOP,
    LOOPNE,
    LOOPE,
    MOV,
    MOVSB,
    MOVSW,
    MOVSD,
    MUL,
    NEG,
    NOT,
    OR,
    OUT,
    POP,
    POPF,
    POPFW,
    POPFD,
    PUSH,
    PUSHF,
    RCL,
    RCR,
    REP,
    REPNE,
    REPE,
    RETF,
    RET,
    RETW,
    RETD,
    ROL,
    ROR,
    SAHF,
    SALC,
    SAR,
    SBB,
    SCASB,
    SCASW,
    SCASD,
    SETMO,
    SETMOC,
    SHL,
    SHR,
    SAL,
    STC,
    STD,
    STI,
    STOSB,
    STOSW,
    STOSD,
    SUB,
    TEST,
    XCHG,
    XLAT,
    XOR,
    // 186 Instructions
    PUSHA,
    PUSHAW,
    PUSHAD,
    POPA,
    POPAW,
    POPAD,
    BOUND,
    INSB,
    INSW,
    INSD,
    OUTSB,
    OUTSW,
    OUTSD,
    ENTER,
    LEAVE,
    // V20 Instructions
    UNDEF,
    FPO2,
    TEST1,
    CLR1,
    SET1,
    NOT1,
    ADD4S,
    SUB4S,
    CMP4S,
    ROL4,
    ROR4,
    BINS,
    BEXT,
    BRKEM,
    // Extended 386 instructions
    ARPL,
    SLDT,
    STR,
    LLDT,
    LTR,
    VERR,
    VERW,
    SGDT,
    SIDT,
    LGDT,
    LIDT,
    SMSW,
    LMSW,
    LAR,
    LSL,
    CLTS,
    LOADALL,
    SETO,
    SETNO,
    SETB,
    SETNB,
    SETZ,
    SETNZ,
    SETBE,
    SETNBE,
    SETS,
    SETNS,
    SETP,
    SETNP,
    SETL,
    SETNL,
    SETLE,
    SETNLE,
    SHLD,
    SHRD,
    RSM,
    BT,
    BTC,
    BTS,
    BTR,
    BSF,
    BSR,
    LSS,
    LFS,
    LGS,
    MOVZX,
    MOVSX,
}

pub(crate) fn mnemonic_to_str(op: Mnemonic) -> &'static str {
    use Mnemonic::*;
    match op {
        NOP => "NOP",
        AAA => "AAA",
        AAD => "AAD",
        AAM => "AAM",
        AAS => "AAS",
        ADC => "ADC",
        ADD => "ADD",
        AND => "AND",
        CALL => "CALL",
        CALLF => "CALL",
        CBW => "CBW",
        CLC => "CLC",
        CLD => "CLD",
        CLI => "CLI",
        CMC => "CMC",
        CMP => "CMP",
        CMPSB => "CMPSB",
        CMPSW => "CMPSW",
        CMPSD => "CMPSD",
        CWD => "CWD",
        CDQ => "CDQ",
        CWDE => "CWDE",
        DAA => "DAA",
        DAS => "DAS",
        DEC => "DEC",
        DIV => "DIV",
        ESC => "ESC",
        WAIT => "WAIT",
        HLT => "HLT",
        IDIV => "IDIV",
        IMUL => "IMUL",
        IN => "IN",
        INC => "INC",
        INT => "INT",
        INT1 => "INT1",
        INT3 => "INT3",
        INTO => "INTO",
        IRET => "IRET",
        JB => "JB",
        JBE => "JBE",
        JCXZ => "JCXZ",
        JECXZ => "JECXZ",
        JL => "JL",
        JLE => "JLE",
        JMP => "JMP",
        JMPF => "JMP",
        JNB => "JNB",
        JNBE => "JNBE",
        JNL => "JNL",
        JNLE => "JNLE",
        JNO => "JNO",
        JNP => "JNP",
        JNS => "JNS",
        JNZ => "JNZ",
        JO => "JO",
        JP => "JP",
        JS => "JS",
        JZ => "JZ",
        LAHF => "LAHF",
        LDS => "LDS",
        LEA => "LEA",
        LES => "LES",
        LOCK => "LOCK",
        LODSB => "LODSB",
        LODSW => "LODSW",
        LODSD => "LODSD",
        LOOP => "LOOP",
        LOOPNE => "LOOPNE",
        LOOPE => "LOOPE",
        MOV => "MOV",
        MOVSB => "MOVSB",
        MOVSW => "MOVSW",
        MOVSD => "MOVSD",
        MUL => "MUL",
        NEG => "NEG",
        NOT => "NOT",
        OR => "OR",
        OUT => "OUT",
        POP => "POP",
        POPF => "POPF",
        POPFW => "POPFW",
        POPFD => "POPFD",
        PUSH => "PUSH",
        PUSHF => "PUSHF",
        RCL => "RCL",
        RCR => "RCR",
        REP => "REP",
        REPNE => "REPNE",
        REPE => "REPE",
        RETF => "RETF",
        RET => "RET",
        RETW => "RETW",
        RETD => "RETD",
        ROL => "ROL",
        ROR => "ROR",
        SAHF => "SAHF",
        SALC => "SALC",
        SAR => "SAR",
        SBB => "SBB",
        SCASB => "SCASB",
        SCASW => "SCASW",
        SCASD => "SCASD",
        SETMO => "SETMO",
        SETMOC => "SETMOC",
        SHL => "SHL",
        SHR => "SHR",
        SAL => "SAL",
        STC => "STC",
        STD => "STD",
        STI => "STI",
        STOSB => "STOSB",
        STOSW => "STOSW",
        STOSD => "STOSD",
        SUB => "SUB",
        TEST => "TEST",
        XCHG => "XCHG",
        XLAT => "XLATB",
        XOR => "XOR",
        // 186+ Instructions
        PUSHA => "PUSHA",
        PUSHAW => "PUSHAW",
        PUSHAD => "PUSHAD",
        POPA => "POPA",
        POPAW => "POPAW",
        POPAD => "POPAD",
        BOUND => "BOUND",
        INSB => "INSB",
        INSW => "INSW",
        INSD => "INSD",
        OUTSB => "OUTSB",
        OUTSW => "OUTSW",
        OUTSD => "OUTSD",
        ENTER => "ENTER",
        LEAVE => "LEAVE",
        // V20 instructions
        FPO2 => "FPO2",
        TEST1 => "TEST1",
        CLR1 => "CLR1",
        SET1 => "SET1",
        NOT1 => "NOT1",
        ADD4S => "ADD4S",
        SUB4S => "SUB4S",
        CMP4S => "CMP4S",
        ROL4 => "ROL4",
        ROR4 => "ROR4",
        BINS => "BINS",
        BEXT => "BEXT",
        BRKEM => "BRKEM",
        // 386+ Instructions
        ARPL => "ARPL",
        SLDT => "SLDT",
        STR => "STR",
        LLDT => "LLDT",
        LTR => "LTR",
        VERR => "VERR",
        VERW => "VERW",
        SGDT => "SGDT",
        SIDT => "SIDT",
        LGDT => "LGDT",
        LIDT => "LIDT",
        SMSW => "SMSW",
        LMSW => "LMSW",
        LAR => "LAR",
        LSL => "LSL",
        CLTS => "CLTS",
        LOADALL => "LOADALL",
        SETO => "SETO",
        SETNO => "SETNO",
        SETB => "SETB",
        SETNB => "SETNB",
        SETZ => "SETZ",
        SETNZ => "SETNZ",
        SETBE => "SETBE",
        SETNBE => "SETNBE",
        SETS => "SETS",
        SETNS => "SETNS",
        SETP => "SETP",
        SETNP => "SETNP",
        SETL => "SETL",
        SETNL => "SETNL",
        SETLE => "SETLE",
        SETNLE => "SETNLE",
        SHLD => "SHLD",
        SHRD => "SHRD",
        RSM => "RSM",
        BT => "BT",
        BTC => "BTC",
        BTS => "BTS",
        BTR => "BTR",
        BSF => "BSF",
        BSR => "BSR",
        LSS => "LSS",
        LFS => "LFS",
        LGS => "LGS",
        MOVZX => "MOVZX",
        MOVSX => "MOVSX",
        _ => "INVALID",
    }
}

impl fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", mnemonic_to_str(*self))
    }
}

impl Mnemonic {
    pub fn is_string_op(&self) -> bool {
        match self {
            Mnemonic::MOVSB
            | Mnemonic::MOVSW
            | Mnemonic::MOVSD
            | Mnemonic::CMPSB
            | Mnemonic::CMPSW
            | Mnemonic::CMPSD
            | Mnemonic::SCASB
            | Mnemonic::SCASW
            | Mnemonic::SCASD
            | Mnemonic::LODSB
            | Mnemonic::LODSW
            | Mnemonic::LODSD
            | Mnemonic::STOSB
            | Mnemonic::STOSW
            | Mnemonic::STOSD
            | Mnemonic::INSB
            | Mnemonic::INSW
            | Mnemonic::INSD
            | Mnemonic::OUTSB
            | Mnemonic::OUTSW
            | Mnemonic::OUTSD => true,
            _ => false,
        }
    }

    pub fn is_stos(&self) -> bool {
        match self {
            Mnemonic::STOSB | Mnemonic::STOSW | Mnemonic::STOSD => true,
            _ => false,
        }
    }

    pub fn is_scas(&self) -> bool {
        match self {
            Mnemonic::SCASB | Mnemonic::SCASW | Mnemonic::SCASD => true,
            _ => false,
        }
    }

    pub fn is_ins(&self) -> bool {
        match self {
            Mnemonic::INSB | Mnemonic::INSW | Mnemonic::INSD => true,
            _ => false,
        }
    }

    pub fn is_jump(&self) -> bool {
        match self {
            Mnemonic::JO
            | Mnemonic::JNO
            | Mnemonic::JB
            | Mnemonic::JNB
            | Mnemonic::JZ
            | Mnemonic::JNZ
            | Mnemonic::JBE
            | Mnemonic::JNBE
            | Mnemonic::JS
            | Mnemonic::JNS
            | Mnemonic::JP
            | Mnemonic::JNP
            | Mnemonic::JL
            | Mnemonic::JNL
            | Mnemonic::JLE
            | Mnemonic::JNLE
            | Mnemonic::JCXZ
            | Mnemonic::JECXZ
            | Mnemonic::JMP
            | Mnemonic::JMPF => true,
            _ => false,
        }
    }

    pub fn is_far(&self) -> bool {
        match self {
            Mnemonic::JMPF | Mnemonic::CALLF => true,
            _ => false,
        }
    }

    pub fn is_call(&self) -> bool {
        match self {
            Mnemonic::CALL | Mnemonic::CALLF => true,
            _ => false,
        }
    }

    /// Convert a word-sized mnemonic to its dword equivalent.
    pub fn wide_o32(&self) -> Mnemonic {
        match self {
            Mnemonic::CBW => Mnemonic::CWDE,
            Mnemonic::CWD => Mnemonic::CDQ,
            Mnemonic::STOSW => Mnemonic::STOSD,
            Mnemonic::MOVSW => Mnemonic::MOVSD,
            Mnemonic::LODSW => Mnemonic::LODSD,
            Mnemonic::SCASW => Mnemonic::SCASD,
            Mnemonic::CMPSW => Mnemonic::CMPSD,
            Mnemonic::INSW => Mnemonic::INSD,
            Mnemonic::OUTSW => Mnemonic::OUTSD,
            Mnemonic::JCXZ => Mnemonic::JECXZ,
            _ => *self,
        }
    }

    pub fn wide_a32(&self) -> Mnemonic {
        match self {
            Mnemonic::NOP => Mnemonic::XCHG,
            Mnemonic::JCXZ => Mnemonic::JECXZ,
            //Mnemonic::RET => Mnemonic::RETW,
            _ => *self,
        }
    }

    pub fn operand_size_override(&self, op_size: OperandSize) -> Mnemonic {
        match (self, op_size) {
            (Mnemonic::RET, OperandSize::Operand16) => Mnemonic::RETW,
            (Mnemonic::RET, OperandSize::Operand32) => Mnemonic::RETD,
            (Mnemonic::PUSHA, OperandSize::Operand16) => Mnemonic::PUSHAW,
            (Mnemonic::PUSHA, OperandSize::Operand32) => Mnemonic::PUSHAD,
            (Mnemonic::POPA, OperandSize::Operand16) => Mnemonic::POPAW,
            (Mnemonic::POPA, OperandSize::Operand32) => Mnemonic::POPAD,
            (Mnemonic::POPF, OperandSize::Operand16) => Mnemonic::POPFW,
            (Mnemonic::POPF, OperandSize::Operand32) => Mnemonic::POPFD,
            _ => *self,
        }
    }

    pub fn to_str(&self) -> &'static str {
        mnemonic_to_str(*self)
    }

    pub fn to_iced_str(&self) -> Option<&'static str> {
        match self {
            Mnemonic::JNL => Some("JGE"),
            Mnemonic::JNLE => Some("JG"),
            Mnemonic::JNB => Some("JAE"),
            Mnemonic::JNBE => Some("JA"),
            Mnemonic::JZ => Some("JE"),
            Mnemonic::JNZ => Some("JNE"),
            Mnemonic::SETZ => Some("SETE"),
            Mnemonic::SETNZ => Some("SETNE"),
            Mnemonic::SETNL => Some("SETGE"),
            Mnemonic::SETNLE => Some("SETG"),
            Mnemonic::SETNBE => Some("SETA"),
            Mnemonic::SETNB => Some("SETAE"),

            //Mnemonic::JCXZ => Some("JECXZ"),
            _ => None,
        }
    }

    #[inline]
    pub fn disambiguate_operand_size(&self) -> bool {
        use Mnemonic::*;
        match self {
            PUSH | LOCK | POP | JO | JNO | JB | JNB | JZ | JNZ | JBE | JNBE | JS | JNS | JP | JNP | JL | JNL | JLE
            | JNLE | ENTER | LEAVE | LOOPNE | LOOPE | LOOP | JCXZ | JECXZ | JMP | LMSW | LIDT => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_push(&self) -> bool {
        match self {
            Mnemonic::PUSH => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_pop(&self) -> bool {
        match self {
            Mnemonic::POP => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_push_or_pop(&self) -> bool {
        self.is_push() || self.is_pop()
    }

    #[inline]
    pub fn is_loop(&self) -> bool {
        match self {
            Mnemonic::LOOP | Mnemonic::LOOPE | Mnemonic::LOOPNE => true,
            _ => false,
        }
    }

    pub fn rep1_prefix(&self) -> &str {
        match self {
            Mnemonic::MOVSB
            | Mnemonic::MOVSW
            | Mnemonic::MOVSD
            | Mnemonic::CMPSB
            | Mnemonic::CMPSW
            | Mnemonic::CMPSD
            | Mnemonic::SCASB
            | Mnemonic::SCASW
            | Mnemonic::SCASD
            | Mnemonic::LODSB
            | Mnemonic::LODSW
            | Mnemonic::LODSD
            | Mnemonic::STOSB
            | Mnemonic::STOSW
            | Mnemonic::STOSD
            | Mnemonic::INSB
            | Mnemonic::INSW
            | Mnemonic::INSD
            | Mnemonic::OUTSB
            | Mnemonic::OUTSW
            | Mnemonic::OUTSD => "repne",
            _ => "rep",
        }
    }

    pub fn rep2_prefix(&self) -> &str {
        match self {
            Mnemonic::CMPSB
            | Mnemonic::CMPSW
            | Mnemonic::CMPSD
            | Mnemonic::SCASB
            | Mnemonic::SCASW
            | Mnemonic::SCASD => "repe",
            Mnemonic::MOVSB
            | Mnemonic::MOVSW
            | Mnemonic::MOVSD
            | Mnemonic::LODSB
            | Mnemonic::LODSW
            | Mnemonic::LODSD => "rep",
            _ => "rep",
        }
    }
}
