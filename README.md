# marty_dasm
A retro disassembler for the 8088, 8086, V20, V30, 80286 and 80386

## Rationale

[iced-x86](https://github.com/icedland/iced) is an excellent disassembler for the x86 ISA.

Its main drawback at least for retro developers is that other than a general 'bitness' toggle it cannot disassemble instructions from the perspective of a specific CPU architecture.

While developing MartyPC, I noticed that iced didn't handle a number of undocumented or aliased instructions on the 8088. 

This crate will leverage MartyPC's internal disassembler for the 8088 and V20, and expand upon it for support of the 286 and 386. It is heavily influenced by iced-x86's design.

When specifying a CPU type as part of a disassembly context, marty_dasm will produce output that should exactly match what that specific CPU would decode. For the 8088 this may include several 'impossible' instruction forms that traditional disassemblers would never emit and traditional assemblers would refuse to encode.

## Math Coprocessor Support

`marty_dasm` 0.4.0 adds support for decoding the x87 ISA.

FPU instruction decoding is implemented as a decoration pass on a decoded `ESC` instruction from one of the fixed CPU decoders, that call a shared `i80X87` decoder.

The `i80X87` decoder supports the 8087, 80287, 80287XL and 80387 FPUs. When decoding, select the desired FPU with `DecoderOptions::fpu`. A list of compatible FPUs can be returned from  `CpuType::compatible_fpus()`.

For example, a 386 can decode for either a 287 or a 387, and a 286 with a 287XL can decode the 387 instruction set.

`DecoderOptions::fpu` is an `Option<FpuType>`: select `Some(FpuType::Intel80387)`, for example, to enable x87 decoding. The default, `None`, preserves generic `ESC` output; no FPU is selected automatically. CPU-accepted encodings unknown to the selected FPU also retain  `ESC`. Incompatible CPU/FPU options return `InvalidOptions`.



## Web interface

A web interface to marty_dasm can be accessed at [https://dasm.martypc.net/](https://dasm.martypc.net/)
