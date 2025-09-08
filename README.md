# marty_dasm
A retro disassembler for the 8088, 8086, V20, V30, 80286 and 80386

[iced-x86](https://github.com/icedland/iced) is an excellent disassembler for the x86 ISA.

Its main drawback at least for retro developers is that other than a general 'bitness' toggle it cannot disassemble instructions from the perspective of a specific CPU architecture.

While developing MartyPC, I noticed that iced didn't handle a number of undocumented or aliased instructions on the 8088. 

This crate will leverage MartyPC's internal disassembler for the 8088 and V20, and expand upon it for support of the 286 and 386. 

When specifying a CPU type as part of a disassembly context, marty_dasm will produce output that should exactly match what that specific CPU would decode. For the 8088 this may include several 'impossible' instruction forms that traditional disassemblers would never emit and traditional assemblers would refuse to encoode.

This project is still in the design phase.
