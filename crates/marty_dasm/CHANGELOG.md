# Changelog

## 0.4.0 - 2026-11-07

### Added

#### x87 Support

- `CpuType::compatible_fpus()` and `is_fpu_compatible()`, with CPU/FPU option validation before decoding consumes bytes.
- Shared `i80X87` decoding for 8087, 80287, 80287XL and 80387, with independent `DecoderOptions::fpu` selection, `Some(FpuType)` for a specific coprocessor and `None` (the default) for generic ESC decoding.

#### 286 ISA Support

- Decoder: Implement Intel 80286 decoding, including protected-mode instructions, `LOADALL` (`0F 05`), and `STOREALL` (`0F 04`, including the `F1` ICE prefix).

### Fixed

- Fixed 386 address-size overrides for ESC instructions and coprocessor environment/save layout selection.
- Fixed 'repc' and 'repnc' prefixes on VX0

## 0.3.5 - 2026-08-06

### Added

- Decoder: Add byte-position reporting, EOF detection, and repositioning for seekable input streams.
- Decoder: Distinguish expected end-of-input from an instruction truncated by unexpected EOF.

### Fixed

- Decoder: Fix mistakenly carried-over uses of peek_* methods

## 0.3.4 - 2026-08-05

### Added

- Decoder: Add the undocumented 80386 `UMOV` instruction (`0F 10` through `0F 13`).
- Decoder: Add the 80386 test-register `MOV` instructions (`0F 24` and `0F 26`) with `TR4` through `TR7`.
- Decoder: Add the 80386 `UD2` (`0F 0B`), `UD1` (`0F B9`), and `UD0` (`0F FF`) instructions as operandless two-byte forms.

### Fixed

- Decoder: Correct `SMSW` and `SLDT` register widths.
- Decoder: Correct `LAR` and `LSL` operand widths in 16-bit and 32-bit segments.
- Decoder: Prevent spurious `nop` decoding for `(bad)` decode output.
- NASM: Preserve operand-size prefixes on memory forms of segment-register `MOV` with `o16`/`o32` notation.
- NASM: Preserve ignored operand-size prefixes on `LMSW`, `LLDT`, `LTR`, `VERR`, and `VERW` with `o16`/`o32` notation.
- NASM: Preserve operand-size prefixes on `ENTER` and `LEAVE` with `o16`/`o32` notation.
- NASM: Resolve the 32-bit operand-size override mnemonic for `RETFD`.
- NASM: Show the address-size-selected `CX` or `ECX` counter for overridden `LOOP` instructions.
- NASM: Select `JCXZ` or `JECXZ` by address size independently of operand-size overrides.
- NASM: Resolve operand-size mnemonic overrides for `POPA`.

## 0.3.3 - 2026-08-04

### Fixed

- NASM: Preserve full 32-bit addresses when formatting relative branch targets in 32-bit segments.

## 0.3.2 - 2026-08-04

### Fixed

- Decoder: Select the correct operand size when decoding 8088 and V20 instructions, fixing relative branch formatting.

## 0.3.1 - 2026-08-04

### Fixed

- Decoder: Correct the 80386 `LOADALL` and `CLTS` instruction lengths.
## 0.3.0 - 2025-07-23

Initial release.
