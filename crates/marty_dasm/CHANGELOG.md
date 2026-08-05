# Changelog

## 0.3.4 - 2026-08-05

### Added

- Add the undocumented 80386 `UMOV` instruction (`0F 10` through `0F 13`).

## 0.3.3 - 2026-08-04

### Fixed

- Preserve full 32-bit addresses when formatting relative branch targets in 32-bit segments.

## 0.3.2 - 2026-08-04

### Fixed

- Select the correct operand size when decoding 8088 and V20 instructions, fixing relative branch formatting.

## 0.3.1 - 2026-08-04

### Fixed

- Correct the 80386 `LOADALL` and `CLTS` instruction lengths.

## 0.3.0 - 2025-07-23

Initial release.
