# Changelog

## 1.1.0 - 2026-11-07

### Added

- Add x87 disassembly with independent math coprocessor selection
- Add Intel 80286

## 1.0.3 - 2026-08-06

### Changed

- Refactored app logic
- Updated `marty_dasm` to version 0.3.5
- Display the parsed byte count and MD5 hash beneath the machine-code input.
- Optionally expand non-ASCII Unicode input into its UTF-8 byte representation.
- Add button to compact parsed input into contiguous uppercase hexadecimal
- Reuse a persistent decoder while disassembling, with byte-wise seeking for error recovery.

## 1.0.2 - 2026-08-05

### Changed

- Added a button to copy the hex input exactly as entered.
- Added a byte count alongside the disassembled instruction count.
- Added a header button to copy the current shareable disassembly link.
- Updated `marty_dasm` to version 0.3.4
- Added visual pressed state feedback to buttons
- Treat semicolons in hex input as end-of-line comment delimiters instead of byte separators.

### Fixed

- Preserved the last valid disassembly while a hexadecimal byte is incomplete.
- Replaced low-level truncated-instruction errors with `Unexpected EOF`.
- Prevented LocalStorage values from being restored when the corresponding query parameter is present.

## 1.0.1 - 2026-08-04

### Changed

- Mobile: drop bytes column below mobile page width.

## 1.0.0 - 2026-08-04

Initial release.
