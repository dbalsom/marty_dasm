// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Daniel Balsom

use std::io::{Read, Write};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use flate2::{read::GzDecoder, Compression, GzBuilder};

pub(crate) const MIN_HEX_LENGTH_FOR_COMPRESSION: usize = 64;
const MAX_DECOMPRESSED_INPUT_SIZE: usize = 1024 * 1024;

pub(crate) fn compress_input(input: &str) -> Result<String, String> {
    let mut encoder = GzBuilder::new().mtime(0).write(Vec::new(), Compression::default());
    encoder
        .write_all(input.as_bytes())
        .map_err(|error| format!("Could not compress the shared input: {error}"))?;
    let compressed = encoder
        .finish()
        .map_err(|error| format!("Could not finish compressing the shared input: {error}"))?;
    Ok(URL_SAFE_NO_PAD.encode(compressed))
}

pub(crate) fn may_compress_input(input: &str) -> bool {
    input.len() >= MIN_HEX_LENGTH_FOR_COMPRESSION
}

pub(crate) fn decompress_input(encoded: &str) -> Result<String, String> {
    let compressed = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| "The compressed input in this link is not valid Base64URL data.".to_owned())?;
    let decoder = GzDecoder::new(compressed.as_slice());
    let mut limited = decoder.take((MAX_DECOMPRESSED_INPUT_SIZE + 1) as u64);
    let mut decoded = Vec::new();
    limited
        .read_to_end(&mut decoded)
        .map_err(|_| "The compressed input in this link is not valid gzip data.".to_owned())?;

    if decoded.len() > MAX_DECOMPRESSED_INPUT_SIZE {
        return Err("The compressed input in this link expands beyond the 1 MiB limit.".to_owned());
    }

    String::from_utf8(decoded).map_err(|_| "The compressed input in this link is not valid UTF-8 text.".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressed_input_preserves_whitespace_and_invalid_hex() {
        let input = "  B8 34 12\n\nnot hex\t; comment  ";
        let encoded = compress_input(input).unwrap();
        assert_eq!(decompress_input(&encoded), Ok(input.to_owned()));
    }

    #[test]
    fn compressed_input_is_deterministic() {
        let input = "90 ".repeat(100);
        assert_eq!(compress_input(&input), compress_input(&input));
    }

    #[test]
    fn compression_starts_at_the_64_byte_boundary() {
        assert!(!may_compress_input(&"0".repeat(MIN_HEX_LENGTH_FOR_COMPRESSION - 1)));
        assert!(may_compress_input(&"0".repeat(MIN_HEX_LENGTH_FOR_COMPRESSION)));
    }

    #[test]
    fn rejects_compressed_input_beyond_one_mibibyte() {
        let input = "0".repeat(MAX_DECOMPRESSED_INPUT_SIZE + 1);
        let encoded = compress_input(&input).unwrap();
        assert!(decompress_input(&encoded).unwrap_err().contains("1 MiB limit"));
    }
}
