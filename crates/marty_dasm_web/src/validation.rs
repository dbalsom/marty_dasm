// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Daniel Balsom

pub(crate) fn is_valid_cpu(value: &str) -> bool {
    matches!(value, "intel808x" | "necvx0" | "intel80286" | "intel80386")
}

pub(crate) fn is_valid_fpu(value: &str) -> bool {
    matches!(
        value,
        "disabled" | "intel8087" | "intel80287" | "intel80287xl" | "intel80387"
    )
}

pub(crate) fn is_valid_segment_size(value: &str) -> bool {
    matches!(value, "16" | "32")
}

pub(crate) fn is_valid_offset(value: &str) -> bool {
    value.len() <= 8 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn parse_query_flag(value: &str) -> Option<bool> {
    match value {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_fpu_values() {
        for value in ["disabled", "intel8087", "intel80287", "intel80287xl", "intel80387"] {
            assert!(is_valid_fpu(value));
        }
        for value in ["", "auto", "intel80286", "intel80487", "Intel80387"] {
            assert!(!is_valid_fpu(value));
        }
    }

    #[test]
    fn validates_cpu_values() {
        for value in ["intel808x", "necvx0", "intel80286", "intel80386"] {
            assert!(is_valid_cpu(value));
        }
        for value in ["", "POTATO", "Intel80386"] {
            assert!(!is_valid_cpu(value));
        }
    }

    #[test]
    fn validates_segment_sizes() {
        assert!(is_valid_segment_size("16"));
        assert!(is_valid_segment_size("32"));
        assert!(!is_valid_segment_size("64"));
        assert!(!is_valid_segment_size("POTATO"));
    }

    #[test]
    fn validates_offsets() {
        for value in ["", "0", "deadBEEF", "FFFFFFFF"] {
            assert!(is_valid_offset(value));
        }
        for value in ["100000000", "POTATO", "12 34", "🐸"] {
            assert!(!is_valid_offset(value));
        }
    }

    #[test]
    fn parses_query_flags_strictly() {
        assert_eq!(parse_query_flag("0"), Some(false));
        assert_eq!(parse_query_flag("1"), Some(true));
        assert_eq!(parse_query_flag("true"), None);
        assert_eq!(parse_query_flag("POTATO"), None);
        assert_eq!(parse_query_flag(""), None);
    }
}
