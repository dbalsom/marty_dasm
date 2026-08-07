// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Daniel Balsom

use wasm_bindgen::{closure::Closure, JsCast, JsValue};
use web_sys::{HtmlInputElement, HtmlSelectElement, HtmlTextAreaElement, ResizeObserver, Storage};

use crate::validation::{is_valid_cpu, is_valid_offset, is_valid_segment_size};

const THEME_STORAGE_KEY: &str = "marty-theme";
const CPU_STORAGE_KEY: &str = "marty-cpu";
const SEGMENT_SIZE_STORAGE_KEY: &str = "marty-segment-size";
const OFFSET_STORAGE_KEY: &str = "marty-offset";
const HEX_INPUT_STORAGE_KEY: &str = "marty-hex-input";
const EXPAND_UNICODE_STORAGE_KEY: &str = "marty-expand-unicode";
const COMPACT_URL_STORAGE_KEY: &str = "marty-compact-url";
const HEX_INPUT_HEIGHT_STORAGE_KEY: &str = "marty-hex-input-height";
const COPY_OFFSETS_STORAGE_KEY: &str = "marty-copy-offsets";
const COPY_BYTES_STORAGE_KEY: &str = "marty-copy-bytes";
const MIN_SAVED_INPUT_HEIGHT: i32 = 64;
const MAX_SAVED_INPUT_HEIGHT: i32 = 4096;

pub(crate) struct RestoreDisassemblyStateOptions {
    pub(crate) input: bool,
    pub(crate) cpu: bool,
    pub(crate) segment_size: bool,
    pub(crate) offset: bool,
    pub(crate) expand_unicode: bool,
    pub(crate) compact_url: bool,
}

pub(crate) fn restore_theme(storage: Option<&Storage>) -> Option<String> {
    storage
        .and_then(|storage| storage.get_item(THEME_STORAGE_KEY).ok().flatten())
        .filter(|theme| theme == "light" || theme == "dark")
}

pub(crate) fn persist_theme(storage: Option<&Storage>, theme: &str) {
    if let Some(storage) = storage {
        let _ = storage.set_item(THEME_STORAGE_KEY, theme);
    }
}

pub(crate) fn restore_disassembly_state(
    storage: Option<&Storage>,
    input: &HtmlTextAreaElement,
    cpu: &HtmlSelectElement,
    segment_size: &HtmlSelectElement,
    offset: &HtmlInputElement,
    expand_unicode: &HtmlInputElement,
    compact_url: &HtmlInputElement,
    options: RestoreDisassemblyStateOptions,
) {
    let Some(storage) = storage else {
        return;
    };

    if options.cpu {
        if let Ok(Some(value)) = storage.get_item(CPU_STORAGE_KEY) {
            if is_valid_cpu(&value) {
                cpu.set_value(&value);
            }
        }
    }
    if options.segment_size {
        if let Ok(Some(value)) = storage.get_item(SEGMENT_SIZE_STORAGE_KEY) {
            if is_valid_segment_size(&value) {
                segment_size.set_value(&value);
            }
        }
    }
    if options.input {
        if let Ok(Some(value)) = storage.get_item(HEX_INPUT_STORAGE_KEY) {
            input.set_value(&value);
        }
    }
    if options.offset {
        if let Ok(Some(value)) = storage.get_item(OFFSET_STORAGE_KEY) {
            if is_valid_offset(&value) {
                offset.set_value(&value.to_ascii_uppercase());
            }
        }
    }
    if options.expand_unicode {
        if let Ok(Some(value)) = storage.get_item(EXPAND_UNICODE_STORAGE_KEY) {
            if matches!(value.as_str(), "true" | "false") {
                expand_unicode.set_checked(value == "true");
            }
        }
    }
    if options.compact_url {
        if let Ok(Some(value)) = storage.get_item(COMPACT_URL_STORAGE_KEY) {
            if matches!(value.as_str(), "true" | "false") {
                compact_url.set_checked(value == "true");
            }
        }
    }
}

pub(crate) fn persist_disassembly_state(
    storage: Option<&Storage>,
    input: &HtmlTextAreaElement,
    cpu: &HtmlSelectElement,
    segment_size: &HtmlSelectElement,
    offset: &HtmlInputElement,
    expand_unicode: &HtmlInputElement,
    compact_url: &HtmlInputElement,
) {
    let Some(storage) = storage else {
        return;
    };

    let _ = storage.set_item(CPU_STORAGE_KEY, &cpu.value());
    let _ = storage.set_item(SEGMENT_SIZE_STORAGE_KEY, &segment_size.value());
    let _ = storage.set_item(HEX_INPUT_STORAGE_KEY, &input.value());
    let _ = storage.set_item(OFFSET_STORAGE_KEY, &offset.value());
    let _ = storage.set_item(
        EXPAND_UNICODE_STORAGE_KEY,
        if expand_unicode.checked() { "true" } else { "false" },
    );
    let _ = storage.set_item(
        COMPACT_URL_STORAGE_KEY,
        if compact_url.checked() { "true" } else { "false" },
    );
}

pub(crate) fn restore_copy_preferences(
    storage: Option<&Storage>,
    copy_offsets: &HtmlInputElement,
    copy_bytes: &HtmlInputElement,
) {
    let Some(storage) = storage else {
        return;
    };

    if let Ok(Some(value)) = storage.get_item(COPY_OFFSETS_STORAGE_KEY) {
        if matches!(value.as_str(), "true" | "false") {
            copy_offsets.set_checked(value == "true");
        }
    }
    if let Ok(Some(value)) = storage.get_item(COPY_BYTES_STORAGE_KEY) {
        if matches!(value.as_str(), "true" | "false") {
            copy_bytes.set_checked(value == "true");
        }
    }
}

pub(crate) fn persist_copy_preferences(
    storage: Option<&Storage>,
    copy_offsets: &HtmlInputElement,
    copy_bytes: &HtmlInputElement,
) {
    let Some(storage) = storage else {
        return;
    };

    let _ = storage.set_item(
        COPY_OFFSETS_STORAGE_KEY,
        if copy_offsets.checked() { "true" } else { "false" },
    );
    let _ = storage.set_item(
        COPY_BYTES_STORAGE_KEY,
        if copy_bytes.checked() { "true" } else { "false" },
    );
}

pub(crate) fn restore_input_height(storage: Option<&Storage>, input: &HtmlTextAreaElement) {
    let Some(storage) = storage else {
        return;
    };
    let height = storage
        .get_item(HEX_INPUT_HEIGHT_STORAGE_KEY)
        .ok()
        .flatten()
        .and_then(|value| value.parse::<i32>().ok())
        .filter(|height| (MIN_SAVED_INPUT_HEIGHT..=MAX_SAVED_INPUT_HEIGHT).contains(height));
    if let Some(height) = height {
        let _ = input.style().set_property("height", &format!("{height}px"));
    }
}

pub(crate) fn observe_input_height(storage: Option<Storage>, input: &HtmlTextAreaElement) -> Result<(), JsValue> {
    let observed_input = input.clone();
    let observer_callback = Closure::<dyn FnMut()>::new(move || {
        persist_input_height(storage.as_ref(), &observed_input);
    });
    let observer = ResizeObserver::new(observer_callback.as_ref().unchecked_ref())?;
    observer.observe(input);

    observer_callback.forget();
    std::mem::forget(observer);
    Ok(())
}

pub(crate) fn persist_input_height(storage: Option<&Storage>, input: &HtmlTextAreaElement) {
    if let Some(storage) = storage {
        let _ = storage.set_item(HEX_INPUT_HEIGHT_STORAGE_KEY, &input.offset_height().to_string());
    }
}
