// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Daniel Balsom

use wasm_bindgen::{closure::Closure, JsCast, JsValue};
use web_sys::{HtmlInputElement, HtmlSelectElement, HtmlTextAreaElement, ResizeObserver, Storage};

const THEME_STORAGE_KEY: &str = "marty-theme";
const CPU_STORAGE_KEY: &str = "marty-cpu";
const SEGMENT_SIZE_STORAGE_KEY: &str = "marty-segment-size";
const OFFSET_STORAGE_KEY: &str = "marty-offset";
const HEX_INPUT_STORAGE_KEY: &str = "marty-hex-input";
const HEX_INPUT_HEIGHT_STORAGE_KEY: &str = "marty-hex-input-height";
const COPY_OFFSETS_STORAGE_KEY: &str = "marty-copy-offsets";
const COPY_BYTES_STORAGE_KEY: &str = "marty-copy-bytes";
const MIN_SAVED_INPUT_HEIGHT: i32 = 64;
const MAX_SAVED_INPUT_HEIGHT: i32 = 4096;

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
) {
    let Some(storage) = storage
    else {
        return;
    };

    if let Ok(Some(value)) = storage.get_item(CPU_STORAGE_KEY) {
        if matches!(value.as_str(), "intel808x" | "necvx0" | "intel80386") {
            cpu.set_value(&value);
        }
    }
    if let Ok(Some(value)) = storage.get_item(SEGMENT_SIZE_STORAGE_KEY) {
        if matches!(value.as_str(), "16" | "32") {
            segment_size.set_value(&value);
        }
    }
    if let Ok(Some(value)) = storage.get_item(HEX_INPUT_STORAGE_KEY) {
        input.set_value(&value);
    }
    if let Ok(Some(value)) = storage.get_item(OFFSET_STORAGE_KEY) {
        if value.len() <= 8 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            offset.set_value(&value);
        }
    }
}

pub(crate) fn persist_disassembly_state(
    storage: Option<&Storage>,
    input: &HtmlTextAreaElement,
    cpu: &HtmlSelectElement,
    segment_size: &HtmlSelectElement,
    offset: &HtmlInputElement,
) {
    let Some(storage) = storage
    else {
        return;
    };

    let _ = storage.set_item(CPU_STORAGE_KEY, &cpu.value());
    let _ = storage.set_item(SEGMENT_SIZE_STORAGE_KEY, &segment_size.value());
    let _ = storage.set_item(HEX_INPUT_STORAGE_KEY, &input.value());
    let _ = storage.set_item(OFFSET_STORAGE_KEY, &offset.value());
}

pub(crate) fn restore_copy_preferences(
    storage: Option<&Storage>,
    copy_offsets: &HtmlInputElement,
    copy_bytes: &HtmlInputElement,
) {
    let Some(storage) = storage
    else {
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
    let Some(storage) = storage
    else {
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
    let Some(storage) = storage
    else {
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
