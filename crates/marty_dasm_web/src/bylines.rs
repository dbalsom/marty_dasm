// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Daniel Balsom

use wasm_bindgen::{JsCast, JsValue};
use web_sys::{Document, HtmlElement, Window};

const BYLINES: &[&str] = &[
    "You wouldn't disassemble a car.",
    "You wouldn't disassemble a cow.",
    "Your IDA Pro subscription has lapsed.",
    "Is that a boot sector?",
    "Ask me about MartyPC.",
    "Nice ModR/M byte, nerd.",
    "POP CS is the best instruction.",
    "NO DISASSEMBLE #5!",
    "You're not violating the DMCA are you?",
    "That can't be right, surely?",
    "Lost in the code forest again.",
    "Not written by the NSA.",
    "The only disassembler with Emoji support.",
];

pub(crate) fn set_random_byline(window: &Window, document: &Document) -> Result<(), JsValue> {
    let mut random_value = [0u8];
    let index = window
        .crypto()
        .and_then(|crypto| crypto.get_random_values_with_u8_array(&mut random_value))
        .map(|_| random_value[0] as usize % BYLINES.len())
        .unwrap_or(0);
    let byline = document
        .get_element_by_id("random-byline")
        .ok_or("missing #random-byline")?
        .dyn_into::<HtmlElement>()
        .map_err(|_| JsValue::from_str("#random-byline has an unexpected element type"))?;
    byline.set_text_content(Some(BYLINES[index]));
    Ok(())
}
