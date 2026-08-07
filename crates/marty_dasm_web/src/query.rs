// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Daniel Balsom

use crate::compression::{compress_input, decompress_input, may_compress_input};
use crate::disassembly::compact_url_input;
use crate::validation::{is_valid_cpu, is_valid_offset, is_valid_segment_size, parse_query_flag};
use wasm_bindgen::JsValue;
use web_sys::{HtmlInputElement, HtmlSelectElement, HtmlTextAreaElement, Location, UrlSearchParams, Window};

#[derive(Clone, Copy)]
pub(crate) struct QueryOverrides {
    pub(crate) input: bool,
    pub(crate) cpu: bool,
    pub(crate) segment_size: bool,
    pub(crate) offset: bool,
    pub(crate) expand_unicode: bool,
    pub(crate) compact_url: bool,
}

pub(crate) struct QueryState {
    params: UrlSearchParams,
}

impl QueryState {
    pub(crate) fn from_window(window: &Window) -> Result<Self, JsValue> {
        Ok(Self {
            params: UrlSearchParams::new_with_str(&window.location().search()?)?,
        })
    }

    pub(crate) fn is_raw_requested(&self) -> bool {
        self.params
            .get("raw")
            .as_deref()
            .and_then(parse_query_flag)
            .unwrap_or(false)
    }

    pub(crate) fn overrides(&self) -> QueryOverrides {
        QueryOverrides {
            input: self.params.get("hex").is_some() || self.params.get("hex_gz").is_some(),
            cpu: self.cpu().is_some(),
            segment_size: self.segment_size().is_some(),
            offset: self.offset().is_some(),
            expand_unicode: self.expand_unicode().is_some(),
            compact_url: self.compact_url().is_some(),
        }
    }

    pub(crate) fn restore(
        &self,
        input: &HtmlTextAreaElement,
        cpu: &HtmlSelectElement,
        segment_size: &HtmlSelectElement,
        offset: &HtmlInputElement,
        expand_unicode: &HtmlInputElement,
        compact_url: &HtmlInputElement,
    ) -> Result<(), JsValue> {
        if let Some(value) = self.cpu() {
            cpu.set_value(&value);
        }
        if let Some(value) = self.segment_size() {
            segment_size.set_value(&value);
        }
        if let Some(value) = self.offset() {
            offset.set_value(&value.to_ascii_uppercase());
        }
        if let Some(value) = self.expand_unicode() {
            expand_unicode.set_checked(value);
        }
        if let Some(value) = self.compact_url() {
            compact_url.set_checked(value);
        }
        if let Some(value) = self.params.get("hex_gz") {
            input.set_value("");
            input.set_value(&decompress_input(&value).map_err(js_error)?);
        } else if let Some(value) = self.params.get("hex") {
            input.set_value(&value);
        }

        Ok(())
    }

    fn cpu(&self) -> Option<String> {
        self.params.get("cpu").filter(|value| is_valid_cpu(value))
    }

    fn segment_size(&self) -> Option<String> {
        self.params.get("segment").filter(|value| is_valid_segment_size(value))
    }

    fn offset(&self) -> Option<String> {
        self.params.get("offset").filter(|value| is_valid_offset(value))
    }

    fn expand_unicode(&self) -> Option<bool> {
        self.params.get("eu").as_deref().and_then(parse_query_flag)
    }

    fn compact_url(&self) -> Option<bool> {
        self.params.get("cu").as_deref().and_then(parse_query_flag)
    }
}

pub(crate) fn update_query(
    window: &Window,
    input: &HtmlTextAreaElement,
    cpu: &HtmlSelectElement,
    segment_size: &HtmlSelectElement,
    offset: &HtmlInputElement,
    expand_unicode: &HtmlInputElement,
    compact_url: &HtmlInputElement,
) -> Result<usize, JsValue> {
    let location = window.location();
    let original_input = input.value();
    let input_value = if compact_url.checked() {
        compact_url_input(&original_input, expand_unicode.checked()).unwrap_or(original_input)
    } else {
        original_input
    };
    let plain_params = query_params(cpu, segment_size, offset, expand_unicode, compact_url)?;
    plain_params.set("hex", &input_value);
    let plain_url = query_url(&location, &plain_params)?;

    let url = if may_compress_input(&input_value) {
        let compressed_params = query_params(cpu, segment_size, offset, expand_unicode, compact_url)?;
        let compressed_url = compress_input(&input_value)
            .map(|encoded| {
                compressed_params.set("hex_gz", &encoded);
                query_url(&location, &compressed_params)
            })
            .map_err(js_error)??;
        if compressed_url.len() < plain_url.len() {
            compressed_url
        } else {
            plain_url
        }
    } else {
        plain_url
    };

    window
        .history()?
        .replace_state_with_url(&JsValue::NULL, "", Some(&url))?;
    Ok(window.location().href()?.len())
}

fn query_params(
    cpu: &HtmlSelectElement,
    segment_size: &HtmlSelectElement,
    offset: &HtmlInputElement,
    expand_unicode: &HtmlInputElement,
    compact_url: &HtmlInputElement,
) -> Result<UrlSearchParams, JsValue> {
    let params = UrlSearchParams::new()?;
    params.set("cpu", &cpu.value());
    params.set("segment", &segment_size.value());
    params.set("offset", &offset.value());
    params.set("eu", if expand_unicode.checked() { "1" } else { "0" });
    params.set("cu", if compact_url.checked() { "1" } else { "0" });
    Ok(params)
}

fn query_url(location: &Location, params: &UrlSearchParams) -> Result<String, JsValue> {
    let mut url = format!("{}?{}", location.pathname()?, params.to_string());
    let hash = location.hash()?;
    if !hash.is_empty() {
        url.push_str(&hash);
    }
    Ok(url)
}

fn js_error(error: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}
