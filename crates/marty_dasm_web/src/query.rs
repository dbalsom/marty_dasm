// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Daniel Balsom

use crate::compression::{compress_input, decompress_input, may_compress_input};
use wasm_bindgen::JsValue;
use web_sys::{HtmlInputElement, HtmlSelectElement, HtmlTextAreaElement, Location, UrlSearchParams, Window};

#[derive(Clone, Copy)]
pub(crate) struct QueryOverrides {
    pub(crate) input: bool,
    pub(crate) cpu: bool,
    pub(crate) segment_size: bool,
    pub(crate) offset: bool,
    pub(crate) expand_unicode: bool,
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
        self.params.get("raw").is_some()
    }

    pub(crate) fn overrides(&self) -> QueryOverrides {
        QueryOverrides {
            input: self.params.get("hex").is_some() || self.params.get("hex_gz").is_some(),
            cpu: self.params.get("cpu").is_some(),
            segment_size: self.params.get("segment").is_some(),
            offset: self.params.get("offset").is_some(),
            expand_unicode: self.params.get("eu").is_some(),
        }
    }

    pub(crate) fn restore(
        &self,
        input: &HtmlTextAreaElement,
        cpu: &HtmlSelectElement,
        segment_size: &HtmlSelectElement,
        offset: &HtmlInputElement,
        expand_unicode: &HtmlInputElement,
    ) -> Result<(), JsValue> {
        let params = &self.params;

        if let Some(value) = params.get("cpu") {
            if matches!(value.as_str(), "intel808x" | "necvx0" | "intel80386") {
                cpu.set_value(&value);
            }
        }
        if let Some(value) = params.get("segment") {
            if matches!(value.as_str(), "16" | "32") {
                segment_size.set_value(&value);
            }
        }
        if let Some(value) = params.get("offset") {
            offset.set_value(&value);
        }
        if let Some(value) = params.get("eu") {
            expand_unicode.set_checked(value == "1");
        }
        if let Some(value) = params.get("hex_gz") {
            input.set_value("");
            input.set_value(&decompress_input(&value).map_err(js_error)?);
        } else if let Some(value) = params.get("hex") {
            input.set_value(&value);
        }

        Ok(())
    }
}

pub(crate) fn update_query(
    window: &Window,
    input: &HtmlTextAreaElement,
    cpu: &HtmlSelectElement,
    segment_size: &HtmlSelectElement,
    offset: &HtmlInputElement,
    expand_unicode: &HtmlInputElement,
) -> Result<usize, JsValue> {
    let location = window.location();
    let input_value = input.value();
    let plain_params = query_params(cpu, segment_size, offset, expand_unicode)?;
    plain_params.set("hex", &input_value);
    let plain_url = query_url(&location, &plain_params)?;

    let url = if may_compress_input(&input_value) {
        let compressed_params = query_params(cpu, segment_size, offset, expand_unicode)?;
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
) -> Result<UrlSearchParams, JsValue> {
    let params = UrlSearchParams::new()?;
    params.set("cpu", &cpu.value());
    params.set("segment", &segment_size.value());
    params.set("offset", &offset.value());
    params.set("eu", if expand_unicode.checked() { "1" } else { "0" });
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
