// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Daniel Balsom

use wasm_bindgen::{JsCast, JsValue};
use web_sys::{Document, HtmlElement, HtmlSelectElement, HtmlTextAreaElement, UrlSearchParams, Window};

const OFFICIAL_HOST: &str = "dasm.martypc.net";
const NEW_ISSUE_URL: &str = "https://github.com/dbalsom/marty_dasm/issues/new";

pub(crate) fn install_panic_hook() {
    std::panic::set_hook(Box::new(|panic_info| {
        console_error_panic_hook::hook(panic_info);
        let _ = show_panic_banner(panic_info);
    }));
}

fn show_panic_banner(panic_info: &std::panic::PanicHookInfo<'_>) -> Result<(), JsValue> {
    let window = web_sys::window().ok_or("browser window is unavailable")?;
    let document = window.document().ok_or("browser document is unavailable")?;
    let banner = element::<HtmlElement>(&document, "panic-banner")?;
    banner.set_hidden(false);

    if window.location().hostname()? != OFFICIAL_HOST {
        return Ok(());
    }

    let report_prompt = element::<HtmlElement>(&document, "panic-report-prompt")?;
    let issue_link = element::<HtmlElement>(&document, "panic-issue-link")?;
    let params = UrlSearchParams::new()?;
    params.set("title", "Web disassembler panic");
    params.set(
        "body",
        &format!(
            "The Marty x86 Disassembler panicked.\n\nReproduction URL:\n{}\n\nPanic details:\n{}",
            panic_reproduction_url(&window, &document)?,
            panic_details(panic_info),
        ),
    );
    issue_link.set_attribute("href", &format!("{NEW_ISSUE_URL}?{}", params.to_string()))?;
    report_prompt.set_hidden(false);
    Ok(())
}

fn panic_reproduction_url(window: &Window, document: &Document) -> Result<String, JsValue> {
    let current_url = window.location().href()?;
    let input = element::<HtmlTextAreaElement>(document, "hex-input")?;
    let cpu = element::<HtmlSelectElement>(document, "cpu-select")?;
    let segment_size = element::<HtmlSelectElement>(document, "segment-size-select")?;
    let offset = element::<web_sys::HtmlInputElement>(document, "offset-input")?;
    let params = UrlSearchParams::new()?;
    params.set("cpu", &cpu.value());
    params.set("segment", &segment_size.value());
    params.set("offset", &offset.value());
    params.set("hex", &input.value());

    let base_url = current_url.split(['?', '#']).next().unwrap_or(current_url.as_str());
    Ok(format!("{base_url}?{}", params.to_string()))
}

fn panic_details(panic_info: &std::panic::PanicHookInfo<'_>) -> String {
    let message = panic_info
        .payload()
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| panic_info.payload().downcast_ref::<String>().map(String::as_str))
        .unwrap_or("Unknown panic payload");
    match panic_info.location() {
        Some(location) => format!(
            "{message}\nLocation: {}:{}:{}",
            location.file(),
            location.line(),
            location.column()
        ),
        None => message.to_owned(),
    }
}

fn element<T: JsCast>(document: &Document, id: &str) -> Result<T, JsValue> {
    document
        .get_element_by_id(id)
        .ok_or_else(|| JsValue::from_str(&format!("missing #{id}")))?
        .dyn_into::<T>()
        .map_err(|_| JsValue::from_str(&format!("#{id} has an unexpected element type")))
}
