// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Daniel Balsom

const URL_WARNING_THRESHOLD: usize = 2_000;
const URL_LENGTH_WARNING: &str =
    "This share link is longer than 2,000 characters and may not work in all browsers or services.";

use std::{cell::RefCell, rc::Rc};

use crate::{
    bylines::set_random_byline,
    disassembly::{binary_md5, disassemble, disassemble_bytes, format_disassembly_text, parse_hex},
    local_storage::{
        observe_input_height,
        persist_copy_preferences,
        persist_disassembly_state,
        persist_input_height,
        persist_theme,
        restore_copy_preferences,
        restore_disassembly_state,
        restore_input_height,
        restore_theme,
        RestoreDisassemblyStateOptions,
    },
    panic_report::install_panic_hook,
    query::{update_query, QueryState},
    template::render_app,
};

use wasm_bindgen::{closure::Closure, prelude::wasm_bindgen, JsCast, JsValue};
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::{
    Document,
    Element,
    Event,
    HtmlElement,
    HtmlInputElement,
    HtmlOptionElement,
    HtmlSelectElement,
    HtmlTextAreaElement,
    Storage,
    Window,
};

const URI_UPDATE_DELAY_MS: i32 = 500;
type PendingUriUpdate = Rc<RefCell<Option<(i32, Closure<dyn FnMut()>)>>>;

#[wasm_bindgen(start)]
pub fn start() -> Result<(), JsValue> {
    install_panic_hook();

    let window = web_sys::window().ok_or("browser window is unavailable")?;
    let document = window.document().ok_or("document is unavailable")?;
    let body = document.body().ok_or("document body is unavailable")?;
    let query_state = QueryState::from_window(&window)?;
    let raw_requested = query_state.is_raw_requested();
    body.set_inner_html(&render_app().map_err(js_error)?);
    set_random_byline(&window, &document)?;

    let document_root = document.document_element().ok_or("document root is unavailable")?;
    let share_link = element::<HtmlElement>(&document, "share-link")?;
    let theme_toggle = element::<HtmlElement>(&document, "theme-toggle")?;
    let storage = window.local_storage()?;

    // Get the initial dark/light theme from local storage or the user's system preference.
    let initial_theme = restore_theme(storage.as_ref()).unwrap_or_else(|| {
        let prefers_dark = window
            .match_media("(prefers-color-scheme: dark)")
            .ok()
            .flatten()
            .is_some_and(|query| query.matches());
        if prefers_dark { "dark" } else { "light" }.to_owned()
    });

    apply_theme(&document_root, &theme_toggle, &initial_theme)?;

    let theme_root = document_root.clone();
    let theme_button = theme_toggle.clone();
    let theme_storage = storage.clone();
    let theme_handler = Closure::<dyn FnMut(Event)>::new(move |_event| {
        let next_theme = if theme_root.get_attribute("data-theme").as_deref() == Some("dark") {
            "light"
        }
        else {
            "dark"
        };
        let _ = apply_theme(&theme_root, &theme_button, next_theme);
        persist_theme(theme_storage.as_ref(), next_theme);
    });
    theme_toggle.add_event_listener_with_callback("click", theme_handler.as_ref().unchecked_ref())?;
    theme_handler.forget();

    let input = element::<HtmlTextAreaElement>(&document, "hex-input")?;
    let binary_byte_count = element::<HtmlElement>(&document, "binary-byte-count")?;
    let binary_md5_output = element::<HtmlElement>(&document, "binary-md5")?;
    let copy_hex_input = element::<HtmlElement>(&document, "copy-input")?;
    let clear_input = element::<HtmlElement>(&document, "clear-input")?;
    let cpu = element::<HtmlSelectElement>(&document, "cpu-select")?;
    let segment_size = element::<HtmlSelectElement>(&document, "segment-size-select")?;
    let segment_size_32 = element::<HtmlOptionElement>(&document, "segment-size-32")?;
    let offset = element::<HtmlInputElement>(&document, "offset-input")?;
    let output = element::<Element>(&document, "disassembly-output")?;
    let status = element::<HtmlElement>(&document, "status")?;
    let url_warning = element::<HtmlElement>(&document, "url-warning")?;
    let fpu_warning = element::<HtmlElement>(&document, "fpu-warning")?;
    let copy_offsets = element::<HtmlInputElement>(&document, "copy-offsets")?;
    let copy_bytes = element::<HtmlInputElement>(&document, "copy-bytes")?;
    let copy_disassembly = element::<HtmlElement>(&document, "copy-disassembly")?;

    // Raw output ignores localstorage
    if !raw_requested {
        let query_overrides = query_state.overrides();
        restore_disassembly_state(
            storage.as_ref(),
            &input,
            &cpu,
            &segment_size,
            &offset,
            RestoreDisassemblyStateOptions {
                input: !query_overrides.input,
                cpu: !query_overrides.cpu,
                segment_size: !query_overrides.segment_size,
                offset: !query_overrides.offset,
            },
        );
        restore_copy_preferences(storage.as_ref(), &copy_offsets, &copy_bytes);
        restore_input_height(storage.as_ref(), &input);
    }
    let restore_error = query_state.restore(&input, &cpu, &segment_size, &offset).err();
    if raw_requested {
        render_raw_output(&document, &body, &input, &cpu, &segment_size, &offset, restore_error)?;
        return Ok(());
    }

    observe_input_height(storage.clone(), &input)?;

    update_output(
        &document,
        &input,
        &cpu,
        &segment_size,
        &offset,
        &segment_size_32,
        &output,
        &status,
        &fpu_warning,
        &binary_byte_count,
        &binary_md5_output,
    );

    update_uri(
        &window,
        storage.as_ref(),
        &input,
        &cpu,
        &segment_size,
        &offset,
        &url_warning,
    );

    // something went wrong restoring uri from localstorage
    if let Some(error) = restore_error {
        url_warning.set_text_content(Some(&format!(
            "Could not restore this share link: {}",
            error.as_string().unwrap_or_default()
        )));
        url_warning.set_hidden(false);
    }

    let pending_uri_update: PendingUriUpdate = Rc::new(RefCell::new(None));

    let share_window = window.clone();
    let share_input = input.clone();
    let share_cpu = cpu.clone();
    let share_segment_size = segment_size.clone();
    let share_offset = offset.clone();
    let share_url_warning = url_warning.clone();
    let share_storage = storage.clone();
    let share_pending_uri_update = pending_uri_update.clone();
    let share_handler = Closure::<dyn FnMut(Event)>::new(move |_event| {
        cancel_pending_uri_update(&share_window, &share_pending_uri_update);
        update_uri(
            &share_window,
            share_storage.as_ref(),
            &share_input,
            &share_cpu,
            &share_segment_size,
            &share_offset,
            &share_url_warning,
        );
        if let Ok(url) = share_window.location().href() {
            let write = share_window.navigator().clipboard().write_text(&url);
            spawn_local(async move {
                let _ = JsFuture::from(write).await;
            });
        }
    });
    share_link.add_event_listener_with_callback("click", share_handler.as_ref().unchecked_ref())?;
    share_handler.forget();

    let input_document = document.clone();
    let input_window = window.clone();
    let input_control = input.clone();
    let input_cpu = cpu.clone();
    let input_segment_size = segment_size.clone();
    let input_offset = offset.clone();
    let input_segment_size_32 = segment_size_32.clone();
    let input_output = output.clone();
    let input_status = status.clone();
    let input_fpu_warning = fpu_warning.clone();
    let input_binary_byte_count = binary_byte_count.clone();
    let input_binary_md5 = binary_md5_output.clone();
    let input_url_warning = url_warning.clone();
    let input_storage = storage.clone();
    let input_pending_uri_update = pending_uri_update.clone();
    let input_handler = Closure::<dyn FnMut(Event)>::new(move |_event| {
        update_output(
            &input_document,
            &input_control,
            &input_cpu,
            &input_segment_size,
            &input_offset,
            &input_segment_size_32,
            &input_output,
            &input_status,
            &input_fpu_warning,
            &input_binary_byte_count,
            &input_binary_md5,
        );

        if let Some((handle, _callback)) = input_pending_uri_update.borrow_mut().take() {
            input_window.clear_timeout_with_handle(handle);
        }

        let timeout_window = input_window.clone();
        let timeout_input = input_control.clone();
        let timeout_cpu = input_cpu.clone();
        let timeout_segment_size = input_segment_size.clone();
        let timeout_offset = input_offset.clone();
        let timeout_url_warning = input_url_warning.clone();
        let timeout_storage = input_storage.clone();
        let timeout_handler = Closure::<dyn FnMut()>::new(move || {
            update_uri(
                &timeout_window,
                timeout_storage.as_ref(),
                &timeout_input,
                &timeout_cpu,
                &timeout_segment_size,
                &timeout_offset,
                &timeout_url_warning,
            );
        });
        if let Ok(handle) = input_window.set_timeout_with_callback_and_timeout_and_arguments_0(
            timeout_handler.as_ref().unchecked_ref(),
            URI_UPDATE_DELAY_MS,
        ) {
            *input_pending_uri_update.borrow_mut() = Some((handle, timeout_handler));
        }
    });
    input.add_event_listener_with_callback("input", input_handler.as_ref().unchecked_ref())?;
    input_handler.forget();

    let offset_document = document.clone();
    let offset_window = window.clone();
    let offset_input = input.clone();
    let offset_cpu = cpu.clone();
    let offset_segment_size = segment_size.clone();
    let offset_segment_size_32 = segment_size_32.clone();
    let offset_control = offset.clone();
    let offset_output = output.clone();
    let offset_status = status.clone();
    let offset_fpu_warning = fpu_warning.clone();
    let offset_binary_byte_count = binary_byte_count.clone();
    let offset_binary_md5 = binary_md5_output.clone();
    let offset_url_warning = url_warning.clone();
    let offset_storage = storage.clone();
    let offset_pending_uri_update = pending_uri_update.clone();
    let offset_handler = Closure::<dyn FnMut(Event)>::new(move |_event| {
        normalize_offset_input(&offset_control);
        update_output(
            &offset_document,
            &offset_input,
            &offset_cpu,
            &offset_segment_size,
            &offset_control,
            &offset_segment_size_32,
            &offset_output,
            &offset_status,
            &offset_fpu_warning,
            &offset_binary_byte_count,
            &offset_binary_md5,
        );

        cancel_pending_uri_update(&offset_window, &offset_pending_uri_update);
        let timeout_window = offset_window.clone();
        let timeout_input = offset_input.clone();
        let timeout_cpu = offset_cpu.clone();
        let timeout_segment_size = offset_segment_size.clone();
        let timeout_offset = offset_control.clone();
        let timeout_url_warning = offset_url_warning.clone();
        let timeout_storage = offset_storage.clone();
        let timeout_handler = Closure::<dyn FnMut()>::new(move || {
            update_uri(
                &timeout_window,
                timeout_storage.as_ref(),
                &timeout_input,
                &timeout_cpu,
                &timeout_segment_size,
                &timeout_offset,
                &timeout_url_warning,
            );
        });
        if let Ok(handle) = offset_window.set_timeout_with_callback_and_timeout_and_arguments_0(
            timeout_handler.as_ref().unchecked_ref(),
            URI_UPDATE_DELAY_MS,
        ) {
            *offset_pending_uri_update.borrow_mut() = Some((handle, timeout_handler));
        }
    });
    offset.add_event_listener_with_callback("input", offset_handler.as_ref().unchecked_ref())?;
    offset_handler.forget();

    let select_document = document.clone();
    let select_window = window.clone();
    let select_input = input.clone();
    let select_cpu = cpu.clone();
    let select_segment_size = segment_size.clone();
    let select_offset = offset.clone();
    let select_segment_size_32 = segment_size_32.clone();
    let select_output = output.clone();
    let select_status = status.clone();
    let select_fpu_warning = fpu_warning.clone();
    let select_binary_byte_count = binary_byte_count.clone();
    let select_binary_md5 = binary_md5_output.clone();
    let select_url_warning = url_warning.clone();
    let select_storage = storage.clone();
    let select_pending_uri_update = pending_uri_update.clone();
    let select_handler = Closure::<dyn FnMut(Event)>::new(move |_event| {
        if let Some((handle, _callback)) = select_pending_uri_update.borrow_mut().take() {
            select_window.clear_timeout_with_handle(handle);
        }
        update_output(
            &select_document,
            &select_input,
            &select_cpu,
            &select_segment_size,
            &select_offset,
            &select_segment_size_32,
            &select_output,
            &select_status,
            &select_fpu_warning,
            &select_binary_byte_count,
            &select_binary_md5,
        );
        update_uri(
            &select_window,
            select_storage.as_ref(),
            &select_input,
            &select_cpu,
            &select_segment_size,
            &select_offset,
            &select_url_warning,
        );
    });
    let select_callback = select_handler.as_ref().unchecked_ref();
    cpu.add_event_listener_with_callback("change", select_callback)?;
    segment_size.add_event_listener_with_callback("change", select_callback)?;
    select_handler.forget();

    let copy_hex_window = window.clone();
    let copy_hex_control = input.clone();
    let copy_hex_handler = Closure::<dyn FnMut(Event)>::new(move |_event| {
        let write = copy_hex_window
            .navigator()
            .clipboard()
            .write_text(&copy_hex_control.value());
        spawn_local(async move {
            let _ = JsFuture::from(write).await;
        });
    });
    copy_hex_input.add_event_listener_with_callback("click", copy_hex_handler.as_ref().unchecked_ref())?;
    copy_hex_handler.forget();

    let clear_document = document.clone();
    let clear_window = window.clone();
    let clear_input_control = input.clone();
    let clear_cpu = cpu.clone();
    let clear_segment_size = segment_size.clone();
    let clear_offset = offset.clone();
    let clear_segment_size_32 = segment_size_32.clone();
    let clear_output = output.clone();
    let clear_status = status.clone();
    let clear_fpu_warning = fpu_warning.clone();
    let clear_binary_byte_count = binary_byte_count.clone();
    let clear_binary_md5 = binary_md5_output.clone();
    let clear_url_warning = url_warning.clone();
    let clear_storage = storage.clone();
    let clear_pending_uri_update = pending_uri_update.clone();
    let clear_handler = Closure::<dyn FnMut(Event)>::new(move |_event| {
        cancel_pending_uri_update(&clear_window, &clear_pending_uri_update);
        clear_input_control.set_value("");
        update_output(
            &clear_document,
            &clear_input_control,
            &clear_cpu,
            &clear_segment_size,
            &clear_offset,
            &clear_segment_size_32,
            &clear_output,
            &clear_status,
            &clear_fpu_warning,
            &clear_binary_byte_count,
            &clear_binary_md5,
        );
        update_uri(
            &clear_window,
            clear_storage.as_ref(),
            &clear_input_control,
            &clear_cpu,
            &clear_segment_size,
            &clear_offset,
            &clear_url_warning,
        );
        let _ = clear_input_control.focus();
    });
    clear_input.add_event_listener_with_callback("click", clear_handler.as_ref().unchecked_ref())?;
    clear_handler.forget();

    let copy_window = window.clone();
    let copy_input = input.clone();
    let copy_cpu = cpu.clone();
    let copy_segment_size = segment_size.clone();
    let copy_offset = offset.clone();
    let copy_handler_offsets = copy_offsets.clone();
    let copy_handler_bytes = copy_bytes.clone();
    let copy_handler = Closure::<dyn FnMut(Event)>::new(move |_event| {
        let rows = match disassemble(
            &copy_input.value(),
            &copy_cpu.value(),
            &copy_segment_size.value(),
            &copy_offset.value(),
        ) {
            Ok(rows) if !rows.is_empty() => rows,
            _ => return,
        };
        let text = format_disassembly_text(&rows, copy_handler_offsets.checked(), copy_handler_bytes.checked());
        let write = copy_window.navigator().clipboard().write_text(&text);
        spawn_local(async move {
            let _ = JsFuture::from(write).await;
        });
    });
    copy_disassembly.add_event_listener_with_callback("click", copy_handler.as_ref().unchecked_ref())?;
    copy_handler.forget();

    let preference_storage = storage.clone();
    let preference_offsets = copy_offsets.clone();
    let preference_bytes = copy_bytes.clone();
    let preference_handler = Closure::<dyn FnMut(Event)>::new(move |_event| {
        persist_copy_preferences(preference_storage.as_ref(), &preference_offsets, &preference_bytes);
    });
    let preference_callback = preference_handler.as_ref().unchecked_ref();
    copy_offsets.add_event_listener_with_callback("change", preference_callback)?;
    copy_bytes.add_event_listener_with_callback("change", preference_callback)?;
    preference_handler.forget();

    let pagehide_storage = storage.clone();
    let pagehide_input = input.clone();
    let pagehide_cpu = cpu.clone();
    let pagehide_segment_size = segment_size.clone();
    let pagehide_offset = offset.clone();
    let pagehide_handler = Closure::<dyn FnMut(Event)>::new(move |_event| {
        persist_disassembly_state(
            pagehide_storage.as_ref(),
            &pagehide_input,
            &pagehide_cpu,
            &pagehide_segment_size,
            &pagehide_offset,
        );
        persist_input_height(pagehide_storage.as_ref(), &pagehide_input);
    });
    window.add_event_listener_with_callback("pagehide", pagehide_handler.as_ref().unchecked_ref())?;
    pagehide_handler.forget();

    Ok(())
}

fn update_output(
    document: &Document,
    input: &HtmlTextAreaElement,
    cpu: &HtmlSelectElement,
    segment_size: &HtmlSelectElement,
    offset: &HtmlInputElement,
    segment_size_32: &HtmlOptionElement,
    output: &Element,
    status: &HtmlElement,
    fpu_warning: &HtmlElement,
    binary_byte_count: &HtmlElement,
    binary_md5_output: &HtmlElement,
) {
    let supports_32_bit_segments = cpu.value() == "intel80386";
    fpu_warning.set_hidden(!supports_32_bit_segments);
    segment_size_32.set_hidden(!supports_32_bit_segments);
    segment_size_32.set_disabled(!supports_32_bit_segments);
    if !supports_32_bit_segments {
        segment_size.set_value("16");
    }
    let result = match parse_hex(&input.value()) {
        Ok(bytes) => {
            binary_byte_count.set_text_content(Some(&bytes.len().to_string()));
            binary_md5_output.set_text_content(Some(&binary_md5(&bytes)));
            disassemble_bytes(&bytes, &cpu.value(), &segment_size.value(), &offset.value())
        }
        Err(error) => {
            binary_byte_count.set_text_content(Some("—"));
            binary_md5_output.set_text_content(Some("—"));
            Err(error)
        }
    };

    match result {
        Ok(rows) if rows.is_empty() => {
            output.set_text_content(None);
            append_message_row(document, output, "Enter hexadecimal machine code above.", "empty-row");
            status.set_text_content(Some("Waiting for input"));
            status.set_class_name("status");
        }
        Ok(rows) => {
            output.set_text_content(None);
            let instruction_count = rows.len();
            let byte_count = rows.iter().map(|row| row.byte_count).sum::<usize>();
            for row in rows {
                let table_row = document.create_element("tr").expect("create table row");
                if row.is_error {
                    table_row.set_class_name("decode-error");
                }
                append_cell(document, &table_row, "th", &row.offset, "offset mono");
                append_cell(document, &table_row, "td", &row.bytes, "bytes mono");
                append_cell(document, &table_row, "td", &row.instruction, "instruction mono");
                output.append_child(&table_row).expect("append table row");
            }
            status.set_text_content(Some(&format!(
                "{byte_count} byte{}, {instruction_count} instruction{}",
                if byte_count == 1 { "" } else { "s" },
                if instruction_count == 1 { "" } else { "s" }
            )));
            status.set_class_name("status status--ready");
        }
        Err(error) if error.is_incomplete_hex_byte() => {
            status.set_text_content(Some("Waiting for another hex digit"));
            status.set_class_name("status status--pending");
        }
        Err(error) => {
            output.set_text_content(None);
            append_message_row(document, output, &error.to_string(), "error-row");
            status.set_text_content(Some("Check the input"));
            status.set_class_name("status status--error");
        }
    }
}

fn render_raw_output(
    document: &Document,
    body: &HtmlElement,
    input: &HtmlTextAreaElement,
    cpu: &HtmlSelectElement,
    segment_size: &HtmlSelectElement,
    offset: &HtmlInputElement,
    restore_error: Option<JsValue>,
) -> Result<(), JsValue> {
    if cpu.value() != "intel80386" {
        segment_size.set_value("16");
    }
    let text = if let Some(error) = restore_error {
        format!(
            "error: {}",
            error.as_string().unwrap_or_else(|| "invalid shared input".to_owned())
        )
    }
    else {
        match disassemble(&input.value(), &cpu.value(), &segment_size.value(), &offset.value()) {
            Ok(rows) => format_disassembly_text(&rows, true, true),
            Err(error) => format!("error: {error}"),
        }
    };

    body.set_inner_html("");
    body.set_class_name("raw-page");
    let output = document.create_element("pre")?;
    output.set_id("raw-output");
    output.set_class_name("raw-output");
    output.set_text_content(Some(&text));
    body.append_child(&output)?;
    Ok(())
}

fn update_uri(
    window: &Window,
    storage: Option<&Storage>,
    input: &HtmlTextAreaElement,
    cpu: &HtmlSelectElement,
    segment_size: &HtmlSelectElement,
    offset: &HtmlInputElement,
    url_warning: &HtmlElement,
) {
    persist_disassembly_state(storage, input, cpu, segment_size, offset);
    url_warning.set_text_content(Some(URL_LENGTH_WARNING));
    if let Ok(url_length) = update_query(window, input, cpu, segment_size, offset) {
        url_warning.set_hidden(url_length <= URL_WARNING_THRESHOLD);
    }
}

fn normalize_offset_input(input: &HtmlInputElement) {
    let normalized = input
        .value()
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(8)
        .flat_map(char::to_uppercase)
        .collect::<String>();
    if normalized != input.value() {
        input.set_value(&normalized);
    }
}

fn cancel_pending_uri_update(window: &Window, pending: &PendingUriUpdate) {
    if let Some((handle, _callback)) = pending.borrow_mut().take() {
        window.clear_timeout_with_handle(handle);
    }
}

fn append_cell(document: &Document, row: &Element, tag: &str, text: &str, class_name: &str) {
    let cell = document.create_element(tag).expect("create table cell");
    cell.set_class_name(class_name);
    cell.set_text_content(Some(text));
    if tag == "th" {
        cell.set_attribute("scope", "row").expect("set row heading scope");
    }
    row.append_child(&cell).expect("append table cell");
}

fn append_message_row(document: &Document, output: &Element, message: &str, class_name: &str) {
    let row = document.create_element("tr").expect("create message row");
    row.set_class_name(class_name);
    let cell = document.create_element("td").expect("create message cell");
    cell.set_attribute("colspan", "3").expect("span message columns");
    cell.set_text_content(Some(message));
    row.append_child(&cell).expect("append message cell");
    output.append_child(&row).expect("append message row");
}

fn apply_theme(document_root: &Element, button: &HtmlElement, theme: &str) -> Result<(), JsValue> {
    document_root.set_attribute("data-theme", theme)?;
    let label = if theme == "dark" {
        "Switch to light mode"
    }
    else {
        "Switch to dark mode"
    };
    button.set_attribute("aria-label", label)?;
    button.set_attribute("title", label)?;
    Ok(())
}

fn element<T: JsCast>(document: &Document, id: &str) -> Result<T, JsValue> {
    document
        .get_element_by_id(id)
        .ok_or_else(|| JsValue::from_str(&format!("missing #{id}")))?
        .dyn_into::<T>()
        .map_err(|_| JsValue::from_str(&format!("#{id} has an unexpected element type")))
}

fn js_error(error: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}
