// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Daniel Balsom

const URL_WARNING_THRESHOLD: usize = 2_000;
const URL_LENGTH_WARNING: &str =
    "This share link is longer than 2,000 characters and may not work in all browsers or services.";
const URI_UPDATE_DELAY_MS: i32 = 500;

use std::{cell::RefCell, rc::Rc};

use crate::{
    bylines::set_random_byline,
    disassembly::{binary_md5, compact_input, disassemble, disassemble_bytes, format_disassembly_text, parse_input},
    local_storage::{
        observe_input_height, persist_copy_preferences, persist_disassembly_state, persist_input_height, persist_theme,
        restore_copy_preferences, restore_disassembly_state, restore_input_height, restore_theme,
        RestoreDisassemblyStateOptions,
    },
    panic_report::install_panic_hook,
    query::{update_query, QueryState},
    template::render_app,
};

use wasm_bindgen::{closure::Closure, prelude::wasm_bindgen, JsCast, JsValue};
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::{
    Document, Element, Event, EventTarget, HtmlElement, HtmlInputElement, HtmlOptionElement, HtmlSelectElement,
    HtmlTextAreaElement, Storage, Window,
};

type PendingUriUpdate = RefCell<Option<(i32, Closure<dyn FnMut()>)>>;

struct Ui {
    document_root: Element,
    share_link: HtmlElement,
    theme_toggle: HtmlElement,
    input: HtmlTextAreaElement,
    binary_byte_count: HtmlElement,
    binary_md5: HtmlElement,
    copy_input: HtmlElement,
    clear_input: HtmlElement,
    compact_input: HtmlElement,
    cpu: HtmlSelectElement,
    segment_size: HtmlSelectElement,
    segment_size_32: HtmlOptionElement,
    offset: HtmlInputElement,
    expand_unicode: HtmlInputElement,
    compact_url: HtmlInputElement,
    output: Element,
    status: HtmlElement,
    url_warning: HtmlElement,
    fpu_warning: HtmlElement,
    copy_offsets: HtmlInputElement,
    copy_bytes: HtmlInputElement,
    copy_disassembly: HtmlElement,
}

impl Ui {
    fn from_document(document: &Document) -> Result<Self, JsValue> {
        Ok(Self {
            document_root: document.document_element().ok_or("document root is unavailable")?,
            share_link: element(document, "share-link")?,
            theme_toggle: element(document, "theme-toggle")?,
            input: element(document, "hex-input")?,
            binary_byte_count: element(document, "binary-byte-count")?,
            binary_md5: element(document, "binary-md5")?,
            copy_input: element(document, "copy-input")?,
            clear_input: element(document, "clear-input")?,
            compact_input: element(document, "compact-input")?,
            cpu: element(document, "cpu-select")?,
            segment_size: element(document, "segment-size-select")?,
            segment_size_32: element(document, "segment-size-32")?,
            offset: element(document, "offset-input")?,
            expand_unicode: element(document, "expand-unicode")?,
            compact_url: element(document, "compact-url")?,
            output: element(document, "disassembly-output")?,
            status: element(document, "status")?,
            url_warning: element(document, "url-warning")?,
            fpu_warning: element(document, "fpu-warning")?,
            copy_offsets: element(document, "copy-offsets")?,
            copy_bytes: element(document, "copy-bytes")?,
            copy_disassembly: element(document, "copy-disassembly")?,
        })
    }
}

struct App {
    window: Window,
    document: Document,
    storage: Option<Storage>,
    ui: Ui,
    pending_uri_update: PendingUriUpdate,
}

impl App {
    fn new(window: Window, document: Document, storage: Option<Storage>, ui: Ui) -> Self {
        Self {
            window,
            document,
            storage,
            ui,
            pending_uri_update: RefCell::new(None),
        }
    }

    fn toggle_theme(&self) {
        let next_theme = if self.ui.document_root.get_attribute("data-theme").as_deref() == Some("dark") {
            "light"
        } else {
            "dark"
        };
        let _ = apply_theme(&self.ui.document_root, &self.ui.theme_toggle, next_theme);
        persist_theme(self.storage.as_ref(), next_theme);
    }

    fn update_output(&self) {
        let supports_32_bit_segments = self.ui.cpu.value() == "intel80386";
        self.ui.fpu_warning.set_hidden(!supports_32_bit_segments);
        self.ui.segment_size_32.set_hidden(!supports_32_bit_segments);
        self.ui.segment_size_32.set_disabled(!supports_32_bit_segments);
        if !supports_32_bit_segments {
            self.ui.segment_size.set_value("16");
        }

        let result = match parse_input(&self.ui.input.value(), self.ui.expand_unicode.checked()) {
            Ok(bytes) => {
                self.ui
                    .binary_byte_count
                    .set_text_content(Some(&bytes.len().to_string()));
                self.ui.binary_md5.set_text_content(Some(&binary_md5(&bytes)));
                disassemble_bytes(
                    &bytes,
                    &self.ui.cpu.value(),
                    &self.ui.segment_size.value(),
                    &self.ui.offset.value(),
                )
            }
            Err(error) => {
                self.ui.binary_byte_count.set_text_content(Some("—"));
                self.ui.binary_md5.set_text_content(Some("—"));
                Err(error)
            }
        };

        match result {
            Ok(rows) if rows.is_empty() => {
                self.ui.output.set_text_content(None);
                append_message_row(
                    &self.document,
                    &self.ui.output,
                    "Enter hexadecimal machine code above.",
                    "empty-row",
                );
                self.ui.status.set_text_content(Some("Waiting for input"));
                self.ui.status.set_class_name("status");
            }
            Ok(rows) => {
                self.ui.output.set_text_content(None);
                let instruction_count = rows.len();
                let byte_count = rows.iter().map(|row| row.byte_count).sum::<usize>();
                for row in rows {
                    let table_row = self.document.create_element("tr").expect("create table row");
                    if row.is_error {
                        table_row.set_class_name("decode-error");
                    }
                    append_cell(&self.document, &table_row, "th", &row.offset, "offset mono");
                    append_cell(&self.document, &table_row, "td", &row.bytes, "bytes mono");
                    append_cell(&self.document, &table_row, "td", &row.instruction, "instruction mono");
                    self.ui.output.append_child(&table_row).expect("append table row");
                }
                self.ui.status.set_text_content(Some(&format!(
                    "{byte_count} byte{}, {instruction_count} instruction{}",
                    if byte_count == 1 { "" } else { "s" },
                    if instruction_count == 1 { "" } else { "s" }
                )));
                self.ui.status.set_class_name("status status--ready");
            }
            Err(error) if error.is_incomplete_hex_byte() => {
                self.ui.status.set_text_content(Some("Waiting for another hex digit"));
                self.ui.status.set_class_name("status status--pending");
            }
            Err(error) => {
                self.ui.output.set_text_content(None);
                append_message_row(&self.document, &self.ui.output, &error.to_string(), "error-row");
                self.ui.status.set_text_content(Some("Check the input"));
                self.ui.status.set_class_name("status status--error");
            }
        }
    }

    fn update_uri(&self) {
        self.persist_state();
        self.ui.url_warning.set_text_content(Some(URL_LENGTH_WARNING));
        if let Ok(url_length) = update_query(
            &self.window,
            &self.ui.input,
            &self.ui.cpu,
            &self.ui.segment_size,
            &self.ui.offset,
            &self.ui.expand_unicode,
            &self.ui.compact_url,
        ) {
            self.ui.url_warning.set_hidden(url_length <= URL_WARNING_THRESHOLD);
        }
    }

    fn persist_state(&self) {
        persist_disassembly_state(
            self.storage.as_ref(),
            &self.ui.input,
            &self.ui.cpu,
            &self.ui.segment_size,
            &self.ui.offset,
            &self.ui.expand_unicode,
            &self.ui.compact_url,
        );
    }

    fn cancel_pending_uri_update(&self) {
        if let Some((handle, _callback)) = self.pending_uri_update.borrow_mut().take() {
            self.window.clear_timeout_with_handle(handle);
        }
    }

    fn schedule_uri_update(self: &Rc<Self>) {
        self.cancel_pending_uri_update();

        let weak_app = Rc::downgrade(self);
        let timeout_handler = Closure::<dyn FnMut()>::new(move || {
            if let Some(app) = weak_app.upgrade() {
                app.update_uri();
            }
        });
        if let Ok(handle) = self.window.set_timeout_with_callback_and_timeout_and_arguments_0(
            timeout_handler.as_ref().unchecked_ref(),
            URI_UPDATE_DELAY_MS,
        ) {
            *self.pending_uri_update.borrow_mut() = Some((handle, timeout_handler));
        }
    }

    fn input_changed(self: &Rc<Self>) {
        self.update_output();
        self.schedule_uri_update();
    }

    fn offset_changed(self: &Rc<Self>) {
        normalize_offset_input(&self.ui.offset);
        self.update_output();
        self.schedule_uri_update();
    }

    fn selection_changed(&self) {
        self.cancel_pending_uri_update();
        self.update_output();
        self.update_uri();
    }

    fn url_option_changed(&self) {
        self.cancel_pending_uri_update();
        self.update_uri();
    }

    fn share_link(&self) {
        self.cancel_pending_uri_update();
        self.update_uri();
        if let Ok(url) = self.window.location().href() {
            self.copy_text(&url);
        }
    }

    fn compact_input(self: &Rc<Self>) {
        let Ok(compacted) = compact_input(&self.ui.input.value(), self.ui.expand_unicode.checked()) else {
            return;
        };
        self.ui.input.set_value(&compacted);
        self.input_changed();
    }

    fn copy_input(&self) {
        self.copy_text(&self.ui.input.value());
    }

    fn clear_input(&self) {
        self.cancel_pending_uri_update();
        self.ui.input.set_value("");
        self.update_output();
        self.update_uri();
        let _ = self.ui.input.focus();
    }

    fn copy_disassembly(&self) {
        let rows = match disassemble(
            &self.ui.input.value(),
            &self.ui.cpu.value(),
            &self.ui.segment_size.value(),
            &self.ui.offset.value(),
            self.ui.expand_unicode.checked(),
        ) {
            Ok(rows) if !rows.is_empty() => rows,
            _ => return,
        };
        let text = format_disassembly_text(&rows, self.ui.copy_offsets.checked(), self.ui.copy_bytes.checked());
        self.copy_text(&text);
    }

    fn persist_copy_preferences(&self) {
        persist_copy_preferences(self.storage.as_ref(), &self.ui.copy_offsets, &self.ui.copy_bytes);
    }

    fn persist_page_state(&self) {
        self.persist_state();
        persist_input_height(self.storage.as_ref(), &self.ui.input);
    }

    fn copy_text(&self, text: &str) {
        let write = self.window.navigator().clipboard().write_text(text);
        spawn_local(async move {
            let _ = JsFuture::from(write).await;
        });
    }

    fn render_raw_output(&self, body: &HtmlElement, restore_error: Option<JsValue>) -> Result<(), JsValue> {
        if self.ui.cpu.value() != "intel80386" {
            self.ui.segment_size.set_value("16");
        }
        let text = if let Some(error) = restore_error {
            format!(
                "error: {}",
                error.as_string().unwrap_or_else(|| "invalid shared input".to_owned())
            )
        } else {
            match disassemble(
                &self.ui.input.value(),
                &self.ui.cpu.value(),
                &self.ui.segment_size.value(),
                &self.ui.offset.value(),
                self.ui.expand_unicode.checked(),
            ) {
                Ok(rows) => format_disassembly_text(&rows, true, true),
                Err(error) => format!("error: {error}"),
            }
        };

        body.set_inner_html("");
        body.set_class_name("raw-page");
        let output = self.document.create_element("pre")?;
        output.set_id("raw-output");
        output.set_class_name("raw-output");
        output.set_text_content(Some(&text));
        body.append_child(&output)?;
        Ok(())
    }
}

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

    let storage = window.local_storage()?;
    let ui = Ui::from_document(&document)?;
    let app = Rc::new(App::new(window, document, storage, ui));

    let initial_theme = restore_theme(app.storage.as_ref()).unwrap_or_else(|| {
        let prefers_dark = app
            .window
            .match_media("(prefers-color-scheme: dark)")
            .ok()
            .flatten()
            .is_some_and(|query| query.matches());
        if prefers_dark { "dark" } else { "light" }.to_owned()
    });
    apply_theme(&app.ui.document_root, &app.ui.theme_toggle, &initial_theme)?;

    if !raw_requested {
        let query_overrides = query_state.overrides();
        restore_disassembly_state(
            app.storage.as_ref(),
            &app.ui.input,
            &app.ui.cpu,
            &app.ui.segment_size,
            &app.ui.offset,
            &app.ui.expand_unicode,
            &app.ui.compact_url,
            RestoreDisassemblyStateOptions {
                input: !query_overrides.input,
                cpu: !query_overrides.cpu,
                segment_size: !query_overrides.segment_size,
                offset: !query_overrides.offset,
                expand_unicode: !query_overrides.expand_unicode,
                compact_url: !query_overrides.compact_url,
            },
        );
        restore_copy_preferences(app.storage.as_ref(), &app.ui.copy_offsets, &app.ui.copy_bytes);
        restore_input_height(app.storage.as_ref(), &app.ui.input);
    }

    let restore_error = query_state
        .restore(
            &app.ui.input,
            &app.ui.cpu,
            &app.ui.segment_size,
            &app.ui.offset,
            &app.ui.expand_unicode,
            &app.ui.compact_url,
        )
        .err();
    if raw_requested {
        app.render_raw_output(&body, restore_error)?;
        return Ok(());
    }

    observe_input_height(app.storage.clone(), &app.ui.input)?;
    app.update_output();
    app.update_uri();

    if let Some(error) = restore_error {
        app.ui.url_warning.set_text_content(Some(&format!(
            "Could not restore this share link: {}",
            error.as_string().unwrap_or_default()
        )));
        app.ui.url_warning.set_hidden(false);
    }

    install_event_handlers(&app)?;
    Ok(())
}

fn install_event_handlers(app: &Rc<App>) -> Result<(), JsValue> {
    listen(&app.ui.theme_toggle, "click", app, |app, _event| app.toggle_theme())?;
    listen(&app.ui.share_link, "click", app, |app, _event| app.share_link())?;
    listen(&app.ui.input, "input", app, |app, _event| app.input_changed())?;
    listen(&app.ui.compact_input, "click", app, |app, _event| app.compact_input())?;
    listen(&app.ui.offset, "input", app, |app, _event| app.offset_changed())?;
    listen(&app.ui.cpu, "change", app, |app, _event| app.selection_changed())?;
    listen(&app.ui.segment_size, "change", app, |app, _event| {
        app.selection_changed()
    })?;
    listen(&app.ui.expand_unicode, "change", app, |app, _event| {
        app.selection_changed()
    })?;
    listen(&app.ui.compact_url, "change", app, |app, _event| {
        app.url_option_changed()
    })?;
    listen(&app.ui.copy_input, "click", app, |app, _event| app.copy_input())?;
    listen(&app.ui.clear_input, "click", app, |app, _event| app.clear_input())?;
    listen(&app.ui.copy_disassembly, "click", app, |app, _event| {
        app.copy_disassembly()
    })?;
    listen(&app.ui.copy_offsets, "change", app, |app, _event| {
        app.persist_copy_preferences()
    })?;
    listen(&app.ui.copy_bytes, "change", app, |app, _event| {
        app.persist_copy_preferences()
    })?;
    listen(&app.window, "pagehide", app, |app, _event| app.persist_page_state())?;
    Ok(())
}

fn listen<T, F>(target: &T, event_type: &str, app: &Rc<App>, mut handler: F) -> Result<(), JsValue>
where
    T: AsRef<EventTarget>,
    F: FnMut(&Rc<App>, Event) + 'static,
{
    let app = Rc::clone(app);
    let callback = Closure::<dyn FnMut(Event)>::new(move |event| handler(&app, event));
    target
        .as_ref()
        .add_event_listener_with_callback(event_type, callback.as_ref().unchecked_ref())?;
    callback.forget();
    Ok(())
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
    } else {
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
