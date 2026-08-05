// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Daniel Balsom

use minijinja::{context, Environment};

const APP_TEMPLATE: &str = include_str!("../templates/app.html.j2");

// Renders the application jinja2 template with the provided context.
pub(crate) fn render_app() -> Result<String, minijinja::Error> {
    let mut env = Environment::new();
    env.add_template("app.html.j2", APP_TEMPLATE)?;
    env.get_template("app.html.j2")?.render(context! {
        title => "Marty x86 Disassembler",
        web_version => env!("CARGO_PKG_VERSION"),
        dasm_version => marty_dasm::VERSION,
        sample_bytes => "B8 34 12 05 78 56 90",
        cpus => vec![
            context! { value => "intel808x", label => "Intel 8088 / 8086" },
            context! { value => "necvx0", label => "NEC V20 / V30" },
            context! { value => "intel80386", label => "Intel 80386" },
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_application_shell() {
        let app = render_app().unwrap();
        assert!(app.contains("Intel 80386"));
        assert!(app.contains("href=\"https://github.com/dbalsom\""));
        assert!(app.contains("id=\"random-byline\""));
        assert!(app.contains("id=\"share-link\""));
        assert!(app.contains("id=\"banner-container\""));
        assert!(app.contains("id=\"panic-banner\""));
        assert!(app.contains("id=\"panic-report-prompt\""));
        // Please don't point at my repository issues if you fork this.
        assert!(!app.contains("https://github.com/dbalsom/marty_dasm/issues/new"));
    }
}
