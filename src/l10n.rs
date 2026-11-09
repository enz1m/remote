use enzui_iced_core::localization::{CatalogBuilder, Localizer, preferred_locales};
pub(crate) fn text(key: &str) -> String {
    resolve(key, None)
}

pub(crate) fn with(
    key: &str,
    name: &str,
    value: impl enzui_iced_core::localization::MessageArgument,
) -> String {
    let mut arguments = enzui_iced_core::localization::Arguments::new();
    arguments.set(name, value.message_value());
    resolve(key, Some(&arguments))
}

fn resolve(key: &str, arguments: Option<&enzui_iced_core::localization::Arguments<'_>>) -> String {
    enzui_iced_core::localization::current()
        .try_text(key, arguments)
        .unwrap_or_else(|_| {
            static FALLBACK: std::sync::LazyLock<Localizer> = std::sync::LazyLock::new(localizer);
            FALLBACK.resolve(key, arguments).value
        })
}

pub(crate) fn localizer() -> Localizer {
    let mut catalog = CatalogBuilder::new();
    for (locale, source) in [
        ("en-US", include_str!("../assets/locales/en-US.ftl")),
        ("de", include_str!("../assets/locales/de.ftl")),
        ("ar", include_str!("../assets/locales/ar.ftl")),
    ] {
        catalog
            .add_resource(locale, source)
            .expect("valid bundled catalog");
    }
    Localizer::new(catalog.build(), preferred_locales(), Default::default())
}

#[cfg(test)]
mod tests {}
