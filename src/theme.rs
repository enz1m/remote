//! Shared theme token adapters.

pub(crate) fn list_row_tokens(
    theme: &iced::Theme,
) -> enzui_iced_widgets::list_row_surface::ListRowSurfaceTokens {
    let mut tokens = enzui_iced_widgets::list_row_surface::ListRowSurfaceTokens::from_palette(
        &enzui_iced_theme::Palette::from_iced(theme),
    );
    tokens.row_radius = enzui_iced_widgets::theme_lookup::shape_radius(theme, |shape| shape.row);
    tokens
}

/// Sidebar rows use the shared row shape and a quiet accent selection.
pub(crate) fn sidebar_row_tokens(
    theme: &iced::Theme,
) -> enzui_iced_widgets::list_row_surface::ListRowSurfaceTokens {
    let mut tokens = list_row_tokens(theme);
    tokens.selected_background = enzui_iced_theme::Palette::from_iced(theme).accent_soft;
    tokens
}

/// The enclosing folder group owns hover chrome for its header.
pub(crate) fn sidebar_folder_tokens(
    theme: &iced::Theme,
) -> enzui_iced_widgets::list_row_surface::ListRowSurfaceTokens {
    let mut tokens = sidebar_row_tokens(theme);
    tokens.hover_overlay = iced::Color::TRANSPARENT;
    tokens
}
