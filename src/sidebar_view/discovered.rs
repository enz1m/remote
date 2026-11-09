//! Discovered section.

use super::*;

/// Widget id of the Save action on the discovered host identified by `key`.
pub(crate) fn discovered_save_id(key: &str) -> iced::advanced::widget::Id {
    enzui_iced_core::identity::OwnerId::of_kind("remote-app-discovered-host", key).id("save")
}

/// The Discovered section: header, scan chip, and one row per host.
///
/// Always present, small when empty, so the scan trigger is there before any
/// result exists.
pub fn discovered_section(app: &App) -> Vec<Element<'_, Message>> {
    let enz = &app.enz_theme;

    let tip = scan_tooltip(app.scanning);
    let header = enz_toolbar_row()
        .start(
            enzui_iced_widgets::section_header::enz_section_header(DISCOVER_HEADER)
                .title_size(enz.typography.label_size)
                .width(Length::Shrink)
                .tone(TextTone::Muted)
                .into_element(),
        )
        .end(
            enz_toolbar_icon(
                if app.scanning { "loader" } else { "radar" },
                if app.scanning {
                    Message::ScanCancel
                } else {
                    Message::ScanNetwork
                },
            )
            .tooltip(tip)
            .aria_label(tip)
            // Stays pressable while a browse runs, because what it does then
            // is abandon it. A disabled chip would leave the only control over
            // a bounded network operation unreachable for its duration.
            .enabled(true)
            .id(iced::advanced::widget::Id::new("remote-app-scan"))
            .into_element(),
        )
        .inset(SpaceToken::Sm)
        .zone_spacing(SpaceToken::Xs)
        .center_absolute(false)
        .spacing_scale(enz.spacing)
        .sizing_scale(enz.sizing)
        .into_element();

    let mut out: Vec<Element<'_, Message>> = vec![header];

    // A machine that could not look outranks every line about the network: a
    // browse that never ran has learned nothing, and "no hosts found" over a
    // host with no daemon is a claim about somebody else's network.
    let line = app.discovery_refusal.map_or_else(
        || {
            crate::discovery::scan_status_line(
                app.scanning,
                app.discovered.len(),
                app.scan_completed,
            )
        },
        |refusal| Some(refusal.banner_message()),
    );
    if let Some(line) = line {
        let text: Element<'_, Message> = enz_text(line)
            .size(TextSize::Caption2)
            .tone(TextTone::Muted)
            .into_element();
        out.push(
            SemanticsContainer::leaf(text, Announcement::Status.region(line))
                .id(iced::advanced::widget::Id::new("remote-discovery-status"))
                .into(),
        );
    }

    for host in &app.discovered {
        out.push(discovered_row(app, host));
    }
    out
}

/// One discovered host: name, `PROTO · host:port`, and a Save chip.
///
/// A discovered host has no session or profile to select, so the row's
/// activation is the Save action itself.
fn discovered_row<'a>(app: &'a App, host: &'a DiscoveredHost) -> Element<'a, Message> {
    let enz = &app.enz_theme;
    let key = host.key();

    let text_col = enz_vstack(vec![
        enz_text(&host.name)
            .size(TextSize::Caption)
            // App-supplied names are bounded to one audited elided line
            // (`.single_line_elided()` publishes a `TextElision` finding on clamp)
            // instead of wrapping into the row below.
            .single_line_elided()
            .full_width()
            .into_element(),
        enz_text(host.subtitle())
            .size(TextSize::Caption2)
            .tone(TextTone::Muted)
            // Both lines stay, with the subtitle clamped to one audited elided line;
            // the accessible label keeps the full string.
            .single_line_elided()
            .full_width()
            .into_element(),
    ])
    .gap(SpaceToken::Xxs)
    .cross(CrossAlign::Start)
    // Report a Fill width so the elided lines have a bound to elide against (a
    // Shrink column always fits its own single line, so nothing would clamp)
    // and so the trailing Save chip pins to the row's trailing edge.
    .hug_content(false)
    .spacing_scale(enz.spacing)
    .into_element();

    let save = enz_button("Save", Message::SaveDiscovered(key.clone()))
        .kind(ButtonKind::Secondary)
        .size(ButtonSize::Sm)
        .aria_label(format!("Save {}", host.name))
        .id(discovered_save_id(&key))
        .into_element();

    // The Fill-width `text_col` above already claims the leading extent, so the
    // Save chip pins to the trailing edge without a separate `Space::Fill`
    // spacer (a second Fill would split the row 50/50 and squeeze both).
    let inner = enz_hstack(vec![text_col, save])
        .gap(SpaceToken::Xs)
        .cross(CrossAlign::Center)
        .hug_content(false)
        .spacing_scale(enz.spacing)
        .into_element();

    enz_list_row_surface(inner, Message::SaveDiscovered(key))
        .selectable(false)
        .content_height(true)
        .label(host.name.clone())
        .id_prefix("remote-app-discovered")
        .tokens_resolved(crate::theme::list_row_tokens)
        .into()
}
