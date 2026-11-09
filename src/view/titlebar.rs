//! Titlebar and sidebar panes.

use super::*;

pub const TITLEBAR_EMPTY_TITLE: &str = "Remote";

pub(crate) fn titlebar(app: &App) -> Element<'_, Message> {
    let selected = app
        .selected_profile
        .and_then(|pid| app.profiles.iter().find(|x| x.id == pid));

    let mut bar = enz_title_bar().id("remote-app-window");
    bar = match selected {
        Some(p) if app.has_connected_session(p.id) => bar,
        Some(p) => {
            let name = enz_text(crate::display::bound_display_name(&p.name))
                .size(TextSize::Body)
                .weight_rung(enzui_iced_theme::WeightRung::Semibold)
                .single_line_elided()
                .full_width()
                .into_element();
            let address = enz_vstack(vec![
                enz_text(p.protocol.label())
                    .size(TextSize::Caption)
                    .align(enzui_iced_widgets::TextAlign::End)
                    .width(Length::Shrink.max(180))
                    .into_element(),
                enz_text(crate::display::bound_host_display(
                    &p.host,
                    p.port,
                    p.protocol.default_port(),
                ))
                .size(TextSize::Caption2)
                .tone(enzui_iced_widgets::TextTone::Muted)
                .align(enzui_iced_widgets::TextAlign::End)
                .single_line_elided()
                .width(Length::Shrink.max(180))
                .into_element(),
            ])
            .gap(SpaceToken::None)
            .cross(CrossAlign::End)
            .into_element();
            bar.push(
                iced::widget::Row::new()
                    .push(name)
                    .push(iced::widget::container(address).width(Length::Shrink.max(180)))
                    .spacing(app.enz_theme.spacing.sm())
                    .align_y(iced::Alignment::Center)
                    .width(Length::Fill),
            )
        }
        None => bar.title(TITLEBAR_EMPTY_TITLE),
    }
    .fluid_content(0.0);

    let mut actions = Vec::new();
    if let Some(p) = selected {
        if let Some(display) = crate::session_view::display_controls(app, p) {
            bar = bar.leading(display).fluid_content(96.0);
        }
        actions.extend(crate::session_view::session_actions(app, p));
        let pid = p.id;
        let status = app.session_status_for(pid);
        actions.push(connection_edit_action_item(
            Descriptor::new("connection.edit"),
            pid,
        ));
        if app.backends.available(p.protocol) && app.close_progress_for(pid).is_none() {
            actions.push(connection_session_action_item(
                Descriptor::new("connection.session").pinned(),
                pid,
                status,
                app.credentials_pending(pid),
            ));
        }
    }

    actions.push(ActionItem::command(
        Descriptor::new("remote.help").always_overflow(),
        Action::new(
            "remote.help",
            Message::AppCommand(crate::shortcuts::Command::Help),
        )
        .with_label(crate::l10n::text("remote-keyboard-shortcuts"))
        .with_icon(Icon::named("keyboard")),
    ));
    bar.actions(actions, Message::ToggleTitlebarOverflow)
        .action_dismiss(Message::CloseTitlebarOverflow)
        .overflow_open(app.titlebar_overflow_open)
        .action_menu_id_prefix("remote-app-titlebar-actions")
        .action_overflow_trigger_id("remote-app-titlebar-overflow")
        .into_element()
}

pub(crate) fn sidebar_titlebar(app: &App) -> Element<'_, Message> {
    let actions = iced::widget::Row::new()
        .push(
            enz_toolbar_icon("zap", Message::QuickConnectOpen)
                .tooltip(crate::l10n::text("remote-quick-connect"))
                .aria_label(crate::l10n::text("remote-quick-connect"))
                .id(quick_connect_button_id())
                .into_element(),
        )
        // The import menu's bar reserves room after its trigger; a toolbar
        // icon's box keeps the header's icons on one 32 px pitch.
        .push(
            iced::widget::container(crate::sidebar_view::import_button(app))
                .width(Length::Fixed(28.0)),
        )
        .push(
            enz_toolbar_icon("action.add", Message::FormOpenAdd)
                .tooltip(crate::l10n::text("remote-new-connection"))
                .aria_label(crate::l10n::text("remote-new-connection"))
                .id(add_button_id())
                .into_element(),
        )
        // The titlebar icon gap, as between every other titlebar's icons.
        .spacing(enzui_iced_widgets::title_bar::PANE_HEADER_ICON_GAP)
        .align_y(iced::Alignment::Center);
    // The framework's pane header: the title on the sidebar's content edge,
    // the actions one icon gap from the sidebar toggle.
    enz_title_bar()
        .title(crate::l10n::text("remote-connections"))
        .title_heading(HeadingLevel::Page)
        .push(actions)
        .id("remote-app-sidebar-header")
        .into_element()
}

pub(crate) fn sidebar(app: &App) -> Element<'_, Message> {
    let enz = &app.enz_theme;

    let search: Element<'_, Message> = enz_search_field(&app.search_query, Message::SearchChanged)
        .placeholder(crate::l10n::text("remote-search-connections"))
        .id("remote-app-connection-search")
        .size(TextFieldSize::Sm)
        .chrome(enzui_iced_widgets::search_field::SearchFieldChrome::Ghost)
        .on_clear(Message::SearchChanged(String::new()))
        .into();
    let search = enzui_iced_widgets::surface::enz_surface(search)
        .width(Length::Fill)
        .tone(enzui_iced_widgets::surface::SurfaceTone::Surface)
        .radius_resolved(|theme| {
            enzui_iced_widgets::theme_lookup::shape_radius(theme, |shape| shape.search_field).into()
        })
        .into_element();

    let groups = crate::sidebar_view::grouping(app);

    let list_children = crate::sidebar_view::grouped_list(app, &groups);

    let list = enz_vstack(list_children)
        .gap(SpaceToken::Xs)
        .cross(CrossAlign::Stretch)
        .spacing_scale(enz.spacing)
        .into_element();

    let discover: Element<'_, Message> = enz_vstack(
        std::iter::once(enz_divider().into_element())
            .chain(crate::sidebar_view::discovered_section(app))
            .collect::<Vec<_>>(),
    )
    .gap(SpaceToken::Xs)
    .cross(CrossAlign::Stretch)
    .spacing_scale(enz.spacing)
    .into_element();

    let list_scroll: Element<'_, Message> = enz_scroll_view(
        enzui_iced_widgets::surface::enz_surface(list)
            .width(Length::Fill)
            .tone(enzui_iced_widgets::surface::SurfaceTone::Transparent)
            .into_element(),
    )
    .axis(Axis::Vertical)
    .height(Length::Fill)
    .into();

    enz_sidebar_content()
        .push(search)
        .push(list_scroll)
        .push(discover)
        .spacing_scale(enz.spacing)
        .width(Length::Fill)
        .height(Length::Fill)
        .into_element()
}
