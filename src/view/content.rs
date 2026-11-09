//! Content and session pane.

use super::*;

pub(crate) fn content_area<'a>(app: &'a App, content_width: f32) -> Element<'a, Message> {
    let enz = &app.enz_theme;

    if let Some(pid) = app.selected_profile
        && let Some(p) = app.profiles.iter().find(|x| x.id == pid)
    {
        return session_pane(app, p, content_width);
    }

    let page = enz_status_page("No active remote session")
        .icon("monitor")
        .description(if app.profiles.is_empty() {
            "Add a connection to open a session.".to_string()
        } else {
            format!(
                "Select a saved connection, then choose Connect. {} profiles saved.",
                app.profiles.len()
            )
        })
        .primary_action(crate::sidebar_view::new_connection_action())
        .id_prefix("remote-app-empty")
        .into_element();

    enzui_iced_widgets::content_pane::enz_content_pane(vec![
        enz_center(page).padding(enz.spacing.xl()).into(),
    ])
    .tokens(enzui_iced_widgets::content_pane::ContentPaneTokens {
        pane_background: enz.palette.background,
    })
    .content_padding(0.0)
    .into()
}

pub(crate) fn session_pane<'a>(
    app: &'a App,
    p: &'a ConnectionProfile,
    _content_width: f32,
) -> Element<'a, Message> {
    let enz = &app.enz_theme;

    let surface_card: Element<'a, Message> = crate::session_view::surface_body(app, p);

    let body = surface_card;
    enzui_iced_widgets::content_pane::enz_content_pane(vec![body])
        .tokens(enzui_iced_widgets::content_pane::ContentPaneTokens {
            pane_background: enz.palette.background,
        })
        .spacing_scale(enz.spacing)
        .into()
}

pub const EDIT_ICON: &str = "pencil";

pub(crate) fn action_for(status: SessionStatus) -> (&'static str, ButtonKind, &'static str) {
    match status {
        SessionStatus::Disconnected => ("Connect", ButtonKind::Accent, "plug"),
        SessionStatus::Connecting => ("Cancel", ButtonKind::Secondary, "x"),
        SessionStatus::Connected => ("Disconnect", ButtonKind::Secondary, "unplug"),
        SessionStatus::Error => ("Retry", ButtonKind::Accent, "refresh-cw"),
    }
}

pub(crate) fn connection_edit_action_item<'a>(
    descriptor: Descriptor,
    pid: uuid::Uuid,
) -> ActionItem<'a, Message> {
    ActionItem::with_inline(
        descriptor,
        Action::new("connection.edit", Message::FormOpenEdit(pid))
            .with_label(crate::l10n::text("remote-edit"))
            .with_icon(Icon::named(EDIT_ICON)),
        move |_, _| {
            enz_toolbar_icon(EDIT_ICON, Message::FormOpenEdit(pid))
                .tooltip(crate::l10n::text("remote-edit"))
                .aria_label(crate::l10n::text("remote-edit"))
                .id(edit_button_id(pid))
                .into_element()
        },
    )
}

pub(crate) fn connection_session_action_item<'a>(
    descriptor: Descriptor,
    pid: uuid::Uuid,
    status: SessionStatus,
    credentials_pending: bool,
) -> ActionItem<'a, Message> {
    let pending =
        credentials_pending && matches!(status, SessionStatus::Disconnected | SessionStatus::Error);
    let (action_label, action_kind, action_icon) = if pending {
        ("Saving credentials", ButtonKind::Quiet, "hourglass")
    } else {
        action_for(status)
    };
    ActionItem::with_inline(
        descriptor.with_enabled(!pending),
        Action::new("connection.session", Message::SessionAction(pid))
            .with_label(action_label)
            .with_enabled(!pending)
            .with_icon(Icon::named(action_icon)),
        move |_, _| {
            let _ = action_kind;
            let control = enz_toolbar_icon(action_icon, Message::SessionAction(pid))
                .enabled(!pending)
                .tooltip(action_label)
                .aria_label(action_label)
                .id(session_action_button_id(pid))
                .into_element();
            if status == SessionStatus::Connected {
                iced::widget::Row::new()
                    .push(
                        iced::widget::container(enz_divider().vertical().into_element())
                            .height(18)
                            .padding(iced::Padding::ZERO.right(6)),
                    )
                    .push(control)
                    .align_y(iced::Alignment::Center)
                    .into()
            } else {
                control
            }
        },
    )
}
