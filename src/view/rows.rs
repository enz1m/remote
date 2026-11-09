//! Two-line saved connections with a right-aligned action/protocol column.

use super::*;

pub const SIDEBAR_TREE_ID_PREFIX: &str = "remote-app-sidebar-tree";

pub fn profile_row_body(
    enz: &EnzTheme,
    credentials: &dyn CredentialStore,
    p: &ConnectionProfile,
    _status: SessionStatus,
    backdrop: Color,
) -> Element<'static, Message> {
    let name = enz_text(crate::display::bound_display_name(&p.name))
        .size(TextSize::Callout)
        .single_line_elided()
        .full_width()
        .into_element();
    let mut details = iced::widget::row![
        enz_text(crate::display::bound_host_display(
            &p.host,
            p.port,
            p.protocol.default_port()
        ))
        .size(TextSize::Caption2)
        .color(enz.palette.text_muted_on(backdrop))
        .single_line_elided()
        .full_width()
        .into_element(),
    ]
    .spacing(enz.spacing.xs())
    .align_y(iced::Alignment::Center);
    let badge = crate::keyring::badge_for(credentials, p);
    if badge == crate::keyring::KeyringBadge::Present
        && let Some(icon) = badge.icon()
    {
        details = details.push(
            enz_icon(icon)
                .size(enz.sizing.icon_xs)
                .tint(enz.palette.text_muted_on(backdrop))
                .into_element(),
        );
    }
    let name = iced::widget::container(name)
        .height(enz.sizing.min_hit_target)
        .align_y(iced::Alignment::Center)
        .width(Length::Fill);
    let body = iced::widget::column![name, details]
        .spacing(0)
        .width(Length::Fill)
        .into();
    enzui_iced_widgets::tooltip::enz_tooltip(
        body,
        format!(
            "{}\n{} · {}",
            crate::display::bound_display_name(&p.name),
            p.protocol.label(),
            crate::display::bound_host_display(&p.host, p.port, p.protocol.default_port())
        ),
        iced::widget::tooltip::Position::Right,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn profile_row_trailing(
    row_identity: &str,
    p: &ConnectionProfile,
    status: SessionStatus,
    available: bool,
    closing: Option<crate::SessionCloseProgress>,
    credentials_pending: bool,
    hovered: bool,
    row_hovered: bool,
    enz: &EnzTheme,
    backdrop: Color,
) -> Element<'static, Message> {
    let (glyph, label, enabled) = if !available {
        ("ban", crate::protocol::NOT_IN_THIS_BUILD.to_owned(), false)
    } else if let Some(progress) = closing {
        (
            "hourglass",
            crate::session_view::close_progress_line(progress).to_owned(),
            false,
        )
    } else if credentials_pending
        && matches!(status, SessionStatus::Disconnected | SessionStatus::Error)
    {
        ("hourglass", "Saving credentials".into(), false)
    } else {
        let (name, _, glyph) = action_for(status);
        (
            if status == SessionStatus::Connected && !hovered {
                "plug-zap"
            } else {
                glyph
            },
            format!("{name} {}", crate::display::bound_display_name(&p.name)),
            true,
        )
    };
    let id = if enabled {
        format!("remote-app-session-action-{row_identity}")
    } else {
        format!("remote-app-session-status-{row_identity}")
    };
    let mut tokens =
        enzui_iced_widgets::toolbar_icon::ToolbarIconTokens::from_palette(&enz.palette);
    if status == SessionStatus::Connected && enabled {
        tokens.icon_color = enzui_iced_theme::Palette::with_contrast_on(
            backdrop,
            if hovered {
                enz.palette.tone_error_fg
            } else {
                enz.palette.tone_success_fg
            },
            3.0,
        );
        tokens.hover_color =
            enzui_iced_theme::Palette::with_contrast_on(backdrop, enz.palette.tone_error_fg, 3.0);
        tokens.pressed_color = tokens.hover_color;
    }
    // Preserve the action slot and protocol alignment while revealing only
    // this connection's glyph. The whole-folder hover must not reveal siblings.
    if !row_hovered && status != SessionStatus::Connected {
        tokens.icon_color = Color::TRANSPARENT;
        tokens.disabled_color = Color::TRANSPARENT;
    }
    tokens.hover_background = Color::TRANSPARENT;
    tokens.pressed_background = Color::TRANSPARENT;
    let button = enz_toolbar_icon(glyph, Message::SessionAction(p.id))
        .id(id.into())
        .tokens(tokens)
        .size(enz.sizing.min_hit_target, enz.sizing.icon_sm)
        .enabled(enabled)
        .label(label)
        .into_element();
    let identity = row_identity.to_owned();
    let leaving = identity.clone();
    let button = iced::widget::mouse_area(button)
        .on_enter(Message::SidebarActionHover(identity, true))
        .on_exit(Message::SidebarActionHover(leaving, false));
    let protocol = iced::widget::container(
        enz_text(p.protocol.label())
            .size(TextSize::Caption2)
            .color(enz.palette.text_muted_on(backdrop))
            .into_element(),
    )
    .padding(iced::Padding::ZERO.right((enz.sizing.min_hit_target - enz.sizing.icon_sm) / 2.0));
    iced::widget::container(iced::widget::column![button, protocol].align_x(iced::Alignment::End))
        .padding(
            iced::Padding::ZERO
                .right(enz.spacing.xs())
                .top(SpaceToken::Xxs.resolve(&enz.spacing))
                .bottom(SpaceToken::Xxs.resolve(&enz.spacing)),
        )
        .into()
}
