//! Shell assembly.

use super::*;

/// Flush content with an independent sidebar header.
pub(crate) fn shell_tokens(enz: &EnzTheme) -> ShellTokens {
    ShellTokens {
        sidebar_width: enz.sizing.sidebar_width,
        sidebar_width_adaptive: false,
        sidebar_header: SidebarHeader::Inside,
        ..ShellTokens::flush_page()
    }
}

/// Profile navigation beside a flush session pane.
pub fn shell(app: &App) -> Element<'_, Message> {
    let enz = &app.enz_theme;

    // Fullscreen gives the session the whole window. The branch lives here because
    // the chrome it removes is owned by `enz_app_shell`; the overlays still wrap it
    // so a pending confirmation stays visible.
    if let Some(p) = fullscreen_profile(app) {
        return overlays(app, fullscreen_surface(app, p));
    }

    let builder =
        enz_app_shell_with_geometry(move |geometry| content_area(app, geometry.content_width))
            .layout(ShellLayout::TitlebarSidebarContent)
            .tokens(shell_tokens(enz))
            .breakpoints(enz.breakpoints)
            .state(app.nav)
            .titlebar_with_geometry(move |_| titlebar(app))
            .sidebar_titlebar(move || sidebar_titlebar(app))
            .sidebar(move || sidebar(app))
            .sidebar_label(crate::l10n::text("remote-connections"))
            .on_window_gesture(Message::Window)
            .on_sidebar_state(Message::SidebarState)
            .on_dismiss_overlay(Message::CloseSidebarOverlay);

    let shell = builder.into_element();
    overlays(app, shell)
}

/// The profile whose session is showing fullscreen, if any.
///
/// Scoped to the selected profile so a background session left fullscreen does
/// not blank the chrome of the visible connection.
fn fullscreen_profile(app: &App) -> Option<&ConnectionProfile> {
    let pid = app.selected_profile?;
    let profile = app.profiles.iter().find(|x| x.id == pid)?;
    let session = app.sessions.iter().find(|s| s.profile_id == pid)?;
    session.fullscreen.then_some(profile)
}

/// Fullscreen keeps an exit control above the desktop without reserving shell space.
fn fullscreen_surface<'a>(app: &'a App, p: &'a ConnectionProfile) -> Element<'a, Message> {
    iced::widget::stack![
        session_pane(app, p, 0.0),
        enz_toolbar_icon("minimize", Message::ToggleSessionFullscreen(p.id))
            .label(crate::session::fullscreen_label(true))
            .id(iced::advanced::widget::Id::from(format!(
                "remote-app-session-fullscreen-{}",
                p.id
            )))
            .into_element(),
    ]
    .into()
}

fn overlays<'a>(app: &'a App, shell: Element<'a, Message>) -> Element<'a, Message> {
    let mut host = app
        .context_menu
        .menu
        .host(shell, Message::ContextMenuEvent)
        .id_prefix("remote-app-context-menu");
    if let Some(label) = crate::context_menu::menu_label(app) {
        host = host.label(label);
    }
    if let Some(invoker) = crate::context_menu::menu_invoker_id(app) {
        host = host.invoker(invoker);
    }
    let with_menu = host.into_element();

    let with_quick = crate::quick_connect_view::present(app, with_menu);
    let with_form = crate::form_view::present(app, with_quick);
    // Presented last so it stacks above the connection form, whose Delete button
    // opens it.
    let with_confirm = delete_confirm(app, with_form);
    let with_help = app.dialogs.view_with(
        with_confirm,
        |_| crate::shortcuts::help(app),
        Message::HelpDialog,
        |_, host| host.label(crate::l10n::text("remote-keyboard-shortcuts")),
    );
    let notices = iced::widget::Column::new()
        .extend(
            [
                crate::sidebar_view::close_hold_toast(app),
                crate::sidebar_view::db_boot_error_toast(app),
                crate::sidebar_view::transfer_toast(app),
                crate::sidebar_view::credential_toast(app),
                crate::sidebar_view::wol_toast(app),
            ]
            .into_iter()
            .flatten(),
        )
        .push(app.toasts.view().map(Message::Toast))
        .spacing(app.enz_theme.spacing.xs());
    enzui_iced_widgets::toast_host::enz_toast_layer(
        with_help,
        Some(notices.into()),
        enzui_iced_widgets::toast_host::ToastOverlayPlacement::default(),
    )
}

/// The delete-profile confirmation.
///
/// Deletion removes the stored row and destroys its keyring secret. The scoped
/// host makes focus operations decline once the dialog is dismissed. `alert` is
/// false, so Escape and the scrim cancel.
fn delete_confirm<'a>(app: &'a App, background: Element<'a, Message>) -> Element<'a, Message> {
    enzui_iced_widgets::modal_host::host_when_shown(
        background,
        app.pending_delete_profile.map(|id| delete_dialog(app, id)),
        |dialog, background| {
            dialog.into_scoped_host(
                background,
                enzui_iced_widgets::modal_host::presentation_scope_id(DELETE_CONFIRM_SCOPE),
            )
        },
        |event| {
            Message::DeleteProfileConfirmEvent(
                enzui_iced_widgets::confirm_dialog::ConfirmDialogEvent::from_host(event),
            )
        },
    )
}

fn delete_dialog<'a>(
    app: &'a App,
    id: uuid::Uuid,
) -> enzui_iced_widgets::confirm_dialog::EnzConfirmDialog<'a, Message> {
    let name = app.profiles.iter().find(|p| p.id == id).map_or_else(
        || "this connection".to_string(),
        |p| crate::display::bound_display_name(&p.name),
    );
    let (title, body, confirm_label) = if app.delete_without_credentials_warning {
        (
            format!("Delete {name} without checking its password?"),
            "The system keyring is unavailable, so Remote cannot confirm or \
             remove this connection's stored password. Deleting only the \
             connection may leave a password in the keyring.",
            "Delete anyway",
        )
    } else {
        (
            format!("Delete {name}?"),
            "The saved connection and its stored password will be removed from \
             this computer. This cannot be undone.",
            "Delete",
        )
    };
    enzui_iced_widgets::confirm_dialog::enz_confirm_dialog(
        title,
        body,
        &app.delete_confirm_state,
        Message::DeleteProfileConfirmEvent,
    )
    .confirm_label(confirm_label)
    .cancel_label("Cancel")
    .destructive(true)
    // The preset's fallback namespace is the title, which carries the
    // profile's name and changes with the credentials warning: an assistive
    // technology that resolved a control would lose it on a rename.
    .id_prefix(DELETE_CONFIRM_SCOPE)
}
