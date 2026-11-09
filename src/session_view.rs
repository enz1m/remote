//! Remote desktop presentation and titlebar session controls.

use enzui_iced_theme::SpaceToken;
use enzui_iced_widgets::center::enz_center;
use enzui_iced_widgets::enz_text::{TextSize, TextTone, enz_text};
use enzui_iced_widgets::menu_button::enz_menu_button;
use enzui_iced_widgets::stack::{CrossAlign, enz_vstack};
use enzui_iced_widgets::status_page::{StatusPageTone, StatusPageVariant, enz_status_page};
use enzui_iced_widgets::toolbar_icon::enz_toolbar_icon;
use iced::Element;

use crate::model::{ConnectionProfile, Session};
use crate::protocol::PointerButton;
use crate::session::{SurfaceBody, fullscreen_label};
use crate::{App, Message, SessionCloseProgress};

/// What the surface says while a severed connection is still being ended.
pub const CLOSING_LINE: &str = "Disconnecting\u{2026}";

/// What it says when the join that would have proved a severed VNC
/// transport's workers ended was lost.
///
/// Says what is known and stops: the socket is shut down, and the shutdown of
/// the threads that held it is unconfirmed. It promises no retry of its own,
/// because there is none to offer — the close surface's Retry and Keep Open
/// are the routes, and this row is not one of them.
pub const UNCONFIRMED_LINE: &str =
    "This VNC connection was severed, but worker shutdown could not be confirmed.";

/// The one line a closing connection shows.
///
/// The single mapping from the app's typed progress to words, so the row and
/// any test that asserts what the row says read the same constant. None of
/// the three is an idle reading.
#[must_use]
pub fn close_progress_line(progress: SessionCloseProgress) -> &'static str {
    match progress {
        SessionCloseProgress::Closing => CLOSING_LINE,
        SessionCloseProgress::Unconfirmed => UNCONFIRMED_LINE,
    }
}

/// Session controls use the shell's measured titlebar overflow.
pub(crate) fn session_actions<'a>(
    app: &'a App,
    p: &'a ConnectionProfile,
) -> Vec<enzui_iced_widgets::action_bar::ActionItem<'a, Message>> {
    use enzui_iced_core::action_overflow::Descriptor;
    use enzui_iced_core::{Action, Icon};
    use enzui_iced_widgets::action_bar::ActionItem;
    let Some(session) = app.sessions.iter().find(|s| s.profile_id == p.id) else {
        return Vec::new();
    };
    let pid = p.id;
    let mut actions = Vec::new();
    if matches!(
        p.protocol,
        crate::model::Protocol::Vnc
            | crate::model::Protocol::Rdp
            | crate::model::Protocol::Moonlight
    ) {
        actions.push(session_icon(
            "session.clipboard-send",
            pid,
            "action.copy",
            if p.protocol == crate::model::Protocol::Moonlight {
                "Type clipboard text".into()
            } else {
                crate::l10n::text("remote-send-clipboard-as-keystrokes")
            },
            Message::SendClipboardToSession(pid),
            session.can_send_clipboard_as_keystrokes(),
            false,
        ));
    }
    if matches!(
        p.protocol,
        crate::model::Protocol::Vnc
            | crate::model::Protocol::Rdp
            | crate::model::Protocol::Spice
            | crate::model::Protocol::RustDesk
    ) {
        actions.push(session_icon(
            "session.clipboard-toggle",
            pid,
            if session.clipboard_enabled {
                "clipboard-check"
            } else {
                "clipboard-x"
            },
            session.clipboard_action_label().into(),
            Message::ToggleSessionClipboard(pid),
            true,
            session.clipboard_enabled,
        ));
    }
    // Saving a local screenshot is occasional, so it waits in the overflow
    // rather than taking titlebar width from the live controls.
    let has_picture = app
        .frames
        .get(&pid)
        .is_some_and(|sink| sink.displayed().is_some());
    actions.push(ActionItem::command(
        Descriptor::new("session.screenshot")
            .always_overflow()
            .with_enabled(has_picture),
        Action::new("session.screenshot", Message::SaveScreenshot(pid))
            .with_label(crate::l10n::text("remote-save-screenshot"))
            .with_icon(Icon::named("camera"))
            .with_enabled(has_picture),
    ));
    let immutable_view_only =
        p.protocol != crate::model::Protocol::Vnc && session.negotiated.view_only;
    actions.push(session_icon(
        "session.input",
        pid,
        if session.input_mode.forwards_input() {
            "eye-off"
        } else {
            "eye"
        },
        session.input_mode.action_label().into(),
        Message::ToggleSessionInputMode(pid),
        !immutable_view_only,
        !session.input_mode.forwards_input(),
    ));
    actions.push(ActionItem::with_inline(
        Descriptor::new("session.keystrokes")
            .pinned()
            .with_enabled(session.input_mode.forwards_input()),
        Action::new(
            "session.keystrokes",
            Message::KeystrokeMenu(enzui_iced_widgets::menu_button::MenuButtonEvent::Open(
                enzui_iced_core::menu_model::OpenCause::Pointer,
            )),
        )
        .with_label("Send keystrokes")
        .with_icon(Icon::named("keyboard"))
        .with_enabled(session.input_mode.forwards_input()),
        move |_, _| {
            enz_menu_button(
                "",
                &app.keystroke_model,
                &app.keystroke_menu,
                Message::KeystrokeMenu,
            )
            .aria_label("Send keystrokes")
            .kind(enzui_iced_widgets::menu_button::MenuButtonKind::Toolbar)
            .trigger_icon("keyboard")
            .enabled(session.input_mode.forwards_input())
            .menu_id(iced::advanced::widget::Id::from(format!(
                "remote-app-session-keystrokes-{pid}"
            )))
            .into_element()
        },
    ));
    actions
}

pub(crate) fn display_controls<'a>(
    app: &'a App,
    p: &'a ConnectionProfile,
) -> Option<Element<'a, Message>> {
    let session = app
        .sessions
        .iter()
        .find(|s| s.profile_id == p.id && s.status == crate::model::SessionStatus::Connected)?;
    if p.protocol == crate::model::Protocol::Ssh {
        return None;
    }
    let pid = p.id;
    let mut buttons = vec![
        enz_toolbar_icon(
            if session.scaling.scales_to_fit() {
                "maximize"
            } else {
                "minimize-2"
            },
            Message::ToggleSessionScaling(pid),
        )
        .label(session.scaling.action_label())
        .active(session.scaling.scales_to_fit())
        .id(format!("remote-app-session-scaling-{pid}").into())
        .into_element(),
    ];
    if matches!(
        p.protocol,
        crate::model::Protocol::Rdp | crate::model::Protocol::Spice
    ) && let Some(generation) = app.session_streams.get(&pid).copied()
    {
        buttons.push(
            enz_toolbar_icon("monitor-cog", Message::ToggleSessionResize(pid, generation))
                .label(if session.dynamic_resize {
                    "Resize guest to window: on (click to disable)"
                } else {
                    "Resize guest to window: off (click to enable)"
                })
                .active(session.dynamic_resize)
                .enabled(session.input_mode.forwards_input() && !session.negotiated.view_only)
                .id(format!("remote-app-session-resize-{pid}").into())
                .into_element(),
        );
    }
    buttons.push(
        enz_toolbar_icon(
            if session.fullscreen {
                "minimize"
            } else {
                "expand"
            },
            Message::ToggleSessionFullscreen(pid),
        )
        .label(fullscreen_label(session.fullscreen))
        .active(session.fullscreen)
        .id(format!("remote-app-session-fullscreen-{pid}").into())
        .into_element(),
    );
    Some(enzui_iced_widgets::titlebar_icon_group::enz_titlebar_icon_group(buttons).into_element())
}

fn session_icon<'a>(
    id: &'static str,
    pid: uuid::Uuid,
    icon: &'static str,
    label: String,
    message: Message,
    enabled: bool,
    active: bool,
) -> enzui_iced_widgets::action_bar::ActionItem<'a, Message> {
    use enzui_iced_core::action_overflow::Descriptor;
    use enzui_iced_core::{Action, Icon};
    use enzui_iced_widgets::action_bar::ActionItem;
    ActionItem::with_inline(
        Descriptor::new(id).with_enabled(enabled),
        Action::new(id, message.clone())
            .with_label(label)
            .with_icon(Icon::named(icon))
            .with_enabled(enabled),
        move |action, _| {
            enz_toolbar_icon(icon, action.message().clone())
                .label(action.label())
                .enabled(action.is_enabled())
                .active(active)
                .id(iced::advanced::widget::Id::from(format!(
                    "remote-app-session-{}-{pid}",
                    id.strip_prefix("session.").unwrap_or(id)
                )))
                .into_element()
        },
    )
    .group("Input and clipboard")
}

/// The recessed card's contents: four distinct states.
///
/// Read from [`Session::surface_body`] so this file cannot invent a fifth
/// reading. A stalled connection shown as "no signal" or a failed one as
/// "loading" would hide what happened.
pub fn surface_body<'a>(app: &'a App, p: &'a ConnectionProfile) -> Element<'a, Message> {
    let session = app.sessions.iter().find(|s| s.profile_id == p.id);
    let body = match session {
        Some(s) => s.surface_body(),
        // No session at all — not "disconnected with a stale message".
        None => SurfaceBody::NotStarted,
    };

    if let (SurfaceBody::Live { .. }, Some(session)) = (&body, session) {
        let picture = framebuffer_surface(app, p, session);
        return picture;
    }

    if matches!(body, SurfaceBody::Loading | SurfaceBody::NoSignal) {
        let label = if matches!(body, SurfaceBody::Loading) {
            "Connecting…"
        } else {
            "Waiting for desktop…"
        };
        let progress = iced::widget::column![
            enzui_iced_widgets::spinner::enz_spinner()
                .size(app.enz_theme.sizing.icon_lg)
                .label(label)
                .into_element(),
            enz_text(label).size(TextSize::Callout).into_element(),
            enz_text(format!("{} · {}", p.protocol.label(), bounded_host(p)))
                .size(TextSize::Caption)
                .tone(TextTone::Muted)
                .into_element(),
        ]
        .spacing(app.enz_theme.spacing.sm())
        .align_x(iced::Alignment::Center);
        return enz_center(progress)
            .padding(app.enz_theme.spacing.lg())
            .into();
    }

    let title = body.title(p.protocol.label());
    let description = describe(&body, p, session);

    let page = enz_status_page(title)
        .description(description)
        .variant(StatusPageVariant::Inline)
        .tone(if body.is_error() {
            StatusPageTone::Error
        } else {
            StatusPageTone::Empty
        })
        .id_prefix("remote-app-session")
        .into_element();

    // The negotiated picture parameters under the hero: the Quality picker's
    // render-side consumer, pinned by
    // `render_tests::the_session_surface_reports_the_negotiated_quality`. Gated on
    // `has_negotiated()` so defaults are never shown as negotiated facts.
    let mut children: Vec<Element<'a, Message>> = vec![page];
    if let Some(s) = session
        && body.has_negotiated()
    {
        children.push(
            enz_text(s.negotiated.summary())
                .size(TextSize::Caption)
                .tone(TextTone::Subtle)
                .into_element(),
        );
    }
    let closing = app.close_progress_for(p.id);
    if let Some(retry) = app
        .reconnect_presentation(p.id)
        .filter(|_| closing.is_none())
    {
        if retry.offers_routes() {
            children.push(
                enzui_iced_widgets::button::enz_button("Retry now", Message::SessionAction(p.id))
                    .into_element(),
            );
            children.push(
                enzui_iced_widgets::button::enz_button(
                    "Stop reconnecting",
                    Message::ReconnectCancel(p.id),
                )
                .into_element(),
            );
        }
        children.push(
            enz_text(retry.label())
                .size(TextSize::Caption)
                .tone(TextTone::Subtle)
                .into_element(),
        );
        if let Some(detail) = retry.body() {
            children.push(
                enz_text(detail)
                    .size(TextSize::Caption)
                    .tone(TextTone::Subtle)
                    .into_element(),
            );
        }
    }

    // The transport is up and the app says so; what this line adds is that the
    // next launch will not know when it happened.
    if let Some(debt) = app.recency_debt_for(p.id) {
        children.push(
            enz_text(debt.summary())
                .size(TextSize::Caption)
                .tone(TextTone::Subtle)
                .into_element(),
        );
    }

    // A severed connection is not a closed one: while its client or its
    // workers are still being ended, the surface says so rather than reading
    // as idle. Both protocols arrive here, each in its own words.
    if let Some(progress) = closing {
        children.push(
            enz_text(close_progress_line(progress))
                .size(TextSize::Caption)
                .tone(TextTone::Subtle)
                .into_element(),
        );
    }

    // `.hug_content(false)` + `CrossAlign::Stretch` are required: a hugging
    // `enz_vstack` reports `Length::Shrink`, and the inline `enz_status_page`'s
    // `Length::Fill` width then resolves to zero, painting an empty card while
    // semantics assertions still pass.
    let stack = enz_vstack(children)
        .gap(SpaceToken::Sm)
        .cross(CrossAlign::Stretch)
        .hug_content(false)
        .spacing_scale(app.enz_theme.spacing)
        .into_element();

    enz_center(stack).padding(app.enz_theme.spacing.lg()).into()
}

/// The live picture: the displayed framebuffer's exact pixels, the slot
/// measurement that positions them, and the pointer route back to the remote.
///
/// The retained image handle changes only when an admitted frame is presented;
/// pointer movement and chrome updates reuse its GPU allocation.
///
/// A `Sensor` reports the slot's actual size, used both for pointer projection
/// and for the backend resize request; the window size would be off by the
/// sidebar width.
///
/// The `mouse_area` reports positions in its own coordinates, the space
/// [`crate::framebuffer::remote_pixel`] expects. Gestures carry this profile's id,
/// and the reducer refuses anything but a connected, interactive session with a
/// frame and a measured slot.
fn framebuffer_surface<'a>(
    app: &'a App,
    p: &'a ConnectionProfile,
    session: &'a Session,
) -> Element<'a, Message> {
    use crate::session::PointerGesture;
    use enzui_iced_widgets::image::{EnzImageFit, enz_image_handle};

    let pid = p.id;
    let Some(handle) = app.frame_handle(pid).cloned() else {
        return enz_text("Waiting for a desktop frame").into_element();
    };
    let fit = match session.scaling {
        crate::session::ScalingMode::ScaleToFit => EnzImageFit::Contain,
        crate::session::ScalingMode::OriginalSize => EnzImageFit::None,
    };

    let picture = enz_image_handle(handle)
        .fit(fit)
        .placeholder_background(app.enz_theme.palette.background)
        // The accessible name of a remote desktop is what it is a picture of.
        // Without it the surface is a nameless `Role::Image` and a screen
        // reader announces "image" over the largest thing on screen.
        .alt_text({
            // Screen-reader users get this name instead of the picture, so it states what is
            // shown, the negotiated parameters, and whether the connection is unprotected.
            let mut name = format!(
                "{} desktop, {}\u{00d7}{}, {}",
                p.protocol.label(),
                session.surface_size.0,
                session.surface_size.1,
                session.scaling.label(),
            );
            let negotiated = session.negotiated.summary();
            if !negotiated.is_empty() {
                name.push_str(", ");
                name.push_str(&negotiated);
            }
            if let Some(warning) = plaintext_disclosure(p) {
                name.push_str(". ");
                name.push_str(warning);
            }
            name
        })
        .into_element();

    let interactive = iced::widget::mouse_area(picture)
        // One move per frame: the remote needs the pointer's position, not
        // every sample of a high-rate mouse, each of which is an update.
        .on_move_coalesced(move |at| Message::SessionPointer(pid, PointerGesture::Moved(at)))
        // A press and a release carry no position from `mouse_area`, and none
        // is invented here: the reducer reports them against the last position
        // a move mapped, and refuses a button that had no move before it.
        .on_press(Message::SessionPointer(
            pid,
            PointerGesture::Pressed(PointerButton::Left),
        ))
        .on_right_press(Message::SessionPointer(
            pid,
            PointerGesture::Pressed(PointerButton::Right),
        ))
        .on_middle_press(Message::SessionPointer(
            pid,
            PointerGesture::Pressed(PointerButton::Middle),
        ));

    let interactive = iced::widget::mouse_area(interactive)
        .on_scroll(move |delta| Message::DesktopScroll(pid, delta));
    let enabled = session.input_mode.forwards_input() && !app.modal_open();
    let interactive = Element::new(
        crate::desktop_input::DesktopInput::new(interactive.into(), pid, enabled)
            .clipboard_generation(
                (matches!(
                    p.protocol,
                    crate::model::Protocol::Vnc
                        | crate::model::Protocol::Rdp
                        | crate::model::Protocol::Spice
                        | crate::model::Protocol::RustDesk
                ) && session.clipboard_enabled)
                    .then(|| app.session_streams.get(&pid).copied())
                    .flatten(),
            )
            .capture_lease(
                app.session_backend(pid)
                    .and_then(|backend| backend.input_capture_for(pid)),
            ),
    );
    iced::widget::Sensor::new(interactive)
        // `on_resize` fires only on change, so `on_show` supplies the first measurement
        // the pointer mapping needs.
        .on_show(move |size| Message::SessionSurfaceResized(pid, size))
        .on_resize(move |size| Message::SessionSurfaceResized(pid, size))
        .into()
}

/// The bounded, single-line `host`/`host:port` shown in a session detail
/// sentence. Projects the imported host through the Remote-local display helper
/// so a crafted host cannot spoof or inflate the session surface; the stored
/// `host`/`port` are untouched, and the default-port elision matches the
/// sidebar subtitle and `ConnectionProfile::host_display`.
fn bounded_host(p: &ConnectionProfile) -> String {
    crate::display::bound_host_display(&p.host, p.port, p.protocol.default_port())
}

/// The sub-line under each surface state's title.
///
/// One function so the four descriptions are visibly four different sentences
/// rather than one string with a status appended — the failure mode where a
/// user reads the same paragraph for "connecting" and "the backend refused".
fn describe(body: &SurfaceBody, p: &ConnectionProfile, session: Option<&Session>) -> String {
    let base = describe_state(body, p, session);
    match plaintext_disclosure(p) {
        Some(warning) => format!("{base} {warning}"),
        None => base,
    }
}

pub(crate) fn plaintext_disclosure(p: &ConnectionProfile) -> Option<&'static str> {
    if p.ssh_tunnel.is_some() {
        return None;
    }
    match p.protocol {
        crate::model::Protocol::Vnc
            if !crate::rfb::policy::requires_tls(p) && crate::rfb::policy::acknowledged(p) =>
        {
            Some(crate::rfb::policy::PLAINTEXT_ACTIVE)
        }
        crate::model::Protocol::RustDesk
            if !crate::rustdesk::rendezvous::is_id(p)
                && !p
                    .extra
                    .get(crate::rustdesk::PEER_KEY)
                    .is_some_and(|key| !key.trim().is_empty()) =>
        {
            Some(crate::rustdesk::PLAINTEXT_ACTIVE)
        }
        _ => None,
    }
}

fn describe_state(body: &SurfaceBody, p: &ConnectionProfile, session: Option<&Session>) -> String {
    match body {
        // Names the action rather than a button, because the narrow rung reaches
        // Connect through the row's context menu.
        SurfaceBody::NotStarted => format!(
            "Connect to open the session for {} at {}.",
            p.protocol.label(),
            bounded_host(p)
        ),
        SurfaceBody::Loading => {
            format!("Reaching {} at {}", p.protocol.label(), bounded_host(p))
        }
        SurfaceBody::NoSignal => format!(
            "Connected to {}, but the remote has sent no framebuffer yet.",
            bounded_host(p)
        ),
        SurfaceBody::Live { size } => {
            let scaling = session
                .map(|s| s.scaling.label())
                .unwrap_or("Scaled to fit");
            format!("{}×{} · {scaling}", size.0, size.1)
        }
        // The backend's own message is already in the title (`Error: …`), so
        // the description says what to do instead of repeating it.
        SurfaceBody::Failed(_) => "Press Retry to attempt the connection again.".to_string(),
    }
}
