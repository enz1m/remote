//! The Quick Connect dialog.
//!
//! Presentation only: recency wording, dedup, cap and profile projection
//! belong to [`crate::quick_connect`].
//!
//! # Shape
//!
//! `enz_modal_host` hosting an `enz_modal_surface` with a
//! [`CappedDialogBody`], the same composition as `form_view::present`, so the
//! action row stays visible when the body outgrows the window. Geometry reuses
//! `form_view`'s `dialog_width`, `dialog_max_height` and `surface_padding`, so
//! the two dialogs cannot drift apart.
//!
//! # Two actions per row
//!
//! Each recent carries Connect (presents the form) and Save (persists, opens
//! nothing). Save's accessible name is the full
//! localized no-session sentence, because a bare "Save"
//! is indistinguishable from the form's Save, which does connect, and
//! screen-reader users get no tooltip.

use enzui_iced_core::identity::OwnerId;
use enzui_iced_theme::SpaceToken;
use enzui_iced_widgets::button::{ButtonKind, ButtonSize, enz_button};
use enzui_iced_widgets::capped_dialog_body::CappedDialogBody;
use enzui_iced_widgets::enz_text::{TextSize, TextTone, enz_text};
use enzui_iced_widgets::list_row_surface::enz_list_row_surface;
use enzui_iced_widgets::modal_host::enz_modal_host;
use enzui_iced_widgets::modal_surface::{ModalSurfaceTokens, enz_modal_surface};
use enzui_iced_widgets::scroll_view::{Axis, enz_scroll_view};
use enzui_iced_widgets::stack::{CrossAlign, enz_hstack, enz_vstack};
use enzui_iced_widgets::status_page::{StatusPageTone, StatusPageVariant, enz_status_page};
use enzui_iced_widgets::text_field::{TextFieldSize, enz_text_field_owned};
use enzui_iced_widgets::toolbar_row::enz_toolbar_row;
use enzui_iced_widgets::window_title::enz_window_title;
use iced::advanced::widget::Id;
use iced::{Element, Length};

use crate::form_view::{dialog_max_height, dialog_width, surface_padding};

/// Stable scope shared by the Quick Connect host and focus lifecycle.
pub(crate) const QUICK_CONNECT_SCOPE_KEY: &str = "remote-quick-connect";

use crate::quick_connect::RecentConnection;
use crate::{App, Message};

// An anonymous button is published to assistive technology with its action
// mask cleared, and the shared activation carrier — the path that invokes the
// same `on_press` a pointer release runs — is offered only under an id.

/// Owner namespace of the per-recent row actions.
const RECENT_ACTION_OWNER: &str = "remote-app-quick-recent-action";

/// Widget id of the dialog's address Connect action.
pub(crate) fn address_submit_id() -> Id {
    Id::from("remote-app-quick-connect-submit")
}

/// Widget id of the dialog's `Enter details…` action.
pub(crate) fn enter_details_id() -> Id {
    Id::from("remote-app-quick-connect-enter-details")
}

/// Widget id of the dialog's `Clear all` action, which exists only while
/// there is history.
pub(crate) fn clear_recents_id() -> Id {
    Id::from("remote-app-quick-connect-clear-recents")
}

/// Widget id of the dialog's Cancel action.
pub(crate) fn cancel_button_id() -> Id {
    Id::from("remote-app-quick-connect-cancel")
}

/// One of the actions a recent row offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecentAction {
    Connect,
    Save,
    Retry,
    Forget,
}

impl RecentAction {
    /// The role segment this action occupies inside a recent's namespace.
    fn role(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Save => "save",
            Self::Retry => "retry",
            Self::Forget => "forget",
        }
    }
}

/// Widget id of `action` on the recent identified by `key`.
///
/// Keyed by [`RecentConnection::key`], not row position, because every
/// connect re-sorts the list.
pub(crate) fn recent_action_id(key: &str, action: RecentAction) -> Id {
    OwnerId::of_kind(RECENT_ACTION_OWNER, key).id(action.role())
}

/// Present the Quick Connect dialog over `background`, or return `background`
/// unchanged.
///
/// Closed, it builds no scrim and leaves the shell interactive.
///
/// # Ordering against the connection form
///
/// `view::shell` presents this inside `form_view::present`'s background, so
/// the form is on top if both are open. Paths that open the form from here
/// close this dialog in the same reducer arm; any overlap must leave
/// keystrokes with the dialog being typed in.
pub fn present<'a>(app: &'a App, background: Element<'a, Message>) -> Element<'a, Message> {
    if !app.quick_connect_open {
        return enz_modal_host(background, None, Message::QuickConnectModalEvent).into_element();
    }
    let enz = &app.enz_theme;

    let title = enz_window_title(crate::l10n::text("remote-quick-connect"))
        .subtitle(crate::l10n::text("remote-recent-header"))
        .subtitle_tone(TextTone::Muted)
        .centered(false)
        .into_element();

    let body: Element<'a, Message> = enz_scroll_view(body_column(app))
        .axis(Axis::Vertical)
        .height(Length::Shrink)
        .width(Length::Fill)
        .into();

    let stack = CappedDialogBody::new(
        vec![title],
        body,
        vec![action_row(app)],
        enz.spacing.md(),
        dialog_max_height(enz, app.window_height),
    );

    let surface = enz_modal_surface(stack.into())
        .padding(surface_padding(enz))
        .width(Length::Fixed(dialog_width(app.window_width)))
        .tokens(ModalSurfaceTokens::from_palette(&enz.palette))
        .into_element();

    enz_modal_host(background, Some(surface), Message::QuickConnectModalEvent)
        .scoped_to(
            app.quick_connect_focus
                .as_ref()
                .expect("open Quick Connect dialog has no focus lifecycle"),
        )
        .label(crate::l10n::text("remote-quick-connect"))
        .into_element()
}

/// What the address field offers as an example, derived from the registry.
///
/// The schemes named are exactly the protocols this build can dial, so the
/// field never invites one the reducer would refuse.
///
/// A bare host and `host:port` are always offered; they parse as the default
/// protocol, and whether that is connectable is the submit's answer.
pub(crate) fn address_placeholder(app: &App) -> String {
    let schemes: Vec<String> = app
        .backends
        .choices()
        .iter()
        .map(|c| format!("{}://", c.key()))
        .collect();
    if schemes.is_empty() {
        return crate::l10n::text("remote-address-placeholder");
    }
    crate::l10n::with("remote-address-schemes", "schemes", schemes.join(" / "))
}

/// The address entry group: a labelled row with the text field and a
/// Connect button, plus an inline error line under the field on a refused
/// submit.
///
/// Kept as its own function so the dialog composition reads top-to-bottom as
/// [address, blurb, recents-or-empty] with no mixing.
fn address_group(app: &App) -> Element<'_, Message> {
    let enz = &app.enz_theme;

    let inline_error: Option<String> = app
        .quick_connect_address_error
        .as_ref()
        .map(|e| e.inline_error());

    let mut field = enz_text_field_owned(
        crate::l10n::text("remote-address"),
        address_placeholder(app),
        app.quick_connect_address.as_str(),
        Message::QuickConnectAddressChanged,
    )
    .size(TextFieldSize::Md)
    .on_submit(Message::QuickConnectAddressSubmit)
    .id_prefix("remote-app-quick-address");
    if let Some(msg) = inline_error {
        // Owned `String` → `Cow::Owned`, so the widget outlives this frame's
        // locals without borrowing them.
        field = field.error(msg);
    }

    let connect = enz_button(
        crate::l10n::text("remote-connect"),
        Message::QuickConnectAddressSubmit,
    )
    .kind(ButtonKind::Accent)
    .size(ButtonSize::Md)
    .aria_label(crate::l10n::text("remote-connect-to-the-typed-address"))
    .id(address_submit_id())
    .into_element();

    enz_hstack(vec![field.into_element(), connect])
        .gap(SpaceToken::Xs)
        .cross(CrossAlign::End)
        .hug_content(false)
        .spacing_scale(enz.spacing)
        .into_element()
}

/// The blurb naming both row actions, then the rows — or the empty state.
fn body_column(app: &App) -> Element<'_, Message> {
    let enz = &app.enz_theme;

    let blurb = enz_text(crate::l10n::text("remote-recent-blurb"))
        .size(TextSize::Footnote)
        .tone(TextTone::Muted)
        .wrap(true)
        .into_element();

    let mut children: Vec<Element<'_, Message>> = vec![address_group(app), blurb];

    if app.recents.is_empty() {
        // The empty state has its own sentence, distinct from the scan's in-flight
        // label and the sidebar's list empty states, so each points to the right
        // remedy.
        children.push(
            enz_status_page(crate::l10n::text("remote-no-recents"))
                .icon("history")
                .description(crate::l10n::text("remote-no-recents-body"))
                .variant(StatusPageVariant::Inline)
                .tone(StatusPageTone::Empty)
                .id_prefix("remote-app-quick-empty")
                .into_element(),
        );
    } else {
        // One clock read, so rows in one frame agree on "now".
        let now = chrono::Utc::now();
        for recent in &app.recents {
            children.push(recent_row(app, recent, now));
        }
    }

    enz_vstack(children)
        .gap(SpaceToken::Sm)
        .cross(CrossAlign::Stretch)
        .spacing_scale(enz.spacing)
        .into_element()
}

/// One recent: endpoint over `PROTO · user · when`, with Save and Connect on
/// the trailing edge.
///
/// The row is `selectable(false)` and activates as Connect, since a recent
/// has no profile to select (as in `sidebar_view::discovered_row`).
///
/// # A recent this build cannot dial
///
/// When [`crate::protocol::BackendRegistry::available`] has no slot for the
/// protocol, Connect is replaced by the muted
/// [`crate::protocol::NOT_IN_THIS_BUILD`] disclosure. Save stays, since
/// recording the endpoint is still a complete outcome. Row activation stays
/// `QuickConnectRecent`, which only seeds the form.
fn recent_row<'a>(
    app: &'a App,
    recent: &'a RecentConnection,
    now: chrono::DateTime<chrono::Utc>,
) -> Element<'a, Message> {
    let enz = &app.enz_theme;
    let key = recent.key();

    // Store durability is a separate fact from the connection, and only this
    // row can disclose it before the entry vanishes at next launch.
    let unsaved = app.unsaved_recents.contains(&key);
    let detail = if unsaved {
        format!(
            "{} · {}",
            recent.detail(now),
            crate::l10n::text("remote-not-saved")
        )
    } else {
        recent.detail(now)
    };

    let text_col = enz_vstack(vec![
        enz_text(recent.endpoint())
            .size(TextSize::Callout)
            .into_element(),
        enz_text(detail)
            .size(TextSize::Caption2)
            .tone(if unsaved {
                TextTone::Warning
            } else {
                TextTone::Subtle
            })
            .into_element(),
    ])
    .gap(SpaceToken::Xxs)
    .cross(CrossAlign::Start)
    .spacing_scale(enz.spacing)
    .into_element();

    // Accessible name "Save as a connection (no session)", visible label `Save`;
    // see the module docs.
    let save = enz_button(
        crate::l10n::text("remote-save"),
        Message::QuickConnectSaveRecent(key.clone()),
    )
    .kind(ButtonKind::Ghost)
    .size(ButtonSize::Sm)
    .aria_label(crate::l10n::text("remote-save-no-session"))
    .id(recent_action_id(&key, RecentAction::Save))
    .into_element();

    let connect = if app.backends.available(recent.protocol) {
        enz_button(
            crate::l10n::text("remote-connect"),
            Message::QuickConnectRecent(key.clone()),
        )
        .kind(ButtonKind::Accent)
        .size(ButtonSize::Sm)
        .aria_label(crate::l10n::with(
            "remote-connect-endpoint",
            "endpoint",
            recent.endpoint(),
        ))
        .id(recent_action_id(&key, RecentAction::Connect))
        .into_element()
    } else {
        enz_text(crate::l10n::text("remote-not-in-build"))
            .size(TextSize::Caption)
            .tone(TextTone::Muted)
            .no_wrap()
            .into_element()
    };

    // Only while there is something to retry. A permanent Retry beside every
    // row would read as "this might not be saved" for rows that are.
    let mut controls: Vec<Element<'_, Message>> = vec![
        text_col,
        iced::widget::Space::new().width(Length::Fill).into(),
    ];
    if unsaved {
        controls.push(
            enz_button(
                crate::l10n::text("remote-retry"),
                Message::QuickConnectRetrySave(key.clone()),
            )
            .kind(ButtonKind::Secondary)
            .size(ButtonSize::Sm)
            .aria_label(crate::l10n::with(
                "remote-retry-endpoint",
                "endpoint",
                recent.endpoint(),
            ))
            .id(recent_action_id(&key, RecentAction::Retry))
            .into_element(),
        );
    }
    controls.push(
        enz_button(
            crate::l10n::text("remote-forget"),
            Message::QuickConnectForgetRecent(key.clone()),
        )
        .kind(ButtonKind::Ghost)
        .size(ButtonSize::Sm)
        .aria_label(crate::l10n::with(
            "remote-forget-endpoint",
            "endpoint",
            recent.endpoint(),
        ))
        .id(recent_action_id(&key, RecentAction::Forget))
        .into_element(),
    );
    controls.push(save);
    controls.push(connect);

    let inner = enz_hstack(controls)
        .gap(SpaceToken::Xs)
        .cross(CrossAlign::Center)
        .hug_content(false)
        .spacing_scale(enz.spacing)
        .into_element();

    enz_list_row_surface(inner, Message::QuickConnectRecent(key))
        .selectable(false)
        .content_height(true)
        .label(recent.endpoint())
        .id_prefix("remote-app-recent")
        .tokens_resolved(crate::theme::list_row_tokens)
        .into()
}

/// `Enter details…` — and `Clear all`, when there is history — on the leading
/// edge, `Cancel` on the trailing one.
///
/// `Enter details…` is always present: with no history it is the dialog's
/// only action.
fn action_row(app: &App) -> Element<'_, Message> {
    let enz = &app.enz_theme;

    // `Clear all` only while there is history to clear: over an empty list it
    // is a control that cannot do anything, and the empty state already says
    // there is nothing here.
    let mut start: Vec<Element<'_, Message>> = vec![
        enz_button(
            crate::l10n::text("remote-enter-details"),
            Message::QuickConnectEnterDetails,
        )
        .kind(ButtonKind::Secondary)
        .size(ButtonSize::Md)
        .icon("action.add")
        .id(enter_details_id())
        .into_element(),
    ];
    if !app.recents.is_empty() {
        start.push(
            enz_button(
                crate::l10n::text("remote-clear-recents"),
                Message::QuickConnectClearRecents,
            )
            .kind(ButtonKind::Ghost)
            .size(ButtonSize::Md)
            .id(clear_recents_id())
            .into_element(),
        );
    }

    enz_toolbar_row()
        .start(
            enz_hstack(start)
                .gap(SpaceToken::Xs)
                .cross(CrossAlign::Center)
                .spacing_scale(enz.spacing)
                .into_element(),
        )
        .end(
            enz_button(
                crate::l10n::text("remote-cancel"),
                Message::QuickConnectDismiss,
            )
            .kind(ButtonKind::Quiet)
            .size(ButtonSize::Md)
            .id(cancel_button_id())
            .into_element(),
        )
        .inset(SpaceToken::None)
        .zone_spacing(SpaceToken::Sm)
        .center_absolute(false)
        .spacing_scale(enz.spacing)
        .sizing_scale(enz.sizing)
        .into_element()
}
