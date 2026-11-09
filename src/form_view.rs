//! The connection form dialog.
//!
//! # Shape
//!
//! `enz_modal_host` (scrim, Escape, focus trap, background inert) hosts an
//! `enz_modal_surface` containing a [`CappedDialogBody`]: title chrome, a
//! scrolling body of `enz_preferences_group` / `enz_preferences_row`, and an
//! action row.
//!
//! `CappedDialogBody` measures the title and action rows and caps the body at
//! `max_height - measured_chrome`, so the action row stays inside the surface at
//! every window height. A plain column would size the surface to the body and lay
//! the actions out below the visible frame.
//!
//! Protocol selection maps the shared dropdown's index through the available
//! protocol values, independently of their displayed labels.
//!
//! Dialog geometry derives from the tracked window size, with a fallback for the
//! frame before the first `Resized`.

use enzui_iced_core::identity::OwnerId;
use enzui_iced_theme::{EnzTheme, SpaceToken};
use enzui_iced_widgets::button::{ButtonKind, ButtonSize, enz_button};
use enzui_iced_widgets::capped_dialog_body::CappedDialogBody;
use enzui_iced_widgets::enz_text::{TextSize, TextTone, enz_text};
use enzui_iced_widgets::modal_host::enz_modal_host;
use enzui_iced_widgets::modal_surface::{ModalSurfaceTokens, enz_modal_surface};
use enzui_iced_widgets::preferences_group::enz_preferences_group;
use enzui_iced_widgets::preferences_row::{EnzPreferencesRow, PreferencesRowTokens};
use enzui_iced_widgets::radio_group::{Orientation, RadioTokens, enz_radio_group};
use enzui_iced_widgets::scroll_view::{Axis, enz_scroll_view};
use enzui_iced_widgets::stack::{CrossAlign, enz_hstack, enz_vstack};
use enzui_iced_widgets::toolbar_row::enz_toolbar_row;
use enzui_iced_widgets::window_title::enz_window_title;
use iced::advanced::widget::Id;
use iced::{Element, Length};

use crate::form::{ConnectionForm, RuleDraft};

fn compact_row<'a>(label: impl Into<std::borrow::Cow<'a, str>>) -> EnzPreferencesRow<'a, Message> {
    let mut tokens = PreferencesRowTokens::default();
    tokens.row_height = enzui_iced_theme::text_defaults::sizing().control_height;
    tokens.row_height_with_subtitle = tokens.row_height + tokens.subtitle_size + 4.0;
    tokens.wrap_vertical_padding = 8.0;
    enzui_iced_widgets::preferences_row::enz_preferences_row(label)
        .field_size(enzui_iced_widgets::text_field::TextFieldSize::Sm)
        .tokens(tokens)
}

/// Stable scope shared by the form host and its owned focus lifecycle.
pub(crate) const FORM_SCOPE_KEY: &str = "remote-connection-form";

use crate::model::{PORT_FORWARD_TYPE_LABELS, PortForwardType, Protocol, QUALITY_LABELS};
use crate::{App, Message};

// An anonymous button is published to assistive technology with its action
// mask cleared, and the shared activation carrier — the path that invokes the
// same `on_press` a pointer release runs — is offered only under an id.

/// Widget id of the form's Cancel action.
pub(crate) fn cancel_button_id() -> Id {
    Id::from("remote-app-form-cancel")
}

/// Widget id of the form's Save action.
pub(crate) fn save_button_id() -> Id {
    Id::from("remote-app-form-save")
}

/// Widget id of the form's Delete action, which exists only while editing a
/// saved connection.
pub(crate) fn delete_button_id() -> Id {
    Id::from("remote-app-form-delete")
}

/// Identity kind of one port-forward rule's controls.
const RULE_OWNER_KIND: &str = "remote-app-forward-rule";

/// The namespace the controls of the forward rule `rule_id` publish under.
///
/// Keyed by the draft's own id, so a rule keeps its controls across reorder,
/// insertion and retitling. The group node is `owner.id("group")` and the
/// Remove action is
/// [`card_header_action_id`](enzui_iced_widgets::card::card_header_action_id)
/// of the same owner.
pub(crate) fn rule_owner(rule_id: uuid::Uuid) -> OwnerId {
    OwnerId::of_kind(RULE_OWNER_KIND, &rule_id.to_string())
}

/// Fraction of the tracked window height the dialog may occupy.
const DIALOG_HEIGHT_FRACTION: f32 = 0.86;

/// The auto-derive rule stays in wrapping helper text instead of competing
/// with typed input inside the field.
pub const NAME_SUBTITLE: &str = "Optional; defaults to the host.";

/// A short input example; the complete empty-value behavior is in
/// [`NAME_SUBTITLE`].
pub const NAME_PLACEHOLDER: &str = "e.g. Web server";

/// The window size the geometry falls back to before the first `Resized`
/// arrives (`window_width == 0`). Deliberately a *fallback for a missing
/// measurement*, not a declared window size — the app never asks the
/// compositor for a size (settled decision #2).
const ASSUMED_WINDOW: (f32, f32) = (1400.0, 900.0);

/// The dialog's width for a window / host width.
///
/// Capped so a short form does not sprawl, and never wider than the window minus a
/// gutter. It reads an app-held width because dialog overlays sit outside the
/// shell and `enz_responsive` requires a `Clone` content element.
pub fn dialog_width(window_width: f32) -> f32 {
    let w = if window_width > 0.0 {
        window_width
    } else {
        ASSUMED_WINDOW.0
    };
    (w - 32.0).clamp(240.0, 460.0)
}

/// The maximum height for the dialog stack (title, scrolling body and action row),
/// excluding the modal surface's padding.
///
/// `CappedDialogBody` subtracts the measured title and action rows from this.
/// The surface adds [`surface_padding`] above and below, so that inset is
/// subtracted here and the painted surface stays within the bound.
pub fn dialog_max_height(enz: &EnzTheme, window_height: f32) -> f32 {
    let h = if window_height > 0.0 {
        window_height
    } else {
        ASSUMED_WINDOW.1
    };
    (h * DIALOG_HEIGHT_FRACTION - 2.0 * surface_padding(enz)).max(200.0)
}

/// The modal surface's inset. One function, read by [`dialog_max_height`] and
/// handed to `enz_modal_surface`, because two places deciding the same padding
/// is a mutation nothing can catch.
pub fn surface_padding(enz: &EnzTheme) -> f32 {
    enz.spacing.md()
}

/// Present the connection form over `background`, or return `background`
/// unchanged when no form is open.
///
/// A pure pass-through when closed: no scrim is built, so the shell behind is
/// untouched and stays interactive.
pub fn present<'a>(app: &'a App, background: Element<'a, Message>) -> Element<'a, Message> {
    let Some(form) = app.form.as_ref() else {
        return enz_modal_host(background, None, Message::FormModalEvent).into_element();
    };
    let enz = &app.enz_theme;

    let title = enz_window_title(form.title())
        .subtitle(if form.editing.is_some() {
            "Saved connection"
        } else {
            "Add a saved connection"
        })
        .subtitle_tone(TextTone::Muted)
        .centered(false)
        .into_element();

    let body: Element<'a, Message> = enz_scroll_view(body_column(app, form))
        .axis(Axis::Vertical)
        .height(Length::Shrink)
        .width(Length::Fill)
        .into();

    let stack = CappedDialogBody::new(
        vec![title],
        body,
        vec![action_row(app, form)],
        enz.spacing.md(),
        dialog_max_height(enz, app.window_height),
    );

    let surface = enz_modal_surface(stack.into())
        .padding(surface_padding(enz))
        .width(Length::Fixed(dialog_width(app.window_width)))
        .tokens(ModalSurfaceTokens::from_palette(&enz.palette))
        .into_element();

    enz_modal_host(background, Some(surface), Message::FormModalEvent)
        .scoped_to(
            app.form_focus
                .as_ref()
                .expect("open connection form has no focus lifecycle"),
        )
        .label(form.title())
        .into_element()
}

/// The dialog's trailing action row.
///
/// Delete is destructive and sits in the leading zone of `enz_toolbar_row`, away
/// from Save. Save is disabled rather than hidden when the draft is incomplete;
/// `ConnectionForm::can_save` is shared with the reducer so the button and
/// `FormSave` agree.
fn action_row<'a>(app: &'a App, form: &ConnectionForm) -> Element<'a, Message> {
    let enz = &app.enz_theme;
    let cancel = enz_button(crate::l10n::text("remote-cancel"), Message::FormCancel)
        .kind(ButtonKind::Quiet)
        .size(ButtonSize::Md)
        .id(cancel_button_id())
        .into_element();
    let save = enz_button(
        if form.connect_on_save {
            "Connect"
        } else if app.form_disconnects_session(form) {
            "Save & disconnect"
        } else {
            "Save"
        },
        Message::FormSave,
    )
    .kind(ButtonKind::Accent)
    .size(ButtonSize::Md)
    .enabled(form.can_save())
    .id(save_button_id())
    .into_element();

    let trailing = enz_hstack(vec![cancel, save])
        .gap(SpaceToken::Sm)
        .cross(CrossAlign::Center)
        .spacing_scale(enz.spacing)
        .into_element();

    let mut row = enz_toolbar_row()
        .end(trailing)
        .inset(SpaceToken::None)
        .zone_spacing(SpaceToken::Sm)
        .center_absolute(false)
        .spacing_scale(enz.spacing)
        .sizing_scale(enz.sizing);

    // Delete only exists for a profile that exists. On the add form there is
    // nothing to delete, and a disabled Delete would advertise an action that
    // can never apply here.
    if form.editing.is_some() {
        row = row.start(
            enz_button(crate::l10n::text("remote-delete"), Message::FormDelete)
                .kind(ButtonKind::Destructive)
                .size(ButtonSize::Md)
                .id(delete_button_id())
                .into_element(),
        );
    }

    row.into_element()
}

/// The scrolling body: the Connection group, the Credentials group, and the
/// optional connection settings.
fn body_column<'a>(app: &'a App, form: &'a ConnectionForm) -> Element<'a, Message> {
    let enz = &app.enz_theme;
    use crate::form::FormSection as S;
    let section = |key, title, content| {
        enzui_iced_widgets::expander::enz_expander(
            title,
            form.sections.contains(&key),
            move |open| Message::FormSectionChanged(key, open),
        )
        .content(content)
        .id_prefix(format!("remote-form-section-{key:?}"))
        .tokens(enzui_iced_widgets::expander::ExpanderTokens {
            header_height: enz.sizing.control_height,
            content_inset: enz.spacing.md(),
            card_radius: enzui_iced_theme::text_defaults::shape_radius(|shape| shape.card),
            ..enzui_iced_widgets::expander::ExpanderTokens::from_palette(&enz.palette)
        })
        .into_element()
    };
    let mut sections = vec![
        connection_group(
            enz,
            form,
            app.backends.choices(),
            app.backends.available(form.protocol),
        ),
        credentials_group(enz, form),
        section(
            S::Organization,
            "Organization",
            organization_group(enz, form),
        ),
        section(S::Options, "Connection options", options_group(enz, form)),
    ];
    {
        let mut routing = Vec::new();
        if form.protocol == crate::model::Protocol::Moonlight {
            routing.push(enz_text("Moonlight requires UDP. Use a VPN; ordinary SSH TCP forwarding cannot route its stream.")
                .size(TextSize::Caption).tone(TextTone::Muted).full_width().into_element());
        }
        if form.protocol != crate::model::Protocol::Moonlight
            || form.has_tunnel()
            || !form.rules.is_empty()
        {
            routing.push(tunnel_group(enz, form));
            routing.extend(port_forward_section(enz, form));
        }
        sections.push(section(
            S::SshRouting,
            "SSH routing",
            enz_vstack(routing)
                .gap(SpaceToken::Md)
                .cross(CrossAlign::Stretch)
                .spacing_scale(enz.spacing)
                .into_element(),
        ));
    }
    if matches!(
        form.protocol,
        Protocol::Rdp | Protocol::Spice | Protocol::RustDesk | Protocol::Moonlight
    ) {
        sections.push(section(
            S::Media,
            "Audio, input and display",
            media_group(enz, form),
        ));
    }
    if !matches!(
        form.protocol,
        crate::model::Protocol::Vnc | crate::model::Protocol::Ssh
    ) {
        sections.push(section(S::Display, "Display", display_group(enz, form)));
    }

    enz_vstack(sections)
        .gap(SpaceToken::Sm)
        .cross(CrossAlign::Stretch)
        .spacing_scale(enz.spacing)
        .into_element()
}

/// Name / host / port / protocol.
///
/// `choices` is [`crate::protocol::BackendRegistry::choices`], one option per
/// protocol with a real backend, so an unsupported protocol cannot be created.
/// `available` covers a saved or imported profile whose protocol has no backend:
/// the form stays editable, the group shows no selection, a disclosure line names
/// the protocol, and saving preserves it.
fn connection_group<'a>(
    enz: &EnzTheme,
    form: &'a ConnectionForm,
    choices: &'a [Protocol],
    available: bool,
) -> Element<'a, Message> {
    // "Optional" holds because every path that can produce a nameless connection
    // derives a name from the host first. The auto-derive rule lives in the wrapping
    // subtitle because the fixed inline slot clips a long placeholder at 375px.
    let name = compact_row(crate::l10n::text("remote-name"))
        .subtitle(NAME_SUBTITLE)
        .subtitle_wrap(true)
        .entry(&form.name, NAME_PLACEHOLDER, Message::FormNameChanged)
        .into_element();

    let host = compact_row(crate::l10n::text("remote-host"))
        .entry(
            &form.host,
            if form.protocol == Protocol::RustDesk {
                "RustDesk ID or host"
            } else {
                "hostname or IP"
            },
            Message::FormHostChanged,
        )
        .into_element();

    // The subtitle names the default without replacing a typed zero or custom
    // port; the draft remains the sole input buffer.
    let port = connection_port_row(form, form.port_error().unwrap_or_default());

    let protocol = compact_row("Protocol")
        .control(
            enzui_iced_widgets::combo_box::enz_combo_box(
                "",
                choices.iter().map(|p| p.label().to_owned()).collect(),
                None,
                |_| Message::NoOp,
            )
            .aria_label("Protocol")
            .selected_index(choices.iter().position(|p| *p == form.protocol))
            .on_select_index(move |index| {
                choices
                    .get(index)
                    .copied()
                    .map_or(Message::NoOp, Message::FormProtocolPicked)
            })
            .size(enzui_iced_widgets::text_field::TextFieldSize::Sm)
            .id("remote-app-form-protocol".into())
            .into_element(),
        )
        .into_element();

    let support = enz_text("VNC, RDP, SPICE, RustDesk direct or ID/relay access, and paired Sunshine/Moonlight desktops. SSH tunnels are available for TCP connections.")
        .size(TextSize::Caption2)
        .tone(TextTone::Muted)
        .full_width()
        .into_element();
    let mut rows = vec![name, host, port, protocol, support];
    if !available {
        // Wraps directly beneath the group it qualifies so it reads with the selection.
        rows.push(
            enz_text(format!(
                "{}: {}",
                form.protocol.label(),
                crate::protocol::NOT_IN_THIS_BUILD
            ))
            .size(TextSize::Caption)
            .tone(TextTone::Muted)
            .full_width()
            .into_element(),
        );
    }

    let content = enz_vstack(rows)
        .gap(SpaceToken::Xs)
        .cross(CrossAlign::Stretch)
        .spacing_scale(enz.spacing)
        .into_element();

    enz_preferences_group(content)
        .title(&crate::l10n::text("remote-connection"))
        .spacing_scale(enz.spacing)
        .into_element()
}

pub(crate) fn port_hint_for(form: &ConnectionForm) -> String {
    format!(
        "Default for {} is {}",
        form.protocol.label(),
        form.protocol.default_port()
    )
}

pub(crate) fn connection_port_row<'a>(
    form: &'a ConnectionForm,
    error: &'a str,
) -> Element<'a, Message> {
    compact_row(crate::l10n::text("remote-port"))
        .subtitle(port_hint_for(form))
        .entry(&form.port, "port", Message::FormPortChanged)
        .error(error)
        .into_element()
}

/// Credentials supported by the selected transport, with removal of legacy SSH secrets.
fn credentials_group<'a>(enz: &EnzTheme, form: &'a ConnectionForm) -> Element<'a, Message> {
    let username = compact_row(crate::l10n::text(if form.protocol == Protocol::RustDesk {
        "remote-rustdesk-peer-id"
    } else {
        "remote-username"
    }))
    .entry(
        &form.username,
        if form.protocol == Protocol::Rdp {
            "DOMAIN\\user"
        } else {
            "optional"
        },
        Message::FormUsernameChanged,
    )
    .into_element();

    // Opening the form does not read the keyring, so the field is empty even when a
    // password is saved; the subtitle says so. `ConnectionForm::password_hint` owns
    // the wording, and
    // `form_tests::a_typed_password_reaches_the_keyring_and_never_the_database`
    // keeps it true.
    let password = compact_row(crate::l10n::text(if form.protocol == Protocol::Moonlight {
        "remote-moonlight-pin"
    } else {
        "remote-password"
    }))
    .subtitle(form.password_hint())
    .subtitle_wrap(true)
    .password(
        &form.password,
        if form.protocol == Protocol::Moonlight {
            "4 digits"
        } else {
            "password"
        },
        form.password_revealed,
        Message::FormPasswordChanged,
        Message::FormPasswordRevealToggled,
    )
    .into_element();

    let mut rows = if matches!(
        form.protocol,
        Protocol::Vnc | Protocol::Spice | Protocol::Moonlight
    ) {
        vec![password]
    } else if form.protocol == crate::model::Protocol::Ssh {
        let mut rows = vec![
            username,
            enz_text(
                "SSH uses your local keys or agent. The host must already be trusted by OpenSSH.",
            )
            .size(TextSize::Caption)
            .tone(TextTone::Muted)
            .full_width()
            .into_element(),
        ];
        if form.had_keyring_password || !form.password.is_empty() {
            let pending = form.password_dirty && form.password.is_empty();
            rows.push(
                compact_row(crate::l10n::text("remote-saved-ssh-password"))
                    .subtitle(if pending {
                        "Removal requested; save to apply."
                    } else {
                        "SSH cannot use this password. Remove it before connecting."
                    })
                    .subtitle_wrap(true)
                    .control(
                        enz_button(
                            crate::l10n::text("remote-remove"),
                            Message::FormPasswordChanged(String::new()),
                        )
                        .kind(ButtonKind::Quiet)
                        .size(ButtonSize::Sm)
                        .aria_label(crate::l10n::text("remote-remove-saved-ssh-password"))
                        .enabled(!pending)
                        .id(Id::from("remote-form-clear-ssh-password"))
                        .into_element(),
                    )
                    .into_element(),
            );
        }
        rows
    } else {
        vec![username, password]
    };
    if form.protocol == Protocol::RustDesk {
        rows.push(compact_row("Connect by RustDesk ID")
            .subtitle("Numeric hosts use ID discovery automatically. Empty server settings use the official RustDesk service.")
            .subtitle_wrap(true).switch(form.rustdesk_id_mode, Message::FormRustDeskIdModeChanged).into_element());
        if form.rustdesk_id_mode
            || (!form.host.is_empty() && form.host.bytes().all(|byte| byte.is_ascii_digit()))
        {
            rows.push(
                compact_row("ID server")
                    .entry(
                        &form.rustdesk_server,
                        "Official RustDesk service",
                        Message::FormRustDeskServerChanged,
                    )
                    .into_element(),
            );
            rows.push(
                compact_row("Server public key")
                    .subtitle(
                        "Required for a custom server; verifies the discovered host identity.",
                    )
                    .subtitle_wrap(true)
                    .entry(
                        &form.rustdesk_server_key,
                        "Base64 Ed25519 public key",
                        Message::FormRustDeskServerKeyChanged,
                    )
                    .into_element(),
            );
            rows.push(
                compact_row("Relay override")
                    .entry(
                        &form.rustdesk_relay,
                        "Discover automatically",
                        Message::FormRustDeskRelayChanged,
                    )
                    .into_element(),
            );
        }
        rows.push(
            compact_row(crate::l10n::text("remote-rustdesk-peer-key"))
                .subtitle(crate::l10n::text("remote-rustdesk-peer-key-hint"))
                .subtitle_wrap(true)
                .entry(
                    &form.rustdesk_peer_key,
                    "Base64 Ed25519 public key",
                    Message::FormRustDeskPeerKeyChanged,
                )
                .into_element(),
        );
    }
    if form.protocol == Protocol::Moonlight {
        rows.push(
            enz_text(crate::l10n::text("remote-moonlight-pair-hint"))
                .size(TextSize::Caption)
                .tone(TextTone::Muted)
                .full_width()
                .into_element(),
        );
        rows.push(
            compact_row(crate::l10n::text("remote-moonlight-app-id"))
                .subtitle(crate::l10n::text("remote-moonlight-app-id-hint"))
                .subtitle_wrap(true)
                .entry(
                    &form.moonlight_app_id,
                    "Desktop",
                    Message::FormMoonlightAppIdChanged,
                )
                .into_element(),
        );
        rows.push(
            compact_row(crate::l10n::text("remote-moonlight-pair-again"))
                .subtitle(crate::l10n::text("remote-moonlight-pair-again-hint"))
                .subtitle_wrap(true)
                .switch(
                    form.moonlight_pair_again,
                    Message::FormMoonlightPairAgainChanged,
                )
                .into_element(),
        );
    }
    let content = enz_vstack(rows)
        .gap(SpaceToken::Xs)
        .cross(CrossAlign::Stretch)
        .spacing_scale(enz.spacing)
        .into_element();

    enz_preferences_group(content)
        .title(&crate::l10n::text("remote-credentials"))
        .spacing_scale(enz.spacing)
        .into_element()
}

/// Jump-host routing and the selected transport’s authentication policy.
fn tunnel_group<'a>(enz: &EnzTheme, form: &'a ConnectionForm) -> Element<'a, Message> {
    let host = compact_row(crate::l10n::text("remote-jump-host"))
        .subtitle("Tunnel through this host first. Empty means no tunnel.")
        .subtitle_wrap(true)
        .entry(
            &form.tunnel_host,
            "bastion.example.com",
            Message::FormTunnelHostChanged,
        )
        .into_element();

    let mut port = compact_row(crate::l10n::text("remote-jump-port"))
        .subtitle("A jump host is reached over SSH; the default is 22.")
        .subtitle_wrap(true)
        .entry(&form.tunnel_port, "22", Message::FormTunnelPortChanged);
    if let Some(error) = form.tunnel_port_error() {
        port = port.error(error);
    }
    let port = port.into_element();

    let username = compact_row(crate::l10n::text("remote-jump-username"))
        .entry(
            &form.tunnel_username,
            "optional",
            Message::FormTunnelUsernameChanged,
        )
        .into_element();

    let mut children: Vec<Element<'a, Message>> = vec![host, port, username];

    if form.has_tunnel() {
        children.push(compact_row("SSH identity file")
            .subtitle("Empty uses your SSH agent or default keys. Host keys must already be trusted in OpenSSH.")
            .subtitle_wrap(true)
            .entry(&form.tunnel_identity, "/home/you/.ssh/id_ed25519", Message::FormTunnelIdentityChanged)
            .into_element());
        if form.had_tunnel_password || form.tunnel_legacy_password {
            children.push(
                compact_row("Legacy password authentication")
                    .subtitle("Password login is not supported for SSH tunnels.")
                    .control(
                        enz_button(
                            "Use keys / agent",
                            Message::FormTunnelPasswordChanged(String::new()),
                        )
                        .kind(ButtonKind::Quiet)
                        .size(ButtonSize::Sm)
                        .into_element(),
                    )
                    .into_element(),
            );
        }
    }

    let content = enz_vstack(children)
        .gap(SpaceToken::Xs)
        .cross(CrossAlign::Stretch)
        .spacing_scale(enz.spacing)
        .into_element();

    enz_preferences_group(content)
        .title("SSH jump host")
        .spacing_scale(enz.spacing)
        .into_element()
}

/// The Organization section: folder and notes.
///
/// `group` is the sidebar's folder bucket. There is no tags field because nothing
/// groups, filters or paints by tag.
fn organization_group<'a>(enz: &EnzTheme, form: &'a ConnectionForm) -> Element<'a, Message> {
    let group = compact_row("Group")
        .subtitle("Slash-delimited path for sidebar grouping. Empty is ungrouped.")
        .subtitle_wrap(true)
        .entry(&form.group, "Work/Servers", Message::FormGroupChanged)
        .into_element();

    // Single-line because `enz_text_area` needs owned editor `Content`, which would
    // make `ConnectionForm` non-`Clone` and split the field's source of truth.
    let notes = compact_row("Notes")
        .entry(
            &form.notes,
            "Anything worth remembering…",
            Message::FormNotesChanged,
        )
        .into_element();

    let content = enz_vstack(vec![group, notes])
        .gap(SpaceToken::Xs)
        .cross(CrossAlign::Stretch)
        .spacing_scale(enz.spacing)
        .into_element();

    enz_preferences_group(content)
        .id("remote-form-organization")
        .spacing_scale(enz.spacing)
        .into_element()
}

fn display_group<'a>(enz: &EnzTheme, form: &'a ConnectionForm) -> Element<'a, Message> {
    let mut rows = Vec::new();
    if matches!(form.protocol, Protocol::Rdp | Protocol::Moonlight) {
        rows.push(enz_text("Leave both dimensions blank to request 1280 × 720. For an existing-screen RDP bridge, use the host's actual desktop size.")
            .size(TextSize::Caption).tone(TextTone::Muted).full_width().into_element());
        for (label, value, placeholder, change) in [
            (
                "Desktop width",
                &form.display_width,
                "1280",
                Message::FormDisplayWidthChanged as fn(String) -> Message,
            ),
            (
                "Desktop height",
                &form.display_height,
                "720",
                Message::FormDisplayHeightChanged as fn(String) -> Message,
            ),
        ] {
            let mut row = compact_row(label).entry(value, placeholder, change);
            if let Some(error) = form.display_size_error() {
                row = row.error(error);
            }
            rows.push(row.into_element());
        }
    }
    rows.push(
        enz_text("Desktop images use 32-bit color.")
            .size(TextSize::Caption)
            .tone(TextTone::Muted)
            .full_width()
            .into_element(),
    );
    if form.protocol == Protocol::RustDesk {
        let selected = match form.quality {
            0..=2 => 0,
            3..=6 => 1,
            _ => 2,
        };
        rows.push(
            enz_radio_group(
                "Quality",
                &["Low", "Balanced", "Best"],
                Some(selected),
                |i| Message::FormQualityPicked([0, 2, 4][i]),
            )
            .orientation(Orientation::Vertical)
            .spacing(enz.spacing.xs())
            .tokens(RadioTokens::from_palette(&enz.palette))
            .into_element(),
        );
    } else if form.protocol == Protocol::Moonlight {
        rows.push(
            enz_radio_group(
                "Quality",
                &QUALITY_LABELS,
                form.quality_index(),
                Message::FormQualityPicked,
            )
            .orientation(Orientation::Vertical)
            .spacing(enz.spacing.xs())
            .tokens(RadioTokens::from_palette(&enz.palette))
            .option_id_prefix("remote-app-form-quality")
            .into_element(),
        );
    }
    let content = enz_vstack(rows)
        .gap(SpaceToken::Sm)
        .cross(CrossAlign::Stretch)
        .spacing_scale(enz.spacing)
        .into_element();

    enz_preferences_group(content)
        .title(&crate::l10n::text("remote-display"))
        .spacing_scale(enz.spacing)
        .into_element()
}

/// The Options section: clipboard sharing, read-only, Wake-on-LAN and the
/// reconnect policy.
///
/// The clipboard switch reads "Disable clipboard sharing" to match the persisted
/// `disable_clipboard` polarity.
fn options_group<'a>(enz: &EnzTheme, form: &'a ConnectionForm) -> Element<'a, Message> {
    let clipboard = compact_row("Disable clipboard sharing")
        .subtitle("New sessions for this connection start with the clipboard off.")
        .subtitle_wrap(true)
        .switch(form.disable_clipboard, Message::FormDisableClipboardToggled)
        .into_element();

    // An empty MAC is optional; only non-empty malformed input gets an error.
    let mut mac = compact_row("MAC Address (WoL)")
        .subtitle("For Wake-on-LAN.")
        .entry(
            &form.wol_mac,
            "aa:bb:cc:dd:ee:ff",
            Message::FormWolMacChanged,
        );
    if let Some(error) = form.mac_error() {
        mac = mac.error(error);
    }
    let mac = mac.into_element();

    // "Open read-only" seeds the session's `InputMode`, which is the gate
    // `App::deliver_macro_to_session` consults — so this switch really does
    // stop keystrokes reaching the remote, rather than only relabelling a chip.
    let view_only = compact_row("Open read-only")
        .subtitle("New sessions start view-only: no keyboard or pointer is forwarded.")
        .subtitle_wrap(true)
        .switch(form.view_only, Message::FormViewOnlyToggled)
        .into_element();

    // The policy is off unless this switch is on, and the two bounds below are
    // what make an enabled policy finite. They stay editable while it is off so
    // the bounds can be set before it is switched on.
    let reconnect = compact_row("Reconnect automatically")
        .subtitle("After an unexpected disconnection, try again with a growing delay.")
        .subtitle_wrap(true)
        .switch(form.reconnect_enabled, Message::FormReconnectToggled)
        .into_element();

    let mut attempts = compact_row("Reconnect attempts")
        .subtitle("How many times to try before giving up.")
        .subtitle_wrap(true)
        .entry(
            &form.reconnect_attempts,
            "5",
            Message::FormReconnectAttemptsChanged,
        );
    if let Some(error) = form.reconnect_attempts_error() {
        attempts = attempts.error(error);
    }
    let attempts = attempts.into_element();

    let mut ceiling = compact_row("Longest wait (seconds)")
        .subtitle("The delay stops growing here.")
        .subtitle_wrap(true)
        .entry(
            &form.reconnect_ceiling,
            "60",
            Message::FormReconnectCeilingChanged,
        );
    if let Some(error) = form.reconnect_ceiling_error() {
        ceiling = ceiling.error(error);
    }
    let ceiling = ceiling.into_element();

    let mut rows = match form.protocol {
        Protocol::Vnc | Protocol::Rdp | Protocol::Spice | Protocol::RustDesk => {
            vec![clipboard, view_only, mac]
        }
        Protocol::Ssh => vec![mac],
        Protocol::Moonlight => vec![
            compact_row("Allow clipboard text input")
                .subtitle("The Type clipboard text action types into the remote app. Moonlight does not synchronize clipboards in either direction.")
                .subtitle_wrap(true)
                .switch(!form.disable_clipboard, |enabled| Message::FormDisableClipboardToggled(!enabled))
                .into_element(),
            view_only, mac,
        ],
    };
    if form.protocol == Protocol::Vnc {
        rows.push(compact_row("Require verified TLS (VeNCrypt)")
            .subtitle("Requires a trusted host certificate and VeNCrypt 0.2. Refuses plaintext downgrade.")
            .subtitle_wrap(true).switch(form.vnc_tls, Message::FormVncTlsChanged).into_element());
    }
    if form.plaintext_ack_offered() {
        rows.push(
            compact_row(format!(
                "Allow unencrypted {} to this host",
                form.protocol.label()
            ))
            .subtitle(
                "Screen and input are exposed on the network. \
                     Off until you turn it on, and turned off again if you change \
                     the host or the protocol.",
            )
            .subtitle_wrap(true)
            .switch(
                form.plaintext_acknowledged(),
                Message::FormPlaintextAckToggled,
            )
            .into_element(),
        );
    }
    rows.extend([reconnect, attempts, ceiling]);

    let content = enz_vstack(rows)
        .gap(SpaceToken::Xs)
        .cross(CrossAlign::Stretch)
        .spacing_scale(enz.spacing)
        .into_element();

    enz_preferences_group(content)
        .id("remote-form-options")
        .spacing_scale(enz.spacing)
        .into_element()
}

fn media_group<'a>(enz: &EnzTheme, form: &'a ConnectionForm) -> Element<'a, Message> {
    let mut rows = Vec::new();
    if matches!(
        form.protocol,
        Protocol::Rdp | Protocol::Spice | Protocol::RustDesk | Protocol::Moonlight
    ) {
        rows.push(
            compact_row("Play remote audio")
                .switch(form.audio_enabled, Message::FormAudioEnabledChanged)
                .into_element(),
        );
    }
    if form.protocol == Protocol::Moonlight {
        rows.push(
            compact_row("Resume running host app")
                .subtitle(
                    "Join the app already running on this host; this can affect its other clients.",
                )
                .subtitle_wrap(true)
                .switch(form.moonlight_resume, Message::FormMoonlightResumeChanged)
                .into_element(),
        );
        rows.push(
            compact_row("Forward gamepads")
                .subtitle(
                    "Controllers are forwarded only while the remote desktop has input capture.",
                )
                .subtitle_wrap(true)
                .switch(
                    form.moonlight_gamepads,
                    Message::FormMoonlightGamepadsChanged,
                )
                .into_element(),
        );
    }
    if matches!(form.protocol, Protocol::Rdp | Protocol::Spice) {
        rows.push(compact_row("Resize remote display with this window")
            .subtitle("Requires host display-control support or the SPICE guest agent. Disabled in view-only sessions.")
            .subtitle_wrap(true).switch(form.dynamic_resize, Message::FormDynamicResizeChanged).into_element());
    }
    enz_preferences_group(
        enz_vstack(rows)
            .gap(SpaceToken::Xs)
            .cross(CrossAlign::Stretch)
            .spacing_scale(enz.spacing)
            .into_element(),
    )
    .spacing_scale(enz.spacing)
    .into_element()
}

/// The port-forwarding section: an "Add rule" row followed by one group per
/// rule.
///
/// A plain column rather than `enz_reorder_list`, because forward order carries no
/// meaning.
fn port_forward_section<'a>(enz: &EnzTheme, form: &'a ConnectionForm) -> Vec<Element<'a, Message>> {
    let mut out: Vec<Element<'a, Message>> = Vec::new();

    // The group already shows "Port forwarding" as its heading, so the row names
    // its action.
    let header = compact_row("Add a forward rule")
        .subtitle("Additional TCP forwarding rules run while this connection is active.")
        .subtitle_wrap(true)
        .icon("action.add")
        .action("Add Rule", Message::RuleAdded)
        .into_element();

    // An explicit empty state distinguishes an empty list from a failed load.
    let mut group_children: Vec<Element<'a, Message>> = vec![header];
    if form.rules.is_empty() {
        group_children.push(
            enz_text(crate::organise::NO_FORWARDING_RULES)
                .size(TextSize::Caption)
                .tone(TextTone::Muted)
                .into_element(),
        );
    }

    out.push(
        enz_preferences_group(
            enz_vstack(group_children)
                .gap(SpaceToken::Xs)
                .cross(CrossAlign::Stretch)
                .spacing_scale(enz.spacing)
                .into_element(),
        )
        .title("Port forwarding")
        // The flags match `PortForwardRule::summary`;
        // `form::tests::the_rule_summary_specimen_is_what_the_formatter_produces` pins
        // the two together.
        .description("SSH tunnel rules (-L, -R, -D)")
        .spacing_scale(enz.spacing)
        .into_element(),
    );

    for rule in &form.rules {
        out.push(rule_group(enz, rule));
    }
    out
}

/// One editable forward rule.
fn rule_group<'a>(enz: &EnzTheme, rule: &'a RuleDraft) -> Element<'a, Message> {
    let id = rule.id;
    let identity = rule_owner(id);
    let mut children: Vec<Element<'a, Message>> = Vec::new();

    // Direction. Index-based into `PORT_FORWARD_TYPE_LABELS`, pinned against
    // `PORT_FORWARD_TYPES` by `model::tests::
    // port_forward_type_labels_are_index_aligned_with_the_variant_array`.
    children.push(
        enz_radio_group(
            "Direction",
            &PORT_FORWARD_TYPE_LABELS,
            Some(rule.forward_type.index()),
            move |i| Message::RuleTypePicked(id, i),
        )
        .orientation(Orientation::Vertical)
        .spacing(enz.spacing.xs())
        .tokens(RadioTokens::from_palette(&enz.palette))
        .id(identity.id("direction"))
        .into_element(),
    );

    // Names the default listener; a remote forward listens on the server, so it is
    // never promised as loopback.
    let (bind_help, bind_placeholder) = if rule.forward_type.binds_on_the_server() {
        (
            "Empty uses the server's default; * asks the server for all interfaces",
            "server default",
        )
    } else {
        (
            "Empty binds localhost only; * binds all interfaces",
            "localhost",
        )
    };
    children.push(
        compact_row("Bind Address")
            .subtitle(bind_help)
            .subtitle_wrap(true)
            .id(identity.id("bind-address"))
            .entry(&rule.bind_address, bind_placeholder, move |v| {
                Message::RuleBindAddressChanged(id, v)
            })
            .into_element(),
    );
    let mut bind_port = compact_row("Bind Port").id(identity.id("bind-port")).entry(
        &rule.bind_port,
        "e.g. 8080",
        move |v| Message::RuleBindPortChanged(id, v),
    );
    if let Some(error) = rule.bind_port_error() {
        bind_port = bind_port.error(error);
    }
    children.push(bind_port.into_element());

    // A dynamic (`-D`) forward is a SOCKS proxy with no fixed destination, so the
    // destination rows are absent.
    if rule.forward_type.needs_destination() {
        let mut destination_host = compact_row("Dest Host")
            .id(identity.id("destination-host"))
            .entry(&rule.dest_host, "e.g. db.internal", move |v| {
                Message::RuleDestHostChanged(id, v)
            });
        if let Some(error) = rule.dest_host_error() {
            destination_host = destination_host.error(error);
        }
        children.push(destination_host.into_element());

        let mut destination_port = compact_row("Dest Port")
            .id(identity.id("destination-port"))
            .entry(&rule.dest_port, "e.g. 5432", move |v| {
                Message::RuleDestPortChanged(id, v)
            });
        if let Some(error) = rule.dest_port_error() {
            destination_port = destination_port.error(error);
        }
        children.push(destination_port.into_element());
    }

    children.push(
        compact_row("Enabled")
            .id(identity.id("enabled"))
            .switch(rule.enabled, move |on| Message::RuleEnabledToggled(id, on))
            .into_element(),
    );

    let content = enz_vstack(children)
        .gap(SpaceToken::Xs)
        .cross(CrossAlign::Stretch)
        .spacing_scale(enz.spacing)
        .into_element();

    enz_preferences_group(content)
        .title(&rule.heading())
        // `owner` also names Remove; under `.id` that action would reach assistive
        // technology without Click or focus.
        .owner(identity)
        .header_action("Remove", Message::RuleRemoved(id))
        .bordered(true)
        .spacing_scale(enz.spacing)
        .into_element()
}

/// The forward-type variant a picker index means.
///
/// The reducer calls this rather than indexing `PORT_FORWARD_TYPES` itself, so
/// there is one place the index → variant mapping happens and it is the one
/// `model.rs`'s alignment tests pin.
pub fn forward_type_from_index(i: usize) -> PortForwardType {
    PortForwardType::from_index(i)
}
