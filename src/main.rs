//! Remote connection profiles, embedded desktops and SSH file browsing.
//!
//! Saved profiles for unavailable protocols remain editable and exportable.

#![deny(unconditional_recursion)]

#[cfg(feature = "center")]
mod center;
mod context_menu;
mod db;
mod desktop_input;
mod desktop_open;
mod desktop_scancode;
mod desktop_worker;
mod discovery;
mod display;
mod error_boundary;
mod form;
mod form_view;
mod framebuffer;
mod import_remmina;
mod import_source;
mod keyring;
mod l10n;
mod layout;
mod modal_focus;
mod model;
mod moonlight;
mod native_clipboard;
mod organise;
mod picker;
mod portable;
mod protocol;
mod quick_connect;
mod quick_connect_view;
mod rdp;
mod reconnect;
mod rfb;
mod rustdesk;
mod screenshot;
mod session;
mod session_view;
mod shortcuts;
mod sidebar_view;
mod spice;
mod state_machine;
mod stream_audio;
mod stream_video;
mod theme;
mod tunnel;
mod view;

// Message model, credential plumbing, app state and post-`impl App`
// free helpers relocated into dedicated modules.
mod app_state;
mod credential_plumbing;
mod main_helpers;
mod message;

#[path = "app_parts/boot.rs"]
mod boot;
#[path = "app_parts/close.rs"]
mod close;
#[path = "app_parts/connect.rs"]
mod connect;
#[path = "app_parts/credentials.rs"]
mod credentials;
#[path = "app_parts/delivery.rs"]
mod delivery;
#[path = "app_parts/events.rs"]
mod events;
#[path = "app_parts/import_export.rs"]
mod import_export;
#[path = "app_parts/profiles.rs"]
mod profiles;
#[path = "app_parts/recency.rs"]
mod recency;
#[path = "app_parts/reduce_batch1.rs"]
mod reduce_batch1;
#[path = "app_parts/reduce_batch2.rs"]
mod reduce_batch2;
#[path = "app_parts/reduce_batch3.rs"]
mod reduce_batch3;
#[path = "app_parts/scan.rs"]
mod scan;
#[path = "app_parts/shell.rs"]
mod shell;
#[path = "app_parts/transfers.rs"]
mod transfers;

use enzui_iced_widgets::nav_split::NavSplitState;
use iced::{Element, Subscription, Task, Theme, advanced::widget::operate};
use uuid::Uuid;

use std::sync::Arc;

use crate::db::ProfileDb;
use crate::discovery::{HostScanner, StubScanner};
use crate::form::{ConnectionForm, PasswordOutcome};
use crate::keyring::{profile_password_key, tunnel_password_key};
use crate::model::{ConnectionProfile, Protocol, Session, SessionStatus};
use crate::session::{KeystrokeMacro, KeystrokePage};
use crate::state_machine::{SessionEvent, transition};
use enzui_iced_core::close_guard::{CloseDecision, CloseGuardAction, CloseRequest, UnsavedItem};
use enzui_iced_core::focus::{Traversal, traversal_operation};
use enzui_iced_core::frame_plan::FrameSeq;
use enzui_iced_core::menu_model::MenuState;
use enzui_iced_widgets::app_shell::{ShellLayout, enz_window_settings};
#[cfg(not(test))]
use enzui_services::credential_store::UnavailableCredentialStore;
#[cfg(not(test))]
use enzui_services::credential_store::secret_service::SecretServiceTransport;
use enzui_services::credential_store::{CredentialStore, Secret};

// Named only by this file's inline `#[cfg(test)]` modules.

// Keep every `crate::…` path and the test modules' `use super::*`
// resolving unchanged after the relocation above.
pub(crate) use crate::app_state::{App, ProfileOp, TransferResult, WolStatus, theme_boot};
pub(crate) use crate::credential_plumbing::{
    ConnectedCredentialStore, CredResult, CredentialNotice,
};
pub(crate) use crate::main_helpers::{
    LibraryFixture, capture_demo_hosts, classify_close_request, classify_event,
    classify_main_window_opened, form_restore_id, keystroke_menu_model, start_view,
};
pub(crate) use crate::message::Message;

/// How often the app wakes while a connection is still closing.
///
/// A retry interval, not a deadline: each wake collects what has finished and
/// redispatches what a busy teardown pool refused. The subscription exists
/// only while there is owed work, so an idle app holds no timer.
pub(crate) const CLOSE_TICK: std::time::Duration = std::time::Duration::from_millis(150);

/// How many wakes a held window close waits before it asks the user.
///
/// Counted in wakes so the deadline does not depend on a clock read:
/// [`CLOSE_TICK`] times this is six seconds, after which the close stops
/// waiting silently and shows its exact remaining debt with Retry and a veto.
pub(crate) const CLOSE_WAKE_BUDGET: u32 = 40;

// ---------------------------------------------------------------------------
// Credential plumbing
// ---------------------------------------------------------------------------

/// Which of a profile's two secrets a credential op refers to.
///
/// A profile can hold a connection password and a distinct SSH-tunnel
/// password (`crate::keyring::{profile_password_key, tunnel_password_key}`),
/// so a save result has to say which flag it confirms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretSlot {
    /// The connection's own password.
    Password,
    /// The SSH jump host's password.
    Tunnel,
}

/// What a credential save op was trying to do, so its outcome can be read
/// correctly: an `Unavailable` on a *store* is "could not save the password",
/// while an `Unavailable` on a *clear* cannot prove whether an old secret is
/// gone and is surfaced truthfully.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveIntent {
    /// A `set` — the marker is raised only on `Stored`, and only then.
    Store,
    /// A `delete` — the marker stays raised until the store confirms the
    /// secret is gone, so a deletion that never happened cannot leave a
    /// secret in the keyring with no record pointing at it.
    Clear,
}

/// How far one profile's connection has got in closing, whichever protocol
/// held it.
///
/// A lost VNC worker join remains distinct from a confirmed retirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCloseProgress {
    /// Severed, and the client or the workers are still being ended. Ordinary,
    /// and expected to clear on its own on a later wake.
    Closing,
    /// VNC: the transport was severed, and the join that would have proved its
    /// reader and writer ended was lost. Permanent — the close surface's Retry
    /// and Keep Open are the only routes left, and admission stays shut.
    Unconfirmed,
}

/// The two ways a Wake-on-LAN attempt can go wrong before the boundary
/// classifier runs. Kept small on purpose: the reducer takes this shape from
/// [`Message::WakeOnLan`] (and only from there); tests can construct it
/// directly to inject a permission / unavailable / hostile raw payload
/// without touching a real UDP socket.
#[derive(Debug, Clone)]
pub(crate) enum WolAttemptFailure {
    /// The stored MAC did not parse. Never a socket failure.
    InvalidMac(String),
    /// [`crate::model::send_wol_packet`] returned an untranslated
    /// diagnostic; the classifier consumes it on `record_wol_attempt`.
    SendFailed(String),
}

/// The sequence number the next frame for `sink` must carry.
///
/// Derived from the sink's own plan rather than kept in a parallel counter,
/// because the plan is what will compare it: it refuses anything not newer
/// than every frame it retains, and a counter that drifted from the plan
/// would silently start dropping every frame.
fn next_frame_seq(sink: &enzui_iced_core::media::BoundedFrameSink) -> FrameSeq {
    let plan = sink.plan();
    match [
        plan.displayed_seq(),
        plan.in_flight_seq(),
        plan.queued_seq(),
    ]
    .into_iter()
    .flatten()
    .max()
    {
        Some(newest) => newest.next(),
        None => FrameSeq(0),
    }
}

/// What handing a keystroke chord to a session actually did.
///
/// An unavailable or disconnected backend differs from a partial input failure.
enum MacroOutcome {
    /// Every key event reached a registered backend.
    Sent,
    /// No backend serves this protocol, or the session is not connected.
    NoBackend,
    /// A registered backend refused part-way through the chord.
    Refused { sent: usize, reason: String },
}

fn save_export(
    path: &std::path::Path,
    bytes: &[u8],
) -> Result<(), enzui_iced_core::user_file::SaveError> {
    enzui_iced_core::user_file::save(
        path,
        enzui_iced_core::user_file::SavePolicy::ReplaceOrCreate,
        bytes,
    )?;
    #[cfg(test)]
    if export_fault::take_published_failure() {
        return Err(
            enzui_iced_core::user_file::SaveError::PublishedButNotDurable {
                operation: enzui_iced_core::user_file::SaveOperation::SyncParent,
                source: std::io::Error::other("injected parent sync failure"),
            },
        );
    }
    Ok(())
}

#[cfg(test)]
mod export_fault {
    use std::cell::Cell;

    thread_local! {
        static PUBLISHED_FAILURE: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn take_published_failure() -> bool {
        PUBLISHED_FAILURE.with(|armed| armed.replace(false))
    }
}

impl App {
    fn update(&mut self, message: Message) -> Task<Message> {
        enzui_iced_core::crash_report::observe(&message);
        // The countdown a waiting profile shows is a function of reducer
        // state, refreshed once per turn, rather than of when a frame happened
        // to be painted. An app with nothing waiting reads no clock.
        if self.reconnect.is_waiting() {
            self.reconnect.observe(std::time::Instant::now());
        }
        // Only a receipt's own arm may drain its batch; a generic drain would consume
        // a newer batch under an older identity. Other turns drain because ordinary
        // messages can arrive before the wake.
        let receipt = matches!(&message, Message::A11yWake(_));
        let routed = if receipt {
            Vec::new()
        } else {
            Self::drain_routed_accessibility_actions()
        };
        if matches!(
            &message,
            Message::ImportRdp
                | Message::ImportRemmina
                | Message::ImportProfiles
                | Message::ExportProfiles
        ) {
            self.import_menu_open = false;
        }
        if matches!(
            &message,
            Message::FormOpenEdit(_) | Message::SessionAction(_)
        ) {
            self.titlebar_overflow_open = false;
        }
        // Each action's operation runs in the window that published its target,
        // not the current window.
        let a11y_pending =
            enzui_iced_widgets::a11y_actions::apply_accessibility_actions::<Message>(routed);
        let task = self.update_inner(message);
        self.reconcile_open_context_menu();
        self.release_inactive_desktops();
        let _ = self
            .toasts
            .sync_expiry(&mut self.toast_schedule, std::time::Instant::now());
        Task::batch([
            a11y_pending,
            task,
            self.sync_standard_modal_focus(),
            self.connect_saved_requests(),
            self.sync_fullscreen(),
        ])
    }

    #[allow(clippy::too_many_lines)]
    fn update_inner(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::FormSectionChanged(section, open) => {
                if let Some(form) = self.form.as_mut() {
                    if open {
                        form.sections.insert(section);
                    } else {
                        form.sections.remove(&section);
                    }
                }
                return Task::none();
            }
            Message::HelpDialog(event) => {
                let (_, task) = self.dialogs.update(event);
                return task;
            }
            Message::CloseHelp => {
                let (_, task) = self.dialogs.dismiss(
                    &crate::shortcuts::Dialog::Help,
                    enzui_iced_core::modal::DismissCause::CancelAction,
                );
                return task;
            }
            Message::AppCommand(command) => {
                if self.modal_open() {
                    return Task::none();
                }
                self.titlebar_overflow_open = false;
                self.import_menu_open = false;
                self.context_menu.close();
                return self.update_inner(match command {
                    crate::shortcuts::Command::NewConnection => Message::FormOpenAdd,
                    crate::shortcuts::Command::QuickConnect => Message::QuickConnectOpen,
                    crate::shortcuts::Command::Help => {
                        return self.dialogs.open(
                            crate::shortcuts::Dialog::Help,
                            Some(iced::advanced::widget::Id::new(
                                "remote-app-titlebar-overflow",
                            )),
                        );
                    }
                });
            }
            // Forward framework theme events to the shared host and re-emit its task.
            // `theme_generation` must never decrease; a debug_assert guards it.
            Message::Theme(event) => return self.reduce1_theme_0(*event),
            Message::WindowResized(size) => return self.reduce1_window_resized_1(size),
            Message::CloseSidebarOverlay => return self.reduce1_close_sidebar_overlay_2(),
            Message::SidebarState(next) => return self.reduce1_sidebar_state_3(next),
            Message::ToggleTitlebarOverflow => return self.reduce1_toggle_titlebar_overflow_4(),
            Message::CloseTitlebarOverflow => {
                self.titlebar_overflow_open = false;
            }
            Message::CloseImportMenu => {
                if self.import_menu_open {
                    return self.reduce1_toggle_import_menu_5();
                }
            }
            Message::ToggleImportMenu => return self.reduce1_toggle_import_menu_5(),
            Message::Window(command) => return self.reduce1_window_6(command),
            Message::MainWindowOpened(id) => return self.reduce1_main_window_opened_7(id),
            Message::WindowCloseRequested(request) => {
                return self.reduce1_window_close_requested_8(request);
            }
            Message::ConnectionCloseTick => return self.reduce1_connection_close_tick_9(),
            Message::WindowCloseRetry => return self.reduce1_window_close_retry_10(),
            Message::WindowCloseVeto => return self.reduce1_window_close_veto_11(),
            Message::ToggleGroup(key) => return self.reduce1_toggle_group_12(key),
            Message::ToggleFavorites => return self.reduce1_toggle_favorites_13(),
            Message::NoOp => return self.reduce1_no_op_14(),
            Message::A11yWake(receipt) => return self.reduce1_a11y_wake_15(receipt),
            Message::SearchChanged(q) => return self.reduce1_search_changed_16(q),
            Message::SelectProfile(id) => return self.reduce1_select_profile_17(id),
            Message::ActivateProfile(id) => {
                if self.modal_open() || !self.profiles.iter().any(|p| p.id == id) {
                    return Task::none();
                }
                let select = self.reduce1_select_profile_17(id);
                let connect = if matches!(
                    self.session_status_for(id),
                    SessionStatus::Disconnected | SessionStatus::Error
                ) {
                    self.drive_session(id)
                } else {
                    Task::none()
                };
                return Task::batch([select, connect]);
            }
            Message::SidebarProfilePressed(id, path) => {
                if self.modal_open() || !self.profiles.iter().any(|p| p.id == id) {
                    return Task::none();
                }
                self.selected_profile = Some(id);
                return iced::advanced::widget::operate(
                    enzui_iced_core::focus::focus_and_reveal_id(crate::sidebar_view::row_id(&path)),
                );
            }
            Message::SidebarNavigate(path, key) => {
                return crate::sidebar_view::navigate(self, path, key);
            }
            #[cfg(feature = "center")]
            Message::Center(event) => return self.center_event(event),
            Message::SessionAction(pid) => return self.reduce1_session_action_18(pid),
            Message::ConnectResult(pid, generation, result, stream_slot) => {
                return self.reduce1_connect_result_19(pid, generation, result, stream_slot);
            }
            // An event from a live session stream.
            Message::FrameUploaded(pid, instance, frame) => {
                return self.frame_uploaded(pid, instance, frame);
            }
            Message::SessionStreamEvent(pid, generation, event) => {
                return self.reduce1_session_stream_event_20(pid, generation, event);
            }
            // A scheduled reconnect deadline elapsed.
            Message::ReconnectTick(pid, generation, now) => {
                return self.reduce1_reconnect_tick_21(pid, generation, now);
            }
            Message::ReconnectCancel(pid) => return self.reduce1_reconnect_cancel_22(pid),
            Message::SessionSurfaceResized(pid, size) => {
                return self.reduce1_session_surface_resized_23(pid, size);
            }
            Message::DesktopPointerCancel(pid) => {
                self.cancel_desktop_pointer(pid);
            }
            Message::DesktopScroll(pid, delta) => {
                self.deliver_desktop_scroll(pid, delta);
                return Task::none();
            }
            Message::DesktopKey(pid, input) => {
                self.deliver_desktop_key(pid, input);
                return Task::none();
            }
            Message::SessionPointer(pid, gesture) => {
                return self.reduce1_session_pointer_24(pid, gesture);
            }

            // ---- Credential store ---------------------------
            Message::CredentialStoreReady(ConnectedCredentialStore(store)) => {
                return self.reduce1_credential_store_ready_25(store);
            }
            Message::PasswordFetched(pid, generation, result) => {
                return self.reduce1_password_fetched_26(pid, generation, result);
            }
            Message::CredentialSaveResult(id, generation, slot, intent, result) => {
                return self
                    .reduce1_credential_save_result_27(id, generation, slot, intent, result);
            }
            Message::DismissDbNotice => self.db_notice_dismissed = true,
            Message::SidebarActionHover(id, hovered) => {
                if hovered {
                    self.sidebar_action_hover = Some(id);
                } else if self.sidebar_action_hover.as_ref() == Some(&id) {
                    self.sidebar_action_hover = None;
                }
            }
            Message::ToggleSessionResize(pid, generation) => {
                return self.toggle_session_resize(pid, generation);
            }
            Message::DismissCredentialNotice => return self.reduce1_dismiss_credential_notice_28(),
            Message::DismissWolStatus => return self.reduce1_dismiss_wol_status_29(),
            Message::Toast(event) => {
                let _ = self.toasts.update(event);
            }

            // ---- Clipboard sharing ----------------------------------------
            Message::NativeClipboardWritten(pid, generation, result) => {
                if result.is_ok()
                    && self.native_clipboard_allowed(pid, generation)
                    && self.sessions.iter().any(|s| {
                        s.profile_id == pid && s.profile_snapshot.protocol == Protocol::RustDesk
                    })
                {
                    self.toasts.push(
                        enzui_iced_widgets::toast_host::ToastSpec::new(crate::l10n::text(
                            "remote-native-copy-ready",
                        ))
                        .coalesce_key("remote-native-clipboard"),
                    );
                }
                if self.session_streams.get(&pid) == Some(&generation)
                    && result.is_err()
                    && let Some(session) = self.sessions.iter_mut().find(|s| s.profile_id == pid)
                {
                    session.last_message = "Cannot write the local clipboard.".into();
                }
                return Task::none();
            }
            Message::SyncClipboard(pid, generation, paste) => {
                return self.read_native_clipboard(pid, generation, paste);
            }
            Message::SyncedClipboard(pid, generation, paste, result) => {
                return self.sync_native_clipboard(
                    pid,
                    generation,
                    paste,
                    result.map(|text| text.0),
                );
            }
            Message::ToggleSessionClipboard(pid) => {
                return self.reduce1_toggle_session_clipboard_30(pid);
            }
            Message::SendClipboardToSession(pid) => {
                return self.reduce1_send_clipboard_to_session_31(pid);
            }
            Message::SaveScreenshot(pid) => return self.begin_screenshot(pid),
            Message::ScreenshotSaved(result) => {
                self.transfer_result = Some(match result {
                    Ok(path) => TransferResult::ScreenshotSaved { path },
                    Err(message) => TransferResult::Failed {
                        message: format!("The screenshot could not be saved: {message}"),
                    },
                });
                return Task::none();
            }
            Message::ClipboardToSession(pid, result) => {
                return self.reduce2_clipboard_to_session_46(pid, result);
            }
            Message::FocusNext => return self.reduce2_focus_next_47(),
            Message::FocusPrevious => return self.reduce2_focus_previous_48(),

            // ---- Connection form ------------------------------------------
            Message::FormOpenAdd => return self.reduce2_form_open_add_49(),
            Message::FormOpenEdit(id) => return self.reduce2_form_open_edit_50(id),
            Message::FormNameChanged(v) => return self.reduce2_form_name_changed_51(v),
            Message::FormHostChanged(v) => return self.reduce2_form_host_changed_52(v),
            Message::FormPortChanged(v) => return self.reduce2_form_port_changed_53(v),
            Message::FormProtocolPicked(protocol) => {
                return self.reduce2_form_protocol_picked_54(protocol);
            }
            Message::FormUsernameChanged(v) => return self.reduce2_form_username_changed_55(v),
            Message::FormMoonlightAppIdChanged(value) => {
                if let Some(form) = self.form.as_mut() {
                    form.moonlight_app_id = value;
                }
                return Task::none();
            }
            Message::FormVncTlsChanged(value) => {
                if let Some(form) = self.form.as_mut() {
                    form.vnc_tls = value;
                }
                return Task::none();
            }
            Message::FormVncFingerprintChanged(value) => {
                if let Some(form) = self.form.as_mut() {
                    form.set_vnc_fingerprint(value);
                }
                return Task::none();
            }
            Message::FormDynamicResizeChanged(value) => {
                if let Some(form) = self.form.as_mut() {
                    form.dynamic_resize = value;
                }
                return Task::none();
            }
            Message::FormAudioEnabledChanged(value) => {
                if let Some(form) = self.form.as_mut() {
                    form.audio_enabled = value;
                }
                return Task::none();
            }
            Message::FormMoonlightResumeChanged(value) => {
                if let Some(form) = self.form.as_mut() {
                    form.moonlight_resume = value;
                }
                return Task::none();
            }
            Message::FormMoonlightGamepadsChanged(value) => {
                if let Some(form) = self.form.as_mut() {
                    form.moonlight_gamepads = value;
                }
                return Task::none();
            }
            Message::FormMoonlightPairAgainChanged(value) => {
                if let Some(form) = self.form.as_mut() {
                    form.moonlight_pair_again = value;
                    form.moonlight_pair_request = value.then(|| Uuid::new_v4().to_string());
                }
                return Task::none();
            }
            Message::FormRustDeskIdModeChanged(value) => {
                if let Some(form) = self.form.as_mut() {
                    form.rustdesk_id_mode = value;
                }
                return Task::none();
            }
            Message::FormRustDeskServerChanged(value) => {
                if let Some(form) = self.form.as_mut() {
                    form.rustdesk_server = value;
                }
                return Task::none();
            }
            Message::FormRustDeskServerKeyChanged(value) => {
                if let Some(form) = self.form.as_mut() {
                    form.rustdesk_server_key = value;
                }
                return Task::none();
            }
            Message::FormRustDeskRelayChanged(value) => {
                if let Some(form) = self.form.as_mut() {
                    form.rustdesk_relay = value;
                }
                return Task::none();
            }
            Message::FormRustDeskPeerKeyChanged(value) => {
                if let Some(form) = self.form.as_mut() {
                    form.rustdesk_peer_key = value;
                }
                return Task::none();
            }
            Message::FormPasswordChanged(v) => return self.reduce2_form_password_changed_56(v),
            Message::FormPasswordRevealToggled => {
                return self.reduce2_form_password_reveal_toggled_57();
            }
            Message::FormDisplayWidthChanged(value) => {
                if let Some(form) = self.form.as_mut() {
                    form.display_width = value;
                }
                return Task::none();
            }
            Message::FormDisplayHeightChanged(value) => {
                if let Some(form) = self.form.as_mut() {
                    form.display_height = value;
                }
                return Task::none();
            }
            Message::FormWolMacChanged(v) => return self.reduce2_form_wol_mac_changed_59(v),
            Message::FormDisableClipboardToggled(on) => {
                return self.reduce2_form_disable_clipboard_toggled_60(on);
            }
            Message::FormPlaintextAckToggled(on) => {
                return self.reduce2_form_plaintext_ack_toggled_61(on);
            }
            Message::FormReconnectToggled(on) => return self.reduce2_form_reconnect_toggled_62(on),
            Message::FormReconnectAttemptsChanged(text) => {
                return self.reduce2_form_reconnect_attempts_changed_63(text);
            }
            Message::FormReconnectCeilingChanged(text) => {
                return self.reduce2_form_reconnect_ceiling_changed_64(text);
            }
            Message::FormSave => return self.reduce2_form_save_65(),
            Message::FormCancel => return self.reduce2_form_cancel_66(),
            Message::FormDelete => return self.reduce2_form_delete_67(),
            Message::RequestDeleteProfile(id) => return self.reduce2_request_delete_profile_68(id),
            Message::DeleteProfileConfirmEvent(event) => {
                return self.reduce2_delete_profile_confirm_event_69(event);
            }
            Message::FormModalEvent(event) => return self.reduce2_form_modal_event_70(event),

            // ---- Port-forward rules ---------------------------------------
            Message::RuleAdded => return self.reduce2_rule_added_71(),
            Message::RuleRemoved(id) => return self.reduce2_rule_removed_72(id),
            Message::RuleTypePicked(id, index) => {
                return self.reduce2_rule_type_picked_73(id, index);
            }
            Message::RuleBindAddressChanged(id, v) => {
                return self.reduce2_rule_bind_address_changed_74(id, v);
            }
            Message::RuleBindPortChanged(id, v) => {
                return self.reduce2_rule_bind_port_changed_75(id, v);
            }
            Message::RuleDestHostChanged(id, v) => {
                return self.reduce2_rule_dest_host_changed_76(id, v);
            }
            Message::RuleDestPortChanged(id, v) => {
                return self.reduce2_rule_dest_port_changed_77(id, v);
            }
            Message::RuleEnabledToggled(id, on) => {
                return self.reduce2_rule_enabled_toggled_78(id, on);
            }
            Message::FormQualityPicked(index) => return self.reduce2_form_quality_picked_79(index),
            Message::FormViewOnlyToggled(on) => return self.reduce3_form_view_only_toggled_80(on),
            Message::FormGroupChanged(v) => return self.reduce3_form_group_changed_81(v),
            Message::FormNotesChanged(v) => return self.reduce3_form_notes_changed_82(v),

            // ---- SSH jump host --------------------------------------------
            Message::FormTunnelHostChanged(v) => {
                return self.reduce3_form_tunnel_host_changed_83(v);
            }
            Message::FormTunnelPortChanged(v) => {
                return self.reduce3_form_tunnel_port_changed_84(v);
            }
            Message::FormTunnelUsernameChanged(v) => {
                return self.reduce3_form_tunnel_username_changed_85(v);
            }
            Message::FormTunnelIdentityChanged(value) => {
                if let Some(form) = self.form.as_mut() {
                    form.tunnel_identity = value;
                    form.tunnel_password.clear();
                    form.tunnel_password_dirty = true;
                }
                return Task::none();
            }
            Message::FormTunnelPasswordChanged(v) => {
                return self.reduce3_form_tunnel_password_changed_86(v);
            }

            // ---- Session view chrome --------------------------------------
            Message::ToggleSessionFullscreen(pid) => {
                return self.reduce3_toggle_session_fullscreen_88(pid);
            }
            Message::ToggleSessionScaling(pid) => {
                return self.reduce3_toggle_session_scaling_89(pid);
            }
            Message::ToggleSessionInputMode(pid) => {
                return self.reduce3_toggle_session_input_mode_90(pid);
            }
            Message::KeystrokeMenu(event) => return self.reduce3_keystroke_menu_91(event),

            // ---- Organisation ---------------------------------------------
            Message::ScanNetwork => return self.reduce3_scan_network_92(),
            Message::ScanFinished {
                generation,
                outcome,
            } => return self.reduce3_scan_finished_93(generation, outcome),
            Message::ScanCancel => return self.reduce3_scan_cancel_94(),
            Message::SaveDiscovered(key) => return self.reduce3_save_discovered_95(key),

            // ---- Import / export ------------------------------------------
            Message::ExportProfiles => return self.reduce3_export_profiles_96(),
            Message::ImportRdp => return self.reduce3_import_rdp_97(),
            Message::ImportRemmina => return self.reduce3_import_remmina_98(),
            Message::ImportProfiles => return self.reduce3_import_profiles_99(),
            Message::ChooserParentReady(tag, window, reply) => {
                let live_window = if self.close_is_held() {
                    None
                } else {
                    self.main_window
                };
                return self
                    .transfer_picker
                    .parent_ready(tag, window, reply, live_window);
            }
            Message::TransferChooser(tag, event) => return self.transfer_picker.handle(tag, event),
            Message::TransferChosen(tag, outcome) => {
                if !self.transfer_picker.claim(tag) {
                    return Task::none();
                }
                return self.finish_transfer_pick(tag.target, outcome);
            }
            Message::InstanceWake => {
                let (intents, raise) = self.instance.drain(self.main_window);
                let opened = self.open_desktop_intents(intents);
                return Task::batch([raise, opened]);
            }
            Message::TransferPortalTick => return self.reduce3_transfer_portal_tick_100(),
            Message::ImportReady {
                generation,
                target,
                outcome,
            } => return self.reduce3_import_ready_101(generation, target, *outcome),
            Message::ImportCancel => return self.reduce3_import_cancel_102(),
            Message::DismissTransferResult => return self.reduce3_dismiss_transfer_result_103(),

            // ---- Quick Connect --------------------------------------------
            Message::QuickConnectOpen => return self.reduce3_quick_connect_open_104(),
            Message::QuickConnectDismiss => return self.reduce3_quick_connect_dismiss_105(),
            Message::QuickConnectModalEvent(event) => {
                return self.reduce_quick_connect_host(event);
            }
            Message::QuickConnectRecent(key) => return self.reduce3_quick_connect_recent_107(key),
            Message::QuickConnectSaveRecent(key) => {
                return self.reduce3_quick_connect_save_recent_108(key);
            }
            Message::QuickConnectRetrySave(key) => {
                return self.reduce3_quick_connect_retry_save_109(key);
            }
            Message::QuickConnectForgetRecent(key) => {
                return self.reduce3_quick_connect_forget_recent_110(key);
            }
            Message::QuickConnectClearRecents => {
                return self.reduce3_quick_connect_clear_recents_111();
            }
            Message::QuickConnectEnterDetails => {
                return self.reduce3_quick_connect_enter_details_112();
            }
            Message::QuickConnectAddressChanged(text) => {
                return self.reduce3_quick_connect_address_changed_113(text);
            }
            Message::QuickConnectAddressSubmit => {
                return self.reduce3_quick_connect_address_submit_114();
            }

            // ---- the saved-connection row context menu ----------------------
            Message::OpenContextMenu(id, at, row_path) => {
                return self.reduce3_open_context_menu_115(id, at, row_path);
            }
            // The single funnel for framework host events: the host proposes and
            // `apply_event` applies, including separator-skipping navigation and
            // re-resolving activations against the live surface.
            Message::ContextMenuEvent(event) => return self.reduce3_context_menu_event_116(event),
            Message::ContextRowActivated(id, row) => {
                return self.reduce3_context_row_activated_118(id, row);
            }

            Message::ToggleFavorite(id) => return self.reduce3_toggle_favorite_119(id),
            Message::DuplicateProfile(id) => return self.reduce3_duplicate_profile_120(id),
            Message::DeleteProfile(id) => return self.reduce3_delete_profile_121(id),
            Message::ProfileSecretDeleted(id, generation, result) => {
                return self.reduce3_profile_secret_deleted_122(id, generation, result);
            }
            Message::ProfileTunnelSecretDeleted(id, generation, result) => {
                return self.reduce3_profile_tunnel_secret_deleted_123(id, generation, result);
            }
            Message::WakeOnLan(id) => return self.reduce3_wake_on_lan_124(id),
        }
        Task::none()
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> iced::Result {
    enzui_iced_core::crash_report::CrashReporter::for_app("remote-app", env!("CARGO_PKG_VERSION"));
    use enzui_iced_widgets::single_instance::{InstanceStart, SingleInstance};
    let (instance, intent) = match SingleInstance::start(DESKTOP_APP_ID) {
        InstanceStart::Forwarded => return Ok(()),
        InstanceStart::Owner(instance, intent) if instance.is_shared() => (instance, intent),
        InstanceStart::Owner(_, _) => {
            eprintln!("Remote cannot establish single-instance ownership on the session bus.");
            return Ok(());
        }
    };
    let initial = std::cell::RefCell::new(Some((instance, intent)));
    enzui_iced_widgets::app_setup::run_with_services(
        iced::application(
            move || {
                let (mut app, task) = App::boot();
                let (instance, intent) =
                    initial.borrow_mut().take().expect("application boots once");
                app.instance = instance;
                let opened = app.open_desktop_intents([intent]);
                (app, Task::batch([task, opened]))
            },
            App::update,
            App::view,
        )
        .title("Remote")
        .theme(App::theme)
        .subscription(App::subscription)
        // Held so `App::drive_close_debt` destroys the window only once no
        // connection is still running; teardown in `Drop` would run after the
        // surface is gone.
        .exit_on_close_request(false)
        // Derived from the layout, so it cannot drift from the `.layout(..)` the view
        // renders.
        .window(with_desktop_identity(enz_window_settings(
            ShellLayout::TitlebarSidebarContent,
        ))),
        enzui_iced_widgets::app_setup::AppServices::default()
            .traversal(enzui_iced_widgets::app_setup::TraversalBinding::Disabled)
            .accessibility_actions(false)
            .localizer(crate::l10n::localizer()),
    )
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
//

// Routed accessibility actions for one test turn; the process-global router
// is seeded only by the winit bridge. Thread-local to isolate tests.
#[cfg(test)]
pub(crate) mod a11y_test_queue {
    use enzui_iced_core::app_runtime::RoutedAccessibilityAction;
    use std::cell::RefCell;

    thread_local! {
        static QUEUED: RefCell<Vec<RoutedAccessibilityAction>> = const { RefCell::new(Vec::new()) };
    }

    pub(crate) fn joined(
        drained: Vec<RoutedAccessibilityAction>,
    ) -> Vec<RoutedAccessibilityAction> {
        let mut joined = drained;
        joined.extend(QUEUED.with_borrow_mut(std::mem::take));
        joined
    }
}

/// Render-level guards — the tests that redden when a *view's read* of state
/// is severed. See the module docs for why they are separate from the reducer
/// suites below.
#[cfg(test)]
#[path = "render_tests.rs"]
mod render_tests;

// ---------------------------------------------------------------------------
// Persistence tests
// ---------------------------------------------------------------------------
//
// These drive `App::boot_with_db` and `App::update`, not the `db` module.

#[cfg(test)]
mod persistence_tests;

// ---------------------------------------------------------------------------
// Profile store write outcomes
// ---------------------------------------------------------------------------
//
// A refused write leaves no row, listing, closed dialog or success banner,
// and the user's draft stays for the retry.

#[cfg(test)]
mod store_write_tests;

// ---------------------------------------------------------------------------
// Durable secret markers
// ---------------------------------------------------------------------------
//
// The keyring answers first and the row records it second; a refused row
// write is disclosed as a disagreement.

#[cfg(test)]
mod secret_marker_tests;

// ---------------------------------------------------------------------------
// Database migration adoption tests
// ---------------------------------------------------------------------------
//
// These drive `App::boot_with_resolver` and `crate::db::open_with_resolver`,
// the functions `boot()` calls, so skipping the migration plan fails here.

#[cfg(test)]
mod db_migration_tests;

// ---------------------------------------------------------------------------
// Connection-form tests
// ---------------------------------------------------------------------------
//
// These drive `App::update` and, for persistence, boot a second app at the
// same DB path.

// ---------------------------------------------------------------------------
// Clipboard sharing
// ---------------------------------------------------------------------------
//
// `Session::clipboard_enabled` is asserted through
// `deliver_clipboard_to_session`, the transfer path. The render half is in
// `render_tests.rs`.

#[cfg(test)]
mod clipboard_tests;

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
//

// ---------------------------------------------------------------------------
// Connect-path plumbing tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod connect_plumbing_tests;

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
//

/// The Wayland/desktop application identity, the basename of the
/// shipped `io.github.enzui.Remote.desktop`, carried onto the main window through the
/// framework's validated descriptor so the compositor and the desktop entry
/// agree (window grouping, icon, `StartupWMClass`).
const DESKTOP_APP_ID: &str = "io.github.enzui.Remote";

fn with_desktop_identity(settings: iced::window::Settings) -> iced::window::Settings {
    enzui_iced_widgets::app_shell::DesktopApplicationIdentity::new(DESKTOP_APP_ID)
        .expect("BUG: DESKTOP_APP_ID must be a portable desktop-entry basename")
        .apply_to_window_settings(settings)
}

#[cfg(test)]
mod desktop_workflow_tests;
