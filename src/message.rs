//! The application `Message` model and its crash-report `MessageKind`
//! projection. Relocated verbatim from `main.rs`.

use std::sync::Arc;

use iced::Size;
use uuid::Uuid;

use enzui_iced_core::app_runtime::AccessibilityWake;
use enzui_iced_core::theme_file::integration::ThemeEvent;
use enzui_iced_widgets::nav_split::NavSplitState;

use crate::credential_plumbing::{ConnectedCredentialStore, CredResult};
use crate::protocol::ProtocolError;
use crate::state_machine::SessionEvent;
use crate::{SaveIntent, SecretSlot};

// ---------------------------------------------------------------------------
// Message
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Message {
    AppCommand(crate::shortcuts::Command),
    FormSectionChanged(crate::form::FormSection, bool),
    // Navigation / shell
    WindowResized(Size),
    CloseSidebarOverlay,
    /// The shell's sidebar toggle published a new [`NavSplitState`].
    ///
    /// The shell already applied `NavSplitState::toggle_for_presentation` for the
    /// frame it drew, so the reducer only stores the result.
    SidebarState(NavSplitState),
    /// Toggle the framework titlebar's measured action-overflow menu.
    ///
    /// The menu state is durable application state; `enz_title_bar` owns the
    /// width measurement and publishes this message for trigger, Escape, and
    /// outside-click dismissal.
    ToggleTitlebarOverflow,
    ToggleImportMenu,
    CloseImportMenu,
    CloseTitlebarOverflow,
    ToggleGroup(String),
    /// Expand or collapse the Favorites pseudo-group. Distinct
    /// from [`Self::ToggleGroup`] because Favorites uses inverted default semantics
    /// (collapsed by default) and is not keyed by a folder/tag name.
    ToggleFavorites,
    /// Benign no-op routed by the sidebar tree_view when Enter/Space
    /// activates a branch row (a folder header). Not `SelectProfile(current)`:
    /// that would touch dismissal state and encode "branch is a profile".
    NoOp,
    /// Coalesced accessibility wake from the shared bootstrap.
    ///
    /// The receipt names the batch of routed actions; the shared applier drains it
    /// (or applies nothing if an earlier turn did) and runs each action in its target
    /// window. Without it the AccessKit thread would wait forever on an idle app.
    A11yWake(AccessibilityWake),
    /// A policy-bearing gesture from the framework titlebar.
    /// Native edge resize bypasses app messages and uses iced's id-less,
    /// current-window request channel instead.
    Window(enzui_iced_widgets::title_bar_gesture::WindowCommand),
    /// The runtime id from the initial window's `Opened` event. The reducer
    /// binds it once so later windows cannot retarget titlebar commands.
    MainWindowOpened(iced::window::Id),
    /// The compositor asked to close a window, named exactly.
    ///
    /// The window is still alive: the reducer severs its connections and
    /// closes this exact id once nothing of theirs is left running.
    WindowCloseRequested(enzui_iced_core::close_guard::CloseRequest),
    /// A coalesced wake while a connection is still closing.
    ///
    /// One call to `BackendRegistry::ssh_close_debt`, which collects what has
    /// finished and redispatches what has not.
    ConnectionCloseTick,
    /// Ask for another teardown attempt after a close failed.
    WindowCloseRetry,
    /// Abandon a held close and keep the app open.
    WindowCloseVeto,
    // Search
    SearchChanged(String),
    // Profiles
    SelectProfile(Uuid),
    ActivateProfile(Uuid),
    SidebarProfilePressed(Uuid, Vec<String>),
    SidebarNavigate(Vec<String>, iced::keyboard::key::Named),
    /// One enzui-center connector event.
    #[cfg(feature = "center")]
    Center(enzui_iced_agent::center::ConnectorEvent),
    // Sessions
    SessionAction(Uuid),
    /// The outcome of a `RemoteProtocol::connect` call that ran off-thread via
    /// `Task::perform`.
    ///
    /// Carries the profile id, the dispatch generation, the immediate events, and an
    /// optional session stream in an `Arc<Mutex<Option<..>>>` so `Message` stays
    /// `Clone`; the reducer takes the stream on first access.
    ///
    /// The `u64` is `App::connect_generation` at dispatch, recorded in
    /// `App::dispatched_connects`. `Task::perform` cannot be cancelled, so an
    /// abandoned connect still lands here and is recognised by its generation. It is
    /// the handshake-stage counterpart of [`Self::SessionStreamEvent`]'s generation.
    ConnectResult(
        Uuid,
        u64,
        Result<Vec<SessionEvent>, ProtocolError>,
        Arc<std::sync::Mutex<Option<crate::protocol::SessionStream>>>,
    ),
    /// An event arrived through a live session's stream and is applied through
    /// `apply_session_event`.
    ///
    /// The `u64` is the stream generation; a stream keeps draining after its session
    /// is closed or replaced, so events from a stale generation are dropped.
    SessionStreamEvent(Uuid, u64, SessionEvent),
    FrameUploaded(Uuid, u64, enzui_iced_widgets::video::ReadyFrame),

    /// A scheduled reconnect attempt's deadline elapsed.
    ///
    /// Carries the profile, the policy generation the deadline was armed under, and
    /// the wake instant. A stale generation (disconnect, edit, delete, app close, or a
    /// Ready that reset the policy) makes the tick inert.
    ReconnectTick(Uuid, u64, std::time::Instant),

    /// Stop reconnecting this profile: cancel the armed deadline and withdraw
    /// the policy's remaining attempts until the user asks again.
    ReconnectCancel(Uuid),

    /// The session surface was laid out at a new size.
    ///
    /// Published by the surface's own `iced::widget::Sensor` every layout
    /// pass. The reducer stores it (the pointer mapping needs the slot the
    /// picture was fitted into) and forwards a *changed* size upstream as a
    /// framebuffer resize request; an unchanged one sends nothing.
    SessionSurfaceResized(Uuid, iced::Size),

    /// A pointer gesture on the session surface.
    ///
    /// Carries slot coordinates; the reducer owns the mapping to remote pixels because
    /// only it holds the slot size, frame geometry and scaling mode.
    DesktopScroll(Uuid, iced::mouse::ScrollDelta),
    DesktopPointerCancel(Uuid),
    DesktopKey(Uuid, crate::protocol::RemoteInput),
    SessionPointer(Uuid, crate::session::PointerGesture),

    // ---- Credential store ---------------------------------
    /// The asynchronous Secret Service connection completed. Boot starts with an
    /// unavailable store so no D-Bus work blocks first paint.
    #[cfg_attr(
        test,
        expect(
            dead_code,
            reason = "The desktop boot connects Secret Service; unit boots use injected stores."
        )
    )]
    CredentialStoreReady(ConnectedCredentialStore),
    /// The profile's stored password fetch resolved, as the first async step of a
    /// connect.
    ///
    /// A value or benign "nothing stored" dispatches the backend connect; a
    /// cancellation reverts the amber dot with no error. The connect generation stops
    /// a superseded op from driving a replacement connect.
    PasswordFetched(Uuid, u64, CredResult),
    /// A credential `set`/`delete` fired by a form save resolved.
    ///
    /// The only message that moves a profile's durable secret marker: raised on a
    /// confirmed store, lowered on a confirmed removal, unchanged on failure or
    /// cancellation. The generation and slot identify the op in `App::profile_ops`,
    /// so superseded, replayed or undispatched terminals are dropped.
    CredentialSaveResult(Uuid, u64, SecretSlot, SaveIntent, CredResult),
    /// A profile's secret `delete`, fired before the profile record is removed,
    /// resolved.
    ///
    /// The record is dropped only on `Deleted`/`NotFound`; refusal and cancellation
    /// keep it so the secret is not orphaned, and `Unavailable` asks for explicit
    /// acknowledgement first. The generation stops a superseded delete from removing
    /// a row a later edit saved.
    ProfileSecretDeleted(Uuid, u64, CredResult),
    /// The same ordered deletion result for the profile's optional SSH-tunnel
    /// secret, under the same generation. The profile record is committed only
    /// after both keys are gone.
    ProfileTunnelSecretDeleted(Uuid, u64, CredResult),
    /// Dismiss the credential notice.
    DismissCredentialNotice,
    DismissDbNotice,
    SidebarActionHover(String, bool),
    /// Dismiss the Wake-on-LAN outcome.
    DismissWolStatus,
    /// A toast expired, was dismissed, or its timer ticked.
    Toast(enzui_iced_widgets::toast_host::ToastEvent),

    // ---- Clipboard sharing ----------------------------------------------
    /// Flip clipboard sharing for the profile's live session.
    ///
    /// Per session, not per profile; the form's "Disable clipboard sharing" switch
    /// edits the saved profile. Inert without a session.
    ToggleSessionClipboard(Uuid),
    NativeClipboardWritten(Uuid, u64, Result<(), iced::clipboard::Error>),
    SyncClipboard(Uuid, u64, Option<bool>),
    SyncedClipboard(
        Uuid,
        u64,
        Option<bool>,
        Result<crate::native_clipboard::Text, iced::clipboard::Error>,
    ),
    /// Read the system clipboard text for the profile's session; the result arrives
    /// as [`Message::ClipboardToSession`].
    ///
    /// Uses iced's async clipboard API, so a slow clipboard owner cannot stall the
    /// reducer.
    SendClipboardToSession(Uuid),
    /// The clipboard text arrived (or failed to). Delivery is gated on the
    /// session's `clipboard_enabled` inside
    /// `App::deliver_clipboard_to_session`.
    ClipboardToSession(Uuid, Result<std::sync::Arc<String>, iced::clipboard::Error>),

    /// Capture the session's current remote picture and ask where to save it
    /// as a PNG.
    SaveScreenshot(Uuid),
    /// The screenshot settled: the saved path, or the sentence explaining why
    /// not.
    ScreenshotSaved(Result<String, String>),
    /// Tab / Shift+Tab move keyboard focus through the shell's focusable widgets,
    /// including the titlebar's close control.
    ///
    /// iced does not traverse focus on Tab itself; the reducer runs
    /// [`enzui_iced_core::focus::traversal_operation`]. The press is decoded by
    /// [`enzui_iced_core::focus::traversal_from_event`], and global traversal is
    /// suppressed while `App::modal_open` is true because a presented modal runs its
    /// own scope.
    FocusNext,
    FocusPrevious,

    // ---- Connection form ------------------------------------------------
    /// Open a blank form for a new profile.
    FormOpenAdd,
    /// Open a form pre-filled from an existing profile.
    FormOpenEdit(Uuid),
    FormNameChanged(String),
    FormHostChanged(String),
    FormPortChanged(String),
    /// A protocol picked in the connection form's radio group.
    ///
    /// Carries the variant, not an index, because the option list is filtered by
    /// `protocol::BackendRegistry::choices`. The reducer still re-checks availability
    /// because a routed accessibility action or replay can reach this arm.
    FormProtocolPicked(crate::model::Protocol),
    FormUsernameChanged(String),
    FormRustDeskPeerKeyChanged(String),
    FormRustDeskIdModeChanged(bool),
    FormRustDeskServerChanged(String),
    FormRustDeskServerKeyChanged(String),
    FormRustDeskRelayChanged(String),
    FormMoonlightAppIdChanged(String),
    FormMoonlightPairAgainChanged(bool),
    FormMoonlightResumeChanged(bool),
    FormMoonlightGamepadsChanged(bool),
    FormAudioEnabledChanged(bool),
    FormDynamicResizeChanged(bool),
    FormVncTlsChanged(bool),
    FormVncFingerprintChanged(String),
    FormPasswordChanged(String),
    FormPasswordRevealToggled,
    FormDisplayWidthChanged(String),
    FormDisplayHeightChanged(String),
    /// The Wake-on-LAN MAC field, stored as text and canonicalised on save so a
    /// half-typed MAC survives.
    FormWolMacChanged(String),
    /// The "Disable clipboard sharing" switch. Carries the model's polarity:
    /// `true` means clipboard sharing is OFF for this profile.
    FormDisableClipboardToggled(bool),
    /// The unencrypted-VNC switch. `true` accepts that the screen and keyboard travel
    /// in clear text to the named host; retyping the host or protocol withdraws it.
    FormPlaintextAckToggled(bool),
    /// The "Reconnect automatically" switch. `true` opts this profile into the
    /// bounded retry policy; the default is off.
    FormReconnectToggled(bool),
    /// The reconnect policy's attempt ceiling, as typed text.
    FormReconnectAttemptsChanged(String),
    /// The reconnect policy's longest wait in seconds, as typed text.
    FormReconnectCeilingChanged(String),
    /// Persist the draft: SQLite for the profile, the OS keyring for the
    /// password. Inert when the draft cannot be saved.
    FormSave,
    /// Close without writing anything.
    FormCancel,
    /// Delete the profile being edited (add-mode is inert).
    FormDelete,
    /// Escape / scrim / Tab inside the dialog. Carries the whole host event
    /// rather than collapsing onto "close", because a Tab press funnelled into
    /// the dismissal closes the dialog the user was tabbing inside of.
    FormModalEvent(enzui_iced_widgets::modal_host::ModalHostEvent),

    // ---- Port-forward rules ---------------------------------------------
    RuleAdded,
    RuleRemoved(Uuid),
    /// A forward direction picked by index into
    /// `model::PORT_FORWARD_TYPE_LABELS`.
    RuleTypePicked(Uuid, usize),
    RuleBindAddressChanged(Uuid, String),
    RuleBindPortChanged(Uuid, String),
    RuleDestHostChanged(Uuid, String),
    RuleDestPortChanged(Uuid, String),
    RuleEnabledToggled(Uuid, bool),

    /// A picture quality picked by index into `model::QUALITY_LABELS`, mapped by
    /// `model::quality_from_index`.
    FormQualityPicked(usize),
    /// The "Open read-only" switch. `true` means input is not forwarded.
    FormViewOnlyToggled(bool),
    FormGroupChanged(String),
    FormNotesChanged(String),

    // ---- SSH jump host --------------------------------------------------
    /// The jump host to tunnel through. Empty removes the tunnel, hiding the
    /// tunnel-password row and deleting its keyring entry on save.
    FormTunnelHostChanged(String),
    FormTunnelPortChanged(String),
    FormTunnelUsernameChanged(String),
    /// The jump host's password, stored under `keyring::tunnel_password_key`, a
    /// different key from the connection's password, and never on the profile.
    FormTunnelPasswordChanged(String),
    FormTunnelIdentityChanged(String),

    // ---- Session view chrome --------------------------------------------
    /// Toggle fullscreen (`Fullscreen` / `Exit fullscreen`). Per session, so other
    /// connections keep the sidebar.
    ToggleSessionFullscreen(Uuid),
    /// Flip between `Scaled to fit` and `Original size`.
    ToggleSessionScaling(Uuid),
    ToggleSessionResize(Uuid, u64),
    /// Flip between `Interactive` and `View-only`. The mode is read by
    /// `App::deliver_macro_to_session`, which refuses to forward when it is
    /// view-only.
    ToggleSessionInputMode(Uuid),
    /// Open, close or navigate a session's Send keystrokes menu; `enz_menu_button` is
    /// controlled, so the app owns the `MenuState`.
    KeystrokeMenu(enzui_iced_widgets::menu_button::MenuButtonEvent),

    // ---- Organisation --------------------------------------------------
    /// Start (or re-run) a network scan for discoverable hosts.
    ScanNetwork,
    /// A scan finished off-thread.
    ScanFinished {
        /// The scan this answer belongs to. An answer whose generation is not
        /// the one the reducer owns is dropped, which is how a cancelled or
        /// superseded browse installs nothing.
        generation: u64,
        outcome: crate::discovery::DiscoveryOutcome,
    },
    /// Abandon the scan in flight.
    ScanCancel,
    /// Save a discovered host as a profile. Discovered hosts are a separate
    /// collection, so this copies rather than flagging.
    SaveDiscovered(String),

    // ---- Import / export ------------------------------------------------
    /// Export every saved profile as JSON. Never carries a password; secrets stay in
    /// the keyring and are referenced by flag.
    ExportProfiles,
    /// Import profiles from `.rdp` text. Malformed input degrades to a
    /// reported error rather than a panic.
    ImportRdp,
    /// Choose a `.remmina` INI file and import it as one
    /// `ConnectionProfile`. Any source field that did not come across is
    /// reported on the result banner — the reported-not-dropped contract
    /// at the UI end.
    ImportRemmina,
    /// Import profiles from an export document, the counterpart to
    /// [`Self::ExportProfiles`] via `portable::import_json`.
    ImportProfiles,
    /// One dispatched import has finished reading and parsing.
    ///
    /// An answer quoting a superseded generation is dropped. Nothing has been written
    /// yet; the reducer decides what to do with the document or refusal.
    ImportReady {
        generation: u64,
        target: crate::picker::TransferTarget,
        outcome: Box<crate::import_source::ImportOutcome>,
    },
    /// Abandon the import being read. Invalidates its answer by generation,
    /// since the read itself cannot be interrupted.
    ImportCancel,
    /// Dismiss the import/export result.
    DismissTransferResult,
    /// A frame-rate poll that drives `file_chooser::pump` while the
    /// export / import chooser is in flight. Gated by
    /// `transfer_picker.is_pending()`, so an app with no dialog open never
    /// wakes to poll.
    TransferPortalTick,
    ChooserParentReady(
        crate::picker::PickTag,
        iced::window::Id,
        crate::picker::ParentReply,
    ),
    TransferChooser(
        crate::picker::PickTag,
        enzui_iced_widgets::file_chooser::FallbackEvent,
    ),
    TransferChosen(
        crate::picker::PickTag,
        enzui_iced_widgets::file_chooser::PortalOutcome<
            enzui_iced_widgets::file_chooser::FileResult,
        >,
    ),
    InstanceWake,
    HelpDialog(enzui_iced_widgets::modal_host::DialogEvent<crate::shortcuts::Dialog>),
    CloseHelp,

    // ---- Quick Connect --------------------------------------------------
    /// Open the Quick Connect dialog: the recents list plus an `Enter details…` entry.
    QuickConnectOpen,
    /// Dismiss the dialog without doing anything.
    QuickConnectDismiss,
    /// Escape / scrim / Tab inside the Quick Connect dialog. Carries the whole
    /// host event for the same reason [`Self::FormModalEvent`] does: funnelling
    /// a Tab into the dismissal closes the dialog the user was tabbing inside
    ///.
    QuickConnectModalEvent(enzui_iced_widgets::modal_host::ModalHostEvent),
    /// Connect on a recent row: seed the connection form from that endpoint with a
    /// blank password. Named by [`crate::quick_connect::RecentConnection::key`]
    /// because a connect re-sorts the list.
    QuickConnectRecent(String),
    /// Save as a connection (no session) on a recent row: persist a profile and open
    /// nothing.
    QuickConnectSaveRecent(String),
    /// `Enter details…` — close the dialog and present a blank add form.
    QuickConnectEnterDetails,
    /// Retry the refused store write for one live recent, named by
    /// [`crate::quick_connect::RecentConnection::key`].
    ///
    /// Raised by the per-row retry the dialog shows only while an entry is in
    /// `App::unsaved_recents`. The row itself is already on screen and stays
    /// there either way; what this changes is whether the next launch has it.
    QuickConnectRetrySave(String),
    /// Forget one recorded endpoint, named by its identity.
    ///
    /// The store delete settles before the row leaves the list, so a
    /// refused delete leaves the entry visible rather than removing it from a
    /// screen the next launch contradicts.
    QuickConnectForgetRecent(String),
    /// Forget the whole history. Same settle-before-removal rule as
    /// [`Self::QuickConnectForgetRecent`], applied to every row at once.
    QuickConnectClearRecents,
    /// The Quick Connect address entry's value changed. This is the
    /// bare host / `host:port` / URI field at the top of the dialog. Live
    /// parsing happens in the view via [`crate::quick_connect::parse_address`];
    /// this message just stores the raw text.
    QuickConnectAddressChanged(String),
    /// The address entry was submitted (Enter or the Connect button):
    /// parse the raw text with [`crate::quick_connect::parse_address`]. On
    /// `Ok`, close the dialog and open a seeded add form the same way
    /// [`Self::QuickConnectRecent`] does. On `Err`, leave the field open with
    /// the inline error visible — no dialog dismissal, no connect attempt.
    QuickConnectAddressSubmit,

    // ---- the saved-connection row context menu ---------------------------
    /// A right-click landed on a profile row, at that viewport point.
    ///
    /// The point anchors `enz_point_context_menu_host`. The third field is the
    /// invoking row's ancestor key path, needed because a starred profile appears on
    /// two rows; empty restores focus to the tree without moving its cursor.
    OpenContextMenu(Uuid, iced::Point, Vec<String>),
    /// Every event the framework context-menu host reports, through one funnel.
    ///
    /// Pointer and Escape dismissals both arrive as `Dismissed(cause)` and share
    /// `CloseCause::restores_focus`. The highlight lives only in the `MenuModel`.
    ContextMenuEvent(enzui_iced_widgets::context_menu_host::ContextMenuEvent),
    /// A context row was activated on that profile. Carries the typed row so the
    /// label and effect come from the same `context_menu::items` arm.
    ContextRowActivated(Uuid, crate::context_menu::RowKind),

    /// Flip a profile's favourite flag. Persisted, so a restart does not
    /// forget the star.
    ToggleFavorite(Uuid),
    /// Copy a profile under a `(copy)`-suffixed name.
    DuplicateProfile(Uuid),
    /// Delete a profile, its keyring secret and any live session.
    ///
    /// This is the COMMIT, not the request. Nothing in the UI produces
    /// it directly any more; `RequestDeleteProfile` stages the confirmation
    /// and the dialog's default action resolves to this.
    DeleteProfile(Uuid),
    /// Ask to delete a profile — stages the confirmation dialog.
    RequestDeleteProfile(Uuid),
    /// Every exit from the delete-profile confirmation.
    DeleteProfileConfirmEvent(enzui_iced_widgets::confirm_dialog::ConfirmDialogEvent),
    /// Broadcast a Wake-on-LAN magic packet to the profile's MAC.
    WakeOnLan(Uuid),

    // ---- Shared theme host --------------------------------------
    /// A framework-owned theme event: appearance snapshot or change, theme-file load,
    /// watch tick, or stat completion. Boxed to keep `Message` small.
    ///
    /// Forwarded to [`enzui_iced_core::theme_file::integration::ThemeIntegration`];
    /// any returned task is re-emitted.
    Theme(Box<ThemeEvent>),
}

impl enzui_iced_core::crash_report::MessageKind for Message {
    fn message_kind(&self) -> &'static str {
        match self {
            Self::FormSectionChanged(..) => "FormSectionChanged",
            Self::AppCommand(..) => "AppCommand",
            Self::WindowResized(..) => "WindowResized",
            Self::CloseSidebarOverlay => "CloseSidebarOverlay",
            Self::SidebarState(..) => "SidebarState",
            Self::ToggleTitlebarOverflow => "ToggleTitlebarOverflow",
            Self::ToggleImportMenu => "ToggleImportMenu",
            Self::CloseImportMenu => "CloseImportMenu",
            Self::CloseTitlebarOverflow => "CloseTitlebarOverflow",
            Self::ToggleGroup(..) => "ToggleGroup",
            Self::ToggleFavorites => "ToggleFavorites",
            Self::NoOp => "NoOp",
            Self::A11yWake(..) => "A11yWake",
            Self::Window(..) => "Window",
            Self::MainWindowOpened(..) => "MainWindowOpened",
            Self::WindowCloseRequested(..) => "WindowCloseRequested",
            Self::ConnectionCloseTick => "ConnectionCloseTick",
            Self::WindowCloseRetry => "WindowCloseRetry",
            Self::WindowCloseVeto => "WindowCloseVeto",
            Self::SearchChanged(..) => "SearchChanged",
            Self::SelectProfile(..) => "SelectProfile",
            Self::ActivateProfile(..) => "ActivateProfile",
            Self::SidebarProfilePressed(..) => "SidebarProfilePressed",
            Self::SidebarNavigate(..) => "SidebarNavigate",
            #[cfg(feature = "center")]
            Self::Center(..) => "Center",
            Self::SessionAction(..) => "SessionAction",
            Self::ConnectResult(..) => "ConnectResult",
            Self::SessionStreamEvent(..) => "SessionStreamEvent",
            Self::FrameUploaded(..) => "FrameUploaded",
            Self::ReconnectTick(..) => "ReconnectTick",
            Self::ReconnectCancel(..) => "ReconnectCancel",
            Self::SessionSurfaceResized(..) => "SessionSurfaceResized",
            Self::DesktopScroll(..) => "DesktopScroll",
            Self::DesktopPointerCancel(..) => "DesktopPointerCancel",
            Self::DesktopKey(..) => "DesktopKey",
            Self::SessionPointer(..) => "SessionPointer",
            Self::CredentialStoreReady(..) => "CredentialStoreReady",
            Self::PasswordFetched(..) => "PasswordFetched",
            Self::CredentialSaveResult(..) => "CredentialSaveResult",
            Self::ProfileSecretDeleted(..) => "ProfileSecretDeleted",
            Self::ProfileTunnelSecretDeleted(..) => "ProfileTunnelSecretDeleted",
            Self::DismissDbNotice => "DismissDbNotice",
            Self::SidebarActionHover(..) => "SidebarActionHover",
            Self::ToggleSessionResize(..) => "ToggleSessionResize",
            Self::DismissCredentialNotice => "DismissCredentialNotice",
            Self::DismissWolStatus => "DismissWolStatus",
            Self::Toast(_) => "Toast",
            Self::NativeClipboardWritten(..) => "NativeClipboardWritten",
            Self::SyncClipboard(..) => "SyncClipboard",
            Self::SyncedClipboard(..) => "SyncedClipboard",
            Self::ToggleSessionClipboard(..) => "ToggleSessionClipboard",
            Self::SendClipboardToSession(..) => "SendClipboardToSession",
            Self::ClipboardToSession(..) => "ClipboardToSession",
            Self::SaveScreenshot(..) => "SaveScreenshot",
            Self::ScreenshotSaved(..) => "ScreenshotSaved",
            Self::FocusNext => "FocusNext",
            Self::FocusPrevious => "FocusPrevious",
            Self::FormOpenAdd => "FormOpenAdd",
            Self::FormOpenEdit(..) => "FormOpenEdit",
            Self::FormNameChanged(..) => "FormNameChanged",
            Self::FormHostChanged(..) => "FormHostChanged",
            Self::FormPortChanged(..) => "FormPortChanged",
            Self::FormProtocolPicked(..) => "FormProtocolPicked",
            Self::FormUsernameChanged(..) => "FormUsernameChanged",
            Self::FormRustDeskPeerKeyChanged(..) => "FormRustDeskPeerKeyChanged",
            Self::FormRustDeskIdModeChanged(..) => "FormRustDeskIdModeChanged",
            Self::FormRustDeskServerChanged(..) => "FormRustDeskServerChanged",
            Self::FormRustDeskServerKeyChanged(..) => "FormRustDeskServerKeyChanged",
            Self::FormRustDeskRelayChanged(..) => "FormRustDeskRelayChanged",
            Self::FormMoonlightAppIdChanged(..) => "FormMoonlightAppIdChanged",
            Self::FormMoonlightPairAgainChanged(..) => "FormMoonlightPairAgainChanged",
            Self::FormMoonlightResumeChanged(..) => "FormMoonlightResumeChanged",
            Self::FormMoonlightGamepadsChanged(..) => "FormMoonlightGamepadsChanged",
            Self::FormAudioEnabledChanged(..) => "FormAudioEnabledChanged",
            Self::FormVncTlsChanged(..) => "FormVncTlsChanged",
            Self::FormVncFingerprintChanged(..) => "FormVncFingerprintChanged",
            Self::FormDynamicResizeChanged(..) => "FormDynamicResizeChanged",
            Self::FormPasswordChanged(..) => "FormPasswordChanged",
            Self::FormPasswordRevealToggled => "FormPasswordRevealToggled",
            Self::FormDisplayWidthChanged(..) => "FormDisplayWidthChanged",
            Self::FormDisplayHeightChanged(..) => "FormDisplayHeightChanged",
            Self::FormWolMacChanged(..) => "FormWolMacChanged",
            Self::FormDisableClipboardToggled(..) => "FormDisableClipboardToggled",
            Self::FormPlaintextAckToggled(..) => "FormPlaintextAckToggled",
            Self::FormReconnectToggled(..) => "FormReconnectToggled",
            Self::FormReconnectAttemptsChanged(..) => "FormReconnectAttemptsChanged",
            Self::FormReconnectCeilingChanged(..) => "FormReconnectCeilingChanged",
            Self::FormSave => "FormSave",
            Self::FormCancel => "FormCancel",
            Self::FormDelete => "FormDelete",
            Self::FormModalEvent(..) => "FormModalEvent",
            Self::RuleAdded => "RuleAdded",
            Self::RuleRemoved(..) => "RuleRemoved",
            Self::RuleTypePicked(..) => "RuleTypePicked",
            Self::RuleBindAddressChanged(..) => "RuleBindAddressChanged",
            Self::RuleBindPortChanged(..) => "RuleBindPortChanged",
            Self::RuleDestHostChanged(..) => "RuleDestHostChanged",
            Self::RuleDestPortChanged(..) => "RuleDestPortChanged",
            Self::RuleEnabledToggled(..) => "RuleEnabledToggled",
            Self::FormQualityPicked(..) => "FormQualityPicked",
            Self::FormViewOnlyToggled(..) => "FormViewOnlyToggled",
            Self::FormGroupChanged(..) => "FormGroupChanged",
            Self::FormNotesChanged(..) => "FormNotesChanged",
            Self::FormTunnelHostChanged(..) => "FormTunnelHostChanged",
            Self::FormTunnelPortChanged(..) => "FormTunnelPortChanged",
            Self::FormTunnelUsernameChanged(..) => "FormTunnelUsernameChanged",
            Self::FormTunnelPasswordChanged(..) => "FormTunnelPasswordChanged",
            Self::FormTunnelIdentityChanged(..) => "FormTunnelIdentityChanged",
            Self::ToggleSessionFullscreen(..) => "ToggleSessionFullscreen",
            Self::ToggleSessionScaling(..) => "ToggleSessionScaling",
            Self::ToggleSessionInputMode(..) => "ToggleSessionInputMode",
            Self::KeystrokeMenu(..) => "KeystrokeMenu",
            Self::ScanNetwork => "ScanNetwork",
            Self::ScanFinished { .. } => "ScanFinished",
            Self::ScanCancel => "ScanCancel",
            Self::SaveDiscovered(..) => "SaveDiscovered",
            Self::ExportProfiles => "ExportProfiles",
            Self::ImportRdp => "ImportRdp",
            Self::ImportRemmina => "ImportRemmina",
            Self::ImportProfiles => "ImportProfiles",
            Self::ImportReady { .. } => "ImportReady",
            Self::ImportCancel => "ImportCancel",
            Self::DismissTransferResult => "DismissTransferResult",
            Self::TransferPortalTick => "TransferPortalTick",
            Self::ChooserParentReady(..) => "ChooserParentReady",
            Self::TransferChooser(..) => "TransferChooser",
            Self::TransferChosen(..) => "TransferChosen",
            Self::InstanceWake => "InstanceWake",
            Self::HelpDialog(_) => "HelpDialog",
            Self::CloseHelp => "CloseHelp",
            Self::QuickConnectOpen => "QuickConnectOpen",
            Self::QuickConnectDismiss => "QuickConnectDismiss",
            Self::QuickConnectModalEvent(..) => "QuickConnectModalEvent",
            Self::QuickConnectRecent(..) => "QuickConnectRecent",
            Self::QuickConnectSaveRecent(..) => "QuickConnectSaveRecent",
            Self::QuickConnectRetrySave(..) => "QuickConnectRetrySave",
            Self::QuickConnectForgetRecent(..) => "QuickConnectForgetRecent",
            Self::QuickConnectClearRecents => "QuickConnectClearRecents",
            Self::QuickConnectEnterDetails => "QuickConnectEnterDetails",
            Self::QuickConnectAddressChanged(..) => "QuickConnectAddressChanged",
            Self::QuickConnectAddressSubmit => "QuickConnectAddressSubmit",
            Self::OpenContextMenu(..) => "OpenContextMenu",
            Self::ContextMenuEvent(..) => "ContextMenuEvent",
            Self::ContextRowActivated(..) => "ContextRowActivated",
            Self::ToggleFavorite(..) => "ToggleFavorite",
            Self::DuplicateProfile(..) => "DuplicateProfile",
            Self::DeleteProfile(..) => "DeleteProfile",
            Self::RequestDeleteProfile(..) => "RequestDeleteProfile",
            Self::DeleteProfileConfirmEvent(..) => "DeleteProfileConfirmEvent",
            Self::WakeOnLan(..) => "WakeOnLan",
            Self::Theme(..) => "Theme",
        }
    }
}
