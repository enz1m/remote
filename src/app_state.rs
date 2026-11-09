//! Application state (`App`), the Wake-on-LAN and transfer status types,
//! and the shared-theme boot seam. Relocated verbatim from
//! `main.rs`; the 2,478-line `impl App` stays alongside the entry point.

use std::sync::Arc;

use iced::Task;
use uuid::Uuid;

use enzui_iced_core::menu_model::{MenuModel, MenuState};
use enzui_iced_core::theme_file::integration::{ThemeEvent, ThemeIntegration};
use enzui_iced_theme::EnzTheme;
use enzui_iced_widgets::nav_split::NavSplitState;
use enzui_services::credential_store::CredentialStore;

use crate::credential_plumbing::CredentialNotice;
use crate::db::ProfileDb;
use crate::discovery::{DiscoveredHost, HostScanner};
use crate::form::ConnectionForm;
use crate::model::{ConnectionProfile, Session};
use crate::protocol::BackendRegistry;
use crate::session::KeystrokePage;

#[derive(Debug)]
pub(crate) struct FramePresentation {
    // A recreated profile can reuse its UUID and native upload tokens.
    pub instance: u64,
    pub native: enzui_iced_widgets::video::LatestFramePresenter,
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

/// One backend call in flight, and what it was dialling.
///
/// `identity` is read from the profile clone handed to
/// `RemoteBackend::connect` and is never refreshed: the profile it came from
/// is editable while the call is in flight, so rereading it at `Ready` could
/// credit a connection to an endpoint or an account no transport ever
/// reached. It carries no password, no key material and no profile id.
///
/// It holds no timestamp either. The recent-connections row is built from it
/// at the accepted `Connecting -> Connected` edge, so the recorded time is
/// the Ready reading rather than when the dial or its keyring prompt started.
pub struct DispatchedConnect {
    /// The [`App::connect_generation`] this call was dispatched under. Only an
    /// answer quoting the same value may be applied.
    pub generation: u64,
    /// What the profile was dialling and authenticating as, from
    /// [`crate::model::ConnectionProfile::dial_identity`].
    ///
    /// The endpoint in it is what a completed dial is credited to, which is
    /// why it is the recents admission's candidate; the rest of it is what
    /// decides whether the profile may be credited at all.
    pub candidate: crate::model::DialIdentity,
}

/// One import being read and parsed off the reducer thread.
///
/// `generation` is what tells this import's answer from the answer to one the
/// user has since abandoned: `Task::perform` cannot be cancelled, so the work
/// runs to completion either way and the reducer decides whether to believe
/// it. Carries no pathname, because nothing that survives an import names the
/// file it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportInFlight {
    /// The [`App::import_generation`] this read was dispatched under.
    pub generation: u64,
    /// Which import the user started, for the banner's wording.
    pub target: crate::picker::TransferTarget,
}

/// One in-flight profile mutation, and which credential slots it is still
/// waiting on.
///
/// The generation identifies the operation across the asynchronous credential
/// seam. A save that stores both the connection and jump-host passwords
/// dispatches two ops under one generation, answered in any order or not at
/// all. A terminal is honoured only while its generation is the newest for its
/// profile and its own slot is still outstanding, so a duplicate, replayed or
/// undispatched-slot terminal cannot publish a marker.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProfileOp {
    /// The stamp every terminal for this operation carries.
    pub generation: u64,
    /// Whether the connection password's credential op is still outstanding.
    pub password_pending: bool,
    /// Whether the jump host password's credential op is still outstanding.
    pub tunnel_pending: bool,
}

pub(crate) struct SavedConnectionRequest {
    pub generation: u64,
    pub password: bool,
    pub tunnel_password: bool,
    pub failed: bool,
}

pub struct App {
    /// The framework-owned shared XDG theme host. Owns the initial
    /// probe capture, the OS appearance feed, the debounced watcher, and
    /// the currently resolved `EnzTheme`. Never construct a bare `EnzTheme`
    /// on this app; go through `themes.theme()` so every reader sees the
    /// same resolved value the root `theme()` callback ships to iced.
    pub themes: ThemeIntegration,
    /// Mirror of the shared theme host that views read for palette and spacing
    /// tokens; resynced from [`Self::themes`] on each new host generation.
    ///
    /// Tests may assign it to force a palette; production must not, because any
    /// mutation outside the resync is lost on the next Theme event.
    pub enz_theme: EnzTheme,

    /// The SQLite profile store. Opened once at boot and kept for the
    /// lifetime of the app so `upsert` / `delete` can be called on every
    /// CRUD change.
    pub db: ProfileDb,

    /// The typed refusal from [`crate::db::open_default`], so the shell can show a
    /// toast instead of presenting a migration refusal as an empty database.
    /// `Some` means the app is running on the in-memory fallback and on-disk data
    /// is not being written.
    pub db_boot_error: Option<String>,
    pub db_notice_dismissed: bool,

    /// The [`crate::db::DbBootErrorKind`] paired with [`Self::db_boot_error`].
    /// The toast picks its copy from this tag; the paired string is for logs
    /// only, so a path inside `DbBootError::Display` never reaches the toast.
    pub db_boot_error_kind: Option<crate::db::DbBootErrorKind>,

    /// Every saved profile, in load order. The DB is written on every CRUD
    /// change; this vector is the display-source-of-truth.
    pub profiles: Vec<ConnectionProfile>,

    /// Live sessions, keyed by profile id (at most one per profile). Empty
    /// when the app boots.
    pub sessions: Vec<Session>,

    /// Which profile is currently selected in the sidebar.
    pub selected_profile: Option<Uuid>,
    /// The process-wide enzui-center session, when opted in and enrolled.
    #[cfg(feature = "center")]
    pub(crate) center: Option<enzui_iced_agent::center::CenterHost<crate::center::CenterCall>>,

    /// The registry of protocol backends; demo profiles get `StubBackend`
    /// slots.
    pub backends: BackendRegistry,

    /// Search query the user has typed.
    pub search_query: String,

    /// Typed expansion state for real folder groups. The initial `All` state
    /// and an explicit empty set of expanded groups are distinct, so a lone
    /// folder can remain collapsed.
    pub group_expansion: crate::organise::GroupExpansion,

    /// Whether the Favorites pseudo-group is expanded.
    ///
    /// Defaults to collapsed, unlike [`Self::group_expansion`]: Favorites repeats
    /// starred rows from real folders, so expanding it by default duplicates
    /// every starred row and hides whether starring moved or copied it.
    pub favorites_expanded: bool,

    /// The framework's navigation-shell state: the user's durable
    /// sidebar preference plus whether the overlay drawer is open.
    ///
    /// This replaces the app's own `sidebar_open` / `sidebar_overlay_open`
    /// pair. Nothing here is derived from geometry — the presentation is
    /// recomputed every pass by `view::sidebar_presentation`, which is the
    /// single width authority.
    pub nav: NavSplitState,

    /// Caller-owned open state for the titlebar's measured action overflow.
    /// Geometry remains view-derived; this flag only controls presentation of
    /// the already-folded commands.
    pub titlebar_overflow_open: bool,

    pub import_menu_open: bool,
    pub sidebar_action_hover: Option<String>,
    pub dialogs: enzui_iced_widgets::modal_host::DialogStack<crate::shortcuts::Dialog>,

    pub instance: enzui_iced_widgets::single_instance::SingleInstance,

    /// Bind-once target for policy-bearing titlebar commands. Automatic edge
    /// resize binds directly to its dispatching window and does not use this id.
    pub main_window: Option<iced::window::Id>,
    pub native_fullscreen: bool,

    /// Last native width, used to cap dialogs before layout.
    /// Session composition use the shared shell's resolved geometry.
    pub window_width: f32,
    pub window_height: f32,

    /// The open connection form, or `None` when no dialog is up. `Some`/`None`
    /// is the only "is the dialog open" authority — there is no second bool
    /// that could disagree with whether there is a draft to render.
    pub form: Option<ConnectionForm>,
    /// Owned scope/invoker for the currently presented connection form.
    pub(crate) form_focus: Option<enzui_iced_widgets::modal_host::ModalFocusLifecycle>,

    /// The credential store. Passwords go here and never into SQLite;
    /// `db.rs`'s `password_column_is_not_in_the_schema` is the other half of
    /// that contract.
    ///
    /// Owned by `App` so every reader sees the same store. Boot connects
    /// `SecretServiceTransport` asynchronously; until then this is an
    /// `UnavailableCredentialStore`, never an in-memory or disk fallback.
    pub credentials: Arc<dyn CredentialStore>,

    /// Connect operations waiting on a credential fetch, keyed by profile id.
    ///
    /// A keyring unlock prompt can take arbitrarily long, so the entry holds the
    /// op's [`CancelHandle`](enzui_services::credential_store::CancelHandle)
    /// for Cancel/Disconnect to abort the prompt itself. The paired connect
    /// generation lets [`Self::on_password_fetched`] reject a stale terminal so
    /// it cannot revert a newer connect for the same profile.
    pub pending_connects:
        std::collections::HashMap<Uuid, (u64, enzui_services::credential_store::CancelHandle)>,

    /// Monotonic counter stamping each connect's credential fetch.
    /// A `PasswordFetched` terminal is honoured only while its generation is
    /// still the pending op for its profile.
    pub connect_generation: u64,

    /// The backend call currently in flight for each profile.
    ///
    /// Covers the stage after the credential fetch: `pending_connects` is
    /// removed the moment the password resolves, so it cannot say whether a
    /// backend answer arriving minutes later belongs to the dial still in
    /// flight. A newer dial overwrites the entry, a cancel or disconnect
    /// removes it, and `Message::ConnectResult` is applied only on an exact
    /// generation match.
    pub dispatched_connects: std::collections::HashMap<Uuid, DispatchedConnect>,

    /// One bounded framebuffer sink per profile with a live session.
    ///
    /// Kept off [`Session`] because sessions are cloned every frame and a
    /// framebuffer can reach [`crate::framebuffer::REMOTE_FRAME_LIMITS`]`.max_rgba_bytes`.
    /// The sink validates CPU frames; the native presenter owns GPU handover.
    ///
    /// An entry exists from `Connected` until the session leaves it; removal
    /// frees the buffers and stops a late frame from repainting a closed session.
    pub frames: std::collections::HashMap<Uuid, enzui_iced_core::media::BoundedFrameSink>,

    /// Resident shown image, one upload and one latest pending frame per profile.
    pub frame_presenters: std::collections::HashMap<Uuid, FramePresentation>,

    /// The size the session surface was last laid out at, per profile.
    ///
    /// Published by the surface's own [`iced::widget::Sensor`]: the window also
    /// holds the sidebar, titlebar and toolbar, so its width is not the surface
    /// width. Pointer mapping and the upstream resize request both read this.
    pub surface_slots: std::collections::HashMap<Uuid, iced::Size>,

    /// The framebuffer size most recently requested from each backend.
    ///
    /// A slot is re-measured on every layout pass, and an unguarded
    /// `resize` per pass would be a request storm on a socket. This is the
    /// last value actually sent, so an unchanged slot sends nothing.
    pub requested_sizes: std::collections::HashMap<Uuid, (u32, u32)>,

    /// Monotonic counter stamping each session's frame/input stream.
    ///
    /// Distinct from [`Self::connect_generation`], which stamps one credential
    /// fetch. Advanced whenever a session starts or stops and carried on every
    /// `SessionStreamEvent`; an event from a superseded stream is dropped before
    /// it can paint or transition anything.
    pub session_generation: u64,

    /// The live stream generation per profile, or absent when no stream is
    /// running for it.
    pub session_streams: std::collections::HashMap<Uuid, u64>,

    /// The remote pixel the pointer was last mapped onto, per profile.
    ///
    /// Button gestures carry no coordinates, so their position comes from here.
    /// Absent until a move lands on the picture, so a press before any move is
    /// refused, and cleared with the surface so a reconnect cannot click at a
    /// stale coordinate.
    pub held_keys: std::collections::HashMap<Uuid, std::collections::BTreeSet<u32>>,
    pub held_buttons:
        std::collections::HashMap<Uuid, std::collections::BTreeSet<crate::protocol::PointerButton>>,
    pub pointer_at: std::collections::HashMap<Uuid, (i32, i32)>,

    /// The frame generation each new sink is opened at.
    ///
    /// [`Self::session_generation`] routes messages; this one is stamped into
    /// every admitted frame and compared by
    /// [`enzui_iced_core::media::BoundedFrameSink`], so a buffer from a replaced
    /// source is refused by the shared sink rather than by app code.
    pub frame_generation: enzui_iced_core::media::Generation,

    /// Monotonic counter stamping each profile mutation that reaches the
    /// profile store.
    ///
    /// Saves and deletes cross the asynchronous credential seam before their row
    /// write, so two mutations of one profile can overlap. A terminal is honoured
    /// only while its generation is the newest for its profile; otherwise a
    /// superseded save could overwrite `has_keyring_password` or a superseded
    /// delete could remove a re-saved row.
    ///
    /// Generations start at one, so zero is never a live operation.
    pub profile_op_generation: u64,

    /// The newest operation dispatched for each profile, with the credential
    /// slots it is still waiting on.
    ///
    /// Entries are overwritten rather than retired, so one save's first terminal
    /// cannot invalidate its second. A profile with no entry has nothing to
    /// supersede, so its terminals are honoured; `commit_profile_delete` drops
    /// the entry with the profile.
    pub pending_save_connects: std::collections::HashMap<Uuid, SavedConnectionRequest>,
    pub profile_ops: std::collections::HashMap<Uuid, ProfileOp>,

    /// The current credential notice banner. Raised only for genuine failures
    /// (`Unavailable`/`Denied`/`Failed`), never for a cancellation.
    pub credential_notice: Option<CredentialNotice>,

    /// The remote picture captured by "Save screenshot", waiting for the Save
    /// dialog to choose its destination.
    pub pending_screenshot: Option<crate::screenshot::PendingScreenshot>,

    /// The XDG Pictures directory the screenshot dialog opens in, resolved
    /// once at boot like [`Self::download_dir`].
    pub pictures_dir: Option<std::path::PathBuf>,

    /// The window close being held while connections are still closing.
    ///
    /// Holds the exact window the compositor named, so the app closes that id
    /// and no other. [`Self::close_budget`] and [`Self::vnc_close_notices`] are
    /// meaningful only while this is pending.
    pub close_guard: enzui_iced_core::close_guard::CloseGuard<Uuid>,

    /// How many further retry wakes a held close may spend before it stops
    /// waiting silently and shows its exact debt with a Retry and a veto.
    ///
    /// Counted in wakes rather than read from a clock, so the deadline is the
    /// same one in a test as in a launch.
    pub close_budget: u32,

    /// The VNC transports severed but not yet joined, rebuilt beside
    /// [`Self::vnc_close_notices`] on the same wake.
    ///
    /// Cached because reading a close report collects joins and redispatches
    /// owed closes, which a view must not do while painting. Separate from the
    /// SSH list because a lost VNC join leaves worker shutdown unconfirmed.
    pub vnc_close_notices: Vec<crate::rfb::backend::VncCloseDebt>,
    pub desktop_close_notices: Vec<Uuid>,

    /// Hosts the last network scan found. Separate from [`Self::profiles`]: a
    /// discovered host has no user-chosen id, no credentials, and vanishes when
    /// the next scan misses it. `discovery::DiscoveredHost::to_profile` is the
    /// one crossing point.
    pub discovered: Vec<DiscoveredHost>,

    /// Whether a scan is in flight. Drives the chip's tooltip and its enabled
    /// state, and stops a second scan being queued behind the first.
    pub scanning: bool,

    /// Whether a scan has completed at least once this session.
    ///
    /// Not derivable from [`Self::scanning`] or [`Self::discovered`]: idle
    /// with no hosts is both "nobody has scanned" and "the scan found
    /// nothing", and those are different things to tell the user.
    /// `discovery::scan_status_line` reads this to give the Discover chip an
    /// observable result when the network answers with nobody.
    pub scan_completed: bool,

    /// The host scanner. `Arc` for the same `Task::perform` reason
    /// [`Self::remote_fs`] is.
    pub scanner: std::sync::Arc<dyn HostScanner>,

    /// The Send keystrokes menu's open/highlight state and its entries.
    /// `enz_menu_button` is controlled, so the app owns both and applies each
    /// `MenuButtonEvent`.
    pub keystroke_menu: MenuState,
    pub keystroke_model: MenuModel,

    /// Which page of the keystroke menu is showing — the six chords, or the
    /// seven `Ctrl+Alt+F<n>` console switches.
    ///
    /// The page selects which entries [`Self::keystroke_model`] carries, so a
    /// single model, and a single highlight, matches the popup on screen.
    pub keystroke_page: KeystrokePage,

    /// The last import/export outcome, rendered as a banner until dismissed.
    /// `None` when there is nothing to report.
    pub transfer_result: Option<TransferResult>,

    /// The XDG portal file chooser behind `Export all profiles (JSON)`,
    /// `Import profiles (JSON)` and `Import .rdp files`. Holds which request is
    /// in flight and what it was opened for; `is_pending()` gates the poll
    /// subscription.
    pub transfer_picker: crate::picker::Picker,

    /// The import being read off the reducer thread, or `None`.
    ///
    /// Set the moment a path is known and cleared by the answer that matches
    /// its generation, so the banner can offer a cancel for exactly as long as
    /// there is something to cancel.
    pub import_in_flight: Option<ImportInFlight>,
    pub launch_imports:
        std::collections::VecDeque<(crate::picker::TransferTarget, std::path::PathBuf)>,

    /// The generation every dispatched import quotes back.
    ///
    /// Bumped by a cancel, a dismissal and by starting another import, so each
    /// of those invalidates an answer still in flight without needing to reach
    /// the thread computing it.
    pub import_generation: u64,
    /// The handle that abandons the import in flight.
    ///
    /// Retained for exactly as long as that import is the owned one. Dropping
    /// it early would leave a read nobody can tell to stop, and keeping it
    /// past its answer would let a later cancel address an import that already
    /// reported.
    pub import_cancellation: Option<
        enzui_iced_core::blocking_task::BlockingTaskCancellation<
            crate::import_source::ImportOutcome,
        >,
    >,
    /// The scan whose answer the reducer will believe, and the handle that
    /// abandons it.
    ///
    /// The handle is retained for exactly as long as the scan is the owned
    /// one: dropping it early would leave a browse nobody can tell to stop,
    /// and keeping it past its answer would let a later cancel address a scan
    /// that already reported.
    pub scan_in_flight: Option<crate::discovery::PendingScan>,
    pub scan_generation: u64,
    /// Why discovery could not run, when it could not.
    ///
    /// Separate from the section's empty state, which says the network
    /// answered nobody. A machine with no daemon has not learned anything
    /// about its network, and saying so is the difference between a control
    /// that reports and one that looks broken.
    pub discovery_refusal: Option<crate::discovery::DiscoveryRefusal>,

    /// Harness/test path overrides that bypass the chooser.
    ///
    /// `REMOTE_APP_EXPORT_PATH` / `REMOTE_APP_RDP_PATH` make headless captures
    /// and transfer render tests deterministic. Read once at boot
    /// ([`crate::picker::TransferOverrides::from_env`]); tests set fields through
    /// `crate::picker::TransferOverrides::set` instead of mutating the process env.
    pub transfer_overrides: crate::picker::TransferOverrides,

    /// Whether the Quick Connect dialog is showing.
    ///
    /// The dialog holds no editable state of its own: it lists [`Self::recents`]
    /// and hands two of its three actions to the connection form.
    pub quick_connect_open: bool,
    /// Owned scope/invoker for the currently presented Quick Connect dialog.
    pub(crate) quick_connect_focus: Option<enzui_iced_widgets::modal_host::ModalFocusLifecycle>,

    /// The Quick Connect address entry's raw text, and its most recent parse
    /// error (`None` while the field is empty or the last submit succeeded).
    ///
    /// The view parses live for its preview; an error is stored only after Enter
    /// or Connect, so a partly typed address does not paint the field red.
    pub quick_connect_address: String,
    /// The submitted parse error (see [`Self::quick_connect_address`]).
    pub quick_connect_address_error: Option<crate::quick_connect::AddressParseError>,

    /// Hosts recently dialled, newest first, capped at
    /// [`crate::quick_connect::RECENT_CAP`].
    ///
    /// In-memory mirror of the `recents` table, written through on every
    /// admission. A row arrives only after a transport reported `Connected`; see
    /// `App::admit_recent`. A dialled host is not a saved profile, so this is
    /// separate from [`Self::profiles`].
    pub recents: Vec<crate::quick_connect::RecentConnection>,

    /// Identities of entries in [`Self::recents`] the store refused to write.
    ///
    /// Lets the dialog disclose per row that the entry will not survive a restart
    /// and offer a retry. Kept off [`crate::quick_connect::RecentConnection`]
    /// because durability belongs to this process's store, not the endpoint.
    /// Bounded by the same cap as the list it indexes.
    pub unsaved_recents: Vec<String>,

    /// Whether this launch reads and writes Quick Connect history.
    ///
    /// Resolved once at boot from the same
    /// [`crate::main_helpers::LibraryFixture`] that decides the library and
    /// the backend registry, so the three cannot disagree. False for a demo or
    /// capture launch, whose fabricated connections must not enter history.
    pub records_history: bool,

    pub context_menu: crate::context_menu::OpenContextMenu,

    /// The profile whose deletion is awaiting confirmation.
    ///
    /// Deletion is irreversible: the row leaves the store and its keyring secret
    /// (`keyring::profile_password_key`) is destroyed. The secret is deleted
    /// first and the row dropped only once the store confirms it. Both the
    /// context-menu Delete and the form's Delete stage this; only
    /// `Message::DeleteProfile`, from the confirm dialog, deletes.
    pub pending_delete_profile: Option<Uuid>,
    /// Whether the pending confirmation is the explicit second acknowledgement
    /// required after Secret Service answered `Unavailable`. Until this is
    /// confirmed the profile and its possibly-unreachable secret are retained.
    pub delete_without_credentials_warning: bool,
    /// Lifecycle state for the `enz_confirm_dialog` presenting that
    /// confirmation. No checkbox; it is what makes every exit (either button,
    /// Escape, the scrim) fan into one `Resolved(cause)`.
    pub delete_confirm_state: enzui_iced_core::confirm::ConfirmState,

    /// The last Wake-on-LAN outcome, as a one-line status. `None` when nothing
    /// has been sent this session.
    ///
    /// Rendered in the sidebar's transfer banner slot. Every outcome produces a
    /// line, because a fire-and-forget UDP broadcast otherwise looks identical
    /// whether it worked or not.
    pub wol_status: Option<WolStatus>,

    /// Self-dismissing confirmations, such as a sent Wake-on-LAN packet.
    pub toasts: enzui_iced_widgets::toast_host::ToastHost,
    /// The one expiry wake the toasts above need, armed after every turn.
    pub toast_schedule: enzui_iced_widgets::toast_host::ToastExpirySchedule,

    /// Every profile's reconnect schedule, policy generation and recency
    /// publication order.
    ///
    /// The only authority for "is something being retried": the subscription
    /// arms one deadline from it, the reducer reads it before spawning an
    /// attempt, and the session surface reads it for the line it shows. There
    /// is no second flag a stale wake could find agreeing with it.
    pub reconnect: crate::reconnect::ReconnectState,

    /// Paired durable records a transport earned and the store refused.
    ///
    /// The session stays live, but neither the connection time nor its history
    /// row reached disk, and the surface says so. At most one entry per profile;
    /// a debt whose history row is gone is dropped, since that row is the
    /// retry's only route.
    pub recency_debt: Vec<crate::reconnect::RecencyDebt>,
}

/// The outcome of a Wake-on-LAN attempt, as the banner shows it.
///
/// Typed rather than a `String` plus `is_error` flag, so a failure cannot be
/// painted in the success tone.
///
/// # No raw OS strings in [`WolStatus::Failed`]
///
/// The failed variant carries a bounded
/// [`crate::error_boundary::WolFailure`] category. The untranslated
/// diagnostic on `raw` is for logging only and never reaches
/// [`WolStatus::title`] / [`WolStatus::body`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WolStatus {
    /// A magic packet went out to this profile's MAC.
    Sent { name: String, mac: String },
    /// The profile's stored MAC did not parse, so nothing was sent.
    InvalidMac { name: String, mac: String },
    /// The socket refused. The banner reads `cause`; `raw` is the
    /// untranslated backend string retained only for diagnostics/logging and
    /// is never surfaced in the title or body.
    Failed {
        name: String,
        cause: crate::error_boundary::WolFailure,
        raw: String,
    },
}

impl WolStatus {
    /// The banner title.
    pub fn title(&self) -> String {
        match self {
            WolStatus::Sent { name, mac } => {
                let name = crate::display::bound_display_name(name);
                format!("Wake-on-LAN packet sent to {name} ({mac}).")
            }
            WolStatus::InvalidMac { mac, .. } => format!("Invalid MAC address: {mac}"),
            // Bounded category prose. The raw backend string is
            // deliberately not consulted here — it lives on `raw` for logs
            // only.
            WolStatus::Failed { name, cause, .. } => {
                cause.title(&crate::display::bound_display_name(name))
            }
        }
    }

    /// The banner body, or `None` when there is nothing to add below the
    /// title (successes and invalid-MAC read as one line).
    pub fn body(&self) -> Option<String> {
        match self {
            WolStatus::Sent { .. } | WolStatus::InvalidMac { .. } => None,
            WolStatus::Failed { name, cause, .. } => {
                Some(cause.body(&crate::display::bound_display_name(name)))
            }
        }
    }

    /// Whether this outcome is a failure — the banner's tone reads this, so
    /// the tone cannot disagree with the variant.
    pub fn is_error(&self) -> bool {
        !matches!(self, WolStatus::Sent { .. })
    }
}

/// The outcome of an import or an export, as the banner shows it.
///
/// Typed rather than a `String` plus `is_error` flag, so a failure cannot be
/// rendered in the success tone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransferResult {
    Exported {
        path: String,
        count: usize,
    },
    /// Publication occurred, but current identity or durability is uncertain.
    ExportPublicationUncertain {
        path: String,
        count: usize,
    },
    Imported {
        name: String,
    },
    /// A JSON export restores MANY profiles at once, so it reports a
    /// count rather than one name.
    ImportedMany {
        count: usize,
    },
    /// A Remmina (or other foreign-format) import that succeeded
    /// but did not translate every source field. Carries the human list
    /// of what did not come across so the banner can show it — that is
    /// the reported-not-dropped contract at the UI end.
    ImportedWithWarnings {
        name: String,
        unsupported: Vec<String>,
        has_reported_password: bool,
        /// Source fields counted by the parser but omitted from the bounded
        /// presentation window.
        omitted: usize,
    },
    /// A refusal the user sees on the sidebar Danger banner.
    ///
    /// `message` is the only failure payload kept in state, and every producer
    /// writes bounded, authored copy ([`crate::error_boundary::TransferFailure`],
    /// [`crate::portable::JsonImportError`] / [`crate::portable::RdpImportError`]
    /// / [`crate::import_remmina::RemminaParseError`] `banner_message`, or the
    /// picker guards). Raw parser `Display` text never reaches it.
    Failed {
        message: String,
    },
    /// A screenshot of the remote desktop was saved locally.
    ScreenshotSaved {
        path: String,
    },
}

impl TransferResult {
    /// The banner's title.
    pub fn title(&self) -> String {
        match self {
            Self::Exported { count, .. } => {
                format!(
                    "Exported {count} profile{}",
                    if *count == 1 { "" } else { "s" }
                )
            }
            Self::ExportPublicationUncertain { count, .. } => {
                format!(
                    "Exported {count} profile{}; publication uncertain",
                    if *count == 1 { "" } else { "s" }
                )
            }
            Self::Imported { name } => {
                format!("Imported {}", crate::display::bound_display_name(name))
            }
            Self::ImportedMany { count } => {
                format!(
                    "Imported {count} profile{}",
                    if *count == 1 { "" } else { "s" }
                )
            }
            Self::ImportedWithWarnings { name, .. } => {
                format!("Imported {}", crate::display::bound_display_name(name))
            }
            Self::Failed { .. } => "Transfer failed".to_string(),
            Self::ScreenshotSaved { .. } => "Screenshot saved".to_string(),
        }
    }

    /// The banner's body — the detail the title does not carry.
    pub fn body(&self) -> String {
        match self {
            Self::Exported { path, .. } => {
                let name = crate::display::bound_path_name(path);
                format!("Written to {name}. Passwords stay in the OS keyring.")
            }
            Self::ExportPublicationUncertain { path, .. } => {
                let name = crate::display::bound_path_name(path);
                format!(
                    "Publication occurred for {name}, but current contents or durability could not be confirmed."
                )
            }
            Self::Imported { .. } => {
                "Saved as a new connection. Its password is not imported.".to_string()
            }
            Self::ImportedMany { .. } => {
                "Saved as new connections. Passwords are not imported — each \
                 profile looks its own up in this machine's keyring."
                    .to_string()
            }
            Self::ImportedWithWarnings {
                unsupported,
                has_reported_password,
                omitted,
                ..
            } => crate::display::bounded_warning_summary(
                unsupported,
                *omitted,
                *has_reported_password,
            ),
            Self::Failed { message } => message.clone(),
            Self::ScreenshotSaved { path } => {
                format!("Saved to {}.", crate::display::bound_path_name(path))
            }
        }
    }

    pub fn is_error(&self) -> bool {
        matches!(
            self,
            Self::Failed { .. } | Self::ExportPublicationUncertain { .. }
        )
    }

    /// The number of source fields that did not come across in an import.
    /// Zero for every fully translated success; shown and omitted warning counts
    /// are both included for [`Self::ImportedWithWarnings`].
    #[allow(
        dead_code,
        reason = "introduced with the Remmina import; consumed by \
            the import-outcome tests and available to the view for a \
            future severity choice on the banner."
    )]
    pub fn warning_count(&self) -> usize {
        match self {
            Self::ImportedWithWarnings {
                unsupported,
                omitted,
                ..
            } => unsupported.len() + *omitted,
            _ => 0,
        }
    }
}

// The only call site that opens `ThemeIntegration`; `boot()` reads XDG paths
// and the probe env off the UI thread.
#[cfg(not(test))]
pub(crate) fn theme_boot() -> (ThemeIntegration, Task<ThemeEvent>) {
    ThemeIntegration::boot()
}

// Unit tests must not open OS subscriptions or watch the developer's XDG
// directories. The fleet source gate excludes this function via its
// `#[cfg(test)]` region parser, so `unmanaged_compiled_theme` stays test-only.
#[cfg(test)]
pub(crate) fn theme_boot() -> (ThemeIntegration, Task<ThemeEvent>) {
    (
        ThemeIntegration::unmanaged_compiled_theme(EnzTheme::dark()).0,
        Task::none(),
    )
}
