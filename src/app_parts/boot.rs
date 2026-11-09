//! App boot constructors.

use super::*;

impl App {
    pub fn boot() -> (Self, Task<Message>) {
        #[cfg_attr(not(all(feature = "center", not(test))), allow(unused_mut))]
        let (mut app, task) = Self::boot_with_db(None);
        // The shipping boot alone may expose the app.
        #[cfg(all(feature = "center", not(test)))]
        app.start_center();
        (app, task)
    }

    /// Boots the app, optionally with a specific DB path.
    ///
    /// `None` opens the default XDG path (or the `REMOTE_APP_DB_PATH` override)
    /// through [`crate::db::open_default`], which runs the crash-safe migration
    /// plan from [`enzui_iced_core::db_migration`] before any SQLite connection
    /// opens; `Some(":memory:")` opens an in-memory DB. A typed refusal (no data
    /// home, stale destination, cross-device) is stored on [`App::db_boot_error`]
    /// and the app boots in-memory, never opening a relative or legacy path.
    pub(crate) fn boot_with_db(db_path: Option<&str>) -> (Self, Task<Message>) {
        use crate::db::DbBootFailure;
        let opened = match db_path {
            Some(":memory:") => Ok(ProfileDb::open_in_memory().unwrap()),
            Some(p) => ProfileDb::open(std::path::Path::new(p))
                .map_err(|e| DbBootFailure::from_explicit_open(p, e)),
            None => match std::env::var("REMOTE_APP_DB_PATH").ok().as_deref() {
                Some(":memory:") => Ok(ProfileDb::open_in_memory().unwrap()),
                Some(p) => ProfileDb::open(std::path::Path::new(p))
                    .map_err(|e| DbBootFailure::from_explicit_open(p, e)),
                None => crate::db::open_default().map_err(DbBootFailure::from),
            },
        };
        // Launches resolve the library fixture from the environment; tests take the
        // demo library, and `cfg(test)` code is absent from a shipped binary.
        #[cfg(not(test))]
        let library = LibraryFixture::from_env();
        #[cfg(test)]
        let library = LibraryFixture::Demo;
        Self::boot_with_db_result(opened, library)
    }

    #[cfg(test)]
    pub(crate) fn boot_with_production_library(db_path: &str) -> (Self, Task<Message>) {
        use crate::db::DbBootFailure;
        let opened = if db_path == ":memory:" {
            Ok(ProfileDb::open_in_memory().unwrap())
        } else {
            ProfileDb::open(std::path::Path::new(db_path))
                .map_err(|e| DbBootFailure::from_explicit_open(db_path, e))
        };
        Self::boot_with_db_result(opened, LibraryFixture::Production)
    }

    /// Shared tail of the two boot entry points: apply the resolved DB (or
    /// fall back to in-memory with a surfaced error) and hand off to the
    /// large constructor that owns the rest of the state.
    pub(crate) fn boot_with_db_result(
        db: Result<ProfileDb, crate::db::DbBootFailure>,
        library: LibraryFixture,
    ) -> (Self, Task<Message>) {
        let (themes, theme_boot) = theme_boot();
        // The first frame paints against this; the deferred load resyncs it
        // through `Message::Theme`.
        let enz_theme = themes.theme().clone();

        // Refusals land typed on `db_boot_error` and the app boots in-memory, so the
        // banner can distinguish them from an empty DB. Never fall back to the legacy
        // pathname: reopening the source after a migration refusal defeats the
        // crash-safe protocol.
        let crate::db::BootedStore {
            db,
            profiles: mut persisted,
            failure,
        } = crate::db::boot_store(db);
        // Retain legacy SSH rows on disk; Terminal and Files own those connections.
        persisted.retain(|profile| profile.protocol != Protocol::Ssh);
        let (db_boot_error, db_boot_error_kind) = match failure {
            Some(f) => (Some(f.message), Some(f.kind)),
            None => (None, None),
        };

        // Only a shipping launch reads history, so demo and capture runs show none.
        // A read refusal is surfaced because an empty list and an unreadable table
        // look identical on screen.
        let records_history = library.records_history();
        let mut recents = Vec::new();
        let mut recents_failure: Option<crate::db::DbBootFailure> = None;
        if records_history {
            match db.load_recents(crate::quick_connect::RECENT_CAP) {
                Ok(rows) => {
                    recents = rows
                        .into_iter()
                        .filter(|row| row.protocol != Protocol::Ssh)
                        .collect()
                }
                Err(err) => {
                    recents_failure = Some(crate::db::DbBootFailure::from_recents_read(&err));
                }
            }
        }
        let (db_boot_error, db_boot_error_kind) = match (db_boot_error, recents_failure) {
            // A profile-read refusal outranks a history one: the library is
            // what the window is for, and two banners cannot both be the
            // first thing read.
            (Some(message), _) => (Some(message), db_boot_error_kind),
            (None, Some(f)) => (Some(f.message), Some(f.kind)),
            (None, None) => (None, None),
        };

        // The capture policy supplies this only inside the visual harness; normal
        // launches always connect Secret Service. Env is read once into a value so
        // the mapping is testable without `std::env` (`keyring::CaptureCredentialFixture`).
        let credential_fixture = crate::keyring::CaptureCredentialFixture::from_start_view(
            std::env::var("REMOTE_APP_CREDENTIAL_SETTLED").as_deref() == Ok("1"),
            start_view().as_deref(),
        );

        // The demo library is opt-in: a fabricated profile is indistinguishable from
        // a saved one and survives restarts. An unreadable store is skipped too.
        // Both paths list what `db.load_all()` returns, so order follows its
        // `ORDER BY group_path, name` and first boot and reload select the same row.
        let mut profiles = persisted;
        if library.seeds_an_empty_library() && db_boot_error.is_none() && profiles.is_empty() {
            let seeded = crate::model::seed_profiles();
            for p in &seeded {
                let _ = db.upsert(p);
            }
            // Re-reading shows what the store accepted when a seed write refused;
            // falling back to `seeded` would list rows no restart could find.
            profiles = db.load_all().unwrap_or_default();
        }

        // Return state before touching D-Bus: production starts with the unavailable
        // store until the async Secret Service connection resolves.
        #[cfg(not(test))]
        let credentials: Arc<dyn CredentialStore> = credential_fixture
            .store()
            .unwrap_or_else(|| Arc::new(UnavailableCredentialStore));
        #[cfg(test)]
        let credentials: Arc<dyn CredentialStore> =
            Arc::new(enzui_services::credential_store::MemoryCredentialStore::new());

        // Reconcile only exact `contains` answers. The real transport returns
        // Unknown without prompting, so persisted hints survive while row
        // badges truthfully show the unknown state. No `get` runs in this loop.
        crate::keyring::reconcile_badge_on_boot(&mut profiles, credentials.as_ref());
        // `keyring-saved` without REMOTE_APP_CREDENTIAL_SETTLED classifies as `None`
        // and leaves production profile hints untouched.
        credential_fixture.seed_saved_profile_hints(&mut profiles);

        // Pre-select the head of the `db.load_all()` sort so first boot and reload
        // agree. `REMOTE_APP_START_VIEW=sidebar` (capture harness only) selects
        // nothing so the narrow rung shows the connection list.
        let initial_selection = match start_view().as_deref() {
            Some("sidebar") | Some("empty") => None,
            // Select the VNC profile when showing a connected session.
            Some("session-nosignal") | Some("session-live") => profiles
                .iter()
                .find(|p| p.protocol == Protocol::Vnc)
                .map(|p| p.id),
            _ => profiles.first().map(|p| p.id),
        };
        // `sidebar` and the keyring fixtures open the overlay drawer, since the
        // password badge and credential banner they photograph live in the sidebar.
        // `NavSplitState::effective_overlay_open` makes this inert when docked.
        let initial_overlay = start_view().as_deref() == Some("sidebar")
            || credential_fixture.needs_sidebar_visible();

        // Capture-only `form` (blank add) and `form-edit` (pre-filled, two rules)
        // open the connection form at boot through the same constructors the
        // reducer uses. The argv form exists because `_shared/capture.sh` forwards
        // arguments but not arbitrary environment variables.
        let initial_form = match start_view().as_deref() {
            Some("form") => Some(ConnectionForm::for_add()),
            Some("form-edit") => profiles.first().map(|p| {
                let mut f = ConnectionForm::for_profile(p);
                // One local rule and one dynamic one, so the capture shows both
                // the four-row destination-carrying group and the two-row
                // destination-free one.
                let mut local = crate::form::RuleDraft::new_local();
                local.bind_address = "127.0.0.1".into();
                local.bind_port = "15432".into();
                local.dest_host = "db.internal".into();
                local.dest_port = "5432".into();
                let mut socks = crate::form::RuleDraft::new_local();
                socks.forward_type = crate::model::PortForwardType::Dynamic;
                socks.bind_port = "1080".into();
                f.rules = vec![local, socks];
                f
            }),
            // Capture-only: a configured jump host makes the conditional tunnel-password
            // row photographable, filling the fields `FormTunnelHostChanged` writes.
            Some("form-tunnel") => profiles.first().map(|p| {
                let mut f = ConnectionForm::for_profile(p);
                f.tunnel_host = "bastion.example.com".into();
                f.tunnel_port = "2222".into();
                f.tunnel_username = "jumper".into();
                // Only pixels can show the secret is masked; the semantics tree only says
                // `Role::PasswordInput`.
                f.tunnel_password = "jump-secret".into();
                f.tunnel_password_dirty = true;
                f
            }),
            // Capture-only rejected input: out-of-range port, unparseable MAC, and a
            // rule with an empty destination host.
            Some("form-invalid") => profiles.first().map(|p| {
                let mut f = ConnectionForm::for_profile(p);
                f.port = "65536".into();
                f.port_touched = true;
                f.wol_mac = "not-a-mac".into();
                let mut broken = crate::form::RuleDraft::new_local();
                broken.dest_host = String::new();
                broken.dest_port = "99999".into();
                f.rules = vec![broken];
                f
            }),
            _ => None,
        };

        // Capture-only `discovered-demo` injects a fixed scan with a long host name
        // and address to show single-line elision. Boot never browses: one decision
        // yields both scanner and rows so the real scanner cannot open the system
        // bus and stall the first frame.
        let (scanner, initial_discovered): (
            std::sync::Arc<dyn HostScanner>,
            Vec<crate::discovery::DiscoveredHost>,
        ) = if start_view().as_deref() == Some("discovered-demo") {
            let hosts = capture_demo_hosts();
            (
                std::sync::Arc::new(StubScanner::with_hosts(hosts.clone())),
                hosts,
            )
        } else {
            (
                std::sync::Arc::new(crate::discovery::AvahiScanner),
                Vec::new(),
            )
        };

        // Capture-only `quick`, `quick-invalid` (refused URI, inline error) and
        // `quick-valid` open Quick Connect, setting the field `QuickConnectOpen` writes.
        let initial_quick_connect = matches!(
            start_view().as_deref(),
            Some("quick") | Some("quick-invalid") | Some("quick-valid")
        );

        // Capture-only setup for the two Quick Connect entry states.
        // The reducer path is unchanged: the field's value and its pinned
        // error are the SAME state a user typing would produce.
        let (initial_qc_address, initial_qc_error) = match start_view().as_deref() {
            Some("quick-invalid") => (
                "http://box.example.com".to_string(),
                Some(crate::quick_connect::AddressParseError::UnsupportedScheme(
                    "http".to_string(),
                )),
            ),
            // A scheme this build can connect, so "valid" matches the reducer.
            Some("quick-valid") => ("vnc://alice@build-box.internal:5901".to_string(), None),
            _ => (String::new(), None),
        };

        // Capture-only: seeds the Remmina import result banner without a file chooser.
        let initial_transfer_result = match start_view().as_deref() {
            Some("import-remmina-result") => Some(TransferResult::ImportedWithWarnings {
                name: "Legacy Box".to_string(),
                unsupported: vec![
                    "password (present, not imported)".to_string(),
                    "ssh_enabled = 1".to_string(),
                    "ssh_server = jump.example.com".to_string(),
                ],
                has_reported_password: true,
                omitted: 2,
            }),
            _ => None,
        };

        let initial_sessions = if matches!(
            start_view().as_deref(),
            Some("session-nosignal") | Some("session-live")
        ) {
            profiles
                .iter()
                .find(|p| p.protocol == Protocol::Vnc)
                .cloned()
                .map(|p| {
                    let mut s = Session::new(p);
                    s.status = SessionStatus::Connected;
                    vec![s]
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let mut app = Self {
            themes,
            enz_theme,
            db,
            db_boot_error,
            db_boot_error_kind,
            profiles,
            sessions: initial_sessions,
            selected_profile: initial_selection,
            #[cfg(feature = "center")]
            center: None,
            backends: library.backends(),
            search_query: String::new(),
            group_expansion: crate::organise::GroupExpansion::default(),
            // Favorites is collapsed by default so starred profiles
            // are not duplicated on the first paint; the folder copy is the
            // canonical one and Favorites is an opt-in shortcut shelf.
            favorites_expanded: false,
            nav: NavSplitState {
                preference: enzui_iced_widgets::nav_split::SidebarPreference::Automatic,
                overlay_open: initial_overlay,
            },
            instance: enzui_iced_widgets::single_instance::SingleInstance::standalone(),
            titlebar_overflow_open: false,
            sidebar_action_hover: None,
            db_notice_dismissed: false,
            import_menu_open: false,
            dialogs: Default::default(),
            // The initial `Opened` event binds this titlebar target once.
            main_window: None,
            native_fullscreen: false,
            window_width: 0.0,
            window_height: 0.0,
            form: initial_form,
            form_focus: None,
            // Only the trait object is retained. Production begins with
            // `Unavailable` while the async boot task connects Secret Service;
            // tests begin with a deterministic injected-compatible store.
            credentials,
            pending_connects: std::collections::HashMap::new(),
            dispatched_connects: std::collections::HashMap::new(),
            connect_generation: 0,
            frame_presenters: std::collections::HashMap::new(),
            frames: std::collections::HashMap::new(),
            surface_slots: std::collections::HashMap::new(),
            requested_sizes: std::collections::HashMap::new(),
            session_generation: 0,
            session_streams: std::collections::HashMap::new(),
            frame_generation: enzui_iced_core::media::Generation::FIRST,
            held_keys: std::collections::HashMap::new(),
            held_buttons: std::collections::HashMap::new(),
            pointer_at: std::collections::HashMap::new(),
            profile_op_generation: 0,
            pending_save_connects: Default::default(),
            profile_ops: std::collections::HashMap::new(),
            // The capture-only unavailable frame shows the SAME notice
            // the reducer raises from a real `Unavailable` save, so the
            // screenshot depicts a state the app can actually reach.
            credential_notice: credential_fixture
                .raises_unavailable_notice()
                .then(|| CredentialNotice::save_unavailable("the selected connection")),
            pending_screenshot: None,
            pictures_dir: directories::UserDirs::new()
                .and_then(|dirs| dirs.picture_dir().map(std::path::Path::to_path_buf)),
            close_guard: enzui_iced_core::close_guard::CloseGuard::new(),
            close_budget: 0,
            vnc_close_notices: Vec::new(),
            desktop_close_notices: Vec::new(),
            discovered: initial_discovered,
            scanning: false,
            scan_completed: false,
            scanner,
            keystroke_menu: MenuState::closed(),
            keystroke_model: keystroke_menu_model(KeystrokePage::Root),
            keystroke_page: KeystrokePage::Root,
            quick_connect_open: initial_quick_connect,
            quick_connect_focus: None,
            quick_connect_address: initial_qc_address,
            quick_connect_address_error: initial_qc_error,
            // A "Recent connections" heading is a claim about the user's
            // past, so the only thing that may fill it is a connection this
            // app saw complete.
            recents,
            unsaved_recents: Vec::new(),
            records_history,
            transfer_result: initial_transfer_result,
            import_in_flight: None,
            launch_imports: std::collections::VecDeque::new(),
            import_generation: 0,
            import_cancellation: None,
            scan_in_flight: None,
            scan_generation: 0,
            discovery_refusal: None,
            transfer_picker: crate::picker::Picker::new(),
            // Env is read here, once, at cold start. Never again from
            // any test in this crate — tests write directly to the field.
            transfer_overrides: crate::picker::TransferOverrides::from_env(),
            context_menu: Default::default(),
            pending_delete_profile: None,
            delete_without_credentials_warning: false,
            delete_confirm_state: enzui_iced_core::confirm::ConfirmState::new(None),
            wol_status: None,
            toasts: enzui_iced_widgets::toast_host::ToastHost::new(),
            toast_schedule: enzui_iced_widgets::toast_host::ToastExpirySchedule::default(),
            reconnect: crate::reconnect::ReconnectState::default(),
            recency_debt: Vec::new(),
        };

        if start_view().as_deref() == Some("context")
            && let Some(pid) = app.profiles.first().map(|p| p.id)
        {
            let row_path = crate::sidebar_view::sidebar_row_path(&app, pid).unwrap_or_default();
            let _ = app.update(Message::OpenContextMenu(
                pid,
                iced::Point::new(40.0, 120.0),
                row_path,
            ));
        }

        // Capture-only `session` and `fullscreen` open a session on the first
        // profile through the toolbar's messages, so only reducer-reachable states
        // are photographed.
        if matches!(start_view().as_deref(), Some("session" | "fullscreen"))
            && let Some(pid) = app.profiles.first().map(|p| p.id)
        {
            let _ = app.update(Message::SessionAction(pid));
            if start_view().as_deref() == Some("fullscreen") {
                let _ = app.update(Message::ToggleSessionFullscreen(pid));
            }
        }

        // The frame goes through `accept_frame`, the stream route's admission, so a
        // rejected frame shows `No signal` rather than a fabricated picture.
        let frame_boot = if start_view().as_deref() == Some("session-live")
            && let Some(pid) = app.sessions.first().map(|s| s.profile_id)
        {
            app.seed_capture_frame(pid)
        } else {
            Task::none()
        };

        // zbus stays out of the reducer; tests inject protocol fakes and never touch
        // the real session bus. A capture fixture's store needs no connection.
        #[cfg(not(test))]
        let credential_boot = if !credential_fixture.connects_real_transport() {
            Task::none()
        } else {
            Task::perform(SecretServiceTransport::connect_or_unavailable(), |store| {
                Message::CredentialStoreReady(ConnectedCredentialStore(store))
            })
        };
        #[cfg(test)]
        let credential_boot = Task::none();

        // Both deferred boots must reach the runtime, or the app ships a compiled
        // default theme or an amnesiac credential store.
        let modal_focus_boot = app.sync_standard_modal_focus();
        let boot_tasks = Task::batch([
            theme_boot.map(|event| Message::Theme(Box::new(event))),
            credential_boot,
            modal_focus_boot,
            frame_boot,
        ]);

        (app, boot_tasks)
    }

    /// The bind-once runtime target for titlebar chrome commands. Native edge
    /// resize uses iced's current-window request channel instead.
    pub(crate) fn chrome_target(&self) -> Option<iced::window::Id> {
        self.main_window
    }
}
