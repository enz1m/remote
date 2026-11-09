//! Free helpers that follow `impl App`: event classification,
//! focus-restore seams, the capture-harness start view, the keystroke-menu
//! model builder, and the pure rules governing a profile's durable
//! secret markers.

use enzui_iced_core::focus::{Traversal, traversal_from_event};
use enzui_iced_core::menu_model::MenuModel;

use crate::SecretSlot;
use crate::discovery::DiscoveredHost;
use crate::form::{ConnectionForm, PasswordOutcome};
use crate::message::Message;
use crate::model::{ConnectionProfile, Protocol, SshAuth};
use crate::session::KeystrokePage;

/// Classify a raw runtime event into an app message, or `None` to let it fall
/// through. A free function so tests can pump it without a running runtime.
///
/// Tab decodes through the framework's [`traversal_from_event`], so
/// modifiers are kept and a captured Tab is not overridden.
/// `Window::Resized` is this app's single width authority.
pub(crate) fn classify_event(
    event: iced::Event,
    status: iced::event::Status,
    _id: iced::window::Id,
) -> Option<Message> {
    if let iced::Event::Window(iced::window::Event::Resized(size)) = event {
        return Some(Message::WindowResized(size));
    }
    if status == iced::event::Status::Ignored
        && let iced::Event::Keyboard(key) = &event
        && let Some(command) = crate::shortcuts::dispatch(key)
    {
        return Some(command);
    }
    traversal_from_event(&event, status).map(|traversal| match traversal {
        Traversal::Next => Message::FocusNext,
        Traversal::Previous => Message::FocusPrevious,
    })
}

/// Lift only `Opened` for bind-once titlebar routing. Automatic edge resize
/// reads authoritative native state and needs no mirrored lifecycle stream.
pub(crate) fn classify_main_window_opened(
    event: iced::Event,
    _status: iced::event::Status,
    id: iced::window::Id,
) -> Option<Message> {
    match event {
        iced::Event::Window(iced::window::Event::Opened { .. }) => {
            Some(Message::MainWindowOpened(id))
        }
        _ => None,
    }
}

/// Lift the close request for the exact window that produced it.
///
/// The close is only lifted, never performed: the runtime is configured with
/// `exit_on_close_request(false)`, so the window stays alive until the reducer
/// closes this same id once its connections are gone.
pub(crate) fn classify_close_request(
    event: iced::Event,
    _status: iced::event::Status,
    id: iced::window::Id,
) -> Option<Message> {
    enzui_iced_core::close_guard::CloseRequest::from_event(&event, id)
        .map(Message::WindowCloseRequested)
}

/// The focus-restore target for whichever connection form is closing: the
/// per-row "Edit" button for an edit form, or the "New connection" button for
/// an add form. Read the `editing` field BEFORE the form is cleared.
pub(crate) fn form_restore_id(form: Option<&ConnectionForm>) -> Option<iced::advanced::widget::Id> {
    form.map(|f| match f.editing {
        Some(pid) => crate::view::edit_button_id(pid),
        None => crate::view::add_button_id(),
    })
}

/// The capture harness's requested start view: `--start-view=<v>` on the
/// command line, else `REMOTE_APP_START_VIEW`, else `None`.
///
/// Argv wins because it is the only channel `_shared/capture.sh` can reach (see
/// `boot_with_db`); the env form serves the `sidebar` / `empty` captures and
/// the shell tests.
pub(crate) fn start_view() -> Option<String> {
    const FLAG: &str = "--start-view=";
    if let Some(v) = std::env::args().find_map(|a| a.strip_prefix(FLAG).map(str::to_owned)) {
        return Some(v);
    }
    std::env::var("REMOTE_APP_START_VIEW").ok()
}

/// Environment variable that requests the demo connection library. The
/// capture harness sets it in `remote-app/capture.env`; a normal launch
/// leaves it unset.
#[cfg(not(test))]
pub(crate) const DEMO_LIBRARY_ENV: &str = "REMOTE_APP_SEED";

/// Which library an empty profile database boots with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LibraryFixture {
    /// The shipping default: the library is whatever the database already
    /// holds, and an empty database stays empty.
    Production,
    /// The capture and example opt-in: an empty database is populated with
    /// [`crate::model::seed_profiles`] and those rows are persisted.
    Demo,
}

impl LibraryFixture {
    /// The fixture [`DEMO_LIBRARY_ENV`] requests in this process.
    #[cfg(not(test))]
    pub(crate) fn from_env() -> Self {
        Self::from_value(std::env::var(DEMO_LIBRARY_ENV).ok().as_deref())
    }

    /// [`Self::from_env`] with the variable's value supplied directly.
    ///
    /// Only the exact value `1` opts in; anything else is [`Self::Production`],
    /// so a stray value in a user's environment cannot fabricate a library.
    #[cfg(not(test))]
    pub(crate) fn from_value(value: Option<&str>) -> Self {
        match value {
            Some("1") => Self::Demo,
            _ => Self::Production,
        }
    }

    /// Whether Quick Connect history is read and written for this launch.
    ///
    /// True only for a shipping launch, so demo and capture runs neither record
    /// fabricated dials nor show a real user's rows beside fabricated profiles.
    pub(crate) fn records_history(self) -> bool {
        matches!(self, Self::Production)
    }

    /// Whether an empty database should be populated with demo profiles.
    pub(crate) fn seeds_an_empty_library(self) -> bool {
        matches!(self, Self::Demo)
    }

    /// The protocol backends this fixture boots with.
    ///
    /// Demo profiles get [`crate::protocol::StubBackend`] slots; the shipping
    /// library gets [`crate::protocol::BackendRegistry::production`], which
    /// registers only protocols with a transport. One opt-in decides both.
    pub(crate) fn backends(self) -> crate::protocol::BackendRegistry {
        match self {
            Self::Production => crate::protocol::BackendRegistry::production(),
            Self::Demo => crate::protocol::BackendRegistry::with_stubs(),
        }
    }
}

/// The Send keystrokes menu's entries for a page, built from the macro table:
/// entry ids are `KeystrokeMacro::id()`, resolved back through
/// `KeystrokeMacro::from_id`.
///
/// The seven VT rows are generated from `KeystrokePage::SwitchVt.macros()`,
/// so id, label, icon and chord share one `n`.
pub(crate) fn keystroke_menu_model(page: KeystrokePage) -> MenuModel {
    use crate::session::{
        KEYSTROKE_BACK_ENTRY_ID, KEYSTROKE_BACK_LABEL, SWITCH_VT_ENTRY_ID, SWITCH_VT_LABEL,
    };
    use enzui_iced_core::menu_model::MenuEntryModel;

    let mut entries: Vec<MenuEntryModel> = Vec::new();

    if page == KeystrokePage::SwitchVt {
        // `Back` first. A command row, not a
        // submenu row: it *leaves* a page rather than entering one.
        entries.push(
            MenuEntryModel::command(KEYSTROKE_BACK_ENTRY_ID, KEYSTROKE_BACK_LABEL)
                .icon("arrow-left"),
        );
        entries.push(MenuEntryModel::separator("keystroke-back-rule"));
    }

    entries.extend(
        page.macros()
            .into_iter()
            .map(|m| MenuEntryModel::command(m.id(), m.label()).icon(m.icon())),
    );

    if page == KeystrokePage::Root {
        // `Switch VT` is a `submenu` entry, so activation resolves to
        // `OpenSubmenu` rather than a chord `Dispatch`.
        entries.push(MenuEntryModel::separator("keystroke-vt-rule"));
        entries.push(MenuEntryModel::submenu(SWITCH_VT_ENTRY_ID, SWITCH_VT_LABEL).icon("terminal"));
    }

    MenuModel::new(entries)
}

/// The capture harness's demo scan, reached only via
/// `--start-view=discovered-demo`. The first host has a long name and address
/// to exercise single-line elision beside an ordinary neighbour.
pub(crate) fn capture_demo_hosts() -> Vec<DiscoveredHost> {
    vec![DiscoveredHost::new(
        "Engineering Lab Raspberry Pi Cluster Head Node — Building 4, Rack 12, Shelf 3",
        "engineering-lab-raspberry-pi-cluster-head-node.building4.rack12.corp.example.internal",
        Protocol::Vnc,
        5900,
    )]
}

// ---------------------------------------------------------------------------
// Durable secret markers
// ---------------------------------------------------------------------------

/// Set one slot's durable secret marker on `profile`.
///
/// A marker is the connection record's claim that a secret for this slot is in
/// the system keyring. The tunnel slot carries the claim in two fields:
/// `has_tunnel_password`, and the auth method the row reports — a jump host
/// that authenticates with a password it does not have would misreport how it
/// connects, so the two always move together.
pub(crate) fn set_secret_marker(profile: &mut ConnectionProfile, slot: SecretSlot, stored: bool) {
    match slot {
        SecretSlot::Password => profile.has_keyring_password = stored,
        SecretSlot::Tunnel => {
            if let Some(tunnel) = profile.ssh_tunnel.as_mut() {
                tunnel.has_tunnel_password = stored;
                tunnel.auth = if stored {
                    SshAuth::Password
                } else {
                    SshAuth::Agent
                };
            }
        }
    }
}

/// Hold a profile's secret markers at what is still durably true, for the row
/// a save writes before the credential store has answered.
///
/// * A pending `Set` is forced to `false`, so a refused, cancelled or
///   unavailable store cannot leave the row claiming a secret never stored.
/// * A pending `Cleared` keeps its marker, since withdrawing it before the
///   deletion is confirmed would orphan an unreachable secret.
/// * `Unchanged` dispatches nothing, so `apply_to`'s marker stands.
///
/// Removing the jump host is not handled here: `apply_to` drops the whole
/// `SshTunnel`, which under-claims while the deletion is in flight.
pub(crate) fn hold_pending_secret_markers(
    profile: &mut ConnectionProfile,
    password: &PasswordOutcome,
    password_before: bool,
    tunnel: &PasswordOutcome,
    tunnel_before: bool,
) {
    match password {
        PasswordOutcome::Set(_) => profile.has_keyring_password = false,
        PasswordOutcome::Cleared => profile.has_keyring_password = password_before,
        PasswordOutcome::Unchanged => {}
    }
    let Some(slot) = profile.ssh_tunnel.as_mut() else {
        return;
    };
    match tunnel {
        PasswordOutcome::Set(_) => {
            slot.has_tunnel_password = false;
            slot.auth = SshAuth::Agent;
        }
        PasswordOutcome::Cleared => {
            slot.has_tunnel_password = tunnel_before;
            slot.auth = if tunnel_before {
                SshAuth::Password
            } else {
                SshAuth::Agent
            };
        }
        PasswordOutcome::Unchanged => {}
    }
}

#[cfg(test)]
mod tests {

    // The committed capture policy must request the demo library under the
    // name the code reads, or every recapture photographs an empty sidebar.
}
