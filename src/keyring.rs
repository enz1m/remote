//! Credential keys for remote-app profiles, and the three-valued
//! [`KeyringBadge`] that reports whether a profile has a stored secret.
//!
//! The store itself is the framework's async, cancellable
//! [`enzui_services::credential_store`]; this module names the keys, maps
//! presence to [`KeyringBadge`], and reconciles hints at boot in
//! [`reconcile_badge_on_boot`].
//!
//! # Persistence
//!
//! The app connects the Secret Service transport asynchronously after its
//! first [`App`](crate::App) state and holds an unavailable store until then;
//! it never substitutes a file or in-process map. The persisted
//! `has_keyring_password` bit is a hint: updated on an exact `contains` answer,
//! preserved on `Unknown`.
//!
//! The badge calls [`CredentialStore::contains`] on every paint, which never
//! unlocks or retrieves the secret; the Secret Service transport answers
//! `Unknown` rather than doing D-Bus I/O per row.
//!
//! # `KeyringBadge` semantics
//!
//! * [`KeyringBadge::Present`] — a secret is known to be stored. The form's
//!   password field shows [`crate::form::PASSWORD_IN_KEYRING_STORED`] and the
//!   sidebar profile row paints a small key glyph.
//! * [`KeyringBadge::Absent`] — no secret is stored for this profile. No
//!   glyph, and the form field shows [`crate::form::PASSWORD_IN_KEYRING`].
//! * [`KeyringBadge::Unknown`] — the backend cannot answer without unlocking;
//!   maps `CredentialPresence::Unknown` and is never shown as `Absent`.
//!
//! [`MemoryCredentialStore`]: enzui_services::credential_store::MemoryCredentialStore

#[cfg(not(test))]
use std::sync::Arc;

use enzui_services::credential_store::{CredentialKey, CredentialPresence, CredentialStore};
#[cfg(not(test))]
use enzui_services::credential_store::{PendingCredentialOp, Secret};
use uuid::Uuid;

use crate::model::ConnectionProfile;

/// The reverse-DNS application id every credential of this app is namespaced
/// under. A backend can forget every secret this app owns by matching this
/// attribute, and two apps that both label a secret `password` for the same
/// owner cannot collide.
pub const APP_ID: &str = "com.enzui.remote-app";

/// The label for a connection's own password.
pub const LABEL_PASSWORD: &str = "password";

/// The label for an SSH jump host's password. Distinct from
/// [`LABEL_PASSWORD`] so one profile can hold two secrets without them
/// overwriting each other.
pub const LABEL_TUNNEL: &str = "ssh-tunnel";

/// The [`CredentialKey`] for a profile's connection password.
///
/// Maps to `CredentialKey::new("com.enzui.remote-app", "profile:{id}",
/// "password")`.
pub fn profile_password_key(id: Uuid) -> CredentialKey {
    CredentialKey::new(APP_ID, format!("profile:{id}"), LABEL_PASSWORD)
}

/// The [`CredentialKey`] for a profile's SSH jump-host password.
///
/// Maps to `CredentialKey::new("com.enzui.remote-app", "profile:{id}",
/// "ssh-tunnel")`.
pub fn tunnel_password_key(id: Uuid) -> CredentialKey {
    CredentialKey::new(APP_ID, format!("profile:{id}"), LABEL_TUNNEL)
}

// ---------------------------------------------------------------------------
// The three-valued keyring badge
// ---------------------------------------------------------------------------

/// What the profile list should say about a profile's stored password.
///
/// `Unknown` is returned when the backend cannot answer without unlocking;
/// the UI must not treat it as `Absent`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeyringBadge {
    /// A secret is stored for this profile in this session.
    Present,
    /// No secret is stored for this profile.
    Absent,
    /// The backend cannot answer without unlocking or otherwise paying a
    /// user-visible cost. The badge renders as a muted `?` and the UI must
    /// not treat this as `Absent`.
    Unknown,
}

impl KeyringBadge {
    /// The badge's short one-word accessible label (for AT and inline error
    /// prose). Kept in one place so a rename of the state does not have to
    /// hunt through the view files.
    #[allow(
        dead_code,
        reason = "consumed by the row's accessible-name aggregation only in \
            the test module today; kept here so the label lives with the \
            enum, not the caller."
    )]
    pub fn label(self) -> &'static str {
        match self {
            Self::Present => "Password saved",
            Self::Absent => "No saved password",
            Self::Unknown => "Saved password status unknown",
        }
    }

    /// The lucide icon key for the row glyph, or `None` when no glyph is
    /// drawn. `Absent` deliberately draws nothing — empty is louder than a
    /// crossed-out icon in a busy list.
    pub fn icon(self) -> Option<&'static str> {
        match self {
            Self::Present => Some("key"),
            Self::Absent => None,
            Self::Unknown => Some("status.info"),
        }
    }
}

/// The badge the app should paint for `profile`, answered by the credential
/// store without retrieving or unlocking the secret.
///
/// This is the ONE place the app asks "is there a saved password?". The
/// persisted `has_keyring_password` flag is deliberately not consulted: boot
/// can clear that stale hint while an injected or future persistent backend
/// still knows that a secret exists.
pub fn badge_for(credentials: &dyn CredentialStore, profile: &ConnectionProfile) -> KeyringBadge {
    match credentials.contains(&profile_password_key(profile.id)) {
        CredentialPresence::Present => KeyringBadge::Present,
        CredentialPresence::Absent => KeyringBadge::Absent,
        CredentialPresence::Unknown => KeyringBadge::Unknown,
    }
}

/// Capture-only decorator that pins the cheap presence answer while delegating
/// every real operation to an outcome-shaped framework store.
///
/// This is selected only when `REMOTE_APP_CREDENTIAL_SETTLED=1`; it lets the
/// current-source visual gate render saved and unknown badges without touching
/// the operator's real keyring. The app still holds it solely as
/// `Arc<dyn CredentialStore>`.
#[cfg(not(test))]
pub(crate) struct CapturePresenceStore {
    inner: Arc<dyn CredentialStore>,
    presence: CredentialPresence,
}

#[cfg(not(test))]
impl CapturePresenceStore {
    pub(crate) fn new(inner: Arc<dyn CredentialStore>, presence: CredentialPresence) -> Self {
        Self { inner, presence }
    }
}

#[cfg(not(test))]
impl CredentialStore for CapturePresenceStore {
    fn get(&self, key: CredentialKey) -> PendingCredentialOp {
        self.inner.get(key)
    }

    fn set(&self, key: CredentialKey, secret: Secret) -> PendingCredentialOp {
        self.inner.set(key, secret)
    }

    fn delete(&self, key: CredentialKey) -> PendingCredentialOp {
        self.inner.delete(key)
    }

    fn contains(&self, _key: &CredentialKey) -> CredentialPresence {
        self.presence
    }
}

// ---------------------------------------------------------------------------
// Capture fixtures
// ---------------------------------------------------------------------------

/// Which credential state a capture run is asking to photograph.
///
/// Built from `--start-view=` and `REMOTE_APP_CREDENTIAL_SETTLED` as data, so
/// store selection, connection, notice, drawer and profile seeding are
/// unit-testable without mutating the environment.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum CaptureCredentialFixture {
    /// Not a capture run. Boot holds an [`UnavailableCredentialStore`] and
    /// connects the real Secret Service transport asynchronously.
    ///
    /// [`UnavailableCredentialStore`]: enzui_services::credential_store::UnavailableCredentialStore
    None,
    /// A capture run whose start view is about something else (the connection
    /// form, a context menu…). It still must not touch the operator's session
    /// bus, so the store is deterministic and no connection is attempted — but
    /// nothing about the sidebar changes, so those committed shots are
    /// unaffected.
    Deterministic,
    /// `--start-view=keyring-saved`: every row reports a stored password.
    Saved,
    /// `--start-view=keyring-locked`: a locked keyring whose unlock prompt was
    /// dismissed. Not an error: the badge is `Unknown` and no banner is raised.
    Locked,
    /// `--start-view=keyring-unavailable`: no Secret Service on the bus, with
    /// the "could not save the password" notice on screen.
    Unavailable,
}

impl CaptureCredentialFixture {
    /// Classify a capture request. `settled` is the harness's committed
    /// `REMOTE_APP_CREDENTIAL_SETTLED=1`; `view` is the `--start-view=` value.
    ///
    /// Without `settled` there is no fixture at all, whatever the view says: a
    /// keyring start view alone must never suppress the real transport in a
    /// normal launch.
    pub(crate) fn from_start_view(settled: bool, view: Option<&str>) -> Self {
        if !settled {
            return Self::None;
        }
        match view {
            Some("keyring-saved") => Self::Saved,
            Some("keyring-locked") => Self::Locked,
            Some("keyring-unavailable") => Self::Unavailable,
            _ => Self::Deterministic,
        }
    }

    /// The store this fixture boots with, or `None` when the real transport
    /// should be connected instead.
    ///
    /// `Some` also means "do not schedule the D-Bus connect": a capture must be
    /// deterministic and must never depend on the operator's keyring.
    #[cfg(not(test))]
    pub(crate) fn store(self) -> Option<Arc<dyn CredentialStore>> {
        use enzui_services::credential_store::{
            MemoryCredentialStore, UnavailableCredentialStore, UnlockCancelledCredentialStore,
        };
        match self {
            Self::None => None,
            Self::Deterministic | Self::Unavailable => Some(Arc::new(UnavailableCredentialStore)),
            Self::Locked => Some(Arc::new(UnlockCancelledCredentialStore)),
            // A real, working store behind a pinned `Present` answer: the rows
            // paint the saved badge without the capture inventing a secret in
            // anybody's keyring.
            Self::Saved => Some(Arc::new(CapturePresenceStore::new(
                Arc::new(MemoryCredentialStore::new()),
                CredentialPresence::Present,
            ))),
        }
    }

    /// Whether boot should connect the real Secret Service transport.
    ///
    /// The complement of [`store`](Self::store) returning `Some`, stated as its
    /// own predicate so the boot site does not have to build a fixture store
    /// twice to ask the question. The two are pinned together by
    /// `tests::a_fixture_store_and_a_real_connection_are_exclusive`.
    #[cfg(not(test))]
    pub(crate) fn connects_real_transport(self) -> bool {
        matches!(self, Self::None)
    }

    /// Whether this fixture seeds the credential notice banner.
    pub(crate) fn raises_unavailable_notice(self) -> bool {
        matches!(self, Self::Unavailable)
    }

    /// Seed the alternating saved-password hints used by the saved capture.
    ///
    /// This mutation belongs to the classified value rather than directly to
    /// `--start-view=keyring-saved`: without the harness's settled opt-in the
    /// classifier is [`Self::None`] and leaves production profile state
    /// unchanged.
    pub(crate) fn seed_saved_profile_hints(self, profiles: &mut [ConnectionProfile]) {
        if !matches!(self, Self::Saved) {
            return;
        }
        for (index, profile) in profiles.iter_mut().enumerate() {
            if index.is_multiple_of(2) {
                profile.has_keyring_password = true;
            }
        }
    }

    /// Whether the sidebar pane must be visible for this fixture.
    ///
    /// The keyring fixtures show the row badge and notice banner, which a
    /// collapsed narrow-rung drawer hides. Other fixtures answer `false` so their
    /// committed shots stay put.
    pub(crate) fn needs_sidebar_visible(self) -> bool {
        matches!(self, Self::Saved | Self::Locked | Self::Unavailable)
    }
}

/// Reconcile each persisted password hint with the store's cheap, non-unlocking
/// existence answer.
///
/// `Present` and `Absent` update the hint; `Unknown` leaves it unchanged.
/// Never calls [`CredentialStore::get`], so it cannot trigger unlock prompts.
pub fn reconcile_badge_on_boot(
    profiles: &mut [ConnectionProfile],
    credentials: &dyn CredentialStore,
) {
    for profile in profiles.iter_mut() {
        match credentials.contains(&profile_password_key(profile.id)) {
            CredentialPresence::Present => profile.has_keyring_password = true,
            CredentialPresence::Absent => profile.has_keyring_password = false,
            CredentialPresence::Unknown => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {

    // ---- KeyringBadge --------------------------------------------
}
