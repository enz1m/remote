//! Credential plumbing: the `Message`-safe projection of the
//! framework credential outcome and the sidebar notice it can raise.
//!
//! Relocated verbatim from `main.rs`; no behaviour changed.

use std::sync::Arc;

use enzui_services::credential_store::{CredentialOutcome, CredentialStore};

/// A cloneable message payload for the asynchronously connected store.
///
/// Keeps the store opaque (`CredentialStore` does not require `Debug`) while
/// `Message` keeps its derived `Debug`.
#[derive(Clone)]
pub struct ConnectedCredentialStore(pub(crate) Arc<dyn CredentialStore>);

impl std::fmt::Debug for ConnectedCredentialStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConnectedCredentialStore(<dyn CredentialStore>)")
    }
}

/// A `Clone`-able, `Message`-safe projection of
/// [`enzui_services::credential_store::CredentialOutcome`].
///
/// The framework's non-`Clone` `Secret` cannot live in a `Message`. The
/// retrieved password appears as `Option<String>` only on the connect path
/// and is dropped once the backend call is dispatched.
#[derive(Debug, Clone, PartialEq)]
pub enum CredResult {
    /// A `set` completed: the secret is stored.
    Stored,
    /// A `delete` completed (idempotent: also covers "there was nothing").
    Deleted,
    /// A `get` found a value.
    Retrieved(String),
    /// A `get` found nothing.
    NotFound,
    /// No Secret Service on the bus. On a `set` the password could not be saved
    /// and must not be written anywhere else; on a `get`/`delete` treat it as
    /// gone.
    Unavailable,
    /// A locked keyring's unlock prompt was dismissed by the user. Not an error;
    /// no error surface may be raised.
    UnlockCancelled,
    /// The application cancelled the op (e.g. the user pressed Cancel on a
    /// pending connect). Like [`Self::UnlockCancelled`], not an error.
    Cancelled,
    /// A policy layer refused the op.
    Denied,
    /// Transport/protocol failure. The string is a short diagnostic.
    Failed(String),
}

impl CredResult {
    /// Project a framework [`CredentialOutcome`] onto the reducer's view of
    /// it, consuming (and thereby wiping) any retrieved `Secret`.
    pub fn from_outcome(outcome: CredentialOutcome) -> Self {
        match outcome {
            CredentialOutcome::Retrieved(secret) => {
                // The bytes are UTF-8 in this app (passwords typed into a text
                // field). Copy them out, then let the Secret drop and wipe.
                let s = String::from_utf8_lossy(secret.expose_secret()).into_owned();
                CredResult::Retrieved(s)
            }
            CredentialOutcome::Stored => CredResult::Stored,
            CredentialOutcome::Deleted => CredResult::Deleted,
            CredentialOutcome::NotFound => CredResult::NotFound,
            CredentialOutcome::Unavailable => CredResult::Unavailable,
            CredentialOutcome::UnlockCancelled => CredResult::UnlockCancelled,
            CredentialOutcome::Cancelled => CredResult::Cancelled,
            CredentialOutcome::PermissionDenied => CredResult::Denied,
            CredentialOutcome::Saturated => {
                CredResult::Failed("The credential service is busy.".to_owned())
            }
            CredentialOutcome::OwnerShutdown => CredResult::Unavailable,
            CredentialOutcome::MutationUncertain => CredResult::Failed(
                "The credential change is uncertain and requires reconciliation.".to_owned(),
            ),
            CredentialOutcome::Failed(msg) => CredResult::Failed(msg),
        }
    }

    /// Whether this outcome is a user-visible cancellation (unlock prompt
    /// dismissed or application-side cancel). No error surface may be raised for
    /// either.
    pub fn is_cancellation(&self) -> bool {
        matches!(self, Self::UnlockCancelled | Self::Cancelled)
    }

    /// Whether a `set` under this outcome stored the secret. Only
    /// [`Self::Stored`] did.
    pub fn stored_ok(&self) -> bool {
        matches!(self, Self::Stored)
    }
}

/// A dismissable notice raised by a profile operation that did not complete.
///
/// Rendered as a dismissible toast (`sidebar_view::credential_toast`), only for
/// genuine failures, never for
/// [`CredResult::UnlockCancelled`]/[`CredResult::Cancelled`]. Credential and
/// profile-store write refusals share this surface; the constructors keep a
/// database refusal from wearing the keyring's title.
#[derive(Debug, Clone, PartialEq)]
pub struct CredentialNotice {
    /// The banner title.
    pub title: String,
    /// The banner body.
    pub body: String,
    /// `true` paints the danger tone; `false` a neutral "heads up" tone. An
    /// `Unavailable`-on-save is `true` (the password was not saved) but is
    /// still a carry-on, not a crash.
    pub is_error: bool,
    /// Whether the refusal this reports was a Quick Connect history write.
    ///
    /// Carried rather than re-derived from the prose: a later history write
    /// that succeeds withdraws this banner, and deciding which banner that is
    /// by matching its text would tie the rule to the authored wording.
    history_write: bool,
}

impl CredentialNotice {
    /// "Could not save the password" — the store was unavailable. The security
    /// gate: nothing was written anywhere, and the UI says so plainly rather
    /// than pretending the save worked.
    pub fn save_unavailable(profile: &str) -> Self {
        Self {
            title: "Could not save the password".to_string(),
            body: format!(
                "No system keyring is available, so {profile}'s password was \
                 not stored. The connection was saved without it — you will be \
                 asked for the password when you connect."
            ),
            is_error: true,
            history_write: false,
        }
    }

    /// A credential failure whose reason is already a bounded human string.
    /// Route raw D-Bus / zbus / secret-service diagnostics through
    /// [`Self::save_translated`] instead.
    pub fn save_failed(profile: &str, reason: &str) -> Self {
        Self {
            title: "Could not save the password".to_string(),
            body: format!("{profile}: {reason}"),
            is_error: true,
            history_write: false,
        }
    }

    /// Build a save-failure notice from a bounded
    /// [`crate::error_boundary::KeyringFailure`] category; no raw D-Bus text
    /// reaches the banner.
    pub fn save_translated(cause: crate::error_boundary::KeyringFailure, profile: &str) -> Self {
        Self {
            title: cause.title(profile),
            body: cause.body(profile),
            is_error: true,
            history_write: false,
        }
    }

    /// Build a notice for a profile-store write the database refused.
    ///
    /// The title comes from the operation and the body from the bounded
    /// [`crate::error_boundary::DbWriteFailure`] category; the raw
    /// `rusqlite::Error` (statement and pathname) never reaches it. The marker
    /// publication operations
    /// ([`crate::error_boundary::DbWriteOperation::PublishSecretStored`],
    /// [`crate::error_boundary::DbWriteOperation::PublishSecretRemoved`]) say
    /// which way the keyring and row disagree and how to reconcile them.
    pub fn write_refused(
        cause: crate::error_boundary::DbWriteFailure,
        op: crate::error_boundary::DbWriteOperation,
        profile: &str,
    ) -> Self {
        Self {
            title: op.title(),
            body: cause.body(op, profile),
            is_error: true,
            history_write: op.is_recent_history(),
        }
    }

    /// Whether this banner was raised about a Quick Connect history write.
    #[must_use]
    pub fn is_recent_write(&self) -> bool {
        self.history_write
    }
}
