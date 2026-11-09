//! Translate WoL socket, Secret Service credential, profile store write, and
//! profile import/export filesystem failures at their typed boundary into
//! bounded, human categories.
//!
//! Raw backend `Display` text (`io::Error`, `zbus`/`secret-service`,
//! `rusqlite`, `serde_json`) is unactionable, varies with locale and system, and
//! can carry newlines, control bytes or unbounded length into a live-region
//! announcement. This module is the single place it becomes bounded prose.
//!
//! # Contract
//!
//! For each boundary this module exposes:
//!
//! * a classifier that consumes the raw string once, produces a bounded
//!   category variant, and lets the raw string drop (or be logged
//!   separately) so nothing above the boundary sees it;
//! * `title(&subject)` and `body(&subject)` — the stable, human,
//!   substring-testable prose the banner renders. The subject (a profile
//!   name) is the ONE dynamic value permitted, sanitised via
//!   [`sanitize_subject`] so newline/control payloads cannot survive.
//!
//! The categories are:
//!
//! | boundary | category | meaning |
//! |---|---|---|
//! | WoL | [`WolFailure::SocketUnavailable`] | UDP bind/socket refused (address in use, socket cost) |
//! | WoL | [`WolFailure::PermissionDenied`]  | OS refused a broadcast/bind (capability missing) |
//! | WoL | [`WolFailure::NetworkUnavailable`] | Network stack has no route (interface down/unreach) |
//! | WoL | [`WolFailure::Other`]            | Untranslated — safe generic prose |
//! | keyring | [`KeyringFailure::Unavailable`] | No Secret Service on the bus |
//! | keyring | [`KeyringFailure::Locked`]      | Keyring is locked and cannot unlock |
//! | keyring | [`KeyringFailure::Denied`]      | Policy/permission refused the operation |
//! | keyring | [`KeyringFailure::Other`]       | Untranslated — safe generic prose |
//! | transfer | [`TransferFailure::PermissionDenied`] | OS refused a read or write |
//! | transfer | [`TransferFailure::SourceMissing`]    | The import file does not exist |
//! | transfer | [`TransferFailure::DestinationMissing`] | The export destination does not exist |
//! | transfer | [`TransferFailure::StorageExhausted`] | No space, quota exceeded, or the volume is full |
//! | transfer | [`TransferFailure::InvalidData`]      | The file could not be read as UTF-8 text |
//! | transfer | [`TransferFailure::Other`]            | Untranslated — safe generic prose |
//! | profile store | [`DbWriteFailure::ReadOnly`] | SQLite refused the write on permission grounds |
//! | profile store | [`DbWriteFailure::StorageExhausted`] | The volume or the database cannot grow |
//! | profile store | [`DbWriteFailure::Busy`] | Another writer holds the database or a table lock |
//! | profile store | [`DbWriteFailure::Damaged`] | The file is not a readable database, or is malformed |
//! | profile store | [`DbWriteFailure::Other`] | Untranslated — safe generic prose |
//!
//! [`DbWriteOperation`] selects which consequence the profile-store copy names.
//! The `Publish*` arms describe a disagreement between the keyring and the
//! connection record, not a lost edit.
//!
//! Every category maps to prose that:
//!
//! * contains no raw substring from the classified input;
//! * never contains `(os error`, the tokens `zbus`, `secret-service error:`,
//!   a D-Bus interface (`org.freedesktop.*`), a newline, or any control byte;
//! * stays under [`MAX_BANNER_BYTES`] bytes for title+body combined.

use std::borrow::Cow;

/// The byte ceiling for the combined title + body of any banner this module
/// produces, so a `Role::Alert` announcement stays short.
///
/// A hard bound the tests assert; widening it is a policy change.
#[allow(
    dead_code,
    reason = "consumed by `error_boundary_tests` as the banner byte ceiling; \
        exported here so the bound lives with the classifiers, not the test file."
)]
pub const MAX_BANNER_BYTES: usize = 512;

/// The maximum bytes a subject (a profile name) may contribute after
/// sanitisation. A malformed hostile payload cannot inflate the banner past
/// this bound whatever its length.
pub const MAX_SUBJECT_BYTES: usize = 96;

/// Clean a subject string for banner interpolation:
///
/// * strips newlines and other control bytes;
/// * collapses runs of whitespace;
/// * caps the byte length at [`MAX_SUBJECT_BYTES`] on a UTF-8 char boundary
///   with an ellipsis when it had to shorten.
///
/// Returns `Cow::Borrowed` when the input was already clean and short.
pub fn sanitize_subject(raw: &str) -> Cow<'_, str> {
    let needs_scrub = raw
        .chars()
        .any(|c| c.is_control() || c == '\u{FEFF}' || c == '\u{200B}');
    let cleaned: Cow<'_, str> = if needs_scrub {
        let mut out = String::with_capacity(raw.len());
        let mut prev_space = false;
        for c in raw.chars() {
            if c.is_control() || c.is_whitespace() || c == '\u{FEFF}' || c == '\u{200B}' {
                if !prev_space {
                    out.push(' ');
                    prev_space = true;
                }
            } else {
                out.push(c);
                prev_space = false;
            }
        }
        Cow::Owned(out.trim().to_string())
    } else {
        Cow::Borrowed(raw)
    };

    if cleaned.len() <= MAX_SUBJECT_BYTES {
        return cleaned;
    }

    // Leave room for a three-byte ellipsis inside the byte ceiling.
    const ELLIPSIS: char = '…';
    let budget = MAX_SUBJECT_BYTES.saturating_sub(ELLIPSIS.len_utf8());
    let mut end = budget;
    while end > 0 && !cleaned.is_char_boundary(end) {
        end -= 1;
    }
    let mut owned = cleaned[..end].to_string();
    owned.push(ELLIPSIS);
    debug_assert!(owned.len() <= MAX_SUBJECT_BYTES);
    Cow::Owned(owned)
}

// ---------------------------------------------------------------------------
// Wake-on-LAN
// ---------------------------------------------------------------------------

/// A bounded classification of a Wake-on-LAN send failure.
///
/// The raw diagnostic that a `std::io::Error` (or its `format!("bind: {e}")`
/// prefix from `send_wol_packet`) produces is retained only for logging: the
/// user-facing banner reads a category, not the string.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WolFailure {
    /// A UDP socket could not be opened for broadcast (address already in
    /// use, per-process socket limit, or bind on a specific broadcast
    /// address refused).
    SocketUnavailable,
    /// The OS refused to open a broadcast socket without a capability the
    /// process does not hold (`EPERM` / `EACCES`), or refused
    /// `set_broadcast(true)`.
    PermissionDenied,
    /// The network stack itself refused: the interface is down, the network
    /// is unreachable, no route to the broadcast address.
    NetworkUnavailable,
    /// The raw string did not match a translated category. The banner uses
    /// a generic safe fallback rather than interpolating the string.
    Other,
}

impl WolFailure {
    /// Classify the raw error string emitted by
    /// [`crate::model::send_wol_packet`] (or an equivalent seam) into a
    /// bounded category. Matching is ASCII case-insensitive and never keeps
    /// a reference to the input.
    #[must_use]
    pub fn classify(raw: &str) -> Self {
        let lc = raw.to_ascii_lowercase();
        // Permission is checked before "address" and "unreachable" so a permission
        // failure is never reclassified.
        if lc.contains("permission denied")
            || lc.contains("os error 13")
            || lc.contains("os error 1)")
            || lc.contains("(os error 1 ")
            || lc.contains("access denied")
        {
            return Self::PermissionDenied;
        }
        if lc.contains("network is unreachable")
            || lc.contains("no route to host")
            || lc.contains("host is down")
            || lc.contains("network is down")
            || lc.contains("os error 101")
            || lc.contains("os error 100")
            || lc.contains("os error 113")
            || lc.contains("os error 112")
        {
            return Self::NetworkUnavailable;
        }
        if lc.contains("address already in use")
            || lc.contains("address not available")
            || lc.contains("cannot assign requested address")
            || lc.contains("too many open files")
            || lc.contains("os error 98")
            || lc.contains("os error 99")
            || lc.contains("os error 24")
            || lc.starts_with("bind:")
            || lc.starts_with("set_broadcast:")
            || lc.contains("no broadcast port accepted")
        {
            return Self::SocketUnavailable;
        }
        Self::Other
    }

    /// The banner title for this category. Names the profile through the
    /// bounded subject path so the user knows *which* wake attempt failed.
    #[must_use]
    pub fn title(self, subject: &str) -> String {
        let name = sanitize_subject(subject);
        match self {
            Self::SocketUnavailable => format!("Wake-on-LAN could not be sent to {name}"),
            Self::PermissionDenied => format!("Wake-on-LAN could not be sent to {name}"),
            Self::NetworkUnavailable => format!("Wake-on-LAN could not be sent to {name}"),
            Self::Other => format!("Wake-on-LAN could not be sent to {name}"),
        }
    }

    /// The banner body. Actionable, bounded, never contains the raw string.
    #[must_use]
    pub fn body(self, subject: &str) -> String {
        let _ = subject; // subject is named in the title only
        match self {
            Self::SocketUnavailable => "The broadcast socket is unavailable on this machine. \
                 Close any other program that is sending Wake-on-LAN \
                 packets and try again."
                .to_string(),
            Self::PermissionDenied => "This system refused to open a broadcast socket. Check that \
                 the app has network permission and try again."
                .to_string(),
            Self::NetworkUnavailable => {
                "No network connection is available for a broadcast. Check \
                 that this machine is on the same network as the target and \
                 try again."
                    .to_string()
            }
            Self::Other => "The broadcast could not be sent. Check the target's Wake-on-LAN \
                 configuration and the local network, then try again."
                .to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Keyring
// ---------------------------------------------------------------------------

/// A bounded classification of a Secret Service (or equivalent transport)
/// failure surfaced on a credential save.
///
/// The raw diagnostic (a D-Bus error name, a zbus transport string, or the
/// framework's opaque `Failed(String)` payload) is retained only for
/// logging. The banner reads a category.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeyringFailure {
    /// No Secret Service on the bus at all (`ServiceUnknown`, no session
    /// bus, or a container without a bus socket).
    Unavailable,
    /// The keyring is present but locked and the user's unlock prompt could
    /// not be completed (dismissed by policy, or a locked collection that
    /// cannot be reached from this session).
    Locked,
    /// Policy or permission refused the write (SELinux, Flatpak permission
    /// missing, `AuthenticationFailed`).
    Denied,
    /// Untranslated failure. The banner uses a safe generic prose.
    Other,
}

impl KeyringFailure {
    /// Classify a raw Secret Service diagnostic — for example, the string
    /// carried by `CredResult::Failed(_)` — into a bounded category. Never
    /// keeps a reference to the input.
    #[must_use]
    pub fn classify(raw: &str) -> Self {
        let lc = raw.to_ascii_lowercase();
        if lc.contains("serviceunknown")
            || lc.contains("service unknown")
            || lc.contains("no such name")
            || lc.contains("no session bus")
            || lc.contains("not provided by any .service")
            || lc.contains("connection is closed")
            || lc.contains("no session dbus")
        {
            return Self::Unavailable;
        }
        if lc.contains("islocked")
            || lc.contains("is locked")
            || lc.contains("keyring is locked")
            || lc.contains("collection is locked")
            || lc.contains("prompt dismissed")
        {
            return Self::Locked;
        }
        if lc.contains("permission denied")
            || lc.contains("access denied")
            || lc.contains("not authorized")
            || lc.contains("authenticationfailed")
            || lc.contains("policy refused")
            || lc.contains("authorization required")
        {
            return Self::Denied;
        }
        Self::Other
    }

    /// The banner title. Uniform across categories: a save failure is one
    /// user-visible fact regardless of which OS layer refused it.
    #[must_use]
    pub fn title(self, _subject: &str) -> String {
        "Could not save the password".to_string()
    }

    /// The banner body. Names the profile (bounded), states the category
    /// in plain prose, and never interpolates the raw string.
    #[must_use]
    pub fn body(self, subject: &str) -> String {
        let name = sanitize_subject(subject);
        match self {
            Self::Unavailable => format!(
                "No system keyring is available, so {name}'s password was not \
                 stored. The connection was saved without it — you will be \
                 asked for the password when you connect."
            ),
            Self::Locked => format!(
                "The system keyring is locked, so {name}'s password could not \
                 be stored. Unlock the keyring and save again."
            ),
            Self::Denied => format!(
                "The system keyring refused to store {name}'s password. \
                 Check the keyring's permissions and save again."
            ),
            Self::Other => format!(
                "The system keyring could not store {name}'s password. \
                 The password was not saved."
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Profile import / export (filesystem)
// ---------------------------------------------------------------------------

/// Whether a translated transfer failure was on the READ side (importing an
/// existing file into the profile store) or the WRITE side (exporting the
/// profile store to a chosen path). Reads and writes share the same
/// [`TransferFailure`] classifier — the difference is the verb the banner
/// speaks, and which arm the recovery hint reaches for.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TransferOperation {
    /// Reading an import file — the banner talks about the source.
    Read,
    /// Writing an export document — the banner talks about the destination.
    Write,
}

/// A bounded classification of filesystem errors from profile import and
/// pre-publication export operations.
///
/// Raw paths and the `io::Error`'s `Display` text are discarded at this
/// boundary. Application state and the banner retain only this bounded
/// category's safe message.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TransferFailure {
    /// The OS refused the read or the write on permission grounds
    /// ([`std::io::ErrorKind::PermissionDenied`]).
    PermissionDenied,
    /// The import file does not exist ([`std::io::ErrorKind::NotFound`] on a
    /// read). Kept distinct from [`Self::DestinationMissing`] so the copy
    /// can name the correct side.
    SourceMissing,
    /// The export destination does not exist ([`std::io::ErrorKind::NotFound`]
    /// on a write — a parent directory the chooser named that has since
    /// disappeared).
    DestinationMissing,
    /// The volume is full, the user's quota is exhausted, or a similar
    /// storage-side refusal. Delegated to the shared
    /// [`enzui_iced_core::io_class::IoFailureCategory::StorageExhausted`]
    /// category so `ErrorKind::StorageFull`, `ErrorKind::QuotaExceeded`,
    /// and the raw Linux ENOSPC/EDQUOT calibration all reach one arm.
    StorageExhausted,
    /// The file was reached but its bytes are not UTF-8 text — the JSON /
    /// `.rdp` / `.remmina` parsers only ever see a `String`, so
    /// [`crate::import_source::SourceRefusal::NotText`] reaches this arm
    /// before any parser runs.
    InvalidData,
    /// Untranslated failure. The banner uses a safe generic prose.
    Other,
}

impl TransferFailure {
    /// Classify an `io::Error` raised on the read side of a transfer.
    ///
    /// `InvalidData` (non-UTF-8 payload) is handled first because the shared category
    /// does not model it. The rest delegates to
    /// [`enzui_iced_core::io_class::IoFailureCategory::classify`], keeping only the
    /// read/write NotFound split local.
    #[must_use]
    pub fn classify_read(err: &std::io::Error) -> Self {
        if err.kind() == std::io::ErrorKind::InvalidData {
            return Self::InvalidData;
        }
        use enzui_iced_core::io_class::IoFailureCategory as C;
        match C::classify(err) {
            C::Permission => Self::PermissionDenied,
            C::NotFound => Self::SourceMissing,
            C::StorageExhausted => Self::StorageExhausted,
            C::NotADirectory | C::Unknown => Self::Other,
        }
    }

    /// Classify an `io::Error` raised on the WRITE side of a transfer.
    /// A `NotFound` on write means the destination parent is missing —
    /// distinct from an import's `NotFound` on the source. The remaining
    /// mapping delegates to the shared
    /// [`enzui_iced_core::io_class::IoFailureCategory::classify`] for the
    /// same reasons documented on [`Self::classify_read`].
    #[must_use]
    pub fn classify_write(err: &std::io::Error) -> Self {
        if err.kind() == std::io::ErrorKind::InvalidData {
            return Self::InvalidData;
        }
        use enzui_iced_core::io_class::IoFailureCategory as C;
        match C::classify(err) {
            C::Permission => Self::PermissionDenied,
            C::NotFound => Self::DestinationMissing,
            C::StorageExhausted => Self::StorageExhausted,
            C::NotADirectory | C::Unknown => Self::Other,
        }
    }

    /// The bounded, human, substring-testable banner body for this category
    /// and operation. Never contains a path, an `errno`, a control byte, or
    /// any substring of the raw `io::Error::Display`.
    #[must_use]
    pub fn body(self, op: TransferOperation) -> String {
        match (self, op) {
            (Self::PermissionDenied, TransferOperation::Read) => {
                "The system refused permission to read the connection file. \
                 Check the file's permissions and try again."
                    .to_string()
            }
            (Self::PermissionDenied, TransferOperation::Write) => {
                "The system refused permission to write the export. \
                 Choose a different destination and try again."
                    .to_string()
            }
            (Self::SourceMissing, _) => "The connection file could not be found. \
                 Choose a different file and try again."
                .to_string(),
            (Self::DestinationMissing, _) => "The export destination could not be found. \
                 Choose a different location and try again."
                .to_string(),
            (Self::StorageExhausted, _) => "There is not enough storage available to complete the \
                 transfer. Free some space and try again."
                .to_string(),
            (Self::InvalidData, TransferOperation::Read) => {
                "The file is not a supported connection file. Choose a \
                 different file and try again."
                    .to_string()
            }
            (Self::InvalidData, TransferOperation::Write) => {
                "The export could not be written. Choose a different \
                 destination and try again."
                    .to_string()
            }
            (Self::Other, TransferOperation::Read) => {
                "The connection file could not be read. Check the file \
                 and try again."
                    .to_string()
            }
            (Self::Other, TransferOperation::Write) => {
                "The export could not be written. Choose a different \
                 destination and try again."
                    .to_string()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Profile store writes
// ---------------------------------------------------------------------------

/// Which profile-store write a [`DbWriteFailure`] refused.
///
/// All arms share the classifier and differ in what the user has lost. The
/// `Publish*` arms follow a keyring answer, so their copy states what the keyring
/// holds and how the connection record now disagrees.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DbWriteOperation {
    /// A row was being inserted or updated: a form save, an import, a
    /// duplicate, or a favourite toggle.
    Save,
    /// A row was being removed.
    Delete,
    /// The row write that records a secret the keyring confirmed it stored. A
    /// refusal leaves the secret with nothing pointing at it.
    PublishSecretStored,
    /// The row write that withdraws a secret the keyring confirmed it removed. A
    /// refusal leaves the connection listing a missing password.
    PublishSecretRemoved,
    /// The row write that records a completed connection in Quick
    /// Connect history. A refusal leaves the endpoint listed for this process
    /// and absent from the next launch, which is why the row says so and
    /// offers a retry rather than the list quietly disagreeing with the store.
    RecordRecent,
    /// The statement that removes one or all history rows. A refusal
    /// leaves the rows on screen, because the alternative is emptying a list
    /// the next launch refills with no explanation.
    ForgetRecent,
}

impl DbWriteOperation {
    /// Whether this operation writes Quick Connect history.
    ///
    /// The two history writes and nothing else. A banner about one of them
    /// stops describing anything once another history write succeeds, which
    /// is not true of a profile save or a secret marker.
    #[must_use]
    pub fn is_recent_history(self) -> bool {
        matches!(self, Self::RecordRecent | Self::ForgetRecent)
    }

    /// The bounded banner title for this operation.
    ///
    /// The title names the *consequence* rather than the cause, because that
    /// is what the user has to decide about: the change they just made is not
    /// in the store. The cause is the body's job.
    #[must_use]
    pub fn title(self) -> String {
        match self {
            Self::Save => "Change not saved".to_string(),
            Self::Delete => "Connection not deleted".to_string(),
            Self::PublishSecretStored => "Password stored, connection not updated".to_string(),
            Self::PublishSecretRemoved => "Password removed, connection not updated".to_string(),
            // Names the durable consequence, not the statement: the user is
            // connected, and what did not happen is the remembering.
            Self::RecordRecent => "Recent connection not saved".to_string(),
            Self::ForgetRecent => "Recent connections not forgotten".to_string(),
        }
    }

    /// The past participle the banner body uses for this operation.
    fn verb(self) -> &'static str {
        match self {
            Self::Save | Self::PublishSecretStored | Self::RecordRecent => "saved",
            Self::Delete | Self::PublishSecretRemoved | Self::ForgetRecent => "removed",
        }
    }
}

/// A bounded classification of a SQLite refusal on the profile store's write
/// path.
///
/// A `rusqlite::Error`'s `Display` carries the failing SQL statement, the
/// database pathname and an extended result code, none of which belong in a
/// banner or a live-region announcement. The raw error is consumed here and
/// only this `Copy` category crosses into application state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DbWriteFailure {
    /// Refused on permission grounds: the file or its directory is not
    /// writable, or the database opened read-only (`SQLITE_READONLY`,
    /// `SQLITE_PERM`, `SQLITE_CANTOPEN`, `SQLITE_AUTH`).
    ReadOnly,
    /// The volume is full or the database hit a size limit (`SQLITE_FULL`,
    /// `SQLITE_TOOBIG`).
    StorageExhausted,
    /// Another writer holds the file or one of its tables (`SQLITE_BUSY`,
    /// `SQLITE_LOCKED`) — the shape a second copy of the app presents.
    Busy,
    /// Malformed, or not a database at all (`SQLITE_CORRUPT`,
    /// `SQLITE_NOTADB`). Distinct because retrying cannot help.
    Damaged,
    /// Untranslated refusal. The banner uses safe generic prose.
    Other,
}

impl DbWriteFailure {
    /// Classify a `rusqlite::Error` raised by a profile-store write.
    ///
    /// Errors carrying no SQLite result code (a serialisation or parameter
    /// defect) reach [`Self::Other`]: build defects rather than conditions the
    /// user can resolve, and the generic prose still tells the truth about
    /// what did not happen.
    #[must_use]
    pub fn classify(err: &rusqlite::Error) -> Self {
        use rusqlite::ErrorCode as C;
        match err.sqlite_error_code() {
            Some(
                C::ReadOnly
                | C::PermissionDenied
                | C::CannotOpen
                | C::AuthorizationForStatementDenied,
            ) => Self::ReadOnly,
            Some(C::DiskFull | C::TooBig) => Self::StorageExhausted,
            Some(C::DatabaseBusy | C::DatabaseLocked) => Self::Busy,
            Some(C::DatabaseCorrupt | C::NotADatabase) => Self::Damaged,
            _ => Self::Other,
        }
    }

    /// The cause clause and the recovery advice for this category. The clause
    /// reads as a sentence opener so the subject body, the advisory and the
    /// mid-sentence form can all build on it.
    fn parts(self) -> (&'static str, &'static str) {
        match self {
            Self::ReadOnly => (
                "The saved connections file is not writable",
                "Check the permissions on your data directory, then try again.",
            ),
            Self::StorageExhausted => (
                "There is not enough storage to update the saved connections",
                "Free some space, then try again.",
            ),
            Self::Busy => (
                "Another window is using the saved connections",
                "Close the other window, then try again.",
            ),
            Self::Damaged => (
                "The saved connections file is damaged",
                "Restore it from a backup before changing connections again.",
            ),
            Self::Other => (
                "The saved connections could not be updated",
                "Nothing was changed on disk. Try again.",
            ),
        }
    }

    /// The bounded, human, substring-testable banner body. Never contains a
    /// path, a SQL statement, a result code, or any substring of the raw
    /// `rusqlite::Error::Display`. `subject` — a profile name — is the one
    /// dynamic value, sanitised through [`sanitize_subject`].
    #[must_use]
    pub fn body(self, op: DbWriteOperation, subject: &str) -> String {
        let subject = sanitize_subject(subject);
        let verb = op.verb();
        let (cause, advice) = self.parts();
        match op {
            DbWriteOperation::Save | DbWriteOperation::Delete => {
                format!("{cause}, so {subject} was not {verb}. {advice}")
            }
            // The connection succeeded, so the body separates what is true now from what
            // survives a restart.
            DbWriteOperation::RecordRecent => {
                let mid = self.cause_mid_sentence();
                format!(
                    "You are connected to {subject}, but {mid}, so it will not appear in \
                     recent connections after a restart. {advice} The entry is marked \
                     unsaved until it is stored."
                )
            }
            DbWriteOperation::ForgetRecent => {
                format!("{cause}, so {subject} was not {verb}. {advice}")
            }
            // Leads with what the keyring durably holds, then what the record failed to
            // store; saving again reruns the credential decision and this row write.
            DbWriteOperation::PublishSecretStored => {
                let mid = self.cause_mid_sentence();
                format!(
                    "{subject}'s password is in the system keyring, but {mid}, so the \
                     connection does not record it and will not offer it after a restart. \
                     {advice} Save the connection again to finish."
                )
            }
            DbWriteOperation::PublishSecretRemoved => {
                let mid = self.cause_mid_sentence();
                format!(
                    "{subject}'s password was removed from the system keyring, but {mid}, \
                     so the connection still records one and the two will not agree after a \
                     restart. {advice} Save the connection again to finish."
                )
            }
        }
    }

    /// The cause clause with its first character lowered, for the arms that
    /// place it inside a sentence rather than at the front of one.
    fn cause_mid_sentence(self) -> String {
        let (cause, _) = self.parts();
        let mut chars = cause.chars();
        match chars.next() {
            None => String::new(),
            Some(first) => first.to_lowercase().collect::<String>() + chars.as_str(),
        }
    }
}

#[cfg(test)]
impl DbWriteFailure {}

#[cfg(test)]
mod tests {}
