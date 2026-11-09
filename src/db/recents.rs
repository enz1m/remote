//! The value-level vocabulary of the `recents` table: what a row may hold,
//! and what it takes for one to describe a connection this build could have
//! made. The statements that read and write those rows are in the parent
//! module.

use crate::model::Protocol;
use crate::quick_connect::RecentConnection;

/// The longest host a recents row may admit.
///
/// Room for a hostname (253 bytes at most) or an IPv6 literal. Bounds what the
/// reader accepts, not what the writer produces: the writer's hosts come from
/// a profile the form already bounds.
pub const MAX_RECENT_HOST_BYTES: usize = 256;

/// The longest username a recents row may admit: the display bound the rest of
/// the app applies to any name it renders.
pub const MAX_RECENT_USERNAME_BYTES: usize = crate::display::MAX_DISPLAY_BYTES;

/// The longest protocol key a recents row may admit. Above every key
/// [`Protocol::from_key_exact`] knows, so the bound rejects a hostile value
/// without deciding which keys exist.
pub(super) const MAX_RECENT_PROTOCOL_BYTES: usize = 32;

/// The longest timestamp a recents row may admit. An RFC 3339 instant with
/// nanoseconds and an offset is under 40 bytes.
pub(super) const MAX_RECENT_STAMP_BYTES: usize = 64;

/// The longest identity a recents row may admit: a protocol key, a host and a
/// port, with separators.
pub const MAX_RECENT_IDENTITY_BYTES: usize = MAX_RECENT_PROTOCOL_BYTES + MAX_RECENT_HOST_BYTES + 8;

/// The largest `cap` any recents statement will honour.
///
/// `usize as i64` on a hostile value wraps to a negative `LIMIT`, which SQLite
/// reads as unbounded, so the caller's `cap` is clamped here instead.
pub const MAX_RECENT_CAP: usize = 64;

/// How many rows [`super::ProfileDb::load_recents`] will read to find `cap`
/// it accepts. Bounds the work on a store this build did not write.
pub const RECENT_READ_WINDOW: usize = MAX_RECENT_CAP * 8;

/// How many rows a write examines when choosing survivors. Rows past it are
/// deleted unread, being older than the cap window in any case.
pub(super) const RECENT_SETTLE_WINDOW: usize = RECENT_READ_WINDOW;

/// The `cap` a recents statement is allowed to use.
pub(super) fn bounded_recent_cap(cap: usize) -> i64 {
    i64::try_from(cap.min(MAX_RECENT_CAP)).unwrap_or(0)
}

/// The byte bounds bound to `?1..?5` of [`RECENT_DECODABLE_SQL`].
pub(super) fn recent_bound_params() -> [i64; 5] {
    [
        MAX_RECENT_IDENTITY_BYTES as i64,
        MAX_RECENT_PROTOCOL_BYTES as i64,
        MAX_RECENT_HOST_BYTES as i64,
        MAX_RECENT_USERNAME_BYTES as i64,
        MAX_RECENT_STAMP_BYTES as i64,
    ]
}

/// The storage-class and byte-length half of "this build could have written
/// this row", as a predicate over `recents`.
///
/// In SQL because these are the checks that keep an oversized durable value
/// from being copied into a Rust `String` at all. `length(CAST(col AS BLOB))`
/// counts bytes, where `length(col)` would count characters and disagree with
/// the Rust bounds. Never NULL: each `typeof` test is total and short-circuits
/// the comparison after it, so `NOT (..)` is usable.
pub(super) const RECENT_DECODABLE_SQL: &str = "typeof(identity)     = 'text'
            AND typeof(protocol)     = 'text'
            AND typeof(host)         = 'text'
            AND typeof(username)     = 'text'
            AND typeof(connected_at) = 'text'
            AND typeof(port)         = 'integer'
            AND port BETWEEN 0 AND 65535
            AND length(CAST(identity     AS BLOB)) BETWEEN 1 AND ?1
            AND length(CAST(protocol     AS BLOB)) BETWEEN 1 AND ?2
            AND length(CAST(host         AS BLOB)) BETWEEN 1 AND ?3
            AND length(CAST(username     AS BLOB)) <= ?4
            AND length(CAST(connected_at AS BLOB)) BETWEEN 1 AND ?5";

/// One `recents` row, with the ordering key left out: `seq` places a row in
/// the list, it is not part of what the row claims.
pub(super) struct RecentRow {
    pub(super) identity: String,
    pub(super) protocol: String,
    pub(super) host: String,
    pub(super) port: i64,
    pub(super) username: String,
    pub(super) connected_at: String,
}

impl RecentRow {
    /// The connection this row describes, or `None` if it describes none this
    /// build could have recorded.
    ///
    /// The only definition of a usable row, and the only way to obtain one, so
    /// the reader and the settlement a write performs cannot disagree about
    /// which rows exist. Covers what SQL cannot express: the protocol key
    /// table, RFC 3339 syntax, a host blank once canonicalised, and a stored
    /// key that does not name the endpoint its own columns describe.
    ///
    /// The last of those is what makes a row actionable rather than merely
    /// legible. A row keyed by one endpoint and describing another would be
    /// listed under the endpoint its columns give, while forgetting or
    /// retrying it addresses the stored key, so no control could reach it.
    pub(super) fn settled(&self) -> Option<RecentConnection> {
        let protocol = Protocol::from_key_exact(&self.protocol)?;
        let port = u16::try_from(self.port).ok()?;
        let at = chrono::DateTime::parse_from_rfc3339(&self.connected_at).ok()?;
        if self.host.len() > MAX_RECENT_HOST_BYTES
            || self.username.len() > MAX_RECENT_USERNAME_BYTES
            || self.protocol.len() > MAX_RECENT_PROTOCOL_BYTES
            || self.connected_at.len() > MAX_RECENT_STAMP_BYTES
            || self.identity.len() > MAX_RECENT_IDENTITY_BYTES
        {
            return None;
        }
        let entry = RecentConnection::new(
            self.host.clone(),
            port,
            protocol,
            self.username.clone(),
            at.with_timezone(&chrono::Utc),
        );
        if entry.host.is_empty() || entry.key() != self.identity {
            return None;
        }
        Some(entry)
    }
}
