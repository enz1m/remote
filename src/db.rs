//! SQLite persistence for connection profiles.
//!
//! # Contract
//!
//! - There is no password column. Passwords go to the OS keyring
//!   (`crate::keyring`); the DB carries only the `has_keyring_pw` flag so the
//!   UI can show "password saved" versus "prompt every time". The
//!   `password_column_is_not_in_the_schema` test enforces this.
//! - Nullable columns use SQL `NULL`, not empty strings, so "no domain" and
//!   "domain = ''" stay distinct through a Remmina round trip.
//! - `open()` runs the schema migration and is idempotent.
//! - `open_in_memory()` exists for tests so the CRUD suite does not touch the
//!   filesystem.
//!
//! # Boot path
//!
//! The on-disk database lives at `$XDG_DATA_HOME/enzui-remote/connections.db`,
//! resolved by [`enzui_iced_core::app_data::AppDataResolver`]. Before any
//! connection opens, `open_with_resolver` runs the crash-safe plan from
//! [`enzui_iced_core::db_migration`] once, on the closed source, surfacing
//! every typed refusal instead of falling back to another path. Usually the
//! destination is already in place ([`MigrationOutcome::AlreadyInPlace`]);
//! data at another pathname is relocated by pointing
//! [`REMOTE_APP_LEGACY_DB_PATH_ENV`] at its main file.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use enzui_iced_core::app_data::{AppDataError, AppDataResolver, AppId};
use enzui_iced_core::db_migration::{MigrationError, MigrationOutcome, MigrationPlan};
use rusqlite::{Connection, OptionalExtension, Result as SqlResult, params};
use uuid::Uuid;

use crate::model::{ConnectionProfile, PortForwardRule, Protocol, SshTunnel};
use crate::quick_connect::RecentConnection;

mod recents;
pub use recents::RECENT_READ_WINDOW;
use recents::{
    RECENT_DECODABLE_SQL, RECENT_SETTLE_WINDOW, RecentRow, bounded_recent_cap, recent_bound_params,
};

/// XDG data-directory segment for this application. A validated [`AppId`]
/// so a concatenation into a filesystem path cannot escape the base.
pub const REMOTE_APP_ID: &str = "enzui-remote";

/// Filename of the on-disk database inside the app's XDG data directory.
pub const DB_FILE_NAME: &str = "connections.db";

/// Env var: absolute pathname of a `connections.db` main file to relocate to
/// the resolved destination at boot, before the destination is opened. For
/// tests and rare cross-machine moves; an ordinary install leaves it unset.
pub const REMOTE_APP_LEGACY_DB_PATH_ENV: &str = "REMOTE_APP_LEGACY_DB_PATH";

#[path = "db/boot.rs"]
mod boot;
#[path = "db/schema.rs"]
mod schema;

pub use boot::{BootedStore, DbBootErrorKind, DbBootFailure, boot_store, open_default};
#[cfg(test)]
pub use boot::{DbBootError, open_with_resolver};
use schema::{
    AdmittedSchema, PROFILES_LABEL, RECENTS_LABEL, ReadyRefusal, SchemaRefusal,
    classify_profile_columns, classify_recent_columns, stored_columns,
};
pub use schema::{ProfileSchema, ReadyRecord, RecentsSchema};

/// The most bytes of column names and declared types together this build
/// reads for one table.
///
/// SQLite returns declared types as long as the `CREATE` statement made
/// them, so a column count alone does not bound the text. The budget is
/// checked before each value is copied, so a hostile schema costs one
/// oversized read and then a typed refusal. The widest table here uses about
/// five hundred bytes.
const MAX_SCHEMA_TEXT_BYTES: usize = 4096;
pub struct ProfileDb {
    conn: Connection,
}

impl std::fmt::Debug for ProfileDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileDb").finish()
    }
}

/// The `recents` table.
///
/// Named so the schema has one definition: `migrate` creates it and the
/// test-only repair in `ProfileDb::restore_recents` recreates the same thing,
/// rather than an approximation that could drift from what the statements
/// expect.
const RECENTS_DDL: &str = "
    -- Quick Connect history. A sibling table in the same migration
    -- rather than a second document: recents and profiles are
    -- written by the same connection under one `journal_mode=WAL`,
    -- so a recorded connection and the profile it was dialled from
    -- cannot land in two files that disagree after a crash.
    --
    -- `identity` is the whole primary key and holds exactly the
    -- normalized protocol, canonical host and effective port
    -- (`quick_connect::RecentConnection::key`). Keying on it makes
    -- deduplication a property of the schema: a second INSERT for
    -- one endpoint cannot produce a second row even if a caller
    -- forgets to check.
    --
    -- `username` sits outside the key, so connecting to one host as
    -- two accounts is one row, and is refreshed on conflict. No
    -- password, token, query string, file path or profile id is
    -- stored here.
    --
    -- `seq` orders the list rather than `connected_at`: two
    -- connections inside one clock tick tie, and a clock that steps
    -- backwards reorders history that already happened. Assigned
    -- MAX+1 per write, so newest-first is total and the cap can
    -- delete an exact tail.
    CREATE TABLE IF NOT EXISTS recents (
        identity        TEXT PRIMARY KEY,
        protocol        TEXT NOT NULL DEFAULT 'vnc',
        host            TEXT NOT NULL DEFAULT '',
        port            INTEGER NOT NULL DEFAULT 0,
        username        TEXT NOT NULL DEFAULT '',
        connected_at    TEXT NOT NULL DEFAULT '',
        seq             INTEGER NOT NULL DEFAULT 0
    );";

/// This build's `profiles` table, created whole for a file that has none.
///
/// Every column here is matched against a stored file by
/// `REQUIRED_PROFILE_COLUMNS` plus `RECONNECT_COLUMN`; the two must agree,
/// or a database this build just created would not classify as
/// [`ProfileSchema::Current`].
const PROFILES_DDL: &str = "CREATE TABLE IF NOT EXISTS profiles (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL DEFAULT '',
    group_path      TEXT NOT NULL DEFAULT '',
    protocol        TEXT NOT NULL DEFAULT 'vnc',
    host            TEXT NOT NULL DEFAULT '',
    port            INTEGER NOT NULL DEFAULT 0,
    username        TEXT NOT NULL DEFAULT '',
    domain          TEXT,
    resolution_w    INTEGER,
    resolution_h    INTEGER,
    color_depth     INTEGER NOT NULL DEFAULT 32,
    quality         INTEGER NOT NULL DEFAULT 6,
    view_only       INTEGER NOT NULL DEFAULT 0,
    disable_clip    INTEGER NOT NULL DEFAULT 0,
    ssh_tunnel_json TEXT,
    -- Tags are retired. The column survives so an existing file still opens
    -- (and its DEFAULT covers a fresh INSERT that no longer names it); no code
    -- path reads or writes it.
    tags_json       TEXT NOT NULL DEFAULT '[]',
    notes           TEXT NOT NULL DEFAULT '',
    extra_json      TEXT NOT NULL DEFAULT '{}',
    created         TEXT NOT NULL DEFAULT '',
    last_connected  TEXT,
    favorite        INTEGER NOT NULL DEFAULT 0,
    has_keyring_pw  INTEGER NOT NULL DEFAULT 0,
    wol_mac         TEXT,
    port_fwd_json   TEXT NOT NULL DEFAULT '[]',
    reconnect_json  TEXT NOT NULL DEFAULT '{}'
);";

// ---------------------------------------------------------------------------
// The stored schema contract
// ---------------------------------------------------------------------------

/// The most `PRAGMA table_info` rows this build reads for one table.
///
/// This build's widest table has 25 columns and the margin covers retired
/// ones. A table with more columns than this is not one of ours, and the
/// point of the bound is that deciding so costs a bounded read of a file the
/// user may not have written.
const MAX_SCHEMA_COLUMNS: usize = 64;

impl ProfileDb {
    /// Open (or create) the on-disk database, applying the schema migration.
    pub fn open(path: &std::path::Path) -> SqlResult<Self> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = Connection::open(path)?;
        // Connection-local, and the only setting applied before the file has
        // been read: `foreign_keys` lives on this handle and writes nothing.
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        // Read the stored contract before `journal_mode=WAL`, which persistently
        // rewrites the header and leaves `-wal`/`-shm` sidecars on a file this build
        // may be about to refuse.
        let schema = Self::admitted_schema(&conn)?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        Self::apply_schema(&conn, schema)?;
        Ok(Self { conn })
    }

    /// In-memory database, purely for tests. Applies the migration too.
    pub fn open_in_memory() -> SqlResult<Self> {
        let conn = Connection::open_in_memory()?;
        let schema = Self::admitted_schema(&conn)?;
        Self::apply_schema(&conn, schema)?;
        Ok(Self { conn })
    }

    /// Both stored tables, or the typed refusal as an error.
    ///
    /// Read-only: nothing in this call, or in the decision it returns, writes
    /// to the database. Both tables are classified before either is acted on,
    /// so a file whose history table this build cannot read is refused with
    /// its saved connections untouched as well.
    fn admitted_schema(conn: &Connection) -> SqlResult<AdmittedSchema> {
        let profiles = Self::profile_schema(conn)?;
        if let ProfileSchema::Incompatible(refusal) = &profiles {
            return Err(refusal.as_sqlite_error(PROFILES_LABEL));
        }
        let recents = Self::recents_schema(conn)?;
        if let RecentsSchema::Incompatible(refusal) = &recents {
            return Err(refusal.as_sqlite_error(RECENTS_LABEL));
        }
        Ok(AdmittedSchema { profiles, recents })
    }

    /// Bring an admitted schema up to this build's.
    ///
    /// The only DDL this module runs. Every arm here has already been
    /// admitted by [`Self::admitted_schema`], so no statement reaches a table
    /// this build cannot read.
    fn apply_schema(conn: &Connection, schema: AdmittedSchema) -> SqlResult<()> {
        match schema.profiles {
            // No `profiles` table: a new file, or one holding only other
            // tables. This build's own schema is created whole, so there is
            // nothing to migrate afterwards.
            ProfileSchema::Absent => conn.execute_batch(PROFILES_DDL)?,
            ProfileSchema::Current => {}
            ProfileSchema::LegacyAdditive => Self::add_reconnect_column(conn)?,
            ProfileSchema::Incompatible(refusal) => {
                return Err(refusal.as_sqlite_error(PROFILES_LABEL));
            }
        }
        match schema.recents {
            // Created only once the whole file has been admitted, so a
            // refused open leaves no table behind as evidence it was here.
            RecentsSchema::Absent => conn.execute_batch(RECENTS_DDL)?,
            RecentsSchema::Current => {}
            RecentsSchema::Incompatible(refusal) => {
                return Err(refusal.as_sqlite_error(RECENTS_LABEL));
            }
        }
        Ok(())
    }

    /// Add the reconnect-policy column to a table that predates it.
    ///
    /// The re-read happens inside the transaction and commits only if the
    /// contract now reads as [`ProfileSchema::Current`]; otherwise dropping the
    /// transaction rolls the `ALTER` back.
    fn add_reconnect_column(conn: &Connection) -> SqlResult<()> {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(
            "ALTER TABLE profiles ADD COLUMN reconnect_json TEXT NOT NULL DEFAULT '{}';",
        )?;
        match Self::profile_schema(&tx)? {
            ProfileSchema::Current => {}
            ProfileSchema::Incompatible(refusal) => {
                return Err(refusal.as_sqlite_error(PROFILES_LABEL));
            }
            ProfileSchema::Absent | ProfileSchema::LegacyAdditive => {
                return Err(SchemaRefusal::MigrationNotApplied.as_sqlite_error(PROFILES_LABEL));
            }
        }
        tx.commit()
    }

    /// What the stored `profiles` table is, measured against this build's
    /// schema.
    ///
    /// Column order is not part of the contract: every statement names its
    /// columns explicitly.
    pub fn profile_schema(conn: &Connection) -> SqlResult<ProfileSchema> {
        Ok(match stored_columns(conn, "profiles")? {
            Ok(stored) => classify_profile_columns(&stored),
            Err(refusal) => ProfileSchema::Incompatible(refusal),
        })
    }

    /// What the stored `recents` table is, measured against this build's
    /// schema. Read under the same bounds as [`Self::profile_schema`].
    pub fn recents_schema(conn: &Connection) -> SqlResult<RecentsSchema> {
        Ok(match stored_columns(conn, "recents")? {
            Ok(stored) => classify_recent_columns(&stored),
            Err(refusal) => RecentsSchema::Incompatible(refusal),
        })
    }

    /// Insert or update a profile. On conflict on `id`, all fields are
    /// overwritten. This is the intended CRUD create+update entry point.
    pub fn upsert(&self, p: &ConnectionProfile) -> SqlResult<()> {
        Self::upsert_on(&self.conn, p)
    }

    /// Insert or update every profile, or none of them.
    ///
    /// One transaction, so a refusal on the last row leaves the store as it
    /// was rather than durably holding the rows before it. An importer needs
    /// this: rows written one at a time turn a partly hostile document into a
    /// library the user cannot reconstruct, and retrying it lands somewhere
    /// different again.
    pub fn upsert_all(&self, profiles: &[ConnectionProfile]) -> SqlResult<()> {
        let tx = self.conn.unchecked_transaction()?;
        for p in profiles {
            Self::upsert_on(&tx, p)?;
        }
        tx.commit()
    }

    /// The statement both entry points share, against whichever connection or
    /// open transaction the caller holds.
    fn upsert_on(conn: &Connection, p: &ConnectionProfile) -> SqlResult<()> {
        let ssh_json = p
            .ssh_tunnel
            .as_ref()
            .and_then(|t| serde_json::to_string(t).ok());
        let extra_json = serde_json::to_string(&p.extra).unwrap_or_else(|_| "{}".into());
        let port_fwd_json =
            serde_json::to_string(&p.port_forward_rules).unwrap_or_else(|_| "[]".into());
        let created_str = p.created.to_rfc3339();
        let last_str = p.last_connected.map(|d| d.to_rfc3339());
        let reconnect_json =
            serde_json::to_string(&p.reconnect.normalized()).unwrap_or_else(|_| "{}".into());

        conn.execute(
            "INSERT INTO profiles (
                id, name, group_path, protocol, host, port, username, domain,
                resolution_w, resolution_h, color_depth, quality, view_only,
                disable_clip, ssh_tunnel_json, notes, extra_json,
                created, last_connected, favorite, has_keyring_pw, wol_mac, port_fwd_json,
                reconnect_json
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24
             )
             ON CONFLICT(id) DO UPDATE SET
                name=excluded.name,
                group_path=excluded.group_path,
                protocol=excluded.protocol,
                host=excluded.host,
                port=excluded.port,
                username=excluded.username,
                domain=excluded.domain,
                resolution_w=excluded.resolution_w,
                resolution_h=excluded.resolution_h,
                color_depth=excluded.color_depth,
                quality=excluded.quality,
                view_only=excluded.view_only,
                disable_clip=excluded.disable_clip,
                ssh_tunnel_json=excluded.ssh_tunnel_json,
                notes=excluded.notes,
                extra_json=excluded.extra_json,
                created=excluded.created,
                last_connected=excluded.last_connected,
                favorite=excluded.favorite,
                has_keyring_pw=excluded.has_keyring_pw,
                wol_mac=excluded.wol_mac,
                port_fwd_json=excluded.port_fwd_json,
                reconnect_json=excluded.reconnect_json",
            params![
                p.id.to_string(),
                p.name,
                p.group,
                p.protocol.key(),
                p.host,
                p.port as i64,
                p.username,
                p.domain.as_deref(),
                p.resolution.map(|(w, _)| w as i64),
                p.resolution.map(|(_, h)| h as i64),
                p.color_depth as i64,
                p.quality as i64,
                p.view_only as i64,
                p.disable_clipboard as i64,
                ssh_json,
                p.notes,
                extra_json,
                created_str,
                last_str,
                p.favorite as i64,
                p.has_keyring_password as i64,
                p.wol_mac.as_deref(),
                port_fwd_json,
                reconnect_json,
            ],
        )?;
        Ok(())
    }

    /// Record one authoritative Ready: the profile's connection time and the
    /// endpoint's history row, in one transaction.
    ///
    /// Both records or neither: a store holding only one would sort a connection
    /// it cannot show, or show one it will not sort.
    ///
    /// `stamp` is written to both, so the pair cannot drift by a second clock
    /// read. `expected` is the identity the dial was sent under; the stored row
    /// is re-read inside the transaction and must still match, so a profile
    /// edited after the Ready is not credited with somewhere else. The update
    /// must match exactly one row. Each of these failures is
    /// [`ReadyRecord::Declined`], not an error: nothing was written.
    ///
    /// `entry` is absent when the Ready did not take the admitting edge (an
    /// already-connected session answering Ready again); the profile update is
    /// then the whole transaction.
    pub fn record_ready(
        &self,
        profile_id: Uuid,
        expected: &crate::model::DialIdentity,
        stamp: chrono::DateTime<chrono::Utc>,
        entry: Option<&RecentConnection>,
        cap: usize,
    ) -> SqlResult<ReadyRecord> {
        let tx = self.conn.unchecked_transaction()?;
        let Some(stored) = Self::get_on(&tx, profile_id)? else {
            return Ok(ReadyRecord::Declined(ReadyRefusal::ProfileGone));
        };
        if stored.dial_identity() != *expected {
            return Ok(ReadyRecord::Declined(ReadyRefusal::IdentityChanged));
        }
        let updated = tx.execute(
            "UPDATE profiles SET last_connected = ?2 WHERE id = ?1",
            params![profile_id.to_string(), stamp.to_rfc3339()],
        )?;
        if updated != 1 {
            // Dropped without committing, so the update is rolled back.
            return Ok(ReadyRecord::Declined(ReadyRefusal::RowCount(updated)));
        }
        if let Some(entry) = entry {
            Self::record_recent_on(&tx, entry, cap)?;
        }
        tx.commit()?;
        Ok(ReadyRecord::Committed)
    }

    /// `Self::get` against a given handle, so a transaction can read the
    /// row it is about to update through the same statement.
    fn get_on(conn: &Connection, id: Uuid) -> SqlResult<Option<ConnectionProfile>> {
        conn.query_row(
            "SELECT id, name, group_path, protocol, host, port, username, domain,
                    resolution_w, resolution_h, color_depth, quality, view_only,
                    disable_clip, ssh_tunnel_json, notes, extra_json,
                    created, last_connected, favorite, has_keyring_pw, wol_mac, port_fwd_json,
                    reconnect_json
                 FROM profiles WHERE id = ?1",
            params![id.to_string()],
            row_to_profile,
        )
        .optional()
    }

    /// Load every profile, ordered by group then name.
    pub fn load_all(&self) -> SqlResult<Vec<ConnectionProfile>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, group_path, protocol, host, port, username, domain,
                    resolution_w, resolution_h, color_depth, quality, view_only,
                    disable_clip, ssh_tunnel_json, notes, extra_json,
                    created, last_connected, favorite, has_keyring_pw, wol_mac, port_fwd_json,
                    reconnect_json
             FROM profiles ORDER BY group_path, name",
        )?;
        let rows = stmt.query_map([], row_to_profile)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Delete one profile. Returns the number of rows removed (0 if id
    /// was not present).
    pub fn delete(&self, id: Uuid) -> SqlResult<usize> {
        self.conn.execute(
            "DELETE FROM profiles WHERE id = ?1",
            params![id.to_string()],
        )
    }

    /// The recorded recents this build can reproduce, newest first, at most
    /// `cap` of them.
    ///
    /// A row is skipped, never repaired: a repair would invent a place the user
    /// has not been. [`RecentRow::settled`] decides usability.
    ///
    /// Rejected rows ahead of a valid one are passed over, within
    /// [`RECENT_READ_WINDOW`] rows read; rows past the window are not read and
    /// the next [`ProfileDb::record_recent`] removes them.
    ///
    /// `seq DESC, identity DESC` is total, so tied or mixed-class keys cannot
    /// reorder between launches.
    pub fn load_recents(&self, cap: usize) -> SqlResult<Vec<RecentConnection>> {
        let want = bounded_recent_cap(cap) as usize;
        let mut out = Vec::new();
        if want == 0 {
            return Ok(out);
        }
        for row in Self::decodable_recent_rows(&self.conn, RECENT_READ_WINDOW)? {
            if out.len() == want {
                break;
            }
            if let Some(entry) = row.settled() {
                out.push(entry);
            }
        }
        Ok(out)
    }

    /// Record one connection as the newest recent.
    ///
    /// One transaction discards unusable rows, keeps and renumbers the newest
    /// survivors, and writes the row; the table holds at most `cap` rows before
    /// and after.
    ///
    /// A `cap` of zero admits nothing, this connection included: the write
    /// succeeds and leaves the table empty.
    ///
    /// A conflict on `identity` overwrites every non-identity fact, so a stale
    /// or non-canonical protocol, host or port on a matching row is corrected.
    ///
    /// Ordering keys are reassigned `1..=N` on every write, so they never run out
    /// of headroom. The wall clock is never an ordering authority: it ties
    /// within a tick and can move backwards.
    pub fn record_recent(&self, entry: &RecentConnection, cap: usize) -> SqlResult<()> {
        let tx = self.conn.unchecked_transaction()?;
        Self::record_recent_on(&tx, entry, cap)?;
        tx.commit()
    }

    /// [`Self::record_recent`]'s statements, inside a transaction the caller
    /// owns.
    ///
    /// Opens none of its own, so the paired settlement in
    /// [`Self::record_ready`] can hold the profile update and this history
    /// write in one transaction. Every claim in `record_recent`'s
    /// documentation is a claim about these statements.
    fn record_recent_on(tx: &Connection, entry: &RecentConnection, cap: usize) -> SqlResult<()> {
        let keep = bounded_recent_cap(cap) as usize;
        if keep == 0 {
            tx.execute("DELETE FROM recents", [])?;
            return Ok(());
        }
        let identity = entry.key();

        // Before anything is chosen. A row no reader can use is still a row
        // the cap counts, so leaving it in place lets unreachable rows evict
        // real history on every write.
        tx.execute(
            &format!("DELETE FROM recents WHERE NOT ({RECENT_DECODABLE_SQL})"),
            rusqlite::params_from_iter(recent_bound_params()),
        )?;

        let room = keep.saturating_sub(1);
        let mut survivors: Vec<String> = Vec::with_capacity(room);
        for row in Self::decodable_recent_rows(tx, RECENT_SETTLE_WINDOW)? {
            if survivors.len() == room {
                break;
            }
            if row.identity != identity && row.settled().is_some() {
                survivors.push(row.identity);
            }
        }

        let mut sql = String::from("DELETE FROM recents WHERE identity <> ?1");
        if !survivors.is_empty() {
            sql.push_str(" AND identity NOT IN (");
            for index in 0..survivors.len() {
                if index > 0 {
                    sql.push(',');
                }
                sql.push('?');
                sql.push_str(&(index + 2).to_string());
            }
            sql.push(')');
        }
        let mut binds: Vec<&str> = Vec::with_capacity(survivors.len() + 1);
        binds.push(identity.as_str());
        binds.extend(survivors.iter().map(String::as_str));
        tx.execute(&sql, rusqlite::params_from_iter(binds))?;

        // Oldest first, the inverse of the order they were chosen in, so the
        // newest survivor keeps the highest key.
        for (index, survivor) in survivors.iter().rev().enumerate() {
            tx.execute(
                "UPDATE recents SET seq = ?1 WHERE identity = ?2",
                params![i64::try_from(index + 1).unwrap_or(i64::MAX), survivor],
            )?;
        }

        tx.execute(
            "INSERT INTO recents
                 (identity, protocol, host, port, username, connected_at, seq)
             VALUES
                 (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(identity) DO UPDATE SET
                 protocol     = excluded.protocol,
                 host         = excluded.host,
                 port         = excluded.port,
                 username     = excluded.username,
                 connected_at = excluded.connected_at,
                 seq          = excluded.seq",
            params![
                identity,
                entry.protocol.key(),
                entry.host,
                entry.port as i64,
                entry.username,
                entry.connected_at.to_rfc3339(),
                i64::try_from(survivors.len()).unwrap_or(0) + 1,
            ],
        )?;
        Ok(())
    }

    /// The newest `limit` rows holding values of the declared storage class
    /// and within the byte bounds.
    ///
    /// Takes a `&Connection` so a write transaction can pass itself, and the
    /// reader and the writer therefore see one candidate set.
    fn decodable_recent_rows(conn: &Connection, limit: usize) -> SqlResult<Vec<RecentRow>> {
        let mut stmt = conn.prepare(&format!(
            "SELECT identity, protocol, host, port, username, connected_at
               FROM recents
              WHERE {RECENT_DECODABLE_SQL}
              ORDER BY seq DESC, identity DESC
              LIMIT ?6"
        ))?;
        let bounds = recent_bound_params();
        let rows = stmt.query_map(
            params![
                bounds[0],
                bounds[1],
                bounds[2],
                bounds[3],
                bounds[4],
                i64::try_from(limit.min(RECENT_READ_WINDOW)).unwrap_or(0),
            ],
            |row| {
                Ok(RecentRow {
                    identity: row.get(0)?,
                    protocol: row.get(1)?,
                    host: row.get(2)?,
                    port: row.get(3)?,
                    username: row.get(4)?,
                    connected_at: row.get(5)?,
                })
            },
        )?;
        rows.collect()
    }

    /// Forget one recorded endpoint. The count is what the caller settles on.
    pub fn delete_recent(&self, identity: &str) -> SqlResult<usize> {
        self.conn
            .execute("DELETE FROM recents WHERE identity = ?1", params![identity])
    }

    /// Forget all recorded endpoints.
    pub fn clear_recents(&self) -> SqlResult<usize> {
        self.conn.execute("DELETE FROM recents", [])
    }
}

fn row_to_profile(row: &rusqlite::Row<'_>) -> SqlResult<ConnectionProfile> {
    let id_str: String = row.get(0)?;
    let id = Uuid::parse_str(&id_str).unwrap_or_else(|_| Uuid::new_v4());
    let protocol_str: String = row.get(3)?;
    let protocol = Protocol::from_key(&protocol_str);
    let res_w: Option<i64> = row.get(8)?;
    let res_h: Option<i64> = row.get(9)?;
    let resolution = match (res_w, res_h) {
        (Some(w), Some(h)) => Some((w as u32, h as u32)),
        _ => None,
    };
    let ssh_json: Option<String> = row.get(14)?;
    let ssh_tunnel: Option<SshTunnel> = ssh_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());
    let extra_json: String = row.get(16)?;
    let extra: BTreeMap<String, String> = serde_json::from_str(&extra_json).unwrap_or_default();
    let created_str: String = row.get(17)?;
    let created = chrono::DateTime::parse_from_rfc3339(&created_str)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());
    let last_str: Option<String> = row.get(18)?;
    let last_connected = last_str
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));
    let port_fwd_json: String = row.get(22)?;
    let port_forward_rules: Vec<PortForwardRule> =
        serde_json::from_str(&port_fwd_json).unwrap_or_default();
    let reconnect_json: String = row.get(23)?;
    // An unreadable policy is the off default, never a partly-read one: a row
    // that cannot be parsed must not leave a connection reconnecting itself
    // under bounds nobody can see.
    let reconnect = serde_json::from_str::<crate::reconnect::ReconnectPolicy>(&reconnect_json)
        .unwrap_or_default()
        .normalized();

    Ok(ConnectionProfile {
        id,
        name: row.get(1)?,
        group: row.get(2)?,
        protocol,
        host: row.get(4)?,
        port: row.get::<_, i64>(5)? as u16,
        username: row.get(6)?,
        domain: row.get(7)?,
        resolution,
        color_depth: row.get::<_, i64>(10)? as u8,
        quality: row.get::<_, i64>(11)? as u8,
        view_only: row.get::<_, i64>(12)? != 0,
        disable_clipboard: row.get::<_, i64>(13)? != 0,
        ssh_tunnel,
        notes: row.get(15)?,
        extra,
        created,
        last_connected,
        favorite: row.get::<_, i64>(19)? != 0,
        has_keyring_password: row.get::<_, i64>(20)? != 0,
        wol_mac: row.get(21)?,
        port_forward_rules,
        reconnect,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;

#[cfg(test)]
impl ProfileDb {
    pub fn get(&self, id: Uuid) -> SqlResult<Option<ConnectionProfile>> {
        Self::get_on(&self.conn, id)
    }

    pub fn count(&self) -> SqlResult<usize> {
        self.conn
            .query_row("SELECT COUNT(*) FROM profiles", [], |row| {
                row.get::<_, usize>(0)
            })
    }
}
