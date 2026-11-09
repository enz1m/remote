//! Schema admission: columns, refusals, and classification.

use super::*;

/// One column as the stored file declares it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct StoredColumn {
    name: String,
    /// The declared type, upper-cased: SQLite keeps the declaration verbatim,
    /// so `text` and `TEXT` are one contract written two ways.
    declared: String,
    not_null: bool,
    primary_key: bool,
}

/// One column this build requires, and the contract it requires of it.
struct RequiredColumn {
    name: &'static str,
    declared: &'static str,
    not_null: bool,
    primary_key: bool,
}

impl RequiredColumn {
    /// Whether `stored` satisfies this contract exactly.
    ///
    /// Exactly, not loosely: a column whose declared type or nullability
    /// differs is a table this build would read wrong, and guessing is how a
    /// foreign file gets edited.
    fn satisfied_by(&self, stored: &StoredColumn) -> bool {
        stored.declared == self.declared
            && stored.not_null == self.not_null
            && stored.primary_key == self.primary_key
    }
}

/// A shorthand for one row of a table's column contract.
const fn required(
    name: &'static str,
    declared: &'static str,
    not_null: bool,
    primary_key: bool,
) -> RequiredColumn {
    RequiredColumn {
        name,
        declared,
        not_null,
        primary_key,
    }
}

/// Every column this build's `profiles` table carries except the reconnect
/// policy, with the contract each must already satisfy.
///
/// The complete pre-reconnect schema: the migration adds a column only to a table
/// matching all of it, so a foreign table sharing one column name is refused.
/// `id` is `TEXT PRIMARY KEY`, which SQLite leaves nullable.
const REQUIRED_PROFILE_COLUMNS: &[RequiredColumn] = &[
    required("id", "TEXT", false, true),
    required("name", "TEXT", true, false),
    required("group_path", "TEXT", true, false),
    required("protocol", "TEXT", true, false),
    required("host", "TEXT", true, false),
    required("port", "INTEGER", true, false),
    required("username", "TEXT", true, false),
    required("domain", "TEXT", false, false),
    required("resolution_w", "INTEGER", false, false),
    required("resolution_h", "INTEGER", false, false),
    required("color_depth", "INTEGER", true, false),
    required("quality", "INTEGER", true, false),
    required("view_only", "INTEGER", true, false),
    required("disable_clip", "INTEGER", true, false),
    required("ssh_tunnel_json", "TEXT", false, false),
    required("tags_json", "TEXT", true, false),
    required("notes", "TEXT", true, false),
    required("extra_json", "TEXT", true, false),
    required("created", "TEXT", true, false),
    required("last_connected", "TEXT", false, false),
    required("favorite", "INTEGER", true, false),
    required("has_keyring_pw", "INTEGER", true, false),
    required("wol_mac", "TEXT", false, false),
    required("port_fwd_json", "TEXT", true, false),
];

/// The one column the reconnect policy adds, under the contract the migration
/// gives it.
const RECONNECT_COLUMN: RequiredColumn = required("reconnect_json", "TEXT", true, false);

/// Columns a file written by an older build may carry that this one no longer
/// creates.
///
/// Empty: every column ever created is still in [`REQUIRED_PROFILE_COLUMNS`]
/// (`tags_json` is unused but still written). Any other column is one this build
/// cannot account for.
const KNOWN_LEGACY_COLUMNS: &[&str] = &[];

/// How the saved-connections table names itself in a refusal.
pub(super) const PROFILES_LABEL: &str = "the saved connections table";

/// How the history table names itself in a refusal.
///
/// Says "recent connections" because that is what the surface calls it: a
/// refusal the user reads has to name the thing they would miss.
pub(super) const RECENTS_LABEL: &str = "the recent connections table";

/// Every column this build's `recents` table carries.
///
/// The complete contract, like [`REQUIRED_PROFILE_COLUMNS`]: history has no
/// migration, so a stored table either is this one or is not touched.
/// `identity` is `TEXT PRIMARY KEY`, which SQLite leaves nullable.
const REQUIRED_RECENT_COLUMNS: &[RequiredColumn] = &[
    required("identity", "TEXT", false, true),
    required("protocol", "TEXT", true, false),
    required("host", "TEXT", true, false),
    required("port", "INTEGER", true, false),
    required("username", "TEXT", true, false),
    required("connected_at", "TEXT", true, false),
    required("seq", "INTEGER", true, false),
];

/// Why a stored `profiles` table is not one this build can read or migrate.
///
/// Typed rather than a message, because the decision is taken before any DDL
/// runs and the caller must be able to tell "needs the additive column" from
/// "leave this file alone".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemaRefusal {
    /// The table has more columns than this build will read.
    TooManyColumns,
    /// The table's column names and declared types together exceed
    /// [`MAX_SCHEMA_TEXT_BYTES`].
    DeclarationsTooLarge,
    /// A column this build requires is absent.
    MissingColumn {
        /// The required column's name.
        column: &'static str,
    },
    /// A column is present under a different contract.
    ColumnContract {
        /// The column's name.
        column: String,
        /// The type the file declares for it.
        declared: String,
        /// Whether the file declares it `NOT NULL`.
        not_null: bool,
        /// Whether the file makes it part of the primary key.
        primary_key: bool,
    },
    /// The table carries a column this build cannot account for.
    UnknownColumn {
        /// The unaccounted column's name.
        column: String,
    },
    /// The additive migration committed and the re-read still says the column
    /// is missing.
    MigrationNotApplied,
}

impl std::fmt::Display for SchemaRefusal {
    /// The subject is the caller's: every sentence continues a table name so
    /// one refusal reads correctly about either table.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyColumns => {
                write!(f, "declares more than {MAX_SCHEMA_COLUMNS} columns")
            }
            Self::DeclarationsTooLarge => write!(
                f,
                "declares column names and types exceeding {MAX_SCHEMA_TEXT_BYTES} bytes"
            ),
            Self::MissingColumn { column } => write!(
                f,
                "has no {column} column, so it was not written by this application"
            ),
            Self::ColumnContract {
                column,
                declared,
                not_null,
                primary_key,
            } => write!(
                f,
                "declares {column} as {declared} (not null: {not_null}, primary key: \
                 {primary_key}), which this application cannot read"
            ),
            Self::UnknownColumn { column } => write!(
                f,
                "carries an unknown {column} column, so it was not written by this application"
            ),
            Self::MigrationNotApplied => f.write_str("did not accept the reconnect policy column"),
        }
    }
}

impl std::error::Error for SchemaRefusal {}

impl SchemaRefusal {
    /// This refusal as the error the open path already carries.
    ///
    /// `SQLITE_NOTADB`, so the boot path classifies it as a store refusal, falls back
    /// to memory and leaves the file alone. The sentence travels with it for logs.
    pub(super) fn as_sqlite_error(&self, table: &str) -> rusqlite::Error {
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_NOTADB),
            Some(format!("{table} {self}")),
        )
    }
}

/// Why a Ready settlement was not recorded against a profile.
///
/// A decision, not a failure: the statements are valid and the store is
/// healthy, and what the transaction declined is the *pairing*. The caller
/// must be able to tell this from a disk that refused, because a declined
/// pairing is never worth retrying against the same profile while a refused
/// disk is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadyRefusal {
    /// No stored row carries that id, so there is no connection time to
    /// record against anything.
    ProfileGone,
    /// The stored row no longer describes the dial that reached Ready.
    IdentityChanged,
    /// The update matched a number of rows other than one, which is not a
    /// partial success: nothing is committed on a count this build cannot
    /// account for.
    RowCount(usize),
}

impl std::fmt::Display for ReadyRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProfileGone => {
                f.write_str("the connection this session belongs to is no longer saved")
            }
            Self::IdentityChanged => f.write_str(
                "the saved connection no longer describes the endpoint that was reached",
            ),
            Self::RowCount(rows) => write!(
                f,
                "recording the connection time matched {rows} saved connections instead of one"
            ),
        }
    }
}

impl std::error::Error for ReadyRefusal {}

/// What one paired Ready settlement did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadyRecord {
    /// Both records committed, under one timestamp.
    Committed,
    /// Neither record was written, for a reason that is about the profile
    /// rather than about the store.
    Declined(ReadyRefusal),
}

/// What a stored `profiles` table is, measured against this build's schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileSchema {
    /// There is no `profiles` table: a new file, or one holding only other
    /// tables. This build's schema may be created whole.
    Absent,
    /// Exactly this build's schema, reconnect column included.
    Current,
    /// The complete pre-reconnect schema and nothing unaccounted for: the one
    /// additive column may be added.
    LegacyAdditive,
    /// Not a table this build can read. No DDL may run against it.
    Incompatible(SchemaRefusal),
}

/// What a stored `recents` table is, measured against this build's schema.
///
/// There is no additive case: the history table has never changed shape, so
/// a table that is not exactly this one was written by something else and is
/// left alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecentsSchema {
    /// There is no `recents` table. It may be created once the rest of the
    /// file has been admitted.
    Absent,
    /// Exactly this build's history table.
    Current,
    /// Not a table this build can read. No DDL may run against it.
    Incompatible(SchemaRefusal),
}

/// Decide what a stored `recents` table is, without touching the database.
pub(super) fn classify_recent_columns(stored: &[StoredColumn]) -> RecentsSchema {
    if stored.is_empty() {
        return RecentsSchema::Absent;
    }
    for required in REQUIRED_RECENT_COLUMNS {
        let Some(found) = stored.iter().find(|column| column.name == required.name) else {
            return RecentsSchema::Incompatible(SchemaRefusal::MissingColumn {
                column: required.name,
            });
        };
        if !required.satisfied_by(found) {
            return RecentsSchema::Incompatible(breach(found));
        }
    }
    for column in stored {
        let accounted = REQUIRED_RECENT_COLUMNS
            .iter()
            .any(|required| required.name == column.name);
        if !accounted {
            return RecentsSchema::Incompatible(SchemaRefusal::UnknownColumn {
                column: column.name.clone(),
            });
        }
    }
    RecentsSchema::Current
}

/// Both tables as one decision, so the open path takes it once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AdmittedSchema {
    pub(super) profiles: ProfileSchema,
    pub(super) recents: RecentsSchema,
}

/// Decide what `stored` is without touching the database.
///
/// Pure, so the contract can be exercised against a column list directly
/// rather than only through a file.
pub(super) fn classify_profile_columns(stored: &[StoredColumn]) -> ProfileSchema {
    if stored.is_empty() {
        return ProfileSchema::Absent;
    }
    for required in REQUIRED_PROFILE_COLUMNS {
        let Some(found) = stored.iter().find(|column| column.name == required.name) else {
            return ProfileSchema::Incompatible(SchemaRefusal::MissingColumn {
                column: required.name,
            });
        };
        if !required.satisfied_by(found) {
            return ProfileSchema::Incompatible(breach(found));
        }
    }
    let mut has_reconnect = false;
    for column in stored {
        if column.name == RECONNECT_COLUMN.name {
            if !RECONNECT_COLUMN.satisfied_by(column) {
                return ProfileSchema::Incompatible(breach(column));
            }
            has_reconnect = true;
            continue;
        }
        let accounted = REQUIRED_PROFILE_COLUMNS
            .iter()
            .any(|required| required.name == column.name)
            || KNOWN_LEGACY_COLUMNS.contains(&column.name.as_str());
        if !accounted {
            return ProfileSchema::Incompatible(SchemaRefusal::UnknownColumn {
                column: column.name.clone(),
            });
        }
    }
    if has_reconnect {
        ProfileSchema::Current
    } else {
        ProfileSchema::LegacyAdditive
    }
}

/// The contract breach `stored` represents, named with what the file says.
fn breach(stored: &StoredColumn) -> SchemaRefusal {
    SchemaRefusal::ColumnContract {
        column: stored.name.clone(),
        declared: stored.declared.clone(),
        not_null: stored.not_null,
        primary_key: stored.primary_key,
    }
}

/// How many bytes of text one `table_info` value holds.
///
/// Non-text reads as zero: a name or declared type SQLite does not hand back
/// as text carries no declaration to bound, and the column contract it
/// belongs to is refused on its own terms.
fn text_bytes(value: rusqlite::types::ValueRef<'_>) -> usize {
    match value {
        rusqlite::types::ValueRef::Text(bytes) | rusqlite::types::ValueRef::Blob(bytes) => {
            bytes.len()
        }
        _ => 0,
    }
}

/// One table's columns as the file declares them, or why they were refused.
///
/// Read-only, and bounded twice: at [`MAX_SCHEMA_COLUMNS`] rows and at
/// [`MAX_SCHEMA_TEXT_BYTES`] of names and declared types together, each
/// checked before the value is copied out of SQLite. Both tables are read
/// through here, so neither can be classified under a looser bound than the
/// other.
///
/// An absent table reads as no columns, which every classifier answers for
/// itself: absence is a decision about what may be created, not a refusal.
pub(super) fn stored_columns(
    conn: &Connection,
    table: &'static str,
) -> SqlResult<Result<Vec<StoredColumn>, SchemaRefusal>> {
    let mut stmt = stmt_table_info(conn, table)?;
    let mut rows = stmt.query([])?;
    let mut stored: Vec<StoredColumn> = Vec::new();
    let mut budget = MAX_SCHEMA_TEXT_BYTES;
    while let Some(row) = rows.next()? {
        if stored.len() >= MAX_SCHEMA_COLUMNS {
            return Ok(Err(SchemaRefusal::TooManyColumns));
        }
        // Measured through `get_ref`, which borrows SQLite's own buffer, so
        // an oversized declaration is refused without being copied into a
        // `String` first.
        let spend = text_bytes(row.get_ref(1)?).saturating_add(text_bytes(row.get_ref(2)?));
        let Some(remaining) = budget.checked_sub(spend) else {
            return Ok(Err(SchemaRefusal::DeclarationsTooLarge));
        };
        budget = remaining;
        stored.push(StoredColumn {
            name: row.get::<_, String>(1)?,
            // A column declared with no type at all reads as an empty
            // declaration rather than as a missing value.
            declared: row
                .get::<_, Option<String>>(2)?
                .unwrap_or_default()
                .to_ascii_uppercase(),
            not_null: row.get::<_, i64>(3)? != 0,
            primary_key: row.get::<_, i64>(5)? != 0,
        });
    }
    Ok(Ok(stored))
}

/// The `table_info` statement for one of this module's own tables.
///
/// SQLite cannot bind a PRAGMA argument, so the name is interpolated; taking
/// `&'static str` is what keeps anything user-supplied structurally out of
/// the statement text.
fn stmt_table_info<'c>(
    conn: &'c Connection,
    table: &'static str,
) -> SqlResult<rusqlite::Statement<'c>> {
    conn.prepare(&format!("PRAGMA table_info({table})"))
}
