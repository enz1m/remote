//! Store boot: open, resolver, and boot failures.

use super::*;

/// Every way the boot path can refuse to open the database, kept typed so
/// the app surfaces them without collapsing into “the DB is missing”.
#[derive(Debug)]
pub enum DbBootError {
    /// Neither `$XDG_DATA_HOME` nor a usable `$HOME` is available, so the boot path
    /// writes nowhere, including a relative path under the cwd.
    NoDataHome(AppDataError),
    /// The application data directory could not be created or is occupied
    /// by a non-directory / symlink. Never silently redirected.
    CreateDataDir(AppDataError),
    /// The [`AppId`] is invalid. Static, so this can only fire if
    /// [`REMOTE_APP_ID`] is edited into an unsafe value.
    InvalidAppId(AppDataError),
    /// The crash-safe relocation plan refused. The legacy database is still
    /// complete at the source pathname; nothing has been moved.
    Migration(MigrationError),
    /// SQLite refused to open the destination file.
    Open(rusqlite::Error),
}

impl std::fmt::Display for DbBootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDataHome(e) => write!(f, "no data directory: {e}"),
            Self::CreateDataDir(e) => write!(f, "cannot create data directory: {e}"),
            Self::InvalidAppId(e) => write!(f, "invalid app id: {e}"),
            Self::Migration(e) => {
                write!(
                    f,
                    "database relocation refused: {e}. The legacy database is intact at its source path and can be recovered manually."
                )
            }
            Self::Open(e) => write!(f, "cannot open the destination database: {e}"),
        }
    }
}

impl std::error::Error for DbBootError {}

/// A compact `Copy` class for [`DbBootError`], carried on
/// [`crate::App::db_boot_error_kind`] so the shell can pick class-specific copy
/// without reparsing the message or exposing paths.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DbBootErrorKind {
    /// [`DbBootError::NoDataHome`] — neither `$XDG_DATA_HOME` nor `$HOME`
    /// is usable, so there is no correct destination path.
    NoDataHome,
    /// [`DbBootError::CreateDataDir`] — the destination directory could not
    /// be created or is occupied by a non-directory / symlink.
    CreateDataDir,
    /// [`DbBootError::InvalidAppId`] — [`REMOTE_APP_ID`] was edited into an
    /// unsafe value; static, so this can only fire from a build defect.
    InvalidAppId,
    /// [`DbBootError::Migration`] — the crash-safe relocation plan refused.
    /// The legacy database is still complete at the source pathname.
    Migration,
    /// [`DbBootError::Open`]: SQLite could not open the destination (permission,
    /// corruption, io error), an explicit path override could not be opened, or an
    /// opened database refused to read its profile table.
    Open,
}

impl DbBootError {
    /// The compact [`DbBootErrorKind`] tag for this refusal.
    pub fn kind(&self) -> DbBootErrorKind {
        match self {
            Self::NoDataHome(_) => DbBootErrorKind::NoDataHome,
            Self::CreateDataDir(_) => DbBootErrorKind::CreateDataDir,
            Self::InvalidAppId(_) => DbBootErrorKind::InvalidAppId,
            Self::Migration(_) => DbBootErrorKind::Migration,
            Self::Open(_) => DbBootErrorKind::Open,
        }
    }
}

/// The typed boot failure the reducer carries across the
/// [`crate::App::boot_with_db_result`] boundary.
///
/// Pairs the compact [`DbBootErrorKind`] with the full display string.
#[derive(Clone, Debug)]
pub struct DbBootFailure {
    /// Which class of refusal this is.
    pub kind: DbBootErrorKind,
    /// The full display of the underlying error. It may name a path, so the banner
    /// renders class-specific copy instead and keeps this for logs and tests.
    pub message: String,
}

impl DbBootFailure {
    /// Construct a failure from a caller-supplied explicit-path open error.
    /// The path passes through in the message because a user who typed the
    /// path already knows it; the banner still renders class-only copy.
    pub fn from_explicit_open(path: &str, err: rusqlite::Error) -> Self {
        Self {
            kind: DbBootErrorKind::Open,
            message: format!("cannot open {path}: {err}"),
        }
    }

    /// Construct a failure from a profile-table read that refused on a
    /// database that had already opened.
    ///
    /// Classified as [`DbBootErrorKind::Open`] because the user-visible
    /// consequence is the same one that class already describes: the stored
    /// library is unavailable and the session runs on memory.
    pub fn from_library_read(err: &rusqlite::Error) -> Self {
        Self {
            kind: DbBootErrorKind::Open,
            message: format!("cannot read the saved connections table: {err}"),
        }
    }

    /// A Quick Connect history read that refused on a database that had
    /// already opened.
    ///
    /// Uses the [`DbBootErrorKind::Open`] class like [`Self::from_library_read`] but
    /// names its own table. Raised rather than absorbed, because an unreadable history
    /// looks the same as an empty one on screen.
    pub fn from_recents_read(err: &rusqlite::Error) -> Self {
        Self {
            kind: DbBootErrorKind::Open,
            message: format!("cannot read the recent connections table: {err}"),
        }
    }
}

/// The profile store the shell runs on, together with the library it holds
/// and the typed refusal that forced an in-memory fallback.
pub struct BootedStore {
    /// The store every later write goes to.
    pub db: ProfileDb,
    /// The stored library, ordered by [`ProfileDb::load_all`]. Empty whenever
    /// [`Self::failure`] is set.
    pub profiles: Vec<ConnectionProfile>,
    /// `None` when the destination opened and its profile table was read.
    pub failure: Option<DbBootFailure>,
}

impl std::fmt::Debug for BootedStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootedStore")
            .field("profiles", &self.profiles.len())
            .field("failure", &self.failure)
            .finish()
    }
}

/// Resolve an opened-or-refused database into the store plus its library.
///
/// A refusal to open, or to read the profile table of an opened database, yields
/// an in-memory store with an empty library and the typed failure. The failing
/// file is left untouched so an unreadable library is never overwritten as an
/// empty one.
pub fn boot_store(opened: Result<ProfileDb, DbBootFailure>) -> BootedStore {
    fn fallback(failure: DbBootFailure) -> BootedStore {
        BootedStore {
            db: ProfileDb::open_in_memory().expect("an in-memory database always opens"),
            profiles: Vec::new(),
            failure: Some(failure),
        }
    }

    let db = match opened {
        Ok(db) => db,
        Err(failure) => return fallback(failure),
    };
    match db.load_all() {
        Ok(profiles) => BootedStore {
            db,
            profiles,
            failure: None,
        },
        Err(err) => fallback(DbBootFailure::from_library_read(&err)),
    }
}

impl From<DbBootError> for DbBootFailure {
    fn from(err: DbBootError) -> Self {
        Self {
            kind: err.kind(),
            message: err.to_string(),
        }
    }
}

/// Resolve the destination via `AppDataResolver::from_env` and open the
/// database, running the crash-safe migration plan first.
///
/// The legacy pathname comes from [`REMOTE_APP_LEGACY_DB_PATH_ENV`]; when unset
/// the destination is used as the source, which the plan classifies as
/// [`MigrationOutcome::AlreadyInPlace`] or [`MigrationOutcome::NothingToMigrate`].
///
/// # Errors
///
/// Any [`DbBootError`].
pub fn open_default() -> Result<ProfileDb, DbBootError> {
    let resolver = AppDataResolver::from_env();
    let legacy = std::env::var_os(REMOTE_APP_LEGACY_DB_PATH_ENV).map(PathBuf::from);
    open_with_resolver(&resolver, legacy.as_deref())
}

/// The injectable half of [`open_default`]. Tests build a resolver with
/// explicit `$XDG_DATA_HOME`/`$HOME` roots and pass an optional legacy
/// pathname; production calls [`open_default`] once at boot.
///
/// # Contract
///
/// 1. [`AppDataResolver::ensure`] creates the destination directory (or
///    surfaces the typed refusal). No file is opened before this.
/// 2. [`MigrationPlan::prepare`] classifies the two paths. Its refusals
///    (destination exists, stale sidecar, cross-device, same directory, or
///    an io error) are propagated as [`DbBootError::Migration`] before any
///    connection is opened, leaving the legacy database complete at its source.
/// 3. Only after the plan executes (or reports
///    [`MigrationOutcome::NothingToMigrate`] / [`MigrationOutcome::AlreadyInPlace`])
///    is [`ProfileDb::open`] called on the destination.
///
/// The source pathname is never opened as a fallback after a partial migration.
///
/// # Errors
///
/// Any [`DbBootError`].
pub fn open_with_resolver(
    resolver: &AppDataResolver,
    legacy: Option<&Path>,
) -> Result<ProfileDb, DbBootError> {
    let id = AppId::new(REMOTE_APP_ID).map_err(DbBootError::InvalidAppId)?;
    let data_dir = resolver.ensure_tightening(&id).map_err(|e| match e {
        AppDataError::NoDataHome { .. } => DbBootError::NoDataHome(e),
        AppDataError::Create { .. } => DbBootError::CreateDataDir(e),
        AppDataError::InvalidAppId { .. } => DbBootError::InvalidAppId(e),
    })?;
    let destination = data_dir
        .join(DB_FILE_NAME)
        .expect("the static database child path is valid");

    // Always called: a missing or identical source is a no-op, and a different
    // location is relocated, resuming an interrupted run if needed.
    let source = legacy.unwrap_or(&destination);
    let plan = MigrationPlan::prepare(source, &destination).map_err(DbBootError::Migration)?;
    let _outcome: MigrationOutcome = plan.execute().map_err(DbBootError::Migration)?;

    ProfileDb::open(&destination).map_err(DbBootError::Open)
}
