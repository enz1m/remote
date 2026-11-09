//! The app's adoption of [`enzui_iced_core::db_migration`] and
//! [`enzui_iced_core::app_data::AppDataResolver`].
//!
//! Tests drive [`App::boot_with_resolver`] and [`crate::db::open_with_resolver`]
//! rather than `MigrationPlan::prepare`, so they redden when the app's call to
//! `open_with_resolver` is severed.

use std::path::{Path, PathBuf};

use enzui_iced_core::app_data::{AppDataResolver, AppId};
use rusqlite::Connection;

use crate::db::{DB_FILE_NAME, DbBootError, REMOTE_APP_ID, open_with_resolver};

fn scratch(tag: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "remote-app-1939-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&base).unwrap();
    base
}

fn private_dir(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn resolved_destination(xdg: Option<&Path>, home: Option<&Path>) -> PathBuf {
    let resolver = AppDataResolver::new(xdg.map(Path::to_path_buf), home.map(Path::to_path_buf));
    let id = AppId::new(REMOTE_APP_ID).unwrap();
    resolver.resolve(&id).unwrap().join(DB_FILE_NAME)
}

fn crashed_wal_database(main: &Path) {
    // A clean close checkpoints and may remove the WAL, so the committed file set
    // is copied while the staging connection is still open.
    let staging_dir = main.parent().unwrap().join("fixture-writer");
    std::fs::create_dir_all(&staging_dir).unwrap();
    let staging_main = staging_dir.join(DB_FILE_NAME);
    let conn = Connection::open(&staging_main).unwrap();
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;\n\
         PRAGMA wal_autocheckpoint=0;\n\
         CREATE TABLE connections(id INTEGER PRIMARY KEY, host TEXT NOT NULL);\n\
         INSERT INTO connections(host) VALUES('alpha.example');\n\
         INSERT INTO connections(host) VALUES('beta.example');",
    )
    .unwrap();

    let staging_wal = with_suffix(&staging_main, "-wal");
    assert!(
        std::fs::metadata(&staging_wal)
            .map(|metadata| metadata.len() > 0)
            .unwrap_or(false),
        "the fixture is meaningless without committed frames in a real WAL"
    );
    std::fs::copy(&staging_main, main).unwrap();
    std::fs::copy(&staging_wal, with_suffix(main, "-wal")).unwrap();
    let staging_shm = with_suffix(&staging_main, "-shm");
    if staging_shm.exists() {
        std::fs::copy(staging_shm, with_suffix(main, "-shm")).unwrap();
    }

    drop(conn);
    std::fs::remove_dir_all(staging_dir).unwrap();
    assert!(
        with_suffix(main, "-wal").exists(),
        "the fixture is meaningless without a real WAL sidecar to relocate"
    );
}

fn with_suffix(main: &Path, suffix: &str) -> PathBuf {
    let mut name = main.file_name().unwrap().to_owned();
    name.push(suffix);
    main.parent().unwrap().join(name)
}

fn read_hosts(main: &Path) -> Vec<String> {
    let conn = Connection::open(main).unwrap();
    let mut stmt = conn
        .prepare("SELECT host FROM connections ORDER BY host")
        .unwrap();
    let rows: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    rows
}

#[test]
fn boot_relocates_a_wal_backed_legacy_database_and_a_restart_reads_the_rows() {
    let root = scratch("wal-restart");
    let legacy_dir = root.join("legacy/enzui-remote");
    std::fs::create_dir_all(&legacy_dir).unwrap();
    let legacy_db = legacy_dir.join(DB_FILE_NAME);
    crashed_wal_database(&legacy_db);

    let xdg = root.join("xdg");
    std::fs::create_dir_all(&xdg).unwrap();
    let destination = resolved_destination(Some(&xdg), None);

    let db = open_with_resolver(
        &AppDataResolver::new(Some(xdg.clone()), None::<PathBuf>),
        Some(&legacy_db),
    )
    .expect("adoption must not refuse a plain legacy-elsewhere upgrade");
    // The WAL frames would sit unmoved in `legacy/` if the destination were
    // opened fresh instead of migrated.
    drop(db);

    assert!(
        !legacy_db.exists(),
        "phase C of the migration must have unlinked the source main file; \
         a live source is proof the plan was not executed"
    );
    assert!(
        !with_suffix(&legacy_db, "-wal").exists(),
        "the WAL sidecar must also be unlinked at the source; a resurrected \
         `db-wal` would corrupt the DESTINATION db the next time SQLite \
         opens it"
    );

    let rows = read_hosts(&destination);
    assert_eq!(
        rows,
        vec!["alpha.example".to_string(), "beta.example".into()]
    );
}

#[test]
fn a_stale_destination_wal_is_a_typed_refusal_and_leaves_the_legacy_intact() {
    let root = scratch("stale-wal");
    let legacy_dir = root.join("legacy");
    std::fs::create_dir_all(&legacy_dir).unwrap();
    let legacy_db = legacy_dir.join(DB_FILE_NAME);
    crashed_wal_database(&legacy_db);

    let xdg = root.join("xdg");
    let dest_dir = xdg.join(REMOTE_APP_ID);
    private_dir(&dest_dir);
    // A `-wal` that is not the migrating file's own inode would corrupt the
    // migrated main file if applied.
    std::fs::write(dest_dir.join("connections.db-wal"), b"unrelated-wal").unwrap();

    let resolver = AppDataResolver::new(Some(xdg.clone()), None::<PathBuf>);
    let err =
        open_with_resolver(&resolver, Some(&legacy_db)).expect_err("stale sidecar must refuse");
    assert!(
        matches!(err, DbBootError::Migration(_)),
        "the refusal must be typed as a migration refusal, not swallowed \
         into an `Open` failure: got {err:?}"
    );

    assert!(
        legacy_db.exists(),
        "the legacy main file must not have moved"
    );
    let rows = read_hosts(&legacy_db);
    assert!(
        rows.contains(&"alpha.example".to_string()),
        "the legacy database must remain the source of truth after a \
         refusal; the user's data is still there"
    );
}
