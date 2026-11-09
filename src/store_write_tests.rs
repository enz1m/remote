//! A profile-store write the database refuses never reads as a success.
//!
//! Tests drive real [`crate::Message`]s against a real SQLite file and re-open
//! it on their own connection, since `App::profiles` alone would pass for a
//! reducer that discarded the `Result`. The refusal is a schema trigger, so the
//! reducer meets a genuine `rusqlite::Error` from production `ProfileDb` methods
//! while the table stays readable. `secret_marker_tests` shares these fixtures.

use super::*;

pub(super) fn refuse_writes(db_path: &std::path::Path) {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER refuse_insert BEFORE INSERT ON profiles
             BEGIN SELECT RAISE(ABORT, 'refused'); END;
         CREATE TRIGGER refuse_update BEFORE UPDATE ON profiles
             BEGIN SELECT RAISE(ABORT, 'refused'); END;
         CREATE TRIGGER refuse_delete BEFORE DELETE ON profiles
             BEGIN SELECT RAISE(ABORT, 'refused'); END;",
    )
    .unwrap();
}

pub(super) fn allow_writes(db_path: &std::path::Path) {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    conn.execute_batch(
        "DROP TRIGGER refuse_insert;
         DROP TRIGGER refuse_update;
         DROP TRIGGER refuse_delete;",
    )
    .unwrap();
}

pub(super) fn stored_rows(db_path: &std::path::Path) -> usize {
    crate::db::ProfileDb::open(db_path)
        .unwrap()
        .count()
        .unwrap()
}

pub(super) fn stored_marker(db_path: &std::path::Path, id: uuid::Uuid) -> bool {
    crate::db::ProfileDb::open(db_path)
        .unwrap()
        .get(id)
        .unwrap()
        .expect("the row must still exist")
        .has_keyring_password
}

pub(super) fn temp_store(prefix: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.db");
    (dir, path)
}

pub(super) fn run_task(app: &mut App, task: Task<Message>) {
    use iced::futures::StreamExt;
    let Some(stream) = iced_test::runtime::task::into_stream(task) else {
        return;
    };
    let messages: Vec<Message> = iced_test::futures::futures::executor::block_on(
        stream
            .filter_map(|action| async move {
                match action {
                    iced_test::runtime::Action::Output(m) => Some(m),
                    _ => None,
                }
            })
            .collect(),
    );
    for m in messages {
        let next = app.update(m);
        if next.units() > 0 {
            run_task(app, next);
        }
    }
}

fn save_one(app: &mut App, name: &str, host: &str) -> uuid::Uuid {
    let _ = app.update(Message::FormOpenAdd);
    let _ = app.update(Message::FormNameChanged(name.into()));
    let _ = app.update(Message::FormHostChanged(host.into()));
    let _ = app.update(Message::FormSave);
    app.profiles
        .iter()
        .find(|p| p.name == name)
        .unwrap_or_else(|| panic!("the precondition save of {name:?} must land"))
        .id
}

pub(super) fn notice(app: &App) -> (String, String) {
    let n = app
        .credential_notice
        .as_ref()
        .expect("a refused write must raise the sidebar notice");
    (n.title.clone(), n.body.clone())
}

#[test]
fn a_refused_save_keeps_the_draft_and_leaves_no_phantom_row() {
    let (dir, db_path) = temp_store("remote-app-refused-save");
    let db_str = db_path.to_str().unwrap();

    let (mut app, _) = App::boot_with_production_library(db_str);
    assert!(app.profiles.is_empty(), "the launch starts with no library");
    refuse_writes(&db_path);

    let _ = app.update(Message::FormOpenAdd);
    let _ = app.update(Message::FormNameChanged("Prod Laptop".into()));
    let _ = app.update(Message::FormHostChanged("10.0.0.9".into()));
    let _ = app.update(Message::FormSave);

    assert!(
        app.profiles.is_empty(),
        "a refused write must not add a row to the list; got {:?}",
        app.profiles.iter().map(|p| &p.name).collect::<Vec<_>>()
    );
    assert_eq!(
        app.selected_profile, None,
        "a refused write must not select the row it did not create"
    );
    assert_eq!(
        stored_rows(&db_path),
        0,
        "nothing may have reached the file"
    );

    let draft = app
        .form
        .as_ref()
        .expect("a refused save must leave the dialog open on the user's draft");
    assert_eq!(draft.name, "Prod Laptop");
    assert_eq!(draft.host, "10.0.0.9");

    // Reported in database language, with no rusqlite text.
    let (title, body) = notice(&app);
    assert_eq!(
        title, "Change not saved",
        "a store refusal must not wear the keyring's title"
    );
    assert!(
        body.contains("Prod Laptop") && body.contains("was not saved"),
        "the notice must name what did not happen: {body:?}"
    );
    // The trigger's `refused` message and the statement's table name must not
    // reach the banner.
    for leak in ["INSERT", "profiles", "refused", "sqlite", "SQL"] {
        assert!(
            !body.contains(leak),
            "the notice leaked raw database text {leak:?}: {body:?}"
        );
    }

    allow_writes(&db_path);
    let _ = app.update(Message::FormSave);
    assert!(
        app.form.is_none(),
        "an accepted save closes the dialog it kept open"
    );
    assert_eq!(app.profiles.len(), 1, "the retry must add the connection");
    assert_eq!(stored_rows(&db_path), 1);
    drop(app);

    let (restarted, _) = App::boot_with_production_library(db_str);
    let names: Vec<&str> = restarted.profiles.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["Prod Laptop"],
        "exactly the accepted save survives the restart"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_refused_delete_keeps_the_row_and_restages_the_confirmation() {
    let (dir, db_path) = temp_store("remote-app-refused-delete");
    let db_str = db_path.to_str().unwrap();

    let (mut app, _) = App::boot_with_production_library(db_str);
    let id = save_one(&mut app, "Doomed", "10.0.0.4");
    assert_eq!(stored_rows(&db_path), 1);
    refuse_writes(&db_path);

    let _ = app.update(Message::RequestDeleteProfile(id));
    let task = app.update(Message::DeleteProfileConfirmEvent(
        enzui_iced_widgets::confirm_dialog::ConfirmDialogEvent::Resolved(
            enzui_iced_core::modal::DismissCause::DefaultAction,
        ),
    ));
    run_task(&mut app, task);

    assert!(
        app.profiles.iter().any(|p| p.id == id),
        "a refused delete must keep the connection it could not remove"
    );
    assert_eq!(stored_rows(&db_path), 1, "the row is still in the file");
    assert_eq!(
        app.pending_delete_profile,
        Some(id),
        "the confirmation must be re-staged so Delete is one press from a retry"
    );
    let (title, body) = notice(&app);
    assert_eq!(title, "Connection not deleted");
    assert!(
        body.contains("Doomed") && body.contains("was not removed"),
        "the notice must name what did not happen: {body:?}"
    );

    // Positive control: the restored confirmation retries and the row stays gone
    // across a restart.
    allow_writes(&db_path);
    let task = app.update(Message::DeleteProfileConfirmEvent(
        enzui_iced_widgets::confirm_dialog::ConfirmDialogEvent::Resolved(
            enzui_iced_core::modal::DismissCause::DefaultAction,
        ),
    ));
    run_task(&mut app, task);
    assert!(
        app.profiles.iter().all(|p| p.id != id),
        "the retry must remove the connection"
    );
    assert_eq!(stored_rows(&db_path), 0);
    drop(app);

    let (restarted, _) = App::boot_with_production_library(db_str);
    assert!(
        restarted.profiles.is_empty(),
        "the deleted connection must not come back"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// Keyring unlock can block indefinitely, so a newer save can finish before the older credential operation.
#[test]
fn a_superseded_credential_terminal_cannot_rewrite_a_newer_save() {
    let (dir, db_path) = temp_store("remote-app-stale-terminal");
    let db_str = db_path.to_str().unwrap();

    let (mut app, _) = App::boot_with_production_library(db_str);
    let id = save_one(&mut app, "Jump Box", "10.0.0.6");

    // The first save's keyring leg is left waiting: its task is dropped.
    let _ = app.update(Message::FormOpenEdit(id));
    let _ = app.update(Message::FormPasswordChanged("first".into()));
    let _ = app.update(Message::FormSave);
    let stale = app
        .profile_ops
        .get(&id)
        .expect("a save records its operation")
        .generation;

    let _ = app.update(Message::FormOpenEdit(id));
    let _ = app.update(Message::FormPasswordChanged("second".into()));
    let task = app.update(Message::FormSave);
    let current = app
        .profile_ops
        .get(&id)
        .expect("the newer save supersedes")
        .generation;
    assert_ne!(stale, current, "each save must get its own identity");
    run_task(&mut app, task);
    assert!(
        app.profiles
            .iter()
            .any(|p| p.id == id && p.has_keyring_password),
        "precondition: the newer save's stored secret is published"
    );
    app.credential_notice = None;

    // The first save's keyring leg answers late, and badly.
    let _ = app.update(Message::CredentialSaveResult(
        id,
        stale,
        SecretSlot::Password,
        SaveIntent::Store,
        CredResult::Unavailable,
    ));
    assert!(
        app.profiles
            .iter()
            .any(|p| p.id == id && p.has_keyring_password),
        "a superseded terminal must not withdraw the newer save's published marker"
    );
    assert!(
        app.credential_notice.is_none(),
        "a superseded terminal must not report on a save the user replaced: {:?}",
        app.credential_notice
    );
    drop(app);

    assert!(
        stored_marker(&db_path, id),
        "the newer save's published marker must be the durable one"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
