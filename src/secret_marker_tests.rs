//! A profile's stored-password marker (`has_keyring_password`, and the jump
//! host's `has_tunnel_password`/`auth` pair) is published only by the credential
//! outcome that earns it: the keyring answers first and the row records the
//! answer second. Writing the claim at save time and compensating later fails
//! exactly when the compensating row write is refused too.
//!
//! Tests drive real [`crate::Message`]s, inspect the credential store, and read
//! the marker off the SQLite row; see `store_write_tests::stored_marker` for
//! why a restarted `App` cannot answer this in-process.

use super::*;
use crate::keyring::profile_password_key;
use crate::store_write_tests::{
    allow_writes, notice, refuse_writes, run_task, stored_marker, temp_store,
};
use enzui_services::credential_store::{
    CredentialKey, CredentialOutcome, CredentialStore, MemoryCredentialStore,
};
use std::sync::Arc;

fn inject_store(app: &mut App) -> Arc<MemoryCredentialStore> {
    let store = Arc::new(MemoryCredentialStore::new());
    app.credentials = Arc::clone(&store) as Arc<dyn CredentialStore>;
    store
}

fn cred_value(store: &MemoryCredentialStore, key: CredentialKey) -> Option<String> {
    match iced_test::futures::futures::executor::block_on(store.get(key)) {
        CredentialOutcome::Retrieved(secret) => {
            Some(String::from_utf8(secret.expose_secret().to_vec()).unwrap())
        }
        _ => None,
    }
}

fn live_marker(app: &App, id: uuid::Uuid) -> bool {
    app.profiles
        .iter()
        .find(|p| p.id == id)
        .expect("the profile must still be listed")
        .has_keyring_password
}

fn begin_save_with_password(
    app: &mut App,
    name: &str,
    secret: &str,
) -> (uuid::Uuid, Task<Message>) {
    let _ = app.update(Message::FormOpenAdd);
    let _ = app.update(Message::FormNameChanged(name.into()));
    let _ = app.update(Message::FormHostChanged("10.0.0.2".into()));
    let _ = app.update(Message::FormPasswordChanged(secret.into()));
    let task = app.update(Message::FormSave);
    let id = app
        .profiles
        .iter()
        .find(|p| p.name == name)
        .unwrap_or_else(|| panic!("the save of {name:?} must list the connection"))
        .id;
    (id, task)
}

fn begin_resave_with_password(app: &mut App, id: uuid::Uuid, secret: &str) -> Task<Message> {
    let _ = app.update(Message::FormOpenEdit(id));
    let _ = app.update(Message::FormPasswordChanged(secret.into()));
    app.update(Message::FormSave)
}

#[test]
fn a_stored_secret_whose_marker_is_refused_is_disclosed_then_retryable() {
    let (dir, db_path) = temp_store("remote-app-marker-stored-refused");
    let db_str = db_path.to_str().unwrap();

    let (mut app, _) = App::boot_with_production_library(db_str);
    let store = inject_store(&mut app);
    let (id, task) = begin_save_with_password(&mut app, "Prod VNC", "s3cret");
    refuse_writes(&db_path);
    run_task(&mut app, task);

    assert_eq!(
        cred_value(&store, profile_password_key(id)).as_deref(),
        Some("s3cret"),
        "precondition: the keyring definitively took the secret"
    );
    assert!(
        !live_marker(&app, id),
        "a marker the store refused may not be claimed in the model"
    );
    assert!(
        !stored_marker(&db_path, id),
        "…nor on the row, which is what the next launch reads"
    );

    let (title, body) = notice(&app);
    assert_eq!(title, "Password stored, connection not updated");
    assert!(
        body.contains("Prod VNC") && body.contains("system keyring"),
        "the disclosure must name the connection and where the secret is: {body:?}"
    );
    assert!(
        body.contains("Save the connection again"),
        "the disclosure must name the retry route: {body:?}"
    );
    for leak in ["INSERT", "profiles", "refused", "sqlite"] {
        assert!(
            !body.contains(leak),
            "the disclosure leaked raw database text {leak:?}: {body:?}"
        );
    }

    // The keyring `set` is idempotent, so retrying is the route the banner named.
    allow_writes(&db_path);
    let task = begin_resave_with_password(&mut app, id, "s3cret");
    run_task(&mut app, task);
    assert!(
        live_marker(&app, id),
        "the retry must publish the marker it could not commit"
    );
    assert!(
        stored_marker(&db_path, id),
        "…durably, so the two stores finally agree"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
