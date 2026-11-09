use super::*;

#[test]
fn a_launch_with_no_saved_connections_persists_nothing() {
    let dir = std::env::temp_dir().join(format!("remote-app-empty-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("test.db");
    let db_str = db_path.to_str().unwrap();

    {
        let (app, _) = App::boot_with_production_library(db_str);
        assert!(
            app.db_boot_error.is_none(),
            "a fresh path must open cleanly; got {:?}",
            app.db_boot_error
        );
        let names: Vec<&str> = app.profiles.iter().map(|p| p.name.as_str()).collect();
        assert!(
            names.is_empty(),
            "a launch must not invent connections; got {names:?}"
        );
        assert_eq!(
            app.selected_profile, None,
            "nothing can be selected out of an empty library"
        );
    }

    let stored = crate::db::ProfileDb::open(&db_path).unwrap();
    assert_eq!(
        stored.count().unwrap(),
        0,
        "the profile table must still be empty after a launch"
    );
    drop(stored);

    // Positive control: the opt-in fixture does seed, so the empty result is the
    // fixture decision and not a severed write.
    {
        let (app, _) = App::boot_with_db(Some(db_str));
        assert_eq!(
            app.profiles.len(),
            crate::model::seed_profiles().len(),
            "the opt-in fixture must still populate an empty library"
        );
    }
    let stored = crate::db::ProfileDb::open(&db_path).unwrap();
    assert_eq!(
        stored.count().unwrap(),
        crate::model::seed_profiles().len(),
        "the opt-in fixture must persist what it seeded"
    );
    drop(stored);

    let _ = std::fs::remove_dir_all(&dir);
}
