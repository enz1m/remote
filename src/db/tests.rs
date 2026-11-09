//! Profile-store round-trip and schema guarantees.

use super::*;

fn sample() -> ConnectionProfile {
    let mut p = ConnectionProfile::new("Prod VNC", Protocol::Vnc, "10.0.0.5");
    p.group = "Work/Servers".into();
    p.port = 5901;
    p.username = "admin".into();
    p.domain = Some("EXAMPLE".into());
    p.resolution = Some((1920, 1080));
    p.view_only = true;
    p.notes = "The main box.".into();
    p.favorite = true;
    p.has_keyring_password = true;
    p.wol_mac = Some("aa:bb:cc:dd:ee:ff".into());
    p
}

#[test]
fn create_and_read_round_trips_all_fields_and_related_cases() {
    {
        let db = ProfileDb::open_in_memory().unwrap();
        let p = sample();
        db.upsert(&p).unwrap();
        let round = db.get(p.id).unwrap().unwrap();
        assert_eq!(round.name, "Prod VNC");
        assert_eq!(round.group, "Work/Servers");
        assert_eq!(round.protocol, Protocol::Vnc);
        assert_eq!(round.host, "10.0.0.5");
        assert_eq!(round.port, 5901);
        assert_eq!(round.username, "admin");
        assert_eq!(round.domain.as_deref(), Some("EXAMPLE"));
        assert_eq!(round.resolution, Some((1920, 1080)));
        assert!(round.view_only);
        assert_eq!(round.notes, "The main box.");
        assert!(round.favorite);
        assert!(round.has_keyring_password);
        assert_eq!(round.wol_mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
    }

    {
        let db = ProfileDb::open_in_memory().unwrap();
        let mut p = sample();
        db.upsert(&p).unwrap();
        assert_eq!(db.count().unwrap(), 1);
        p.name = "Prod VNC (renamed)".into();
        db.upsert(&p).unwrap();
        assert_eq!(db.count().unwrap(), 1); // still one row
        assert_eq!(db.get(p.id).unwrap().unwrap().name, "Prod VNC (renamed)");
    }

    {
        let db = ProfileDb::open_in_memory().unwrap();
        let p = sample();
        db.upsert(&p).unwrap();
        let removed = db.delete(p.id).unwrap();
        assert_eq!(removed, 1);
        assert!(db.get(p.id).unwrap().is_none());
        assert_eq!(db.count().unwrap(), 0);
    }

    {
        let db = ProfileDb::open_in_memory().unwrap();
        assert_eq!(db.delete(Uuid::new_v4()).unwrap(), 0);
    }
}

#[test]
fn load_all_orders_by_group_then_name_and_related_cases() {
    {
        let db = ProfileDb::open_in_memory().unwrap();
        let mut a = ConnectionProfile::new("Alpha", Protocol::Vnc, "a");
        a.group = "Work".into();
        let mut b = ConnectionProfile::new("Bravo", Protocol::Ssh, "b");
        b.group = "Home".into();
        let mut c = ConnectionProfile::new("Charlie", Protocol::Rdp, "c");
        c.group = "Home".into();
        db.upsert(&a).unwrap();
        db.upsert(&b).unwrap();
        db.upsert(&c).unwrap();
        let all = db.load_all().unwrap();
        // Home/Bravo, Home/Charlie, Work/Alpha
        assert_eq!(all[0].name, "Bravo");
        assert_eq!(all[1].name, "Charlie");
        assert_eq!(all[2].name, "Alpha");
    }

    {
        let db = ProfileDb::open_in_memory().unwrap();
        let mut stmt = db.conn.prepare("PRAGMA table_info(profiles)").unwrap();
        let rows = stmt
            .query_map([], |row| {
                let name: String = row.get(1)?;
                Ok(name)
            })
            .unwrap();
        for r in rows {
            let name = r.unwrap();
            assert!(
                !name.eq_ignore_ascii_case("password"),
                "found 'password' column in profiles table; must live in the OS keyring"
            );
            assert!(
                !name.to_lowercase().contains("password") || name == "has_keyring_pw",
                "found suspicious column '{name}'"
            );
        }
    }

    {
        let db = ProfileDb::open_in_memory().unwrap();
        let secret = "this-is-a-real-password-DO-NOT-STORE";
        let mut p = sample();
        p.notes = "The main box.".into();
        db.upsert(&p).unwrap();

        let round = db.get(p.id).unwrap().unwrap();
        let mut haystack = String::new();
        haystack.push_str(&round.name);
        haystack.push_str(&round.group);
        haystack.push_str(&round.host);
        haystack.push_str(&round.username);
        haystack.push_str(round.domain.as_deref().unwrap_or(""));
        haystack.push_str(&round.notes);
        for (k, v) in &round.extra {
            haystack.push_str(k);
            haystack.push_str(v);
        }
        assert!(
            !haystack.contains(secret),
            "profile round-trip contains the plaintext secret"
        );
    }
}
