use super::*;

fn profile_with_everything() -> ConnectionProfile {
    use crate::model::{ForwardDest, ForwardKind, PortForwardRule, SshAuth, SshTunnel};
    use uuid::Uuid;

    let mut p = ConnectionProfile::new("Prod VNC", Protocol::Vnc, "10.0.0.5");
    p.port = 5901;
    p.username = "admin".into();
    p.group = "Work/Servers".into();
    p.notes = "The main box.".into();
    p.color_depth = 24;
    p.quality = 8;
    p.view_only = true;
    p.disable_clipboard = true;
    p.favorite = true;
    p.has_keyring_password = true;
    p.wol_mac = Some("aa:bb:cc:dd:ee:ff".into());
    p.ssh_tunnel = Some(SshTunnel {
        host: "bastion.corp.example".into(),
        port: 2207,
        username: "jump-admin".into(),
        auth: SshAuth::PrivateKey {
            path: "/home/admin/.ssh/prod_ed25519".into(),
        },
        // Positive control for the import-side credential clearing check.
        has_tunnel_password: true,
    });
    p.port_forward_rules = vec![
        PortForwardRule {
            id: Uuid::new_v4(),
            kind: ForwardKind::Local(ForwardDest {
                host: "postgres.internal".into(),
                port: 5432,
            }),
            bind_address: "127.0.0.2".into(),
            bind_port: 15432,
            label: "Production database".into(),
            enabled: true,
        },
        PortForwardRule {
            id: Uuid::new_v4(),
            kind: ForwardKind::Remote(ForwardDest {
                host: "metrics.internal".into(),
                port: 9090,
            }),
            bind_address: "0.0.0.0".into(),
            bind_port: 19090,
            label: "Remote metrics".into(),
            enabled: false,
        },
        PortForwardRule {
            id: Uuid::new_v4(),
            kind: ForwardKind::Dynamic,
            bind_address: "::1".into(),
            bind_port: 1081,
            label: "Browser SOCKS".into(),
            enabled: true,
        },
    ];
    p
}

#[test]
fn export_never_contains_a_password_and_related_cases() {
    {
        use crate::keyring::{profile_password_key, tunnel_password_key};
        use enzui_services::credential_store::{
            CredentialOutcome, CredentialStore, MemoryCredentialStore, Secret,
        };
        use iced_test::futures::futures::executor::block_on;

        const CONNECTION_SECRET: &str = "connection-secret-correct-horse-battery-staple";
        const TUNNEL_SECRET: &str = "tunnel-secret-purple-monkey-dishwasher";

        let p = profile_with_everything();
        let store = MemoryCredentialStore::new();
        for (key, secret) in [
            (profile_password_key(p.id), CONNECTION_SECRET),
            (tunnel_password_key(p.id), TUNNEL_SECRET),
        ] {
            assert_eq!(
                block_on(store.set(key, Secret::from_string(secret.to_string()))),
                CredentialOutcome::Stored,
                "the in-memory store cannot fail"
            );
        }

        // Positive control: the store holds both secrets, so their absence below is
        // a property of the export.
        for (key, secret) in [
            (profile_password_key(p.id), CONNECTION_SECRET),
            (tunnel_password_key(p.id), TUNNEL_SECRET),
        ] {
            match block_on(store.get(key)) {
                CredentialOutcome::Retrieved(s) => {
                    assert_eq!(s.expose_secret(), secret.as_bytes())
                }
                other => panic!("the fixture must actually store the secret, got {other:?}"),
            }
        }

        let json = export_json(std::slice::from_ref(&p));

        for secret in [CONNECTION_SECRET, TUNNEL_SECRET] {
            assert!(
                !json.contains(secret),
                "the exported document contains a plaintext password:\n{json}"
            );
            // A secret smuggled out in an encoding is still out.
            for encoded in [
                hex_of(secret),
                secret.replace('-', "%2D"),
                secret.to_ascii_uppercase(),
            ] {
                assert!(
                    !json.contains(&encoded),
                    "the export contains an encoded form of a password: {encoded}"
                );
            }
        }
        for needle in ["\"password\"", "\"secret\"", "\"credential\""] {
            assert!(
                !json.contains(needle),
                "the export declares a {needle} field; secrets belong in the \
                 keyring:\n{json}"
            );
        }
        // Credential-presence claims are machine-local, so neither flag is a v2
        // export field even though the fixture sets both.
        for needle in ["\"has_keyring_password\"", "\"has_tunnel_password\""] {
            assert!(
                !json.contains(needle),
                "the export must omit machine-local credential flag {needle}:\n{json}"
            );
        }
    }

    {
        assert_eq!(EXPORT_VERSION, 2, "the expanded export shape is version 2");
        let json = export_json(&[profile_with_everything()]);
        for needle in [
            "\"version\": 2",
            "\"name\": \"Prod VNC\"",
            "\"protocol\": \"vnc\"",
            "\"host\": \"10.0.0.5\"",
            "\"port\": 5901",
            "\"group\": \"Work/Servers\"",
            "\"quality\": 8",
            "\"color_depth\": 24",
            "\"wol_mac\": \"aa:bb:cc:dd:ee:ff\"",
            "\"ssh_tunnel\"",
            "\"host\": \"bastion.corp.example\"",
            "\"port\": 2207",
            "\"username\": \"jump-admin\"",
            "\"auth\"",
            "\"PrivateKey\"",
            "\"path\": \"/home/admin/.ssh/prod_ed25519\"",
            "\"port_forward_rules\"",
            "\"Local\"",
            "\"Remote\"",
            "\"Dynamic\"",
            "\"host\": \"postgres.internal\"",
            "\"port\": 5432",
            "\"bind_address\": \"127.0.0.2\"",
            "\"bind_port\": 15432",
            "\"label\": \"Production database\"",
            "\"host\": \"metrics.internal\"",
            "\"port\": 9090",
            "\"bind_address\": \"0.0.0.0\"",
            "\"bind_port\": 19090",
            "\"label\": \"Remote metrics\"",
            "\"enabled\": false",
            "\"bind_address\": \"::1\"",
            "\"bind_port\": 1081",
            "\"label\": \"Browser SOCKS\"",
        ] {
            assert!(json.contains(needle), "export is missing {needle}:\n{json}");
        }
        // The profile id is the keyring lookup key, so it is not exported.
        assert!(
            !json.contains("\"id\""),
            "profile and forwarding-rule ids must not be exported:\n{json}"
        );
        for needle in ["\"has_keyring_password\"", "\"has_tunnel_password\""] {
            assert!(
                !json.contains(needle),
                "credential-presence flags are machine-local and must not be exported:\n{json}"
            );
        }
    }

    {
        let original = profile_with_everything();
        let restored =
            import_json(&export_json(std::slice::from_ref(&original))).expect("valid document");
        assert_eq!(restored.len(), 1);
        let r = &restored[0];

        assert_eq!(r.name, original.name);
        assert_eq!(r.protocol, original.protocol);
        assert_eq!(r.host, original.host);
        assert_eq!(r.port, original.port);
        assert_eq!(r.username, original.username);
        assert_eq!(r.group, original.group);
        assert_eq!(r.notes, original.notes);
        assert_eq!(r.color_depth, original.color_depth);
        assert_eq!(r.quality, original.quality);
        assert_eq!(r.view_only, original.view_only);
        assert_eq!(r.disable_clipboard, original.disable_clipboard);
        assert_eq!(r.favorite, original.favorite);
        assert_eq!(r.wol_mac, original.wol_mac);

        let original_tunnel = original.ssh_tunnel.as_ref().expect("fixture tunnel");
        let restored_tunnel = r.ssh_tunnel.as_ref().expect("restored tunnel");
        assert_eq!(restored_tunnel.host, original_tunnel.host);
        assert_eq!(restored_tunnel.port, original_tunnel.port);
        assert_eq!(restored_tunnel.username, original_tunnel.username);
        assert_eq!(restored_tunnel.auth, original_tunnel.auth);

        assert_eq!(
            r.port_forward_rules.len(),
            original.port_forward_rules.len()
        );
        for (restored_rule, original_rule) in r
            .port_forward_rules
            .iter()
            .zip(&original.port_forward_rules)
        {
            assert_eq!(restored_rule.kind, original_rule.kind);
            assert_eq!(restored_rule.bind_address, original_rule.bind_address);
            assert_eq!(restored_rule.bind_port, original_rule.bind_port);
            assert_eq!(restored_rule.label, original_rule.label);
            assert_eq!(restored_rule.enabled, original_rule.enabled);
            assert_ne!(
                restored_rule.id, original_rule.id,
                "forwarding-rule identities are local to the imported profile"
            );
        }
        let restored_rule_ids: std::collections::HashSet<_> =
            r.port_forward_rules.iter().map(|rule| rule.id).collect();
        assert_eq!(
            restored_rule_ids.len(),
            r.port_forward_rules.len(),
            "every imported forwarding rule needs its own fresh identity"
        );

        // Fresh identities and no keyring claims: neither secret travelled.
        assert_ne!(r.id, original.id, "an import mints a new profile identity");
        assert!(
            original.has_keyring_password,
            "credential clearing needs a source claim"
        );
        assert!(
            original_tunnel.has_tunnel_password,
            "credential clearing needs a tunnel claim"
        );
        assert!(
            !r.has_keyring_password,
            "the connection secret is not on this machine, so the flag must not be set"
        );
        assert!(
            !restored_tunnel.has_tunnel_password,
            "the tunnel secret is not on this machine, so the flag must not be set"
        );
    }

    {
        let text = r#"{
            "version": 1,
            "profiles": [{
                "name": "Legacy SSH",
                "protocol": "ssh",
                "host": "legacy.example",
                "port": 22,
                "username": "legacy-user",
                "has_keyring_password": true
            }]
        }"#;

        let restored = import_json(text).expect("literal v1 exports remain supported");
        assert_eq!(restored.len(), 1);
        let profile = &restored[0];
        assert_eq!(profile.name, "Legacy SSH");
        assert_eq!(profile.host, "legacy.example");
        assert!(profile.ssh_tunnel.is_none());
        assert!(profile.port_forward_rules.is_empty());
        assert!(!profile.has_keyring_password);
    }
}

fn hex_of(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn a_newer_export_version_is_refused_rather_than_partially_read_and_related_cases() {
    {
        let text = format!("{{\"version\": {}, \"profiles\": []}}", EXPORT_VERSION + 1);
        let err = import_json(&text).expect_err("a newer version must be refused");
        assert_eq!(
            err,
            JsonImportError::UnsupportedVersion,
            "a newer document must classify as `UnsupportedVersion`, not \
             `InvalidDocument` — the two banners lead to different escape \
             hatches (upgrade vs. pick a different file)"
        );
        // The current version is accepted, so the refusal is about the number.
        assert!(
            import_json(&format!(
                "{{\"version\": {EXPORT_VERSION}, \"profiles\": []}}"
            ))
            .is_ok()
        );
    }

    {
        for junk in ["", "   ", "not json", "{", "[]", "{\"profiles\": 3}"] {
            let r = import_json(junk);
            assert_eq!(
                r.as_ref().err().copied(),
                Some(JsonImportError::InvalidDocument),
                "{junk:?} must classify as InvalidDocument, got {r:?}"
            );
        }
    }

    {
        // Valid JSON of the wrong shape, whose serde_json `Display` echoes the bidi
        // and control content.
        let hostile = "{\"version\": \"attacker-BEACON-\u{202e}rtl\u{0007}\", \
                       \"profiles\": []}";
        let err = import_json(hostile).expect_err("wrong type must be refused");
        assert_eq!(err, JsonImportError::InvalidDocument);
        let banner = err.banner_message();
        for needle in [
            "attacker", "BEACON", "\u{202e}", "\u{0007}", "line ", "column ",
        ] {
            assert!(
                !banner.contains(needle),
                "the banner must not carry parser payload {needle:?}: {banner:?}"
            );
        }
        // Control-free, so the alert cannot host a smuggled line break.
        assert!(
            !banner.chars().any(|c| c.is_control()),
            "banner must be control-free: {banner:?}"
        );
    }

    {
        let invalid = JsonImportError::InvalidDocument.banner_message();
        let newer = JsonImportError::UnsupportedVersion.banner_message();
        assert_ne!(
            invalid, newer,
            "the two categories must lead to different bounded copy so the \
             user can act on each"
        );
        assert!(
            !newer.chars().any(|c| c.is_ascii_digit()),
            "the newer-version banner must not carry version digits: {newer:?}"
        );
    }
}

const RDP_FIXTURE: &str = "\
screen mode id:i:2
desktopwidth:i:1920
desktopheight:i:1080
session bpp:i:24
full address:s:winbox.corp.example.com
server port:i:3390
username:s:CORP\\alice
domain:s:CORP
audiomode:i:0
redirectclipboard:i:1
";

#[test]
fn an_rdp_fixture_imports_its_host_port_user_and_depth_and_related_cases() {
    {
        let p = import_rdp(RDP_FIXTURE, "Work Desktop").expect("the fixture is valid");
        assert_eq!(p.name, "Work Desktop");
        assert_eq!(p.protocol, Protocol::Rdp);
        assert_eq!(p.host, "winbox.corp.example.com");
        assert_eq!(p.port, 3390, "an explicit `server port` must win");
        assert_eq!(p.username, "CORP\\alice");
        assert_eq!(p.domain, Some("CORP".to_string()));
        assert_eq!(p.color_depth, 24);
        assert_eq!(
            p.extra.get("screen_mode_id").map(String::as_str),
            Some("2"),
            "an unmappable setting is kept in `extra`, not dropped"
        );
        assert!(!p.has_keyring_password);
    }

    {
        let p = import_rdp("full address:s:10.1.2.3", "   ").expect("valid");
        assert_eq!(p.name, "10.1.2.3");
        assert_eq!(p.port, 3389, "no port line means the RDP default");
    }

    {
        let a = import_rdp("full address:s:box.example.com:3391", "n").expect("valid");
        assert_eq!(a.host, "box.example.com");
        assert_eq!(a.port, 3391);

        let b = import_rdp(
            "full address:s:box.example.com:3391\nserver port:i:3392",
            "n",
        )
        .expect("valid");
        assert_eq!(b.host, "box.example.com");
        assert_eq!(b.port, 3392, "the explicit key is the deliberate statement");

        let c = import_rdp("full address:s:fe80::1234:5678:9abc:def0", "n").expect("valid");
        assert_eq!(
            c.host, "fe80::1234:5678:9abc:def0",
            "an IPv6 literal must survive whole"
        );
        assert_eq!(c.port, 3389);
    }

    {
        // A hostless profile cannot be dialled, so it is a reported error.
        for hostless in [
            "",
            "   \n\n  ",
            "username:s:alice",
            "full address:s:",
            "garbage without colons",
            "one:two",
            "\u{0}\u{1}\u{2}binary noise\u{ff}",
        ] {
            let r = import_rdp(hostless, "n");
            assert_eq!(
                r.as_ref().err().copied(),
                Some(RdpImportError::MissingAddress),
                "{hostless:?} has no host and must classify as MissingAddress, \
                 got {r:?}"
            );
        }

        let banner = RdpImportError::MissingAddress.banner_message();
        assert!(
            !banner.chars().any(|c| c.is_control()),
            "RDP MissingAddress banner must be control-free: {banner:?}"
        );

        // A garbled port falls back to the protocol default; the host survives.
        let p = import_rdp("full address:s:h\nserver port:i:not-a-number", "n").expect("valid");
        assert_eq!(p.host, "h");
        assert_eq!(p.port, 3389);

        let q = import_rdp(
            "# a comment\n\n; another\nunknown key:s:whatever\nfull address:s:h2\n",
            "n",
        )
        .expect("valid");
        assert_eq!(q.host, "h2");

        // A host past the field ceiling is refused whole, not truncated, because
        // half an address dials somewhere else.
        let ceiling = crate::import_source::MAX_IMPORT_FIELD_BYTES;
        let at_ceiling = format!("full address:s:{}", "a".repeat(ceiling));
        assert_eq!(
            import_rdp(&at_ceiling, "n")
                .expect("the ceiling itself is admitted")
                .host
                .len(),
            ceiling,
        );
        let past_ceiling = format!("full address:s:{}", "a".repeat(ceiling + 1));
        assert_eq!(
            import_rdp(&past_ceiling, "n").err(),
            Some(RdpImportError::TooComplex),
            "a host past the field ceiling must be refused, not carried",
        );
    }
}

#[test]
fn an_rdp_value_may_contain_colons() {
    let p = import_rdp("full address:s:host:5555\nusername:s:a:b:c", "n").expect("valid");
    assert_eq!(p.username, "a:b:c");
    assert_eq!(p.host, "host");
    assert_eq!(p.port, 5555);
}
