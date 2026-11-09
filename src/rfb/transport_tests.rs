//! The production handshake, reader and writer against a generated loopback
//! RFB server: each test binds `127.0.0.1:0`, scripts the server, and drives
//! [`super::backend::open`] for real. Every wait takes a deadline so a hang
//! fails by name.

use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use super::backend::JoinOutcome;
use super::handshake::{self, RfbFailure};
use super::policy;
use super::server_fixture::{ScriptedServer, Step, handshake_steps};
use super::wire;
use crate::state_machine::SessionEvent;

#[test]
fn required_tls_never_selects_plaintext_even_with_saved_plaintext_consent() {
    let server = ScriptedServer::start(vec![
        Step::Version,
        Step::ExpectVersion,
        Step::Security(vec![1, 2]),
        Step::ExpectSecurityChoice,
    ]);
    let mut profile = server.profile();
    profile.extra.insert(policy::TLS_KEY.into(), "true".into());
    profile
        .extra
        .insert(policy::ACK_KEY.into(), policy::ACK_VALUE.into());
    match super::backend::open(&profile, 1) {
        Err(RfbFailure::Tls(reason)) => assert!(reason.contains("downgrade")),
        _ => panic!("required TLS must refuse a plaintext-only host"),
    }
    assert_eq!(server.observed().security_choice, None);
    profile.host = "192.0.2.1".into();
    profile.extra.remove(policy::ACK_KEY);
    assert!(policy::admit(&profile, &["192.0.2.1:5900".parse().unwrap()]).is_ok());
    profile.extra.remove(policy::TLS_KEY);
    assert!(policy::admit(&profile, &["192.0.2.1:5900".parse().unwrap()]).is_err());
}

#[test]
fn a_complete_handshake_connects_and_sends_the_required_client_messages() {
    let server = ScriptedServer::start(handshake_steps(640, 400));
    let profile = server.profile();

    let (session, established, events, _stream) =
        super::backend::open(&profile, 7).expect("a scripted 3.8 server must connect");

    assert_eq!(events, vec![SessionEvent::Ready]);
    assert_eq!((established.width, established.height), (640, 400));
    assert_eq!(established.name, "fixture desktop");
    assert_eq!(established.exposure, policy::Exposure::Loopback);
    assert_eq!(session.generation(), 7);
    assert_eq!(session.geometry(), (640, 400));

    let observed = server.observed();
    assert_eq!(
        observed.client_version.as_deref(),
        Some(&wire::RFB_003_008[..]),
        "the client must answer with the same version",
    );
    assert_eq!(observed.security_choice, Some(1), "security type None");
    assert_eq!(observed.client_init, Some(1), "shared");
    assert_eq!(
        observed.set_pixel_format.as_deref(),
        Some(&wire::set_pixel_format()[..]),
        "the client imposes its own format and does not echo the server's",
    );
    assert_eq!(
        observed.set_encodings.as_deref(),
        Some(&wire::set_encodings()[..]),
    );
    assert_eq!(
        observed.messages.first().map(Vec::as_slice),
        Some(&wire::framebuffer_update_request(false, 640, 400)[..]),
        "the first request must be a full update, not an incremental one",
    );
    drop(observed);

    assert_eq!(session.close(), JoinOutcome::Joined);
}

#[test]
fn every_refusable_handshake_is_a_typed_failure_and_never_connects() {
    struct Case {
        name: &'static str,
        script: Vec<Step>,
        expect: fn(&RfbFailure) -> bool,
    }

    let cases = vec![
        Case {
            name: "wrong version",
            script: vec![Step::VersionRaw(b"RFB 003.003\n"), Step::ExpectVersion],
            expect: |f| {
                matches!(
                    f,
                    RfbFailure::Wire(wire::WireError::UnsupportedVersion { .. })
                )
            },
        },
        Case {
            name: "server refuses with a reason",
            script: vec![
                Step::Version,
                Step::ExpectVersion,
                Step::SecurityRefused("too many security failures".to_string()),
            ],
            expect: |f| {
                matches!(
                    f,
                    RfbFailure::Wire(wire::WireError::ServerRefused { reason }) if reason.contains("security failures")
                )
            },
        },
        Case {
            name: "only VNC password offered",
            script: vec![
                Step::Version,
                Step::ExpectVersion,
                Step::Security(vec![wire::SecurityType::VncAuth.number()]),
            ],
            expect: |f| {
                matches!(
                    f,
                    RfbFailure::SecurityUnsupported(wire::SecurityType::VncAuth)
                )
            },
        },
        Case {
            name: "only unrecognised security types offered",
            script: vec![
                Step::Version,
                Step::ExpectVersion,
                Step::Security(vec![18, 19]),
            ],
            expect: |f| {
                matches!(
                    f,
                    RfbFailure::Wire(wire::WireError::NoSupportedSecurity { .. })
                )
            },
        },
        Case {
            name: "security rejected",
            script: vec![
                Step::Version,
                Step::ExpectVersion,
                Step::Security(vec![1]),
                Step::ExpectSecurityChoice,
                Step::SecurityResult {
                    code: 1,
                    reason: "authentication failure".to_string(),
                },
            ],
            expect: |f| {
                matches!(
                    f,
                    RfbFailure::Wire(wire::WireError::SecurityFailed { reason }) if reason.contains("authentication")
                )
            },
        },
        Case {
            name: "unusable ServerInit dimensions",
            script: vec![
                Step::Version,
                Step::ExpectVersion,
                Step::Security(vec![1]),
                Step::ExpectSecurityChoice,
                Step::SecurityResult {
                    code: 0,
                    reason: String::new(),
                },
                Step::ExpectClientInit,
                Step::ServerInit {
                    width: 0,
                    height: 1080,
                    name: String::new(),
                },
            ],
            expect: |f| {
                matches!(
                    f,
                    RfbFailure::Wire(wire::WireError::UnusableDimensions { width: 0, .. })
                )
            },
        },
        Case {
            name: "overlong desktop name",
            script: vec![
                Step::Version,
                Step::ExpectVersion,
                Step::Security(vec![1]),
                Step::ExpectSecurityChoice,
                Step::SecurityResult {
                    code: 0,
                    reason: String::new(),
                },
                Step::ExpectClientInit,
                Step::ServerInitOverlongName {
                    claimed: 0xFFFF_FFFF,
                },
            ],
            expect: |f| {
                matches!(
                    f,
                    RfbFailure::Wire(wire::WireError::LengthTooLarge {
                        field: "desktop name",
                        ..
                    })
                )
            },
        },
        Case {
            name: "closed mid-handshake",
            script: vec![Step::Version, Step::ExpectVersion, Step::CloseAbruptly],
            expect: |f| matches!(f, RfbFailure::Io { .. }),
        },
        Case {
            name: "truncated greeting",
            script: vec![Step::VersionRaw(b"RFB 00"), Step::CloseAbruptly],
            expect: |f| {
                matches!(
                    f,
                    RfbFailure::Io { .. }
                        | RfbFailure::Wire(wire::WireError::UnsupportedVersion { .. })
                )
            },
        },
    ];

    for case in cases {
        let server = ScriptedServer::start(case.script);
        let profile = server.profile();
        let outcome = super::backend::open(&profile, 1);
        match outcome {
            Ok((session, _, _, _)) => {
                session.close();
                panic!("{}: must not connect", case.name);
            }
            Err(failure) => {
                assert!(
                    (case.expect)(&failure),
                    "{}: unexpected failure {failure:?} ({failure})",
                    case.name,
                );
                // Every refusal reaches a status line, so it must be prose with
                // no control bytes.
                let text = failure.to_string();
                assert!(
                    !text.chars().any(char::is_control),
                    "{}: {text:?}",
                    case.name
                );
                assert!(!text.is_empty(), "{}", case.name);
            }
        }
    }
}

#[test]
fn a_silent_server_expires_the_handshake_budget() {
    // `HANDSHAKE_DEADLINE` is not injectable, so the real one runs against a
    // stall-then-close server.
    let server = ScriptedServer::start(vec![Step::Stall, Step::CloseAbruptly]);
    let profile = server.profile();

    let started = Instant::now();
    let outcome = super::backend::open(&profile, 1);
    let elapsed = started.elapsed();

    assert!(outcome.is_err(), "a silent server must not connect");
    assert!(
        elapsed < handshake::HANDSHAKE_DEADLINE + Duration::from_secs(5),
        "the handshake must end on its own budget; took {elapsed:?}",
    );
    let failure = outcome.expect_err("checked above");
    assert!(
        matches!(failure, RfbFailure::Timeout | RfbFailure::Io { .. }),
        "got {failure:?}",
    );
}

#[test]
fn a_cancelled_handshake_reports_cancellation_rather_than_a_transport_error() {
    let server = ScriptedServer::start(vec![
        Step::Version,
        Step::ExpectVersion,
        Step::Stall,
        Step::CloseAbruptly,
    ]);
    let profile = server.profile();
    let destination = handshake::resolve(&profile).expect("loopback resolves and is admitted");
    let socket = std::net::TcpStream::connect_timeout(&destination.address, Duration::from_secs(5))
        .expect("the fixture is listening");

    // Checked before every read, so a pre-cancelled handshake stops at its first.
    let cancelled = AtomicBool::new(true);
    let outcome = handshake::handshake(&socket, destination, &cancelled);
    assert!(
        matches!(outcome, Err(RfbFailure::Cancelled)),
        "got {outcome:?}",
    );

    // Control: with the flag clear the same script gets past the version.
    let clear = AtomicBool::new(false);
    let server2 = ScriptedServer::start(handshake_steps(64, 64));
    let profile2 = server2.profile();
    let destination2 = handshake::resolve(&profile2).expect("loopback");
    let socket2 =
        std::net::TcpStream::connect_timeout(&destination2.address, Duration::from_secs(5))
            .expect("listening");
    assert!(
        handshake::handshake(&socket2, destination2, &clear).is_ok(),
        "the same handshake must succeed with the flag clear",
    );
}
