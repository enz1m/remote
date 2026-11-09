//! Frames, input and availability: the reader and writer against a generated
//! loopback RFB server (the handshake is in `transport_tests`). Every wait is
//! bounded; see [`DRAIN`].

use std::time::{Duration, Instant};

use super::server_fixture::{ScriptedServer, Step, handshake_steps};
use super::wire;
use crate::protocol::SessionStream;
use crate::state_machine::SessionEvent;

/// How long a drain waits for the events a test expects.
const DRAIN: Duration = Duration::from_secs(5);

fn drain(stream: &mut SessionStream, want: usize) -> Vec<SessionEvent> {
    let deadline = Instant::now() + DRAIN;
    let mut out = Vec::new();
    while out.len() < want && Instant::now() < deadline {
        match poll_once(stream) {
            Some(event) => out.push(event),
            // A `yield_now` loop would compete with the reader thread for the core.
            None => std::thread::sleep(Duration::from_millis(1)),
        }
    }
    out
}

/// One poll of a session stream, keeping "nothing yet" apart from "never
/// again": only [`Polled::Ended`] proves the event list complete.
enum Polled {
    Event(SessionEvent),
    /// Nothing queued, but the stream is still open.
    Pending,
    /// The queue is closed or every sender is gone.
    Ended,
}

// Nested block_on calls can deadlock this harness, so poll with now_or_never.
fn poll_stream(stream: &mut SessionStream) -> Polled {
    use iced::futures::FutureExt;
    match stream.recv().now_or_never() {
        Some(Some(event)) => Polled::Event(event),
        Some(None) => Polled::Ended,
        None => Polled::Pending,
    }
}

fn poll_once(stream: &mut SessionStream) -> Option<SessionEvent> {
    match poll_stream(stream) {
        Polled::Event(event) => Some(event),
        Polled::Pending | Polled::Ended => None,
    }
}

fn frames(events: &[SessionEvent]) -> Vec<(u32, u32, Vec<u8>)> {
    events
        .iter()
        .filter_map(|e| match e {
            SessionEvent::Frame {
                width,
                height,
                pixels,
            } => Some((*width, *height, pixels.clone().into_vec())),
            _ => None,
        })
        .collect()
}

fn drops(events: &[SessionEvent]) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| match e {
            SessionEvent::Drop(reason) => Some(reason.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn a_raw_rectangle_paints_the_servers_own_pixels_and_pulls_the_next_update() {
    let mut script = handshake_steps(4, 2);
    script.extend([
        Step::RawRect {
            x: 0,
            y: 0,
            width: 4,
            height: 2,
            colour: (0xFF, 0x00, 0x00),
        },
        Step::ExpectClientMessage { bytes: 10 },
        Step::RawRect {
            x: 0,
            y: 0,
            width: 4,
            height: 2,
            colour: (0x00, 0x80, 0xFF),
        },
        Step::ExpectClientMessage { bytes: 10 },
        Step::Checkpoint("two updates delivered"),
    ]);
    let server = ScriptedServer::start(script);
    let profile = server.profile();

    let (session, _established, _events, mut stream) =
        super::backend::open(&profile, 1).expect("connect");

    let events = drain(&mut stream, 2);
    let painted = frames(&events);
    assert_eq!(
        painted.len(),
        2,
        "both updates must reach the app; got {events:?}",
    );

    assert_eq!((painted[0].0, painted[0].1), (4, 2));
    assert_eq!(painted[0].2.len(), 4 * 2 * 4);
    assert!(
        painted[0]
            .2
            .as_chunks::<4>()
            .0
            .iter()
            .all(|px| px.as_slice() == [0xFF, 0, 0, 0xFF]),
        "pure red on the wire must be pure opaque red in the frame; got {:?}",
        &painted[0].2[..8],
    );
    assert!(
        painted[1]
            .2
            .as_chunks::<4>()
            .0
            .iter()
            .all(|px| px.as_slice() == [0x00, 0x80, 0xFF, 0xFF]),
        "the second frame must carry the second colour; got {:?}",
        &painted[1].2[..8],
    );

    assert_eq!(server.checkpoint(), Some("two updates delivered"));
    let observed = server.observed();
    // Message 0 is the handshake's full request; 1 and 2 are the loop's.
    assert!(observed.messages.len() >= 2, "got {:?}", observed.messages);
    assert_eq!(
        observed.messages[1],
        wire::framebuffer_update_request(true, 4, 2).to_vec(),
        "after an update the client must ask incrementally, not for everything again",
    );
    drop(observed);

    session.close();
}

#[test]
fn a_hostile_update_drops_the_session_and_paints_nothing() {
    struct Case {
        name: &'static str,
        step: Step,
        expect: &'static str,
    }

    for case in [
        Case {
            name: "rectangle outside the framebuffer",
            step: Step::RectOutOfBounds {
                x: 60,
                y: 60,
                width: 40,
                height: 40,
            },
            expect: "runs outside",
        },
        Case {
            name: "an encoding we never requested",
            step: Step::RectWithEncoding {
                width: 16,
                height: 16,
                encoding: 5,
            },
            expect: "encoding 5",
        },
        Case {
            name: "a colour map under true colour",
            step: Step::Raw(vec![wire::MSG_SET_COLOUR_MAP, 0, 0, 0, 0, 0]),
            expect: "message type 1",
        },
        Case {
            name: "an unknown message type",
            step: Step::Raw(vec![200]),
            expect: "message type 200",
        },
        Case {
            name: "a rectangle truncated mid-pixels",
            step: Step::TruncatedRect {
                width: 64,
                height: 64,
            },
            expect: "closed",
        },
    ] {
        let mut script = handshake_steps(64, 64);
        script.push(case.step);
        let server = ScriptedServer::start(script);
        let profile = server.profile();
        let (session, _e, _ev, mut stream) =
            super::backend::open(&profile, 1).unwrap_or_else(|e| panic!("{}: {e}", case.name));

        let events = drain(&mut stream, 1);
        let reasons = drops(&events);
        assert_eq!(
            reasons.len(),
            1,
            "{}: must drop exactly once; got {events:?}",
            case.name,
        );
        assert!(
            reasons[0].contains(case.expect),
            "{}: reason {:?} must name the refusal ({})",
            case.name,
            reasons[0],
            case.expect,
        );
        assert!(
            frames(&events).is_empty(),
            "{}: nothing may be painted from a refused update",
            case.name,
        );

        session.close();
    }
}

#[path = "frame_tests/lifecycle_tests.rs"]
mod lifecycle_tests;
