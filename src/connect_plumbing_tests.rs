use super::*;
use std::sync::{Arc, Mutex};

use crate::protocol::{ProtocolError, RemoteInput, RemoteProtocol};
use crate::state_machine::SessionEvent;
use enzui_services::credential_store::CredentialStore;

/// A backend that records the password the reducer fetched and passed in.
#[derive(Debug)]
struct RecordingBackend {
    recorded_password: Mutex<Option<String>>,
}

impl RecordingBackend {
    fn new() -> Self {
        Self {
            recorded_password: Mutex::new(None),
        }
    }
}

impl RemoteProtocol for RecordingBackend {
    fn protocol(&self) -> Protocol {
        Protocol::Vnc
    }

    fn connect(
        &self,
        _profile: &ConnectionProfile,
        password: Option<&str>,
    ) -> Result<(Vec<SessionEvent>, Option<crate::protocol::SessionStream>), ProtocolError> {
        *self.recorded_password.lock().unwrap() = password.map(str::to_owned);
        Ok((
            vec![SessionEvent::Fail("recording-only backend".into())],
            None,
        ))
    }

    fn send_input(&self, _input: RemoteInput) -> Result<(), ProtocolError> {
        Err(ProtocolError::NotSupported(self.protocol()))
    }

    fn resize_for(&self, _profile_id: uuid::Uuid, _size: (u32, u32)) -> Result<(), ProtocolError> {
        Err(ProtocolError::NotSupported(self.protocol()))
    }
}

#[test]
fn the_connect_path_does_not_block_on_the_credential_fetch() {
    use enzui_services::credential_store::{Gate, MemoryCredentialStore};
    let recording = Arc::new(RecordingBackend::new());
    let (mut app, _) = App::boot_with_db(Some(":memory:"));

    let gate = Gate::new_closed();
    app.credentials =
        Arc::new(MemoryCredentialStore::with_gate(Arc::clone(&gate))) as Arc<dyn CredentialStore>;

    let pid = app
        .profiles
        .iter()
        .find(|p| p.protocol == Protocol::Vnc)
        .expect("a VNC profile")
        .id;
    app.backends
        .register(Arc::clone(&recording) as Arc<dyn RemoteProtocol>);

    let _task = app.update(Message::SessionAction(pid));

    assert_eq!(
        app.session_status_for(pid),
        SessionStatus::Connecting,
        "the reducer must apply Connect immediately and return, leaving a \
         visible pending state"
    );
    assert!(
        recording.recorded_password.lock().unwrap().is_none(),
        "the backend must NOT run until the credential fetch resolves"
    );
    assert!(
        app.pending_connects.contains_key(&pid),
        "a pending connect must register its cancel handle so the user can \
         abort a slow unlock prompt"
    );
}

#[test]
fn retry_after_editing_a_failed_certificate_pin_reaches_connected() {
    use crate::rfb::policy::FINGERPRINT_KEY;

    let (mut app, _) = App::boot_with_db(Some(":memory:"));
    app.backends.register(Arc::new(RecordingBackend::new()));
    let mut profile = ConnectionProfile::new("Pinned VNC", Protocol::Vnc, "127.0.0.1");
    profile
        .extra
        .insert(FINGERPRINT_KEY.to_owned(), "00".repeat(32));
    let pid = profile.id;
    app.profiles.push(profile);

    let stream = Arc::new(Mutex::new(None));
    let _ = app.update(Message::SessionAction(pid));
    let refused = app.pending_connects[&pid].0;
    let _ = app.update(Message::PasswordFetched(pid, refused, CredResult::NotFound));
    let _ = app.update(Message::ConnectResult(
        pid,
        refused,
        Err(ProtocolError::Refused(
            "Certificate fingerprint mismatch".into(),
        )),
        Arc::clone(&stream),
    ));
    assert_eq!(app.session_status_for(pid), SessionStatus::Error);

    let _ = app.update(Message::FormOpenEdit(pid));
    let corrected_pin = "12".repeat(32);
    let _ = app.update(Message::FormVncFingerprintChanged(corrected_pin.clone()));
    let _ = app.update(Message::FormSave);
    let _ = app.update(Message::SessionAction(pid));
    assert_eq!(app.session_status_for(pid), SessionStatus::Connecting);
    let session = app.sessions.iter().find(|s| s.profile_id == pid).unwrap();
    assert_eq!(
        session.profile_snapshot.extra[FINGERPRINT_KEY],
        corrected_pin
    );

    let retry = app.pending_connects[&pid].0;
    let _ = app.update(Message::PasswordFetched(pid, retry, CredResult::NotFound));
    let _ = app.update(Message::ConnectResult(
        pid,
        retry,
        Ok(vec![SessionEvent::Ready]),
        stream,
    ));
    assert_eq!(app.session_status_for(pid), SessionStatus::Connected);
}
