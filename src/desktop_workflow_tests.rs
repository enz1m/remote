use super::*;
use crate::protocol::{ProtocolError, RemoteInput, RemoteProtocol, SessionStream};
use std::sync::Mutex;

#[derive(Debug, Default)]
pub(crate) struct Recording {
    received: Mutex<Vec<(Uuid, RemoteInput)>>,
    dials: std::sync::atomic::AtomicUsize,
    protocol: Option<Protocol>,
    resize_enabled: Mutex<Vec<(Uuid, bool)>>,
    sizes: Mutex<Vec<(Uuid, (u32, u32))>>,
}
impl RemoteProtocol for Recording {
    fn protocol(&self) -> Protocol {
        self.protocol.unwrap_or(Protocol::Vnc)
    }
    fn connect(
        &self,
        _: &ConnectionProfile,
        _: Option<&str>,
    ) -> Result<(Vec<SessionEvent>, Option<SessionStream>), ProtocolError> {
        self.dials
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok((vec![SessionEvent::Ready], None))
    }
    fn send_input(&self, _: RemoteInput) -> Result<(), ProtocolError> {
        Err(ProtocolError::Refused(
            "a profile identity is required".into(),
        ))
    }
    fn send_input_for(&self, profile: Uuid, input: RemoteInput) -> Result<(), ProtocolError> {
        self.received.lock().unwrap().push((profile, input));
        Ok(())
    }
    fn set_dynamic_resize_for(&self, pid: Uuid, enabled: bool) -> Result<(), ProtocolError> {
        self.resize_enabled.lock().unwrap().push((pid, enabled));
        Ok(())
    }
    fn resize_for(&self, pid: Uuid, size: (u32, u32)) -> Result<(), ProtocolError> {
        self.sizes.lock().unwrap().push((pid, size));
        Ok(())
    }
}

pub(crate) fn connected() -> (App, Uuid, Arc<Recording>) {
    let (mut app, _) = App::boot_with_production_library(":memory:");
    let profile = ConnectionProfile::new("Desktop", Protocol::Vnc, "127.0.0.1");
    let pid = profile.id;
    app.profiles.push(profile.clone());
    let recording = Arc::new(Recording::default());
    app.backends.register(recording.clone());
    app.selected_profile = Some(pid);
    let mut session = Session::new(profile);
    session.status = SessionStatus::Connected;
    app.sessions.push(session);
    app.open_session_stream(pid);
    (app, pid, recording)
}
