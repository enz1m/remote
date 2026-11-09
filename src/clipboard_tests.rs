use super::*;
use std::sync::Arc;

fn app_with_session() -> (App, Uuid) {
    let (app, pid, _) = crate::desktop_workflow_tests::connected();
    (app, pid)
}

fn clip(text: &str) -> Result<Arc<String>, iced::clipboard::Error> {
    Ok(Arc::new(text.to_string()))
}

#[test]
fn native_clipboard_capture_policy_and_generation_fence_guard_both_directions() {
    use crate::protocol::{ProtocolError, RemoteInput, RemoteProtocol, SessionStream};
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    };
    #[derive(Debug, Default)]
    struct Native {
        capture: Arc<AtomicBool>,
        sent: Mutex<Vec<String>>,
        inputs: Mutex<Vec<RemoteInput>>,
    }
    impl RemoteProtocol for Native {
        fn protocol(&self) -> Protocol {
            Protocol::Vnc
        }
        fn connect(
            &self,
            _: &ConnectionProfile,
            _: Option<&str>,
        ) -> Result<(Vec<SessionEvent>, Option<SessionStream>), ProtocolError> {
            unreachable!()
        }
        fn input_capture_for(&self, _: Uuid) -> Option<Arc<AtomicBool>> {
            Some(Arc::clone(&self.capture))
        }
        fn send_input(&self, input: RemoteInput) -> Result<(), ProtocolError> {
            self.inputs.lock().unwrap().push(input);
            Ok(())
        }
        fn resize_for(&self, _: Uuid, _: (u32, u32)) -> Result<(), ProtocolError> {
            Ok(())
        }
        fn share_clipboard_for(&self, _: Uuid, text: &str) -> Result<(), ProtocolError> {
            self.sent.lock().unwrap().push(text.into());
            Ok(())
        }
    }
    let (mut app, pid) = app_with_session();
    let backend = Arc::new(Native::default());
    backend.capture.store(true, Ordering::SeqCst);
    app.backends.register(backend.clone());
    let generation = app.session_streams[&pid];
    let _ = app.sync_native_clipboard(pid, generation, Some(true), clip("café\n🎈"));
    assert_eq!(*backend.sent.lock().unwrap(), vec!["café\n🎈"]);
    assert_eq!(
        *backend.inputs.lock().unwrap(),
        [
            RemoteInput::KeyDown(xkeysym::key::Control_L),
            RemoteInput::KeyDown(xkeysym::key::Shift_L),
            RemoteInput::KeyDown(xkeysym::key::V),
            RemoteInput::KeyUp(xkeysym::key::V),
            RemoteInput::KeyUp(xkeysym::key::Shift_L),
            RemoteInput::KeyUp(xkeysym::key::Control_L)
        ]
    );
    let remote =
        SessionEvent::Clipboard(crate::rfb::clipboard::Text(Arc::new("from guest".into())));
    let task = app.reduce1_session_stream_event_20(pid, generation, remote.clone());
    let mut stream = iced_test::runtime::task::into_stream(task).unwrap();
    let action =
        iced::futures::executor::block_on(iced::futures::StreamExt::next(&mut stream)).unwrap();
    assert!(
        matches!(action, iced_test::runtime::Action::Clipboard(iced_test::runtime::clipboard::Action::Write {content: iced::clipboard::Content::Text(ref text), ..}) if text=="from guest")
    );
    for gate in 0..4 {
        backend.capture.store(gate != 0, Ordering::SeqCst);
        app.sessions
            .iter_mut()
            .find(|s| s.profile_id == pid)
            .unwrap()
            .clipboard_enabled = gate != 1;
        app.sessions
            .iter_mut()
            .find(|s| s.profile_id == pid)
            .unwrap()
            .input_mode = if gate == 2 {
            crate::session::InputMode::ViewOnly
        } else {
            crate::session::InputMode::Interactive
        };
        if gate == 3 {
            app.open_session_stream(pid);
        }
        let _ = app.sync_native_clipboard(pid, generation, Some(false), clip("must not leave"));
        assert_eq!(backend.sent.lock().unwrap().len(), 1);
        let blocked = app.reduce1_session_stream_event_20(pid, generation, remote.clone());
        assert!(iced_test::runtime::task::into_stream(blocked).is_none());
    }
}
