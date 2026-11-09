use super::*;
use std::io::Read;
use std::net::TcpListener;
use std::time::Instant;

#[test]
fn cancelled_dials_close_the_socket_and_reject_stale_and_view_only_input() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut profile = ConnectionProfile::new("RDP fixture", Protocol::Rdp, "127.0.0.1");
    profile.username = "qa".into();
    profile.view_only = true;
    profile.port = listener.local_addr().unwrap().port();
    let (accepted_tx, accepted_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut header = [0; 4];
        socket.read_exact(&mut header).unwrap();
        assert_eq!(&header[..2], &[3, 0]);
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let mut request = vec![0; length - 4];
        socket.read_exact(&mut request).unwrap();
        accepted_tx.send(()).unwrap();
        match socket.read(&mut [0]) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) => {}
            other => panic!("cancelled RDP socket remained open: {other:?}"),
        }
    });
    let backend = Arc::new(RdpBackend::default());
    let dial_backend = Arc::clone(&backend);
    let dial_profile = profile.clone();
    let (done_tx, done_rx) = mpsc::channel();
    let dial = std::thread::spawn(move || {
        done_tx
            .send(dial_backend.connect(&dial_profile, None).is_err())
            .unwrap();
    });
    accepted_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    assert!(
        backend
            .send_input_for(profile.id, RemoteInput::KeyDown(0x61))
            .is_err()
    );
    assert!(
        backend
            .send_input_for(Uuid::nil(), RemoteInput::KeyDown(0x61))
            .is_err()
    );
    backend.stop();
    backend.resume();
    assert!(done_rx.recv_timeout(Duration::from_secs(3)).unwrap());
    dial.join().unwrap();
    server.join().unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !backend.closing().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(backend.closing().is_empty());
    assert!(!lock(&backend.state).stopped);
}

#[test]
fn stale_dials_cannot_cancel_replacements_and_failed_key_release_closes_input() {
    let backend = RdpBackend::default();
    let id = Uuid::new_v4();
    let (events, _stream) = SessionStream::channel();
    let current = Arc::new(Control {
        route: std::sync::Mutex::new(None),
        cancelled: AtomicBool::new(false),
        input_failed: AtomicBool::new(false),
        active: AtomicBool::new(true),
        input_capture: std::sync::Arc::new(AtomicBool::new(false)),
        clipboard: crate::native_clipboard::Clipboard::new(false),
        requested_size: std::sync::atomic::AtomicU64::new(0),
        dynamic_resize: std::sync::atomic::AtomicBool::new(false),
        resize_available: std::sync::atomic::AtomicBool::new(false),
        socket: Mutex::new(None),
        events: events.clone(),
    });
    let stale = Arc::new(Control {
        route: std::sync::Mutex::new(None),
        cancelled: AtomicBool::new(false),
        input_failed: AtomicBool::new(false),
        active: AtomicBool::new(true),
        input_capture: std::sync::Arc::new(AtomicBool::new(false)),
        clipboard: crate::native_clipboard::Clipboard::new(false),
        requested_size: std::sync::atomic::AtomicU64::new(0),
        dynamic_resize: std::sync::atomic::AtomicBool::new(false),
        resize_available: std::sync::atomic::AtomicBool::new(false),
        socket: Mutex::new(None),
        events,
    });
    let (inputs, receiver) = mpsc::sync_channel(1);
    let (stop, stopped) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let _receiver = receiver;
        stopped.recv().unwrap();
    });
    lock(&backend.state).sessions.insert(
        id,
        Session {
            control: Arc::clone(&current),
            inputs,
            worker,
            view_only: false,
        },
    );
    assert!(backend.set_dynamic_resize_for(id, true).is_err());
    current.resize_available.store(true, Ordering::SeqCst);
    backend.set_dynamic_resize_for(id, true).unwrap();
    backend.resize_for(id, (9999, 9999)).unwrap();
    assert_eq!(
        current.requested_size.load(Ordering::SeqCst),
        (3840_u64 << 32) | 2160
    );
    backend.set_dynamic_resize_for(id, false).unwrap();
    assert_eq!(current.requested_size.load(Ordering::SeqCst), 0);
    assert!(backend.resize_for(id, (800, 600)).is_err());
    lock(&backend.state)
        .sessions
        .get_mut(&id)
        .unwrap()
        .view_only = true;
    assert!(backend.set_dynamic_resize_for(id, true).is_err());
    lock(&backend.state)
        .sessions
        .get_mut(&id)
        .unwrap()
        .view_only = false;
    backend.retire_if_current(id, &stale);
    assert!(!current.cancelled.load(Ordering::SeqCst));
    assert!(
        backend
            .send_input_for(id, RemoteInput::KeyDown(0x61))
            .is_ok()
    );
    assert!(
        backend
            .send_input_for(id, RemoteInput::KeyUp(0x61))
            .is_err()
    );
    assert!(current.cancelled.load(Ordering::SeqCst));
    assert!(current.input_failed.load(Ordering::SeqCst));
    assert!(!current.active.load(Ordering::SeqCst));
    stop.send(()).unwrap();
}
