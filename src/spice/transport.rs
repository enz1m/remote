use std::cell::{Cell, RefCell};
use std::net::IpAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender};
use std::time::{Duration, Instant};

use spice_client_glib::glib::{self, prelude::*};
use spice_client_glib::{
    ChannelEvent, DisplayChannel, InputsChannel, Session, SessionVerify, SurfaceFormat, prelude::*,
};

use super::Control;
use crate::model::ConnectionProfile;
use crate::protocol::{PointerButton, ProtocolError, RemoteInput};
use crate::state_machine::SessionEvent;

const AGENT_CAP_MONITORS_CONFIG: u32 = 1;

#[derive(Default)]
struct Surface {
    display: Option<DisplayChannel>,
    main: Option<spice_client_glib::MainChannel>,
    inputs: Option<InputsChannel>,
    dirty: bool,
    pending: Option<Arc<AtomicBool>>,
    last: Option<Instant>,
    position: (i32, i32),
    buttons: i32,
    size: (i32, i32),
    keyboard: crate::desktop_scancode::KeyboardState,
}

pub(super) fn run(
    profile: &ConnectionProfile,
    password: &str,
    control: &Arc<Control>,
    inputs: Receiver<Vec<RemoteInput>>,
    ready: SyncSender<Result<(), ProtocolError>>,
) {
    let context = glib::MainContext::default();
    let result =
        context.with_thread_default(|| drive(profile, password, control, inputs, &ready, &context));
    if result.is_err() {
        let _ = ready.send(Err(ProtocolError::Refused(
            "The SPICE event context is already owned.".into(),
        )));
    }
}

fn drive(
    profile: &ConnectionProfile,
    password: &str,
    control: &Arc<Control>,
    inputs: Receiver<Vec<RemoteInput>>,
    ready: &SyncSender<Result<(), ProtocolError>>,
    context: &glib::MainContext,
) {
    let session = Session::new();
    session.set_host(Some(&profile.host));
    if let Some(route) = control.route() {
        match route.spice_proxy(
            &profile.host,
            crate::quick_connect::effective_port(profile.port, profile.protocol),
        ) {
            Ok(proxy) => session.set_proxy(Some(&proxy)),
            Err(error) => {
                let _ = ready.send(Err(error));
                return;
            }
        }
    }
    let port = crate::quick_connect::effective_port(profile.port, profile.protocol).to_string();
    let loopback = profile
        .host
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.is_loopback());
    if loopback {
        session.set_port(Some(&port));
    } else {
        session.set_tls_port(Some(&port));
        session.set_secure_channels(&["all"]);
        session.set_verify(SessionVerify::HOSTNAME);
        let ca = std::env::var("SSL_CERT_FILE")
            .unwrap_or_else(|_| "/etc/ssl/certs/ca-certificates.crt".into());
        session.set_ca_file(Some(&ca));
    }
    session.set_password(Some(password));
    session.set_read_only(profile.view_only);
    let audio_enabled = crate::stream_audio::enabled(profile);
    session.set_enable_audio(audio_enabled);
    // Upstream owns audio channels and backend lifetime; do not attach a second player.
    let _audio = if audio_enabled {
        let Some(audio) = spice_client_glib::Audio::get(&session, Some(context)) else {
            let _ = ready.send(Err(ProtocolError::Refused(
                "The SPICE audio backend is unavailable.".into(),
            )));
            return;
        };
        Some(audio)
    } else {
        None
    };
    session.set_enable_usbredir(false);
    session.set_enable_smartcard(false);
    session.set_gl_scanout(false);
    session.set_shared_dir(None);
    session.set_cache_size(16 * 1024 * 1024);
    session.set_glz_window_size(4 * 1024 * 1024);
    let surface = Rc::new(RefCell::new(Surface::default()));
    let failure = Rc::new(RefCell::new(None));
    let disconnected = Rc::new(Cell::new(false));
    let gone = Rc::clone(&disconnected);
    session.connect_disconnected(move |_| gone.set(true));
    let target = Rc::clone(&surface);
    let failed = Rc::clone(&failure);
    let clipboard_control = Arc::clone(control);
    session.connect_channel_new(move |_, channel| {
        if failed.borrow().is_some() {
            return;
        }
        let kind = channel.channel_type();
        // Audio channels are managed by upstream SpiceAudio; other device channels stay unused.
        if ![1, 2, 3].contains(&kind) && !(audio_enabled && kind == 5) {
            return;
        }
        let channel_failed = Rc::clone(&failed);
        channel.connect_channel_event(move |_, event| {
            let error = match event {
                ChannelEvent::ErrorAuth => Some(ProtocolError::Auth(
                    "SPICE authentication was refused.".into(),
                )),
                ChannelEvent::ErrorTls => Some(ProtocolError::Refused(
                    "SPICE TLS verification failed; no certificate bypass is available.".into(),
                )),
                ChannelEvent::ErrorConnect
                | ChannelEvent::ErrorIo
                | ChannelEvent::ErrorLink
                | ChannelEvent::Closed => {
                    Some(ProtocolError::Transport("The SPICE channel closed.".into()))
                }
                ChannelEvent::Switching => Some(ProtocolError::Refused(
                    "SPICE server migration is not supported.".into(),
                )),
                _ => None,
            };
            if let Some(error) = error {
                channel_failed.borrow_mut().get_or_insert(error);
            }
        });
        if let Ok(main) = channel.clone().downcast::<spice_client_glib::MainChannel>() {
            super::clipboard::attach(&main, &clipboard_control);
            target.borrow_mut().main = Some(main);
        } else if let Ok(display) = channel.clone().downcast::<DisplayChannel>() {
            if target.borrow().display.is_some() {
                return;
            }
            target.borrow_mut().display = Some(display.clone());
            let dirty = Rc::downgrade(&target);
            display.connect_display_primary_create(move |_| {
                if let Some(dirty) = dirty.upgrade() {
                    dirty.borrow_mut().dirty = true;
                }
            });
            let dirty = Rc::downgrade(&target);
            display.connect_display_invalidate(move |_, _, _, _, _| {
                if let Some(dirty) = dirty.upgrade() {
                    dirty.borrow_mut().dirty = true;
                }
            });
        } else if let Ok(input) = channel.clone().downcast::<InputsChannel>() {
            target.borrow_mut().inputs = Some(input);
        }
        if kind != 5 {
            ChannelExt::connect(channel);
        }
    });
    let started = session.connect();
    let deadline = Instant::now() + Duration::from_secs(25);
    let mut admitted = false;
    let mut last_resize = 0;
    let mut clipboard_offered = false;
    let mut resize_at = Instant::now();
    if !started {
        *failure.borrow_mut() = Some(ProtocolError::Transport(
            "SPICE could not start its connection.".into(),
        ));
    }
    while !control.cancelled.load(Ordering::SeqCst)
        && !disconnected.get()
        && failure.borrow().is_none()
    {
        for _ in 0..64 {
            if !context.pending() {
                break;
            }
            context.iteration(false);
        }
        let mut surface = surface.borrow_mut();
        control.clipboard.set_available(
            surface
                .main
                .as_ref()
                .is_some_and(|main| main.is_agent_connected()),
        );
        if let Some(main) = surface
            .main
            .as_ref()
            .filter(|main| main.is_agent_connected())
        {
            super::clipboard::poll(main, control, &mut clipboard_offered);
        }
        control.resize_available.store(
            surface.main.as_ref().is_some_and(|main| {
                main.is_agent_connected() && main.agent_test_capability(AGENT_CAP_MONITORS_CONFIG)
            }),
            Ordering::SeqCst,
        );
        let requested = control.requested_size.load(Ordering::SeqCst);
        if control.dynamic_resize.load(Ordering::SeqCst)
            && control.resize_available.load(Ordering::SeqCst)
            && requested != 0
            && requested != last_resize
            && resize_at.elapsed() >= Duration::from_millis(150)
            && let Some(main) = surface
                .main
                .as_ref()
                .filter(|main| main.is_agent_connected())
        {
            main.update_display_enabled(0, true, false);
            main.update_display(
                0,
                0,
                0,
                (requested >> 32) as i32,
                requested as u32 as i32,
                true,
            );
            if main.send_monitor_config() {
                last_resize = requested;
            }
            resize_at = Instant::now();
        }

        match publish(&mut surface, control) {
            Ok(true) if !admitted => {
                admitted = true;
                control.active.store(true, Ordering::SeqCst);
                if ready.send(Ok(())).is_err() {
                    break;
                }
            }
            Err(error) => {
                *failure.borrow_mut() = Some(error);
                break;
            }
            _ => {}
        }
        if !admitted && Instant::now() >= deadline {
            *failure.borrow_mut() = Some(ProtocolError::Refused(
                "SPICE did not deliver a desktop before the connection deadline.".into(),
            ));
            break;
        }
        for _ in 0..8 {
            let Ok(batch) = inputs.try_recv() else {
                break;
            };
            if profile.view_only || apply_inputs(&mut surface, &batch).is_err() {
                control.fail_input();
                break;
            }
        }
        drop(surface);
        std::thread::sleep(Duration::from_millis(4));
    }
    control.active.store(false, Ordering::SeqCst);
    let error = failure
        .borrow_mut()
        .take()
        .unwrap_or_else(|| ProtocolError::Refused("The SPICE connection was closed.".into()));
    if !admitted {
        let _ = ready.send(Err(error));
    } else if !control.cancelled.load(Ordering::SeqCst) {
        let _ = control.events.send(SessionEvent::Drop(error.to_string()));
    }
    session.disconnect();
    // Close debt remains owned until the native channels have released their sockets.
    while !session.channels().is_empty() {
        for _ in 0..64 {
            if !context.pending() {
                break;
            }
            context.iteration(false);
        }
        std::thread::sleep(Duration::from_millis(4));
    }
    session.set_password(None);
}

fn geometry(width: usize, height: usize, stride: usize) -> Result<usize, ProtocolError> {
    let size = width.checked_mul(height).and_then(|p| p.checked_mul(4));
    if width == 0
        || height == 0
        || width > 3840
        || height > 2160
        || stride < width.saturating_mul(4)
        || stride > 3840 * 16
        || stride.checked_mul(height).is_none()
        || size.is_none_or(|n| n > crate::protocol::MAX_QUEUED_BYTES)
    {
        return Err(ProtocolError::Refused(
            "The SPICE desktop exceeds the supported frame limits.".into(),
        ));
    }
    Ok(size.expect("bounded frame size"))
}

fn publish(surface: &mut Surface, control: &Control) -> Result<bool, ProtocolError> {
    if !surface.dirty
        || surface
            .pending
            .as_ref()
            .is_some_and(|p| !p.load(Ordering::Acquire))
        || surface
            .last
            .is_some_and(|t| t.elapsed() < Duration::from_millis(34))
    {
        return Ok(false);
    }
    let Some(display) = surface.display.as_ref() else {
        return Ok(false);
    };
    let Some(primary) = display.primary(0) else {
        return Ok(false);
    };
    let (width, height, stride) = (primary.width(), primary.height(), primary.stride());
    let size = geometry(width, height, stride)?;
    if !matches!(
        primary.format(),
        Ok(SurfaceFormat::_32XRGB | SurfaceFormat::_32ARGB)
    ) {
        return Err(ProtocolError::Refused(
            "This SPICE surface pixel format is not supported.".into(),
        ));
    }
    // The native primary buffer is borrowed only while its GLib context is not dispatched.
    let bytes = primary.data();
    let mut rgba = Vec::with_capacity(size);
    for row in 0..height {
        for pixel in bytes[row * stride..row * stride + width * 4]
            .as_chunks::<4>()
            .0
        {
            rgba.extend_from_slice(&[pixel[2], pixel[1], pixel[0], 255]);
        }
    }
    let consumed = Arc::new(AtomicBool::new(false));
    control
        .events
        .send(SessionEvent::Frame {
            width: width as u32,
            height: height as u32,
            pixels: crate::framebuffer::FrameBytes::tracked(rgba, Arc::clone(&consumed)),
        })
        .map_err(|_| ProtocolError::Refused("The SPICE surface was retired.".into()))?;
    surface.pending = Some(consumed);
    surface.last = Some(Instant::now());
    surface.size = (width as i32, height as i32);
    surface.dirty = false;
    Ok(true)
}

fn apply_inputs(surface: &mut Surface, batch: &[RemoteInput]) -> Result<(), ()> {
    if batch.iter().any(|event| matches!(event, RemoteInput::KeyDown(key) | RemoteInput::KeyUp(key) if crate::desktop_scancode::printable_scan(*key).is_none())) { return Err(()); }
    let input = surface.inputs.as_ref().ok_or(())?;
    for event in batch {
        match *event {
            RemoteInput::KeyDown(key) | RemoteInput::KeyUp(key) => {
                for (scan, extended, down) in surface
                    .keyboard
                    .transition(key, matches!(event, RemoteInput::KeyDown(_)))
                    .ok_or(())?
                {
                    let scan = u32::from(scan) | if extended { 0x100 } else { 0 };
                    if down {
                        input.key_press(scan);
                    } else {
                        input.key_release(scan);
                    }
                }
            }
            RemoteInput::PointerMove(x, y) => {
                surface.position = (
                    x.clamp(0, (surface.size.0 - 1).max(0)),
                    y.clamp(0, (surface.size.1 - 1).max(0)),
                );
                input.position(surface.position.0, surface.position.1, 0, surface.buttons);
            }
            RemoteInput::PointerButton { button, pressed } => {
                let (button, mask) = match button {
                    PointerButton::Left => (1, 1),
                    PointerButton::Middle => (2, 2),
                    PointerButton::Right => (3, 4),
                    PointerButton::WheelUp => (4, 0),
                    PointerButton::WheelDown => (5, 0),
                    // SPICE buttons 6/7 are side/extra, not horizontal wheel events.
                    PointerButton::WheelLeft | PointerButton::WheelRight => continue,
                };
                if pressed {
                    surface.buttons |= mask;
                    input.button_press(button, surface.buttons);
                } else {
                    surface.buttons &= !mask;
                    input.button_release(button, surface.buttons);
                }
            }
        }
    }
    Ok(())
}
