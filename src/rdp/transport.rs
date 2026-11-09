use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use ironrdp_blocking::Framed;
use ironrdp_connector::{self as connector, Credentials};
use ironrdp_pdu::gcc::KeyboardType;
use ironrdp_pdu::input::fast_path::{FastPathInputEvent, KeyboardFlags};
use ironrdp_pdu::input::mouse::{MousePdu, PointerFlags};
use ironrdp_pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp_pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput};
use x509_cert::der::Decode;

use super::Control;
use crate::desktop_scancode::scan_code;
use crate::model::ConnectionProfile;
use crate::protocol::{PointerButton, ProtocolError, RemoteInput};
use crate::state_machine::SessionEvent;

type TlsFramed = Framed<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>;

struct NoAuxiliaryNetwork;

impl connector::sspi::network_client::NetworkClient for NoAuxiliaryNetwork {
    fn send(
        &self,
        _: &connector::sspi::generator::NetworkRequest,
    ) -> connector::sspi::Result<Vec<u8>> {
        Err(connector::sspi::Error::new(
            connector::sspi::ErrorKind::UnsupportedFunction,
            "RDP auxiliary authentication network requests are not enabled",
        ))
    }
}

fn config(profile: &ConnectionProfile, password: &str) -> connector::Config {
    let (width, height) = profile.resolution.unwrap_or((1280, 720));
    connector::Config {
        credentials: Credentials::UsernamePassword {
            username: profile
                .username
                .split_once('\\')
                .map_or(profile.username.as_str(), |(_, name)| name)
                .to_owned(),
            password: password.to_owned(),
        },
        domain: profile
            .username
            .split_once('\\')
            .map(|(domain, _)| domain.to_owned())
            .or_else(|| profile.domain.clone()),
        enable_tls: true,
        enable_credssp: true,
        keyboard_type: KeyboardType::IBM_ENHANCED,
        keyboard_subtype: 0,
        keyboard_layout: 0x409,
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: connector::DesktopSize {
            width: width.clamp(200, 3840) as u16,
            height: height.clamp(200, 2160) as u16,
        },
        bitmap: None,
        client_build: 0,
        client_name: "enzui-remote".into(),
        client_dir: String::new(),
        platform: MajorPlatformType::UNIX,
        enable_server_pointer: false,
        request_data: None,
        autologon: !profile.username.is_empty() && !password.is_empty(),
        enable_audio_playback: crate::stream_audio::enabled(profile),
        compression_type: None,
        pointer_software_rendering: false,
        multitransport_flags: None,
        performance_flags: PerformanceFlags::default(),
        desktop_scale_factor: 0,
        hardware_id: None,
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        monitor_layout: None,
        desktop_physical_size: None,
        desktop_orientation: None,
        device_scale_factor: None,
        monitor_extended_layout: None,
        relative_mouse_input: false,
        enable_standard_rdp_security: false,
        connection_type: ironrdp_pdu::gcc::ConnectionType::Lan,
        remote_application_mode: false,
        rail_support_level: ironrdp_pdu::rdp::capability_sets::RailSupportLevel::empty(),
        enable_audio_capture: false,
        support_dyn_vc_gfx_protocol: false,
    }
}

fn dial_addresses(
    addresses: impl IntoIterator<Item = SocketAddr>,
    cancelled: &AtomicBool,
) -> io::Result<TcpStream> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_error = None;
    for address in addresses.into_iter().take(32) {
        if cancelled.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let timeout = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(2));
        if timeout.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(socket) => return Ok(socket),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| io::ErrorKind::AddrNotAvailable.into()))
}

fn connect(
    profile: &ConnectionProfile,
    password: &str,
    control: &Arc<Control>,
    clipboard: &super::clipboard::Context,
) -> anyhow::Result<(connector::ConnectionResult, TlsFramed)> {
    let port = if profile.port == 0 {
        3389
    } else {
        profile.port
    };
    let tcp = if let Some(route) = control.route() {
        route.connect(&profile.host, port)?
    } else {
        let addresses = (profile.host.as_str(), port).to_socket_addrs()?;
        dial_addresses(addresses, &control.cancelled)?
    };
    control.adopt(&tcp)?;
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(10)))?;
    tcp.set_nodelay(true)?;
    let mut connector =
        connector::ClientConnector::new(config(profile, password), tcp.local_addr()?);
    connector.attach_static_channel(clipboard.channel());
    if crate::stream_audio::enabled(profile) {
        connector.attach_static_channel(super::audio::AudioChannel::new());
    }
    connector.attach_static_channel(ironrdp_dvc::DrdynvcClient::new().with_dynamic_channel(
        ironrdp_displaycontrol::client::DisplayControlClient::new(|_| Ok(Vec::new())),
    ));
    let mut framed = Framed::new(tcp);
    let upgrade =
        ironrdp_blocking::connect_begin(&mut framed, &mut connector).context("RDP negotiation")?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    if roots.is_empty() {
        bail!("No system TLS trust roots are available");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.resumption = rustls::client::Resumption::disabled();
    let tls =
        rustls::ClientConnection::new(Arc::new(tls_config), profile.host.clone().try_into()?)?;
    let mut tls = rustls::StreamOwned::new(tls, framed.into_inner_no_leftover());
    while tls.conn.is_handshaking() {
        tls.conn
            .complete_io(&mut tls.sock)
            .context("RDP TLS certificate validation")?;
    }
    let certificate = tls
        .conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .context("RDP certificate missing")?;
    let certificate = x509_cert::Certificate::from_der(certificate)?;
    let public_key = certificate
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("RDP public key encoding")?
        .to_vec();
    let upgraded = ironrdp_blocking::mark_as_upgraded(upgrade, &mut connector);
    let mut framed = Framed::new(tls);
    let result = ironrdp_blocking::connect_finalize(
        upgraded,
        connector,
        &mut framed,
        &mut NoAuxiliaryNetwork,
        profile.host.clone().into(),
        public_key,
        None,
    )
    .context("RDP authentication/activation")?
    .into_connected()?;
    validate_geometry(result.desktop_size.width, result.desktop_size.height)?;
    framed
        .get_inner()
        .0
        .sock
        .set_read_timeout(Some(Duration::from_millis(25)))?;
    Ok((result, framed))
}

#[derive(Debug)]
struct FrameTooLarge;

impl std::fmt::Display for FrameTooLarge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RDP desktop exceeds framebuffer limits")
    }
}

impl std::error::Error for FrameTooLarge {}

fn validate_geometry(width: u16, height: u16) -> anyhow::Result<()> {
    let limits = crate::framebuffer::REMOTE_FRAME_LIMITS;
    let pixels = u64::from(width) * u64::from(height);
    if width == 0
        || height == 0
        || u32::from(width) > limits.max_width
        || u32::from(height) > limits.max_height
        || pixels > limits.max_pixels
        || pixels * 4 > limits.max_rgba_bytes
    {
        return Err(FrameTooLarge.into());
    }
    Ok(())
}

fn dial_failure(error: anyhow::Error, cancelled: bool) -> ProtocolError {
    if cancelled {
        ProtocolError::Refused("The RDP connection was cancelled.".into())
    } else if error.downcast_ref::<FrameTooLarge>().is_some() {
        ProtocolError::Refused(
            "The RDP server requested a desktop larger than this app can safely display.".into(),
        )
    } else if error.chain().any(|cause| {
        cause.downcast_ref::<rustls::Error>().is_some()
            || cause.downcast_ref::<io::Error>().is_some_and(|io| {
                io.get_ref()
                    .is_some_and(|inner| inner.downcast_ref::<rustls::Error>().is_some())
            })
    }) {
        ProtocolError::Refused("RDP TLS verification failed. Use the certificate hostname and a certificate trusted by the system; no certificate bypass is offered.".into())
    } else if error
        .chain()
        .any(|cause| cause.downcast_ref::<io::Error>().is_some())
    {
        ProtocolError::Transport(
            "The RDP connection could not be opened or was interrupted.".into(),
        )
    } else {
        ProtocolError::Auth("RDP connection negotiation or authentication failed. Check the host, username/domain and saved password; TLS or NLA is required.".into())
    }
}

pub(super) fn run(
    profile: &ConnectionProfile,
    password: &str,
    control: &Arc<Control>,
    inputs: Receiver<Vec<RemoteInput>>,
    ready: SyncSender<Result<(), ProtocolError>>,
) {
    let clipboard = super::clipboard::Context::new(control);
    let (result, mut framed) = match connect(profile, password, control, &clipboard) {
        Ok(result) => result,
        Err(error) => {
            let error = dial_failure(error, control.cancelled.load(Ordering::SeqCst));
            let _ = ready.send(Err(error));
            return;
        }
    };
    if control.cancelled.load(Ordering::SeqCst) {
        return;
    }
    let mut image = DecodedImage::new(
        ironrdp_graphics::image_processing::PixelFormat::RgbA32,
        result.desktop_size.width,
        result.desktop_size.height,
    );
    let mut stage = ActiveStageBuilder {
        static_channels: result.static_channels,
        user_channel_id: result.user_channel_id,
        io_channel_id: result.io_channel_id,
        message_channel_id: result.message_channel_id,
        share_id: result.share_id,
        compression_type: result.compression_type,
        enable_server_pointer: false,
        pointer_software_rendering: false,
    }
    .build();
    control.active.store(true, Ordering::SeqCst);
    if ready.send(Ok(())).is_err() {
        return;
    }
    let activation = result.activation_factory;
    let mut pointer = (0, 0);
    let outcome = active(
        &mut framed,
        &mut stage,
        &mut image,
        control,
        inputs,
        &mut pointer,
        &activation,
    );
    // A full frame queue must not keep a failed connection's keys held down.
    control.sever_socket();
    if !control.cancelled.load(Ordering::SeqCst) || control.input_failed.load(Ordering::SeqCst) {
        let message = if control.input_failed.load(Ordering::SeqCst) {
            "RDP input could not be queued; the connection was closed to release held input.".into()
        } else if outcome.is_ok() {
            "The RDP server ended the session.".into()
        } else {
            let reason: String = format!("{:#}", outcome.unwrap_err())
                .chars()
                .filter(|ch| !ch.is_control())
                .take(240)
                .collect();
            format!("The RDP desktop stream ended: {reason}. Reconnect to continue.")
        };
        let _ = control.events.send(SessionEvent::Drop(message));
    }
}

fn active(
    framed: &mut TlsFramed,
    stage: &mut ActiveStage,
    image: &mut DecodedImage,
    control: &Control,
    inputs: Receiver<Vec<RemoteInput>>,
    pointer: &mut (u16, u16),
    activation: &connector::connection_activation::ConnectionActivationFactory,
) -> anyhow::Result<()> {
    let mut delivery = FrameDelivery::default();
    let mut last_resize = 0;
    let mut resize_at = Instant::now();
    while !control.cancelled.load(Ordering::SeqCst) {
        control.resize_available.store(
            stage
                .get_dvc::<ironrdp_displaycontrol::client::DisplayControlClient>()
                .map(|channel| channel.processor())
                .is_some_and(|client| client.ready()),
            Ordering::SeqCst,
        );
        let requested = control.requested_size.load(Ordering::SeqCst);
        if control.dynamic_resize.load(Ordering::SeqCst)
            && requested != 0
            && requested != last_resize
            && resize_at.elapsed() >= Duration::from_millis(150)
            && stage
                .get_dvc::<ironrdp_displaycontrol::client::DisplayControlClient>()
                .map(|channel| channel.processor())
                .is_some_and(|client| client.ready())
        {
            resize_at = Instant::now();
            if let Some(result) =
                stage.encode_resize((requested >> 32) as u32, requested as u32, None, None)
            {
                framed.write_all(&result?)?;
                last_resize = requested;
            }
        }
        let clipboard_bytes = super::clipboard::poll(stage)?;
        if !clipboard_bytes.is_empty() {
            framed.write_all(&clipboard_bytes)?;
        }
        for batch in inputs.try_iter().take(64) {
            let mut next_pointer = *pointer;
            let events =
                match encode_inputs(&batch, &mut next_pointer, (image.width(), image.height())) {
                    Ok(events) => events,
                    Err(_) => {
                        let _ = control.events.send(SessionEvent::InputRejected(
                            "This RDP key is unsupported; the complete input batch was refused."
                                .into(),
                        ));
                        continue;
                    }
                };
            *pointer = next_pointer;
            for chunk in events.chunks(255) {
                let output = stage.process_fastpath_input(image, chunk)?;
                if process_output(
                    output,
                    framed,
                    image,
                    control,
                    stage,
                    activation,
                    &mut delivery,
                )? {
                    return Ok(());
                }
            }
        }
        let (action, pdu) = match framed.read_pdu() {
            Ok(pdu) => pdu,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                delivery.publish(image, control)?;
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let output = stage.process(image, action, &pdu, framed.last_read_at())?;
        if process_output(
            output,
            framed,
            image,
            control,
            stage,
            activation,
            &mut delivery,
        )? {
            return Ok(());
        }
        delivery.publish(image, control)?;
    }
    Ok(())
}

fn process_output(
    output: Vec<ActiveStageOutput>,
    framed: &mut TlsFramed,
    image: &mut DecodedImage,
    control: &Control,
    stage: &mut ActiveStage,
    activation: &connector::connection_activation::ConnectionActivationFactory,
    delivery: &mut FrameDelivery,
) -> anyhow::Result<bool> {
    let mut changed = false;
    for event in output {
        match event {
            ActiveStageOutput::ResponseFrame(bytes) => framed.write_all(&bytes)?,
            ActiveStageOutput::GraphicsUpdate(_) => changed = true,
            ActiveStageOutput::Terminate(_) => return Ok(true),
            ActiveStageOutput::DeactivateAll => {
                reactivate(framed, stage, image, control, activation)?;
            }
            _ => {}
        }
    }
    delivery.dirty |= changed;
    Ok(false)
}

#[derive(Default)]
struct FrameDelivery {
    dirty: bool,
    pending: Option<Arc<AtomicBool>>,
    last: Option<Instant>,
}

impl FrameDelivery {
    fn publish(&mut self, image: &DecodedImage, control: &Control) -> anyhow::Result<()> {
        if !self.dirty
            || self
                .pending
                .as_ref()
                .is_some_and(|pending| !pending.load(Ordering::Acquire))
            || self
                .last
                .is_some_and(|last| last.elapsed() < Duration::from_millis(34))
        {
            return Ok(());
        }
        validate_geometry(image.width(), image.height())?;
        let consumed = Arc::new(AtomicBool::new(false));
        // The executor may drain the stream ahead of the UI, so queue capacity alone cannot pace frames.
        let pixels =
            crate::framebuffer::FrameBytes::tracked(image.data().to_vec(), Arc::clone(&consumed));
        control
            .events
            .send(SessionEvent::Frame {
                width: u32::from(image.width()),
                height: u32::from(image.height()),
                pixels,
            })
            .map_err(|_| anyhow::anyhow!("RDP surface retired"))?;
        self.pending = Some(consumed);
        self.last = Some(Instant::now());
        self.dirty = false;
        Ok(())
    }
}

fn reactivate(
    framed: &mut TlsFramed,
    stage: &mut ActiveStage,
    image: &mut DecodedImage,
    control: &Control,
    factory: &connector::connection_activation::ConnectionActivationFactory,
) -> anyhow::Result<()> {
    use connector::Sequence;
    use connector::connection_activation::ConnectionActivationState;
    let mut sequence = factory.create();
    let mut buffer = ironrdp_core::WriteBuf::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !control.cancelled.load(Ordering::SeqCst) && Instant::now() < deadline {
        buffer.clear();
        let written = match sequence.next_pdu_hint() {
            Some(hint) => {
                let bytes = match framed.read_by_hint(hint) {
                    Ok(bytes) => bytes,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                // Audio/DVC traffic may interleave the display reactivation sequence.
                if ironrdp_pdu::mcs::decode_send_data_indication(&bytes)?.channel_id
                    != sequence.io_channel_id()
                {
                    for output in stage.process(
                        image,
                        ironrdp_pdu::Action::X224,
                        &bytes,
                        framed.last_read_at(),
                    )? {
                        match output {
                            ActiveStageOutput::ResponseFrame(bytes) => framed.write_all(&bytes)?,
                            ActiveStageOutput::Terminate(_) => {
                                bail!("RDP ended during reactivation")
                            }
                            _ => bail!("Unexpected RDP display event during channel reactivation"),
                        }
                    }
                    continue;
                }
                sequence.step(&bytes, framed.last_read_at(), &mut buffer)?
            }
            None => sequence.step_no_input(&mut buffer)?,
        };
        if let Some(length) = written.size() {
            framed.write_all(&buffer[..length])?;
        }
        if let ConnectionActivationState::Finalized {
            desktop_size,
            share_id,
            ..
        } = sequence.connection_activation_state()
        {
            validate_geometry(desktop_size.width, desktop_size.height)?;
            *image = DecodedImage::new(
                ironrdp_graphics::image_processing::PixelFormat::RgbA32,
                desktop_size.width,
                desktop_size.height,
            );
            stage.set_share_id(share_id);
            stage.set_fastpath_processor(
                ironrdp_session::fast_path::ProcessorBuilder {
                    io_channel_id: sequence.io_channel_id(),
                    user_channel_id: sequence.user_channel_id(),
                    share_id,
                    enable_server_pointer: false,
                    pointer_software_rendering: false,
                }
                .build(),
            );
            return Ok(());
        }
    }
    bail!("RDP reactivation was cancelled or exceeded its deadline")
}

fn encode_inputs(
    inputs: &[RemoteInput],
    pointer: &mut (u16, u16),
    size: (u16, u16),
) -> anyhow::Result<Vec<FastPathInputEvent>> {
    let mut events = Vec::with_capacity(inputs.len());
    for input in inputs {
        match *input {
            RemoteInput::KeyDown(key) | RemoteInput::KeyUp(key) => {
                let mut flags = if matches!(input, RemoteInput::KeyUp(_)) {
                    KeyboardFlags::RELEASE
                } else {
                    KeyboardFlags::empty()
                };
                if let Some((code, extended)) = scan_code(key) {
                    if extended {
                        flags |= KeyboardFlags::EXTENDED;
                    }
                    events.push(FastPathInputEvent::KeyboardEvent(flags, code));
                } else if let Some(character) = xkeysym::Keysym::new(key).key_char() {
                    for unit in character.encode_utf16(&mut [0; 2]) {
                        events.push(FastPathInputEvent::UnicodeKeyboardEvent(flags, *unit));
                    }
                } else {
                    bail!("RDP key is unsupported");
                }
            }
            RemoteInput::PointerMove(x, y) => {
                *pointer = (
                    x.clamp(0, i32::from(size.0.saturating_sub(1))) as u16,
                    y.clamp(0, i32::from(size.1.saturating_sub(1))) as u16,
                );
                events.push(mouse(PointerFlags::MOVE, 0, *pointer));
            }
            RemoteInput::PointerButton { button, pressed } => {
                let (mut flags, wheel) = match button {
                    PointerButton::Left => (PointerFlags::LEFT_BUTTON, 0),
                    PointerButton::Middle => (PointerFlags::MIDDLE_BUTTON_OR_WHEEL, 0),
                    PointerButton::Right => (PointerFlags::RIGHT_BUTTON, 0),
                    PointerButton::WheelUp => (PointerFlags::VERTICAL_WHEEL, 120),
                    PointerButton::WheelDown => (PointerFlags::VERTICAL_WHEEL, -120),
                    PointerButton::WheelLeft => (PointerFlags::HORIZONTAL_WHEEL, -120),
                    PointerButton::WheelRight => (PointerFlags::HORIZONTAL_WHEEL, 120),
                };
                if wheel != 0 && !pressed {
                    continue;
                }
                if wheel == 0 && pressed {
                    flags |= PointerFlags::DOWN;
                }
                events.push(mouse(flags, wheel, *pointer));
            }
        }
    }
    Ok(events)
}

fn mouse(flags: PointerFlags, wheel: i16, pointer: (u16, u16)) -> FastPathInputEvent {
    FastPathInputEvent::MouseEvent(MousePdu {
        flags,
        number_of_wheel_rotation_units: wheel,
        x_position: pointer.0,
        y_position: pointer.1,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn tcp_dial_tries_later_addresses_and_obeys_cancellation() {
        let refused = std::net::TcpListener::bind("127.0.0.1:0").expect("refused fixture");
        let first = refused.local_addr().expect("first address");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("live fixture");
        let second = listener.local_addr().expect("second address");
        drop(refused);
        let cancelled = AtomicBool::new(false);
        let socket = dial_addresses([first, second], &cancelled).expect("fallback connection");
        assert_eq!(socket.peer_addr().expect("connected peer"), second);
        cancelled.store(true, Ordering::SeqCst);
        assert_eq!(
            dial_addresses([second], &cancelled)
                .expect_err("cancelled dial")
                .kind(),
            io::ErrorKind::Interrupted
        );
    }

    use super::*;

    #[test]
    fn frames_coalesce_until_the_ui_consumes_or_discards_the_pending_message() {
        let (events, mut stream) = crate::protocol::SessionStream::channel();
        let control = Control {
            route: std::sync::Mutex::new(None),
            cancelled: AtomicBool::new(false),
            input_failed: AtomicBool::new(false),
            active: AtomicBool::new(true),
            input_capture: std::sync::Arc::new(AtomicBool::new(false)),
            clipboard: crate::native_clipboard::Clipboard::new(false),
            requested_size: std::sync::atomic::AtomicU64::new(0),
            dynamic_resize: std::sync::atomic::AtomicBool::new(false),
            resize_available: std::sync::atomic::AtomicBool::new(false),
            socket: std::sync::Mutex::new(None),
            events,
        };
        let first = DecodedImage::new(
            ironrdp_graphics::image_processing::PixelFormat::RgbA32,
            2,
            2,
        );
        let latest = DecodedImage::new(
            ironrdp_graphics::image_processing::PixelFormat::RgbA32,
            3,
            2,
        );
        let mut delivery = FrameDelivery {
            dirty: true,
            ..FrameDelivery::default()
        };
        delivery.publish(&first, &control).unwrap();
        let message = iced::futures::executor::block_on(stream.recv()).unwrap();
        let SessionEvent::Frame { pixels, .. } = message else {
            panic!("frame");
        };
        let cached = pixels.clone();
        delivery.dirty = true;
        // Remove the rate ceiling so this distinguishes acknowledgement from elapsed time.
        delivery.last = None;
        delivery.publish(&latest, &control).unwrap();
        assert_eq!(stream.queued().0, 0);
        assert_eq!(pixels.into_vec().len(), 16);
        delivery.publish(&latest, &control).unwrap();
        let message = iced::futures::executor::block_on(stream.recv()).unwrap();
        assert!(matches!(
            message,
            SessionEvent::Frame {
                width: 3,
                height: 2,
                ..
            }
        ));
        drop(cached);
        drop(message);
        delivery.dirty = true;
        delivery.last = None;
        delivery.publish(&latest, &control).unwrap();
        assert_eq!(stream.queued().0, 1);
    }

    #[test]
    fn io_wrapped_certificate_errors_require_user_action_instead_of_retry() {
        let error = rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer);
        let error = anyhow::Error::new(io::Error::new(io::ErrorKind::InvalidData, error))
            .context("TLS handshake");
        let failure = dial_failure(error, false);
        assert!(matches!(failure, ProtocolError::Refused(_)));
        assert_eq!(
            failure.retry_disposition(),
            crate::reconnect::RetryDisposition::RequiresUser
        );
    }

    #[test]
    fn frame_limits_are_checked_before_allocating_the_decoder_image() {
        assert!(validate_geometry(3840, 2160).is_ok());
        for size in [(0, 768), (1024, 0), (8192, 8192), (u16::MAX, 1)] {
            assert!(validate_geometry(size.0, size.1).is_err());
        }
    }

    #[test]
    fn input_maps_releases_extended_keys_and_wheel_pulses_to_the_current_position() {
        let mut pointer = (0, 0);
        let events = encode_inputs(
            &[
                RemoteInput::KeyDown(0xffe4),
                RemoteInput::KeyUp(0xffe4),
                RemoteInput::PointerMove(4000, -1),
                RemoteInput::PointerButton {
                    button: PointerButton::WheelDown,
                    pressed: true,
                },
                RemoteInput::PointerButton {
                    button: PointerButton::WheelDown,
                    pressed: false,
                },
            ],
            &mut pointer,
            (1024, 768),
        )
        .unwrap();
        assert_eq!(events.len(), 4);
        assert_eq!(
            events[0],
            FastPathInputEvent::KeyboardEvent(KeyboardFlags::EXTENDED, 0x1d)
        );
        assert_eq!(
            events[1],
            FastPathInputEvent::KeyboardEvent(
                KeyboardFlags::EXTENDED | KeyboardFlags::RELEASE,
                0x1d
            )
        );
        assert_eq!(pointer, (1023, 0));
        assert_eq!(
            events[3],
            mouse(PointerFlags::VERTICAL_WHEEL, -120, pointer)
        );
        let unicode = encode_inputs(
            &[
                RemoteInput::KeyDown(0x0101f600),
                RemoteInput::KeyUp(0x0101f600),
            ],
            &mut pointer,
            (1024, 768),
        )
        .unwrap();
        assert_eq!(unicode.len(), 4);
        assert_eq!(
            unicode[3],
            FastPathInputEvent::UnicodeKeyboardEvent(KeyboardFlags::RELEASE, 0xde00)
        );
    }
}
