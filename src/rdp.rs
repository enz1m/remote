//! Embedded RDP transport.

mod audio;
mod clipboard;
mod transport;

pub(crate) use crate::desktop_worker::Control;
pub(crate) type RdpBackend = crate::desktop_worker::DesktopBackend<Transport>;

#[derive(Debug)]
pub(crate) struct Transport;

impl crate::desktop_worker::Transport for Transport {
    const NATIVE_CLIPBOARD: bool = true;
    const PROTOCOL: crate::model::Protocol = crate::model::Protocol::Rdp;
    const MAX_SESSIONS: usize = 8;
    fn run(
        profile: &crate::model::ConnectionProfile,
        password: &str,
        control: &std::sync::Arc<Control>,
        inputs: std::sync::mpsc::Receiver<Vec<crate::protocol::RemoteInput>>,
        ready: std::sync::mpsc::SyncSender<Result<(), crate::protocol::ProtocolError>>,
    ) {
        transport::run(profile, password, control, inputs, ready);
    }
}
