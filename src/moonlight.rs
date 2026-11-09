//! Paired Sunshine/Moonlight desktop streams with a private per-profile identity.

mod gamepad;
mod http;
pub(crate) mod identity;
mod transport;

pub(crate) use crate::desktop_worker::Control;
pub(crate) type MoonlightBackend = crate::desktop_worker::DesktopBackend<Transport>;
pub(crate) const PAIR_REQUEST: &str = "remote.moonlight.pair-request";
pub(crate) const RESUME: &str = "remote.moonlight.resume";
pub(crate) const GAMEPADS: &str = "remote.moonlight.gamepads";
pub(crate) const APP_ID: &str = "remote.moonlight.app-id";

#[derive(Debug)]
pub(crate) struct Transport;
impl crate::desktop_worker::Transport for Transport {
    const PROTOCOL: crate::model::Protocol = crate::model::Protocol::Moonlight;
    const MAX_SESSIONS: usize = 1;
    const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
    fn interrupt() {
        if let Ok(instance) = moonlight_common::stream::c::MoonlightInstance::global() {
            instance.interrupt_connection();
        }
    }
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
