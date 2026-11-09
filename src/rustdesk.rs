//! RustDesk desktops with pinned encryption or explicitly acknowledged direct access.

mod network;
pub(crate) mod rendezvous;
mod rendezvous_wire;
mod transport;
mod wire;

pub(crate) use crate::desktop_worker::Control;
pub(crate) type RustDeskBackend = crate::desktop_worker::DesktopBackend<Transport>;
pub(crate) const ACK_KEY: &str = "remote.rustdesk.plaintext-ack";
pub(crate) const PLAINTEXT_ACTIVE: &str =
    "Unencrypted RustDesk direct access: screen and input are not protected.";
pub(crate) const PEER_KEY: &str = "remote.rustdesk.peer-key";

#[derive(Debug)]
pub(crate) struct Transport;
impl crate::desktop_worker::Transport for Transport {
    const NATIVE_CLIPBOARD: bool = true;
    const PROTOCOL: crate::model::Protocol = crate::model::Protocol::RustDesk;
    const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
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
