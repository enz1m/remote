use super::*;
use crate::{
    model::{ConnectionProfile, Protocol},
    protocol::{ProtocolError, RemoteProtocol},
};

#[test]
fn routing_is_never_silently_bypassed() {
    let backend = SpiceBackend::default();
    let mut profile = ConnectionProfile::new("SPICE", Protocol::Spice, "127.0.0.1");
    profile.ssh_tunnel = Some(crate::model::SshTunnel {
        host: "jump.invalid".into(),
        port: 22,
        username: "qa".into(),
        auth: crate::model::SshAuth::Agent,
        has_tunnel_password: false,
    });
    assert!(matches!(
        backend.connect(&profile, None),
        Err(ProtocolError::Refused(_))
    ));
    assert!(backend.closing().is_empty());
}
