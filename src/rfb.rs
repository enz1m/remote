//! RFB (VNC) over an owned `std::net::TcpStream`.
//!
//! RFB 3.8, Raw/CopyRect/ZRLE rectangles, desktop resizing and profile-keyed
//! keyboard/pointer input. Classic VNC authentication uses the keyring password;
//! it authenticates the client but does not encrypt the screen or input.
//! [`policy`] requires an explicit acknowledgement for non-loopback destinations.
//! Profiles can require certificate-verified VeNCrypt 0.2 with TLS 1.2 or newer.

pub mod backend;
pub(crate) mod clipboard;
pub mod handshake;
mod io;
pub mod policy;
pub mod reader;
pub mod wire;
mod zrle;

/// Explanation shown when a server requires an unavailable credential method.
pub const SECURITY_UNSUPPORTED: &str =
    "requires a saved VNC password or a security method this build does not support";

#[cfg(test)]
#[path = "rfb/server_fixture.rs"]
pub mod server_fixture;

#[cfg(test)]
#[path = "rfb/wire_tests.rs"]
mod wire_tests;

#[cfg(test)]
#[path = "rfb/transport_tests.rs"]
mod transport_tests;

#[cfg(test)]
#[path = "rfb/frame_tests.rs"]
mod frame_tests;
