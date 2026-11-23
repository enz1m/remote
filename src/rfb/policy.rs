//! Who this build is willing to speak unencrypted RFB to.
//!
//! RFB security type `None` is plaintext: the framebuffer, every keystroke and
//! every pointer position cross the network in the clear, and any host on the
//! path can read or inject them. That is acceptable to `127.0.0.1`, where the
//! "network" is the kernel, and it is not acceptable to a host across a LAN
//! just because a user typed its address.
//!
//! The decision is made here, once, from the resolved addresses rather than the
//! typed text, and a non-loopback destination requires an acknowledgement
//! recorded against that profile.
//!
//! `localhost` is not guaranteed to be loopback (`/etc/hosts` or DNS can point it
//! anywhere), so every resolved address is checked, the verdict is
//! unanimous-or-refuse, and the socket connects to the admitted address so no
//! second DNS answer can intervene.

use std::net::{IpAddr, SocketAddr};

/// Require certificate-verified VeNCrypt without plaintext fallback.
pub const TLS_KEY: &str = "remote.vnc.tls";
pub const FINGERPRINT_KEY: &str = "remote.vnc.certificate-sha256";
pub type Fingerprint = [u8; 32];

pub fn requires_tls(profile: &crate::model::ConnectionProfile) -> bool {
    profile
        .extra
        .get(TLS_KEY)
        .is_some_and(|value| value == "true")
        || profile.extra.contains_key(FINGERPRINT_KEY)
}

pub fn parse_fingerprint(text: &str) -> Option<Fingerprint> {
    let bytes = text.trim().as_bytes();
    let stride = match bytes.len() {
        64 => 2,
        95 => 3,
        _ => return None,
    };
    let mut fingerprint = [0; 32];
    for (index, byte) in fingerprint.iter_mut().enumerate() {
        let offset = index * stride;
        let hi = char::from(bytes[offset]).to_digit(16)?;
        let lo = char::from(bytes[offset + 1]).to_digit(16)?;
        if stride == 3 && index < 31 && bytes[offset + 2] != b':' {
            return None;
        }
        *byte = (hi * 16 + lo) as u8;
    }
    Some(fingerprint)
}

/// The endpoint-scoped explicit plaintext acknowledgement key.
pub const ACK_KEY: &str = "rfb_plaintext_ack";

/// The only value [`ACK_KEY`] may hold to count as an acknowledgement.
///
/// An exact value rather than "the key is present": an import from another
/// client, a hand-edited database or a future field could put something in
/// this key, and "present" would read all of those as consent.
pub const ACK_VALUE: &str = "acknowledged-plaintext";

/// The sentence shown wherever a refused non-loopback plaintext connection is
/// reported.
///
/// Names the exposure, not the mechanism: "security type None" means nothing
/// to somebody trying to reach their desktop.
pub const PLAINTEXT_WARNING: &str = "VNC to this host would send the screen and every keystroke unencrypted. \
     Only loopback connections do that without being acknowledged first.";

/// The disclosure shown while an acknowledged plaintext session is open.
pub const PLAINTEXT_ACTIVE: &str = "Unencrypted VNC: screen and input are not protected.";

/// How a destination is classified for the plaintext decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exposure {
    /// Every resolved address is loopback. Plaintext is the kernel talking to
    /// itself; no acknowledgement is required.
    Loopback,
    /// At least one resolved address is not loopback.
    Network,
}

/// Why a destination was refused before a socket was opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyRefusal {
    /// The host resolved to nothing.
    Unresolvable { host: String },
    /// The host is not loopback and the profile carries no acknowledgement.
    PlaintextNotAcknowledged { host: String },
}

impl std::fmt::Display for PolicyRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unresolvable { host } => write!(f, "{host} did not resolve to any address"),
            Self::PlaintextNotAcknowledged { .. } => write!(f, "{PLAINTEXT_WARNING}"),
        }
    }
}

/// A destination that passed the policy, with the exact address to dial.
///
/// Carrying the address rather than the hostname is the point: the check and
/// the connect use the same `SocketAddr`, so a name that resolves to loopback
/// during the check cannot resolve to a LAN host a millisecond later.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Destination {
    pub address: SocketAddr,
    pub exposure: Exposure,
}

/// Classify a set of already-resolved addresses.
///
/// Unanimous or refuse: a name resolving to both `127.0.0.1` and a routable
/// address is treated as [`Exposure::Network`], because a client that picked
/// the loopback answer and called the destination safe would be one resolver
/// ordering away from sending plaintext to the routable one.
pub fn classify(addresses: &[SocketAddr]) -> Option<(SocketAddr, Exposure)> {
    let first = *addresses.first()?;
    let all_loopback = addresses.iter().all(|a| is_loopback(a.ip()));
    Some((
        first,
        if all_loopback {
            Exposure::Loopback
        } else {
            Exposure::Network
        },
    ))
}

/// Whether an address is the local machine talking to itself.
///
/// `IpAddr::is_loopback` misses IPv4-mapped loopback (`::ffff:127.0.0.1`), so it
/// is unwrapped explicitly rather than refused as network exposure.
pub fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// Whether a profile records an explicit acknowledgement of plaintext RFB.
///
/// Exact-value, not presence; a new profile's empty `extra` answers `false`.
pub fn acknowledged(profile: &crate::model::ConnectionProfile) -> bool {
    profile.extra.get(ACK_KEY).map(String::as_str) == Some(ACK_VALUE)
}

/// Decide whether this profile may be dialled in plaintext, and to which
/// address.
///
/// The one authority. Both the backend and the availability disclosure call
/// it, so a session cannot be refused by one and offered by the other.
pub fn admit(
    profile: &crate::model::ConnectionProfile,
    addresses: &[SocketAddr],
) -> Result<Destination, PolicyRefusal> {
    let Some((address, exposure)) = classify(addresses) else {
        return Err(PolicyRefusal::Unresolvable {
            host: profile.host.clone(),
        });
    };
    if exposure == Exposure::Network && !requires_tls(profile) && !acknowledged(profile) {
        return Err(PolicyRefusal::PlaintextNotAcknowledged {
            host: profile.host.clone(),
        });
    }
    Ok(Destination { address, exposure })
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
