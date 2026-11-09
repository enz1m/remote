//! Core domain model for remote-app.
//!
//! Pure: no I/O, no iced, no rusqlite, so it compiles standalone and its tests
//! run quickly.
//!
//! - The shape of `Protocol`, `ConnectionProfile`, `SshTunnel` and
//!   `PortForwardRule` is fixed by the Remmina-import path.
//! - `SessionStatus` variants define what a status dot may paint: green when
//!   connected, red on error, none when idle.
//! - Sidebar grouping lives in `organise.rs`.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::session::{InputMode, ScalingMode};

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

/// Desktop protocols and the legacy SSH value retained for saved-data compatibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Vnc,
    Rdp,
    Spice,
    /// Read legacy profiles without reinterpreting them as another desktop protocol.
    Ssh,
    RustDesk,
    Moonlight,
}

impl Protocol {
    pub fn label(self) -> &'static str {
        match self {
            Self::Vnc => "VNC",
            Self::Rdp => "RDP",
            Self::Spice => "SPICE",
            Self::Ssh => "SSH",
            Self::RustDesk => "RustDesk",
            Self::Moonlight => "Moonlight",
        }
    }

    /// The stable, untranslated Remmina key and Quick Connect URI scheme.
    pub fn key(self) -> &'static str {
        match self {
            Self::Vnc => "vnc",
            Self::Rdp => "rdp",
            Self::Spice => "spice",
            Self::Ssh => "ssh",
            Self::RustDesk => "rustdesk",
            Self::Moonlight => "moonlight",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Self::Vnc => 5900,
            Self::Rdp => 3389,
            Self::Spice => 5930,
            Self::Ssh => 22,
            Self::RustDesk => 21118,
            Self::Moonlight => 47984,
        }
    }

    /// Case-insensitive parse, or `None` for a key this build does not know.
    ///
    /// The one protocol-key table. Callers that must produce a protocol for
    /// any input use [`Self::from_key`]; callers describing durable state a
    /// user could have hand-edited use this, so an unknown key stays unknown
    /// rather than becoming a claim about a protocol.
    pub fn from_key_exact(key: &str) -> Option<Self> {
        match key.to_ascii_lowercase().as_str() {
            "vnc" => Some(Self::Vnc),
            "rdp" => Some(Self::Rdp),
            "spice" => Some(Self::Spice),
            "ssh" | "sftp" => Some(Self::Ssh),
            "rustdesk" => Some(Self::RustDesk),
            "moonlight" | "sunshine" | "gamestream" => Some(Self::Moonlight),
            _ => None,
        }
    }

    /// Case-insensitive parse. Unknown keys become VNC, tolerating malformed Remmina
    /// imports.
    ///
    /// Lossy: use [`Self::from_key_exact`] to distinguish an unknown key from VNC.
    pub fn from_key(key: &str) -> Self {
        Self::from_key_exact(key).unwrap_or(Self::Vnc)
    }

    /// Every protocol in supported order. Stable across builds so that
    /// dropdown ordering and iteration are deterministic.
    pub fn all() -> &'static [Protocol] {
        &PROTOCOLS
    }
}

/// Current desktop protocols, in a stable order. Legacy SSH is deliberately excluded.
///
/// Not the set a picker offers: [`crate::protocol::BackendRegistry`] decides that
/// through `choices()` and `available()`. A saved or imported profile may carry any
/// of these and must render and round-trip whether or not this build can dial it.
pub const PROTOCOLS: [Protocol; 5] = [
    Protocol::Vnc,
    Protocol::Rdp,
    Protocol::Spice,
    Protocol::RustDesk,
    Protocol::Moonlight,
];

// ---------------------------------------------------------------------------
// SSH tunnel / port forwarding
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SshTunnel {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: SshAuth,
    #[serde(default)]
    pub has_tunnel_password: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SshAuth {
    Password,
    PrivateKey { path: String },
    Agent,
}

/// The direction of an SSH port forward. Payload-free so a picker can select
/// it by index; the *destination* lives on [`ForwardKind`], because a dynamic
/// forward does not have one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortForwardType {
    Local,
    Remote,
    Dynamic,
}

impl PortForwardType {
    /// The label the picker shows — the ssh(1) flag in parentheses
    /// (`Local (-L)` / `Remote (-R)` / `Dynamic (-D)`).
    pub fn label(self) -> &'static str {
        match self {
            Self::Local => "Local (-L)",
            Self::Remote => "Remote (-R)",
            Self::Dynamic => "Dynamic (-D)",
        }
    }

    /// Whether a rule of this direction carries a destination.
    ///
    /// A dynamic (`-D`) forward is a SOCKS proxy: the *client* chooses each
    /// destination at connect time, so the rule has none. This is the one
    /// clause in the form that is not "fill in every field".
    pub fn needs_destination(self) -> bool {
        !matches!(self, Self::Dynamic)
    }

    /// Whether this direction's listener is opened by the server rather than
    /// by this machine.
    pub fn binds_on_the_server(self) -> bool {
        matches!(self, Self::Remote)
    }

    /// How an empty bind address reads for this direction.
    pub fn default_bind_display(self) -> &'static str {
        if self.binds_on_the_server() {
            SERVER_DEFAULT_BIND_DISPLAY
        } else {
            DEFAULT_BIND_DISPLAY
        }
    }

    /// What a rule of this direction may promise about an explicit request
    /// for every interface.
    ///
    /// A remote listener is the server's to open, so the request can only be
    /// reported as asked for, never as granted.
    pub fn all_interfaces_display(self) -> &'static str {
        if self.binds_on_the_server() {
            " — all interfaces, if the server allows"
        } else {
            " — all interfaces"
        }
    }

    pub fn index(self) -> usize {
        PORT_FORWARD_TYPES
            .iter()
            .position(|t| *t == self)
            .expect("PORT_FORWARD_TYPES must contain every PortForwardType variant")
    }

    pub fn from_index(i: usize) -> Self {
        PORT_FORWARD_TYPES.get(i).copied().unwrap_or(Self::Local)
    }
}

pub const PORT_FORWARD_TYPES: [PortForwardType; 3] = [
    PortForwardType::Local,
    PortForwardType::Remote,
    PortForwardType::Dynamic,
];

/// Index-aligned labels for [`PORT_FORWARD_TYPES`]. Guarded by
/// `port_forward_type_labels_are_index_aligned_with_the_variant_array`.
pub static PORT_FORWARD_TYPE_LABELS: [&str; 3] = ["Local (-L)", "Remote (-R)", "Dynamic (-D)"];

/// The quality levels the Options section offers, worst-first, mapped onto the
/// `0..=9` `quality` field the Remmina importer round-trips.
pub const QUALITY_LEVELS: [u8; 5] = [2, 4, 6, 8, 9];

/// Index-aligned labels for [`QUALITY_LEVELS`]. Guarded by
/// `quality_labels_are_index_aligned_with_the_value_array`.
pub static QUALITY_LABELS: [&str; 5] = ["Poor", "Low", "Medium", "Good", "Best"];

/// The index of the quality rung at or below `quality`, so an imported value
/// that is not exactly on a rung still selects a sensible one instead of
/// leaving the picker blank.
pub fn quality_index(quality: u8) -> usize {
    QUALITY_LEVELS
        .iter()
        .rposition(|q| *q <= quality)
        .unwrap_or(0)
}

pub fn quality_from_index(i: usize) -> u8 {
    QUALITY_LEVELS.get(i).copied().unwrap_or(6)
}

// ---------------------------------------------------------------------------
// Wake-on-LAN
// ---------------------------------------------------------------------------

/// Canonicalise a Wake-on-LAN MAC address to lowercase colon-separated hex.
///
/// Accepts `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff` and `aabbccddeeff`, trimming
/// surrounding whitespace. Returns `None` for anything that is not twelve hex
/// digits, including empty input; callers distinguish "no MAC" themselves.
pub fn normalize_mac(input: &str) -> Option<String> {
    let t = input.trim();
    // Reject a separator soup like `aa:bb-cc:dd-ee:ff` only insofar as the
    // digits must still be twelve; the separators themselves are stripped.
    let digits: String = t
        .chars()
        .filter(|c| *c != ':' && *c != '-')
        .collect::<String>()
        .to_ascii_lowercase();
    if digits.len() != 12 || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = String::with_capacity(17);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && i % 2 == 0 {
            out.push(':');
        }
        out.push(c);
    }
    Some(out)
}

/// The six MAC bytes a Wake-on-LAN magic packet needs, or `None` when the
/// input is not a MAC.
///
/// Built on [`normalize_mac`] rather than re-parsing, so "what counts as a
/// MAC" has exactly ONE definition: the form's validation and the packet
/// builder cannot disagree about whether `aa-bb-cc-dd-ee-ff` is acceptable.
pub fn mac_bytes(input: &str) -> Option<[u8; 6]> {
    let canonical = normalize_mac(input)?;
    let mut out = [0u8; 6];
    for (slot, pair) in out.iter_mut().zip(canonical.split(':')) {
        *slot = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

/// The 102-byte Wake-on-LAN magic packet for `mac`: six `0xFF` bytes followed
/// by the MAC repeated sixteen times.
///
/// Split out from [`send_wol_packet`] so the *bytes* are testable without a
/// socket — a send that silently built the wrong payload would look identical
/// to a working one from outside, because nothing on the LAN answers a magic
/// packet.
pub fn magic_packet(mac: &[u8; 6]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(102);
    pkt.extend_from_slice(&[0xFF; 6]);
    for _ in 0..16 {
        pkt.extend_from_slice(mac);
    }
    pkt
}

/// Broadcast a Wake-on-LAN magic packet for `mac` on UDP ports 9 and 7.
///
/// Port 9 (`discard`) is the conventional WoL port and 7 (`echo`) is what older
/// NICs listen on.
///
/// Returns `Err` only when neither port accepted the datagram. Success means the
/// packet was sent, not that the target woke.
pub fn send_wol_packet(mac: &[u8; 6]) -> Result<(), String> {
    use std::net::UdpSocket;
    let pkt = magic_packet(mac);
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("bind: {e}"))?;
    sock.set_broadcast(true)
        .map_err(|e| format!("set_broadcast: {e}"))?;
    let mut sent = false;
    for port in [9u16, 7] {
        if sock
            .send_to(&pkt, format!("255.255.255.255:{port}"))
            .is_ok()
        {
            sent = true;
        }
    }
    if sent {
        Ok(())
    } else {
        Err("no broadcast port accepted the packet".to_string())
    }
}

/// Where a forward sends its traffic.
///
/// The host is resolved by whichever end opens the onward connection: the
/// server for a local (`-L`) forward, this machine for a remote (`-R`) one.
/// `localhost` therefore names the far side of a local forward.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardDest {
    pub host: String,
    pub port: u16,
}

/// The spellings that ask for a listener on every interface.
///
/// An empty address is not one of them: it asks for the default listener of
/// whichever end binds it. Exposure is requested explicitly or not at all.
#[must_use]
pub fn is_wildcard_bind_address(value: &str) -> bool {
    matches!(value.trim(), "*" | "0.0.0.0" | "::" | "[::]")
}

/// How an empty bind address reads for a forward this machine listens on.
pub const DEFAULT_BIND_DISPLAY: &str = "localhost";

/// How an empty bind address reads for a forward the server listens on.
///
/// The server chooses that listener under its own `GatewayPorts`, which no
/// client option reaches, so it is never presented as loopback.
pub const SERVER_DEFAULT_BIND_DISPLAY: &str = "(server default)";

/// A forward's direction together with its destination, so a dynamic forward
/// with a destination is unrepresentable.
///
/// [`ForwardKind::Dynamic`] has no destination slot, so nothing can be stored,
/// round-tripped or misread there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForwardKind {
    Local(ForwardDest),
    Remote(ForwardDest),
    Dynamic,
}

impl ForwardKind {
    pub fn forward_type(&self) -> PortForwardType {
        match self {
            Self::Local(_) => PortForwardType::Local,
            Self::Remote(_) => PortForwardType::Remote,
            Self::Dynamic => PortForwardType::Dynamic,
        }
    }

    pub fn destination(&self) -> Option<&ForwardDest> {
        match self {
            Self::Local(d) | Self::Remote(d) => Some(d),
            Self::Dynamic => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortForwardRule {
    pub id: Uuid,
    pub kind: ForwardKind,
    /// The interface to bind. Empty asks for no bind address at all, which
    /// is the default listener of whichever end opens it: loopback for a
    /// local or dynamic forward, and the server's own `GatewayPorts`
    /// decision for a remote one. Every interface is asked for only through
    /// [`is_wildcard_bind_address`], and for a remote forward that request
    /// is still the server's to refuse.
    pub bind_address: String,
    /// The bind port, stored as typed. `0` is persisted but not connectable:
    /// a listener whose port this app could never report is refused at
    /// connect time.
    pub bind_port: u16,
    pub label: String,
    pub enabled: bool,
}

impl PortForwardRule {
    pub fn forward_type(&self) -> PortForwardType {
        self.kind.forward_type()
    }

    /// Whether this rule asks for a listener reachable from other machines.
    pub fn binds_all_interfaces(&self) -> bool {
        is_wildcard_bind_address(&self.bind_address)
    }

    /// A one-line `ssh(1)`-flavoured description, used as the rule row's title and
    /// accessible name.
    ///
    /// An empty bind address renders as the direction's default
    /// ([`PortForwardType::default_bind_display`]) rather than `:8080` or `*`. A remote
    /// rule states only what it asked for, since the server opens that listener.
    pub fn summary(&self) -> String {
        let direction = self.forward_type();
        let bind = if self.bind_address.is_empty() {
            direction.default_bind_display().to_string()
        } else {
            self.bind_address.clone()
        };
        let exposure = if self.binds_all_interfaces() {
            direction.all_interfaces_display()
        } else {
            ""
        };
        match &self.kind {
            ForwardKind::Local(d) => {
                format!(
                    "-L {bind}:{} → {}:{}{exposure}",
                    self.bind_port, d.host, d.port
                )
            }
            ForwardKind::Remote(d) => {
                format!(
                    "-R {bind}:{} → {}:{}{exposure}",
                    self.bind_port, d.host, d.port
                )
            }
            ForwardKind::Dynamic => {
                format!("-D {bind}:{} (SOCKS){exposure}", self.bind_port)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Connection profile
// ---------------------------------------------------------------------------

/// What a profile was dialling and authenticating as, compared field by field.
///
/// Typed rather than flattened, because any delimiter is a character a user may
/// type into a host, account, bind address or key path. Every field is
/// non-secret: only whether a stored secret is expected, never the secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DialIdentity {
    /// The protocol dialled, which decides the backend and the default port.
    pub protocol: Protocol,
    /// The host, canonicalized by [`crate::quick_connect::canonical_host`] so
    /// `BOX.` and `box` are one host and two spellings are not two dials.
    pub host: String,
    /// The port actually reached, with `0` resolved to the protocol default
    /// by [`crate::quick_connect::effective_port`].
    pub port: u16,
    /// The account offered. Compared byte for byte: this is the credential's
    /// subject, so a case change is a different account until a server says
    /// otherwise.
    pub username: String,
    /// The Windows domain offered, exactly as stored. Part of the credential,
    /// so `None` and `Some("")` stay distinct rather than being folded.
    pub domain: Option<String>,
    /// Whether a stored password was expected for this connection.
    ///
    /// Switching it changes where the credential comes from, so it changes the dial.
    pub keyring_password: bool,
    /// The jump host this dial went through, if any.
    pub tunnel: Option<TunnelIdentity>,
    /// Every forward the dial was asked to establish, in the order it was
    /// given them.
    ///
    /// In the identity because a session is only authoritative once the
    /// forwards the profile asked for are up: a connection that established
    /// one set of listeners did not establish another.
    pub forwards: Vec<ForwardIdentity>,
    /// Whether this profile carried the exact plaintext-RFB acknowledgement the
    /// backend reads ([`crate::rfb::policy::acknowledged`]).
    ///
    /// Controls admission of non-loopback plaintext RFB connections.
    pub plaintext_ack: bool,
    pub transport_options: BTreeMap<String, String>,
}

impl DialIdentity {
    /// The recent-connections row for this endpoint, stamped `at`.
    ///
    /// The caller stamps it at the accepted Ready edge, so the recorded time
    /// is when the transport was authoritative rather than when the dial or
    /// its keyring prompt started.
    #[must_use]
    pub fn recent_at(&self, at: DateTime<Utc>) -> crate::quick_connect::RecentConnection {
        crate::quick_connect::RecentConnection::new(
            self.host.clone(),
            self.port,
            self.protocol,
            self.username.clone(),
            at,
        )
    }
}

/// The jump host part of a [`DialIdentity`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelIdentity {
    /// The jump host, canonicalized like the connection's own host.
    pub host: String,
    /// The jump host's port, as stored: a jump host has no protocol default
    /// to resolve against.
    pub port: u16,
    /// The account offered to the jump host.
    pub username: String,
    /// How the jump host authenticates, including the private-key path carried by
    /// [`SshAuth::PrivateKey`].
    ///
    /// The path selects which key is offered, so it is part of the dial; key contents
    /// are never read here.
    pub auth: SshAuth,
    /// Whether a stored jump-host password was expected, under its own
    /// keyring key.
    pub keyring_password: bool,
}

/// One forward's connectable part, for [`DialIdentity`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardIdentity {
    /// The direction and, for a local or remote forward, the destination.
    pub kind: ForwardKind,
    /// The interface asked for, canonicalized. Empty stays empty: it means
    /// "the direction's own default listener", which is a different request
    /// from a named interface.
    pub bind_address: String,
    /// The port asked for, as stored.
    pub bind_port: u16,
    /// Whether the rule was asked for at all. A disabled rule establishes
    /// nothing, so enabling one changes what a Ready means.
    pub enabled: bool,
}

/// A saved connection. Persisted to SQLite (see `db.rs`); the password (if
/// any) lives in the OS keyring and is never in this struct.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionProfile {
    pub id: Uuid,
    pub name: String,
    /// '/'-delimited folder path (Remmina semantics). Empty string = ungrouped.
    pub group: String,
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub domain: Option<String>,
    pub resolution: Option<(u32, u32)>,
    pub color_depth: u8,
    pub quality: u8,
    pub view_only: bool,
    pub disable_clipboard: bool,
    pub ssh_tunnel: Option<SshTunnel>,
    pub notes: String,
    #[serde(default)]
    pub extra: BTreeMap<String, String>,
    pub created: DateTime<Utc>,
    pub last_connected: Option<DateTime<Utc>>,
    pub favorite: bool,
    /// True when a password for this profile is stored in the OS keyring.
    /// The actual secret is fetched from the app's credential store under the
    /// key built by [`crate::keyring::profile_password_key`].
    #[serde(default)]
    pub has_keyring_password: bool,
    /// Optional Wake-on-LAN MAC (canonical lowercase colon-separated hex).
    #[serde(default)]
    pub wol_mac: Option<String>,
    #[serde(default)]
    pub port_forward_rules: Vec<PortForwardRule>,
    /// Whether this connection reconnects itself after an unexpected loss,
    /// and within which bounds. Off unless the user opted in; a row or a
    /// document that carries no policy loads as off.
    #[serde(default)]
    pub reconnect: crate::reconnect::ReconnectPolicy,
}

impl ConnectionProfile {
    pub fn new(name: impl Into<String>, protocol: Protocol, host: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            group: String::new(),
            protocol,
            host: host.into(),
            port: protocol.default_port(),
            username: String::new(),
            domain: None,
            resolution: None,
            color_depth: 32,
            quality: 6,
            view_only: false,
            disable_clipboard: false,
            ssh_tunnel: None,
            notes: String::new(),
            extra: BTreeMap::new(),
            created: Utc::now(),
            last_connected: None,
            favorite: false,
            has_keyring_password: false,
            wol_mac: None,
            port_forward_rules: Vec::new(),
            reconnect: crate::reconnect::ReconnectPolicy::default(),
        }
    }

    /// Everything about this profile that decides what is dialled and how it
    /// authenticates.
    ///
    /// The profile stays editable during a dial, so the identity read at dispatch is
    /// compared against this one before the connection is credited as
    /// `last_connected`. See [`DialIdentity`].
    #[must_use]
    pub fn dial_identity(&self) -> DialIdentity {
        DialIdentity {
            protocol: self.protocol,
            host: crate::quick_connect::canonical_host(&self.host),
            port: crate::quick_connect::effective_port(self.port, self.protocol),
            username: self.username.clone(),
            domain: self.domain.clone(),
            keyring_password: self.has_keyring_password,
            tunnel: self.ssh_tunnel.as_ref().map(|tunnel| TunnelIdentity {
                host: crate::quick_connect::canonical_host(&tunnel.host),
                port: tunnel.port,
                username: tunnel.username.clone(),
                auth: tunnel.auth.clone(),
                keyring_password: tunnel.has_tunnel_password,
            }),
            forwards: self
                .port_forward_rules
                .iter()
                .map(|rule| ForwardIdentity {
                    kind: rule.kind.clone(),
                    bind_address: crate::quick_connect::canonical_host(&rule.bind_address),
                    bind_port: rule.bind_port,
                    enabled: rule.enabled,
                })
                .collect(),
            plaintext_ack: crate::rfb::policy::acknowledged(self),
            transport_options: self
                .extra
                .iter()
                .filter(|(key, _)| {
                    key.starts_with("remote.rustdesk.")
                        || key.starts_with("remote.moonlight.")
                        || key.starts_with("remote.audio.")
                        || key.starts_with("remote.display.")
                        || key.starts_with("remote.vnc.")
                })
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        }
    }

    /// A short "host:port" for display, elided to just "host" when the port is
    /// the protocol's default.
    pub fn host_display(&self) -> String {
        if self.port == self.protocol.default_port() {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// A case-insensitive multi-term AND search across name, host, group and
/// protocol label.
///
/// Pure so the semantics of a multi-word query are unit-tested without an
/// iced runtime.
#[path = "model/sessions.rs"]
mod sessions;

pub use sessions::{Session, SessionStatus};

pub fn matches_search(profile: &ConnectionProfile, query: &str) -> bool {
    let q = query.trim();
    if q.is_empty() {
        return true;
    }
    let haystack = format!(
        "{} {} {} {}",
        profile.name,
        profile.host,
        profile.group,
        profile.protocol.label(),
    )
    .to_lowercase();
    q.split_whitespace()
        .all(|term| haystack.contains(&term.to_lowercase()))
}

/// The demo connection library, used only by the capture and example opt-in
/// (`REMOTE_APP_SEED=1`). A launch without it never calls this.
///
/// Data, not wiring: a small deterministic mix across protocols and folders so
/// every rung has something to render and grouping is visible in a capture.
/// It lives beside [`ConnectionProfile`] because that is the type it builds.
pub fn seed_profiles() -> Vec<ConnectionProfile> {
    let mut out = Vec::new();
    // A small, deterministic mix across protocols and groups so every rung
    // has something to render and grouping is visible in the shot.
    let seeds: [(&str, Protocol, &str, &str, bool); 6] = [
        ("Prod VNC", Protocol::Vnc, "10.0.0.5", "Work/Servers", true),
        (
            "Staging RDP",
            Protocol::Rdp,
            "staging.example.com",
            "Work/Servers",
            false,
        ),
        ("Home NAS", Protocol::Vnc, "nas.local", "Home", false),
        ("Media Room", Protocol::Moonlight, "media-pc", "Home", true),
        (
            "Old Windows Box",
            Protocol::Spice,
            "192.168.1.42",
            "Home/Legacy",
            false,
        ),
        (
            "Dev Laptop",
            Protocol::Rdp,
            "dev-laptop.internal",
            "",
            false,
        ),
    ];
    for (name, proto, host, group, fav) in seeds {
        let mut p = ConnectionProfile::new(name, proto, host);
        p.group = group.into();
        p.favorite = fav;
        out.push(p);
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
