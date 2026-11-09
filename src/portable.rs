//! Import and export — `Export all profiles (JSON)` and `Import .rdp files`.
//!
//! # No plaintext secrets
//!
//! A password never appears in an export. Credentials live in the OS keyring
//! (`keyring.rs`), keyed by profile id. Version-2 exports omit the secrets and
//! both machine-local credential-presence flags; import accepts the
//! connection-password flag from version 1 but always clears it, and the
//! tunnel DTO reconstructs its omitted flag as false. [`export_json`] takes no
//! `&dyn KeyringStore`, so it cannot leak a secret it was never handed.
//!
//! Round-trip tests are paired with literal assertions on the exported text,
//! since a shared bug in both directions cancels out.
//!
//! # `.rdp` is a foreign format
//!
//! Microsoft's `.rdp` is a `key:type:value` line format. Unknown keys, missing
//! keys, wrong types and binary noise degrade to a skipped line or a reported
//! error, never a panic. See [`import_rdp`].
//!
//! # No file chooser
//!
//! Both directions work on strings: `export_json` returns the document for the
//! reducer to save at the chosen local path, and `import_rdp` parses text the
//! reducer read.

use serde::{Deserialize, Serialize};

use crate::model::{
    ConnectionProfile, ForwardDest, ForwardKind, PortForwardRule, Protocol, SshAuth, SshTunnel,
};

/// The export document's version. Bumped when the shape changes so an importer
/// can refuse a document it does not understand rather than silently reading
/// half of it.
pub const EXPORT_VERSION: u32 = 2;

/// Portable, non-secret SSH jump-host settings.
///
/// Deliberately separate from [`SshTunnel`] so its machine-local
/// `has_tunnel_password` flag cannot be serialized by accident.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedSshTunnel {
    #[serde(deserialize_with = "crate::import_source::bounded_string")]
    pub host: String,
    pub port: u16,
    #[serde(deserialize_with = "crate::import_source::bounded_string")]
    pub username: String,
    pub auth: ExportedSshAuth,
}

/// Authentication configuration that is safe to move between machines.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportedSshAuth {
    Password,
    PrivateKey {
        #[serde(deserialize_with = "crate::import_source::bounded_string")]
        path: String,
    },
    Agent,
}

impl ExportedSshTunnel {
    fn from_tunnel(tunnel: &SshTunnel) -> Self {
        let auth = match &tunnel.auth {
            SshAuth::Password => ExportedSshAuth::Password,
            SshAuth::PrivateKey { path } => ExportedSshAuth::PrivateKey { path: path.clone() },
            SshAuth::Agent => ExportedSshAuth::Agent,
        };
        Self {
            host: tunnel.host.clone(),
            port: tunnel.port,
            username: tunnel.username.clone(),
            auth,
        }
    }

    fn into_tunnel(self) -> SshTunnel {
        let auth = match self.auth {
            ExportedSshAuth::Password => SshAuth::Password,
            ExportedSshAuth::PrivateKey { path } => SshAuth::PrivateKey { path },
            ExportedSshAuth::Agent => SshAuth::Agent,
        };
        SshTunnel {
            host: self.host,
            port: self.port,
            username: self.username,
            auth,
            // Credential-presence claims are machine-local, just like the
            // connection password's `has_keyring_password` flag.
            has_tunnel_password: false,
        }
    }
}

/// A forwarding rule without its profile-local identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedPortForwardRule {
    pub kind: ExportedForwardKind,
    #[serde(deserialize_with = "crate::import_source::bounded_string")]
    pub bind_address: String,
    pub bind_port: u16,
    #[serde(deserialize_with = "crate::import_source::bounded_string")]
    pub label: String,
    pub enabled: bool,
}

/// The portable direction and optional destination of a forwarding rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportedForwardKind {
    Local(ExportedForwardDest),
    Remote(ExportedForwardDest),
    Dynamic,
}

/// A portable forwarding destination.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedForwardDest {
    #[serde(deserialize_with = "crate::import_source::bounded_string")]
    pub host: String,
    pub port: u16,
}

impl ExportedPortForwardRule {
    fn from_rule(rule: &PortForwardRule) -> Self {
        let export_dest = |dest: &ForwardDest| ExportedForwardDest {
            host: dest.host.clone(),
            port: dest.port,
        };
        let kind = match &rule.kind {
            ForwardKind::Local(dest) => ExportedForwardKind::Local(export_dest(dest)),
            ForwardKind::Remote(dest) => ExportedForwardKind::Remote(export_dest(dest)),
            ForwardKind::Dynamic => ExportedForwardKind::Dynamic,
        };
        Self {
            kind,
            bind_address: rule.bind_address.clone(),
            bind_port: rule.bind_port,
            label: rule.label.clone(),
            enabled: rule.enabled,
        }
    }

    fn into_rule(self) -> PortForwardRule {
        let import_dest = |dest: ExportedForwardDest| ForwardDest {
            host: dest.host,
            port: dest.port,
        };
        let kind = match self.kind {
            ExportedForwardKind::Local(dest) => ForwardKind::Local(import_dest(dest)),
            ExportedForwardKind::Remote(dest) => ForwardKind::Remote(import_dest(dest)),
            ExportedForwardKind::Dynamic => ForwardKind::Dynamic,
        };
        PortForwardRule {
            id: uuid::Uuid::new_v4(),
            kind,
            bind_address: self.bind_address,
            bind_port: self.bind_port,
            label: self.label,
            enabled: self.enabled,
        }
    }
}

/// The JSON shape one profile takes in an export.
///
/// A hand-written projection rather than `#[derive(Serialize)]` on
/// `ConnectionProfile`, so a field added to the domain type (a password,
/// token or cookie) is not exported until written here too.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedProfile {
    #[serde(deserialize_with = "crate::import_source::bounded_string")]
    pub name: String,
    #[serde(deserialize_with = "crate::import_source::bounded_string")]
    pub protocol: String,
    #[serde(deserialize_with = "crate::import_source::bounded_string")]
    pub host: String,
    pub port: u16,
    #[serde(default, deserialize_with = "crate::import_source::bounded_string")]
    pub username: String,
    #[serde(default, deserialize_with = "crate::import_source::bounded_string")]
    pub group: String,
    #[serde(default, deserialize_with = "crate::import_source::bounded_string")]
    pub notes: String,
    #[serde(default)]
    pub color_depth: u8,
    #[serde(default)]
    pub quality: u8,
    #[serde(default)]
    pub view_only: bool,
    #[serde(default)]
    pub disable_clipboard: bool,
    #[serde(default)]
    pub ssh_tunnel: Option<ExportedSshTunnel>,
    #[serde(default, deserialize_with = "capped_rules")]
    pub port_forward_rules: Vec<ExportedPortForwardRule>,
    #[serde(default)]
    pub favorite: bool,
    /// Legacy v1 input only. A source machine's keyring state is not portable,
    /// so v2 does not serialize this flag and import always clears it.
    #[serde(default, skip_serializing)]
    pub has_keyring_password: bool,
    #[serde(
        default,
        deserialize_with = "crate::import_source::bounded_option_string"
    )]
    pub wol_mac: Option<String>,
}

impl ExportedProfile {
    /// Project a domain profile into its exportable subset.
    ///
    /// Omits the id (it is the keyring lookup key), the timestamps, and the
    /// port-forward rules' internal uuids.
    pub fn from_profile(p: &ConnectionProfile) -> Self {
        Self {
            name: p.name.clone(),
            protocol: p.protocol.key().to_string(),
            host: p.host.clone(),
            port: p.port,
            username: p.username.clone(),
            group: p.group.clone(),
            notes: p.notes.clone(),
            color_depth: p.color_depth,
            quality: p.quality,
            view_only: p.view_only,
            disable_clipboard: p.disable_clipboard,
            ssh_tunnel: p.ssh_tunnel.as_ref().map(ExportedSshTunnel::from_tunnel),
            port_forward_rules: p
                .port_forward_rules
                .iter()
                .map(ExportedPortForwardRule::from_rule)
                .collect(),
            favorite: p.favorite,
            has_keyring_password: p.has_keyring_password,
            wol_mac: p.wol_mac.clone(),
        }
    }

    /// Consume this row into a domain profile.
    ///
    /// Admitted strings and rules are moved, not copied, so the parse-time
    /// retention charge matches what is held. `Self::to_profile` clones into
    /// this for callers that do not own the row.
    pub fn into_profile(self) -> ConnectionProfile {
        // Read before the moves below: `protocol` is the one field the
        // constructor needs by reference.
        let protocol = Protocol::from_key(&self.protocol);
        let mut p = ConnectionProfile::new(self.name, protocol, self.host);
        p.port = self.port;
        p.username = self.username;
        p.group = self.group;
        p.notes = self.notes;
        p.color_depth = if self.color_depth == 0 {
            32
        } else {
            self.color_depth
        };
        p.quality = self.quality;
        p.view_only = self.view_only;
        p.disable_clipboard = self.disable_clipboard;
        p.ssh_tunnel = self.ssh_tunnel.map(ExportedSshTunnel::into_tunnel);
        p.port_forward_rules = self
            .port_forward_rules
            .into_iter()
            .map(ExportedPortForwardRule::into_rule)
            .collect();
        p.favorite = self.favorite;
        // A version-1 export may record a secret this machine's keyring lacks;
        // keeping the flag would claim a stored password that is not there.
        p.has_keyring_password = false;
        p.wol_mac = self.wol_mac;
        p
    }
}

/// The whole export document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportDocument {
    pub version: u32,
    #[serde(deserialize_with = "capped_profiles")]
    pub profiles: Vec<ExportedProfile>,
}

/// Deserialize the document's profile list under
/// [`crate::import_source::MAX_IMPORT_PROFILES`].
///
/// # Errors
/// As [`crate::import_source::capped_seq`].
fn capped_profiles<'de, D>(d: D) -> Result<Vec<ExportedProfile>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::import_source::capped_seq(
        d,
        crate::import_source::MAX_IMPORT_PROFILES,
        crate::import_source::RetentionBound::Count,
    )
}

/// Deserialize one profile's forward rules under
/// [`crate::import_source::MAX_IMPORT_RULES`].
///
/// # Errors
/// As [`crate::import_source::capped_seq`].
fn capped_rules<'de, D>(d: D) -> Result<Vec<ExportedPortForwardRule>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::import_source::capped_seq(
        d,
        crate::import_source::MAX_IMPORT_RULES,
        crate::import_source::RetentionBound::Fields,
    )
}

/// Serialise every profile to the export JSON.
///
/// Takes no keyring, so it cannot leak a secret.
pub fn export_json(profiles: &[ConnectionProfile]) -> String {
    let doc = ExportDocument {
        version: EXPORT_VERSION,
        profiles: profiles.iter().map(ExportedProfile::from_profile).collect(),
    };
    // `to_string_pretty` cannot fail for this shape (no non-string map keys,
    // no NaN), but an `expect` here would still be a panic in a user-facing
    // path, so the fallback is an empty document rather than a crash.
    serde_json::to_string_pretty(&doc)
        .unwrap_or_else(|_| format!("{{\n  \"version\": {EXPORT_VERSION},\n  \"profiles\": []\n}}"))
}

/// Bounded reasons [`import_json`] refuses a document.
///
/// Fieldless so no attacker-controlled payload (key, offset, version,
/// bidi-marked value) passes this boundary; the banner renders only
/// [`Self::banner_message`]. [`Self::InvalidDocument`] means pick another
/// file; [`Self::UnsupportedVersion`] means upgrade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JsonImportError {
    /// The bytes are not a profile-export document — malformed JSON,
    /// wrong shape, or unrelated content. Covers every `serde_json`
    /// refusal and every valid-JSON-wrong-shape case: neither the raw
    /// parser `Display` nor any field value survives past the boundary.
    InvalidDocument,
    /// The `version` field is newer than this build's [`EXPORT_VERSION`].
    /// Kept distinct from [`Self::InvalidDocument`] because a future
    /// document is a real export written by a newer app, not garbage.
    UnsupportedVersion,
    /// The document is well formed but lists more connections than this build
    /// will retain. Kept distinct from [`Self::InvalidDocument`] because the
    /// file is not broken, so the guidance is to split it.
    TooManyProfiles,
    /// The document is well formed but one of its settings, or the total of
    /// them, is larger than this build retains. Kept distinct from
    /// [`Self::TooManyProfiles`] because splitting the file does not help.
    TooComplex,
}

impl JsonImportError {
    /// Authored, bounded banner copy for this refusal.
    ///
    /// Contains no digits and no substring of the source document, so a hostile
    /// payload cannot bleed a token, path, or bidi mark through it.
    #[must_use]
    pub fn banner_message(&self) -> String {
        match self {
            Self::InvalidDocument => "This file is not a connection-profiles export. \
                 Choose a different file and try again."
                .to_string(),
            Self::UnsupportedVersion => "This export was written by a newer version of this app. \
                 Update the app and try the import again."
                .to_string(),
            Self::TooManyProfiles => "This export holds more connections than \
                 this app will import at once. Split it and try again."
                .to_string(),
            Self::TooComplex => "This export describes more settings than this \
                 app will import. Choose a smaller export and try again."
                .to_string(),
        }
    }
}

/// Parse an export document back into profiles.
///
/// A version this build does not understand is an error rather than a
/// best-effort read, which would silently drop what the new version added.
///
/// # Errors
///
/// Returns the fieldless [`JsonImportError`]; the raw `serde_json::Error`
/// (which echoes attacker-controlled names, fragments and offsets) never
/// reaches [`crate::TransferResult::Failed`] or the sidebar alert. Render
/// [`JsonImportError::banner_message`].
pub fn import_json(text: &str) -> Result<Vec<ConnectionProfile>, JsonImportError> {
    let _budget = crate::import_source::RetainedBudget::open();
    // The raw `serde_json::Error` is dropped here so its text cannot reach the
    // banner. The bounds record which refusal occurred out of band, and every
    // ceiling is applied while deserializing, so a refused document was never
    // retained.
    let doc: ExportDocument = serde_json::from_str(text).map_err(|_| {
        use crate::import_source::RetentionBound;
        match crate::import_source::overflowed() {
            Some(RetentionBound::Count) => JsonImportError::TooManyProfiles,
            Some(RetentionBound::Fields) => JsonImportError::TooComplex,
            None => JsonImportError::InvalidDocument,
        }
    })?;
    if doc.version > EXPORT_VERSION {
        return Err(JsonImportError::UnsupportedVersion);
    }
    // Move fields out so the parse-time charge equals what publication holds.
    Ok(doc
        .profiles
        .into_iter()
        .map(ExportedProfile::into_profile)
        .collect())
}

// ---------------------------------------------------------------------------
// .rdp import
// ---------------------------------------------------------------------------

/// Bounded reasons [`import_rdp`] refuses a document.
///
/// The only fatal case is a missing or empty `full address`. Fieldless like
/// [`JsonImportError`], so no input byte reaches the banner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RdpImportError {
    /// The `.rdp` file has no `full address` line, so there is no host
    /// to dial. Every other malformation degrades silently — see the
    /// module docs.
    MissingAddress,
    /// The file has more lines, or a longer line, than a settings file has.
    /// Refused before any field is read, so no part of it is retained.
    TooComplex,
}

impl RdpImportError {
    /// Authored, bounded banner copy for this refusal.
    ///
    /// Deliberately does not spell the source-format key name (`full
    /// address`) into the message: an authored English sentence stays
    /// readable in every locale, and never reaches for the raw source
    /// text to reconstruct it.
    #[must_use]
    pub fn banner_message(&self) -> String {
        match self {
            Self::MissingAddress => "This .rdp file does not name a host to connect to. \
                 Choose a different file and try again."
                .to_string(),
            Self::TooComplex => "This .rdp file holds more settings than this \
                 app will read. Choose a different file and try again."
                .to_string(),
        }
    }
}

/// Parse a Microsoft `.rdp` file into a profile.
///
/// The format is one `key:type:value` per line, where `type` is `s` (string),
/// `i` (integer) or `b` (binary blob). Every key is optional.
///
/// * A line with fewer than three colon-separated parts is skipped.
/// * A non-integer `i` value is skipped rather than defaulted, so a garbled
///   port does not silently become 3389.
/// * `full address` may carry `host:port`; an explicit `server port` line
///   wins over that port.
///
/// # Errors
///
/// A missing or empty `full address` returns the fieldless [`RdpImportError`];
/// no input byte reaches [`crate::TransferResult::Failed`] or the sidebar alert.
pub fn import_rdp(text: &str, fallback_name: &str) -> Result<ConnectionProfile, RdpImportError> {
    let _budget = crate::import_source::RetainedBudget::open();
    if !crate::import_source::lines_within_bounds(text) {
        return Err(RdpImportError::TooComplex);
    }
    // Each value is admitted before it is copied out of `text`; an oversized
    // host or account is refused rather than dropped, which would dial elsewhere.
    // A function, not a closure: a closure cannot return its argument's borrow,
    // and returning an owned `String` would allocate before the check.
    fn admit(value: &str) -> Result<&str, RdpImportError> {
        crate::import_source::admit_field(value)
            .then_some(value)
            .ok_or(RdpImportError::TooComplex)
    }
    let mut address: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut username = String::new();
    let mut domain: Option<String> = None;
    let mut depth: Option<u8> = None;
    let mut screen_mode: Option<i64> = None;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        // `splitn(3, ..)`: the VALUE may itself contain colons (an IPv6
        // address, a `host:port`), so only the first two separators delimit.
        let mut parts = line.splitn(3, ':');
        let (Some(key), Some(kind), Some(value)) = (parts.next(), parts.next(), parts.next())
        else {
            // Fewer than three fields — not an RDP setting line. Skip it
            // rather than failing the whole file.
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        match (key.as_str(), kind) {
            ("full address", "s") => {
                if !value.is_empty() {
                    address = Some(admit(value)?.to_string());
                }
            }
            ("server port", "i") => {
                // Not `unwrap_or(3389)`: a garbled port must not silently
                // become the default while the user believes it was read.
                port = value.parse::<u16>().ok();
            }
            ("username", "s") => username = admit(value)?.to_string(),
            ("domain", "s") => {
                if !value.is_empty() {
                    domain = Some(admit(value)?.to_string());
                }
            }
            ("session bpp", "i") => depth = value.parse::<u8>().ok(),
            ("screen mode id", "i") => screen_mode = value.parse::<i64>().ok(),
            _ => {}
        }
    }

    // The parser never keeps a raw byte of the failing document in the
    // returned enum — the fieldless [`RdpImportError`] carries only a
    // category. See the type's doc-comment for the audit rationale.
    let address = address.ok_or(RdpImportError::MissingAddress)?;

    // Split an embedded `host:port`, but only for an IPv4/hostname form — an
    // IPv6 literal has many colons and splitting on the last one would eat a
    // hextet. Windows writes IPv6 in brackets when it writes a port at all.
    let (host, embedded_port) = split_host_port(&address);

    let mut p = ConnectionProfile::new(
        if fallback_name.trim().is_empty() {
            host.clone()
        } else {
            fallback_name.trim().to_string()
        },
        Protocol::Rdp,
        host,
    );
    // An explicit `server port` line beats one embedded in the address: it is
    // the more deliberate statement of the two.
    p.port = port
        .or(embedded_port)
        .unwrap_or(Protocol::Rdp.default_port());
    p.username = username;
    p.domain = domain;
    if let Some(d) = depth {
        p.color_depth = d;
    }
    // No fullscreen-at-connect field exists, so `screen mode id: 2` is kept in
    // `extra` rather than silently dropped.
    if let Some(mode) = screen_mode {
        p.extra
            .insert("screen_mode_id".to_string(), mode.to_string());
    }
    Ok(p)
}

/// Split `host:port` when the address is unambiguously of that shape.
///
/// Returns `(host, Some(port))` only for exactly one colon followed by digits
/// that fit a `u16`. An IPv6 literal (several colons) or a trailing garbage
/// port is returned whole, because guessing wrong turns a working address into
/// a broken one.
fn split_host_port(address: &str) -> (String, Option<u16>) {
    let colons = address.matches(':').count();
    if colons != 1 {
        return (address.to_string(), None);
    }
    let (h, p) = address.split_once(':').expect("one colon");
    match p.parse::<u16>() {
        Ok(port) if !h.is_empty() => (h.to_string(), Some(port)),
        _ => (address.to_string(), None),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
