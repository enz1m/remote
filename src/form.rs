//! Connection-form draft state between the persisted model and the view.
//!
//! The draft holds what the model cannot yet:
//!
//! * Ports are text, so half-typed input survives without a default being
//!   invented. [`ConnectionForm::port_value`] is `None` for text that is not a
//!   port; `"0"` is saved as `0`, a zero port being expressible intent.
//! * [`RuleDraft`] keeps destination text across a Local → Dynamic → Local
//!   flip; [`RuleDraft::to_rule`] is where a dynamic forward loses it.
//!
//! Everything here is pure: no iced, no DB, no keyring. The reducer is the
//! only thing that turns a [`PasswordOutcome`] into a keyring write.

use uuid::Uuid;

use crate::model::{
    ConnectionProfile, ForwardDest, ForwardKind, PortForwardRule, PortForwardType, Protocol,
    normalize_mac, quality_from_index, quality_index,
};

// ---------------------------------------------------------------------------
// Field-error strings
// ---------------------------------------------------------------------------
//
// `&'static str` because `enz_text_field::error` borrows for the element's
// lifetime; constants so the view and tests name the same string.

/// Shown under a port field whose text is not a port.
///
/// It names the legal range explicitly, including the `0` that is legal:
/// "required" would be a lie (a `0` port is fine) and "invalid" would not tell
/// the user what to do.
pub const PORT_ERROR: &str = "Enter a port from 0 to 65535";

/// Shown under a destination host that a Local/Remote forward needs and does
/// not have. Never shown for a Dynamic forward, which has no destination.
pub const DEST_HOST_ERROR: &str = "A local or remote forward needs a destination host";

/// Shown under the Wake-on-LAN MAC field for text that is not a MAC. An
/// empty field is not an error; Wake-on-LAN is optional.
pub const MAC_ERROR: &str = "Use aa:bb:cc:dd:ee:ff, aa-bb-… or bare hex";

/// Shown under the attempts field of an enabled reconnect policy whose text is
/// not a finite attempt count this build will act on.
///
/// Shown only while the policy is enabled: an off policy acts on neither
/// number, so flagging one would block a save over a field that changes
/// nothing.
pub const RECONNECT_ATTEMPTS_ERROR: &str = "Enter how many attempts to make, from 1 to 10";

/// Shown under the backoff-ceiling field of an enabled reconnect policy whose
/// text is not a finite number of seconds this build will wait.
pub const RECONNECT_CEILING_ERROR: &str = "Enter the longest wait in seconds, from 1 to 900";

/// The SSH port a fresh jump-host row starts on.
///
/// A jump host is reached over SSH whatever the connection's protocol, so
/// this is 22 rather than `form.protocol.default_port()`.
pub const DEFAULT_SSH_PORT: u16 = 22;

/// The password field's description when nothing is stored yet.
///
/// The secret goes only to Secret Service; an unavailable service raises a
/// failure banner rather than falling back to disk.
pub const PASSWORD_IN_KEYRING: &str = "Saved in the system keyring. Never stored in the database.";

/// The password field's description when a secret is already stored.
///
/// Edit forms do not read the secret back, so without this an empty field
/// reads as "no password".
pub const PASSWORD_IN_KEYRING_STORED: &str = "Saved in the system keyring · type to replace.";

// ---------------------------------------------------------------------------
// Port-forward rule draft
// ---------------------------------------------------------------------------

/// One editable port-forward rule.
///
/// `dest_host` / `dest_port` are retained even while [`Self::forward_type`] is
/// [`PortForwardType::Dynamic`] (which has no destination) so that toggling the
/// direction back and forth does not destroy typed text. They are dropped at
/// the [`Self::to_rule`] boundary, where the model's `ForwardKind::Dynamic`
/// makes their absence structural rather than merely conventional.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleDraft {
    /// Stable identity, carried through an edit so a re-save updates the same
    /// rule rather than appending a duplicate.
    pub id: Uuid,
    pub forward_type: PortForwardType,
    /// Empty asks for OpenSSH's default listener, which is loopback; every
    /// interface is [`crate::model::is_wildcard_bind_address`].
    pub bind_address: String,
    pub bind_port: String,
    pub dest_host: String,
    pub dest_port: String,
    pub label: String,
    pub enabled: bool,
}

impl RuleDraft {
    /// A fresh rule, pre-filled with a Local 8080→localhost:8080 forward.
    ///
    /// These are *initial draft values* for a rule the user just created, not
    /// a silent default applied to something they typed — the distinction
    /// settled decision #3 draws. Pre-filling also means "Add rule" produces a
    /// rule that is already valid, so adding one never blocks Save until every
    /// field is filled in.
    pub fn new_local() -> Self {
        Self {
            id: Uuid::new_v4(),
            forward_type: PortForwardType::Local,
            bind_address: String::new(),
            bind_port: "8080".into(),
            dest_host: "localhost".into(),
            dest_port: "8080".into(),
            label: String::new(),
            enabled: true,
        }
    }

    /// Project a persisted rule into an editable draft.
    ///
    /// A `Dynamic` rule has no destination to project, so the destination text
    /// starts empty; the model cannot tell us what it once was, which is the
    /// point.
    pub fn from_rule(rule: &PortForwardRule) -> Self {
        let (dest_host, dest_port) = match rule.kind.destination() {
            Some(d) => (d.host.clone(), d.port.to_string()),
            None => (String::new(), String::new()),
        };
        Self {
            id: rule.id,
            forward_type: rule.forward_type(),
            bind_address: rule.bind_address.clone(),
            bind_port: rule.bind_port.to_string(),
            dest_host,
            dest_port,
            label: rule.label.clone(),
            enabled: rule.enabled,
        }
    }

    /// The bind port, or `None` when the text is not a port. `"0"` is `Some(0)`.
    pub fn bind_port_value(&self) -> Option<u16> {
        parse_port(&self.bind_port)
    }

    /// The destination port, or `None` when the text is not a port.
    pub fn dest_port_value(&self) -> Option<u16> {
        parse_port(&self.dest_port)
    }

    /// The bind-port field's visible error, if any.
    ///
    /// Unconditional: every direction binds a port, including Dynamic.
    pub fn bind_port_error(&self) -> Option<&'static str> {
        self.bind_port_value().is_none().then_some(PORT_ERROR)
    }

    /// The destination-port field's visible error, if any.
    ///
    /// `None` for a Dynamic forward, which renders no destination fields.
    pub fn dest_port_error(&self) -> Option<&'static str> {
        if !self.forward_type.needs_destination() {
            return None;
        }
        self.dest_port_value().is_none().then_some(PORT_ERROR)
    }

    /// The destination-host field's visible error, if any. `None` for Dynamic,
    /// for the same reason as [`Self::dest_port_error`].
    pub fn dest_host_error(&self) -> Option<&'static str> {
        if !self.forward_type.needs_destination() {
            return None;
        }
        self.dest_host.trim().is_empty().then_some(DEST_HOST_ERROR)
    }

    /// Whether this rule can be persisted.
    ///
    /// A dynamic (SOCKS) forward needs no destination, so its destination
    /// fields are not consulted at all — the one clause in this form that is
    /// not "fill in every field".
    pub fn is_valid(&self) -> bool {
        if self.bind_port_value().is_none() {
            return false;
        }
        if !self.forward_type.needs_destination() {
            return true;
        }
        !self.dest_host.trim().is_empty() && self.dest_port_value().is_some()
    }

    /// The persisted rule, or `None` when the draft is incomplete.
    ///
    /// A dynamic forward drops its destination here; no later round-trip can
    /// recover it.
    pub fn to_rule(&self) -> Option<PortForwardRule> {
        let bind_port = self.bind_port_value()?;
        let kind = match self.forward_type {
            PortForwardType::Dynamic => ForwardKind::Dynamic,
            other => {
                let dest = ForwardDest {
                    host: self.dest_host.trim().to_string(),
                    port: self.dest_port_value()?,
                };
                if dest.host.is_empty() {
                    return None;
                }
                match other {
                    PortForwardType::Local => ForwardKind::Local(dest),
                    _ => ForwardKind::Remote(dest),
                }
            }
        };
        Some(PortForwardRule {
            id: self.id,
            kind,
            bind_address: self.bind_address.clone(),
            bind_port,
            label: self.label.clone(),
            enabled: self.enabled,
        })
    }

    /// The one-line heading the rule's group shows.
    ///
    /// Delegates to [`PortForwardRule::summary`] when the draft is complete, so
    /// the heading is the same `ssh(1)` spelling the persisted rule reports and
    /// cannot drift from it. An incomplete draft says so rather than rendering
    /// a summary of values it does not have.
    pub fn heading(&self) -> String {
        match self.to_rule() {
            Some(rule) => rule.summary(),
            None => format!("{} · incomplete", self.forward_type.label()),
        }
    }
}

/// Parse port text. Empty or non-numeric is `None`; `"0"` is `Some(0)`.
fn parse_port(text: &str) -> Option<u16> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    t.parse::<u16>().ok()
}

// ---------------------------------------------------------------------------
// What a save must do to the keyring
// ---------------------------------------------------------------------------

/// The keyring action a save implies. Computed purely from the draft so the
/// three cases can be tested without a keyring, and so the reducer has exactly
/// one branch per case instead of re-deriving the rule inline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PasswordOutcome {
    /// The user did not touch the password field: the keyring entry and
    /// `has_keyring_password` stay as they were. Edit forms do not read the
    /// secret back, so only `password_dirty` can mean "cleared".
    Unchanged,
    /// Store this secret under the profile's keyring key.
    Set(String),
    /// The user emptied a field they had touched: remove the keyring entry.
    Cleared,
}

// ---------------------------------------------------------------------------
// Unencrypted-VNC acknowledgement
// ---------------------------------------------------------------------------

/// The endpoint a plaintext acknowledgement applies to.
///
/// The host is trimmed and lower-cased; any other change to host or protocol
/// is a different endpoint needing its own answer. The port is excluded, so
/// correcting 5900 to 5901 does not re-ask.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AckedEndpoint {
    pub protocol: Protocol,
    pub host: String,
}

impl AckedEndpoint {
    pub fn of(protocol: Protocol, host: &str) -> Self {
        Self {
            protocol,
            host: host.trim().to_ascii_lowercase(),
        }
    }
}

// ---------------------------------------------------------------------------
// The form draft
// ---------------------------------------------------------------------------

/// Optional sections of a connection draft.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FormSection {
    Organization,
    Options,
    Media,
    SshRouting,
    Display,
}

/// The editable values and expanded sections of a connection form.
#[derive(Debug, Clone)]
pub struct ConnectionForm {
    /// `Some(id)` edits that profile; `None` adds a new one. This is the only
    /// mode flag — there is no separate `is_edit` bool that could disagree
    /// with it.
    pub editing: Option<Uuid>,
    pub connect_on_save: bool,
    pub sections: std::collections::BTreeSet<FormSection>,
    pub name: String,
    pub host: String,
    /// Port text, so a half-typed or zero port survives (see module docs).
    pub port: String,
    /// Whether the user has edited the port. Changing the protocol re-fills an
    /// *untouched* port with the new protocol's default and leaves a touched
    /// one alone, so picking SSH after typing 2222 does not overwrite 2222.
    pub port_touched: bool,
    pub protocol: Protocol,
    pub username: String,
    pub rustdesk_peer_key: String,
    pub rustdesk_id_mode: bool,
    pub rustdesk_server: String,
    pub rustdesk_server_key: String,
    pub rustdesk_relay: String,
    pub moonlight_app_id: String,
    pub moonlight_pair_request: Option<String>,
    pub moonlight_pair_again: bool,
    pub moonlight_resume: bool,
    pub moonlight_gamepads: bool,
    pub audio_enabled: bool,
    pub dynamic_resize: bool,
    pub display_width: String,
    pub display_height: String,
    original_display_size: Option<(u32, u32)>,
    pub vnc_tls: bool,
    /// The secret being typed. Never persisted to SQLite; the reducer routes it
    /// to the keyring.
    pub password: String,
    pub password_revealed: bool,
    /// Whether the user has typed in the password field at all. Distinguishes
    /// "left the field alone" (keep the stored secret) from "emptied it"
    /// (delete the stored secret).
    pub password_dirty: bool,
    /// Whether the profile being edited already had a keyring secret. Drives
    /// the field's subtitle and the `Unchanged` outcome.
    pub had_keyring_password: bool,

    // ---- SSH jump host -------------------------------------------------
    //
    // "Has a tunnel" derives from the host text rather than a flag, so a
    // profile cannot carry a tunnel password without a tunnel.
    /// The jump host to tunnel through. Empty means no tunnel, which is not an
    /// error.
    pub tunnel_host: String,
    /// The jump host's SSH port, as text for the same reason [`Self::port`] is.
    pub tunnel_port: String,
    pub tunnel_username: String,
    pub tunnel_identity: String,
    pub tunnel_legacy_password: bool,
    /// The jump host's password. Never persisted to SQLite; it goes to the
    /// keyring under `KeyringKey::tunnel_password`, distinct from the
    /// connection's own key.
    pub tunnel_password: String,
    pub tunnel_password_dirty: bool,
    /// Whether the profile being edited already had a tunnel secret in the
    /// keyring. Same role `had_keyring_password` plays for the main password.
    pub had_tunnel_password: bool,

    pub rules: Vec<RuleDraft>,

    /// Imported depth retained for export; desktop transports use 32-bit color.
    pub color_depth: u8,

    /// The Options section's picture quality, on the profile's `0..=9` scale.
    ///
    /// Held as the value so an off-rung imported quality survives an edit;
    /// [`quality_index`] selects the rung at or below it. `apply_to` writes it to
    /// the profile and [`crate::protocol::ConnectParams`] carries it to the session.
    pub quality: u8,

    /// Whether the session opens read-only (no input forwarded).
    ///
    /// Persisted on the profile as `view_only` and seeded into the session's
    /// [`crate::session::InputMode`], which is what actually gates the
    /// forward.
    pub view_only: bool,

    /// '/'-delimited folder path. Empty means ungrouped; the sidebar's folder
    /// grouping reads it.
    pub group: String,

    /// Free-form notes.
    pub notes: String,

    /// Wake-on-LAN MAC text, so a half-typed MAC survives. Empty means no
    /// Wake-on-LAN, which is not an error.
    pub wol_mac: String,

    /// Whether clipboard sharing is disabled for this profile.
    ///
    /// Matches the polarity of `ConnectionProfile::disable_clipboard` and the
    /// "Disable clipboard sharing" label.
    pub disable_clipboard: bool,

    /// The endpoint the user accepted plaintext access to, if any.
    ///
    /// Retyping the host or protocol withdraws consent, since the draft then
    /// names a different endpoint. `None` for every new and imported profile.
    pub plaintext_ack: Option<AckedEndpoint>,

    /// Whether this connection reconnects itself after an unexpected loss.
    ///
    /// Off for a new profile, and off for one whose stored policy is off. The
    /// two numbers below are editable either way so a user can set the bounds
    /// before switching the policy on.
    pub reconnect_enabled: bool,
    /// The attempt ceiling as text, for the same reason [`Self::port`] is text.
    pub reconnect_attempts: String,
    /// The longest wait between attempts, in seconds, as text.
    pub reconnect_ceiling: String,
}

impl ConnectionForm {
    /// A blank form for a new profile.
    pub fn for_add() -> Self {
        let protocol = Protocol::Vnc;
        Self {
            editing: None,
            connect_on_save: false,
            sections: Default::default(),
            name: String::new(),
            host: String::new(),
            port: protocol.default_port().to_string(),
            port_touched: false,
            protocol,
            username: String::new(),
            rustdesk_peer_key: String::new(),
            rustdesk_id_mode: false,
            rustdesk_server: String::new(),
            rustdesk_server_key: String::new(),
            rustdesk_relay: String::new(),
            moonlight_app_id: String::new(),
            moonlight_pair_request: None,
            moonlight_pair_again: false,
            moonlight_resume: false,
            moonlight_gamepads: false,
            audio_enabled: true,
            dynamic_resize: false,
            display_width: String::new(),
            display_height: String::new(),
            original_display_size: None,
            vnc_tls: false,
            password: String::new(),
            password_revealed: false,
            password_dirty: false,
            had_keyring_password: false,
            tunnel_host: String::new(),
            tunnel_port: DEFAULT_SSH_PORT.to_string(),
            tunnel_username: String::new(),
            tunnel_identity: String::new(),
            tunnel_legacy_password: false,
            tunnel_password: String::new(),
            tunnel_password_dirty: false,
            had_tunnel_password: false,
            rules: Vec::new(),
            color_depth: 32,
            quality: 6,
            view_only: false,
            group: String::new(),
            notes: String::new(),
            wol_mac: String::new(),
            disable_clipboard: false,
            plaintext_ack: None,
            reconnect_enabled: false,
            reconnect_attempts: crate::reconnect::DEFAULT_MAX_ATTEMPTS.to_string(),
            reconnect_ceiling: crate::reconnect::DEFAULT_BACKOFF_CEILING_SECS.to_string(),
        }
    }

    /// A form pre-filled from an existing profile.
    ///
    /// `port_touched` starts `true`, so changing the protocol never overwrites a
    /// persisted port even when it equals the previous protocol's default.
    pub fn for_profile(p: &ConnectionProfile) -> Self {
        Self {
            editing: Some(p.id),
            connect_on_save: false,
            sections: Default::default(),
            name: p.name.clone(),
            host: p.host.clone(),
            port: p.port.to_string(),
            port_touched: true,
            protocol: p.protocol,
            original_display_size: p.resolution,
            display_width: p
                .resolution
                .map(|size| size.0.to_string())
                .unwrap_or_default(),
            display_height: p
                .resolution
                .map(|size| size.1.to_string())
                .unwrap_or_default(),
            username: p.username.clone(),
            rustdesk_peer_key: p
                .extra
                .get(crate::rustdesk::PEER_KEY)
                .cloned()
                .unwrap_or_default(),
            rustdesk_id_mode: crate::rustdesk::rendezvous::is_id(p),
            rustdesk_server: p
                .extra
                .get(crate::rustdesk::rendezvous::SERVER)
                .cloned()
                .unwrap_or_default(),
            rustdesk_server_key: p
                .extra
                .get(crate::rustdesk::rendezvous::SERVER_KEY)
                .cloned()
                .unwrap_or_default(),
            rustdesk_relay: p
                .extra
                .get(crate::rustdesk::rendezvous::RELAY)
                .cloned()
                .unwrap_or_default(),
            moonlight_app_id: p
                .extra
                .get(crate::moonlight::APP_ID)
                .cloned()
                .unwrap_or_default(),
            moonlight_pair_request: p.extra.get(crate::moonlight::PAIR_REQUEST).cloned(),
            moonlight_pair_again: false,
            moonlight_resume: p
                .extra
                .get(crate::moonlight::RESUME)
                .is_some_and(|v| v == "true"),
            moonlight_gamepads: p
                .extra
                .get(crate::moonlight::GAMEPADS)
                .is_some_and(|v| v == "true"),
            audio_enabled: crate::stream_audio::enabled(p),
            vnc_tls: crate::rfb::policy::requires_tls(p),
            dynamic_resize: p
                .extra
                .get("remote.display.dynamic-resize")
                .is_some_and(|value| value == "true"),
            password: String::new(),
            password_revealed: false,
            password_dirty: false,
            had_keyring_password: p.has_keyring_password,
            tunnel_host: p
                .ssh_tunnel
                .as_ref()
                .map(|t| t.host.clone())
                .unwrap_or_default(),
            tunnel_port: p
                .ssh_tunnel
                .as_ref()
                .map_or_else(|| DEFAULT_SSH_PORT.to_string(), |t| t.port.to_string()),
            tunnel_username: p
                .ssh_tunnel
                .as_ref()
                .map(|t| t.username.clone())
                .unwrap_or_default(),
            tunnel_password: String::new(),
            tunnel_password_dirty: false,
            tunnel_identity: p
                .ssh_tunnel
                .as_ref()
                .and_then(|t| match &t.auth {
                    crate::model::SshAuth::PrivateKey { path } => Some(path.clone()),
                    _ => None,
                })
                .unwrap_or_default(),
            tunnel_legacy_password: p
                .ssh_tunnel
                .as_ref()
                .is_some_and(|t| matches!(t.auth, crate::model::SshAuth::Password)),
            had_tunnel_password: p.ssh_tunnel.as_ref().is_some_and(|t| t.has_tunnel_password),
            rules: p
                .port_forward_rules
                .iter()
                .map(RuleDraft::from_rule)
                .collect(),
            color_depth: p.color_depth,
            quality: p.quality,
            view_only: p.view_only,
            group: p.group.clone(),
            notes: p.notes.clone(),
            wol_mac: p.wol_mac.clone().unwrap_or_default(),
            disable_clipboard: p.disable_clipboard,
            // The stored acknowledgement is read as having been given for the
            // endpoint the profile currently names, which is the only endpoint
            // it could have been dialled at.
            plaintext_ack: match p.protocol {
                Protocol::Vnc if crate::rfb::policy::acknowledged(p) => {
                    Some(AckedEndpoint::of(p.protocol, &p.host))
                }
                Protocol::RustDesk
                    if p.extra.get(crate::rustdesk::ACK_KEY).map(String::as_str)
                        == Some(crate::rfb::policy::ACK_VALUE) =>
                {
                    Some(AckedEndpoint::of(p.protocol, &p.host))
                }
                _ => None,
            },
            reconnect_enabled: p.reconnect.normalized().enabled,
            reconnect_attempts: p.reconnect.normalized().max_attempts.to_string(),
            reconnect_ceiling: p.reconnect.normalized().backoff_ceiling_secs.to_string(),
        }
    }

    /// The endpoint this draft would dial right now.
    pub fn endpoint(&self) -> AckedEndpoint {
        AckedEndpoint::of(self.protocol, &self.host)
    }

    /// Whether the draft carries an acknowledgement for the endpoint it names.
    ///
    /// The switch's checked state and the value written on save are the same
    /// expression, so a form whose host has been retyped cannot render as
    /// acknowledged while saving an acknowledgement, or the reverse.
    #[must_use]
    pub fn plaintext_acknowledged(&self) -> bool {
        let named = self.endpoint();
        self.plaintext_ack
            .as_ref()
            .is_some_and(|acked| acked.protocol == named.protocol && acked.host == named.host)
    }

    /// Record or withdraw the acknowledgement for the endpoint currently named.
    ///
    /// The only writer.
    pub fn set_plaintext_ack(&mut self, accepted: bool) {
        self.plaintext_ack = accepted.then(|| self.endpoint());
    }

    /// Whether the protocol offers explicitly acknowledged plaintext connections.
    #[must_use]
    pub fn plaintext_ack_offered(&self) -> bool {
        (self.protocol == Protocol::Vnc && !self.vnc_tls)
            || (self.protocol == Protocol::RustDesk
                && !self.rustdesk_id_mode
                && !(!self.host.is_empty() && self.host.bytes().all(|byte| byte.is_ascii_digit())))
    }

    /// The dialog title.
    pub fn title(&self) -> &'static str {
        if self.editing.is_some() {
            "Edit Connection"
        } else {
            "New Connection"
        }
    }

    /// The port, or `None` when the text is not a port.
    pub fn port_value(&self) -> Option<u16> {
        parse_port(&self.port)
    }

    /// The port field's visible error, if any.
    pub fn port_error(&self) -> Option<&'static str> {
        self.port_value().is_none().then_some(PORT_ERROR)
    }

    /// The canonical MAC this draft would persist: `None` when the field is
    /// empty or not a MAC.
    ///
    /// Use [`Self::mac_error`] to tell "empty" from "wrong".
    pub fn wol_mac_value(&self) -> Option<String> {
        normalize_mac(&self.wol_mac)
    }

    /// The MAC field's visible error, if any. An empty field is not an error.
    pub fn mac_error(&self) -> Option<&'static str> {
        if self.wol_mac.trim().is_empty() {
            return None;
        }
        self.wol_mac_value().is_none().then_some(MAC_ERROR)
    }

    /// The picker index for [`Self::quality`].
    pub fn quality_index(&self) -> Option<usize> {
        Some(quality_index(self.quality))
    }

    /// Set the quality from a picker index.
    pub fn pick_quality(&mut self, index: usize) {
        self.quality = quality_from_index(index);
    }

    /// Pick a protocol, re-filling an untouched port with its default.
    pub fn pick_protocol(&mut self, protocol: Protocol) {
        self.protocol = protocol;
        if !self.port_touched {
            self.port = protocol.default_port().to_string();
        }
    }

    /// Whether Save may proceed.
    ///
    /// Requires a host, a parseable port, complete port-forward rules,
    /// valid display dimensions, and both bounds of an enabled reconnect policy.
    /// Username, password, bind address and a non-zero port are optional.
    pub fn can_save(&self) -> bool {
        !self.host.trim().is_empty()
            && self.port_value().is_some()
            && self.mac_error().is_none()
            && self.display_size_error().is_none()
            && self.tunnel_port_error().is_none()
            && self.reconnect_attempts_error().is_none()
            && self.reconnect_ceiling_error().is_none()
            && self.rules.iter().all(RuleDraft::is_valid)
    }

    pub(crate) fn display_size_error(&self) -> Option<&'static str> {
        if !matches!(self.protocol, Protocol::Rdp | Protocol::Moonlight)
            || (self.display_width.trim().is_empty() && self.display_height.trim().is_empty())
        {
            return None;
        }
        let size = self
            .display_width
            .trim()
            .parse::<u32>()
            .ok()
            .zip(self.display_height.trim().parse::<u32>().ok());
        let valid = size
            .is_some_and(|(w, h)| (200..=3840).contains(&w) && (200..=2160).contains(&h))
            || (self.editing.is_some() && size.is_some() && size == self.original_display_size);
        (!valid).then_some(
            "Enter both dimensions: width 200–3840 and height 200–2160, or leave both blank.",
        )
    }

    /// The attempt ceiling this draft asks for, or `None` when the text is not
    /// one this build will act on.
    pub fn reconnect_attempts_value(&self) -> Option<u32> {
        let value = self.reconnect_attempts.trim().parse::<u32>().ok()?;
        (1..=crate::reconnect::MAX_ATTEMPTS_CEILING)
            .contains(&value)
            .then_some(value)
    }

    /// The backoff ceiling this draft asks for in seconds, or `None` when the
    /// text is not one this build will wait.
    pub fn reconnect_ceiling_value(&self) -> Option<u32> {
        let value = self.reconnect_ceiling.trim().parse::<u32>().ok()?;
        (1..=crate::reconnect::BACKOFF_CEILING_LIMIT_SECS)
            .contains(&value)
            .then_some(value)
    }

    /// The attempts field's visible error, if any. Never shown while the
    /// policy is off.
    pub fn reconnect_attempts_error(&self) -> Option<&'static str> {
        (self.reconnect_enabled && self.reconnect_attempts_value().is_none())
            .then_some(RECONNECT_ATTEMPTS_ERROR)
    }

    /// The ceiling field's visible error, if any. Never shown while the policy
    /// is off.
    pub fn reconnect_ceiling_error(&self) -> Option<&'static str> {
        (self.reconnect_enabled && self.reconnect_ceiling_value().is_none())
            .then_some(RECONNECT_CEILING_ERROR)
    }

    /// The policy this draft would persist.
    ///
    /// An off policy keeps whichever bounds the fields hold, so switching it
    /// back on does not lose them; an unusable number falls back to the
    /// build's default rather than being persisted as text nothing can act on.
    pub fn reconnect_policy(&self) -> crate::reconnect::ReconnectPolicy {
        crate::reconnect::ReconnectPolicy {
            enabled: self.reconnect_enabled,
            max_attempts: self
                .reconnect_attempts_value()
                .unwrap_or(crate::reconnect::DEFAULT_MAX_ATTEMPTS),
            backoff_ceiling_secs: self
                .reconnect_ceiling_value()
                .unwrap_or(crate::reconnect::DEFAULT_BACKOFF_CEILING_SECS),
        }
        .normalized()
    }

    /// The keyring action this save implies. See [`PasswordOutcome`].
    pub fn password_outcome(&self) -> PasswordOutcome {
        if !self.password_dirty {
            return PasswordOutcome::Unchanged;
        }
        if self.password.is_empty() {
            PasswordOutcome::Cleared
        } else {
            PasswordOutcome::Set(self.password.clone())
        }
    }

    /// Whether this draft configures an SSH jump host.
    ///
    /// Derived from the host text rather than a separate flag: two sources of
    /// truth for "is there a tunnel" is how a profile ends up carrying a tunnel
    /// password for a tunnel it does not have.
    pub fn has_tunnel(&self) -> bool {
        !self.tunnel_host.trim().is_empty()
    }

    /// The jump host's port, or `None` when the text is not a port.
    pub fn tunnel_port_value(&self) -> Option<u16> {
        parse_port(&self.tunnel_port)
    }

    /// The error under the jump-host port field, if any.
    ///
    /// `None` when there is no tunnel: an unparseable port in a field the user
    /// cannot see is not something to complain about, and
    /// [`Self::can_save`] agrees (it only consults this when a tunnel exists).
    pub fn tunnel_port_error(&self) -> Option<&'static str> {
        if !self.has_tunnel() {
            return None;
        }
        if self.tunnel_port_value().is_none() {
            Some(PORT_ERROR)
        } else {
            None
        }
    }

    /// The tunnel keyring action this save implies.
    ///
    /// As [`Self::password_outcome`], except that removing the jump host is
    /// `Cleared`, so no unreachable orphan secret remains.
    pub fn tunnel_password_outcome(&self) -> PasswordOutcome {
        if !self.has_tunnel() {
            // The tunnel is gone. Any stored secret for it must go too.
            return if self.had_tunnel_password {
                PasswordOutcome::Cleared
            } else {
                PasswordOutcome::Unchanged
            };
        }
        if !self.tunnel_password_dirty {
            return PasswordOutcome::Unchanged;
        }
        if self.tunnel_password.is_empty() {
            PasswordOutcome::Cleared
        } else {
            PasswordOutcome::Set(self.tunnel_password.clone())
        }
    }

    /// The connection password's description line.
    pub fn password_hint(&self) -> &'static str {
        if self.had_keyring_password && !self.password_dirty {
            PASSWORD_IN_KEYRING_STORED
        } else {
            PASSWORD_IN_KEYRING
        }
    }

    pub(crate) fn changes_dial_parameters(&self, original: &ConnectionProfile) -> bool {
        if !self.can_save() {
            return false;
        }
        let password_changed =
            self.password_dirty && (original.has_keyring_password || !self.password.is_empty());
        let tunnel_auth = original.ssh_tunnel.as_ref().is_some_and(|tunnel| {
            tunnel.has_tunnel_password || !matches!(tunnel.auth, crate::model::SshAuth::Agent)
        });
        if password_changed
            || (self.tunnel_password_dirty && (tunnel_auth || !self.tunnel_password.is_empty()))
        {
            return true;
        }
        let mut projected = original.clone();
        self.apply_to(&mut projected) && projected.dial_identity() != original.dial_identity()
    }

    /// Write the draft's fields onto `profile`, leaving fields the form does not
    /// edit (`group`, `notes`, `favorite`, timestamps, `resolution`, ...)
    /// untouched.
    ///
    /// Returns `false` (and changes nothing) when the draft cannot be saved.
    pub fn apply_to(&self, profile: &mut ConnectionProfile) -> bool {
        if !self.can_save() {
            return false;
        }
        let Some(port) = self.port_value() else {
            return false;
        };
        profile.name = if self.name.trim().is_empty() {
            self.host.trim().to_string()
        } else {
            self.name.trim().to_string()
        };
        profile.host = self.host.trim().to_string();
        profile.port = port;
        profile.protocol = self.protocol;
        if matches!(self.protocol, Protocol::Rdp | Protocol::Moonlight) {
            profile.resolution = self
                .display_width
                .trim()
                .parse::<u32>()
                .ok()
                .zip(self.display_height.trim().parse::<u32>().ok());
        }
        profile.username = self.username.clone();
        if self.protocol == Protocol::RustDesk {
            if self.rustdesk_id_mode {
                profile
                    .extra
                    .insert(crate::rustdesk::rendezvous::ID_MODE.into(), "true".into());
            } else {
                profile.extra.remove(crate::rustdesk::rendezvous::ID_MODE);
            }
            for (key, value) in [
                (crate::rustdesk::rendezvous::SERVER, &self.rustdesk_server),
                (
                    crate::rustdesk::rendezvous::SERVER_KEY,
                    &self.rustdesk_server_key,
                ),
                (crate::rustdesk::rendezvous::RELAY, &self.rustdesk_relay),
            ] {
                if value.trim().is_empty() {
                    profile.extra.remove(key);
                } else {
                    profile.extra.insert(key.into(), value.trim().into());
                }
            }
            if self.rustdesk_peer_key.trim().is_empty() {
                profile.extra.remove(crate::rustdesk::PEER_KEY);
            } else {
                profile.extra.insert(
                    crate::rustdesk::PEER_KEY.into(),
                    self.rustdesk_peer_key.trim().into(),
                );
            }
        }
        if self.protocol == Protocol::Moonlight {
            if self.moonlight_app_id.trim().is_empty() {
                profile.extra.remove(crate::moonlight::APP_ID);
            } else {
                profile.extra.insert(
                    crate::moonlight::APP_ID.into(),
                    self.moonlight_app_id.trim().into(),
                );
            }
            if let Some(request) = &self.moonlight_pair_request {
                profile
                    .extra
                    .insert(crate::moonlight::PAIR_REQUEST.into(), request.clone());
            } else {
                profile.extra.remove(crate::moonlight::PAIR_REQUEST);
            }
        }
        if !self.audio_enabled {
            profile
                .extra
                .insert(crate::stream_audio::ENABLED.into(), "false".into());
        } else {
            profile.extra.remove(crate::stream_audio::ENABLED);
        }
        if self.protocol == Protocol::Moonlight {
            for (key, enabled) in [
                (crate::moonlight::RESUME, self.moonlight_resume),
                (crate::moonlight::GAMEPADS, self.moonlight_gamepads),
            ] {
                if enabled {
                    profile.extra.insert(key.into(), "true".into());
                } else {
                    profile.extra.remove(key);
                }
            }
        }
        if self.protocol == Protocol::Vnc && self.vnc_tls {
            profile
                .extra
                .insert(crate::rfb::policy::TLS_KEY.into(), "true".into());
        } else {
            profile.extra.remove(crate::rfb::policy::TLS_KEY);
        }
        if self.dynamic_resize {
            profile
                .extra
                .insert("remote.display.dynamic-resize".into(), "true".into());
        } else {
            profile.extra.remove("remote.display.dynamic-resize");
        }
        profile.color_depth = self.color_depth;
        profile.quality = self.quality;
        profile.view_only = self.view_only;
        profile.group = self.group.trim().to_string();
        profile.notes = self.notes.clone();
        profile.disable_clipboard = self.disable_clipboard;
        let ack_key = if self.protocol == Protocol::RustDesk {
            crate::rustdesk::ACK_KEY
        } else {
            crate::rfb::policy::ACK_KEY
        };
        profile.extra.remove(crate::rustdesk::ACK_KEY);
        profile.extra.remove(crate::rfb::policy::ACK_KEY);
        if self.plaintext_ack_offered() && self.plaintext_acknowledged() {
            profile.extra.insert(
                ack_key.to_string(),
                crate::rfb::policy::ACK_VALUE.to_string(),
            );
        } else {
            profile.extra.remove(ack_key);
        }
        // Empty clears the stored MAC; `can_save` refuses unparseable text. The
        // canonical form makes `aa-bb-cc-dd-ee-ff` and `AABBCCDDEEFF` equal.
        profile.wol_mac = self.wol_mac_value();
        profile.port_forward_rules = self.rules.iter().filter_map(RuleDraft::to_rule).collect();
        profile.reconnect = self.reconnect_policy();
        // The marker the user's intent implies; the reducer holds it until the
        // keyring answers (`main_helpers::hold_pending_secret_markers`).
        match self.password_outcome() {
            PasswordOutcome::Unchanged => {}
            PasswordOutcome::Set(_) => profile.has_keyring_password = true,
            PasswordOutcome::Cleared => profile.has_keyring_password = false,
        }

        // Only the `has_tunnel_password` boolean is persisted, never the secret.
        profile.ssh_tunnel = if self.has_tunnel() {
            let previously_stored = profile
                .ssh_tunnel
                .as_ref()
                .is_some_and(|t| t.has_tunnel_password);
            Some(crate::model::SshTunnel {
                host: self.tunnel_host.trim().to_string(),
                port: self.tunnel_port_value().unwrap_or(DEFAULT_SSH_PORT),
                username: self.tunnel_username.clone(),
                // `Agent` unless a secret exists: claiming password auth for an
                // agent-authenticated jump host would misreport how it connects.
                auth: if !self.tunnel_identity.trim().is_empty() {
                    crate::model::SshAuth::PrivateKey {
                        path: self.tunnel_identity.trim().to_owned(),
                    }
                } else {
                    match self.tunnel_password_outcome() {
                        PasswordOutcome::Set(_) => crate::model::SshAuth::Password,
                        PasswordOutcome::Cleared => crate::model::SshAuth::Agent,
                        PasswordOutcome::Unchanged if previously_stored => {
                            crate::model::SshAuth::Password
                        }
                        PasswordOutcome::Unchanged => profile
                            .ssh_tunnel
                            .as_ref()
                            .map(|t| t.auth.clone())
                            .unwrap_or(crate::model::SshAuth::Agent),
                    }
                },
                has_tunnel_password: match self.tunnel_password_outcome() {
                    PasswordOutcome::Set(_) => true,
                    PasswordOutcome::Cleared => false,
                    PasswordOutcome::Unchanged => previously_stored,
                },
            })
        } else {
            // A `SshTunnel` with an empty host is not a tunnel.
            None
        };
        true
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
