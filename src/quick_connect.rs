//! Quick Connect: reaching a host that is not a saved profile, and the short
//! list of hosts recently reached.
//!
//! A recent connection is a host the user dialled; a saved connection is a
//! profile with an id, a folder and a keyring entry. Each recent row offers two
//! distinct actions:
//!
//! * Connect seeds the connection form from the recent and presents it, so the
//!   user confirms (and can supply a password) before a session opens.
//! * Save as a connection (no session) persists the profile and opens nothing.

use chrono::{DateTime, Duration, Utc};

use crate::model::{ConnectionProfile, Protocol};

/// How many recent entries the dialog keeps.
///
/// The cap is the model's job, not the view's, so a sixth
/// entry cannot be one scroll away from a list that claims to hold five.
pub const RECENT_CAP: usize = 5;

// ---------------------------------------------------------------------------
// A recent connection
// ---------------------------------------------------------------------------

/// One host the user has dialled.
///
/// Not a `ConnectionProfile`: no id, folder, keyring flag or notes, only the
/// endpoint, protocol, username offered and time. [`Self::to_profile`] is the one
/// crossing point, as with `discovery::DiscoveredHost`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecentConnection {
    pub host: String,
    pub port: u16,
    pub protocol: Protocol,
    /// The username offered, or empty. Never a password — a recent entry is
    /// display data and Connect re-presents the form with the password blank.
    pub username: String,
    pub connected_at: DateTime<Utc>,
}

impl RecentConnection {
    /// A recent for one endpoint, stored in canonical form.
    ///
    /// The host and port are normalized *here*, not only when the identity is
    /// computed, so the value that is displayed, dialled and written to the
    /// store is the same one that was matched. A list holding both `BOX` and
    /// `box` would dedup correctly and still show two rows.
    pub fn new(
        host: impl Into<String>,
        port: u16,
        protocol: Protocol,
        username: impl Into<String>,
        connected_at: DateTime<Utc>,
    ) -> Self {
        Self {
            host: canonical_host(&host.into()),
            port: effective_port(port, protocol),
            protocol,
            username: username.into(),
            connected_at,
        }
    }

    /// This endpoint's identity: normalized protocol, canonical host and
    /// effective port, and nothing else.
    ///
    /// Shared by the in-memory dedup in [`record`], the `recents` table's primary key,
    /// and row actions, which name a key because every connect re-sorts the list.
    ///
    /// The username is excluded so one machine takes one slot; it remains display
    /// data. No password, token, key path or URI query reaches this value.
    ///
    /// Recomputed and normalized here as well as in [`Self::new`], because the fields
    /// are public and a struct literal must still match its stored row.
    pub fn key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.protocol.key(),
            canonical_host(&self.host),
            effective_port(self.port, self.protocol),
        )
    }

    fn raw_endpoint(&self) -> String {
        let mut p = ConnectionProfile::new("", self.protocol, &self.host);
        p.port = self.port;
        p.host_display()
    }

    /// A bounded, single-line endpoint for recent-row text and action
    /// semantics.
    ///
    /// Display only: the bounding is what keeps a hostile imported host from
    /// reaching a label or an action name. The host in this value's fields and
    /// key is the canonical one, which is what selecting or saving the recent
    /// dials.
    pub fn endpoint(&self) -> String {
        crate::display::bound_host_display(&self.host, self.port, self.protocol.default_port())
    }

    /// The row's detail line: `VNC · alice · 5 minutes ago`, omitting the username
    /// segment when there is none. `now` is injected for testability.
    pub fn detail(&self, now: DateTime<Utc>) -> String {
        let mut out = self.protocol.label().to_string();
        if !self.username.is_empty() {
            out.push_str(" · ");
            out.push_str(&self.username);
        }
        out.push_str(" · ");
        out.push_str(&relative_time(self.connected_at, now));
        out
    }

    /// Copy this endpoint into a brand-new saved profile.
    ///
    /// The new profile gets a fresh `Uuid`, an empty folder and no keyring flag,
    /// since a recent never held a secret. The name is the endpoint, matching the
    /// form's auto-derive rule (`form_view::NAME_SUBTITLE`).
    pub fn to_profile(&self) -> ConnectionProfile {
        let mut p = ConnectionProfile::new(self.raw_endpoint(), self.protocol, &self.host);
        p.port = self.port;
        p.username = self.username.clone();
        debug_assert!(
            !p.has_keyring_password,
            "a recent entry holds no secret, so the profile it mints must not \
             claim one"
        );
        p
    }
}

/// One endpoint's canonical host, so two spellings of one machine share a
/// history row.
///
/// 1. Trim, then strip one surrounding `[...]` pair (IPv6 in a URI).
/// 2. Strip a single trailing `.` (the DNS root label).
/// 3. If the rest parses as an IP address, re-render it from the parsed value,
///    collapsing forms like `::0001`.
/// 4. Otherwise ASCII-lowercase it; Unicode case folding is wrong for DNS labels.
///
/// The stored host may differ from what was typed but addresses the same machine,
/// and it only seeds a form the user confirms.
pub fn canonical_host(raw: &str) -> String {
    let trimmed = raw.trim();
    let unbracketed = trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(trimmed);
    let rootless = unbracketed.strip_suffix('.').unwrap_or(unbracketed);
    if let Ok(ip) = rootless.parse::<std::net::IpAddr>() {
        return ip.to_string();
    }
    rootless.to_ascii_lowercase()
}

/// The port this endpoint is actually reached on.
///
/// A profile may carry `0`, which the form accepts and every dial path reads
/// as the protocol default. Identity has to read it the same way, or
/// `vnc://box` recorded from a defaulted profile and `vnc://box:5900` typed
/// explicitly would be two rows for one socket.
pub fn effective_port(port: u16, protocol: Protocol) -> u16 {
    if port == 0 {
        protocol.default_port()
    } else {
        port
    }
}

/// A coarse "how long ago" recency hint.
///
/// A future time (a clock that stepped backwards) reads as `just now`.
pub fn relative_time(then: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let delta = now.signed_duration_since(then);
    let (key, count) = if delta < Duration::minutes(1) {
        return crate::l10n::text("remote-just-now");
    } else if delta < Duration::hours(1) {
        ("remote-minutes-ago", delta.num_minutes())
    } else if delta < Duration::days(1) {
        ("remote-hours-ago", delta.num_hours())
    } else {
        ("remote-days-ago", delta.num_days())
    };
    crate::l10n::with(key, "count", count)
}

// ---------------------------------------------------------------------------
// The list
// ---------------------------------------------------------------------------

/// Record `entry` as the newest recent connection.
///
/// 1. Newest first.
/// 2. Deduplicated by [`RecentConnection::key`]: a repeat replaces the old entry,
///    advancing its timestamp and username. The `recents` table keys on the same
///    identity.
/// 3. Capped at [`RECENT_CAP`] in the model.
pub fn record(list: &mut Vec<RecentConnection>, entry: RecentConnection) {
    let key = entry.key();
    list.retain(|e| e.key() != key);
    list.insert(0, entry);
    list.truncate(RECENT_CAP);
}

/// Find the recent entry with this key.
pub fn find<'a>(list: &'a [RecentConnection], key: &str) -> Option<&'a RecentConnection> {
    list.iter().find(|e| e.key() == key)
}

// ---------------------------------------------------------------------------
// Address entry
// ---------------------------------------------------------------------------

/// The Quick Connect address entry's supported grammar.
///
/// # Accepted
///
/// * A URI: `<scheme>://[user@]host[:port][/rest]`, where `<scheme>` is the
///   [`Protocol::key`] of any protocol this app can describe (plus
///   `sunshine` / `gamestream` for Moonlight). `/rest` is ignored, and a `user@`
///   prefix pre-fills the profile's username. Whether the scheme can be dialled
///   is [`parse_connectable`]'s question.
/// * `host:port`: the protocol falls back to VNC.
/// * A bare host (`box.internal`, `10.0.0.5`, a bracketed IPv6 literal): VNC, on
///   the protocol's [`Protocol::default_port`].
///
/// # Refused
///
/// * An empty string.
/// * A recognised URI scheme with an empty host (`ssh:///` etc).
/// * A port that does not parse as `u16`, including junk after `:port`.
/// * A URI whose scheme names no protocol, so a pasted `http://` URL errors
///   instead of connecting to a web server as VNC.
///
/// Refusals are typed errors so the view can render the reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedAddress {
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub username: String,
}

/// Typed reasons an address cannot be admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddressParseError {
    /// The field was empty or whitespace only.
    Empty,
    /// A URI scheme was present but is not supported.
    UnsupportedScheme(String),
    /// The host was missing (empty authority, or a stray `:port` with no host).
    EmptyHost,
    /// The `:port` segment did not parse as a `u16`.
    BadPort(String),
    /// The address named a protocol this build has no backend for.
    ///
    /// Distinct from [`Self::UnsupportedScheme`]: saying "unsupported scheme"
    /// for a well-formed `rdp://` would blame the user's typing for a property
    /// of the build. Raised by [`parse_connectable`], not [`parse_address`],
    /// because availability is not a property of the text.
    UnavailableProtocol(Protocol),
}

impl AddressParseError {
    pub fn inline_error(&self) -> String {
        match self {
            Self::Empty => crate::l10n::text("remote-address-empty"),
            Self::EmptyHost => crate::l10n::text("remote-address-no-host"),
            Self::UnsupportedScheme(s) => {
                crate::l10n::with("remote-address-scheme-error", "scheme", s)
            }
            Self::BadPort(p) => crate::l10n::with("remote-address-port-error", "port", p),
            Self::UnavailableProtocol(p) => {
                crate::l10n::with("remote-address-protocol-error", "protocol", p.label())
            }
        }
    }
}

/// [`parse_address`], then refuse a protocol this build cannot dial.
///
/// The entry point the reducer uses. Quick Connect is a creation route, so a
/// protocol with no backend is refused here as in the form's picker; a bare host
/// parses as the default protocol and is checked too. `available` is a parameter
/// so this stays pure.
pub fn parse_connectable(
    input: &str,
    available: impl Fn(Protocol) -> bool,
) -> Result<ParsedAddress, AddressParseError> {
    let parsed = parse_address(input)?;
    if !available(parsed.protocol) {
        return Err(AddressParseError::UnavailableProtocol(parsed.protocol));
    }
    Ok(parsed)
}

/// Parse a Quick Connect address into a [`ParsedAddress`] or a typed refusal.
///
/// Pure and deterministic: no DNS, no socket, no environment.
pub fn parse_address(input: &str) -> Result<ParsedAddress, AddressParseError> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err(AddressParseError::Empty);
    }

    // ---- URI form ---------------------------------------------------------
    //
    // Not `url::Url`, which accepts every web scheme. Split on the first `://`;
    // the path after the authority is ignored because the target is a host.
    if let Some((scheme, rest)) = raw.split_once("://") {
        let scheme_lc = scheme.trim().to_ascii_lowercase();
        // Derived from `Protocol::key` so schemes and picker options cannot disagree;
        // the aliases have no key and stay explicit.
        let protocol = Protocol::all()
            .iter()
            .copied()
            .find(|p| p.key() == scheme_lc.as_str())
            .or(match scheme_lc.as_str() {
                "sunshine" | "gamestream" => Some(Protocol::Moonlight),
                _ => None,
            });
        let Some(protocol) = protocol else {
            return Err(AddressParseError::UnsupportedScheme(scheme_lc));
        };
        // Strip a trailing `/...` path if present.
        let authority = match rest.split_once('/') {
            Some((auth, _)) => auth,
            None => rest,
        };
        let (username, host_port) = match authority.split_once('@') {
            Some((u, hp)) => (u.to_owned(), hp),
            None => (String::new(), authority),
        };
        let (host, port) = split_host_port(host_port, protocol)?;
        if host.is_empty() {
            return Err(AddressParseError::EmptyHost);
        }
        return Ok(ParsedAddress {
            protocol,
            host,
            port,
            username,
        });
    }

    // ---- Bare host / host:port -------------------------------------------
    let protocol = Protocol::Vnc; // default fallback
    let (host, port) = split_host_port(raw, protocol)?;
    if host.is_empty() {
        return Err(AddressParseError::EmptyHost);
    }
    Ok(ParsedAddress {
        protocol,
        host,
        port,
        username: String::new(),
    })
}

/// Split `host:port`, a bare host, or a bracketed IPv6 literal into a host and a
/// numeric port.
///
/// Both branches of [`parse_address`] call this, so there is one port parser and
/// one refusal vocabulary. A bracketed host may contain colons and the port is
/// optional; unbracketed, the last `:` separates the port and any remaining `:`
/// is a malformed IPv6 literal. Every port failure maps to
/// [`AddressParseError::BadPort`].
fn split_host_port(input: &str, protocol: Protocol) -> Result<(String, u16), AddressParseError> {
    let s = input.trim();
    // `[::1]:5900` — bracketed IPv6 literal. Rare in this app's audience but
    // free to support once and unambiguous.
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((host, tail)) = rest.split_once(']') {
            let host = host.to_owned();
            let port = if tail.is_empty() {
                protocol.default_port()
            } else if let Some(p) = tail.strip_prefix(':') {
                if p.is_empty() {
                    return Err(AddressParseError::BadPort(String::new()));
                }
                p.parse::<u16>()
                    .map_err(|_| AddressParseError::BadPort(p.to_owned()))?
            } else {
                return Err(AddressParseError::BadPort(tail.to_owned()));
            };
            return Ok((host, port));
        }
        return Err(AddressParseError::EmptyHost);
    }
    // The last `:` decides; a stray colon fails the `u16` parse, so
    // `1.2.3.4:not-a-port` is refused rather than guessed.
    match s.rsplit_once(':') {
        Some((host, port_txt)) if !host.is_empty() && !port_txt.is_empty() => {
            // But: an unbracketed IPv6 literal has many colons; if `host`
            // still contains one, this is not `host:port`, this is a
            // malformed IPv6. Refuse rather than guess.
            if host.contains(':') {
                return Err(AddressParseError::BadPort(port_txt.to_owned()));
            }
            let port = port_txt
                .parse::<u16>()
                .map_err(|_| AddressParseError::BadPort(port_txt.to_owned()))?;
            Ok((host.to_owned(), port))
        }
        Some(("", port_txt)) => {
            // `:port` with no host. `EmptyHost` is louder than `BadPort`
            // here — the user is missing a whole field.
            let _ = port_txt;
            Err(AddressParseError::EmptyHost)
        }
        Some((_, port_txt)) => Err(AddressParseError::BadPort(port_txt.to_owned())),
        None => Ok((s.to_owned(), protocol.default_port())),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
