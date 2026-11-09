//! Network discovery: the Discovered sidebar section.
//!
//! A discovered host is a separate collection, not a flagged profile: it has no
//! user-chosen id, folder or credentials and disappears when a scan no longer
//! finds it. The app holds `Vec<DiscoveredHost>` beside `Vec<ConnectionProfile>`,
//! and [`DiscoveredHost::to_profile`] is the one explicit crossing point
//! (`tests::a_discovered_host_is_not_a_profile_until_it_is_saved`).
//!
//! Scanning is behind a trait so network I/O stays out of `update()` and tests
//! can substitute a fixture. [`avahi::AvahiScanner`] is the shipping
//! implementation; [`StubScanner`] serves the capture harness and tests.
//!
//! * [`bounds`] decides what a browse may cost and what one advertisement may
//!   become; it opens nothing.
//! * [`avahi`] is the structured system-bus browse.
//! * [`owner`] is the bounded owner it runs on, which refuses a second
//!   simultaneous scan.

mod avahi;
pub mod bounds;
mod owner;

pub use avahi::AvahiScanner;
pub use bounds::{DiscoveryOutcome, DiscoveryRefusal};
pub use owner::{PendingScan, dispatch};

use crate::model::Protocol;

/// One host a scan found.
///
/// Not a `ConnectionProfile`: no id, group, credentials or keyring flag, only
/// what a discovery protocol reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredHost {
    /// The advertised service name, or the hostname when there is none.
    pub name: String,
    /// The address to dial.
    pub host: String,
    pub port: u16,
    /// The protocol the advertised service type implies.
    pub protocol: Protocol,
    /// The DNS-SD service type this came from, and the interface index it
    /// arrived on.
    ///
    /// Kept beside the endpoint: two answers for one endpoint share a row, which
    /// records the advertisement that answered first. Excluded from [`Self::key`] so
    /// a re-scan hearing another advertisement first does not rename the row.
    pub source: Option<DiscoverySource>,
}

/// Where one discovered row came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoverySource {
    /// The registered DNS-SD type as advertised.
    pub service_type: String,
    /// Avahi's interface index, or `-1` for an answer not tied to one.
    pub interface: i32,
}

impl DiscoveredHost {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        protocol: Protocol,
        port: u16,
    ) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port,
            protocol,
            source: None,
        }
    }

    /// One host a real browse resolved, carrying the advertisement it came
    /// from.
    pub fn discovered(
        name: impl Into<String>,
        host: impl Into<String>,
        protocol: Protocol,
        port: u16,
        service_type: impl Into<String>,
        interface: i32,
    ) -> Self {
        Self {
            source: Some(DiscoverySource {
                service_type: service_type.into(),
                interface,
            }),
            ..Self::new(name, host, protocol, port)
        }
    }

    /// The subtitle the discovered row shows.
    pub fn subtitle(&self) -> String {
        format!("{} · {}:{}", self.protocol.label(), self.host, self.port)
    }

    /// A stable key for this host, so the Save action never names an index that a
    /// re-scan could reorder.
    pub fn key(&self) -> String {
        format!("{}:{}:{}", self.protocol.key(), self.host, self.port)
    }

    /// Copy this host into a brand-new saved profile.
    ///
    /// The discovered entry stays in `discovered`; the new profile gets a fresh
    /// `Uuid`, an empty folder and no credentials.
    pub fn to_profile(&self) -> crate::model::ConnectionProfile {
        let mut p = crate::model::ConnectionProfile::new(&self.name, self.protocol, &self.host);
        p.port = self.port;
        p
    }
}

/// Something that can find hosts on the network.
///
/// `Send + Sync` because the reducer hands it to the bounded blocking owner in
/// [`owner`], which runs it on a thread of its own.
pub trait HostScanner: Send + Sync + std::fmt::Debug {
    /// Browse, returning what was found or why nothing could be.
    ///
    /// An empty [`DiscoveryOutcome::Found`] means nobody answered, which differs from
    /// a browse that could not run (no system bus, no daemon, an unresponsive daemon,
    /// or an exhausted budget); the section renders them with different remedies.
    ///
    /// Implementations should notice `cancelled` promptly, release what they hold
    /// and return; mid-syscall interruption is not required.
    fn scan(&self, cancelled: &std::sync::atomic::AtomicBool) -> DiscoveryOutcome;
}

/// A deterministic scanner, used until real mDNS lands.
#[derive(Debug, Clone, Default)]
pub struct StubScanner {
    hosts: Vec<DiscoveredHost>,
}

impl StubScanner {
    /// A scanner that finds exactly this set.
    ///
    /// The only constructor that yields an arbitrary host list, so it is not
    /// `#[cfg(test)]`d: it is the injection seam for real scanner results.
    #[allow(dead_code)] // The injection seam for a real scanner's results.
    pub fn with_hosts(hosts: Vec<DiscoveredHost>) -> Self {
        Self { hosts }
    }
}

impl HostScanner for StubScanner {
    fn scan(&self, cancelled: &std::sync::atomic::AtomicBool) -> DiscoveryOutcome {
        if cancelled.load(std::sync::atomic::Ordering::SeqCst) {
            return DiscoveryOutcome::Refused(DiscoveryRefusal::Busy);
        }
        DiscoveryOutcome::Found(self.hosts.clone())
    }
}

/// The Discover section's header.
///
/// The section is pinned to the bottom of the sidebar and is empty until the
/// user presses the radar chip, so the band names the action available there,
/// not a set of findings (`Discovered`) the app does not have.
pub const DISCOVER_HEADER: &str = "Discover";

/// The loading label for a scan in flight.
///
/// Used as the chip's tooltip and as a status line in the section body while a
/// running scan has found nothing yet, so the state is not hover-only. Distinct
/// from every empty state;
/// `quick_connect::tests::the_recents_empty_state_is_distinct_from_the_scanning_and_list_states`
/// pins it. Spelled with the single `…` codepoint like every other in-progress
/// string in the app.
pub const SCANNING_LABEL: &str = "Scanning…";

/// The chip's tooltip while a scan is running / idle.
///
/// While a browse runs the chip's action is to abandon it, so the tooltip is
/// what pressing it would do rather than what is happening. A disabled chip
/// would leave the user watching a bounded browse with nothing to press, and
/// [`SCANNING_LABEL`] is already published as the status line beneath it.
pub fn scan_tooltip(scanning: bool) -> &'static str {
    if scanning {
        STOP_SCANNING
    } else {
        "Scan network"
    }
}

/// The chip's action while a browse is running.
pub const STOP_SCANNING: &str = "Stop scanning";

/// The Discovered section's body line, or `None` when the section's rows speak
/// for themselves.
///
/// | scanning | scanned once | hosts | line |
/// |---|---|---|---|
/// | yes | any | any | [`SCANNING_LABEL`] — a scan can find *more* |
/// | no | no | none | `None` — nobody has asked yet |
/// | no | yes | none | [`NO_HOSTS_FOUND`] — the press produced an answer |
/// | no | any | some | `None` — the rows are the answer |
///
/// The idle-and-empty case is silent because nothing has been scanned yet.
pub fn scan_status_line(
    scanning: bool,
    host_count: usize,
    scanned_once: bool,
) -> Option<&'static str> {
    if scanning {
        return Some(SCANNING_LABEL);
    }
    // `scanned_once` separates "nobody answered" from "nobody has asked", so a
    // finished empty scan has a visible result.
    if scanned_once && host_count == 0 {
        return Some(NO_HOSTS_FOUND);
    }
    None
}

/// The line a completed scan with no results shows, distinct from
/// [`SCANNING_LABEL`] and from the idle silence.
pub const NO_HOSTS_FOUND: &str = "No hosts found on this network";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {}
