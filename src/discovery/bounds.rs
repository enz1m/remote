//! What a browse may cost, and what one advertisement may become.
//!
//! The ceilings, the service-type table and the event state machine sit together
//! because they are one decision about how much of a stranger's broadcast this
//! app holds. Nothing here opens a socket or a bus; [`super::avahi`] feeds the
//! state machine in production and generated events feed it in tests.

use crate::model::Protocol;

/// The longest a single browse may run, however many answers arrive.
///
/// Each of Avahi's browsers ends itself by signalling `AllForNow` once its
/// initial queries have been answered or have timed out, which normally
/// settles inside two seconds. This is the other bound: a browser that never
/// signals must not hold the one discovery worker open, and the section must
/// be able to say the network answered nobody.
pub const BROWSE_BUDGET: std::time::Duration = std::time::Duration::from_secs(4);

/// How long one bounded D-Bus method call may wait for its reply.
///
/// Separate from [`BROWSE_BUDGET`] because it bounds a different failure: a
/// daemon that accepted the connection and then stopped answering. Without it
/// the first call would wait as long as the bus allows, which is forever.
pub const METHOD_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

/// How long the worker waits between looks at the signal queue.
///
/// The queue is drained without blocking, so something has to decide how often
/// to look. Short enough that a browse settles promptly after the last
/// `AllForNow`,
/// long enough that a four-second budget is a few thousand cheap wakeups on
/// one dedicated thread rather than a spin.
pub const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(5);

/// The most advertisements one browse will read, answered or not.
///
/// Reached before anything is retained, so a responder that floods the bus
/// costs this many reads rather than a host for each of them.
pub const MAX_BROWSE_EVENTS: usize = 512;

/// The most hosts one browse will return.
///
/// The section is a list a person scrolls. Past this the answer is not a list
/// of machines to connect to, and truncating is more honest than rendering a
/// thousand rows nobody asked for.
pub const MAX_DISCOVERED_HOSTS: usize = 64;

/// The longest advertised service name this app will keep.
///
/// Above [`crate::display::MAX_DISPLAY_BYTES`], because a stored name may
/// legitimately be longer than its elided presentation, and far below the
/// retained total so no single name can account for it.
pub const MAX_SERVICE_NAME_BYTES: usize = 256;

/// The longest hostname or address this app will keep.
///
/// A DNS name is at most 253 bytes and an IPv6 literal with a zone is far
/// shorter, so anything longer is not a host this app could dial.
pub const MAX_HOST_BYTES: usize = 256;

/// The most addresses one advertisement may offer before it is refused.
///
/// A machine answers with a handful: one IPv4 and one or two IPv6 per
/// interface. A record offering hundreds is describing something else.
pub const MAX_ADDRESSES_PER_SERVICE: usize = 8;

/// The most TXT-record bytes one advertisement may carry.
///
/// None of it is retained — this app dials a host and a port, and a service's
/// own key/value pairs say nothing it can act on. The bound exists because the
/// record still has to be received to be discarded, and a claim of megabytes
/// is a refusal rather than a read.
pub const MAX_TXT_BYTES: usize = 4 * 1024;

/// The DNS-SD service types this app browses, and what each one implies.
///
/// Exactly the protocols the app can save and connect. `_ms-wbt-server._tcp` is
/// what Windows advertises for Remote Desktop and `_rdp._tcp` is used by
/// third-party servers; [`Collector`] deduplicates a host answering on both by
/// endpoint and keeps the first service type as the source.
pub const BROWSED_SERVICES: [(&str, Protocol); 3] = [
    ("_rfb._tcp", Protocol::Vnc),
    ("_rdp._tcp", Protocol::Rdp),
    ("_ms-wbt-server._tcp", Protocol::Rdp),
];

/// The protocol a service type implies, or `None` for one this app does not
/// browse.
///
/// Exact, not a prefix or a contains: `_rfb._tcp` and `_rfb._tcp.local` are
/// different strings and only the registered type is a type. A responder that
/// answers a browse for `_ssh._tcp` with a record naming something else is
/// refused rather than read as SSH.
#[must_use]
pub fn protocol_for_service(service_type: &str) -> Option<Protocol> {
    BROWSED_SERVICES
        .iter()
        .find_map(|(ty, protocol)| (*ty == service_type).then_some(*protocol))
}

/// Which of a browse's service browsers an event came from.
///
/// An index into the browse's own list, assigned where the browsers are
/// created. A browse runs one browser per service type and each signals its
/// own end independently, so an event that did not say which browser produced
/// it would end the whole browse on the first type to finish and truncate the
/// other three.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrowserId(usize);

impl BrowserId {
    /// The browser at `index` in the browse's list.
    #[must_use]
    pub const fn new(index: usize) -> Self {
        Self(index)
    }
}

/// The announced identity of one service, as both `ItemNew` and `ItemRemove`
/// carry it.
///
/// Not the endpoint. A withdrawal names the advertisement and never the
/// address it resolved to, so a row can only be expired if the announcement
/// that produced it was kept beside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceKey {
    /// Avahi's interface index, or `-1` for an answer not tied to one.
    pub interface: i32,
    /// Avahi's address-family selector for the answer.
    pub protocol: i32,
    /// The advertised instance name.
    pub name: String,
    /// The registered DNS-SD type, as advertised.
    pub service_type: String,
    /// The domain the advertisement was seen in.
    pub domain: String,
}

/// One thing a browse can report.
///
/// Carries what Avahi returns and nothing derived from it: no DNS lookup, no
/// connection attempt, no guess at a port. A field this app will not keep is
/// still present here, because the bound has to see it to refuse it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrowseEvent {
    /// One resolved service.
    Resolved(ResolvedService),
    /// One advertisement was withdrawn while the browse was running; its row is
    /// removed, since nobody can connect to it.
    Withdrawn(ServiceKey),
    /// One browser has answered everything it is going to answer for now.
    ///
    /// Lets a quiet network settle well before [`BROWSE_BUDGET`]; the browse ends
    /// when every browser has said this.
    AllForNow(BrowserId),
    /// One browser cannot continue.
    ///
    /// Distinct from a quiet network: one is an answer and the other is the
    /// absence of anyone to ask. It ends that browser and not the others, and
    /// whatever the rest found is still a result.
    Failed(BrowserId),
}

/// One service exactly as Avahi resolved it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedService {
    /// The announcement this answer belongs to, carried so a later withdrawal
    /// can name the row it produced.
    pub key: ServiceKey,
    /// The target host Avahi resolved, which may be a `.local` name.
    pub host: String,
    /// The addresses Avahi resolved for that host, in the order it gave them.
    pub addresses: Vec<String>,
    pub port: u16,
    /// The size of the TXT record, which is checked and then discarded.
    pub txt_bytes: usize,
}

/// Why a browse produced no usable answer.
///
/// Every variant is a category: no pathname, no bus address, no substring of a
/// stranger's advertisement crosses this boundary, and
/// [`Self::banner_message`] is authored at compile time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryRefusal {
    /// The system bus could not be reached at all.
    NoBus,
    /// The bus is there and the Avahi service is not, which is the ordinary
    /// state of a machine without the daemon installed or running.
    NoDaemon,
    /// The daemon accepted the connection and then stopped answering, or went
    /// away while the browse was running.
    DaemonLost,
    /// The budget ran out before the daemon said it had finished. Whatever was
    /// found before the deadline is still reported; this is the refusal only
    /// when nothing was.
    TimedOut,
    /// Another scan holds the one discovery worker.
    Busy,
}

impl DiscoveryRefusal {
    /// Authored, bounded copy for this refusal.
    #[must_use]
    pub fn banner_message(self) -> &'static str {
        match self {
            Self::NoBus => {
                "Network discovery is unavailable on this system: there is no \
                 system message bus to ask."
            }
            Self::NoDaemon => {
                "Network discovery is unavailable: the Avahi service is not \
                 running on this system."
            }
            Self::DaemonLost => "Network discovery stopped responding. Try scanning again.",
            Self::TimedOut => "Network discovery did not finish in time. Try scanning again.",
            Self::Busy => "A scan is already running. Wait for it to finish.",
        }
    }
}

/// What one browse produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiscoveryOutcome {
    /// A browse that ran and reported, including the ordinary case of a
    /// network where nobody answered. An empty list here is a result.
    Found(Vec<super::DiscoveredHost>),
    /// A browse that could not report, as authored copy.
    Refused(DiscoveryRefusal),
}

/// How one browser stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ending {
    /// It delivered everything it had.
    Complete,
    /// It reported that it could not continue.
    Failed,
}

/// What admitting one event did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Kept, or refused on its own merits, and the browse continues.
    Continue,
    /// The browse is over: the daemon finished, a ceiling was reached, or the
    /// daemon went away.
    Stop,
}

/// Turns browse events into the section's hosts, under every ceiling.
///
/// The one place an advertisement becomes a row. Both the real browse and the
/// generated controls feed this, so a bound the transport would have applied
/// differently cannot exist.
#[derive(Debug)]
pub struct Collector {
    hosts: Vec<super::DiscoveredHost>,
    /// The announcement behind each kept row, and the dedup key it took, in
    /// step with `hosts`. What a withdrawal has to be matched against.
    kept: Vec<(ServiceKey, String)>,
    events: usize,
    /// How many browsers this browse is waiting on.
    browsers: usize,
    /// Which browsers ended by saying they had delivered everything.
    completed: Vec<BrowserId>,
    /// Which browsers ended by failing. Disjoint from `completed`, because a
    /// browser ends once and the two outcomes mean different things about
    /// what this browse learned.
    failed: Vec<BrowserId>,
}

impl Collector {
    /// A collector for a browse running `browsers` service browsers.
    ///
    /// The count is what makes the end of the browse knowable. Each browser
    /// signals its own end, so a browse that stopped at the first one would
    /// report whichever service type happened to answer first and silently
    /// drop the rest.
    #[must_use]
    pub fn new(browsers: usize) -> Self {
        Self {
            hosts: Vec::new(),
            kept: Vec::new(),
            events: 0,
            browsers,
            completed: Vec::with_capacity(browsers),
            failed: Vec::with_capacity(browsers),
        }
    }

    /// How many browsers delivered a complete answer.
    ///
    /// The measure of whether this browse learned anything about the network.
    /// A browser that completed and found nothing is an answer; one that
    /// failed is not, and an empty list backed only by failures must not read
    /// as a quiet network.
    #[must_use]
    pub fn completed(&self) -> usize {
        self.completed.len()
    }

    /// How many browsers ended by failing.
    #[must_use]
    pub fn failed(&self) -> usize {
        self.failed.len()
    }

    /// Whether this browse has kept nothing.
    ///
    /// The distinction the caller needs at the deadline: a browse that ran out
    /// of budget having kept nothing has no answer to report, while one that
    /// kept something reports it.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    /// Admit one event.
    ///
    /// A malformed or oversized record is refused on its own and the browse
    /// continues: one hostile answer among twenty real ones must not cost the
    /// other nineteen, and inventing a partial host from the fields that did
    /// pass would put a machine in the list that nobody advertised.
    pub fn admit(&mut self, event: BrowseEvent) -> Admission {
        self.events = self.events.saturating_add(1);
        if self.events > MAX_BROWSE_EVENTS {
            return Admission::Stop;
        }
        match event {
            BrowseEvent::AllForNow(browser) => self.finish_browser(browser, Ending::Complete),
            BrowseEvent::Failed(browser) => self.finish_browser(browser, Ending::Failed),
            BrowseEvent::Withdrawn(key) => {
                self.expire(&key);
                Admission::Continue
            }
            BrowseEvent::Resolved(service) => {
                self.keep(service);
                if self.hosts.len() >= MAX_DISCOVERED_HOSTS {
                    Admission::Stop
                } else {
                    Admission::Continue
                }
            }
        }
    }

    /// Record that one browser has ended, and say whether the browse has.
    ///
    /// Idempotent in the browser, and first-ending-wins: a daemon that
    /// signals twice must not count as two of the browsers this browse is
    /// waiting on, and a browser that failed did not later become one that
    /// answered.
    fn finish_browser(&mut self, browser: BrowserId, ending: Ending) -> Admission {
        let already = self.completed.contains(&browser) || self.failed.contains(&browser);
        if !already {
            match ending {
                Ending::Complete => self.completed.push(browser),
                Ending::Failed => self.failed.push(browser),
            }
        }
        if self.completed.len() + self.failed.len() >= self.browsers {
            Admission::Stop
        } else {
            Admission::Continue
        }
    }

    /// Remove the row one withdrawn advertisement produced, if it produced
    /// one.
    ///
    /// Matched on the announcement, which is all a withdrawal carries. The dedup key
    /// is released too, so a machine that re-advertises in the same browse is offered
    /// again.
    fn expire(&mut self, key: &ServiceKey) {
        let Some(index) = self.kept.iter().position(|(kept, _)| kept == key) else {
            return;
        };
        self.kept.remove(index);
        self.hosts.remove(index);
    }

    /// Everything this browse found, in the order it was found.
    ///
    /// Discovery order is the answer order, which is stable for one network
    /// and one browse; the deduplication below keeps the first answer for an
    /// endpoint, so a re-scan of an unchanged network produces the same list.
    #[must_use]
    pub fn finish(self) -> Vec<super::DiscoveredHost> {
        self.hosts
    }

    fn keep(&mut self, service: ResolvedService) {
        let Some(protocol) = protocol_for_service(&service.key.service_type) else {
            return;
        };
        if service.port == 0
            || service.txt_bytes > MAX_TXT_BYTES
            || service.addresses.len() > MAX_ADDRESSES_PER_SERVICE
            || service.key.name.len() > MAX_SERVICE_NAME_BYTES
            || service.key.domain.len() > MAX_HOST_BYTES
            || service.host.len() > MAX_HOST_BYTES
        {
            return;
        }
        // A resolved address is preferred over its name, which would need a further
        // lookup at connect time; the name is the fallback.
        let Some(endpoint) = service
            .addresses
            .iter()
            .find_map(|raw| normalize_address(raw))
            .or_else(|| normalize_hostname(&service.host))
        else {
            return;
        };
        let name = if service.key.name.trim().is_empty() {
            endpoint.clone()
        } else {
            service.key.name.trim().to_owned()
        };

        // Protocol plus normalized endpoint, so one machine answering on two
        // interfaces or under both RDP service types is one row, while the
        // same address offering VNC and SSH is two.
        let row_key = format!("{}:{}:{}", protocol.key(), endpoint, service.port);
        if self.kept.iter().any(|(_, kept)| *kept == row_key) {
            return;
        }
        // Avahi re-announces on cache refresh; a second row for one identity could not
        // be expired by the single following withdrawal.
        if self.kept.iter().any(|(kept, _)| *kept == service.key) {
            return;
        }

        self.hosts.push(super::DiscoveredHost::discovered(
            name,
            endpoint,
            protocol,
            service.port,
            service.key.service_type.clone(),
            service.key.interface,
        ));
        self.kept.push((service.key, row_key));
    }
}

/// One resolved address as this app will display and dial it, or `None` when
/// it is not an address.
///
/// Parsed rather than trusted. Link-local IPv6 is refused because it needs a zone
/// index this app has no field for.
#[must_use]
pub fn normalize_address(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.len() > MAX_HOST_BYTES {
        return None;
    }
    // A zone suffix is stripped before parsing, because `IpAddr` does not
    // accept one, and then the address is refused on its own merits below.
    let bare = trimmed.split_once('%').map_or(trimmed, |(head, _)| head);
    let address: std::net::IpAddr = bare.parse().ok()?;
    match address {
        std::net::IpAddr::V4(v4) if v4.is_unspecified() || v4.is_loopback() => None,
        std::net::IpAddr::V6(v6) if v6.is_unspecified() || v6.is_loopback() => None,
        // `segments()[0] & 0xffc0 == 0xfe80` is the link-local prefix.
        std::net::IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80 => None,
        // Re-rendered from the parsed value, so two spellings of one address
        // deduplicate against each other rather than becoming two rows.
        other => Some(other.to_string()),
    }
}

/// One resolved hostname as this app will display and dial it, or `None` when
/// it is not a hostname.
///
/// Canonicalised like saved profiles and history so one machine keeps one
/// spelling. Refused when empty or containing characters a hostname may not hold
/// (spaces, control bytes, bidi marks).
#[must_use]
pub fn normalize_hostname(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_HOST_BYTES {
        return None;
    }
    let canonical = crate::quick_connect::canonical_host(trimmed);
    if canonical.is_empty() || canonical.len() > MAX_HOST_BYTES {
        return None;
    }
    let plausible = canonical
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'));
    plausible.then_some(canonical)
}
