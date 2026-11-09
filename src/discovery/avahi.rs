//! The Avahi browse, on the one discovery worker.
//!
//! Structured D-Bus on the system bus through the crate's own zbus: no
//! subprocess, no `PATH` lookup and no private bus.
//!
//! [`browse`] runs entirely on the worker thread [`super::owner`] owns, never
//! touches application state and never returns a partial result. No runtime,
//! executor or timer thread is created here: `zbus::blocking` keeps one
//! process-wide reactor, the signal queue is drained without blocking, and the
//! deadline is a clock comparison.
//!
//! # Custody
//!
//! Avahi objects are daemon-side state that lives until freed, so [`Session`]
//! owns their paths and frees them in `Drop` on every exit path. The signal
//! stream is retired with it (see [`Signals`]), and one server proxy serves the
//! whole browse.
//!
//! # Whose answers these are
//!
//! A match rule selects by sender and interface, so other programs' browses on
//! the same daemon arrive on the same stream. Every signal is checked against
//! this browse's own object paths. The browse ends when every browser has
//! signalled its end.

type ResolveReply = (
    i32,
    i32,
    String,
    String,
    String,
    String,
    i32,
    String,
    u16,
    Vec<Vec<u8>>,
    u32,
);

use super::bounds::{
    Admission, BROWSE_BUDGET, BROWSED_SERVICES, BrowseEvent, BrowserId, Collector,
    DiscoveryOutcome, DiscoveryRefusal, METHOD_BUDGET, POLL_INTERVAL, ResolvedService, ServiceKey,
};

/// The shipping scanner: one bounded Avahi browse per press.
///
/// Holds nothing. Every scan opens its own connection, creates its own
/// browsers and frees them before returning, so the type carries no state a
/// stale answer could be assembled from and two scans cannot share a
/// half-finished browse.
#[derive(Debug, Clone, Copy, Default)]
pub struct AvahiScanner;

impl super::HostScanner for AvahiScanner {
    fn scan(&self, cancelled: &std::sync::atomic::AtomicBool) -> DiscoveryOutcome {
        browse(cancelled)
    }
}

/// The well-known name, paths and interfaces this module addresses.
///
/// Spelled once. A browse that addressed a name assembled at the call site
/// could be pointed somewhere else by a later edit without any test noticing.
const AVAHI_NAME: &str = "org.freedesktop.Avahi";
const AVAHI_ROOT: &str = "/";
const SERVER_INTERFACE: &str = "org.freedesktop.Avahi.Server";
const BROWSER_INTERFACE: &str = "org.freedesktop.Avahi.ServiceBrowser";

/// Avahi's "any interface" and "any address family" selectors, and the
/// empty flag set.
///
/// Passed explicitly rather than left to a default: a browse restricted to one
/// interface would silently miss the machine on the other one, and a browse
/// asking for one address family would miss a v6-only host.
const IF_UNSPEC: i32 = -1;
const PROTO_UNSPEC: i32 = -1;
const NO_FLAGS: u32 = 0;

/// Everything one browse owns on the bus.
///
/// The connection, the one proxy that addresses the daemon's server object,
/// and the service-browser objects this browse asked the daemon to create.
/// A proxy owns a clone of its connection, so holding both here is what makes
/// the paths unable to outlive the bus they live on.
struct Session {
    connection: zbus::blocking::Connection,
    server: zbus::blocking::Proxy<'static>,
    paths: Vec<zbus::zvariant::OwnedObjectPath>,
}

impl Session {
    /// Which of this browse's browsers a signal came from, or `None` for a
    /// signal that did not come from one of them.
    fn browser_at(&self, path: &zbus::zvariant::ObjectPath<'_>) -> Option<BrowserId> {
        self.paths
            .iter()
            .position(|owned| owned.as_str() == path.as_str())
            .map(BrowserId::new)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        for path in std::mem::take(&mut self.paths) {
            // Best effort: the daemon may be gone and there is nowhere to report the
            // failure. Bounded, so a wedged daemon costs one method budget per browser.
            let _ = zbus::blocking::Proxy::new(
                &self.connection,
                AVAHI_NAME,
                path.as_str(),
                BROWSER_INTERFACE,
            )
            .and_then(|proxy| proxy.call::<_, _, ()>("Free", &()));
        }
    }
}

/// Browse for every service type this app supports, and report.
///
/// One connection, one server proxy and one browser per service type, all
/// freed before this returns. The browse ends when every browser has reported
/// its own end; the deadline is the end when one of them never does.
///
/// `cancelled` is read between looks at the signal queue. A cancelled browse
/// returns a refusal rather than a host list, so a scan the user abandoned
/// installs nothing.
fn browse(cancelled: &std::sync::atomic::AtomicBool) -> DiscoveryOutcome {
    match system_bus() {
        Ok(connection) => browse_on(&connection, cancelled),
        Err(refusal) => DiscoveryOutcome::Refused(refusal),
    }
}

/// Browse on a connection that is already open.
///
/// [`browse`] only chooses the bus; this split lets tests act as the daemon on
/// the other end. Takes a borrow and clones the handle so such a caller keeps the
/// connection.
pub(crate) fn browse_on(
    connection: &zbus::blocking::Connection,
    cancelled: &std::sync::atomic::AtomicBool,
) -> DiscoveryOutcome {
    use std::sync::atomic::Ordering;

    let mut session = match attach(connection) {
        Ok(session) => session,
        Err(refusal) => return DiscoveryOutcome::Refused(refusal),
    };

    // One signal stream for the whole browse, established before any browser
    // exists so an answer to the first cannot arrive before anything is
    // listening. Dropping it deregisters the match rule.
    let Ok(stream) = signals(&session.connection) else {
        return DiscoveryOutcome::Refused(DiscoveryRefusal::DaemonLost);
    };
    let mut stream = Signals(Some(stream));

    for (service_type, _) in BROWSED_SERVICES {
        match new_browser(&session.server, service_type) {
            Ok(path) => session.paths.push(path),
            // A daemon that refuses one type will refuse the rest; reporting
            // the first failure is more useful than four identical ones.
            Err(refusal) => return DiscoveryOutcome::Refused(refusal),
        }
    }

    let mut collector = Collector::new(session.paths.len());
    let mut pending: std::collections::VecDeque<Signal> = std::collections::VecDeque::new();
    let deadline = std::time::Instant::now() + BROWSE_BUDGET;
    let mut settled = false;
    while !settled {
        if cancelled.load(Ordering::SeqCst) {
            return DiscoveryOutcome::Refused(DiscoveryRefusal::Busy);
        }
        // Checked every pass: each announcement costs a bounded resolve, so a full
        // queue would otherwise exceed the browse budget.
        if std::time::Instant::now() >= deadline {
            break;
        }

        // Drain before resolving: zbus feeds streams through a fixed-capacity channel,
        // and a full stream stalls the socket reader that also carries the replies to
        // the calls below.
        match stream.drain(&session, &mut pending) {
            Drained::Closed => return DiscoveryOutcome::Refused(DiscoveryRefusal::DaemonLost),
            Drained::Ready => {}
        }

        let Some(signal) = pending.pop_front() else {
            // Nothing queued and nothing outstanding. The wait is on this
            // thread, which the worker owns; no executor worker and no timer
            // thread is involved.
            std::thread::sleep(POLL_INTERVAL);
            continue;
        };
        let event = match signal {
            Signal::Announced(key) => match resolve(&session.server, key) {
                Some(service) => BrowseEvent::Resolved(service),
                // A record the daemon would not resolve is not a machine, and
                // it ends nothing.
                None => continue,
            },
            Signal::Withdrawn(key) => BrowseEvent::Withdrawn(key),
            Signal::AllForNow(browser) => BrowseEvent::AllForNow(browser),
            Signal::Failed(browser) => BrowseEvent::Failed(browser),
        };
        if collector.admit(event) == Admission::Stop {
            settled = true;
        }
    }

    // Hosts already resolved stay valid even if a browser failed or the budget
    // expired.
    if !collector.is_empty() {
        return DiscoveryOutcome::Found(collector.finish());
    }
    // One completed browser is an answer for its service type; only a browse where
    // nothing completed has learned nothing.
    if collector.completed() > 0 {
        return DiscoveryOutcome::Found(Vec::new());
    }
    if collector.failed() > 0 {
        return DiscoveryOutcome::Refused(DiscoveryRefusal::DaemonLost);
    }
    // Silence cannot distinguish a slow network from a dead daemon, so it is asked;
    // the two outcomes offer different remedies.
    DiscoveryOutcome::Refused(if answering(&session.server) {
        DiscoveryRefusal::TimedOut
    } else {
        DiscoveryRefusal::DaemonLost
    })
}

/// Open the system bus, bounded.
///
/// The system bus, not the session bus: Avahi ships
/// `org.freedesktop.Avahi.service` as a system service and its browsers are
/// machine-wide state, so a session-bus connection would find nobody by that
/// name however well the daemon is running. This is the only place the
/// shipping scan decides which bus it is on.
fn system_bus() -> Result<zbus::blocking::Connection, DiscoveryRefusal> {
    bounded_connection(
        zbus::blocking::connection::Builder::system().map_err(|_| DiscoveryRefusal::NoBus)?,
    )
}

/// Finish building a connection under this module's method budget.
///
/// The budget is applied here rather than at each call site because it is the
/// only thing bounding a method reply: a daemon that accepts a call and never
/// answers it would otherwise hold the worker thread for as long as it liked.
/// Shared with anything that supplies its own address, so a connection to a
/// different bus is bounded on the same terms as the system one.
pub(crate) fn bounded_connection(
    builder: zbus::blocking::connection::Builder<'_>,
) -> Result<zbus::blocking::Connection, DiscoveryRefusal> {
    builder
        .method_timeout(METHOD_BUDGET)
        .build()
        .map_err(|_| DiscoveryRefusal::NoBus)
}

/// Address the daemon on an open connection and confirm it is answering.
///
/// The version call is the reachability probe, and it is what separates a
/// machine with no bus from one whose bus has no Avahi: both render as
/// "discovery is unavailable" and they are different sentences. The proxy it
/// probes with is the one the rest of the browse uses.
fn attach(connection: &zbus::blocking::Connection) -> Result<Session, DiscoveryRefusal> {
    let server = zbus::blocking::Proxy::new(connection, AVAHI_NAME, AVAHI_ROOT, SERVER_INTERFACE)
        .map_err(|_| DiscoveryRefusal::NoDaemon)?;
    if !answering(&server) {
        return Err(DiscoveryRefusal::NoDaemon);
    }
    Ok(Session {
        connection: connection.clone(),
        server,
        paths: Vec::new(),
    })
}

/// Whether the daemon answers a bounded question right now.
///
/// Used to open a browse and to word an empty, out-of-budget result: slow versus
/// gone.
fn answering(server: &zbus::blocking::Proxy<'static>) -> bool {
    server.call::<_, _, String>("GetVersionString", &()).is_ok()
}

/// Ask the daemon for one service browser.
///
/// `ServiceBrowserNew` begins browsing as it is created, which is why the
/// signal stream is established first. The prepare-then-start pair the same
/// interface offers exists for callers that cannot do that, and this one can.
fn new_browser(
    server: &zbus::blocking::Proxy<'static>,
    service_type: &str,
) -> Result<zbus::zvariant::OwnedObjectPath, DiscoveryRefusal> {
    // The empty domain is "this machine's own", which for DNS-SD is `.local`.
    // Naming it explicitly would restrict the browse to one domain on a host
    // configured for more.
    server
        .call::<_, _, zbus::zvariant::OwnedObjectPath>(
            "ServiceBrowserNew",
            &(IF_UNSPEC, PROTO_UNSPEC, service_type, "", NO_FLAGS),
        )
        .map_err(|_| DiscoveryRefusal::DaemonLost)
}

/// Listen for the signals Avahi's service browsers emit.
///
/// One stream narrowed to the browser interface, since a match rule cannot name
/// several objects; each message is then checked against this browse's paths.
/// Built via the blocking constructor, which installs the rule on zbus's shared
/// reactor, then unwrapped so the queue can be polled without waiting. Dropping
/// the stream deregisters the rule.
fn signals(connection: &zbus::blocking::Connection) -> zbus::Result<zbus::MessageStream> {
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .sender(AVAHI_NAME)?
        .interface(BROWSER_INTERFACE)?
        .build();
    // One queued message per event this browse will read, so a flood is
    // bounded by the channel rather than by memory.
    zbus::blocking::MessageIterator::for_match_rule(
        rule,
        connection,
        Some(super::bounds::MAX_BROWSE_EVENTS),
    )
    .map(zbus::blocking::MessageIterator::into_inner)
}

/// One signal, read and understood but not yet acted on.
///
/// Free of I/O so every waiting message can be read cheaply and the bus queue
/// never stays full.
enum Signal {
    /// An advertisement worth resolving.
    Announced(ServiceKey),
    /// An advertisement that has gone away.
    Withdrawn(ServiceKey),
    /// One browser has delivered everything it has.
    AllForNow(BrowserId),
    /// One browser cannot continue.
    Failed(BrowserId),
}

/// Whether the connection is still there after a drain.
enum Drained {
    /// Everything queued has been taken.
    Ready,
    /// The stream ended, which for a bus connection means the peer is gone.
    Closed,
}

/// The browse's signal stream, retired where its deregistration can run.
///
/// Dropping a rule-bound `MessageStream` spawns a `RemoveMatch` task on tokio,
/// which panics outside a tokio runtime, which is every thread here. Retiring it
/// through the blocking API's entry point runs the removal on zbus's existing
/// runtime, and `async_drop` waits for it, so the rule is gone before the
/// connection.
struct Signals(Option<zbus::MessageStream>);

impl Signals {
    /// Take every signal already waiting, without waiting for another.
    ///
    /// `now_or_never` polls once; dropping a broadcast receiver future loses
    /// nothing. The loop empties the queue because a full stream stops the reader
    /// that serves every stream on the connection. `pending` is bounded by the browse
    /// ceiling, so a flooding responder is cut off by the queue, not memory.
    fn drain(
        &mut self,
        session: &Session,
        pending: &mut std::collections::VecDeque<Signal>,
    ) -> Drained {
        use iced::futures::{FutureExt, StreamExt};

        // Absent only after retirement, which consumes this value, so a browse
        // cannot reach it. Reported as the end of the stream because that is
        // what it would mean: nothing further can arrive.
        let Some(stream) = self.0.as_mut() else {
            return Drained::Closed;
        };
        while pending.len() < super::bounds::MAX_BROWSE_EVENTS {
            match stream.next().now_or_never() {
                None => return Drained::Ready,
                Some(None) => return Drained::Closed,
                // A message this build could not parse. It is off the queue,
                // which is what the queue needed, and it named nothing.
                Some(Some(Err(_))) => continue,
                Some(Some(Ok(message))) => {
                    if let Some(signal) = classify(session, &message) {
                        pending.push_back(signal);
                    }
                }
            }
        }
        Drained::Ready
    }
}

impl Drop for Signals {
    fn drop(&mut self) {
        if let Some(stream) = self.0.take() {
            zbus::block_on(zbus::AsyncDrop::async_drop(stream));
        }
    }
}

/// What one signal means, or `None` for one this browse does not act on.
///
/// The object path is checked first so another program's browse cannot add hosts
/// or end this one. A body that does not deserialize into its member's shape is
/// ignored rather than read partially.
fn classify(session: &Session, message: &zbus::Message) -> Option<Signal> {
    let header = message.header();
    let browser = session.browser_at(header.path()?)?;
    match header.member()?.as_str() {
        // `ItemNew(interface, protocol, name, type, domain, flags)` — the
        // announcement. Resolving it is a separate bounded call, because
        // `ItemNew` carries no address or port. Types this app does not
        // browse are refused here, so they never cost a resolve.
        "ItemNew" => {
            let key = announced(message)?;
            super::bounds::protocol_for_service(&key.service_type)?;
            Some(Signal::Announced(key))
        }
        // A machine that stops advertising during the browse would be a dead row.
        // Not filtered by type: an unmatched withdrawal removes nothing.
        "ItemRemove" => Some(Signal::Withdrawn(announced(message)?)),
        "AllForNow" => Some(Signal::AllForNow(browser)),
        // The only failure signal acted on: the server's `StateChanged` also fires for
        // ordinary transitions, and a daemon that goes away ends the stream.
        "Failure" => Some(Signal::Failed(browser)),
        // `CacheExhausted` means the daemon is now waiting on the network, not finished.
        _ => None,
    }
}

/// The announced identity in an `ItemNew` or `ItemRemove` body.
///
/// Both signals carry the same six fields, which is what makes a withdrawal
/// matchable against the announcement that produced a row.
fn announced(message: &zbus::Message) -> Option<ServiceKey> {
    let (interface, protocol, name, service_type, domain, _flags): (
        i32,
        i32,
        String,
        String,
        String,
        u32,
    ) = message.body().deserialize().ok()?;
    Some(ServiceKey {
        interface,
        protocol,
        name,
        service_type,
        domain,
    })
}

/// Turn one announcement into a resolved service, or `None`.
///
/// `ResolveService` is a bounded call on the browse's server proxy; this app
/// performs no DNS lookup of its own. The answer is filed under the announced
/// identity, not the echoed one, so a withdrawal can always expire it.
fn resolve(server: &zbus::blocking::Proxy<'static>, key: ServiceKey) -> Option<ResolvedService> {
    let (
        _iface,
        _proto,
        _resolved_name,
        resolved_type,
        _domain,
        host,
        _aproto,
        address,
        port,
        txt,
        _flags,
    ): ResolveReply = server
        .call(
            "ResolveService",
            &(
                key.interface,
                key.protocol,
                key.name.as_str(),
                key.service_type.as_str(),
                key.domain.as_str(),
                PROTO_UNSPEC,
                NO_FLAGS,
            ),
        )
        .ok()?;
    // A reply describing a different service type is refused outright rather
    // than filed under either name: the row would claim a protocol the daemon
    // did not say this machine speaks.
    if resolved_type != key.service_type {
        return None;
    }
    Some(ResolvedService {
        key,
        host,
        addresses: if address.is_empty() {
            Vec::new()
        } else {
            vec![address]
        },
        port,
        txt_bytes: txt.iter().map(Vec::len).sum(),
    })
}
