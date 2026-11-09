//! Shared probe: measure an app's portal wake source through the
//! **real `App::subscription`** it hands the runtime.
//!
//! # Why this file lives in `_shared/`
//!
//! Fleet apps wake on
//! `enzui_iced_widgets::file_chooser::completion_subscription` rather than
//! `iced::window::frames()` / `iced::time::every(..)`, and each needs the same
//! cadence gate. Separate copies could drift into weaker assertions, so each
//! app includes this one implementation:
//!
//! ```ignore
//! #[cfg(test)]
//! #[path = "../../_shared/portal_wake_probe.rs"]
//! mod portal_wake_probe;
//! ```
//!
//! (`#[path]` is relative to the including file's directory, so `../../` from
//! `<app>/src/` is the apps-repo root; a gate one directory deeper uses
//! `../../../_shared/...`.)
//!
//! # What it measures, and why it is measured this way
//!
//! The claim is about **which recipes the app actually returns**, so nothing
//! here reads the app's fields or rebuilds a subscription the test invented:
//!
//! * [`recipe_hashes`] hashes every recipe in a real `App::subscription()`
//!   with iced's own `Recipe::hash` — the identity the runtime keys on. The
//!   portal recipe is then *derived* as the hash that appears only while a
//!   request is live ([`added_recipe`]), never named by the test. An app that
//!   forgets to batch its completion subscription in adds no recipe and the
//!   gate reds; an app that keeps a clock instead adds a recipe that never
//!   settles and [`drain`] catches it.
//! * [`stream_of`] runs that one derived recipe exactly as the runtime would,
//!   with an event stream that **never produces** — so a recipe fed by
//!   `window::frames()` gets no frames and yields nothing, while a recipe fed
//!   by the portal's completion signal yields on [`ProbeHandle::notify`].
//!   The message it yields is the app's own message value, because the
//!   `.map(..)` under test is the product's.
//! * [`ProbeBackend`] is a `PortalBackend` with a real
//!   `completion_signal` — the shape `DbusBackend` has, without a session bus.
//!   The fleet's older scripted backends leave `completion_signal` at the trait
//!   default (`None`), which makes `completion_subscription` return
//!   `Subscription::none()`; a cadence gate built on one of those would mistake
//!   "no subscription at all" for successful adoption.

#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use enzui_iced_widgets::file_chooser::{
    BackendError, BackendReply, CancelReason, CompletionSignal, PortalBackend, PortalOperation,
    PortalResponse, RequestId,
};
use iced::advanced::subscription::{self, Hasher, Recipe};
use iced::futures::stream::{self, BoxStream, StreamExt};

/// Shared state between the boxed backend the picker owns and the handle the
/// test keeps.
struct Shared {
    signal: CompletionSignal,
    reply: Mutex<Option<BackendReply>>,
    closes: AtomicUsize,
    starts: AtomicUsize,
    initialising_starts: AtomicUsize,
}

/// A portal backend that answers only when the test says so, and that exposes
/// a real completion signal so the event-driven subscription has an edge to
/// wake on.
pub struct ProbeBackend {
    shared: Arc<Shared>,
    next: u64,
}

/// The test-side handle to a [`ProbeBackend`] the app now owns.
#[derive(Clone)]
pub struct ProbeHandle {
    shared: Arc<Shared>,
}

/// A backend for the app to own plus the handle that drives it.
#[must_use]
pub fn probe_backend() -> (Box<dyn PortalBackend>, ProbeHandle) {
    probe_backend_after_initialising(0)
}

/// A signalling backend whose first start is deferred while portal
/// availability is still initialising. The handle can later notify the real
/// completion edge, allowing an app test to prove dismissal retired the
/// deferred request instead of letting that edge open a dialog afterwards.
#[must_use]
pub fn deferred_probe_backend() -> (Box<dyn PortalBackend>, ProbeHandle) {
    probe_backend_after_initialising(1)
}

fn probe_backend_after_initialising(
    initialising_starts: usize,
) -> (Box<dyn PortalBackend>, ProbeHandle) {
    let shared = Arc::new(Shared {
        signal: CompletionSignal::new(),
        reply: Mutex::new(None),
        closes: AtomicUsize::new(0),
        starts: AtomicUsize::new(0),
        initialising_starts: AtomicUsize::new(initialising_starts),
    });
    (
        Box::new(ProbeBackend {
            shared: Arc::clone(&shared),
            next: 0,
        }),
        ProbeHandle { shared },
    )
}

impl ProbeHandle {
    /// One portal-side event with no reply attached: the edge without the
    /// answer, which is what a deferred/`Initialising` backend produces.
    pub fn notify(&self) -> u64 {
        self.shared.signal.notify()
    }

    /// Park a terminal reply and fire the signal, exactly as the D-Bus worker
    /// does when the portal's `Response` signal lands.
    pub fn portal_answers(&self, response: PortalResponse, uris: Vec<String>) {
        *self.shared.reply.lock().expect("probe reply lock") =
            Some(BackendReply { response, uris });
        self.shared.signal.notify();
    }

    /// How many waiters the completion signal currently holds. `0` after the
    /// subscription is dropped — this is how "the subscription went away" is
    /// measured rather than asserted.
    #[must_use]
    pub fn waiters(&self) -> usize {
        self.shared.signal.waiter_count()
    }

    /// How many `close()` calls the backend has served (the owed settle).
    #[must_use]
    pub fn closes(&self) -> usize {
        self.shared.closes.load(Ordering::SeqCst)
    }

    /// How many requests the app has started on this backend.
    #[must_use]
    pub fn starts(&self) -> usize {
        self.shared.starts.load(Ordering::SeqCst)
    }
}

impl PortalBackend for ProbeBackend {
    fn start(&mut self, _operation: PortalOperation) -> Result<RequestId, BackendError> {
        if self
            .shared
            .initialising_starts
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(BackendError::Initialising);
        }
        self.next += 1;
        self.shared.starts.fetch_add(1, Ordering::SeqCst);
        Ok(RequestId::new(self.next))
    }

    fn poll_reply(&mut self, _id: RequestId) -> Option<BackendReply> {
        self.shared.reply.lock().expect("probe reply lock").take()
    }

    fn close(&mut self, _id: RequestId, _reason: CancelReason) {
        self.shared.closes.fetch_add(1, Ordering::SeqCst);
    }

    fn describe(&self) -> String {
        "probe (in-process, real completion signal, no D-Bus)".to_owned()
    }

    fn completion_signal(&self) -> Option<CompletionSignal> {
        Some(self.shared.signal.clone())
    }
}

/// The identity iced keys every recipe in a subscription on.
#[must_use]
pub fn recipe_hashes<M: 'static>(sub: iced::Subscription<M>) -> Vec<u64> {
    use std::hash::Hasher as _;

    subscription::into_recipes(sub)
        .iter()
        .map(|recipe| {
            let mut hasher = Hasher::default();
            recipe.hash(&mut hasher);
            hasher.finish()
        })
        .collect()
}

/// The single recipe hash present in `live` and absent from `idle`.
///
/// Panics unless there is exactly one, so "the app grew *the* portal recipe"
/// is a measurement: zero means the adoption is not wired into
/// `App::subscription`, and two means the test cannot tell which is the portal.
#[must_use]
pub fn added_recipe(idle: &[u64], live: &[u64]) -> u64 {
    let added: Vec<u64> = live
        .iter()
        .copied()
        .filter(|hash| !idle.contains(hash))
        .collect();
    assert_eq!(
        added.len(),
        1,
        "a live portal request must add exactly ONE recipe to App::subscription \
         (idle {idle:?}, live {live:?})"
    );
    added[0]
}

/// Run the recipe with `hash` from `sub`, fed by an event stream that never
/// produces — the runtime's own path, minus any frame clock.
pub fn stream_of<M: 'static>(sub: iced::Subscription<M>, hash: u64) -> BoxStream<'static, M> {
    use std::hash::Hasher as _;

    let recipes = subscription::into_recipes(sub);
    let mut found: Option<Box<dyn Recipe<Output = M>>> = None;
    for recipe in recipes {
        let mut hasher = Hasher::default();
        recipe.hash(&mut hasher);
        if hasher.finish() == hash {
            found = Some(recipe);
            break;
        }
    }
    let recipe = found.expect("the subscription no longer carries the portal recipe");
    recipe.stream(stream::pending().boxed())
}

/// Run a subscription that must carry exactly ONE recipe, fed by an event
/// stream that never produces. Used where the subscription under test is a
/// single product expression rather than a whole `App::subscription()` batch.
pub fn single_stream<M: 'static>(sub: iced::Subscription<M>) -> BoxStream<'static, M> {
    let mut recipes = subscription::into_recipes(sub);
    assert_eq!(
        recipes.len(),
        1,
        "expected exactly one recipe, got {}",
        recipes.len()
    );
    recipes.remove(0).stream(stream::pending().boxed())
}

/// Poll a recipe stream once, the way the runtime would.
pub fn poll_once<M>(stream: &mut BoxStream<'static, M>) -> Poll<Option<M>> {
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    stream.poll_next_unpin(&mut cx)
}

/// Every message the stream would deliver before parking, bounded so a
/// free-running (frame- or timer-sourced) subscription cannot hang the suite.
pub fn drain<M>(stream: &mut BoxStream<'static, M>, budget: usize) -> Vec<M> {
    let mut seen = Vec::new();
    for _ in 0..budget {
        match poll_once(stream) {
            Poll::Ready(Some(message)) => seen.push(message),
            Poll::Ready(None) | Poll::Pending => break,
        }
    }
    seen
}
