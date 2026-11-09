//! The one owner every scan runs on.
//!
//! Same shape and framework primitive as [`crate::import_source`]: a bounded
//! blocking job needs an owner that can refuse. One running browse, one
//! queued request, and an immediate typed answer when full.
//!
//! # What cannot accumulate
//!
//! The owner's thread is created on the first scan and lives for the process;
//! zbus's reactor is its own process-wide `OnceLock`. Avahi objects and the
//! signal stream belong to one browse and drop on every exit path, so repeated
//! scans add no thread, reactor, timer or server-side object.
//!
//! # Cancellation, and why there are two flags
//!
//! A cancelled scan is abandoned, not killed: the owner's handle settles the
//! generation at once, freeing the reducer, and the scan flag the browse polls
//! frees the objects. [`super::HostScanner`] reads a flag this module owns
//! because [`enzui_iced_core::blocking_task::BlockingTaskContext`] has no
//! public constructor for fixtures; the context is consulted once at entry,
//! so a request cancelled while queued opens no bus. The slot is released
//! only when the call exits: cancelling frees attention, not capacity.
//!
//! # Shutdown
//!
//! The owner is a `static`, so its `Drop` and bounded shutdown wait never
//! run, by design: quit does not wait on an abandoned browse. A browse alive
//! at exit loses its connection with the process, Avahi reclaims its objects,
//! and its answer reaches nobody.

use enzui_iced_core::blocking_task::{
    BlockingTask, BlockingTaskCancellation, BlockingTaskError, BlockingTaskOwner,
};

use super::bounds::{DiscoveryOutcome, DiscoveryRefusal};

/// How many browses run at once.
///
/// One. A browse holds a bus connection and four server-side browser objects,
/// and two at a time would double that custody for an answer the section can
/// only show one of.
const SCAN_WORKERS: std::num::NonZeroUsize = std::num::NonZeroUsize::new(1).unwrap();

/// How many scans the owner holds beyond the one it is running.
const SCAN_QUEUE_DEPTH: std::num::NonZeroUsize = std::num::NonZeroUsize::new(1).unwrap();

/// The bounded owner every browse runs on.
///
/// `None` when the thread could not be started. The `OnceLock` keeps
/// whatever it is first given, so caching
/// [`BlockingTaskOwner::unavailable`] would turn one transient spawn failure
/// into permanent refusals; leaving it empty lets the next press retry.
fn owner() -> Option<&'static BlockingTaskOwner> {
    static OWNER: std::sync::OnceLock<BlockingTaskOwner> = std::sync::OnceLock::new();

    if let Some(started) = OWNER.get() {
        return Some(started);
    }
    let started =
        BlockingTaskOwner::new("remote-discovery", SCAN_WORKERS, SCAN_QUEUE_DEPTH).ok()?;
    // Losing this race means another caller started one first. The loser is
    // dropped here, which shuts down and joins threads that have taken no
    // work, and the winner is what every caller goes on to use.
    let _ = OWNER.set(started);
    OWNER.get()
}

/// A dispatched scan's answer, and the handles that cancel it.
///
/// Two answer shapes because a claim can already be complete: a fixture
/// scanner finishes between the submission and the first look at it, and an
/// answer that has arrived is not a refusal.
pub struct PendingScan {
    answer: Option<Answer>,
    cancellation: BlockingTaskCancellation<DiscoveryOutcome>,
    abandoned: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// Where one claimed scan's answer is.
enum Answer {
    /// Accepted and still running or queued.
    Running(BlockingTask<DiscoveryOutcome>),
    /// Already answered at claim time.
    Settled(DiscoveryOutcome),
}

impl std::fmt::Debug for PendingScan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingScan")
            .field(
                "abandoned",
                &self.abandoned.load(std::sync::atomic::Ordering::SeqCst),
            )
            .finish_non_exhaustive()
    }
}

impl PendingScan {
    /// Tell this scan nobody is waiting for it any more.
    ///
    /// Retained by the reducer for exactly as long as the scan is the one it
    /// owns. The generation settles at once; a browse already inside the poll
    /// loop reads the flag between looks at its queue, so it stops within one
    /// poll interval rather than at the budget.
    pub fn cancel(&self) {
        self.abandoned
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.cancellation.cancel();
    }

    /// The future that resolves when the owner answers, taken once.
    ///
    /// The handle stays with the reducer so a later press can cancel this
    /// browse, and the answer goes to the task, so the two halves are
    /// separated here rather than by cloning something that must not be
    /// cloned. A second call yields a future that reports the owner as gone,
    /// which is what a caller asking twice has done.
    pub fn watch(
        &mut self,
    ) -> impl std::future::Future<Output = DiscoveryOutcome> + Send + 'static {
        let taken = self.answer.take();
        async move {
            match taken {
                Some(Answer::Settled(outcome)) => outcome,
                Some(Answer::Running(task)) => task
                    .await
                    .into_result()
                    .unwrap_or(DiscoveryOutcome::Refused(DiscoveryRefusal::DaemonLost)),
                None => DiscoveryOutcome::Refused(DiscoveryRefusal::DaemonLost),
            }
        }
    }
}

// Tests share one bounded owner; concurrent cases would consume each other's slots.

/// Claim the owner's free slot, or refuse without waiting.
///
/// Every outcome is immediate because the caller is the reducer; the owner's
/// saturation answer is already terminal, so one poll decides it.
///
/// `generation` is the stamp the reducer checks the answer against.
///
/// # Errors
/// [`DiscoveryRefusal::Busy`] when the slot is taken and
/// [`DiscoveryRefusal::DaemonLost`] when the owner could not be started, is
/// shut down, or had a worker end by unwinding; either way pressing again
/// may succeed.
pub fn dispatch(
    generation: u64,
    scanner: std::sync::Arc<dyn super::HostScanner>,
) -> Result<PendingScan, DiscoveryRefusal> {
    use iced::futures::FutureExt;

    let owner = owner().ok_or(DiscoveryRefusal::DaemonLost)?;
    let abandoned = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let browse_flag = std::sync::Arc::clone(&abandoned);
    let mut task = owner.submit(generation, move |context| {
        if context.is_cancelled() {
            // A request abandoned while it was still queued opens no bus. The
            // owner has already published this generation's terminal answer,
            // so what is returned here is discarded.
            return DiscoveryOutcome::Refused(DiscoveryRefusal::Busy);
        }
        scanner.scan(&browse_flag)
    });
    let cancellation = task.cancellation();
    // Polled through a borrow, so an accepted claim is not dropped — and
    // dropping a live task is itself a cancellation.
    match (&mut task).now_or_never() {
        None => Ok(PendingScan {
            answer: Some(Answer::Running(task)),
            cancellation,
            abandoned,
        }),
        Some(settlement) => match settlement.into_result() {
            Ok(outcome) => Ok(PendingScan {
                answer: Some(Answer::Settled(outcome)),
                cancellation,
                abandoned,
            }),
            Err(BlockingTaskError::Busy) => Err(DiscoveryRefusal::Busy),
            Err(_) => Err(DiscoveryRefusal::DaemonLost),
        },
    }
}
