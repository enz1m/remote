//! Per-profile reconnect policy, the retry schedule, and the recency stamp a
//! connection is allowed to adopt.
//!
//! Three decisions live here, all pure:
//!
//! * [`ReconnectPolicy`] — what a profile stores. Off by default; an opt-in
//!   carries a finite attempt count and a finite backoff ceiling.
//! * [`ReconnectState`] — which profile is waiting, for how long, under which
//!   generation, and how many attempts it has spent. One waiting entry at a
//!   time drives the app's single deadline subscription; nothing here sleeps,
//!   polls or owns a thread.
//! * [`bounded_stamp`] and [`recency_order`] — the wall-clock reading a
//!   successful connection may adopt, and the order durably adopted readings
//!   put profiles in.
//!
//! The reducer owns every transition: this module reads a clock only through
//! the instants and timestamps it is handed.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::model::{ConnectionProfile, DialIdentity, SessionStatus};

/// Attempts an enabled policy makes before it gives up, when the profile does
/// not say otherwise.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 5;

/// The most attempts a profile may ask for.
pub const MAX_ATTEMPTS_CEILING: u32 = 10;

/// The backoff ceiling an enabled policy uses when the profile does not say
/// otherwise, in seconds.
pub const DEFAULT_BACKOFF_CEILING_SECS: u32 = 60;

/// The longest backoff ceiling a profile may ask for, in seconds.
pub const BACKOFF_CEILING_LIMIT_SECS: u32 = 900;

/// The first attempt's unjittered delay, in seconds.
pub const BASE_DELAY_SECS: u64 = 1;

/// How many doublings the delay may take before the ceiling decides it.
///
/// The ceiling is reached long before this, so the cap exists to keep the
/// shift itself in range rather than to shape the curve.
const MAX_BACKOFF_SHIFT: u32 = 20;

/// How many profiles may hold retry state at once.
///
/// One per connection slot: a profile with no session cannot be waiting for
/// one to come back.
pub const MAX_TRACKED_PROFILES: usize = 16;

/// How long a due attempt waits when the previous connection has not finished
/// retiring.
///
/// Spending an attempt on a profile whose child is still being reaped would
/// burn the policy's budget on a refusal the app already knows is coming.
pub const RETIREMENT_DEFER: Duration = Duration::from_millis(250);

/// How many times one attempt may be deferred while the previous connection
/// is still retiring.
///
/// Past this the policy gives up rather than re-arming for a teardown that is
/// not finishing: [`RETIREMENT_DEFER`] times this is six seconds, which is the
/// same order as the close the app is waiting for.
pub const MAX_RETIREMENT_DEFERS: u32 = 24;

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// What a profile stores about reconnecting itself.
///
/// The default is off: nothing reconnects a connection the user did not ask to
/// have reconnected. An opt-in is finite in both directions — a bounded number
/// of attempts and a bounded delay between them — so an unreachable host
/// cannot produce an unbounded sequence of children.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ReconnectPolicy {
    /// Whether an unexpected transport loss schedules another attempt.
    pub enabled: bool,
    /// How many attempts one loss may produce, clamped to
    /// [`MAX_ATTEMPTS_CEILING`] by [`Self::normalized`].
    pub max_attempts: u32,
    /// The longest delay between attempts, in seconds, clamped to
    /// [`BACKOFF_CEILING_LIMIT_SECS`] by [`Self::normalized`].
    pub backoff_ceiling_secs: u32,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            backoff_ceiling_secs: DEFAULT_BACKOFF_CEILING_SECS,
        }
    }
}

impl ReconnectPolicy {
    /// The policy with every field inside the bounds this build honours.
    ///
    /// A stored row, an import or a form draft can carry a value this build
    /// will not act on; clamping here means every consumer reads the same
    /// bounded answer instead of re-deriving it.
    #[must_use]
    pub fn normalized(self) -> Self {
        let max_attempts = self.max_attempts.min(MAX_ATTEMPTS_CEILING);
        let backoff_ceiling_secs = self
            .backoff_ceiling_secs
            .clamp(BASE_DELAY_SECS as u32, BACKOFF_CEILING_LIMIT_SECS);
        Self {
            enabled: self.enabled && max_attempts > 0,
            max_attempts,
            backoff_ceiling_secs,
        }
    }

    /// Whether an unexpected loss of this profile's transport may schedule an
    /// attempt at all.
    #[must_use]
    pub fn admits_retry(self) -> bool {
        let bounded = self.normalized();
        bounded.enabled && bounded.max_attempts > 0
    }
}

/// Whether a failure can differ on its own, or needs the user first.
///
/// A network that was unreachable may be reachable in eight seconds. A refused
/// key, an unknown host key, a forward that cannot bind and a configuration
/// this build will not dial are all identical on the next attempt, so retrying
/// them spends attempts to reproduce one answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryDisposition {
    /// The same attempt may succeed later.
    Transient,
    /// Nothing changes until the user does something.
    RequiresUser,
}

/// The backoff one attempt waits, bounded by `ceiling_secs`.
///
/// `attempt` is one-based. `jitter` is fresh OS entropy; `None` means the
/// entropy source refused, and the attempt then waits the full computed delay
/// rather than a value derived from a clock or a counter. The result is never
/// shorter than half the computed delay and never shorter than
/// [`BASE_DELAY_SECS`], so a jittered wait is still a wait.
#[must_use]
pub fn backoff_delay(attempt: u32, ceiling_secs: u32, jitter: Option<u64>) -> Duration {
    let shift = attempt.saturating_sub(1).min(MAX_BACKOFF_SHIFT);
    let doubled = BASE_DELAY_SECS
        .checked_shl(shift)
        .unwrap_or(u64::from(u32::MAX));
    let ceiling = u64::from(ceiling_secs.max(BASE_DELAY_SECS as u32));
    let capped = doubled.min(ceiling).max(BASE_DELAY_SECS);
    // Rounded up, so the floor of the jitter window is a real wait: the first
    // attempt's one-second delay stays one second instead of becoming zero.
    let half = capped.div_ceil(2);
    let span = capped.saturating_sub(half);
    let offset = match jitter {
        Some(bits) => bits % span.saturating_add(1),
        None => span,
    };
    Duration::from_secs(half.saturating_add(offset))
}

/// `wait` rounded up to whole seconds, never below one.
fn whole_seconds(wait: Duration) -> Duration {
    let seconds = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
    Duration::from_secs(seconds.max(1))
}

/// Fresh OS entropy for one jitter draw, or `None` when the source refused.
///
/// The framework's kernel CSPRNG boundary is the only source; there is
/// deliberately no fallback value, because a predictable draw across a fleet
/// of profiles is the thundering herd jitter exists to prevent.
#[must_use]
pub fn draw_jitter() -> Option<u64> {
    enzui_iced_core::random::random_array::<8>()
        .ok()
        .map(u64::from_le_bytes)
}

// ---------------------------------------------------------------------------
// Schedule
// ---------------------------------------------------------------------------

/// Where one profile is in its retry policy.
///
/// `Waiting { attempt }` is proposed and uncharged; only
/// [`ReconnectState::begin_attempt`] spends it, so a wait that is never
/// dispatched (for example while the previous connection retires) costs
/// nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryPhase {
    /// No attempt is scheduled and none is running.
    Idle,
    /// A deadline is armed for this profile.
    Waiting {
        /// The attempt the deadline would start, one-based and proposed:
        /// it is one past the spent count, and stays uncharged until the
        /// dispatch.
        attempt: u32,
        /// The policy's attempt ceiling, for the surface's `x/y`.
        max: u32,
        /// The whole delay this wait was armed for.
        delay: Duration,
        /// What is left of it at the last observed instant.
        remaining: Duration,
    },
    /// An attempt this policy started is in flight, and spent.
    Attempting {
        /// The running attempt, one-based.
        attempt: u32,
        /// The policy's attempt ceiling.
        max: u32,
    },
    /// The policy stopped, carrying only the attempts it actually made.
    GaveUp {
        /// How many attempts were dispatched. Zero is a real answer: a
        /// schedule that never got to dial spent nothing.
        attempts: u32,
    },
}

/// One profile's retry state.
#[derive(Clone, Copy, Debug)]
struct Tracked {
    /// The token every timer, attempt and publication for this profile must
    /// quote. Drawn from [`ReconnectState::next_token`], so a value is never
    /// reused by a later cycle or by another profile.
    generation: u64,
    /// Attempts dispatched since the last authoritative Ready. A proposed
    /// attempt lives in [`RetryPhase::Waiting`] until it is dispatched, so
    /// this never counts a dial the app did not make.
    attempts: u32,
    max: u32,
    ceiling_secs: u32,
    phase: RetryPhase,
    due_at: Option<Instant>,
    /// Re-arms spent waiting for the previous connection to retire, bounded by
    /// [`MAX_RETIREMENT_DEFERS`].
    defers: u32,
    /// The publication order reserved for this profile's recency stamp, or
    /// zero when none is outstanding.
    reservation: u64,
}

/// The armed deadline the app's one retry subscription is built from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArmedDeadline {
    /// Whose attempt is due.
    pub profile_id: Uuid,
    /// The generation the wake must quote to be honoured.
    pub generation: u64,
    /// How long the subscription waits, whole seconds.
    ///
    /// Quantised so a turn that happens mid-wait does not rebuild the
    /// subscription's recipe on every message; a rebuild re-targets the same
    /// deadline, so the quantisation costs at most one second of precision.
    pub wait: Duration,
}

/// A reserved place in one profile's recency-publication order.
///
/// Held across the publication so a reading whose reservation is no longer the
/// profile's newest — because the profile was edited, deleted or connected
/// again in between — is refused instead of overwriting a later one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecencyReservation {
    /// The profile the reading is about.
    pub profile_id: Uuid,
    /// The policy generation at reservation time.
    pub generation: u64,
    /// Monotonic within one profile.
    pub order: u64,
}

/// Why a scheduled attempt was not armed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScheduleRefusal {
    /// The profile's policy is off, or asks for no attempts.
    PolicyOff,
    /// The failure needs the user before another attempt can differ.
    RequiresUser,
    /// Every attempt the policy allows has been spent.
    Exhausted,
    /// This build tracks as many retrying profiles as it can hold.
    AtCapacity,
    /// The monotonic clock cannot represent the deadline, so no wake could be
    /// matched to it.
    DeadlineUnrepresentable,
    /// The generation counter cannot advance, so no later wake could be told
    /// from an older one.
    GenerationsExhausted,
}

/// Every profile's retry state, and the reducer's publication order.
///
/// Generations and publication orders are drawn from one monotonic counter, so
/// no value is ever minted twice: a wake, an attempt or a publication quoting a
/// retired token matches nothing for the rest of the process.
#[derive(Debug, Default)]
pub struct ReconnectState {
    tracked: BTreeMap<Uuid, Tracked>,
    next_token: u64,
    /// Set once the counter cannot advance. Every later schedule and
    /// reservation is refused rather than reusing a token a stale wake quotes.
    exhausted: bool,
}

impl ReconnectState {
    /// The next unused token, or `None` once the counter is exhausted.
    fn mint(&mut self) -> Option<u64> {
        if self.exhausted {
            return None;
        }
        match self.next_token.checked_add(1) {
            Some(token) => {
                self.next_token = token;
                Some(token)
            }
            None => {
                self.exhausted = true;
                None
            }
        }
    }

    /// Where `profile_id` is in its policy, or [`RetryPhase::Idle`] when it is
    /// not tracked.
    #[must_use]
    pub fn phase(&self, profile_id: Uuid) -> RetryPhase {
        self.tracked
            .get(&profile_id)
            .map_or(RetryPhase::Idle, |tracked| tracked.phase)
    }

    /// Whether any profile holds an armed deadline.
    #[must_use]
    pub fn is_waiting(&self) -> bool {
        self.tracked
            .values()
            .any(|tracked| matches!(tracked.phase, RetryPhase::Waiting { .. }))
    }

    /// The earliest armed deadline, which is the only one the app subscribes
    /// to: a wake for it runs the reducer, and every other due profile is
    /// collected in the same turn.
    #[must_use]
    pub fn armed(&self) -> Option<ArmedDeadline> {
        self.tracked
            .iter()
            .filter_map(|(id, tracked)| match tracked.phase {
                RetryPhase::Waiting { remaining, .. } => Some((*id, tracked.generation, remaining)),
                _ => None,
            })
            .min_by_key(|(_, _, remaining)| *remaining)
            .map(|(profile_id, generation, remaining)| ArmedDeadline {
                profile_id,
                generation,
                wait: whole_seconds(remaining),
            })
    }

    /// Refresh every waiting entry's remaining time against `now`.
    ///
    /// The surface reads the refreshed value, so the countdown it shows is a
    /// function of reducer state rather than of when a frame happened to be
    /// painted.
    pub fn observe(&mut self, now: Instant) {
        for tracked in self.tracked.values_mut() {
            let (Some(due_at), RetryPhase::Waiting { remaining, .. }) =
                (tracked.due_at, &mut tracked.phase)
            else {
                continue;
            };
            *remaining = due_at.saturating_duration_since(now);
        }
    }

    /// Schedule the next attempt for `profile_id` after an unexpected loss.
    ///
    /// Returns the armed deadline, or why nothing was armed. The attempt is
    /// proposed, not charged: the spent count moves only in
    /// [`Self::begin_attempt`]. A proposal past the policy's ceiling is
    /// [`ScheduleRefusal::Exhausted`] and the phase becomes
    /// [`RetryPhase::GaveUp`] carrying the attempts actually made.
    pub fn schedule(
        &mut self,
        profile_id: Uuid,
        policy: ReconnectPolicy,
        disposition: RetryDisposition,
        now: Instant,
        jitter: Option<u64>,
    ) -> Result<ArmedDeadline, ScheduleRefusal> {
        if self.exhausted {
            return Err(ScheduleRefusal::GenerationsExhausted);
        }
        if disposition == RetryDisposition::RequiresUser {
            self.forget(profile_id);
            return Err(ScheduleRefusal::RequiresUser);
        }
        let policy = policy.normalized();
        if !policy.admits_retry() {
            self.forget(profile_id);
            return Err(ScheduleRefusal::PolicyOff);
        }
        if !self.tracked.contains_key(&profile_id) && self.tracked.len() >= MAX_TRACKED_PROFILES {
            return Err(ScheduleRefusal::AtCapacity);
        }
        let Some(generation) = self.mint() else {
            self.give_up(profile_id);
            return Err(ScheduleRefusal::GenerationsExhausted);
        };
        let entry = self.tracked.entry(profile_id).or_insert(Tracked {
            generation,
            attempts: 0,
            max: policy.max_attempts,
            ceiling_secs: policy.backoff_ceiling_secs,
            phase: RetryPhase::Idle,
            due_at: None,
            defers: 0,
            reservation: 0,
        });
        entry.defers = 0;
        entry.max = policy.max_attempts;
        entry.ceiling_secs = policy.backoff_ceiling_secs;
        let max = entry.max;
        let spent = entry.attempts;
        let Some(attempt) = spent.checked_add(1).filter(|attempt| *attempt <= max) else {
            entry.phase = RetryPhase::GaveUp { attempts: spent };
            entry.due_at = None;
            return Err(ScheduleRefusal::Exhausted);
        };
        let delay = backoff_delay(attempt, entry.ceiling_secs, jitter);
        let Some(due_at) = now.checked_add(delay) else {
            entry.phase = RetryPhase::GaveUp { attempts: spent };
            entry.due_at = None;
            return Err(ScheduleRefusal::DeadlineUnrepresentable);
        };
        entry.generation = generation;
        entry.due_at = Some(due_at);
        entry.phase = RetryPhase::Waiting {
            attempt,
            max,
            delay,
            remaining: delay,
        };
        Ok(ArmedDeadline {
            profile_id,
            generation,
            wait: whole_seconds(delay),
        })
    }

    /// Whether `profile_id`'s wake for `generation` is the one this state is
    /// still waiting for, and its deadline has passed.
    ///
    /// A wake from an older generation — a timer armed before the profile was
    /// edited, disconnected or connected again — answers `false`, which is
    /// what makes it inert.
    #[must_use]
    pub fn is_due(&self, profile_id: Uuid, generation: u64, now: Instant) -> bool {
        let Some(tracked) = self.tracked.get(&profile_id) else {
            return false;
        };
        if tracked.generation != generation {
            return false;
        }
        matches!(tracked.phase, RetryPhase::Waiting { .. })
            && tracked.due_at.is_some_and(|due_at| now >= due_at)
    }

    /// Re-arm the proposed attempt for a later deadline.
    ///
    /// Used while the previous connection is still retiring; the budget does not
    /// move. Past [`MAX_RETIREMENT_DEFERS`] the policy gives up, reporting the
    /// attempts actually made (possibly zero).
    pub fn defer(
        &mut self,
        profile_id: Uuid,
        now: Instant,
        wait: Duration,
    ) -> Option<ArmedDeadline> {
        let tracked = self.tracked.get_mut(&profile_id)?;
        let RetryPhase::Waiting {
            attempt,
            max,
            delay,
            ..
        } = tracked.phase
        else {
            return None;
        };
        let next = tracked
            .defers
            .checked_add(1)
            .filter(|defers| *defers <= MAX_RETIREMENT_DEFERS)
            .zip(now.checked_add(wait));
        let Some((defers, due_at)) = next else {
            tracked.due_at = None;
            tracked.phase = RetryPhase::GaveUp {
                attempts: tracked.attempts,
            };
            return None;
        };
        tracked.defers = defers;
        tracked.due_at = Some(due_at);
        tracked.phase = RetryPhase::Waiting {
            attempt,
            max,
            delay,
            remaining: wait,
        };
        Some(ArmedDeadline {
            profile_id,
            generation: tracked.generation,
            wait: whole_seconds(wait),
        })
    }

    /// Move `profile_id` from waiting to attempting, charging the proposal.
    ///
    /// The only place the spent count moves; call it immediately before
    /// dispatching the dial. `None` when the entry is not waiting under
    /// `generation`, so a wake that lost a race with cancellation does nothing.
    pub fn begin_attempt(&mut self, profile_id: Uuid, generation: u64) -> Option<(u32, u32)> {
        let tracked = self.tracked.get_mut(&profile_id)?;
        if tracked.generation != generation {
            return None;
        }
        let RetryPhase::Waiting { attempt, max, .. } = tracked.phase else {
            return None;
        };
        tracked.attempts = attempt;
        tracked.due_at = None;
        tracked.phase = RetryPhase::Attempting { attempt, max };
        Some((attempt, max))
    }

    /// Give up on `profile_id`, keeping only the attempts it dispatched.
    pub fn give_up(&mut self, profile_id: Uuid) {
        if let Some(tracked) = self.tracked.get_mut(&profile_id) {
            tracked.due_at = None;
            tracked.phase = RetryPhase::GaveUp {
                attempts: tracked.attempts,
            };
        }
    }

    /// Cancel `profile_id`'s schedule and retire every wake, attempt and
    /// reservation outstanding under its generation.
    ///
    /// Returns whether an armed or running attempt was cancelled. The entry is
    /// dropped; its generation is never minted again, so an outstanding wake
    /// quoting it stays inert.
    pub fn cancel(&mut self, profile_id: Uuid) -> bool {
        let Some(tracked) = self.tracked.remove(&profile_id) else {
            return false;
        };
        matches!(
            tracked.phase,
            RetryPhase::Waiting { .. } | RetryPhase::Attempting { .. }
        )
    }

    /// Cancel every profile's schedule, reporting how many had an armed or
    /// running attempt.
    pub fn cancel_all(&mut self) -> usize {
        let cancelled = self
            .tracked
            .values()
            .filter(|tracked| {
                matches!(
                    tracked.phase,
                    RetryPhase::Waiting { .. } | RetryPhase::Attempting { .. }
                )
            })
            .count();
        self.tracked.clear();
        cancelled
    }

    /// Drop `profile_id`'s entry, retiring its generation.
    fn forget(&mut self, profile_id: Uuid) {
        let _ = self.cancel(profile_id);
    }

    /// Every profile whose deadline has passed at `now`, newest connection
    /// first.
    ///
    /// The order is the durably adopted recency in `profiles`: when more
    /// attempts are due than this build has connection slots, the connection
    /// the user most recently had is the one that gets a slot.
    #[must_use]
    pub fn due(&self, profiles: &[ConnectionProfile], now: Instant) -> Vec<(Uuid, u64)> {
        let mut due: Vec<(Uuid, u64)> = Vec::new();
        for id in recency_order(profiles) {
            if let Some(tracked) = self.tracked.get(&id)
                && matches!(tracked.phase, RetryPhase::Waiting { .. })
                && tracked.due_at.is_some_and(|due_at| now >= due_at)
            {
                due.push((id, tracked.generation));
            }
        }
        due
    }

    /// Reserve this profile's next recency publication.
    ///
    /// `None`, and the caller records the debt, when the token counter is
    /// exhausted or when [`MAX_TRACKED_PROFILES`] are already tracked and this
    /// profile would need a new entry; the bound is never crossed, even briefly.
    pub fn reserve_recency(&mut self, profile_id: Uuid) -> Option<RecencyReservation> {
        let fresh = !self.tracked.contains_key(&profile_id);
        if fresh && self.tracked.len() >= MAX_TRACKED_PROFILES {
            return None;
        }
        let order = self.mint()?;
        if fresh {
            let generation = self.mint()?;
            self.tracked.insert(
                profile_id,
                Tracked {
                    generation,
                    attempts: 0,
                    max: 0,
                    ceiling_secs: DEFAULT_BACKOFF_CEILING_SECS,
                    phase: RetryPhase::Idle,
                    due_at: None,
                    defers: 0,
                    reservation: 0,
                },
            );
        }
        let tracked = self.tracked.get_mut(&profile_id)?;
        tracked.reservation = order;
        Some(RecencyReservation {
            profile_id,
            generation: tracked.generation,
            order,
        })
    }

    /// Release `reservation` once its publication has settled, dropping an
    /// entry that exists only to hold it.
    pub fn release_recency(&mut self, reservation: RecencyReservation) {
        let spent = match self.tracked.get_mut(&reservation.profile_id) {
            Some(tracked) => {
                if tracked.reservation == reservation.order {
                    tracked.reservation = 0;
                }
                tracked.reservation == 0
                    && tracked.attempts == 0
                    && matches!(tracked.phase, RetryPhase::Idle)
            }
            None => false,
        };
        if spent {
            let _ = self.tracked.remove(&reservation.profile_id);
        }
    }

    /// Whether `reservation` is still the newest one for its profile and its
    /// generation has not moved.
    #[must_use]
    pub fn holds_reservation(&self, reservation: RecencyReservation) -> bool {
        self.tracked
            .get(&reservation.profile_id)
            .is_some_and(|tracked| {
                tracked.reservation == reservation.order
                    && tracked.generation == reservation.generation
            })
    }

    /// Record an authoritative Ready: attempts go back to zero and the entry
    /// stops claiming a policy is waiting.
    pub fn settle_ready(&mut self, profile_id: Uuid) {
        if let Some(tracked) = self.tracked.get_mut(&profile_id) {
            tracked.attempts = 0;
            tracked.defers = 0;
            tracked.due_at = None;
            tracked.phase = RetryPhase::Idle;
        }
    }
}

// ---------------------------------------------------------------------------
// Surface
// ---------------------------------------------------------------------------

/// What the session surface says about a connection under a policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryPresentation {
    /// No transport, and nothing scheduled.
    Disconnected,
    /// A deadline is armed.
    Waiting {
        /// Whole seconds left at the last observed instant.
        seconds: u64,
        /// The attempt the deadline will start.
        attempt: u32,
        /// The policy's attempt ceiling.
        max: u32,
    },
    /// An attempt is in flight.
    Connecting {
        /// The running attempt.
        attempt: u32,
        /// The policy's attempt ceiling.
        max: u32,
    },
    /// The transport is up.
    Ready,
    /// The policy spent every attempt it had.
    GaveUp {
        /// How many attempts were made.
        attempts: u32,
    },
}

impl RetryPresentation {
    /// The one line the surface shows.
    #[must_use]
    pub fn label(self) -> String {
        match self {
            Self::Disconnected => "Disconnected".to_string(),
            Self::Waiting { seconds: 1, .. } => "Waiting 1 second".to_string(),
            Self::Waiting { seconds, .. } => format!("Waiting {seconds} seconds"),
            Self::Connecting { attempt, max } => format!("Connecting attempt {attempt}/{max}"),
            Self::Ready => "Ready".to_string(),
            Self::GaveUp { .. } => "Gave up".to_string(),
        }
    }

    /// The sentence under the line, or `None` when the line is the whole
    /// story.
    #[must_use]
    pub fn body(self) -> Option<String> {
        match self {
            Self::Waiting { attempt, max, .. } => Some(format!(
                "Remote will try this connection again on its own: attempt {attempt} of {max}."
            )),
            // Zero is reachable: a wait whose profile's previous connection
            // never finished retiring gives up without having dialled.
            Self::GaveUp { attempts: 0 } => Some(
                "Remote stopped before it could try again. Retry to try again now.".to_string(),
            ),
            Self::GaveUp { attempts: 1 } => {
                Some("Remote stopped after 1 attempt. Retry to try again now.".to_string())
            }
            Self::GaveUp { attempts } => Some(format!(
                "Remote stopped after {attempts} attempts. Retry to try again now."
            )),
            _ => None,
        }
    }

    /// Whether this state offers the user a route: retry now, or stop.
    #[must_use]
    pub fn offers_routes(self) -> bool {
        matches!(self, Self::Waiting { .. } | Self::GaveUp { .. })
    }
}

/// What the surface says for a session in `status` whose policy is in `phase`.
///
/// `Connecting attempt x/y` names an attempt the policy started; a dial the
/// user asked for has no attempt number, so an idle policy reports only
/// whether the transport is up.
#[must_use]
pub fn presentation(status: SessionStatus, phase: RetryPhase) -> RetryPresentation {
    match phase {
        RetryPhase::Waiting {
            attempt,
            max,
            remaining,
            ..
        } => RetryPresentation::Waiting {
            seconds: remaining.as_secs(),
            attempt,
            max,
        },
        RetryPhase::Attempting { attempt, max } => RetryPresentation::Connecting { attempt, max },
        RetryPhase::GaveUp { attempts } => RetryPresentation::GaveUp { attempts },
        RetryPhase::Idle if status == SessionStatus::Connected => RetryPresentation::Ready,
        RetryPhase::Idle => RetryPresentation::Disconnected,
    }
}

// ---------------------------------------------------------------------------
// Recency
// ---------------------------------------------------------------------------

/// The reading a connection may adopt as its `last_connected`, or `None` when
/// it may not advance recency.
///
/// `sample` is one wall-clock reading taken on the reducer; `adopted` is what
/// the profile durably holds. A sample that is not strictly newer is refused,
/// so a clock that moved backwards cannot rewrite a later connection as an
/// earlier one and cannot reorder a list sorted on these values.
#[must_use]
pub fn bounded_stamp(
    sample: DateTime<Utc>,
    adopted: Option<DateTime<Utc>>,
) -> Option<DateTime<Utc>> {
    match adopted {
        Some(previous) if sample <= previous => None,
        _ => Some(sample),
    }
}

/// Profile ids ordered by durably adopted recency, newest first.
///
/// A profile that has never connected sorts last. Ties break on name and then
/// id, so the order is total and two launches of the same library agree.
#[must_use]
pub fn recency_order(profiles: &[ConnectionProfile]) -> Vec<Uuid> {
    let mut rows: Vec<&ConnectionProfile> = profiles.iter().collect();
    rows.sort_by(|a, b| {
        b.last_connected
            .cmp(&a.last_connected)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a.id.cmp(&b.id))
    });
    rows.into_iter().map(|profile| profile.id).collect()
}

/// One connection whose durable record was refused.
///
/// The session stays live; the next launch just will not know it happened.
/// Connection time and recent-connection row are one transaction, refused
/// together. Carries the reading, the dial identity (revalidated before a
/// retry, so an edited profile is never credited) and the history row's
/// identity through which the retry is offered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecencyDebt {
    /// The profile whose reading was refused.
    pub profile_id: Uuid,
    /// The identity that reached Ready, as the dial was sent under it.
    pub identity: DialIdentity,
    /// The exact reading the store would not take.
    pub stamp: DateTime<Utc>,
    /// The history row this reading is paired with, absent when the Ready
    /// admitted none.
    pub recent_identity: Option<String>,
}

impl RecencyDebt {
    /// The sentence the session surface shows, naming the reading that was
    /// not saved.
    ///
    /// It does not say the connection failed, because it did not: the debt is
    /// only that the next launch will not know this connection happened.
    #[must_use]
    pub fn summary(&self) -> String {
        match &self.recent_identity {
            Some(_) => format!(
                "This connection is open, but neither its connection time ({}) nor its place in \
                 recent connections could be saved to the connection store.",
                self.stamp.to_rfc3339()
            ),
            None => format!(
                "This connection is open, but its connection time ({}) could not be saved to \
                 the connection store.",
                self.stamp.to_rfc3339()
            ),
        }
    }
}
