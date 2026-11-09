//! Network scan and recent-book pruning.

use super::*;

impl App {
    /// Claim the discovery worker for one browse.
    ///
    /// A refused claim leaves the running browse and generation alone and
    /// reports why; only a granted claim retires the previous generation.
    pub(crate) fn dispatch_scan(&mut self) -> Task<Message> {
        // Claimed under the generation this browse will answer under, so the
        // owner stamps the same number the reducer will check.
        let generation = self.scan_generation.wrapping_add(1);
        let mut pending =
            match crate::discovery::dispatch(generation, std::sync::Arc::clone(&self.scanner)) {
                Ok(pending) => pending,
                Err(refusal) => {
                    self.discovery_refusal = Some(refusal);
                    return Task::none();
                }
            };
        let retired = self.retire_scan();
        debug_assert_eq!(retired, generation);
        self.scanning = true;
        self.discovery_refusal = None;
        // The wait is taken out before the handle is stored, because the two
        // halves go to different owners: the reducer keeps the handle so a
        // later press can cancel this browse, and the task keeps the answer.
        let settle = pending.watch();
        self.scan_in_flight = Some(pending);
        Task::perform(settle, move |outcome| Message::ScanFinished {
            generation,
            outcome,
        })
    }

    /// Abandon the browse in flight, and return the generation the next one
    /// may run under.
    ///
    /// Settles the generation and raises the cancel flag the browse reads. A
    /// browse inside a bus call cannot be interrupted and holds the owner's slot
    /// until it exits, so the next press may be told the owner is busy.
    pub(crate) fn retire_scan(&mut self) -> u64 {
        if let Some(pending) = self.scan_in_flight.take() {
            pending.cancel();
        }
        self.scanning = false;
        self.scan_generation = self.scan_generation.wrapping_add(1);
        self.scan_generation
    }

    /// Apply one browse's answer.
    ///
    /// Touches `discovered`, `scanning`, `scan_completed` and the refusal, and
    /// nothing else: a scan is not a library change, so `profiles`, the
    /// selection, the store and Quick Connect's history are all left exactly
    /// as they were.
    pub(crate) fn settle_scan(&mut self, outcome: crate::discovery::DiscoveryOutcome) {
        use crate::discovery::DiscoveryOutcome;

        self.scan_in_flight = None;
        self.scanning = false;
        match outcome {
            DiscoveryOutcome::Found(hosts) => {
                // The press has to leave a trace even when the network answers
                // with nobody, so the section can say so instead of silently
                // returning to its untouched state.
                self.scan_completed = true;
                self.discovery_refusal = None;
                self.discovered = hosts;
            }
            // A browse that could not run keeps the previous results; an empty list
            // would claim a quiet network.
            DiscoveryOutcome::Refused(refusal) => {
                self.discovery_refusal = Some(refusal);
            }
        }
    }

    /// Forget one recorded endpoint, settling the store first.
    ///
    /// The delete lands before the row leaves the list. It is unconditional even
    /// for an identity marked unsaved: the mark covers only the newest write, and
    /// an earlier connection may have persisted a row under the same identity.
    pub(crate) fn forget_recent(&mut self, identity: &str) {
        let Some(subject) = self
            .recents
            .iter()
            .find(|r| r.key() == identity)
            .map(|r| r.endpoint())
        else {
            return;
        };
        if let Err(err) = self.db.delete_recent(identity) {
            self.credential_notice = Some(CredentialNotice::write_refused(
                crate::error_boundary::DbWriteFailure::classify(&err),
                crate::error_boundary::DbWriteOperation::ForgetRecent,
                &subject,
            ));
            return;
        }
        self.recents.retain(|r| r.key() != identity);
        self.unsaved_recents.retain(|k| k != identity);
        // A debt is only retryable through the row it is paired with, so a
        // forgotten row takes its debt with it rather than leaving a reading
        // the user is told about and cannot act on.
        self.recency_debt
            .retain(|debt| debt.recent_identity.as_deref() != Some(identity));
        // The banner's missing row was just deleted on purpose.
        self.clear_recent_write_notice();
    }

    /// Forget the whole history, settling the store first.
    ///
    /// Same rule as [`Self::forget_recent`]: one refused statement leaves the
    /// list exactly as it was rather than emptying a screen the next launch
    /// refills. All-or-nothing, because a partial clear would leave the user
    /// unable to say what they had asked to remove.
    pub(crate) fn clear_recents(&mut self) {
        if self.recents.is_empty() {
            return;
        }
        if let Err(err) = self.db.clear_recents() {
            self.credential_notice = Some(CredentialNotice::write_refused(
                crate::error_boundary::DbWriteFailure::classify(&err),
                crate::error_boundary::DbWriteOperation::ForgetRecent,
                &crate::l10n::text("remote-recent-header"),
            ));
            return;
        }
        self.recents.clear();
        self.unsaved_recents.clear();
        // Same rule as forgetting one row: every paired debt has just lost
        // the row it would be retried through.
        self.recency_debt
            .retain(|debt| debt.recent_identity.is_none());
        self.clear_recent_write_notice();
    }

    /// Withdraw a banner raised about a recents write, once one succeeds.
    ///
    /// Scoped to that operation rather than clearing the notice outright: a
    /// banner about a credential or a profile save is about something this
    /// delete did not touch, and taking it down would hide a failure the user
    /// has not seen the end of.
    pub(crate) fn clear_recent_write_notice(&mut self) {
        let about_recents = self
            .credential_notice
            .as_ref()
            .is_some_and(CredentialNotice::is_recent_write);
        if about_recents {
            self.credential_notice = None;
        }
    }
}
