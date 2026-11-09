//! Profile import and export.

use super::*;

impl App {
    /// Begin an export or import: open the host's file chooser, unless the
    /// environment names the path outright.
    ///
    /// `REMOTE_APP_EXPORT_PATH` / `REMOTE_APP_RDP_PATH` make reducer tests and the
    /// capture harness deterministic on hosts without a portal. Without an override
    /// the user's chooser decides, and a missing chooser is reported in the transfer
    /// banner rather than falling back to `~/Documents`.
    pub(crate) fn begin_transfer(
        &mut self,
        target: crate::picker::TransferTarget,
    ) -> Task<Message> {
        self.begin_transfer_with(target, crate::picker::ChooserHints::default())
    }

    /// [`Self::begin_transfer`] with per-request chooser hints: the name a
    /// Save dialog is pre-filled with and the folder it opens in.
    pub(crate) fn begin_transfer_with(
        &mut self,
        target: crate::picker::TransferTarget,
        hints: crate::picker::ChooserHints,
    ) -> Task<Message> {
        if self.close_is_held() || self.transfer_picker.is_pending() {
            return Task::none();
        }
        // Overrides are snapshotted at boot, so tests inject through
        // `App::transfer_overrides` without mutating process env.
        if let Some(path) = self.transfer_overrides.get(target) {
            return self.start_transfer_at(target, &path);
        }
        match self.transfer_picker.begin(target, self.main_window, hints) {
            Ok(task) => task,
            Err(outcome) => self.finish_transfer_pick(target, outcome),
        }
    }

    /// Route one known path by direction.
    ///
    /// An export is a bounded write of state this app already holds, so it
    /// settles here. An import reads a file nobody vouched for, so it is
    /// dispatched and nothing is decided until its answer comes back.
    pub(crate) fn start_transfer_at(
        &mut self,
        target: crate::picker::TransferTarget,
        path: &std::path::Path,
    ) -> Task<Message> {
        match target {
            crate::picker::TransferTarget::SaveScreenshot => self.save_screenshot_to(path),
            other => match other.import_format() {
                Some(format) => self.dispatch_import(other, format, path),
                None => {
                    let result = self.run_export(path);
                    self.transfer_result = Some(result);
                    Task::none()
                }
            },
        }
    }

    /// Start reading and parsing one chosen file off the reducer thread.
    ///
    /// The worker's slot is claimed first; a refused claim leaves the generation,
    /// in-flight entry and running import untouched and reports why. A granted claim
    /// retires the previous generation, publishes the in-flight entry before the task
    /// (so the first frame shows Importing with Cancel), and clears the previous
    /// outcome.
    fn dispatch_import(
        &mut self,
        target: crate::picker::TransferTarget,
        format: crate::import_source::ImportFormat,
        path: &std::path::Path,
    ) -> Task<Message> {
        // Claimed under the generation this import answers under, so owner and reducer
        // check the same number.
        let generation = self.import_generation.wrapping_add(1);
        let claim = match crate::import_source::enqueue(generation, format, path.to_path_buf()) {
            Ok(claim) => claim,
            Err(refusal) => {
                self.transfer_result = Some(TransferResult::Failed {
                    message: refusal.banner_message(),
                });
                return Task::none();
            }
        };
        self.retire_imports();
        debug_assert_eq!(self.import_generation, generation);
        self.import_in_flight = Some(crate::app_state::ImportInFlight { generation, target });
        self.import_cancellation = Some(claim.cancellation);
        self.transfer_result = None;
        // The task only awaits the owner's answer; the open, the read and the
        // parse all happen on the owner's own thread.
        Task::perform(claim.pending.settle(), move |outcome| {
            Message::ImportReady {
                generation,
                target,
                outcome: Box::new(outcome),
            }
        })
    }

    /// Retire every import answer still in flight, and return the generation
    /// a new one may be dispatched under.
    ///
    /// Cancelling tells the owner the answer is unwanted and stops unstarted
    /// requests; advancing the generation stops an answer already on its way, since a
    /// read in progress cannot be interrupted.
    pub(crate) fn retire_imports(&mut self) -> u64 {
        if let Some(cancellation) = self.import_cancellation.take() {
            cancellation.cancel();
        }
        self.import_generation = self.import_generation.wrapping_add(1);
        self.import_in_flight = None;
        self.import_generation
    }

    /// Route a profile import/export or screenshot chooser outcome.
    pub(crate) fn finish_transfer_pick(
        &mut self,
        target: crate::picker::TransferTarget,
        outcome: enzui_iced_widgets::file_chooser::PortalOutcome<
            enzui_iced_widgets::file_chooser::FileResult,
        >,
    ) -> Task<Message> {
        use enzui_iced_widgets::file_chooser::PortalOutcome;
        if self.close_is_held() {
            self.pending_screenshot = None;
            return Task::none();
        }
        match outcome {
            PortalOutcome::Completed(result) => match crate::picker::chosen_path(&result) {
                Some(path) => return self.start_transfer_at(target, &path),
                None => {
                    self.pending_screenshot = None;
                    self.transfer_result = Some(TransferResult::Failed {
                        message: "That location is not a local file.".into(),
                    });
                }
            },
            PortalOutcome::Cancelled(_) => {
                self.pending_screenshot = None;
            }
            other => {
                if let Some(message) = enzui_iced_widgets::file_chooser::failure_text(&other) {
                    self.transfer_result = Some(TransferResult::Failed { message });
                }
            }
        }
        Task::none()
    }

    fn export_result(
        path: &std::path::Path,
        count: usize,
        result: Result<(), enzui_iced_core::user_file::SaveError>,
    ) -> TransferResult {
        match result {
            Ok(()) => TransferResult::Exported {
                path: path.display().to_string(),
                count,
            },
            Err(error) if error.was_published() => TransferResult::ExportPublicationUncertain {
                path: path.display().to_string(),
                count,
            },
            Err(error) => {
                let cause =
                    crate::error_boundary::TransferFailure::classify_write(error.io_error());
                TransferResult::Failed {
                    message: cause.body(crate::error_boundary::TransferOperation::Write),
                }
            }
        }
    }

    /// Write every saved profile to `path` as one export document.
    ///
    /// Bounded by construction: the bytes come from state this app already
    /// holds, so there is nothing here to admit or refuse.
    fn run_export(&self, path: &std::path::Path) -> TransferResult {
        let json = crate::portable::export_json(&self.profiles);
        let count = self.profiles.len();
        Self::export_result(path, count, save_export(path, json.as_bytes()))
    }

    /// Turn one import proposal into a reported outcome.
    ///
    /// Nothing has been written when this runs. Every arm either commits the
    /// whole document or reports a refusal, so there is no path that leaves
    /// part of one imported.
    pub(crate) fn settle_import(
        &mut self,
        outcome: crate::import_source::ImportOutcome,
    ) -> TransferResult {
        use crate::import_source::ImportOutcome;
        match outcome {
            // Already authored, bounded copy from a fieldless refusal; the
            // store and the model were never touched.
            ImportOutcome::Refused(message) => TransferResult::Failed { message },
            ImportOutcome::Single(profile) => {
                let name = crate::display::bound_display_name(&profile.name);
                match self.commit_import(vec![profile]) {
                    Err(message) => TransferResult::Failed { message },
                    Ok(_) => TransferResult::Imported { name },
                }
            }
            ImportOutcome::Reported {
                profile,
                unsupported,
                has_reported_password,
                omitted,
            } => {
                let name = crate::display::bound_display_name(&profile.name);
                match self.commit_import(vec![profile]) {
                    // A refused write is reported instead of the warning
                    // summary: the warnings describe a row that would exist,
                    // and this one does not.
                    Err(message) => TransferResult::Failed { message },
                    Ok(_) => TransferResult::ImportedWithWarnings {
                        name,
                        unsupported,
                        has_reported_password,
                        omitted,
                    },
                }
            }
            ImportOutcome::Document(profiles) => match self.commit_import(profiles) {
                Err(message) => TransferResult::Failed { message },
                Ok(count) => TransferResult::ImportedMany { count },
            },
        }
    }

    /// Write a whole document as one transaction, then publish it.
    ///
    /// `Err` carries authored banner copy and means the store, profile list, order
    /// and selection are unchanged.
    ///
    /// Bounds are applied during the parse, so there is no second admission step.
    /// Publication appends: every imported profile gets a fresh identity via
    /// `ConnectionProfile::new` (in
    /// `crate::portable::ExportedProfile::to_profile`,
    /// [`crate::portable::import_rdp`] and
    /// [`crate::import_remmina::parse_remmina`]), so importing the same file twice
    /// yields two sets rather than overwriting.
    fn commit_import(&mut self, profiles: Vec<ConnectionProfile>) -> Result<usize, String> {
        if profiles.iter().any(|p| p.protocol == Protocol::Ssh) {
            return Err("SSH and SFTP connections belong in Terminal and Files. This document was not imported.".into());
        }
        self.db.upsert_all(&profiles).map_err(|err| {
            let cause = crate::error_boundary::DbWriteFailure::classify(&err);
            let name = crate::display::bound_display_name(
                profiles.first().map_or("", |p| p.name.as_str()),
            );
            cause.body(crate::error_boundary::DbWriteOperation::Save, &name)
        })?;
        let count = profiles.len();
        let last = profiles.last().map(|p| p.id);
        self.profiles.extend(profiles);
        if let Some(id) = last {
            self.selected_profile = Some(id);
        }
        Ok(count)
    }
}
