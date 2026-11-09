//! Tagged parented chooser intent and transfer purposes.

#[cfg(test)]
#[cfg(not(test))]
use enzui_iced_widgets::file_chooser::PortalBackend;

use enzui_iced_widgets::file_chooser::{
    ChooserOptions, ChooserSession, FileFilter, FileResult, PortalOperation, PortalOutcome,
    PortalWake,
};

/// Which command opened the chooser, so the terminal outcome is routed back to
/// the transfer it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferTarget {
    /// `Export all profiles (JSON)` — choose where the export document is
    /// written.
    ExportProfiles,
    /// `Import profiles (JSON)` — choose an export document to restore from.
    ImportProfiles,
    /// `Import .rdp files` — choose a foreign `.rdp` connection file.
    ImportRdp,
    /// `Import a Remmina profile` — choose a `.remmina` INI file.
    /// One-profile-per-file, same shape as [`Self::ImportRdp`].
    ImportRemmina,
    /// `Save screenshot` — choose where the captured remote picture is saved
    /// as a PNG.
    SaveScreenshot,
}

/// Per-request chooser hints a target cannot know statically: the name a Save
/// dialog is pre-filled with and the folder it opens in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChooserHints {
    pub name: Option<String>,
    pub folder: Option<std::path::PathBuf>,
}

impl TransferTarget {
    /// The portal operation this target asks for. Export saves; both imports
    /// open, so a chooser cannot overwrite a file meant to be read.
    pub fn operation(self) -> PortalOperation {
        match self {
            Self::ExportProfiles | Self::SaveScreenshot => PortalOperation::SaveFile,
            Self::ImportProfiles | Self::ImportRdp | Self::ImportRemmina => {
                PortalOperation::OpenFile
            }
        }
    }

    /// The chooser's window title.
    pub fn title(self) -> &'static str {
        match self {
            Self::ExportProfiles => "Export connection profiles",
            Self::ImportProfiles => "Import connection profiles",
            Self::ImportRdp => "Import an .rdp connection file",
            Self::ImportRemmina => "Import a Remmina profile",
            Self::SaveScreenshot => "Save a screenshot of the remote desktop",
        }
    }

    /// The name a Save dialog is pre-filled with, or `None` for an Open dialog.
    pub fn suggested_name(self) -> Option<&'static str> {
        match self {
            Self::ExportProfiles => Some("remote-app-profiles.json"),
            // The download's name is the remote file's, supplied per request
            // through [`ChooserHints`].
            Self::ImportProfiles | Self::ImportRdp | Self::ImportRemmina | Self::SaveScreenshot => {
                None
            }
        }
    }

    /// The chooser's file-type filter.
    pub fn filter(self) -> FileFilter {
        match self {
            Self::ExportProfiles | Self::ImportProfiles => {
                FileFilter::extensions("Profile export (*.json)", ["json"])
            }
            Self::ImportRdp => FileFilter::extensions("Remote Desktop file (*.rdp)", ["rdp"]),
            Self::ImportRemmina => {
                FileFilter::extensions("Remmina profile (*.remmina)", ["remmina"])
            }
            // Any file may be uploaded, so narrowing the chooser would hide
            // most of the user's files behind a filter they did not ask for.
            Self::SaveScreenshot => FileFilter::extensions("PNG image (*.png)", ["png"]),
        }
    }

    /// The title of the banner shown while a chosen file is being read.
    ///
    /// Total over the enum, so the view needs no fallback. The export target
    /// names the general case: it reads nothing, and never reaches this
    /// banner.
    pub fn importing_title(self) -> &'static str {
        match self {
            Self::ExportProfiles => "Importing connections",
            Self::ImportProfiles => "Importing connection profiles",
            Self::ImportRdp => "Importing an .rdp connection file",
            Self::ImportRemmina => "Importing a Remmina profile",
            Self::SaveScreenshot => "Saving a screenshot",
        }
    }

    /// Which parser this target's chosen file is handed to, or `None` for a
    /// target that writes rather than reads.
    ///
    /// The one place the two directions are told apart, so the bounded import
    /// path cannot be reached with an export target.
    pub fn import_format(self) -> Option<crate::import_source::ImportFormat> {
        use crate::import_source::ImportFormat;
        match self {
            Self::ExportProfiles | Self::SaveScreenshot => None,
            Self::ImportRdp => Some(ImportFormat::Rdp),
            Self::ImportRemmina => Some(ImportFormat::Remmina),
            Self::ImportProfiles => Some(ImportFormat::Document),
        }
    }
}

/// Boot-time transfer path overrides.
///
/// Held on `App` because `cargo test` runs tests as threads in one process,
/// where an env write would leak into siblings; tests write it through
/// `Self::set`. [`App::boot`](crate::App::boot) builds it via
/// [`Self::from_env`].
#[derive(Clone, Debug, Default)]
pub struct TransferOverrides {
    /// `REMOTE_APP_EXPORT_PATH`: shared by JSON export and JSON import.
    export: Option<std::path::PathBuf>,
    /// `REMOTE_APP_RDP_PATH`: the `.rdp` import override.
    rdp: Option<std::path::PathBuf>,
    /// `REMOTE_APP_REMMINA_PATH`: the `.remmina` import override.
    remmina: Option<std::path::PathBuf>,
    /// `REMOTE_APP_SCREENSHOT_PATH`: the local path a screenshot is saved to
    /// without a chooser.
    screenshot: Option<std::path::PathBuf>,
}

impl TransferOverrides {
    /// Capture overrides once at application startup.
    #[must_use]
    pub fn from_env() -> Self {
        fn non_empty(key: &str) -> Option<std::path::PathBuf> {
            std::env::var(key)
                .ok()
                .filter(|s| !s.is_empty())
                .map(std::path::PathBuf::from)
        }
        Self {
            export: non_empty("REMOTE_APP_EXPORT_PATH"),
            rdp: non_empty("REMOTE_APP_RDP_PATH"),
            remmina: non_empty("REMOTE_APP_REMMINA_PATH"),
            screenshot: non_empty("REMOTE_APP_SCREENSHOT_PATH"),
        }
    }

    /// The override path for `target`, if one is set; makes
    /// [`crate::App::begin_transfer`] skip the file chooser.
    #[must_use]
    pub fn get(&self, target: TransferTarget) -> Option<std::path::PathBuf> {
        match target {
            TransferTarget::ExportProfiles | TransferTarget::ImportProfiles => self.export.clone(),
            TransferTarget::ImportRdp => self.rdp.clone(),
            TransferTarget::ImportRemmina => self.remmina.clone(),
            TransferTarget::SaveScreenshot => self.screenshot.clone(),
        }
    }
}

pub type ParentReply = enzui_parent_lease::Handoff<
    enzui_iced_core::blocking_task::BlockingTaskSettlement<enzui_wayland::ParentAdoption>,
>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PickTag {
    pub target: TransferTarget,
    generation: u64,
}

#[derive(Debug)]
pub struct Picker {
    session: ChooserSession<PickTag>,
    generation: u64,
    active: Option<PickTag>,
    /// The hints of the active request, applied when the dialog opens.
    hints: ChooserHints,
    parent_window: Option<(
        iced::window::Id,
        enzui_iced_core::portal::cancel::PortalCancel,
    )>,
    exports: Option<enzui_iced_widgets::export_pool::ExportPoolOwner>,
    #[cfg(test)]
    injected_backend: bool,
}

impl Default for Picker {
    fn default() -> Self {
        Self::new()
    }
}

impl Picker {
    pub fn new() -> Self {
        Self {
            session: ChooserSession::new().with_fallback(),
            generation: 0,
            active: None,
            hints: ChooserHints::default(),
            parent_window: None,
            exports: None,
            #[cfg(test)]
            injected_backend: false,
        }
    }

    pub fn is_pending(&self) -> bool {
        self.active.is_some()
    }

    pub fn begin(
        &mut self,
        target: TransferTarget,
        window: Option<iced::window::Id>,
        hints: ChooserHints,
    ) -> Result<iced::Task<crate::Message>, PortalOutcome<FileResult>> {
        if self.is_pending() {
            return Ok(iced::Task::none());
        }
        self.hints = hints;
        #[cfg(test)]
        if self.injected_backend {
            return self.start(target).map(|()| iced::Task::none());
        }
        let window = window.ok_or(PortalOutcome::ParentUnavailable)?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(PortalOutcome::Unavailable)?;
        self.generation = generation;
        let tag = PickTag { target, generation };
        let pool = self.exports.get_or_insert_with(|| {
            enzui_iced_widgets::export_pool::ExportPoolOwner::start()
                .unwrap_or_else(|_| enzui_iced_widgets::export_pool::ExportPoolOwner::unavailable())
        });
        let cancel = enzui_iced_core::portal::cancel::PortalCancel::new();
        let task = enzui_iced_widgets::portal_parent::export_parent_task(
            &pool.dispatcher(),
            generation,
            window,
            cancel.clone(),
            std::time::Duration::from_secs(3),
        )
        .map(move |reply| crate::Message::ChooserParentReady(tag, window, reply));
        self.active = Some(tag);
        self.parent_window = Some((window, cancel));
        Ok(task)
    }

    pub fn parent_ready(
        &mut self,
        tag: PickTag,
        window: iced::window::Id,
        reply: ParentReply,
        live_window: Option<iced::window::Id>,
    ) -> iced::Task<crate::Message> {
        let Some(reply) = reply.take() else {
            return iced::Task::none();
        };
        if self.active != Some(tag)
            || live_window != Some(window)
            || self.parent_window.as_ref().map(|(id, _)| *id) != Some(window)
        {
            return iced::Task::none();
        }
        self.parent_window = None;
        let parent = match reply.into_result() {
            Ok(enzui_wayland::ParentAdoption::Parented { export, .. }) => {
                enzui_iced_widgets::file_chooser::ChooserParent::Wayland { window, export }
            }
            _ => {
                return iced::Task::done(crate::Message::TransferChosen(
                    tag,
                    PortalOutcome::ParentUnavailable,
                ));
            }
        };
        let options = self.options(tag.target);
        match self
            .session
            .start_parented(tag, tag.target.operation(), options, parent, |id| {
                live_window == Some(id)
            }) {
            Ok(()) => iced::Task::none(),
            Err(outcome) => iced::Task::done(crate::Message::TransferChosen(tag, outcome)),
        }
    }

    pub fn parent_closed(&mut self, window: iced::window::Id) {
        let _ = self.session.parent_closed(window);
        self.cancel();
    }

    /// The dialog options for `target`, with the active request's hints.
    fn options(&self, target: TransferTarget) -> ChooserOptions {
        let mut options = ChooserOptions::new()
            .title(target.title())
            .filter(target.filter());
        if let Some(name) = self
            .hints
            .name
            .as_deref()
            .or_else(|| target.suggested_name())
        {
            options = options.current_name(name);
        }
        if let Some(folder) = self.hints.folder.as_ref() {
            options = options.current_folder(folder.clone());
        }
        options
    }

    #[cfg(test)]
    pub fn start(&mut self, target: TransferTarget) -> Result<(), PortalOutcome<FileResult>> {
        let options = self.options(target);
        if self.session.is_pending() {
            return Ok(());
        }
        let Some(generation) = self.generation.checked_add(1) else {
            return Err(PortalOutcome::Unavailable);
        };
        self.generation = generation;
        let tag = PickTag { target, generation };
        let started = self.session.start(tag, target.operation(), options);
        self.active = started.as_ref().ok().map(|_| tag);
        started
    }

    pub fn completion_subscription(&self) -> iced::Subscription<PortalWake> {
        self.session.subscription()
    }

    pub fn pump(&mut self) -> iced::Task<crate::Message> {
        self.session.pump(crate::Message::TransferChosen)
    }

    pub fn handle(
        &mut self,
        tag: PickTag,
        event: enzui_iced_widgets::file_chooser::FallbackEvent,
    ) -> iced::Task<crate::Message> {
        if self.active != Some(tag) {
            return iced::Task::none();
        }
        self.session.handle(event, crate::Message::TransferChosen)
    }

    pub fn view<'a>(
        &'a self,
        content: iced::Element<'a, crate::Message>,
    ) -> iced::Element<'a, crate::Message> {
        self.session.view(content, move |event| match self.active {
            Some(tag) => crate::Message::TransferChooser(tag, event),
            None => crate::Message::NoOp,
        })
    }

    pub fn claim(&mut self, tag: PickTag) -> bool {
        if self.active != Some(tag) {
            return false;
        }
        self.active = None;
        self.hints = ChooserHints::default();
        true
    }

    pub fn cancel(&mut self) {
        self.active = None;
        self.hints = ChooserHints::default();
        if let Some((_, cancel)) = self.parent_window.take() {
            cancel.cancel(enzui_iced_core::portal::CancelReason::ParentClosed);
        }
        let _ = self
            .session
            .cancel(enzui_iced_widgets::file_chooser::CancelReason::ParentClosed);
    }
}

impl Drop for Picker {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// The single local path a completed chooser produced, or `None` when the user
/// picked a non-local location (a network URI this app cannot read or write).
pub fn chosen_path(result: &FileResult) -> Option<std::path::PathBuf> {
    result.first_local_path()
}

#[cfg(test)]
impl TransferOverrides {}

#[cfg(test)]
pub mod tests {
    //! An in-process [`PortalBackend`] the reducer tests inject, so the whole
    //! outcome flow is exercised with no D-Bus, no session bus and no dialog on
    //! anyone's desktop. It records what was asked for and scripts one reply —
    //! the same shape as mail-app's and music-app's `ScriptedBackend`.
}

#[cfg(test)]
mod parent_tests {}
