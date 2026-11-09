//! Screenshot publishing.
use super::*;
impl App {
    pub(crate) fn begin_screenshot(&mut self, pid: Uuid) -> Task<Message> {
        if self.close_is_held() || self.transfer_picker.is_pending() {
            return Task::none();
        }
        if self.session_status_for(pid) != SessionStatus::Connected {
            return Task::none();
        }
        let Some(frame) = self.frames.get(&pid).and_then(|sink| sink.displayed()) else {
            self.transfer_result = Some(TransferResult::Failed {
                message: "There is no remote picture to save yet.".to_string(),
            });
            return Task::none();
        };
        let shot = crate::screenshot::PendingScreenshot {
            width: frame.width(),
            height: frame.height(),
            pixels: std::sync::Arc::new(frame.pixels().to_vec()),
        };
        let name = self
            .profiles
            .iter()
            .find(|profile| profile.id == pid)
            .map_or("Remote", |profile| profile.name.as_str());
        let hints = crate::picker::ChooserHints {
            name: Some(crate::screenshot::suggested_name(
                name,
                chrono::Local::now(),
            )),
            folder: self.pictures_dir.clone(),
        };
        self.pending_screenshot = Some(shot);
        self.begin_transfer_with(crate::picker::TransferTarget::SaveScreenshot, hints)
    }
    pub(crate) fn save_screenshot_to(&mut self, chosen: &std::path::Path) -> Task<Message> {
        let Some(shot) = self.pending_screenshot.take() else {
            return Task::none();
        };
        let path = if chosen.extension().is_none() {
            chosen.with_extension("png")
        } else {
            chosen.to_path_buf()
        };
        Task::perform(
            crate::screenshot::save(path, shot),
            Message::ScreenshotSaved,
        )
    }
}
