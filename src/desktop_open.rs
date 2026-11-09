//! Desktop file activation through the bounded profile importer.

use std::path::PathBuf;

use enzui_iced_core::activation::ApplicationIntent;
use iced::Task;

use crate::{App, Message, TransferResult, picker::TransferTarget};

const MAX_PENDING_FILES: usize = 32;

fn import_path(uri: &str) -> Option<(TransferTarget, PathBuf)> {
    let path = url::Url::parse(uri).ok()?.to_file_path().ok()?;
    let extension = path.extension()?.to_str()?;
    let target = if extension.eq_ignore_ascii_case("rdp") {
        TransferTarget::ImportRdp
    } else if extension.eq_ignore_ascii_case("remmina") {
        TransferTarget::ImportRemmina
    } else if extension.eq_ignore_ascii_case("json") {
        TransferTarget::ImportProfiles
    } else {
        return None;
    };
    Some((target, path))
}

impl App {
    pub(crate) fn open_desktop_intents(
        &mut self,
        intents: impl IntoIterator<Item = ApplicationIntent>,
    ) -> Task<Message> {
        if self.close_is_held() {
            return Task::none();
        }
        for intent in intents {
            if let ApplicationIntent::Open(uris) = intent {
                for uri in uris {
                    if self.launch_imports.len() >= MAX_PENDING_FILES {
                        self.transfer_result = Some(TransferResult::Failed {
                            message: "Too many connection files were opened at once.".into(),
                        });
                        break;
                    }
                    match import_path(&uri) {
                        Some(file) => self.launch_imports.push_back(file),
                        None => {
                            self.transfer_result = Some(TransferResult::Failed {
                                message: "Open an RDP, Remmina or Remote JSON profile file.".into(),
                            });
                        }
                    }
                }
            }
        }
        self.pump_desktop_imports()
    }

    pub(crate) fn pump_desktop_imports(&mut self) -> Task<Message> {
        if self.close_is_held() {
            self.launch_imports.clear();
            return Task::none();
        }
        if self.import_in_flight.is_some() {
            return Task::none();
        }
        match self.launch_imports.pop_front() {
            Some((target, path)) => self.start_transfer_at(target, &path),
            None => Task::none(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_file_uris_preserve_paths_and_refuse_network_or_unknown_formats() {
        let directory = tempfile::tempdir().expect("temporary directory");
        for (name, expected) in [
            ("Coastal desk.RDP", TransferTarget::ImportRdp),
            ("Studio.remmina", TransferTarget::ImportRemmina),
            ("remote-app-profiles.json", TransferTarget::ImportProfiles),
        ] {
            let path = directory.path().join(name);
            let uri = url::Url::from_file_path(&path).expect("file URI");
            assert_eq!(import_path(uri.as_str()), Some((expected, path)));
        }
        for uri in [
            "https://example.test/profile.rdp",
            "file:///tmp/photo.png",
            "file://server/share.rdp",
        ] {
            assert!(import_path(uri).is_none());
        }
    }

    #[test]
    fn desktop_batch_imports_every_file_once_without_connecting() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let rdp = directory.path().join("Coastal desk.rdp");
        let remmina = directory.path().join("Studio.remmina");
        std::fs::write(&rdp, "full address:s:127.0.0.1:3389\nusername:s:reviewer\n")
            .expect("RDP fixture");
        std::fs::write(
            &remmina,
            "[remmina]\nname=Studio\nprotocol=VNC\nserver=127.0.0.1:5901\n",
        )
        .expect("Remmina fixture");
        let (mut app, _) = App::boot_with_db(Some(":memory:"));
        let before = app.profiles.len();
        let intent = ApplicationIntent::Open(
            [rdp, remmina]
                .iter()
                .map(|p| url::Url::from_file_path(p).expect("file URI").to_string())
                .collect(),
        );
        let task = app.open_desktop_intents([intent]);
        crate::render_tests::connections::send_task(&mut app, task);
        assert_eq!(app.profiles.len(), before + 2);
        assert!(app.sessions.is_empty());
        assert!(app.launch_imports.is_empty());
        assert!(app.import_in_flight.is_none());
    }
}
