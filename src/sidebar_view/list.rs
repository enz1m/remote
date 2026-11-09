//! Profile grouping and the titlebar import menu.

use super::*;
use enzui_iced_core::action_overflow::Descriptor;
use enzui_iced_widgets::action_bar::{ActionItem, Collector, enz_action_bar};

pub const IMPORT_MENU_TRIGGER_ID: &str = "remote-app-import-trigger";

pub fn grouping(app: &App) -> Grouping {
    let profiles: Vec<_> = app
        .profiles
        .iter()
        .filter(|profile| crate::model::matches_search(profile, &app.search_query))
        .cloned()
        .collect();
    grouped(&profiles, &app.group_expansion)
}

pub fn import_button(app: &App) -> Element<'_, Message> {
    let actions = [
        ("rdp", "Remote Desktop (.rdp)…", Message::ImportRdp),
        ("remmina", "Remmina profile…", Message::ImportRemmina),
        ("json", "Remote profiles (.json)…", Message::ImportProfiles),
        ("export", "Export all profiles…", Message::ExportProfiles),
    ]
    .into_iter()
    .map(|(id, label, message)| {
        ActionItem::command(
            Descriptor::new(id),
            Action::new(id, message).with_label(match label {
                "Remote Desktop (.rdp)…" => crate::l10n::text("remote-remote-desktop-rdp"),
                "Remmina profile…" => crate::l10n::text("remote-remmina-profile"),
                "Remote profiles (.json)…" => crate::l10n::text("remote-remote-profiles-json"),
                "Export all profiles…" => crate::l10n::text("remote-export-all-profiles"),
                _ => label.to_owned(),
            }),
        )
    })
    .collect();
    enz_action_bar(actions, Message::ToggleImportMenu)
        .max_inline_actions(0)
        .spacing(SpaceToken::None)
        .trigger_label(crate::l10n::text("remote-import"))
        .trigger_tooltip(crate::l10n::text("remote-import-export-tooltip"))
        .collector(Collector::Kebab {
            icon: "import".into(),
            tokens: None,
        })
        .overflow_open(app.import_menu_open)
        .on_dismiss(Message::CloseImportMenu)
        .overflow_trigger_id(iced::advanced::widget::Id::new(IMPORT_MENU_TRIGGER_ID))
        .menu_id_prefix("remote-app-import-options")
        .into_element()
}

pub fn new_connection_action() -> Action<Message> {
    Action::new("connection.new", Message::FormOpenAdd).with_label("New Connection")
}
