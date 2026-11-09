//! Commands and keyboard help share one binding catalog.

use crate::Message;
use enzui_iced_core::shortcut::{Modifier, Shortcut};
use enzui_iced_core::{ShortcutBinding, dispatch_shortcut_command};

#[derive(Debug, Clone, Copy)]
pub(crate) enum Command {
    NewConnection,
    QuickConnect,
    Help,
}

pub(crate) fn bindings() -> Vec<ShortcutBinding<Command>> {
    [
        (
            "remote.new",
            Command::NewConnection,
            'n',
            "remote-new-connection",
        ),
        (
            "remote.quick",
            Command::QuickConnect,
            'k',
            "remote-quick-connect",
        ),
        (
            "remote.help",
            Command::Help,
            '/',
            "remote-keyboard-shortcuts",
        ),
    ]
    .into_iter()
    .map(|(id, command, key, label)| {
        ShortcutBinding::new(id, command, Shortcut::new(Modifier::CTRL, key))
            .with_description(crate::l10n::text(label))
    })
    .collect()
}

pub(crate) fn dispatch(event: &iced::keyboard::Event) -> Option<Message> {
    dispatch_shortcut_command(bindings().iter(), event, &()).map(Message::AppCommand)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dialog {
    Help,
}

pub(crate) fn help(app: &crate::App) -> iced::Element<'_, Message> {
    let entries = enzui_iced_widgets::shortcut_list::shortcut_catalog_entries(bindings().iter());
    enzui_iced_widgets::shortcuts_dialog::enz_shortcuts_dialog(true, entries)
        .dialog_width(crate::form_view::dialog_width(app.window_width))
        .dialog_max_height(crate::form_view::dialog_max_height(
            &app.enz_theme,
            app.window_height,
        ))
        .into_surface(Some(Box::new(|| Message::CloseHelp)))
}
