//! Widget ids and scopes.

/// The scope key for the delete-profile confirmation, and the
/// namespace its confirm and cancel controls derive their widget ids under.
pub const DELETE_CONFIRM_SCOPE: &str = "remote-app-delete-confirm";

// ---------------------------------------------------------------------------
// Focus-restore targets for the two modal dialogs.
//
// These ids name the durable invokers focus returns to on dismissal: a row's
// Edit button (keyed by profile id), the sidebar's New connection button, and the
// Quick Connect button. `RestoreFocus` probes first, so an invoker that is not
// currently rendered is a safe no-op.
// ---------------------------------------------------------------------------

/// Stable id of the sidebar "New connection" (+) button — the invoker and
/// focus-restore target of the *add* connection form.
pub(crate) fn add_button_id() -> iced::advanced::widget::Id {
    iced::advanced::widget::Id::from("remote-app-new-connection")
}

/// Stable id of a profile row's "Edit" button — the invoker and focus-restore
/// target of the *edit* form for that profile.
pub(crate) fn edit_button_id(profile_id: uuid::Uuid) -> iced::advanced::widget::Id {
    iced::advanced::widget::Id::from(format!("remote-app-edit-{profile_id}"))
}

/// Stable id of the "Quick Connect" button — the invoker and focus-restore
/// target of the Quick Connect dialog.
pub(crate) fn quick_connect_button_id() -> iced::advanced::widget::Id {
    iced::advanced::widget::Id::from("remote-app-quick-connect")
}

/// Stable id of the selected connection's primary session command, whatever
/// state it is labelled for.
///
/// One id across Connect / Cancel / Disconnect / Retry, because it is one
/// control: an assistive technology that resolved the node while the session
/// was disconnected keeps addressing the same button once it reads `Retry`.
pub(crate) fn session_action_button_id(profile_id: uuid::Uuid) -> iced::advanced::widget::Id {
    iced::advanced::widget::Id::from(format!("remote-app-session-action-{profile_id}"))
}
