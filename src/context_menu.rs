//! Typed saved-profile commands with live row reconciliation.

use enzui_iced_core::context_menu::{InvocationKind, Point as CorePoint};
use enzui_iced_widgets::context_menu_host::{ContextMenu, ContextMenuItem, FocusRestoreTarget};
use iced::Point;
use uuid::Uuid;

use crate::App;
use crate::model::ConnectionProfile;

/// A row of the connection context menu.
///
/// One enum, so a label and the effect behind it are produced by the same match
/// arm and cannot drift — `Delete` cannot end up wired to `Duplicate`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RowKind {
    /// Open the profile's session, or focus the one it already has.
    Connect,
    /// This build has no backend for the profile's protocol.
    ///
    /// Takes [`Self::Connect`]'s place, disabled, with the disclosure as its
    /// label, so the user is not left guessing why the verb vanished. Skipped by
    /// keyboard navigation; dispatches nothing.
    Unavailable,
    /// Open the connection form on this profile.
    Edit,
    /// Tear down the profile's live session.
    Disconnect,
    /// Broadcast a Wake-on-LAN magic packet to the profile's MAC.
    Wake,
    /// Flip the profile's favourite flag.
    ToggleFavorite,
    /// Copy the profile under a `(copy)`-suffixed name.
    Duplicate,
    /// Delete the profile. Destructive.
    Delete,
}

/// Separator-delimited groups.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum RowGroup {
    /// Connect / Edit / Disconnect / Wake.
    Session,
    /// Favourite / Duplicate.
    Organise,
    /// Delete.
    Destructive,
}

impl RowKind {
    /// A stable key for the row — the row's `EntryId` in `enz_menu`. Derived
    /// from the action, never from the position, so a reorder moves the
    /// keyboard cursor with the row.
    pub fn key(self) -> &'static str {
        match self {
            RowKind::Connect => "connect",
            RowKind::Unavailable => "unavailable",
            RowKind::Edit => "edit",
            RowKind::Disconnect => "disconnect",
            RowKind::Wake => "wake",
            RowKind::ToggleFavorite => "favorite",
            RowKind::Duplicate => "duplicate",
            RowKind::Delete => "delete",
        }
    }

    /// The row's group. Rules go between groups, never inside one.
    pub fn group(self) -> RowGroup {
        match self {
            RowKind::Connect
            | RowKind::Unavailable
            | RowKind::Edit
            | RowKind::Disconnect
            | RowKind::Wake => RowGroup::Session,
            RowKind::ToggleFavorite | RowKind::Duplicate => RowGroup::Organise,
            RowKind::Delete => RowGroup::Destructive,
        }
    }

    /// Only `Delete` is destructive: it removes a saved connection and its
    /// keyring secret.
    pub fn destructive(self) -> bool {
        self == RowKind::Delete
    }

    /// The row's Lucide / semantic icon.
    ///
    /// Every row has an icon because `enz_menu` reserves a leading gutter
    /// whenever any row has one, and the destructive row should be
    /// distinguishable at a glance. Each name is the one the sibling apps use
    /// for the same verb.
    pub fn icon(self) -> &'static str {
        match self {
            RowKind::Connect => "plug",
            // The same glyph the withdrawn command carried, so the row keeps
            // its place in the gutter and reads as the connect slot rather
            // than as an unrelated notice.
            RowKind::Unavailable => "plug",
            RowKind::Edit => "pencil",
            RowKind::Disconnect => "unplug",
            RowKind::Wake => "power",
            RowKind::ToggleFavorite => "misc.star",
            RowKind::Duplicate => "copy",
            RowKind::Delete => "trash-2",
        }
    }

    pub fn label(self, has_session: bool, is_favorite: bool) -> String {
        let key = match self {
            Self::Connect if has_session => "remote-focus-session",
            Self::Connect => "remote-connect",
            Self::Unavailable => "remote-not-in-build",
            Self::Edit => "remote-edit-menu",
            Self::Disconnect => "remote-disconnect",
            Self::Wake => "remote-wake",
            Self::ToggleFavorite if is_favorite => "remote-remove-favorite",
            Self::ToggleFavorite => "remote-add-favorite",
            Self::Duplicate => "remote-duplicate",
            Self::Delete => "remote-delete",
        };
        crate::l10n::text(key)
    }
}

#[derive(Debug, Default)]
pub struct OpenContextMenu {
    pub menu: ContextMenu<Uuid, RowKind>,
    invoker: Option<iced::advanced::widget::Id>,
}

impl OpenContextMenu {
    pub fn open(
        &mut self,
        profile: Uuid,
        at: Point,
        rows: Vec<ContextMenuItem<RowKind>>,
        row_path: Vec<String>,
    ) {
        let restore = if row_path.is_empty() {
            FocusRestoreTarget::widget(crate::view::add_button_id())
        } else {
            FocusRestoreTarget::widget(crate::sidebar_view::row_id(&row_path))
        };
        self.invoker = restore.invoker_id().cloned();
        self.menu.open_restoring(
            profile,
            InvocationKind::Pointer(CorePoint::new(at.x, at.y)),
            rows,
            restore,
        );
    }

    pub fn close(&mut self) {
        self.menu.close();
        self.invoker = None;
    }
}

/// The rows for `profile`, with three conditionals applied.
///
/// * `Disconnect` only when a session exists;
/// * `Wake (WoL)` only when the profile carries a MAC;
/// * everything else always.
///
/// Inapplicable rows are omitted, not disabled.
///
/// # `available`
///
/// Whether this build has a backend for `profile.protocol`, from
/// [`crate::protocol::BackendRegistry::available`]. When false, the first
/// row is the disabled [`RowKind::Unavailable`] instead of
/// [`RowKind::Connect`]; every other row is unaffected.
pub fn items(profile: &ConnectionProfile, has_session: bool, available: bool) -> Vec<RowKind> {
    let connect = if available {
        RowKind::Connect
    } else {
        RowKind::Unavailable
    };
    let mut rows = vec![connect, RowKind::Edit];
    if has_session {
        rows.push(RowKind::Disconnect);
    }
    if profile.wol_mac.is_some() {
        rows.push(RowKind::Wake);
    }
    rows.push(RowKind::ToggleFavorite);
    rows.push(RowKind::Duplicate);
    rows.push(RowKind::Delete);
    rows
}

pub fn menu_items(
    profile: &ConnectionProfile,
    has_session: bool,
    available: bool,
    session_generation: Option<u64>,
) -> Vec<ContextMenuItem<RowKind>> {
    let mut entries = Vec::new();
    let mut previous = None;
    for row in items(profile, has_session, available) {
        if previous.is_some_and(|group| group != row.group()) {
            entries.push(ContextMenuItem::separator());
        }
        previous = Some(row.group());
        // Disconnect events may only affect the session shown when their row was published.
        let key = if row == RowKind::Disconnect {
            format!("disconnect-{}", session_generation.unwrap_or_default())
        } else {
            row.key().to_string()
        };
        entries.push(
            ContextMenuItem::command(row, row.label(has_session, profile.favorite))
                .key(key)
                .icon(row.icon())
                .destructive(row.destructive())
                .enabled(row != RowKind::Unavailable),
        );
    }
    entries
}

pub(crate) fn session_generation(app: &App, profile: Uuid) -> Option<u64> {
    app.session_streams.get(&profile).copied()
}

pub fn items_for_open(app: &App) -> Option<Vec<ContextMenuItem<RowKind>>> {
    let profile = app
        .profiles
        .iter()
        .find(|p| Some(&p.id) == app.context_menu.menu.target())?;
    Some(menu_items(
        profile,
        app.sessions.iter().any(|s| s.profile_id == profile.id),
        app.backends.available(profile.protocol),
        session_generation(app, profile.id),
    ))
}

/// The accessible name the menu surface publishes: the bounded presentation
/// of the connection's name.
pub fn menu_label(app: &App) -> Option<String> {
    let profile = app.context_menu.menu.target()?;
    app.profiles
        .iter()
        .find(|p| &p.id == profile)
        .map(|p| crate::display::bound_display_name(&p.name))
}

/// The id the context-menu host publishes as its `invoker`.
pub fn menu_invoker_id(app: &App) -> Option<iced::advanced::widget::Id> {
    app.context_menu.invoker.clone()
}

#[cfg(test)]
mod tests {}
