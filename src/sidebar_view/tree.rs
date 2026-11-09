//! Grouped sidebar rows and scoped keyboard navigation.

use super::*;

/// The kind of row a sidebar tree entry represents.
///
/// Parallel to the `Vec<EnzTreeItem>` so the index-taking closures decode a
/// row index into an action; a string discriminant in `EnzTreeItem::key`
/// could mis-route on a name collision.
#[derive(Clone, Debug)]
enum TreeRowKind {
    /// The Favorites shelf header (the pseudo-group at the top).
    Favorites,
    /// A real folder / tag group header, keyed on the bucket's full path so
    /// `Home` and `Home/Legacy` remain distinct.
    Group(String),
    /// A profile leaf.
    Profile(uuid::Uuid),
}

/// Ordered display rows, their actions and stable ancestor paths. Shared by
/// pointer actions, keyboard navigation and context-menu focus restoration.
struct TreeRows {
    items: Vec<EnzTreeItem>,
    kinds: Vec<TreeRowKind>,
    paths: Vec<Vec<String>>,
}

impl TreeRows {
    /// Push a row's item, kind and ancestor path together — the only way a row
    /// is added, so the three vectors cannot drift out of step.
    fn push(&mut self, item: EnzTreeItem, kind: TreeRowKind, path: Vec<String>) {
        self.items.push(item);
        self.kinds.push(kind);
        self.paths.push(path);
    }
}

// Unfiled profiles precede Favorites and named folders.
fn tree_rows(app: &App, groups: &Grouping) -> TreeRows {
    let mut rows = TreeRows {
        items: Vec::new(),
        kinds: Vec::new(),
        paths: Vec::new(),
    };

    for bucket in groups
        .buckets
        .iter()
        .filter(|b| b.name == crate::organise::UNGROUPED)
    {
        for pid in &bucket.profile_ids {
            if let Some(p) = app.profiles.iter().find(|p| p.id == *pid) {
                let key = format!("profile:{}", p.id);
                let shown = crate::display::bound_display_name(&p.name);
                rows.push(
                    EnzTreeItem::leaf(shown.clone(), 0)
                        .key(key.clone())
                        .aria_label(shown),
                    TreeRowKind::Profile(p.id),
                    vec![key],
                );
            }
        }
    }

    // Favorites repeats starred profiles from real folders, so it starts
    // collapsed and its `(n)` label reads as a view rather than a folder.
    if !groups.favorites.is_empty() {
        let branch_key = "favorites".to_owned();
        rows.push(
            EnzTreeItem::branch(
                format!("Favorites ({})", groups.favorites.len()),
                0,
                app.favorites_expanded,
            )
            .key(branch_key.clone()),
            TreeRowKind::Favorites,
            vec![branch_key.clone()],
        );
        if app.favorites_expanded {
            for pid in &groups.favorites {
                if let Some(p) = app.profiles.iter().find(|p| p.id == *pid) {
                    let key = format!("fav:{}", p.id);
                    let shown = crate::display::bound_display_name(&p.name);
                    rows.push(
                        EnzTreeItem::leaf(shown.clone(), 1)
                            .key(key.clone())
                            .aria_label(shown),
                        TreeRowKind::Profile(p.id),
                        vec![branch_key.clone(), key],
                    );
                }
            }
        }
    }

    for bucket in groups
        .buckets
        .iter()
        .filter(|b| b.name != crate::organise::UNGROUPED)
    {
        // Folders are flat: headers at level 0, profiles at level 1.
        let level = 0u8;
        rows.push(
            // The heading is bounded, single-line and control/bidi-free so a crafted
            // imported folder cannot spoof or inflate the sidebar; `bucket.name` stays
            // the identity for grouping, expansion and focus restore.
            EnzTreeItem::branch(
                crate::display::bound_group_heading(&bucket.name),
                level,
                bucket.expanded,
            )
            // The reconciliation key is the FULL bucket path, so
            // `Home/Legacy` and `Work/Legacy` never collide even though
            // both paint the leaf `Legacy`.
            .key(bucket.name.clone()),
            TreeRowKind::Group(bucket.name.clone()),
            vec![bucket.name.clone()],
        );
        if bucket.expanded {
            let leaf_level = level.saturating_add(1);
            for pid in &bucket.profile_ids {
                if let Some(p) = app.profiles.iter().find(|p| p.id == *pid) {
                    // Key on the full bucket path + profile id so the same
                    // profile appearing under two tag buckets still gets
                    // distinct row identities.
                    let key = format!("{}::{}", bucket.name, p.id);
                    let shown = crate::display::bound_display_name(&p.name);
                    rows.push(
                        EnzTreeItem::leaf(shown.clone(), leaf_level)
                            .key(key.clone())
                            .aria_label(shown),
                        TreeRowKind::Profile(p.id),
                        vec![bucket.name.clone(), key],
                    );
                }
            }
        }
    }

    rows
}

/// The ancestor key path of the first sidebar row showing `profile`.
///
/// A starred profile has two rows, so this serves only callers with no row
/// (the `--start-view=context` capture seed and tests); real menus carry the
/// invoking row's path in [`crate::Message::OpenContextMenu`].
///
/// `None` when no row shows the profile (filtered out or collapsed).
pub fn sidebar_row_path(app: &App, profile: uuid::Uuid) -> Option<Vec<String>> {
    let rows = tree_rows(app, &grouping(app));
    let index = rows
        .kinds
        .iter()
        .position(|k| matches!(k, TreeRowKind::Profile(pid) if *pid == profile))?;
    rows.paths.get(index).cloned()
}

/// Compact folder headers and two-line connection rows. Each row is a native
/// list-row surface; the scoped keyboard decoder keeps navigation across folders.
pub fn grouped_list<'a>(app: &'a App, groups: &Grouping) -> Vec<Element<'a, Message>> {
    if let Some(message) = list_empty_state(app.profiles.len(), groups.profile_count()) {
        let mut page = enz_status_page(message)
            .icon(if app.profiles.is_empty() {
                "monitor"
            } else {
                "search"
            })
            .description(if app.profiles.is_empty() {
                "Add a connection to get started."
            } else {
                "No saved connection matches this search."
            })
            .variant(StatusPageVariant::Inline)
            .tone(StatusPageTone::Empty)
            .id_prefix("remote-app-list-empty");
        if app.profiles.is_empty() {
            page = page.primary_action(new_connection_action());
        }
        return vec![page.into_element()];
    }
    let rows = tree_rows(app, groups);
    let mut out = Vec::new();
    let mut section = Vec::new();
    let mut grouped = false;
    for (idx, item) in rows.items.iter().enumerate() {
        if !matches!(rows.kinds[idx], TreeRowKind::Profile(_)) {
            if !section.is_empty() {
                out.push(folder_section(std::mem::take(&mut section), grouped));
            }
            grouped = true;
        }
        let path = rows.paths[idx].clone();
        let id = row_id(&path);
        let content: Element<'a, Message> = match &rows.kinds[idx] {
            TreeRowKind::Profile(pid) => {
                let Some(profile) = app.profiles.iter().find(|p| p.id == *pid).cloned() else {
                    continue;
                };
                let pid = *pid;
                let theme = app.enz_theme.clone();
                let credentials = app.credentials.clone();
                let status = app.session_status_for(pid);
                let selected = app.selected_profile == Some(pid);
                let available = app.backends.available(profile.protocol);
                let closing = app.close_progress_for(pid);
                let pending = app.credentials_pending(pid);
                let action_hovered = app.sidebar_action_hover.as_deref() == item.key.as_deref();
                let identity = item.key.clone().unwrap_or_default();
                let path = path.clone();
                enzui_iced_widgets::hover_group::enz_hover_group_with(
                    move |row_hovered| -> Element<'static, Message> {
                        let palette = &theme.palette;
                        let backdrop = if selected {
                            palette.accent_soft
                        } else {
                            palette.surface_alt
                        };
                        let body = crate::view::profile_row_body(
                            &theme,
                            credentials.as_ref(),
                            &profile,
                            status,
                            backdrop,
                        );
                        let action = crate::view::profile_row_trailing(
                            &identity,
                            &profile,
                            status,
                            available,
                            closing,
                            pending,
                            action_hovered,
                            row_hovered,
                            &theme,
                            backdrop,
                        );
                        let lane = iced::widget::container(body).width(Length::Fill).padding(
                            iced::Padding::ZERO
                                .top(SpaceToken::Xxs.resolve(&theme.spacing))
                                .bottom(SpaceToken::Xxs.resolve(&theme.spacing))
                                .left(
                                    theme.spacing.xs()
                                        + if path.len() > 1 {
                                            theme.spacing.sm()
                                        } else {
                                            0.0
                                        },
                                ),
                        );
                        let context_path = path.clone();
                        let body = enz_list_row_surface(
                            lane,
                            Message::SidebarProfilePressed(pid, path.clone()),
                        )
                        .id(id.clone())
                        .label(profile.name.clone())
                        .selected(selected)
                        .tokens_resolved(crate::theme::sidebar_row_tokens)
                        .outer_gutter(0.0)
                        .content_padding(0.0)
                        .content_height(true)
                        .trailing(action)
                        .trailing_visibility(
                            enzui_iced_widgets::list_row_surface::TrailingVisibility::Always,
                        )
                        .on_enter(move || Message::ActivateProfile(pid))
                        .on_context(move |at| {
                            Message::OpenContextMenu(pid, at, context_path.clone())
                        })
                        .context_label("Connection actions")
                        .into_element();
                        iced::widget::mouse_area(body)
                            .on_double_click(Message::ActivateProfile(pid))
                            .into()
                    },
                )
                .style(|_, _| enzui_iced_widgets::hover_group::HoverGroupStyle::NONE)
                .fill_width()
                .into_element()
            }
            kind => {
                let message = match kind {
                    TreeRowKind::Favorites => Message::ToggleFavorites,
                    TreeRowKind::Group(key) => Message::ToggleGroup(key.clone()),
                    _ => unreachable!(),
                };
                let lane = iced::widget::row![
                    enzui_iced_widgets::icon::enz_icon(if matches!(kind, TreeRowKind::Favorites) {
                        "star"
                    } else {
                        "folder"
                    })
                    .size(app.enz_theme.sizing.icon_sm)
                    .into_element(),
                    enz_text(item.text.clone())
                        .size(TextSize::Callout)
                        .single_line_elided()
                        .full_width()
                        .into_element(),
                    enzui_iced_widgets::icon::enz_icon(if item.expanded {
                        "chevron-down"
                    } else {
                        "chevron-right"
                    })
                    .size(app.enz_theme.sizing.icon_xs)
                    .into_element(),
                ]
                .spacing(app.enz_theme.spacing.xs())
                .align_y(iced::Alignment::Center);
                let mut semantics = enzui_iced_core::semantics::Semantics::new(
                    enzui_iced_core::semantics::Role::Button,
                );
                semantics.label = Some(item.text.clone());
                semantics.expanded = Some(item.expanded);
                enz_list_row_surface(lane, message)
                    .semantics(semantics)
                    .id(id)
                    .label(item.text.clone())
                    .selectable(false)
                    .row_height(app.enz_theme.sizing.min_hit_target)
                    .tokens_resolved(crate::theme::sidebar_folder_tokens)
                    .outer_gutter(0.0)
                    .content_padding(app.enz_theme.spacing.xs())
                    .into_element()
            }
        };
        let path = path.clone();
        section.push(enzui_iced_widgets::keyboard_capture::keyboard_capture(
            content,
            move |key, modifiers| {
                if !modifiers.is_empty() {
                    return None;
                }
                if let iced::keyboard::Key::Named(
                    key @ (iced::keyboard::key::Named::ArrowUp
                    | iced::keyboard::key::Named::ArrowDown
                    | iced::keyboard::key::Named::ArrowLeft
                    | iced::keyboard::key::Named::ArrowRight
                    | iced::keyboard::key::Named::Home
                    | iced::keyboard::key::Named::End),
                ) = key
                {
                    Some(Message::SidebarNavigate(path.clone(), *key))
                } else {
                    None
                }
            },
        ));
    }
    if !section.is_empty() {
        out.push(folder_section(section, grouped));
    }
    vec![
        iced::widget::Column::with_children(out)
            .spacing(app.enz_theme.spacing.xs())
            .width(Length::Fill)
            .into(),
    ]
}

/// Hovering a folder header or one of its connections lights the same section.
fn folder_section<'a>(children: Vec<Element<'a, Message>>, grouped: bool) -> Element<'a, Message> {
    let body = iced::widget::Column::with_children(children)
        .spacing(1)
        .width(Length::Fill);
    if !grouped {
        return body.into();
    }
    enzui_iced_widgets::hover_group::enz_hover_group(body)
        .fill_width()
        .style(
            |theme, hovered| enzui_iced_widgets::hover_group::HoverGroupStyle {
                background: if hovered {
                    enzui_iced_theme::Palette::from_iced(theme).surface_elevated
                } else {
                    iced::Color::TRANSPARENT
                },
                radius: enzui_iced_widgets::theme_lookup::shape_radius(theme, |shape| shape.card),
                ..enzui_iced_widgets::hover_group::HoverGroupStyle::NONE
            },
        )
        .into_element()
}

pub fn row_id(path: &[String]) -> iced::advanced::widget::Id {
    let refs: Vec<_> = path.iter().map(String::as_str).collect();
    enzui_iced_widgets::tree_view::tree_row_id(crate::view::SIDEBAR_TREE_ID_PREFIX, &refs)
}

pub fn navigate(
    app: &mut App,
    path: Vec<String>,
    key: iced::keyboard::key::Named,
) -> iced::Task<Message> {
    use iced::keyboard::key::Named as K;
    if app.modal_open() {
        return iced::Task::none();
    }
    let rows = tree_rows(app, &grouping(app));
    let Some(index) = rows.paths.iter().position(|p| p == &path) else {
        return iced::Task::none();
    };
    let target = match key {
        K::ArrowUp => index.saturating_sub(1),
        K::ArrowDown => (index + 1).min(rows.items.len() - 1),
        K::Home => 0,
        K::End => rows.items.len() - 1,
        K::ArrowLeft | K::ArrowRight => {
            let item = &rows.items[index];
            if item.has_children {
                if item.expanded == (key == K::ArrowLeft) {
                    return match &rows.kinds[index] {
                        TreeRowKind::Favorites => app.reduce1_toggle_favorites_13(),
                        TreeRowKind::Group(group) => app.reduce1_toggle_group_12(group.clone()),
                        _ => iced::Task::none(),
                    };
                }
                if key == K::ArrowRight && item.expanded {
                    (index + 1).min(rows.items.len() - 1)
                } else {
                    index
                }
            } else if key == K::ArrowLeft && path.len() > 1 {
                rows.paths
                    .iter()
                    .position(|p| p == &path[..path.len() - 1])
                    .unwrap_or(index)
            } else {
                index
            }
        }
        _ => index,
    };
    let focus = iced::advanced::widget::operate(enzui_iced_core::focus::focus_and_reveal_id(
        row_id(&rows.paths[target]),
    ));
    if let TreeRowKind::Profile(pid) = rows.kinds[target] {
        iced::Task::batch([focus, iced::Task::done(Message::SelectProfile(pid))])
    } else {
        focus
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::{ConnectionProfile, Protocol},
        render_tests::connections::send,
    };
    use iced::keyboard::key::Named as K;

    #[test]
    fn keyboard_navigation_crosses_folders_and_respects_collapsed_and_filtered_rows() {
        let (mut app, _) = App::boot_with_db(Some(":memory:"));
        let mut first = ConnectionProfile::new("First", Protocol::Vnc, "first.test");
        let mut second = ConnectionProfile::new("Second", Protocol::Rdp, "second.test");
        let mut last = ConnectionProfile::new("Last", Protocol::Spice, "last.test");
        first.group = "Office".into();
        second.group = "Office".into();
        last.group = "Studio".into();
        let ids = [first.id, second.id, last.id];
        app.profiles = vec![first, second, last];
        app.selected_profile = Some(ids[0]);
        let first_path = sidebar_row_path(&app, ids[0]).unwrap();
        let second_path = sidebar_row_path(&app, ids[1]).unwrap();
        send(
            &mut app,
            Message::SidebarNavigate(first_path.clone(), K::ArrowDown),
        );
        assert_eq!(app.selected_profile, Some(ids[1]));
        send(&mut app, Message::SidebarNavigate(second_path, K::End));
        assert_eq!(app.selected_profile, Some(ids[2]));
        send(
            &mut app,
            Message::SidebarNavigate(vec!["Office".into()], K::ArrowLeft),
        );
        assert!(sidebar_row_path(&app, ids[0]).is_none());
        send(
            &mut app,
            Message::SidebarNavigate(vec!["Office".into()], K::ArrowRight),
        );
        assert!(sidebar_row_path(&app, ids[0]).is_some());
        send(
            &mut app,
            Message::SidebarNavigate(vec!["Office".into()], K::ArrowRight),
        );
        assert_eq!(app.selected_profile, Some(ids[0]));
        app.search_query = "Last".into();
        send(&mut app, Message::SidebarNavigate(first_path, K::ArrowDown));
        assert_eq!(
            app.selected_profile,
            Some(ids[0]),
            "a removed/filtered invoker cannot navigate another row"
        );
        send(
            &mut app,
            Message::SidebarNavigate(vec!["Studio".into()], K::ArrowRight),
        );
        assert_eq!(app.selected_profile, Some(ids[2]));
    }
}
