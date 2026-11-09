//! Shared probe: open a titlebar overflow menu through the **real
//! rendered kebab** and measure what each folded row actually paints.
//!
//! # Why this file lives in `_shared/` and not in an app
//!
//! Five apps (calendar, files, mail, reader, remote) run the same gate, and
//! text-app reuses the probe for its overflow tests. Separate copies of a
//! pixel probe could drift into weaker assertions, so each app includes this
//! one implementation:
//!
//! ```ignore
//! #[cfg(test)]
//! #[path = "../../_shared/titlebar_menu_probe.rs"]
//! mod titlebar_menu_probe;
//! ```
//!
//! (`#[path]` is relative to the including file's directory, so `../../` from
//! `<app>/src/` is the apps-repo root. Apps whose gate lives one directory
//! deeper use `../../../_shared/...`.)
//!
//! # What it proves, and what it deliberately does not
//!
//! * The menu is opened by a **pointer click on the painted `More actions`
//!   trigger**, whose position is read from the rendered tree — never by
//!   setting the app's `overflow_open` flag, and never by an environment hook.
//!   A gate that forces the menu open cannot see a trigger that stopped being
//!   clickable.
//! * Each folded row is measured **in painted pixels**, per lane, against the
//!   row's own background colour:
//!   - `blank_ink` — the 8 px strip left of the icon gutter. Always empty; it
//!     is the same-row **zero control** proving the ink counter can return 0.
//!   - `icon_ink` — the 16 px leading gutter
//!     ([`enzui_iced_widgets::menu_row`] `padding_x` 12 + `icon_size` 16).
//!     Non-zero only when the command's `Action` carried an icon.
//!   - `label_ink` — everything right of the gutter. The **positive control**:
//!     a row whose label lane is blank was not really painted, so a blank icon
//!     lane would otherwise be indistinguishable from "menu never rendered".
//! * Group separators are measured the same way: the painted gap between two
//!   consecutive rows. Rows inside one group have an ink-free gap; a group
//!   boundary paints a rule there.
//!
//! Nothing here inspects `Action` metadata: metadata can be present and still
//! never reach the row, and it is not what the user sees.

#![allow(dead_code)]

use enzui_iced_core::collect::{CollectedNode, SemanticsCollector};
use enzui_iced_core::semantics::Role;
use iced::{Element, Point, Rectangle, Size};

/// The accessible name of the framework's overflow trigger. Taken from the
/// widget, so a framework rename breaks these gates loudly instead of silently
/// matching nothing.
pub const TRIGGER_LABEL: &str = enzui_iced_widgets::action_bar::TRIGGER_LABEL;

/// `menu_row`'s horizontal padding, px.
pub const ROW_PADDING_X: f32 = 12.0;
/// `menu_row`'s leading icon side, px.
pub const ROW_ICON_SIZE: f32 = 16.0;
/// `menu_row`'s row_gap between the icon and the label, px.
pub const ROW_GAP: f32 = 8.0;

fn headless_renderer() -> iced_test::renderer::Renderer {
    use iced::advanced::renderer::Headless;
    iced_test::futures::futures::executor::block_on(
        <iced_test::renderer::Renderer as Headless>::new(
            iced::advanced::renderer::Settings::default(),
            std::env::var("ICED_TEST_BACKEND").ok().as_deref(),
        ),
    )
    .expect("headless renderer")
}

/// The collected semantics of one rendered view at `size`.
pub fn nodes_of<'a, Message: 'a>(view: Element<'a, Message>, size: Size) -> Vec<CollectedNode> {
    use iced::advanced::widget::Operation;
    let mut renderer = headless_renderer();
    let mut ui = iced_test::runtime::user_interface::UserInterface::build(
        view,
        size,
        iced_test::runtime::user_interface::Cache::default(),
        &mut renderer,
    );
    ui = ui.relayout(size, &mut renderer);
    let mut collector = SemanticsCollector::new();
    ui.operate(&renderer, &mut collector as &mut dyn Operation);
    remember_subtree_ends(collector)
}

type SubtreeRegistry = Vec<((usize, usize), Vec<usize>)>;

thread_local! {
    // The subtree extents of the node lists this probe collected, keyed by
    // the list's buffer address and length.
    static SUBTREE_ENDS: std::cell::RefCell<SubtreeRegistry> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Collect, keeping each node's exact subtree extent for [`title_bar_scopes`].
fn remember_subtree_ends(collector: SemanticsCollector) -> Vec<CollectedNode> {
    let (nodes, ends) = collector.into_collected_with_subtree_ends();
    let key = (nodes.as_ptr() as usize, nodes.len());
    SUBTREE_ENDS.with(|registry| {
        let mut registry = registry.borrow_mut();
        registry.retain(|(k, _)| *k != key);
        registry.push((key, ends));
        if registry.len() > 64 {
            registry.remove(0);
        }
    });
    nodes
}

/// The recorded subtree extents of `nodes`, when this probe collected them.
fn subtree_ends_of(nodes: &[CollectedNode]) -> Option<Vec<usize>> {
    let key = (nodes.as_ptr() as usize, nodes.len());
    SUBTREE_ENDS.with(|registry| {
        registry
            .borrow()
            .iter()
            .rev()
            .find(|(k, _)| *k == key)
            .map(|(_, ends)| ends.clone())
    })
}

/// The bare accessible name [`enzui_iced_widgets::title_bar`] publishes for an
/// untitled bar; a titled bar publishes `"{title} title bar"`.
pub const TITLE_BAR_LABEL: &str = "Title bar";

/// Whether `node` is the labelled `Role::Group` owner an
/// [`enzui_iced_widgets::title_bar::EnzTitleBar`] publishes.
pub fn is_title_bar_owner(node: &CollectedNode) -> bool {
    node.semantics.role == Role::Group
        && node
            .semantics
            .label
            .as_deref()
            .is_some_and(|label| label == TITLE_BAR_LABEL || label.ends_with(" title bar"))
}

/// One title bar's accessibility subtree: the owner node plus every node
/// collected at greater depth before the scope closes.
#[derive(Debug, Clone)]
pub struct TitleBarScope {
    /// The owner node's accessible name.
    pub label: String,
    /// The band's own bounds.
    pub bounds: Rectangle,
    /// Index range of the owner's descendants in the collected slice.
    pub descendants: std::ops::Range<usize>,
}

/// Every title bar subtree in `nodes`, in tree order.
///
/// Subtree membership rides on [`CollectedNode::depth`]: the title bar
/// publishes a `SemanticsNode::group` **before** descending, so its children
/// are the contiguous run of deeper nodes that follows it.
pub fn title_bar_scopes(nodes: &[CollectedNode]) -> Vec<TitleBarScope> {
    // The collector's exact extents when this probe collected `nodes`: a
    // sibling whose own container publishes nothing looks nested by `depth`
    // alone (mail's 160 px list header followed its title bar that way).
    let ends = subtree_ends_of(nodes);
    let mut scopes = Vec::new();
    for (i, node) in nodes.iter().enumerate() {
        if !is_title_bar_owner(node) {
            continue;
        }
        let end = ends.as_ref().map_or_else(
            || {
                nodes
                    .iter()
                    .enumerate()
                    .skip(i + 1)
                    .find(|(_, n)| n.depth <= node.depth)
                    .map_or(nodes.len(), |(j, _)| j)
            },
            |ends| ends[i],
        );
        scopes.push(TitleBarScope {
            label: node.semantics.label.clone().unwrap_or_default(),
            bounds: node.bounds,
            descendants: (i + 1)..end,
        });
    }
    scopes
}

fn is_trigger(node: &CollectedNode) -> bool {
    node.semantics.role == Role::Button && node.semantics.label.as_deref() == Some(TRIGGER_LABEL)
}

/// **Calibration/diagnostics only — never a gate.** The bounds of the FIRST
/// `More actions` trigger anywhere in the tree, whichever bar owns it.
///
/// Kept solely so the fixture below can show that it answers with a *foreign*
/// bar's trigger. A titlebar gate that calls this can be satisfied by a
/// mailbox or content action bar that folded, so a titlebar that never folds
/// would look green.
pub fn any_trigger_bounds_unscoped(nodes: &[CollectedNode]) -> Option<Rectangle> {
    nodes.iter().find(|n| is_trigger(n)).map(|n| n.bounds)
}

/// Every `More actions` trigger that is NOT inside a title bar subtree.
pub fn foreign_trigger_bounds(nodes: &[CollectedNode]) -> Vec<Rectangle> {
    let scopes = title_bar_scopes(nodes);
    nodes
        .iter()
        .enumerate()
        .filter(|(i, n)| is_trigger(n) && !scopes.iter().any(|s| s.descendants.contains(i)))
        .map(|(_, n)| n.bounds)
        .collect()
}

/// Whether `inner` is painted inside `outer` (1 px slack for rounding).
pub fn contains(outer: Rectangle, inner: Rectangle) -> bool {
    inner.x >= outer.x - 1.0
        && inner.y >= outer.y - 1.0
        && inner.x + inner.width <= outer.x + outer.width + 1.0
        && inner.y + inner.height <= outer.y + outer.height + 1.0
}

/// The painted **titlebar** overflow trigger's bounds, or `None` when the
/// title bar folded nothing.
///
/// Scoped two ways, because an unscoped lookup passes a titlebar gate on a
/// foreign bar's kebab:
///
/// * **subtree** — the trigger must be published inside a `Title bar` group's
///   accessibility scope, and
/// * **bounds** — it must also be painted inside that band's rectangle, so a
///   node parented to the bar but drawn elsewhere cannot stand in for it.
///
/// Loud states rather than a quiet `None`:
///
/// * no title bar in the view at all — a titlebar gate measured the wrong tree;
/// * a trigger inside the bar's subtree painted outside its band;
/// * triggers inside more than one title bar — the caller must say which.
pub fn titlebar_trigger_bounds(nodes: &[CollectedNode]) -> Option<Rectangle> {
    let scopes = title_bar_scopes(nodes);
    assert!(
        !scopes.is_empty(),
        "this view published no `Title bar` group, so a titlebar \
         overflow gate has nothing to scope to. {} `{TRIGGER_LABEL}` trigger(s) \
         exist elsewhere in the tree and must NOT satisfy a titlebar gate.",
        nodes.iter().filter(|n| is_trigger(n)).count()
    );
    let mut found: Option<(String, Rectangle)> = None;
    for scope in &scopes {
        for (i, node) in nodes.iter().enumerate() {
            if !is_trigger(node) || !scope.descendants.contains(&i) {
                continue;
            }
            assert!(
                contains(scope.bounds, node.bounds),
                "a `{TRIGGER_LABEL}` trigger at {:?} is parented to {:?} \
                 ({:?}) but painted outside that band; it cannot be the \
                 titlebar kebab",
                node.bounds,
                scope.label,
                scope.bounds
            );
            if let Some((other, bounds)) = &found {
                assert!(
                    bounds == &node.bounds,
                    "this frame publishes more than one distinct \
                     `{TRIGGER_LABEL}` trigger inside a title bar ({other:?} at \
                     {bounds:?} and {:?} at {:?}); a gate must name which bar \
                     it means instead of taking the first",
                    scope.label,
                    node.bounds
                );
            }
            found = Some((scope.label.clone(), node.bounds));
        }
    }
    found.map(|(_, bounds)| bounds)
}

/// The titlebar-scoped trigger lookup every gate in this repo uses.
///
/// The app gates call this name, so they are scoped by construction; the unscoped behaviour survives only as
/// [`any_trigger_bounds_unscoped`], which no gate may call.
pub fn trigger_bounds(nodes: &[CollectedNode]) -> Option<Rectangle> {
    titlebar_trigger_bounds(nodes)
}

/// Assert the title bar folded NOTHING: it publishes no overflow trigger of
/// its own, whatever other bars in the frame are doing.
///
/// Returns the foreign triggers it ignored, so a caller can record that the
/// frame did contain the decoys this scoping exists to reject.
pub fn assert_no_titlebar_trigger(nodes: &[CollectedNode], ctx: &str) -> Vec<Rectangle> {
    if let Some(bounds) = titlebar_trigger_bounds(nodes) {
        panic!(
            "{ctx}: the title bar published a `{TRIGGER_LABEL}` trigger at \
             {bounds:?}; this disposition expects every titlebar command inline"
        );
    }
    foreign_trigger_bounds(nodes)
}

/// Every `Role::Button` inside a title bar subtree whose accessible name is
/// exactly `label`, with the band that owns it.
pub fn titlebar_buttons<'a>(
    nodes: &'a [CollectedNode],
    label: &str,
) -> Vec<(&'a CollectedNode, Rectangle)> {
    let scopes = title_bar_scopes(nodes);
    nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| {
            n.semantics.role == Role::Button && n.semantics.label.as_deref() == Some(label)
        })
        .filter_map(|(i, n)| {
            scopes
                .iter()
                .find(|s| s.descendants.contains(&i) && contains(s.bounds, n.bounds))
                .map(|s| (n, s.bounds))
        })
        .collect()
}

/// A real pointer click at `at`, returning every message the tree published.
pub fn click_at<'a, Message: 'a>(
    view: Element<'a, Message>,
    size: Size,
    at: Point,
) -> Vec<Message> {
    let mut ui = iced_test::Simulator::with_size(iced::Settings::default(), size, view);
    ui.point_at(at);
    let _ = ui.simulate(iced_test::simulator::click());
    ui.into_messages().collect()
}

/// One painted RGBA frame.
pub struct Frame {
    pub pixels: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

impl Frame {
    fn at(&self, x: u32, y: u32) -> [u8; 4] {
        let i = ((y * self.width + x) * 4) as usize;
        [
            self.pixels[i],
            self.pixels[i + 1],
            self.pixels[i + 2],
            self.pixels[i + 3],
        ]
    }

    /// Pixels inside `rect` that differ from `bg` by more than `tolerance` in
    /// any channel.
    pub fn ink(&self, rect: Rectangle, bg: [u8; 4], tolerance: i32) -> usize {
        let x0 = rect.x.max(0.0).floor() as u32;
        let x1 = (rect.x + rect.width).min(self.width as f32).ceil() as u32;
        let y0 = rect.y.max(0.0).floor() as u32;
        let y1 = (rect.y + rect.height).min(self.height as f32).ceil() as u32;
        let mut n = 0;
        for y in y0..y1 {
            for x in x0..x1 {
                let p = self.at(x, y);
                if (0..4).any(|c| (i32::from(p[c]) - i32::from(bg[c])).abs() > tolerance) {
                    n += 1;
                }
            }
        }
        n
    }

    /// The modal colour inside `rect` — the row's own background, taken from
    /// the pixels rather than assumed from a theme token.
    pub fn modal_color(&self, rect: Rectangle) -> [u8; 4] {
        use std::collections::HashMap;
        let x0 = rect.x.max(0.0).floor() as u32;
        let x1 = (rect.x + rect.width).min(self.width as f32).ceil() as u32;
        let y0 = rect.y.max(0.0).floor() as u32;
        let y1 = (rect.y + rect.height).min(self.height as f32).ceil() as u32;
        let mut counts: HashMap<[u8; 4], usize> = HashMap::new();
        for y in y0..y1 {
            for x in x0..x1 {
                *counts.entry(self.at(x, y)).or_default() += 1;
            }
        }
        counts
            .into_iter()
            .max_by_key(|(_, n)| *n)
            .map(|(c, _)| c)
            .unwrap_or([0, 0, 0, 255])
    }
}

/// Render `view` at `size` in `theme` and return both its pixels and its
/// semantics, measured from the SAME laid-out interface.
pub fn frame_and_nodes<'a, Message: 'a>(
    view: Element<'a, Message>,
    size: Size,
    theme: &iced::Theme,
) -> (Frame, Vec<CollectedNode>) {
    use iced::advanced::graphics::core::theme::Base;
    use iced::advanced::renderer::Headless;
    use iced::advanced::widget::Operation;

    let mut renderer = headless_renderer();
    let mut ui = iced_test::runtime::user_interface::UserInterface::build(
        view,
        size,
        iced_test::runtime::user_interface::Cache::default(),
        &mut renderer,
    );
    ui = ui.relayout(size, &mut renderer);
    let mut collector = SemanticsCollector::new();
    ui.operate(&renderer, &mut collector as &mut dyn Operation);
    let nodes = remember_subtree_ends(collector);

    let base = <iced::Theme as Base>::base(theme);
    ui.draw(
        &mut renderer,
        theme,
        &iced::advanced::renderer::Style {
            text_color: base.text_color,
        },
        iced::mouse::Cursor::Unavailable,
    );
    let width = size.width.round() as u32;
    let height = size.height.round() as u32;
    let pixels = renderer.screenshot(Size::new(width, height), 1.0, base.background_color);
    (
        Frame {
            pixels,
            width,
            height,
        },
        nodes,
    )
}

/// One folded menu row, with its three measured lanes.
#[derive(Debug, Clone)]
pub struct MenuRow {
    pub label: String,
    pub bounds: Rectangle,
    /// Ink in the 8 px strip left of the icon gutter — the zero control.
    pub blank_ink: usize,
    /// Ink in the 16 px leading icon gutter.
    pub icon_ink: usize,
    /// Ink right of the gutter — the positive control.
    pub label_ink: usize,
    /// Ink in the ~6 px "reserve rhythm" strip that straddles the icon
    /// gutter's right edge (`[ROW_PADDING_X + ROW_ICON_SIZE - 1 ..
    /// ROW_PADDING_X + ROW_ICON_SIZE + ROW_GAP - 2]`). This is the
    /// framework's `row_gap` between icon and label when `reserve_leading`
    /// is on — painted background only. When a single-row menu drops its
    /// only icon (the mail `.with_icon` sabotage), `reserve_leading`
    /// collapses, the label slides flush against `padding_x`, and its
    /// letters ("a", "i") fill this strip with ink. So a low value here is
    /// the anchor that separates "icon present, gutter reserved" from
    /// "row has no gutter and the icon lane below is just the label's
    /// leading strokes". Complements [`icon_ink`], which alone cannot make
    /// that distinction.
    pub gutter_gap_ink: usize,
}

fn lane(row: Rectangle, x0: f32, x1: f32) -> Rectangle {
    Rectangle {
        x: row.x + x0,
        y: row.y + 1.0,
        width: x1 - x0,
        height: (row.height - 2.0).max(1.0),
    }
}

/// Every painted folded row in `frame`, top to bottom.
pub fn menu_rows(frame: &Frame, nodes: &[CollectedNode]) -> Vec<MenuRow> {
    let mut rows: Vec<&CollectedNode> = nodes
        .iter()
        .filter(|node| matches!(node.semantics.role, Role::MenuItem | Role::MenuItemCheckBox))
        .collect();
    rows.sort_by(|a, b| a.bounds.y.total_cmp(&b.bounds.y));
    rows.into_iter()
        .map(|node| {
            let bounds = node.bounds;
            let blank = lane(bounds, 1.0, ROW_PADDING_X - 3.0);
            let icon = lane(
                bounds,
                ROW_PADDING_X - 1.0,
                ROW_PADDING_X + ROW_ICON_SIZE + 1.0,
            );
            let label = lane(
                bounds,
                ROW_PADDING_X + ROW_ICON_SIZE + 2.0,
                (bounds.width - 1.0).max(ROW_PADDING_X + ROW_ICON_SIZE + 3.0),
            );
            // The `row_gap` strip: the ~6 px vertical slice that must
            // paint the row's background only when the icon gutter is
            // reserved. If `reserve_leading` collapsed and the label slid
            // flush against `padding_x`, this strip carries the second and
            // third glyphs of the label instead — which is exactly the
            // shape that made the `icon_ink` lane a false positive for
            // mail's one-command sabotage.
            // It starts where the icon's 16 px box ends: a glyph whose
            // stroke runs down the box's right edge (`book-open`) paints
            // that last column, and counting it read a full-height icon
            // edge as label bleed.
            let gutter_gap = lane(
                bounds,
                ROW_PADDING_X + ROW_ICON_SIZE,
                ROW_PADDING_X + ROW_ICON_SIZE + ROW_GAP - 2.0,
            );
            // The row's own background, sampled from the row itself so a
            // hovered/elevated surface cannot be mistaken for ink.
            let bg = frame.modal_color(bounds);
            MenuRow {
                label: node.semantics.label.clone().unwrap_or_default(),
                bounds,
                blank_ink: frame.ink(blank, bg, 12),
                icon_ink: frame.ink(icon, bg, 12),
                label_ink: frame.ink(label, bg, 12),
                gutter_gap_ink: frame.ink(gutter_gap, bg, 12),
            }
        })
        .collect()
}

/// Assert that every folded row paints its command icon, with both controls.
///
/// * `label_ink > 0` — positive control: the row painted at all.
/// * `blank_ink == 0` — zero control: this row's background is not being
///   counted as ink, so a non-zero icon lane means something was drawn.
/// * The published label semantic anchors past the reserved icon gutter —
///   the reserve-rhythm control. Without this a menu whose sabotage
///   collapses `reserve_leading` (mail's one-command inventory does this on
///   `mail.settings.with_icon` removal) would leave the label flush against
///   `padding_x`, and its leading strokes would land INSIDE the `icon_ink`
///   lane below — a false-positive route we already had to correct once.
/// * `icon_ink >= MIN_ICON_INK` — the consequence: the leading gutter holds a
///   glyph, which only happens when the command's `Action` carried an icon.
///
/// `ctx` names the app/theme in every failure so a fleet-wide run says which
/// app and which command lost its icon.
pub fn assert_rows_paint_icons(rows: &[MenuRow], ctx: &str) {
    assert!(
        !rows.is_empty(),
        "{ctx}: no folded menu rows were published — there is nothing to measure"
    );
    for row in rows {
        assert!(
            row.label_ink > 0,
            "{ctx}: row {:?} painted no label ink; the frame is not showing an \
             open menu, so an empty icon lane would prove nothing",
            row.label
        );
        assert_eq!(
            row.blank_ink, 0,
            "{ctx}: zero control failed — the strip left of {:?}'s icon gutter \
             already reads as ink ({} px), so the icon measurement below cannot \
             fail",
            row.label, row.blank_ink
        );
        // Reserve-rhythm control: the framework's `row_gap` between icon
        // and label MUST paint background only. On the mail sabotage this
        // strip captures the label's second/third glyphs (label starts at
        // `padding_x = 12`, hits `x >= 28` by the second character), so a
        // non-empty strip proves the label slid flush left and the
        // `icon_ink` below cannot be trusted. `MAX_GUTTER_GAP_INK` allows
        // sub-pixel bleed from the icon's rightmost stroke without
        // accepting a full letter's worth of ink.
        assert!(
            row.gutter_gap_ink <= MAX_GUTTER_GAP_INK,
            "{ctx}: folded command {:?} left {} px of ink in the \
             row_gap between the icon lane and the label (limit \
             {MAX_GUTTER_GAP_INK}). The framework's `reserve_leading` \
             rhythm collapsed because no row held an icon, so the label \
             slid flush left and the `icon_ink` lane below counts the \
             label's own leading strokes instead of an icon.",
            row.label,
            row.gutter_gap_ink,
        );
        assert!(
            row.icon_ink >= MIN_ICON_INK,
            "{ctx}: folded command {:?} paints no icon in its leading \
             gutter (only {} ink px, need {MIN_ICON_INK}). Its inline control \
             has a canonical icon, so its `Action` must carry the same one.",
            row.label,
            row.icon_ink
        );
    }
}

/// The least painted ink a real 16 px glyph leaves in the gutter. The thinnest
/// icon in the fleet's titlebars is a chevron; measured well above this.
pub const MIN_ICON_INK: usize = 12;

/// The most ink the `row_gap` strip between the icon and the label may
/// contain. A real icon's rightmost stroke can bleed a few sub-pixels into
/// the strip; a label glyph fills it. Kept small on purpose — the mail
/// sabotage exercised this in the tens.
pub const MAX_GUTTER_GAP_INK: usize = 8;

/// Assert separators appear exactly at group boundaries, returning
/// `(boundaries, interior_pairs)` so the caller can require that its menu
/// actually exercised the half it cares about.
pub fn assert_group_separators(
    frame: &Frame,
    rows: &[MenuRow],
    group_of: impl Fn(&str) -> &'static str,
    ctx: &str,
) -> (usize, usize) {
    let mut boundaries = 0;
    let mut interior = 0;
    for pair in rows.windows(2) {
        let (above, below) = (&pair[0], &pair[1]);
        let ink = gap_ink(frame, above, below);
        if group_of(&above.label) == group_of(&below.label) {
            interior += 1;
            assert_eq!(
                ink,
                0,
                "{ctx}: {:?} and {:?} are both in group {:?} and must not \
                 be separated, but their gap paints {ink} px",
                above.label,
                below.label,
                group_of(&above.label)
            );
        } else {
            boundaries += 1;
            assert!(
                ink > 0,
                "{ctx}: the {:?} ({}) → {:?} ({}) group boundary paints no \
                 separator",
                above.label,
                group_of(&above.label),
                below.label,
                group_of(&below.label)
            );
        }
    }
    (boundaries, interior)
}

/// Ink painted in the vertical gap between two consecutive rows: a group
/// separator rule, or nothing.
pub fn gap_ink(frame: &Frame, above: &MenuRow, below: &MenuRow) -> usize {
    let top = above.bounds.y + above.bounds.height;
    let bottom = below.bounds.y;
    if bottom <= top + 0.5 {
        return 0;
    }
    let gap = Rectangle {
        x: above.bounds.x,
        y: top,
        width: above.bounds.width,
        height: bottom - top,
    };
    let bg = frame.modal_color(gap);
    frame.ink(gap, bg, 12)
}

/// The probe's own calibration.
///
/// A lookup helper that has never been observed answering *wrongly* is
/// indistinguishable from one that cannot be wrong. An unscoped lookup takes
/// the first `More actions` button anywhere in the frame, so a mailbox/content
/// action bar that folded would satisfy a **titlebar** gate. These fixtures
/// reproduce that shape — a foreign trigger published EARLIER
/// in the tree than the title bar — and require the two lookups to disagree:
/// the unscoped one still answers with the decoy (the positive control that
/// the fixture really contains it), the scoped one answers with the title
/// bar's own trigger or with `None`.
///
/// This module rides along with every app that includes the probe, so the
/// scoping is calibrated wherever it is used.
#[cfg(test)]
mod scope_calibration {
    use super::*;
    use enzui_iced_core::action_overflow::Descriptor;
    use enzui_iced_core::{Action, Icon};
    use enzui_iced_widgets::action_bar::{ActionItem, enz_action_bar};
    use enzui_iced_widgets::title_bar::enz_title_bar;
    use iced::Length;
    use iced::widget::{Column, container, text};

    #[derive(Debug, Clone, PartialEq)]
    enum Msg {
        Toggle,
    }

    const VIEW: Size = Size {
        width: 480.0,
        height: 320.0,
    };

    /// One command whose inline control is exactly `width` px wide, so folding
    /// is decided by arithmetic we control rather than by font metrics.
    fn command(id: &'static str, label: &'static str, width: f32) -> ActionItem<'static, Msg> {
        ActionItem::with_inline(
            Descriptor::new(id),
            Action::new(id, Msg::Toggle)
                .with_label(label)
                .with_icon(Icon::named("settings")),
            move |action, _| {
                container(text(action.label().to_owned()))
                    .width(Length::Fixed(width))
                    .height(Length::Fixed(28.0))
                    .into()
            },
        )
    }

    /// A NON-titlebar action bar that always folds (`max_inline_actions(0)`),
    /// standing in for mail's mailbox/content bars.
    fn foreign_bar() -> iced::Element<'static, Msg> {
        enz_action_bar(
            vec![command("foreign.one", "Foreign One", 60.0)],
            Msg::Toggle,
        )
        .max_inline_actions(0)
        .into_element()
    }

    /// `[foreign bar that folds] above [title bar]`, so the decoy is the FIRST
    /// trigger in tree order — the ordering that made the old lookup wrong.
    fn view(
        titlebar_actions: Vec<ActionItem<'static, Msg>>,
        title: &str,
    ) -> iced::Element<'static, Msg> {
        let bar = enz_title_bar()
            .title(title.to_owned())
            .id("probe-fixture-window")
            .actions(titlebar_actions, Msg::Toggle)
            .into_element();
        Column::with_children(vec![foreign_bar(), bar]).into()
    }

    /// The title bar's own band, from the collected scope.
    fn only_scope(nodes: &[CollectedNode]) -> TitleBarScope {
        let mut scopes = title_bar_scopes(nodes);
        assert_eq!(
            scopes.len(),
            1,
            "fixture must publish exactly one title bar; got {:?}",
            scopes.iter().map(|s| s.label.clone()).collect::<Vec<_>>()
        );
        scopes.remove(0)
    }

    /// **The mail shape.** The title bar carries one narrow command and folds
    /// nothing; a foreign bar folds and paints a kebab. The unscoped lookup
    /// answers with the foreign kebab (this is what made an impossible
    /// titlebar-menu gate look green); the scoped lookup answers `None`.
    #[test]
    fn a_foreign_bars_trigger_cannot_satisfy_a_titlebar_lookup() {
        let nodes = nodes_of(
            view(vec![command("bar.one", "Only Command", 28.0)], "Fixture"),
            VIEW,
        );
        let scope = only_scope(&nodes);

        let decoy = any_trigger_bounds_unscoped(&nodes)
            .expect("calibration: the fixture must contain a foreign folded trigger");
        assert!(
            !contains(scope.bounds, decoy),
            "calibration: the decoy trigger {decoy:?} must lie OUTSIDE the title \
             bar {:?}, else this fixture proves nothing",
            scope.bounds
        );
        assert_eq!(
            foreign_trigger_bounds(&nodes),
            vec![decoy],
            "calibration: exactly one foreign trigger is expected"
        );

        assert_eq!(
            titlebar_trigger_bounds(&nodes),
            None,
            "the title bar folded nothing, so the titlebar-scoped lookup \
             must answer None even though {decoy:?} is painted elsewhere"
        );
        assert_eq!(assert_no_titlebar_trigger(&nodes, "fixture"), vec![decoy]);
    }

    /// The other direction: a title bar that really does fold. The scoped
    /// lookup must return the bar's OWN trigger — inside its band — and not
    /// the earlier foreign one, so the scoping cannot pass by always
    /// answering `None`.
    #[test]
    fn titlebar_scoping_still_finds_the_real_titlebar_trigger() {
        let nodes = nodes_of(
            view(
                vec![
                    command("bar.one", "Wide One", 240.0),
                    command("bar.two", "Wide Two", 240.0),
                ],
                "Fixture",
            ),
            VIEW,
        );
        let scope = only_scope(&nodes);
        let decoy = any_trigger_bounds_unscoped(&nodes)
            .expect("calibration: the foreign trigger is still first in tree order");
        let scoped = titlebar_trigger_bounds(&nodes)
            .expect("the title bar cannot fit two 240 px commands in 480 px, so it must fold");
        assert_ne!(
            scoped, decoy,
            "the scoped lookup returned the foreign bar's trigger"
        );
        assert!(
            contains(scope.bounds, scoped),
            "the titlebar trigger {scoped:?} must be painted inside the band {:?}",
            scope.bounds
        );
    }

    /// An untitled bar publishes the bare `Title bar` name; a titled one
    /// publishes `"{title} title bar"`. Both must be recognised as scopes,
    /// or the scoping silently degrades to "no title bar found".
    #[test]
    fn both_published_title_bar_names_open_a_scope() {
        for title in ["", "Fixture"] {
            let nodes = nodes_of(
                view(vec![command("bar.one", "Only Command", 28.0)], title),
                VIEW,
            );
            let scope = only_scope(&nodes);
            let expected = if title.is_empty() {
                TITLE_BAR_LABEL.to_owned()
            } else {
                format!("\u{2068}{title}\u{2069} title bar")
            };
            assert_eq!(scope.label, expected);
            assert!(
                !scope.descendants.is_empty(),
                "the {expected:?} scope collected no descendants, so scoping a \
                 lookup to it would reject every real control"
            );
        }
    }

    /// Measuring a tree that has no title bar at all is a loud state, not a
    /// quiet `None` that a gate would read as "nothing folded".
    #[test]
    #[should_panic(expected = "published no `Title bar` group")]
    fn a_view_without_a_title_bar_is_a_loud_state() {
        let nodes = nodes_of(Column::with_children(vec![foreign_bar()]).into(), VIEW);
        let _ = titlebar_trigger_bounds(&nodes);
    }
}
