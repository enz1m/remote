//! The sidebar's organisation chrome: the grouped list, its two empty states,
//! and the Discover section.
//!
//! Presentation only — the grouping decision is [`crate::organise::grouped`]'s
//! and the discovery model is [`crate::discovery`]'s.
//!
//! Folder buckets stay flat. Compact headings and two-line connection rows use
//! native list surfaces, with shared pointer/keyboard routing and stable row IDs.

use enzui_iced_core::Action;
use enzui_iced_core::live_region::Announcement;
use enzui_iced_theme::SpaceToken;
use enzui_iced_widgets::button::{ButtonKind, ButtonSize, enz_button};
use enzui_iced_widgets::enz_text::{TextSize, TextTone, enz_text};
use enzui_iced_widgets::list_row_surface::enz_list_row_surface;
use enzui_iced_widgets::semantics_container::SemanticsContainer;
use enzui_iced_widgets::stack::{CrossAlign, enz_hstack, enz_vstack};
use enzui_iced_widgets::status_page::{StatusPageTone, StatusPageVariant, enz_status_page};
use enzui_iced_widgets::toolbar_icon::enz_toolbar_icon;
use enzui_iced_widgets::toolbar_row::enz_toolbar_row;
use enzui_iced_widgets::tree_view::EnzTreeItem;
use iced::{Element, Length};

use crate::discovery::{DISCOVER_HEADER, DiscoveredHost, scan_tooltip};
use crate::organise::{Grouping, grouped, list_empty_state};
use crate::{App, Message};

mod notifications;
pub use notifications::close_hold_toast;
pub use notifications::credential_toast;
pub use notifications::db_boot_error_toast;
pub use notifications::transfer_toast;
pub use notifications::wol_toast;
mod list;
pub use list::grouping;
pub use list::{IMPORT_MENU_TRIGGER_ID, import_button};

pub use list::new_connection_action;
mod tree;
pub use tree::sidebar_row_path;
pub use tree::{grouped_list, navigate, row_id};

mod discovered;
pub use discovered::discovered_section;
