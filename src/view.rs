//! Remote library navigation and native session surfaces.

use enzui_iced_core::action_overflow::Descriptor;
use enzui_iced_core::semantics::HeadingLevel;
use enzui_iced_core::{Action, Icon};
use enzui_iced_theme::{EnzTheme, SpaceToken};
use enzui_iced_widgets::action_bar::ActionItem;
use enzui_iced_widgets::app_shell::{
    ShellLayout, ShellTokens, SidebarHeader, enz_app_shell_with_geometry,
};
use enzui_iced_widgets::button::ButtonKind;
use enzui_iced_widgets::center::enz_center;
use enzui_iced_widgets::divider::enz_divider;
use enzui_iced_widgets::enz_text::{TextSize, enz_text};
use enzui_iced_widgets::icon::enz_icon;
#[allow(unused_imports)]
use enzui_iced_widgets::list_row_surface::{ListRowSurfaceTokens, enz_list_row_surface};
use enzui_iced_widgets::scroll_view::{Axis, enz_scroll_view};
use enzui_iced_widgets::search_field::enz_search_field;
use enzui_iced_widgets::sidebar_content::enz_sidebar_content;
use enzui_iced_widgets::stack::{CrossAlign, enz_vstack};
use enzui_iced_widgets::status_page::enz_status_page;
use enzui_iced_widgets::text_field::TextFieldSize;
use enzui_iced_widgets::title_bar::enz_title_bar;
use enzui_iced_widgets::toolbar_icon::enz_toolbar_icon;
use enzui_services::credential_store::CredentialStore;
use iced::{Color, Element, Length};

use crate::model::{ConnectionProfile, SessionStatus};
use crate::{App, Message};

pub(crate) use content::{action_for, content_area, session_pane};
pub(crate) use content::{connection_edit_action_item, connection_session_action_item};
pub use ids::DELETE_CONFIRM_SCOPE;
pub(crate) use ids::{
    add_button_id, edit_button_id, quick_connect_button_id, session_action_button_id,
};
pub use rows::{SIDEBAR_TREE_ID_PREFIX, profile_row_body, profile_row_trailing};
pub use shell::shell;

pub(crate) use titlebar::{sidebar, sidebar_titlebar, titlebar};
mod content;
mod ids;
mod rows;
mod shell;
mod titlebar;
