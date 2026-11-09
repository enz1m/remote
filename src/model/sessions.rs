//! Sessions: lifecycle status and the live session.

use super::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Connection lifecycle reported by the transport state machine.
///
/// `state_machine.rs` defines the allowed transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum SessionStatus {
    Disconnected,
    Connecting,
    Connected,
    Error,
}

#[cfg(feature = "center")]
impl SessionStatus {
    /// The status word the center connector reports.
    pub fn label(self) -> &'static str {
        match self {
            Self::Disconnected => "Disconnected",
            Self::Connecting => "Connecting",
            Self::Connected => "Connected",
            Self::Error => "Error",
        }
    }
}

/// A live session bound to a profile.
///
/// Status is driven by the state machine and the picture by the registered
/// backend's stream. Sessions are `Clone` and snapshotted every frame, so the
/// framebuffer lives in `App::frames`, not here.
#[derive(Clone, Debug)]
pub struct Session {
    pub profile_id: Uuid,
    pub profile_snapshot: ConnectionProfile,
    pub status: SessionStatus,
    pub last_message: String,
    /// The displayed framebuffer's size in pixels, or `(0, 0)` for a session
    /// with no picture yet.
    ///
    /// A projection of `App::frames`, written only from the frame the sink just
    /// presented and cleared when the surface retires, so
    /// [`crate::session::SurfaceBody::Live`] means there are pixels to paint.
    /// Kept on the session so [`crate::session::surface_body`] stays a pure
    /// function of it.
    pub surface_size: (u32, u32),
    /// Whether clipboard sharing is live for this session.
    ///
    /// Seeded from the profile's inverted `disable_clipboard`, then toggled per
    /// session from the toolbar without editing the saved profile.
    /// `App::deliver_clipboard_to_session` refuses while it is false.
    pub clipboard_enabled: bool,
    /// The last clipboard payload handed to this session; `None` until something
    /// is delivered.
    ///
    /// Populated after a complete keystroke paste was queued for the live
    /// transport. A refused delivery leaves it untouched.
    pub last_clipboard_sent: Option<String>,

    /// Whether the session surface is fullscreen, with shell chrome hidden.
    ///
    /// Per session, so fullscreening one connection does not hide the sidebar
    /// for others; see [`crate::session::fullscreen_label`].
    pub fullscreen: bool,

    /// How the remote framebuffer is fitted into the surface; independent of
    /// [`Self::fullscreen`].
    pub scaling: ScalingMode,
    pub dynamic_resize: bool,

    /// Whether input is forwarded to the remote. Read by
    /// `App::deliver_macro_to_session`, which refuses when it is `ViewOnly` —
    /// a "view-only" session that still forwards Ctrl+Alt+Del is the worst
    /// kind of inert control.
    pub input_mode: InputMode,

    /// The connection parameters the backend was asked for, captured from the
    /// profile at connect time; this is where the form's Quality and Color Depth
    /// pickers take effect. See [`crate::protocol::ConnectParams`].
    pub negotiated: crate::protocol::ConnectParams,

    /// The id of the last keystroke macro forwarded to the remote.
    ///
    /// `None` until one is sent; a refused send (view-only, or no backend)
    /// leaves it untouched. Owned because VT ids such as `ctrl-alt-f3` are
    /// generated from a console number.
    pub last_macro_sent: Option<String>,
}

impl Session {
    pub fn new(profile: ConnectionProfile) -> Self {
        // Derived from the profile before it moves into the snapshot. Negotiated,
        // not merely requested, via the protocol clamp that
        // `RemoteProtocol::negotiate`'s default also uses, so every creation path
        // agrees; a stricter backend re-clamps in `App::drive_session`.
        let negotiated = crate::protocol::negotiate_for(
            profile.protocol,
            crate::protocol::ConnectParams::from_profile(&profile),
        );
        Self {
            clipboard_enabled: !profile.disable_clipboard,
            dynamic_resize: !profile.view_only
                && profile
                    .extra
                    .get("remote.display.dynamic-resize")
                    .is_some_and(|v| v == "true"),
            profile_id: profile.id,
            profile_snapshot: profile,
            status: SessionStatus::Disconnected,
            last_message: String::new(),
            surface_size: (0, 0),
            last_clipboard_sent: None,
            fullscreen: false,
            scaling: ScalingMode::default(),
            // Seeded from the profile via `negotiated`: a profile saved with "Open
            // read-only" must open a view-only session.
            input_mode: if negotiated.view_only {
                InputMode::ViewOnly
            } else {
                InputMode::Interactive
            },
            negotiated,
            last_macro_sent: None,
        }
    }

    /// What the session surface paints. Delegates to
    /// [`crate::session::surface_body`] so the four-way decision lives in one
    /// place and the view cannot re-derive a fifth reading of it.
    pub fn surface_body(&self) -> crate::session::SurfaceBody {
        crate::session::surface_body(self.status, self.surface_size, &self.last_message)
    }

    /// The long clipboard label, stating state and action; used as the chip's
    /// accessible name, since screen-reader users get no tooltip.
    pub fn clipboard_action_label(&self) -> &'static str {
        if self.clipboard_enabled {
            "Clipboard sharing: ON (click to disable)"
        } else {
            "Clipboard sharing: OFF (click to enable)"
        }
    }

    /// Whether the Send clipboard as keystrokes chip may fire.
    ///
    /// Requires both `clipboard_enabled` and `input_mode.forwards_input()`. The
    /// action synthesises key events, the same channel `Ctrl+Alt+Del` uses, so a
    /// view-only session must refuse it.
    pub fn can_send_clipboard_as_keystrokes(&self) -> bool {
        self.clipboard_enabled && self.input_mode.forwards_input()
    }

    /// Why the send chip is refusing, or `None` when it is live.
    ///
    /// Two conditions mean two reasons, and "clipboard sharing is off" is the
    /// wrong thing to tell someone whose session is view-only: they would go and
    /// flip a switch that changes nothing here.
    pub fn send_clipboard_refusal(&self) -> Option<&'static str> {
        if !self.clipboard_enabled {
            return Some("Clipboard sharing is disabled for this session.");
        }
        if !self.input_mode.forwards_input() {
            return Some("Clipboard not sent: this session is view-only.");
        }
        None
    }
}
