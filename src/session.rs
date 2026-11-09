//! Session-view chrome: scaling mode, the surface's display state, and the
//! keystroke macros a user can send to the remote.
//!
//! Pure (no iced, reducer or I/O), so which surface body to paint and which
//! keysyms a macro expands to are unit-testable without a runtime.
//!
//! # Connecting, waiting for a first frame, and failure are distinct states
//!
//! [`SurfaceBody`] distinguishes the transport handshake from waiting for the
//! first picture. A connected transport without a framebuffer is a normal
//! startup phase; failures keep their own error presentation.
//!
//! # Keystroke macros
//!
//! `Print Screen` forwards the key to the remote (`XK_PRINT` down/up); it is
//! not a local screenshot, which would photograph the wrong machine.

use crate::model::SessionStatus;

// ---------------------------------------------------------------------------
// Scaling mode
// ---------------------------------------------------------------------------

/// How the remote framebuffer is fitted into the session surface.
///
/// A separate control from fullscreen: fullscreen sets how much of the window
/// the surface gets, scaling sets how remote pixels map into that surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ScalingMode {
    /// Scale the framebuffer to fit the surface, preserving aspect ratio.
    #[default]
    ScaleToFit,
    /// Render the framebuffer at 1:1, letting the surface clip or letterbox.
    OriginalSize,
}

impl ScalingMode {
    /// The label naming the currently active mode; used as the tooltip.
    pub fn label(self) -> &'static str {
        match self {
            Self::ScaleToFit => "Scaled to fit",
            Self::OriginalSize => "Original size",
        }
    }

    /// The label naming what activating the chip does; used as the accessible
    /// name, since screen-reader users never receive the tooltip.
    pub fn action_label(self) -> &'static str {
        match self {
            Self::ScaleToFit => "Switch to original size",
            Self::OriginalSize => "Switch to scaled to fit",
        }
    }

    /// The mode a press produces.
    pub fn toggled(self) -> Self {
        match self {
            Self::ScaleToFit => Self::OriginalSize,
            Self::OriginalSize => Self::ScaleToFit,
        }
    }

    /// Whether the framebuffer is scaled to the surface. `OriginalSize`
    /// paints 1:1 and centres, so the picture may be pillarboxed or clipped.
    ///
    /// `framebuffer::fit_for` turns this into the `ContentFit` used both to paint
    /// the picture and to map a pointer back onto a remote pixel, so a press
    /// lands on the pixel under the cursor in either mode.
    pub fn scales_to_fit(self) -> bool {
        matches!(self, Self::ScaleToFit)
    }
}

// ---------------------------------------------------------------------------
// Input mode
// ---------------------------------------------------------------------------

/// A pointer gesture on the session surface, before it is mapped to a remote
/// pixel.
///
/// Deliberately not a mirror of every `iced::mouse` event: a gesture the app
/// does not forward cannot reach the remote by accident. Each maps to exactly
/// one [`crate::protocol::RemoteInput`], with no synthesised drag, wheel or
/// double-click.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PointerGesture {
    /// The pointer moved to this position, in slot coordinates with the origin
    /// at the surface's top-left.
    ///
    /// `mouse_area` reports presses and releases without coordinates, so the
    /// reducer reports buttons against the last mapped position rather than
    /// wherever the remote cursor was left.
    Moved(iced::Point),
    /// A button went down at the last moved-to position.
    Pressed(crate::protocol::PointerButton),
    /// A button came up at the last moved-to position.
    Released(crate::protocol::PointerButton),
}

/// Whether input is forwarded to the remote.
///
/// `View-only` is not cosmetic: it is the gate
/// [`crate::App::deliver_macro_to_session`] consults before handing a keystroke
/// macro to the backend. A "view-only" session that still forwards Ctrl+Alt+Del
/// is the worst kind of inert control — the label says the remote is safe and
/// it is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum InputMode {
    /// Keyboard and pointer are forwarded.
    #[default]
    Interactive,
    /// Nothing is forwarded; the surface is a picture.
    ViewOnly,
}

impl InputMode {
    /// The label naming what activating the chip does — the accessible name.
    pub fn action_label(self) -> &'static str {
        match self {
            Self::Interactive => "Switch to view-only",
            Self::ViewOnly => "Switch to interactive",
        }
    }

    pub fn toggled(self) -> Self {
        match self {
            Self::Interactive => Self::ViewOnly,
            Self::ViewOnly => Self::Interactive,
        }
    }

    /// Whether input may be forwarded to the remote.
    pub fn forwards_input(self) -> bool {
        matches!(self, Self::Interactive)
    }
}

// ---------------------------------------------------------------------------
// Fullscreen
// ---------------------------------------------------------------------------

/// The fullscreen toggle's label for a state; one chip whose label follows
/// the state cannot drift out of sync.
pub fn fullscreen_label(fullscreen: bool) -> &'static str {
    if fullscreen {
        "Exit fullscreen"
    } else {
        "Fullscreen"
    }
}

// ---------------------------------------------------------------------------
// The surface's display state
// ---------------------------------------------------------------------------

/// The literal the surface shows while a connection is being established.
pub const LOADING_LABEL: &str = "Connecting…";

/// The literal the surface shows for a connected session with no framebuffer.
pub const NO_SIGNAL_LABEL: &str = "Waiting for desktop…";

/// The prefix an errored session's title carries.
pub const ERROR_PREFIX: &str = "Error: ";

/// What the session surface paints.
///
/// `Loading`, `NoSignal` and `Failed` must never be conflated; the
/// exhaustive `match` in the view stops compiling if a state is added.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SurfaceBody {
    /// No session has been started for this profile yet.
    NotStarted,
    /// A connection is being established. Not "no signal": nothing has answered
    /// yet, so there is nothing to have lost.
    Loading,
    /// Connected, waiting for the first presented framebuffer.
    NoSignal,
    /// Connected, with a framebuffer of this size displayed.
    ///
    /// Requires an admitted and presented frame, so a remote announcing a
    /// geometry it never sent cannot enter this state.
    Live { size: (u32, u32) },
    /// The connection failed, with the backend's own message. Neither "no
    /// signal" nor "loading", which would hide a failure the user must act on.
    Failed(String),
}

impl SurfaceBody {
    /// The surface's title line.
    pub fn title(&self, protocol_label: &str) -> String {
        match self {
            Self::NotStarted => "Session not started".to_string(),
            Self::Loading => LOADING_LABEL.to_string(),
            Self::NoSignal => NO_SIGNAL_LABEL.to_string(),
            Self::Live { .. } => format!("{protocol_label} session (placeholder)"),
            Self::Failed(message) => format!("{ERROR_PREFIX}{message}"),
        }
    }

    /// Whether this state should be painted in the error tone.
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Failed(_))
    }

    /// Whether the connection reached a state where quality/depth metadata
    /// was actually negotiated with the remote.
    ///
    /// `NoSignal` and `Live` both imply the transport connected and parameters
    /// were exchanged. `NotStarted`, `Loading` and `Failed` do not: rendering
    /// default values as if they were negotiated facts misleads the user
    ///.
    pub fn has_negotiated(&self) -> bool {
        matches!(self, Self::NoSignal | Self::Live { .. })
    }
}

/// Decide which body the surface paints.
///
/// `(0, 0)` is the "no framebuffer yet" sentinel `Session::new` seeds; only a
/// presented frame clears it.
///
/// An errored session with an empty message still renders as an error, with
/// a generic reason, rather than dropping to "no signal".
pub fn surface_body(
    status: SessionStatus,
    surface_size: (u32, u32),
    last_message: &str,
) -> SurfaceBody {
    match status {
        SessionStatus::Disconnected => SurfaceBody::NotStarted,
        SessionStatus::Connecting => SurfaceBody::Loading,
        SessionStatus::Connected => {
            if surface_size.0 == 0 || surface_size.1 == 0 {
                SurfaceBody::NoSignal
            } else {
                SurfaceBody::Live { size: surface_size }
            }
        }
        SessionStatus::Error => SurfaceBody::Failed(if last_message.trim().is_empty() {
            "The backend refused the connection.".to_string()
        } else {
            last_message.to_string()
        }),
    }
}

// ---------------------------------------------------------------------------
// Keystroke macros
// ---------------------------------------------------------------------------

/// X11 keysyms.
pub mod keysyms {
    pub const XK_CONTROL_L: u32 = 0xFFE3;
    pub const XK_ALT_L: u32 = 0xFFE9;
    pub const XK_DELETE: u32 = 0xFFFF;
    pub const XK_TAB: u32 = 0xFF09;
    pub const XK_ESCAPE: u32 = 0xFF1B;
    pub const XK_PRINT: u32 = 0xFF61;
    pub const XK_SUPER_L: u32 = 0xFFEB;
    pub const XK_BACKSPACE: u32 = 0xFF08;

    /// `XK_F1`. The function keysyms are contiguous and ascending, which
    /// [`xk_f`] relies on.
    pub const XK_F1: u32 = 0xFFBE;

    /// The keysym for `F<n>`, `n >= 1`.
    ///
    /// Derived rather than tabulated, because a seven-entry table of
    /// `0xFFBE, 0xFFBF, …` typed by hand is exactly where an off-by-one hides:
    /// the wrong constant sends the user to the wrong console and nothing about
    /// the menu looks different.
    pub const fn xk_f(n: u8) -> u32 {
        XK_F1 + (n as u32) - 1
    }
}

/// A single key press or release in a macro sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyMacroEvent {
    pub keysym: u32,
    pub pressed: bool,
}

impl KeyMacroEvent {
    pub const fn down(keysym: u32) -> Self {
        Self {
            keysym,
            pressed: true,
        }
    }
    pub const fn up(keysym: u32) -> Self {
        Self {
            keysym,
            pressed: false,
        }
    }
}

/// The key combinations the session's Send keystrokes menu offers.
///
/// Each is a chord the local compositor would swallow (Ctrl+Alt+Del,
/// Alt+Tab, Super) or a key laptops lack (Print Screen).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeystrokeMacro {
    CtrlAltDel,
    AltTab,
    CtrlEsc,
    /// The remote Print Screen key, not a local screenshot.
    PrintScreen,
    SuperKey,
    CtrlAltBackspace,
    /// `Ctrl+Alt+F<n>` — switch the remote machine to virtual console `n`.
    ///
    /// One variant over the arithmetic family `XK_F1 + n - 1`, so an off-by-one
    /// cannot hide in seven hand-written keysyms that all look valid.
    ///
    /// `n` is 1-based and expected to be in `1..=VT_COUNT`.
    SwitchVt(u8),
}

/// Every root-page macro, in menu order. Stable so the menu's entry ids and the
/// index-alignment guard have something to be aligned against.
pub const KEYSTROKE_MACROS: [KeystrokeMacro; 6] = [
    KeystrokeMacro::CtrlAltDel,
    KeystrokeMacro::AltTab,
    KeystrokeMacro::CtrlEsc,
    KeystrokeMacro::PrintScreen,
    KeystrokeMacro::SuperKey,
    KeystrokeMacro::CtrlAltBackspace,
];

// ---------------------------------------------------------------------------
// Switch VT — one table, seven entries
// ---------------------------------------------------------------------------

/// How many virtual-console entries the Switch VT submenu offers; the whole
/// family is derived from this number.
pub const VT_COUNT: u8 = 7;

/// The console that is the graphical session rather than a text tty.
///
/// On a modern systemd/logind desktop the seat's graphical session lands on
/// VT 7 when VTs 1-6 are the getty range, which is why the seventh row reads
/// `(GUI)` and not `(tty7)`.
pub const VT_GUI: u8 = 7;

/// Console number to the parenthesised target name for the Switch VT rows.
///
/// `1..=6` are `ttyN`; [`VT_GUI`] is `GUI`. A row's id, keysym and icon all
/// derive from the same `n`, so the pressed row and the sent chord agree.
pub fn vt_target_name(n: u8) -> String {
    if n == VT_GUI {
        "GUI".to_string()
    } else {
        format!("tty{n}")
    }
}

/// Every Switch VT macro, in menu order.
pub fn vt_macros() -> impl Iterator<Item = KeystrokeMacro> {
    (1..=VT_COUNT).map(KeystrokeMacro::SwitchVt)
}

/// Every macro this app can forward, root page then VT page.
///
/// The lookup set for [`KeystrokeMacro::from_id`] and the uniqueness guard, so
/// an id added to one page and forgotten in the other cannot resolve to `None`
/// at runtime while every unit test on the other page stays green.
pub fn all_macros() -> Vec<KeystrokeMacro> {
    KEYSTROKE_MACROS
        .iter()
        .copied()
        .chain(vt_macros())
        .collect()
}

// ---------------------------------------------------------------------------
// The keystroke menu's two pages
// ---------------------------------------------------------------------------

/// Which page of the Send keystrokes menu is showing.
///
/// The page decides which entries the single menu model carries, so the
/// model cannot disagree with the popup on screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum KeystrokePage {
    /// The six single chords, plus the row that opens the VT page.
    #[default]
    Root,
    /// The seven `Ctrl+Alt+F<n>` console switches, plus Back.
    SwitchVt,
}

/// The entry id of the row that opens the VT page. Not a [`KeystrokeMacro`]
/// id: [`KeystrokeMacro::from_id`] must not resolve it, or pressing it would
/// both page and send a chord.
pub const SWITCH_VT_ENTRY_ID: &str = "switch-vt";

/// The visible label of the row that opens the VT page.
///
/// `EnzMenuRow` draws the submenu affordance (`submenu_indicator(true)`, a
/// `navigation.forward` icon in its own trailing cell), so no `▸` is typed
/// into the text — a literal `▸` inside the accessible name is announced as
/// "black right-pointing small triangle" by a screen reader.
pub const SWITCH_VT_LABEL: &str = "Switch VT";

/// The entry id of the VT page's Back row.
pub const KEYSTROKE_BACK_ENTRY_ID: &str = "keystroke-back";

/// The VT page's Back label. No `◂` in the text, for the same reason as
/// [`SWITCH_VT_LABEL`]: the glyph is the row's leading icon.
pub const KEYSTROKE_BACK_LABEL: &str = "Back";

impl KeystrokePage {
    /// The macros this page offers, in menu order.
    pub fn macros(self) -> Vec<KeystrokeMacro> {
        match self {
            Self::Root => KEYSTROKE_MACROS.to_vec(),
            Self::SwitchVt => vt_macros().collect(),
        }
    }
}

impl KeystrokeMacro {
    /// The menu row's stable id.
    pub fn id(self) -> String {
        match self {
            Self::CtrlAltDel => "ctrl-alt-del".to_string(),
            Self::AltTab => "alt-tab".to_string(),
            Self::CtrlEsc => "ctrl-esc".to_string(),
            Self::PrintScreen => "print-screen".to_string(),
            Self::SuperKey => "super".to_string(),
            Self::CtrlAltBackspace => "ctrl-alt-backspace".to_string(),
            Self::SwitchVt(n) => format!("ctrl-alt-f{n}"),
        }
    }

    /// The menu row's visible label; for the VT family, generated from
    /// [`vt_target_name`].
    pub fn label(self) -> String {
        match self {
            Self::CtrlAltDel => "Ctrl + Alt + Del".to_string(),
            Self::AltTab => "Alt + Tab".to_string(),
            Self::CtrlEsc => "Ctrl + Esc".to_string(),
            Self::PrintScreen => "Print Screen".to_string(),
            Self::SuperKey => "Super (Win)".to_string(),
            Self::CtrlAltBackspace => "Ctrl + Alt + Backspace".to_string(),
            // `Ctrl+Alt+F1 (tty1)`: no spaces around the `+` here, unlike the
            // root-page chords.
            Self::SwitchVt(n) => format!("Ctrl+Alt+F{n} ({})", vt_target_name(n)),
        }
    }

    /// The Lucide glyph the row shows.
    pub fn icon(self) -> &'static str {
        match self {
            Self::CtrlAltDel => "shield",
            Self::AltTab => "columns-2",
            Self::CtrlEsc => "menu",
            Self::PrintScreen => "monitor",
            Self::SuperKey => "command",
            Self::CtrlAltBackspace => "x",
            Self::SwitchVt(_) => "terminal",
        }
    }

    /// Parse a menu entry id back into a macro. `None` for anything else, so a
    /// row id that has drifted cannot silently send the wrong chord.
    pub fn from_id(id: &str) -> Option<Self> {
        all_macros().into_iter().find(|m| m.id() == id)
    }

    /// The press/release sequence.
    ///
    /// Modifiers are released in reverse press order, as a real keyboard does;
    /// releasing Ctrl before Delete would leave Delete held on the remote.
    pub fn events(self) -> Vec<KeyMacroEvent> {
        use keysyms::*;
        match self {
            Self::CtrlAltDel => vec![
                KeyMacroEvent::down(XK_CONTROL_L),
                KeyMacroEvent::down(XK_ALT_L),
                KeyMacroEvent::down(XK_DELETE),
                KeyMacroEvent::up(XK_DELETE),
                KeyMacroEvent::up(XK_ALT_L),
                KeyMacroEvent::up(XK_CONTROL_L),
            ],
            Self::AltTab => vec![
                KeyMacroEvent::down(XK_ALT_L),
                KeyMacroEvent::down(XK_TAB),
                KeyMacroEvent::up(XK_TAB),
                KeyMacroEvent::up(XK_ALT_L),
            ],
            Self::CtrlEsc => vec![
                KeyMacroEvent::down(XK_CONTROL_L),
                KeyMacroEvent::down(XK_ESCAPE),
                KeyMacroEvent::up(XK_ESCAPE),
                KeyMacroEvent::up(XK_CONTROL_L),
            ],
            Self::PrintScreen => vec![KeyMacroEvent::down(XK_PRINT), KeyMacroEvent::up(XK_PRINT)],
            Self::SuperKey => vec![
                KeyMacroEvent::down(XK_SUPER_L),
                KeyMacroEvent::up(XK_SUPER_L),
            ],
            Self::CtrlAltBackspace => vec![
                KeyMacroEvent::down(XK_CONTROL_L),
                KeyMacroEvent::down(XK_ALT_L),
                KeyMacroEvent::down(XK_BACKSPACE),
                KeyMacroEvent::up(XK_BACKSPACE),
                KeyMacroEvent::up(XK_ALT_L),
                KeyMacroEvent::up(XK_CONTROL_L),
            ],
            // Same Ctrl+Alt+<key> shape as Ctrl+Alt+Del, with the function
            // keysym derived from `n`.
            Self::SwitchVt(n) => vec![
                KeyMacroEvent::down(XK_CONTROL_L),
                KeyMacroEvent::down(XK_ALT_L),
                KeyMacroEvent::down(xk_f(n)),
                KeyMacroEvent::up(xk_f(n)),
                KeyMacroEvent::up(XK_ALT_L),
                KeyMacroEvent::up(XK_CONTROL_L),
            ],
        }
    }
}

#[cfg(test)]
impl KeystrokeMacro {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {

    // -----------------------------------------------------------------
    // Switch VT
    // -----------------------------------------------------------------
}
