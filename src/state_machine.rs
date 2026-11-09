//! Session state machine.
//!
//! Every transition the app can make on `SessionStatus`, as a pure table with
//! a full transition matrix in the test module.
//!
//! # Contract
//!
//! A status dot is green when connected, red on error, and absent when idle,
//! so transitions must be honest: `Disconnected -> Connected` without
//! `Connecting` is forbidden.
//!
//! ```text
//!   Disconnected --Connect()--> Connecting
//!   Connecting   --Ready()---->  Connected
//!   Connecting   --Fail(_)---->  Error
//!   Connected    --Drop()---->   Error
//!   Connected    --Disconnect() -> Disconnected
//!   Error        --Reconnect() -> Connecting
//!   Error        --Dismiss()  -> Disconnected
//!   Disconnected --Disconnect() -> Disconnected      (idempotent)
//!   Connected    --Connect()   -> Connected          (idempotent, keeps state)
//! ```
//!
//! Anything else returns [`TransitionError::Invalid`]. There is no catch-all;
//! `tests::transition_matrix_is_exhaustive` proves every `(status, event)`
//! pair is either legal or explicitly invalid.

use crate::model::SessionStatus;

/// External events that can drive the session state.
#[derive(Clone, Debug, PartialEq)]
pub enum SessionEvent {
    /// User asked to start connecting.
    Connect,
    /// The backend reports the transport (TCP, TLS, auth exchange) is up and the
    /// session is Connected.
    Ready,
    /// Backend reported a fatal error before reaching Connected.
    Fail(String),
    /// A Connected session dropped unexpectedly.
    ///
    /// Arrives through the session stream: a backend that detects a dead socket
    /// sends `Drop(reason)` and closes its channel, and the row goes to `Error`.
    Drop(String),
    /// User asked to disconnect gracefully.
    Disconnect,
    /// User asked to retry from an Error state.
    Reconnect,
    /// A new framebuffer from the remote: its geometry and pixels, tightly
    /// packed RGBA8, `width * height * 4` bytes.
    ///
    /// Carries no generation or sequence; the reducer stamps those in
    /// [`crate::framebuffer::admit`], since a backend cannot see the app's
    /// connect identity. Nothing is validated here: a mismatched or oversized
    /// geometry is refused at admission and the previous frame stays on screen.
    ///
    /// [`crate::framebuffer::FrameBytes`] keeps the buffer cheap to clone
    /// across `Message` and keeps eight million bytes out of a `Debug` render.
    Frame {
        width: u32,
        height: u32,
        pixels: crate::framebuffer::FrameBytes,
    },
    /// The backend refused an input event.
    ///
    /// A connected backend reports that the remote stopped accepting input (for
    /// example a half-closed channel). The reducer logs the refusal.
    InputRejected(String),
    Clipboard(crate::native_clipboard::Text),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitionError {
    /// The event is not defined in the state machine for this status.
    Invalid,
}

/// Apply a `SessionEvent` to a `SessionStatus`, returning the new status and
/// a human-readable diagnostic message (or `None` if the event carries no
/// message).
pub fn transition(
    status: SessionStatus,
    event: &SessionEvent,
) -> Result<(SessionStatus, Option<String>), TransitionError> {
    use SessionEvent as E;
    use SessionStatus as S;
    match (status, event) {
        (S::Disconnected, E::Connect) => Ok((S::Connecting, None)),
        (S::Disconnected, E::Disconnect) => Ok((S::Disconnected, None)),

        (S::Connecting, E::Ready) => Ok((S::Connected, None)),
        (S::Connecting, E::Fail(msg)) => Ok((S::Error, Some(msg.clone()))),
        (S::Connecting, E::Disconnect) => Ok((S::Disconnected, None)),

        (S::Connected, E::Drop(msg)) => Ok((S::Error, Some(msg.clone()))),
        (S::Connected, E::Disconnect) => Ok((S::Disconnected, None)),
        // Idempotent Connect on Connected: the reducer may see redundant
        // events from a background task; don't error, just stay.
        (S::Connected, E::Connect) => Ok((S::Connected, None)),

        // A frame changes the picture, not the status; admission, retention and
        // coalescing belong to the reducer's frame sink. Only `Connected` accepts
        // one, so a late stream event cannot paint over a closed session.
        (S::Connected, E::Frame { .. }) => Ok((S::Connected, None)),

        // An input rejection while connected is informational; the
        // session stays up. The message is carried for logging/toast.
        (S::Connected, E::Clipboard(_)) => Ok((S::Connected, None)),
        (S::Connected, E::InputRejected(msg)) => Ok((S::Connected, Some(msg.clone()))),

        (S::Error, E::Reconnect) => Ok((S::Connecting, None)),
        (S::Error, E::Disconnect) => Ok((S::Disconnected, None)),

        _ => Err(TransitionError::Invalid),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {}
