//! Session delivery operations.

use super::*;

impl App {
    pub(crate) fn cancel_desktop_pointer(&mut self, pid: Uuid) {
        let buttons = self.held_buttons.get(&pid).cloned().unwrap_or_default();
        for button in buttons {
            self.deliver_pointer_to_session(pid, crate::session::PointerGesture::Released(button));
        }
    }

    pub(crate) fn deliver_desktop_key(&mut self, pid: Uuid, input: crate::protocol::RemoteInput) {
        let releasing = matches!(input, crate::protocol::RemoteInput::KeyUp(_));
        let allowed = self.sessions.iter().any(|session| {
            session.profile_id == pid
                && session.status == SessionStatus::Connected
                && (releasing
                    || (session.input_mode.forwards_input()
                        && self.selected_profile == Some(pid)
                        && !self.modal_open()))
        });
        if !allowed {
            return;
        }
        if let Some(backend) = self.session_backend(pid) {
            match backend.send_input_for(pid, input) {
                Ok(()) => match input {
                    crate::protocol::RemoteInput::KeyDown(key) => {
                        self.held_keys.entry(pid).or_default().insert(key);
                    }
                    crate::protocol::RemoteInput::KeyUp(key) => {
                        if let Some(keys) = self.held_keys.get_mut(&pid) {
                            keys.remove(&key);
                        }
                    }
                    _ => {}
                },
                Err(error) => {
                    if let Some(session) = self
                        .sessions
                        .iter_mut()
                        .find(|session| session.profile_id == pid)
                    {
                        session.last_message = format!("Input not sent: {error}");
                    }
                }
            }
        }
    }

    pub(crate) fn release_inactive_desktops(&mut self) {
        let inactive = |pid: &Uuid| {
            self.selected_profile != Some(*pid)
                || self.modal_open()
                || self
                    .sessions
                    .iter()
                    .find(|session| session.profile_id == *pid)
                    .is_none_or(|session| !session.input_mode.forwards_input())
        };
        for session in &self.sessions {
            if let Some(backend) = self.session_backend(session.profile_id) {
                backend.clipboard_enabled_for(
                    session.profile_id,
                    session.status == SessionStatus::Connected
                        && session.clipboard_enabled
                        && !inactive(&session.profile_id)
                        && backend
                            .input_capture_for(session.profile_id)
                            .is_some_and(|capture| {
                                capture.load(std::sync::atomic::Ordering::SeqCst)
                            }),
                );
            }
            if inactive(&session.profile_id)
                && let Some(lease) = self
                    .session_backend(session.profile_id)
                    .and_then(|backend| backend.input_capture_for(session.profile_id))
            {
                lease.store(false, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let mut release: Vec<_> = self
            .held_keys
            .keys()
            .chain(self.held_buttons.keys())
            .filter(|pid| inactive(pid))
            .copied()
            .collect();
        release.sort_unstable();
        release.dedup();
        for pid in release {
            let Some(backend) = self.session_backend(pid) else {
                continue;
            };
            let keys = self.held_keys.remove(&pid).unwrap_or_default();
            let buttons = self.held_buttons.remove(&pid).unwrap_or_default();
            let inputs: Vec<_> = keys
                .into_iter()
                .map(crate::protocol::RemoteInput::KeyUp)
                .chain(buttons.into_iter().map(|button| {
                    crate::protocol::RemoteInput::PointerButton {
                        button,
                        pressed: false,
                    }
                }))
                .collect();
            if let Err(error) = backend.send_inputs_for(pid, &inputs)
                && let Some(session) = self
                    .sessions
                    .iter_mut()
                    .find(|session| session.profile_id == pid)
            {
                session.last_message = format!("Input release failed: {error}");
            }
        }
    }

    pub(crate) fn deliver_desktop_scroll(&mut self, pid: Uuid, delta: iced::mouse::ScrollDelta) {
        use crate::protocol::PointerButton as B;
        let (x, y) = match delta {
            iced::mouse::ScrollDelta::Lines { x, y } => (x, y),
            iced::mouse::ScrollDelta::Pixels { x, y } => (x / 40.0, y / 40.0),
        };
        for (amount, negative, positive) in [
            (y, B::WheelDown, B::WheelUp),
            (x, B::WheelRight, B::WheelLeft),
        ] {
            if !amount.is_finite() || amount == 0.0 {
                continue;
            }
            let button = if amount < 0.0 { negative } else { positive };
            for _ in 0..(amount.abs().ceil() as u32).min(10) {
                self.deliver_pointer_to_session(
                    pid,
                    crate::session::PointerGesture::Pressed(button),
                );
                self.deliver_pointer_to_session(
                    pid,
                    crate::session::PointerGesture::Released(button),
                );
            }
        }
    }

    /// Hand a keystroke macro to the profile's session if that session forwards
    /// input.
    ///
    /// Gated here at the transfer, not only on the chip, because shortcuts, AT
    /// activations and queued clicks also route the message. A refusal writes
    /// `last_message` and leaves `last_macro_sent` untouched.
    pub(crate) fn deliver_macro_to_session(&mut self, pid: Uuid, mac: KeystrokeMacro) {
        let Some(session) = self.sessions.iter().find(|s| s.profile_id == pid) else {
            return;
        };
        if !session.input_mode.forwards_input() {
            let refusal = format!("{} not sent: this session is view-only.", mac.label());
            if let Some(session) = self.sessions.iter_mut().find(|s| s.profile_id == pid) {
                session.last_message = refusal;
            }
            return;
        }
        let events = mac.events();

        // The chord reaches the remote only through a registered backend on a
        // connected session; the message reports what happened, not the intent.
        let live = session.status == SessionStatus::Connected;
        let outcome = match self.session_backend(pid).filter(|_| live) {
            None => MacroOutcome::NoBackend,
            Some(backend) => {
                let mut sent = 0usize;
                let mut failure = None;
                for event in &events {
                    let input = if event.pressed {
                        crate::protocol::RemoteInput::KeyDown(event.keysym)
                    } else {
                        crate::protocol::RemoteInput::KeyUp(event.keysym)
                    };
                    match backend.send_input_for(pid, input) {
                        Ok(()) => sent += 1,
                        // Stop at the first refusal, so the count describes what was received.
                        Err(e) => {
                            failure = Some(e.to_string());
                            break;
                        }
                    }
                }
                match failure {
                    None => MacroOutcome::Sent,
                    Some(reason) => MacroOutcome::Refused { sent, reason },
                }
            }
        };

        let Some(session) = self.sessions.iter_mut().find(|s| s.profile_id == pid) else {
            return;
        };
        match outcome {
            MacroOutcome::Sent => {
                session.last_message =
                    format!("{} sent ({} key events).", mac.label(), events.len());
                session.last_macro_sent = Some(mac.id());
            }
            MacroOutcome::NoBackend => {
                session.last_message = format!(
                    "{} ({} key events) — no backend in this build.",
                    mac.label(),
                    events.len()
                );
                // Records which chord the user asked for, which the pane reads back.
                session.last_macro_sent = Some(mac.id());
            }
            MacroOutcome::Refused { sent, reason } => {
                session.last_message = format!(
                    "{} not sent: the remote stopped accepting input after {sent} of {} key events ({reason}).",
                    mac.label(),
                    events.len()
                );
                // A chord the remote refused part-way through was not sent.
                // Leaving the field untouched is what keeps "sent" meaning
                // sent, the same rule the view-only gate above relies on.
            }
        }
    }

    /// Swap the keystroke menu to `page`, rebuilding its entries.
    ///
    /// `MenuModel::reconcile` re-finds the highlight by id; the pages' ids are
    /// disjoint, so it falls to the neighbour rule.
    pub(crate) fn set_keystroke_page(&mut self, page: KeystrokePage) {
        if self.keystroke_page == page {
            return;
        }
        self.keystroke_page = page;
        let entries = keystroke_menu_model(page).entries().to_vec();
        self.keystroke_model.reconcile(entries);
        // The page swap is the submenu; leaving the marker set would make
        // `MenuState::open_submenu()` claim a surface that is not on screen.
        self.keystroke_menu.close_submenu();
    }

    /// The open form's rule with this id, if any.
    pub(crate) fn rule_mut(&mut self, id: Uuid) -> Option<&mut crate::form::RuleDraft> {
        self.form.as_mut()?.rules.iter_mut().find(|r| r.id == id)
    }

    /// Hand `text` to the profile's session if that session shares its
    /// clipboard.
    ///
    /// Gated here at the transfer, since other routes than the button reach it.
    /// A refusal writes `last_message` and leaves `last_clipboard_sent`
    /// untouched.
    pub(crate) fn deliver_clipboard_to_session(&mut self, pid: Uuid, text: &str) {
        let Some(session) = self.sessions.iter_mut().find(|s| s.profile_id == pid) else {
            return;
        };
        // The clipboard is sent as synthesised keystrokes, so view-only refuses it
        // too. `Session::send_clipboard_refusal` is shared with the chip's enabled
        // state.
        if let Some(reason) = session.send_clipboard_refusal() {
            session.last_message = reason.into();
            return;
        }
        if text.is_empty() {
            // An empty clipboard is not a failure and not a delivery. Saying
            // "sent 0 characters" would read as success.
            session.last_message = "The clipboard is empty.".into();
            return;
        }
        if text.chars().count() > 4096 {
            session.last_message =
                "Clipboard text is too large. Paste at most 4,096 characters at a time.".into();
            return;
        }
        if session.status != SessionStatus::Connected {
            session.last_message = "Clipboard not sent: the session is not connected.".into();
            return;
        }
        let Some(backend) = self.session_backend(pid) else {
            return;
        };
        let mut sent = 0;
        let mut inputs = Vec::with_capacity(text.len().min(4096) * 2);
        for ch in text.chars() {
            let keysym = match ch {
                '\n' => xkeysym::key::Return,
                '\r' => continue,
                '\t' => xkeysym::key::Tab,
                ch if ch.is_control() => continue,
                ch => xkeysym::Keysym::from_char(ch).raw(),
            };
            inputs.extend([
                crate::protocol::RemoteInput::KeyDown(keysym),
                crate::protocol::RemoteInput::KeyUp(keysym),
            ]);
            sent += 1;
        }
        if let Err(error) = backend.send_inputs_for(pid, &inputs) {
            if let Some(session) = self.sessions.iter_mut().find(|s| s.profile_id == pid) {
                session.last_message = format!("Clipboard not sent: {error}");
            }
            return;
        }
        if let Some(session) = self.sessions.iter_mut().find(|s| s.profile_id == pid) {
            session.last_message = format!("Clipboard sent as keystrokes ({sent} chars).");
            session.last_clipboard_sent = Some(text.to_string());
        }
    }
}

impl App {
    pub(crate) fn native_clipboard_allowed(&self, pid: Uuid, generation: u64) -> bool {
        self.session_streams.get(&pid) == Some(&generation)
            && self.selected_profile == Some(pid)
            && !self.modal_open()
            && self.sessions.iter().any(|s| {
                s.profile_id == pid
                    && matches!(
                        s.profile_snapshot.protocol,
                        Protocol::Vnc | Protocol::Rdp | Protocol::Spice | Protocol::RustDesk
                    )
                    && s.status == SessionStatus::Connected
                    && s.clipboard_enabled
                    && s.input_mode.forwards_input()
            })
            && self
                .session_backend(pid)
                .and_then(|b| b.input_capture_for(pid))
                .is_some_and(|capture| capture.load(std::sync::atomic::Ordering::SeqCst))
    }
    pub(crate) fn read_native_clipboard(
        &self,
        pid: Uuid,
        generation: u64,
        paste: Option<bool>,
    ) -> Task<Message> {
        if !self.native_clipboard_allowed(pid, generation) {
            return Task::none();
        }
        iced::clipboard::read_text().map(move |result| {
            Message::SyncedClipboard(
                pid,
                generation,
                paste,
                result.map(crate::native_clipboard::Text),
            )
        })
    }
    pub(crate) fn sync_native_clipboard(
        &mut self,
        pid: Uuid,
        generation: u64,
        paste: Option<bool>,
        result: Result<std::sync::Arc<String>, iced::clipboard::Error>,
    ) -> Task<Message> {
        if !self.native_clipboard_allowed(pid, generation) {
            return Task::none();
        }
        let outcome = result
            .map_err(|_| "Cannot read the clipboard.".to_owned())
            .and_then(|text| {
                let backend = self
                    .session_backend(pid)
                    .ok_or("The session is no longer active.")?;
                backend
                    .share_clipboard_for(pid, &text)
                    .map_err(|error| error.to_string())?;
                if let Some(shifted) = paste {
                    use crate::protocol::RemoteInput::{KeyDown, KeyUp};
                    let held = self.held_keys.get(&pid);
                    let ctrl = held.is_some_and(|keys| {
                        keys.contains(&xkeysym::key::Control_L)
                            || keys.contains(&xkeysym::key::Control_R)
                    });
                    let shift = held.is_some_and(|keys| {
                        keys.contains(&xkeysym::key::Shift_L)
                            || keys.contains(&xkeysym::key::Shift_R)
                    });
                    let mut inputs = Vec::new();
                    if !ctrl {
                        inputs.push(KeyDown(xkeysym::key::Control_L));
                    }
                    if shifted && !shift {
                        inputs.push(KeyDown(xkeysym::key::Shift_L));
                    }
                    let key = if shifted {
                        xkeysym::key::V
                    } else {
                        xkeysym::key::v
                    };
                    inputs.extend([KeyDown(key), KeyUp(key)]);
                    if shifted && !shift {
                        inputs.push(KeyUp(xkeysym::key::Shift_L));
                    }
                    if !ctrl {
                        inputs.push(KeyUp(xkeysym::key::Control_L));
                    }
                    backend
                        .send_inputs_for(pid, &inputs)
                        .map_err(|error| error.to_string())?;
                }
                Ok(())
            });
        if let Err(reason) = outcome {
            if paste.is_some() {
                self.toasts.push(
                    enzui_iced_widgets::toast_host::ToastSpec::new(reason.clone())
                        .tone(enzui_iced_widgets::toast::ToastTone::Error),
                );
            }
            if let Some(session) = self.sessions.iter_mut().find(|s| s.profile_id == pid) {
                session.last_message = reason;
            }
        }
        Task::none()
    }
}
