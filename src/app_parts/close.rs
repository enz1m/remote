//! Window-close debt and modal status.

use super::*;

impl App {
    /// Hold the window the compositor named, and start emptying it.
    ///
    /// New connections stop and every live session is severed. The window closes here only if nothing of this
    /// app's is still running; otherwise its id is held and only
    /// [`Self::drive_close_debt`] destroys it, so no surface outlives its
    /// connections. An open file chooser's intent is dropped, so a late answer lands
    /// nowhere.
    pub(crate) fn begin_window_close(&mut self, request: CloseRequest) -> Task<Message> {
        if let Some(window) = self.main_window {
            self.transfer_picker.parent_closed(window);
        } else {
            self.transfer_picker.cancel();
        }
        self.retire_imports();
        self.pending_save_connects.clear();
        // Closing admission and retiring reservations prevents late dials from
        // acquiring transports after the surfaces that could end them are gone.
        self.backends.stop_vnc_admission();
        self.backends.stop_desktop_admission();
        // Timers go with admission so no deadline spawns a child during the drain. The
        // recency publication is synchronous, so the close waits only on each severed
        // session's child.
        self.reconnect.cancel_all();
        // The same transition a user's Disconnect makes, so the surfaces a
        // session owns are retired by one route rather than two.
        let severed: Vec<Uuid> = self
            .sessions
            .iter()
            .filter(|session| session.status == SessionStatus::Connected)
            .map(|session| session.profile_id)
            .collect();
        for pid in severed {
            self.apply_session_event(pid, SessionEvent::Disconnect);
        }
        // A transport whose session was not `Connected` above — a dial that
        // registered while the close was being applied — is reached here
        // rather than left holding a socket.
        for pid in self.backends.retire_all_vnc_sessions() {
            self.retire_session_surface(pid);
        }
        self.refresh_close_notices();

        let items = self.close_items();
        match self.close_guard.request(request, items) {
            CloseGuardAction::Close(window) => {
                #[cfg(feature = "center")]
                self.shutdown_center();
                iced::window::close(window)
            }
            CloseGuardAction::Hold => {
                self.close_budget = CLOSE_WAKE_BUDGET;
                Task::none()
            }
            // The guard only asks for a save when it was given one to run, and
            // nothing here is saveable.
            CloseGuardAction::Save { .. } => Task::none(),
        }
    }

    /// One bounded item per thing a close is still waiting for.
    ///
    /// An empty list is the whole close condition: a connection still being
    /// ended, or a worker still holding a channel, each keep the window alive.
    fn close_items(&self) -> Vec<UnsavedItem<Uuid>> {
        let mut items = Vec::new();
        // Severed VNC transports owe their join (reader, writer, socket). Read from the
        // cached report so this list and the close banner agree; a profile whose
        // protocol changed can owe one close of each kind.
        items.extend(self.vnc_close_notices.iter().copied().map(|debt| {
            let name = self
                .profiles
                .iter()
                .find(|profile| profile.id == debt.profile_id)
                .map_or_else(
                    || "a connection".to_string(),
                    |profile| crate::error_boundary::sanitize_subject(&profile.name).into_owned(),
                );
            let label = match debt.progress {
                crate::rfb::backend::VncCloseProgress::Closing => name,
                // This one will not clear on its own, and listing it beside
                // the ones that will would promise it away.
                crate::rfb::backend::VncCloseProgress::Unknown => {
                    format!("{name} (not confirmed closed)")
                }
            };
            UnsavedItem::new(debt.profile_id, label)
        }));
        items.extend(self.desktop_close_notices.iter().copied().map(|id| {
            let name = self
                .profiles
                .iter()
                .find(|profile| profile.id == id)
                .map_or_else(
                    || "Desktop connection".to_owned(),
                    |profile| crate::display::bound_display_name(&profile.name),
                );
            UnsavedItem::new(id, name)
        }));
        items
    }

    /// One coalesced pass of the close route.
    ///
    /// Collects finished teardowns, redispatches what a busy pool refused, and
    /// republishes the per-profile debt. The window is destroyed only at zero debt,
    /// when every child is reaped and every reader and watcher joined. Otherwise one
    /// wake of [`Self::close_budget`] is spent; at zero the surface offers Retry and
    /// a veto.
    pub(crate) fn drive_close_debt(&mut self) -> Task<Message> {
        let owed = self.refresh_close_notices();
        if !self.close_is_held() {
            return Task::none();
        }
        if owed == 0 {
            let Some(window) = self.close_guard.pending_window() else {
                return Task::none();
            };
            // The captured id, never "the current window": the one the
            // compositor asked about is the one that may be destroyed.
            return match self.close_guard.force_close(window) {
                CloseGuardAction::Close(window) => {
                    #[cfg(feature = "center")]
                    self.shutdown_center();
                    iced::window::close(window)
                }
                CloseGuardAction::Hold | CloseGuardAction::Save { .. } => Task::none(),
            };
        }
        self.close_budget = self.close_budget.saturating_sub(1);
        Task::none()
    }

    /// How far this profile's connection has got in closing, if it is closing.
    ///
    /// A severed but unaccounted connection must not be shown as disconnected. Each
    /// transport reports its own close progress through [`SessionCloseProgress`].
    #[must_use]
    pub fn close_progress_for(&self, pid: Uuid) -> Option<SessionCloseProgress> {
        if self.desktop_close_notices.contains(&pid) {
            return Some(SessionCloseProgress::Closing);
        }
        self.backends
            .vnc_close_progress(pid)
            .map(|progress| match progress {
                crate::rfb::backend::VncCloseProgress::Closing => SessionCloseProgress::Closing,
                crate::rfb::backend::VncCloseProgress::Unknown => SessionCloseProgress::Unconfirmed,
            })
    }

    /// Whether a window close is being held for connections that are closing.
    #[must_use]
    pub fn close_is_held(&self) -> bool {
        self.close_guard.is_pending()
    }

    /// Whether a held close has spent its budget and is now asking the user.
    #[must_use]
    pub fn close_is_overdue(&self) -> bool {
        self.close_is_held() && self.close_budget == 0
    }

    /// Whether the retry wake is wanted this frame.
    ///
    /// True while an owed close can advance on its own, or a held window close waits
    /// on unspent budget or an occupied worker. A close that has spent its budget
    /// waits for the user's Retry without a timer.
    #[must_use]
    pub fn wants_close_wake(&self) -> bool {
        if self.backends.vnc_close_work_pending() || !self.desktop_close_notices.is_empty() {
            return true;
        }
        self.close_is_held() && !self.close_is_overdue()
    }

    /// Re-read the backend's close debt into the reducer's own bounded copy.
    ///
    /// Returns the number of connections still closing across all transports. Rebuilt
    /// rather than patched, and the only read of either list: the backend calls also
    /// collect joins and redispatch closes, so surfaces read the cached copies.
    pub(crate) fn refresh_close_notices(&mut self) -> usize {
        let vnc_owed = self.backends.vnc_close_debt();
        self.vnc_close_notices = self.backends.vnc_close_report();
        self.desktop_close_notices = self.backends.desktop_closing();
        vnc_owed + self.desktop_close_notices.len()
    }

    /// Whether a dialog or chooser owns keyboard traversal.
    pub fn modal_open(&self) -> bool {
        !self.dialogs.is_empty()
            || self.transfer_picker.is_pending()
            || self.form.is_some()
            || self.quick_connect_open
            || self.pending_delete_profile.is_some()
    }

    /// The current status for a profile (Disconnected if no session).
    pub fn session_status_for(&self, id: Uuid) -> SessionStatus {
        self.sessions
            .iter()
            .find(|s| s.profile_id == id)
            .map(|s| s.status)
            .unwrap_or(SessionStatus::Disconnected)
    }

    /// Whether `id` has a transport-confirmed connected session.
    ///
    /// A `Session` value is created before credential lookup and survives an
    /// error so Retry has state to act on. Its mere presence therefore proves
    /// nothing about a remote channel. Session-scoped affordances which need a
    /// channel (currently SFTP) must consult this predicate, not `sessions`.
    pub(crate) fn has_connected_session(&self, id: Uuid) -> bool {
        self.sessions
            .iter()
            .any(|session| session.profile_id == id && session.status == SessionStatus::Connected)
    }

    /// Keep an open menu synchronized with live profile and session capabilities.
    pub(crate) fn reconcile_open_context_menu(&mut self) {
        match crate::context_menu::items_for_open(self) {
            Some(rows) => {
                self.context_menu.menu.reconcile(rows);
            }
            None if !self.context_menu.menu.is_open() => self.context_menu.close(),
            // Keep the restore path until dismissal when its profile vanished; live UUID validation refuses actions.
            None => {}
        }
    }

    // Routed accessibility work accepted since the last drain, taken once per
    // turn: the dismissal decision and the applier must see the same batch, and
    // a second drain would hand the applier an empty one.
    #[cfg(not(test))]
    pub(crate) fn drain_routed_accessibility_actions()
    -> Vec<enzui_iced_core::app_runtime::RoutedAccessibilityAction> {
        enzui_iced_core::app_runtime::drain_accessibility_actions()
    }

    // Only the winit accessibility bridge can seed the process-global router,
    // so a reducer test hands its routed actions to the same seam this turn
    // drains.
    #[cfg(test)]
    pub(crate) fn drain_routed_accessibility_actions()
    -> Vec<enzui_iced_core::app_runtime::RoutedAccessibilityAction> {
        crate::a11y_test_queue::joined(enzui_iced_core::app_runtime::drain_accessibility_actions())
    }
}
