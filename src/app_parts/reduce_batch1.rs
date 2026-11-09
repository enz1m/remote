//! Reducer arms batch 1: shell through browser download.

use super::*;
use crate::credential_plumbing::CredResult;
use crate::protocol::ProtocolError;
use crate::state_machine::SessionEvent;
use enzui_iced_core::app_runtime::AccessibilityWake;
use enzui_iced_core::theme_file::integration::ThemeEvent;
use iced::Size;

impl App {
    pub(crate) fn reduce1_theme_0(&mut self, event: ThemeEvent) -> Task<Message> {
        let before = self.themes.theme_generation();
        let task = self.themes.update(event);
        debug_assert!(self.themes.theme_generation() >= before);
        // Resync the compatibility mirror from the host on
        // every generation change. A watcher would race the reducer;
        // this pulls the value at the exact point the host settled.
        if self.themes.theme_generation() != before {
            self.enz_theme = self.themes.theme().clone();
        }
        task.map(|event| Message::Theme(Box::new(event)))
    }

    pub(crate) fn reduce1_window_resized_1(&mut self, size: Size) -> Task<Message> {
        self.window_width = size.width;
        self.window_height = size.height;

        Task::none()
    }

    pub(crate) fn reduce1_close_sidebar_overlay_2(&mut self) -> Task<Message> {
        // Scrim click / navigation. Clears the drawer flag only — the
        // durable preference is untouched, so dismissing a drawer
        // never destroys the user's expanded-mode choice.
        self.nav.dismiss_overlay();

        Task::none()
    }

    pub(crate) fn reduce1_sidebar_state_3(&mut self, next: NavSplitState) -> Task<Message> {
        // Store only: the shell already applied `toggle_for_presentation` against the
        // presentation it rendered, and repeating it here would add a second collapse
        // authority.
        self.nav = next;

        Task::none()
    }

    pub(crate) fn reduce1_toggle_titlebar_overflow_4(&mut self) -> Task<Message> {
        self.titlebar_overflow_open = !self.titlebar_overflow_open;

        Task::none()
    }

    pub(crate) fn reduce1_toggle_import_menu_5(&mut self) -> Task<Message> {
        // Closing restores focus to the trigger id, so Escape or outside-click does not
        // strand the roving cursor in the removed overlay.
        let was_open = self.import_menu_open;
        self.import_menu_open = !was_open;
        if let Some(op) = enzui_iced_widgets::action_bar::overflow_focus_restore_operation(
            was_open,
            Some(&iced::advanced::widget::Id::new(
                crate::sidebar_view::IMPORT_MENU_TRIGGER_ID,
            )),
        ) {
            return iced::advanced::widget::operate(op);
        }

        Task::none()
    }

    pub(crate) fn reduce1_window_6(
        &mut self,
        command: enzui_iced_widgets::title_bar_gesture::WindowCommand,
    ) -> Task<Message> {
        // Chrome commands retain the bound main window as their target.
        let Some(id) = self.chrome_target() else {
            return Task::none();
        };
        // The app's own close control enters the same held route as
        // the compositor's gesture. Dispatching the runtime's close
        // here would destroy the window over live connections.
        if matches!(
            command,
            enzui_iced_widgets::title_bar_gesture::WindowCommand::Close
        ) {
            return self.begin_window_close(CloseRequest::for_window(id));
        }
        command.into_task(id)
    }

    pub(crate) fn reduce1_main_window_opened_7(&mut self, id: iced::window::Id) -> Task<Message> {
        // Bind once: a later preview/dialog must not retarget chrome.
        if self.main_window.is_none() {
            self.main_window = Some(id);
        }

        Task::done(Message::InstanceWake)
    }

    pub(crate) fn reduce1_window_close_requested_8(
        &mut self,
        request: enzui_iced_core::close_guard::CloseRequest,
    ) -> Task<Message> {
        self.begin_window_close(request)
    }

    pub(crate) fn reduce1_connection_close_tick_9(&mut self) -> Task<Message> {
        self.drive_close_debt()
    }

    pub(crate) fn reduce1_window_close_retry_10(&mut self) -> Task<Message> {
        self.close_budget = CLOSE_WAKE_BUDGET;
        let _ = self.backends.retry_vnc_closes();
        self.drive_close_debt()
    }

    pub(crate) fn reduce1_window_close_veto_11(&mut self) -> Task<Message> {
        // The window stays, so the app admits connections again. What
        // was severed stays severed: its debt keeps draining on the
        // same wake, and its profiles keep reporting that they are.
        let _ = self.close_guard.decide(CloseDecision::Cancel);
        self.close_budget = 0;
        // May not reopen yet: VNC admission waits until the transports
        // severed by this close have been joined, so the app never
        // dials beside an owner that is still running.
        let _ = self.backends.resume_vnc_admission();
        self.backends.resume_desktop_admission();
        self.refresh_close_notices();

        Task::none()
    }

    pub(crate) fn reduce1_toggle_group_12(&mut self, key: String) -> Task<Message> {
        // The first toggle converts the typed default-open state into explicit
        // membership; `Only(empty)` means none expanded.
        let group_keys = self
            .profiles
            .iter()
            .map(|profile| crate::organise::group_key(&profile.group))
            .collect::<Vec<_>>();
        self.group_expansion.toggle(key, group_keys);

        Task::none()
    }

    pub(crate) fn reduce1_toggle_favorites_13(&mut self) -> Task<Message> {
        // A plain boolean flip. No empty-set seeding like `ToggleGroup`,
        // because Favorites has its own collapsed-by-default flag rather than
        // sharing the folder convention.
        self.favorites_expanded = !self.favorites_expanded;

        Task::none()
    }

    pub(crate) fn reduce1_no_op_14(&mut self) -> Task<Message> {
        // `on_select` also fires for folder headers; those route to nothing so the
        // drawer is not dismissed by a keystroke on a branch.

        Task::none()
    }

    pub(crate) fn reduce1_a11y_wake_15(&mut self, receipt: AccessibilityWake) -> Task<Message> {
        // The only drain that honours the receipt's batch identity; if an earlier drain
        // took the batch, this applies nothing.
        enzui_iced_widgets::a11y_actions::apply_accessibility_wake::<Message>(receipt)
    }

    pub(crate) fn reduce1_search_changed_16(&mut self, q: String) -> Task<Message> {
        self.search_query = q;

        Task::none()
    }

    pub(crate) fn reduce1_select_profile_17(&mut self, id: Uuid) -> Task<Message> {
        self.selected_profile = Some(id);
        // Selecting a destination dismisses the drawer without touching the preference.
        self.nav.dismiss_overlay();

        Task::none()
    }

    pub(crate) fn reduce1_session_action_18(&mut self, pid: Uuid) -> Task<Message> {
        self.drive_session(pid)
    }

    pub(crate) fn reduce1_connect_result_19(
        &mut self,
        pid: Uuid,
        generation: u64,
        result: Result<Vec<SessionEvent>, ProtocolError>,
        stream_slot: Arc<std::sync::Mutex<Option<crate::protocol::SessionStream>>>,
    ) -> Task<Message> {
        // Identity first: the answer to an abandoned dial still arrives and must not
        // promote the live session. A mismatch leaves the entry for the in-flight dial.
        let dispatched = match self.dispatched_connects.get(&pid) {
            Some(d) if d.generation == generation => self.dispatched_connects.remove(&pid),
            _ => return Task::none(),
        };
        // The typed failure is read before it becomes a sentence: the
        // reconnect policy needs to know whether another attempt
        // could differ, and a rendered string cannot say that.
        let (events, disposition) = match result {
            Ok(evts) => (evts, None),
            Err(e) => {
                let disposition = e.retry_disposition();
                (vec![SessionEvent::Fail(e.to_string())], Some(disposition))
            }
        };
        // One wall-clock reading per settlement so the recent row and connection time
        // record the same edge.
        let ready_at = chrono::Utc::now();
        let mut reached_ready = false;
        let mut admitted = false;
        for event in events {
            // Only a `Ready` from this dial admits a recent, under the identity it was sent
            // with.
            let admits = match (&event, &dispatched) {
                (SessionEvent::Ready, Some(d)) => Some((&d.candidate, ready_at)),
                _ => None,
            };
            reached_ready |= matches!(event, SessionEvent::Ready);
            admitted |= self.apply_session_event_admitting(pid, event, admits);
        }
        if reached_ready {
            // The session is authoritative from the Ready edge. The dial identity travels
            // with it because a profile edited mid-dial may name an endpoint no transport
            // reached.
            let dialled = dispatched.as_ref().map(|d| &d.candidate);
            self.settle_authoritative_ready(pid, dialled, ready_at, admitted);
        } else if let Some(disposition) = disposition {
            self.settle_failed_attempt(pid, disposition);
        }
        // Poll the backend stream as `SessionStreamEvent`s until it closes. The task
        // cannot be cancelled, so it carries the generation it was opened under and
        // stale events are dropped on arrival.
        if let Some(stream) = stream_slot.lock().unwrap().take() {
            let generation = self.open_session_stream(pid);
            return Task::run(
                crate::protocol::session_stream_to_futures_stream(stream),
                move |event| Message::SessionStreamEvent(pid, generation, event),
            );
        }

        Task::none()
    }

    pub(crate) fn reduce1_session_stream_event_20(
        &mut self,
        pid: Uuid,
        generation: u64,
        event: SessionEvent,
    ) -> Task<Message> {
        // Generation first: a superseded stream's frame, drop or rejection must not
        // touch the session that replaced it.
        if self.session_streams.get(&pid) != Some(&generation) {
            return Task::none();
        }
        // Frames bypass `apply_session_event`; admission, retention and presentation
        // belong to the sink.
        match event {
            SessionEvent::Clipboard(text) => {
                if self.native_clipboard_allowed(pid, generation) {
                    return iced::clipboard::write(text.0.as_ref().clone()).map(move |result| {
                        Message::NativeClipboardWritten(pid, generation, result)
                    });
                }
                return Task::none();
            }
            SessionEvent::Frame {
                width,
                height,
                pixels,
            } => return self.accept_frame(pid, width, height, pixels),
            other => {
                // A `Drop` is an unexpected loss and is charged as a transport failure, which a
                // retry can differ on. A `Fail` here carries no typed cause and schedules
                // nothing.
                let lost = matches!(other, SessionEvent::Drop(_));
                self.apply_session_event(pid, other);
                if lost {
                    self.settle_failed_attempt(pid, crate::reconnect::RetryDisposition::Transient);
                }
            }
        }

        Task::none()
    }

    pub(crate) fn reduce1_reconnect_tick_21(
        &mut self,
        pid: Uuid,
        generation: u64,
        now: std::time::Instant,
    ) -> Task<Message> {
        self.run_due_retries(pid, generation, now)
    }

    pub(crate) fn reduce1_reconnect_cancel_22(&mut self, pid: Uuid) -> Task<Message> {
        // Ends the policy only; the session keeps its state and failure message.
        self.reconnect.cancel(pid);

        Task::none()
    }

    pub(crate) fn reduce1_session_surface_resized_23(
        &mut self,
        pid: Uuid,
        size: iced::Size,
    ) -> Task<Message> {
        self.surface_resized(pid, size)
    }

    pub(crate) fn reduce1_session_pointer_24(
        &mut self,
        pid: Uuid,
        gesture: crate::session::PointerGesture,
    ) -> Task<Message> {
        self.deliver_pointer_to_session(pid, gesture);

        Task::none()
    }

    pub(crate) fn reduce1_credential_store_ready_25(
        &mut self,
        store: std::sync::Arc<dyn enzui_services::credential_store::CredentialStore>,
    ) -> Task<Message> {
        self.credentials = store;
        // Exact fake/memory answers can repair stale hints. The real
        // transport answers Unknown synchronously, preserving hints
        // and avoiding any `get`/unlock operation in this list loop.
        let before: Vec<bool> = self
            .profiles
            .iter()
            .map(|profile| profile.has_keyring_password)
            .collect();
        crate::keyring::reconcile_badge_on_boot(&mut self.profiles, self.credentials.as_ref());
        // The reconciler acts only on an exact `contains` answer, so the repaired hint
        // stands in memory even if the row write is refused; that disagreement is
        // disclosed.
        let repaired: Vec<ConnectionProfile> = self
            .profiles
            .iter()
            .zip(&before)
            .filter(|(profile, old)| profile.has_keyring_password != **old)
            .map(|(profile, _)| profile.clone())
            .collect();
        for profile in repaired {
            if let Err(cause) = self.write_profile_row(&profile) {
                let op = if profile.has_keyring_password {
                    crate::error_boundary::DbWriteOperation::PublishSecretStored
                } else {
                    crate::error_boundary::DbWriteOperation::PublishSecretRemoved
                };
                self.disclose_marker_refusal(profile.id, cause, op);
            }
        }

        Task::none()
    }

    pub(crate) fn reduce1_password_fetched_26(
        &mut self,
        pid: Uuid,
        generation: u64,
        result: CredResult,
    ) -> Task<Message> {
        self.on_password_fetched(pid, generation, result)
    }

    pub(crate) fn reduce1_credential_save_result_27(
        &mut self,
        id: Uuid,
        generation: u64,
        slot: SecretSlot,
        intent: SaveIntent,
        result: CredResult,
    ) -> Task<Message> {
        self.on_credential_save_result(id, generation, slot, intent, result);

        Task::none()
    }

    pub(crate) fn reduce1_dismiss_credential_notice_28(&mut self) -> Task<Message> {
        self.credential_notice = None;

        Task::none()
    }

    pub(crate) fn reduce1_dismiss_wol_status_29(&mut self) -> Task<Message> {
        self.wol_status = None;

        Task::none()
    }

    pub(crate) fn reduce1_toggle_session_clipboard_30(&mut self, pid: Uuid) -> Task<Message> {
        if let Some(s) = self.sessions.iter_mut().find(|s| s.profile_id == pid) {
            s.clipboard_enabled = !s.clipboard_enabled;
            let enabled = s.clipboard_enabled && s.input_mode.forwards_input();
            if let Some(backend) = self.session_backend(pid) {
                backend.clipboard_enabled_for(pid, enabled);
            }
        }

        Task::none()
    }

    pub(crate) fn reduce1_send_clipboard_to_session_31(&mut self, pid: Uuid) -> Task<Message> {
        // Read even when sharing is off so the refusal lives only in
        // `deliver_clipboard_to_session`, nearest the transfer.
        iced::clipboard::read_text().map(move |r| Message::ClipboardToSession(pid, r))
    }
}
