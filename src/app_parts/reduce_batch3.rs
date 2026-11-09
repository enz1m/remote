//! Reducer arms batch 3: form view through wake-on-lan.

use super::*;

impl App {
    pub(crate) fn reduce3_form_view_only_toggled_80(&mut self, on: bool) -> Task<Message> {
        if let Some(f) = self.form.as_mut() {
            f.view_only = on;
        }

        Task::none()
    }

    pub(crate) fn reduce3_form_group_changed_81(&mut self, v: String) -> Task<Message> {
        if let Some(f) = self.form.as_mut() {
            f.group = v;
        }

        Task::none()
    }

    pub(crate) fn reduce3_form_notes_changed_82(&mut self, v: String) -> Task<Message> {
        if let Some(f) = self.form.as_mut() {
            f.notes = v;
        }

        Task::none()
    }

    pub(crate) fn reduce3_form_tunnel_host_changed_83(&mut self, v: String) -> Task<Message> {
        if let Some(f) = self.form.as_mut() {
            f.tunnel_host = v;
        }

        Task::none()
    }

    pub(crate) fn reduce3_form_tunnel_port_changed_84(&mut self, v: String) -> Task<Message> {
        if let Some(f) = self.form.as_mut() {
            f.tunnel_port = v;
        }

        Task::none()
    }

    pub(crate) fn reduce3_form_tunnel_username_changed_85(&mut self, v: String) -> Task<Message> {
        if let Some(f) = self.form.as_mut() {
            f.tunnel_username = v;
        }

        Task::none()
    }

    pub(crate) fn reduce3_form_tunnel_password_changed_86(&mut self, v: String) -> Task<Message> {
        if let Some(f) = self.form.as_mut() {
            if v.is_empty() {
                f.tunnel_legacy_password = false;
            }
            f.tunnel_password = v;
            // Same `dirty` role as the connection password's: it is what
            // separates "left the stored secret alone" from
            // "deliberately emptied it".
            f.tunnel_password_dirty = true;
        }

        Task::none()
    }

    pub(crate) fn reduce3_toggle_session_fullscreen_88(&mut self, pid: Uuid) -> Task<Message> {
        if let Some(s) = self.sessions.iter_mut().find(|s| s.profile_id == pid) {
            s.fullscreen = !s.fullscreen;
        }

        Task::none()
    }

    pub(crate) fn reduce3_toggle_session_scaling_89(&mut self, pid: Uuid) -> Task<Message> {
        if let Some(s) = self.sessions.iter_mut().find(|s| s.profile_id == pid) {
            s.scaling = s.scaling.toggled();
        }

        Task::none()
    }

    pub(crate) fn reduce3_toggle_session_input_mode_90(&mut self, pid: Uuid) -> Task<Message> {
        if let Some(s) = self.sessions.iter_mut().find(|s| s.profile_id == pid) {
            if matches!(
                s.profile_snapshot.protocol,
                Protocol::Rdp | Protocol::Spice | Protocol::RustDesk | Protocol::Moonlight
            ) && s.negotiated.view_only
            {
                return Task::none();
            }
            s.input_mode = s.input_mode.toggled();
            if !s.input_mode.forwards_input() && s.dynamic_resize {
                s.dynamic_resize = false;
                if let Some(backend) = self.session_backend(pid) {
                    let _ = backend.set_dynamic_resize_for(pid, false);
                }
                self.requested_sizes.remove(&pid);
            }
        }

        Task::none()
    }

    pub(crate) fn reduce3_keystroke_menu_91(
        &mut self,
        event: enzui_iced_widgets::menu_button::MenuButtonEvent,
    ) -> Task<Message> {
        use enzui_iced_widgets::menu_button::MenuButtonEvent;

        // Paging is decided before the framework applier, which only records a submenu
        // id and knows nothing of this app's page-swap submenus.
        let paged_to = match &event {
            MenuButtonEvent::SubmenuOpened(id)
                if id.as_str() == crate::session::SWITCH_VT_ENTRY_ID =>
            {
                Some(KeystrokePage::SwitchVt)
            }
            MenuButtonEvent::Activated { id, .. }
                if id.as_str() == crate::session::KEYSTROKE_BACK_ENTRY_ID =>
            {
                Some(KeystrokePage::Root)
            }
            // A dismissal returns to the root page so reopening never lands on the VT page.
            MenuButtonEvent::Close(_) => Some(KeystrokePage::Root),
            _ => None,
        };

        if let Some(page) = paged_to {
            self.set_keystroke_page(page);
            // `Back` and `Switch VT` must skip the applier's activation path, which would
            // close the whole menu on `Back`. `Close` is still applied below.
            if !matches!(event, MenuButtonEvent::Close(_)) {
                return Task::none();
            }
        }

        // The framework applier owns the open/close/highlight lifecycle and returns the
        // activated entry, if any.
        let activated = enzui_iced_widgets::menu_button::apply_event(
            &mut self.keystroke_model,
            &mut self.keystroke_menu,
            &event,
        );
        if let Some(entry) = activated
            && let Some(mac) = KeystrokeMacro::from_id(entry.as_str())
            && let Some(pid) = self.selected_profile
        {
            self.deliver_macro_to_session(pid, mac);
        }

        Task::none()
    }

    pub(crate) fn reduce3_scan_network_92(&mut self) -> Task<Message> {
        self.dispatch_scan()
    }

    pub(crate) fn reduce3_scan_finished_93(
        &mut self,
        generation: u64,
        outcome: crate::discovery::DiscoveryOutcome,
    ) -> Task<Message> {
        if generation != self.scan_generation {
            // A superseded scan's answer is dropped; it carries only a proposal, so nothing
            // was installed.
            return Task::none();
        }
        self.settle_scan(outcome);

        Task::none()
    }

    pub(crate) fn reduce3_scan_cancel_94(&mut self) -> Task<Message> {
        self.retire_scan();

        Task::none()
    }

    pub(crate) fn reduce3_save_discovered_95(&mut self, key: String) -> Task<Message> {
        // Copy, not promote: the discovered entry stays where it is
        // (a re-scan finds the machine again regardless) and the new
        // profile gets its own identity.
        let Some(host) = self.discovered.iter().find(|h| h.key() == key) else {
            return Task::none();
        };
        let profile = host.to_profile();
        let id = profile.id;
        // The discovered entry stays in its own list either way, so a
        // refused write leaves the Save affordance right where it was
        // for a retry — with nothing added to the library.
        if !self.settle_profile_write(&profile) {
            return Task::none();
        }
        self.profiles.push(profile);
        self.selected_profile = Some(id);

        Task::none()
    }

    pub(crate) fn reduce3_export_profiles_96(&mut self) -> Task<Message> {
        self.begin_transfer(crate::picker::TransferTarget::ExportProfiles)
    }

    pub(crate) fn reduce3_import_rdp_97(&mut self) -> Task<Message> {
        self.begin_transfer(crate::picker::TransferTarget::ImportRdp)
    }

    pub(crate) fn reduce3_import_remmina_98(&mut self) -> Task<Message> {
        self.begin_transfer(crate::picker::TransferTarget::ImportRemmina)
    }

    pub(crate) fn reduce3_import_profiles_99(&mut self) -> Task<Message> {
        self.begin_transfer(crate::picker::TransferTarget::ImportProfiles)
    }

    pub(crate) fn reduce3_transfer_portal_tick_100(&mut self) -> Task<Message> {
        self.transfer_picker.pump()
    }

    pub(crate) fn reduce3_import_ready_101(
        &mut self,
        generation: u64,
        target: crate::picker::TransferTarget,
        outcome: crate::import_source::ImportOutcome,
    ) -> Task<Message> {
        // The generation retires an abandoned read and the target retires one whose
        // destination changed; dropping either is safe because it carries a proposal,
        // not a written row.
        let wanted = self
            .import_in_flight
            .as_ref()
            .is_some_and(|f| f.generation == generation && f.target == target);
        if !wanted {
            return Task::none();
        }
        self.import_in_flight = None;
        // The answer arrived, so the handle is cleared and a later cancel cannot settle
        // a reported generation.
        self.import_cancellation = None;
        let result = self.settle_import(outcome);
        self.transfer_result = Some(result);

        self.pump_desktop_imports()
    }

    pub(crate) fn reduce3_import_cancel_102(&mut self) -> Task<Message> {
        self.launch_imports.clear();
        self.retire_imports();

        Task::none()
    }

    pub(crate) fn reduce3_dismiss_transfer_result_103(&mut self) -> Task<Message> {
        self.launch_imports.clear();
        // Closing the banner closes the import it is reporting on: the
        // banner's control is the only cancel there is.
        self.retire_imports();
        self.transfer_result = None;

        Task::none()
    }

    pub(crate) fn reduce3_quick_connect_open_104(&mut self) -> Task<Message> {
        self.quick_connect_open = true;

        Task::none()
    }

    pub(crate) fn reduce3_quick_connect_dismiss_105(&mut self) -> Task<Message> {
        self.dismiss_quick_connect_focus(enzui_iced_core::modal::DismissCause::CancelAction)
    }

    pub(crate) fn reduce3_quick_connect_recent_107(&mut self, key: String) -> Task<Message> {
        // Seed and present the form rather than connecting, so the user confirms first.
        let Some(recent) = crate::quick_connect::find(&self.recents, &key) else {
            return Task::none();
        };
        let profile = recent.to_profile();
        // An add form, because `for_profile` sets `editing` for an id not in
        // `self.profiles`, which `save_form` declines.
        let mut form = ConnectionForm::for_add();
        form.connect_on_save = true;
        form.name = profile.name.clone();
        form.host = profile.host.clone();
        form.port = profile.port.to_string();
        form.port_touched = true;
        form.protocol = profile.protocol;
        form.username = profile.username.clone();
        self.form = Some(form);
        self.quick_connect_open = false;

        Task::none()
    }

    pub(crate) fn reduce3_quick_connect_save_recent_108(&mut self, key: String) -> Task<Message> {
        // Persist without connecting or presenting a form;
        // `quick_connect_save_survives_a_restart` covers this path.
        let Some(recent) = crate::quick_connect::find(&self.recents, &key) else {
            return Task::none();
        };
        let profile = recent.to_profile();
        let id = profile.id;
        // Closing the sheet is the success feedback, so it waits for the write; a
        // refused write leaves the sheet open for a retry.
        if !self.settle_profile_write(&profile) {
            return Task::none();
        }
        self.profiles.push(profile);
        // Select it so the result is visible, without starting a session.
        self.selected_profile = Some(id);
        self.quick_connect_open = false;

        Task::none()
    }

    pub(crate) fn reduce3_quick_connect_retry_save_109(&mut self, key: String) -> Task<Message> {
        // The entry is re-read from the list so the retry writes the original
        // connection time.
        let Some(entry) = crate::quick_connect::find(&self.recents, &key).cloned() else {
            return Task::none();
        };
        self.retry_recency_debt(&entry);

        Task::none()
    }

    pub(crate) fn reduce3_quick_connect_forget_recent_110(&mut self, key: String) -> Task<Message> {
        self.forget_recent(&key);

        Task::none()
    }

    pub(crate) fn reduce3_quick_connect_clear_recents_111(&mut self) -> Task<Message> {
        self.clear_recents();

        Task::none()
    }

    pub(crate) fn reduce3_quick_connect_enter_details_112(&mut self) -> Task<Message> {
        self.quick_connect_open = false;
        let mut form = ConnectionForm::for_add();
        form.connect_on_save = true;
        self.form = Some(form);

        Task::none()
    }

    pub(crate) fn reduce3_quick_connect_address_changed_113(
        &mut self,
        text: String,
    ) -> Task<Message> {
        // Typing clears a pinned submit error; the stored error is set only by an
        // explicit submit.
        self.quick_connect_address = text;
        self.quick_connect_address_error = None;

        Task::none()
    }

    pub(crate) fn reduce3_quick_connect_address_submit_114(&mut self) -> Task<Message> {
        // `parse_connectable`, so a typed URI cannot seed a form for a protocol the
        // picker does not offer.
        let parsed = crate::quick_connect::parse_connectable(&self.quick_connect_address, |p| {
            self.backends.available(p)
        });
        match parsed {
            Ok(parsed) => {
                // Seed an add form for review, as with `QuickConnectRecent`.
                let mut form = ConnectionForm::for_add();
                form.connect_on_save = true;
                form.protocol = parsed.protocol;
                form.host = parsed.host.clone();
                form.port = parsed.port.to_string();
                form.port_touched = true;
                form.username = parsed.username.clone();
                // Default the profile name to the endpoint, matching
                // the `Recent → add form` seeding.
                form.name = if parsed.port == parsed.protocol.default_port() {
                    parsed.host
                } else {
                    format!("{}:{}", parsed.host, parsed.port)
                };
                self.form = Some(form);
                self.quick_connect_open = false;
                self.quick_connect_address.clear();
                self.quick_connect_address_error = None;
            }
            Err(e) => {
                // Leave the dialog open with the inline error visible.
                // No dismissal, no connect — the exact behaviour the
                // parser sabotage test would notice was gone.
                self.quick_connect_address_error = Some(e);
            }
        }

        Task::none()
    }

    pub(crate) fn reduce3_open_context_menu_115(
        &mut self,
        id: Uuid,
        at: iced::Point,
        row_path: Vec<String>,
    ) -> Task<Message> {
        if let Some(profile) = self.profiles.iter().find(|p| p.id == id) {
            self.selected_profile = Some(id);
            let rows = crate::context_menu::menu_items(
                profile,
                self.sessions.iter().any(|s| s.profile_id == id),
                self.backends.available(profile.protocol),
                crate::context_menu::session_generation(self, id),
            );
            self.context_menu.open(id, at, rows, row_path);
        }
        Task::none()
    }

    pub(crate) fn reduce3_context_menu_event_116(
        &mut self,
        event: enzui_iced_widgets::context_menu_host::ContextMenuEvent,
    ) -> Task<Message> {
        self.reconcile_open_context_menu();
        let (chosen, focus) = self.context_menu.menu.update(&event);
        let task = match chosen {
            Some((profile_id, row))
                if self.profiles.iter().any(|p| {
                    p.id == profile_id
                        && crate::context_menu::items(
                            p,
                            self.sessions.iter().any(|s| s.profile_id == profile_id),
                            self.backends.available(p.protocol),
                        )
                        .contains(&row)
                }) =>
            {
                self.update(Message::ContextRowActivated(profile_id, row))
            }
            _ => Task::none(),
        };
        Task::batch([focus, task])
    }

    pub(crate) fn reduce3_context_row_activated_118(
        &mut self,
        id: Uuid,
        row: crate::context_menu::RowKind,
    ) -> Task<Message> {
        self.context_menu.close();
        let msg = match row {
            // The disclosure row is disabled in the model; returning here keeps the arm
            // inert whatever a caller sends.
            crate::context_menu::RowKind::Unavailable => return Task::none(),
            crate::context_menu::RowKind::Connect => {
                if self.sessions.iter().any(|session| session.profile_id == id) {
                    self.selected_profile = Some(id);
                    self.nav.dismiss_overlay();
                    return Task::none();
                }
                Message::SessionAction(id)
            }
            crate::context_menu::RowKind::Disconnect => {
                if !matches!(
                    self.session_status_for(id),
                    SessionStatus::Connecting | SessionStatus::Connected
                ) {
                    return Task::none();
                }
                Message::SessionAction(id)
            }
            crate::context_menu::RowKind::Edit => Message::FormOpenEdit(id),
            crate::context_menu::RowKind::Wake => Message::WakeOnLan(id),
            crate::context_menu::RowKind::ToggleFavorite => Message::ToggleFavorite(id),
            crate::context_menu::RowKind::Duplicate => Message::DuplicateProfile(id),
            crate::context_menu::RowKind::Delete => Message::RequestDeleteProfile(id),
        };
        self.update(msg)
    }

    pub(crate) fn reduce3_toggle_favorite_119(&mut self, id: Uuid) -> Task<Message> {
        if let Some(p) = self.profiles.iter_mut().find(|p| p.id == id) {
            p.favorite = !p.favorite;
        }
        // Persist after the mutable borrow ends. Without this the
        // star would be a session-lifetime decoration.
        let Some(written) = self.profiles.iter().find(|p| p.id == id).cloned() else {
            return Task::none();
        };
        // A star the store refused is a session-lifetime decoration
        // again, so put it back where the store still has it. The
        // revert is what makes the next launch agree with the screen.
        let accepted = self.settle_profile_write(&written);
        if !accepted && let Some(p) = self.profiles.iter_mut().find(|p| p.id == id) {
            p.favorite = !p.favorite;
        }

        Task::none()
    }

    pub(crate) fn reduce3_duplicate_profile_120(&mut self, id: Uuid) -> Task<Message> {
        let Some(original) = self.profiles.iter().find(|p| p.id == id).cloned() else {
            return Task::none();
        };
        let mut copy = original.clone();
        copy.id = Uuid::new_v4();
        copy.name = format!("{} (copy)", original.name);
        copy.created = chrono::Utc::now();
        copy.last_connected = None;
        // The secret is not copied, which would mint a second keyring credential, so the
        // copy's keyring flag is cleared.
        copy.has_keyring_password = false;
        // A copy the store refused is not a connection: leaving it in
        // the list would offer a row to connect to, edit and select
        // that no restart can find.
        if !self.settle_profile_write(&copy) {
            return Task::none();
        }
        let new_id = copy.id;
        self.profiles.push(copy);
        // Select the copy: the user just made it and it is what they
        // will edit next.
        self.selected_profile = Some(new_id);

        Task::none()
    }

    pub(crate) fn reduce3_delete_profile_121(&mut self, id: Uuid) -> Task<Message> {
        // Delete the secret first; the record is dropped in
        // `Message::ProfileSecretDeleted` only once the store confirms (`Deleted` /
        // `NotFound`, or acknowledged unavailability), so no orphaned keyring item
        // survives. Both legs run under one generation, so a save made while an unlock
        // prompt is pending supersedes this delete.
        let generation = self.begin_profile_op(id, true, true);
        let op = self.credentials.delete(profile_password_key(id));
        Task::future(op).map(move |o| {
            Message::ProfileSecretDeleted(id, generation, CredResult::from_outcome(o))
        })
    }

    pub(crate) fn reduce3_profile_secret_deleted_122(
        &mut self,
        id: Uuid,
        generation: u64,
        result: CredResult,
    ) -> Task<Message> {
        if !self.settle_secret_slot(id, generation, SecretSlot::Password) {
            return Task::none();
        }
        match result {
            // Only an observed deletion (or an observed absence) may
            // commit immediately.
            CredResult::Deleted | CredResult::NotFound => {
                // If tunnel cleanup is later refused the profile stays, so record that the
                // primary password is confirmed gone; a refused row write is disclosed.
                if let Err(cause) = self.publish_secret_marker(id, SecretSlot::Password, false) {
                    self.disclose_marker_refusal(
                        id,
                        cause,
                        crate::error_boundary::DbWriteOperation::PublishSecretRemoved,
                    );
                }
                let tunnel_op = self.credentials.delete(tunnel_password_key(id));
                return Task::future(tunnel_op).map(move |outcome| {
                    Message::ProfileTunnelSecretDeleted(
                        id,
                        generation,
                        CredResult::from_outcome(outcome),
                    )
                });
            }
            // Without a service a stale keyring item cannot be ruled out, so the profile is
            // kept and profile-only deletion needs explicit acknowledgement.
            CredResult::Unavailable => {
                if self.profiles.iter().any(|profile| profile.id == id) {
                    self.pending_delete_profile = Some(id);
                    self.delete_without_credentials_warning = true;
                }
            }
            // Refusal, unlock dismissal, app cancellation and failure
            // all retain the record. Cancellations are intentionally
            // quiet; genuine failures use the existing notice surface.
            other => {
                if !other.is_cancellation()
                    && let Some(p) = self.profiles.iter().find(|p| p.id == id)
                {
                    let name = crate::display::bound_display_name(&p.name);
                    let reason = match &other {
                        CredResult::Denied => "the system keyring refused the request",
                        CredResult::Failed(_) => "the system keyring could not be reached",
                        _ => "the password could not be removed",
                    };
                    self.credential_notice = Some(CredentialNotice::save_failed(
                        &format!("{name} was not deleted"),
                        reason,
                    ));
                }
            }
        }

        Task::none()
    }

    pub(crate) fn reduce3_profile_tunnel_secret_deleted_123(
        &mut self,
        id: Uuid,
        generation: u64,
        result: CredResult,
    ) -> Task<Message> {
        if !self.settle_secret_slot(id, generation, SecretSlot::Tunnel) {
            return Task::none();
        }
        match result {
            CredResult::Deleted | CredResult::NotFound => {
                return self.commit_profile_delete(id, false);
            }
            CredResult::Unavailable => {
                if self.profiles.iter().any(|profile| profile.id == id) {
                    self.pending_delete_profile = Some(id);
                    self.delete_without_credentials_warning = true;
                }
            }
            other => {
                if !other.is_cancellation()
                    && let Some(profile) = self.profiles.iter().find(|profile| profile.id == id)
                {
                    let reason = match &other {
                        CredResult::Denied => "the system keyring refused the request",
                        CredResult::Failed(_) => "the system keyring could not be reached",
                        _ => "the tunnel password could not be removed",
                    };
                    let name = crate::display::bound_display_name(&profile.name);
                    self.credential_notice = Some(CredentialNotice::save_failed(
                        &format!("{name} was not deleted"),
                        reason,
                    ));
                }
            }
        }

        Task::none()
    }

    pub(crate) fn reduce3_wake_on_lan_124(&mut self, id: Uuid) -> Task<Message> {
        let Some(p) = self.profiles.iter().find(|p| p.id == id) else {
            return Task::none();
        };
        let name = p.name.clone();
        let Some(raw) = p.wol_mac.clone() else {
            // The row is only offered for a profile with a MAC, so this stays inert rather
            // than reporting a failure the user did not cause.
            return Task::none();
        };
        let outcome = match crate::model::mac_bytes(&raw) {
            None => Err(WolAttemptFailure::InvalidMac(raw.clone())),
            Some(bytes) => match crate::model::send_wol_packet(&bytes) {
                Ok(()) => Ok(raw.clone()),
                Err(reason) => Err(WolAttemptFailure::SendFailed(reason)),
            },
        };
        self.record_wol_attempt(name, outcome);

        Task::none()
    }
}
