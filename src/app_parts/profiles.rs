//! Profile store writes.

use super::*;

impl App {
    pub(crate) fn credentials_pending(&self, pid: Uuid) -> bool {
        self.profile_ops
            .get(&pid)
            .is_some_and(|operation| operation.password_pending || operation.tunnel_pending)
    }

    pub(crate) fn form_disconnects_session(&self, form: &ConnectionForm) -> bool {
        let Some(pid) = form.editing else {
            return false;
        };
        let active = matches!(
            self.session_status_for(pid),
            SessionStatus::Connected | SessionStatus::Connecting
        ) || self.pending_connects.contains_key(&pid)
            || self.dispatched_connects.contains_key(&pid);
        active
            && self
                .profiles
                .iter()
                .find(|profile| profile.id == pid)
                .is_some_and(|profile| form.changes_dial_parameters(profile))
    }

    // ---- Profile store writes ---------------------------------

    /// Stamp a new profile operation for `id` and return its generation.
    ///
    /// `password_pending` / `tunnel_pending` name the credential slots this
    /// operation actually dispatched an op for. Every later terminal carries
    /// the returned generation and is admitted by
    /// [`Self::settle_secret_slot`], so an operation the user has superseded
    /// cannot reach committed state and a slot this operation never touched
    /// cannot be settled on its behalf.
    pub(crate) fn begin_profile_op(
        &mut self,
        id: Uuid,
        password_pending: bool,
        tunnel_pending: bool,
    ) -> u64 {
        self.profile_op_generation = self.profile_op_generation.wrapping_add(1);
        let generation = self.profile_op_generation;
        self.profile_ops.insert(
            id,
            ProfileOp {
                generation,
                password_pending,
                tunnel_pending,
            },
        );
        generation
    }

    /// Admit one credential terminal, marking its slot settled.
    ///
    /// `false` means the terminal may not touch anything: it was superseded, its slot
    /// already settled (a replay), or this operation never dispatched that slot.
    /// Settlement is per slot so the connection and jump-host passwords settle
    /// independently. A profile with no recorded operation is admitted.
    pub(crate) fn settle_secret_slot(
        &mut self,
        id: Uuid,
        generation: u64,
        slot: SecretSlot,
    ) -> bool {
        let Some(op) = self.profile_ops.get_mut(&id) else {
            return true;
        };
        if op.generation != generation {
            return false;
        }
        let pending = match slot {
            SecretSlot::Password => &mut op.password_pending,
            SecretSlot::Tunnel => &mut op.tunnel_pending,
        };
        if !*pending {
            return false;
        }
        *pending = false;
        true
    }

    /// Write one profile row, translating a refusal at the typed boundary.
    ///
    /// The raw `rusqlite::Error` is consumed here; only the bounded category
    /// leaves. Callers that own a banner of their own (the transfer banner)
    /// take the category; the rest go through [`Self::settle_profile_write`].
    pub(crate) fn write_profile_row(
        &self,
        profile: &ConnectionProfile,
    ) -> Result<(), crate::error_boundary::DbWriteFailure> {
        self.db
            .upsert(profile)
            .map_err(|err| crate::error_boundary::DbWriteFailure::classify(&err))
    }

    /// Write one profile row and report whether the store accepted it,
    /// raising the sidebar notice when it did not.
    ///
    /// `false` means nothing reached disk: the caller must leave committed
    /// state — the profile list, the selection, the open dialog — exactly as
    /// it was, so the screen keeps showing the user's own unsaved change
    /// instead of a row the next launch cannot find.
    pub(crate) fn settle_profile_write(&mut self, profile: &ConnectionProfile) -> bool {
        match self.write_profile_row(profile) {
            Ok(()) => true,
            Err(cause) => {
                let name = crate::display::bound_display_name(&profile.name);
                self.credential_notice = Some(CredentialNotice::write_refused(
                    cause,
                    crate::error_boundary::DbWriteOperation::Save,
                    &name,
                ));
                false
            }
        }
    }

    /// Publish one slot's durable secret marker after the credential store has
    /// answered for it, and report whether the row write landed.
    ///
    /// The only place a marker moves, and only after a credential terminal. `stored`
    /// is what the keyring confirmed. On a refused row write the in-memory marker is
    /// left `false` in either direction, since neither outcome can back the claim;
    /// the caller discloses the disagreement.
    pub(crate) fn publish_secret_marker(
        &mut self,
        id: Uuid,
        slot: SecretSlot,
        stored: bool,
    ) -> Result<(), crate::error_boundary::DbWriteFailure> {
        let Some(profile) = self.profiles.iter_mut().find(|p| p.id == id) else {
            return Ok(());
        };
        crate::main_helpers::set_secret_marker(profile, slot, stored);
        let snapshot = profile.clone();
        match self.write_profile_row(&snapshot) {
            Ok(()) => Ok(()),
            Err(cause) => {
                if let Some(profile) = self.profiles.iter_mut().find(|p| p.id == id) {
                    crate::main_helpers::set_secret_marker(profile, slot, false);
                }
                Err(cause)
            }
        }
    }

    /// Report a marker publication the profile store refused, naming which of
    /// the two disagreements it left behind.
    pub(crate) fn disclose_marker_refusal(
        &mut self,
        id: Uuid,
        cause: crate::error_boundary::DbWriteFailure,
        op: crate::error_boundary::DbWriteOperation,
    ) {
        if let Some(request) = self.pending_save_connects.get_mut(&id) {
            request.failed = true;
        }
        let name = self
            .profiles
            .iter()
            .find(|p| p.id == id)
            .map(|p| crate::display::bound_display_name(&p.name))
            .unwrap_or_default();
        self.credential_notice = Some(CredentialNotice::write_refused(cause, op, &name));
    }

    /// Remove one profile row and report whether the store accepted it,
    /// raising the sidebar notice when it did not.
    pub(crate) fn settle_profile_delete(&mut self, id: Uuid, name: &str) -> bool {
        match self.db.delete(id) {
            // A zero row count is an accepted delete of a row that was
            // already gone, which is the same durable end state.
            Ok(_) => true,
            Err(err) => {
                let cause = crate::error_boundary::DbWriteFailure::classify(&err);
                self.credential_notice = Some(CredentialNotice::write_refused(
                    cause,
                    crate::error_boundary::DbWriteOperation::Delete,
                    &crate::display::bound_display_name(name),
                ));
                false
            }
        }
    }

    /// Persist the open draft.
    ///
    /// Validates first via `ConnectionForm::can_save` (shared with the Save button),
    /// so a rejected save touches nothing
    /// (`form_tests::an_invalid_draft_writes_nothing_anywhere`). Then it writes the
    /// row, dispatches the credential ops, and moves committed state; nothing after
    /// the write runs unless the store accepted the row.
    pub(crate) fn save_form(&mut self) -> Task<Message> {
        let Some(form) = self.form.as_ref() else {
            return Task::none();
        };
        if !form.can_save() {
            // Deliberately inert rather than partially applied. The Save button
            // is disabled in this state; this is the belt for a routed
            // activation that reaches the message anyway.
            return Task::none();
        }

        let reset_connection = self.form_disconnects_session(form);

        // Which profile is being written: the edited one, or a fresh one.
        let mut profile = match form.editing {
            Some(id) => match self.profiles.iter().find(|p| p.id == id) {
                Some(p) => p.clone(),
                // The profile disappeared under us. Saving would silently
                // resurrect a deleted row, so decline.
                None => return Task::none(),
            },
            None => ConnectionProfile::new("", form.protocol, ""),
        };
        if !form.apply_to(&mut profile) {
            return Task::none();
        }

        // The secret never goes through `profile` or `db.upsert`; markers move only in
        // `CredentialSaveResult` after the async store op.
        let id = profile.id;
        let connect_on_save = form.connect_on_save;
        let expected_password = profile.has_keyring_password;
        let expected_tunnel = profile
            .ssh_tunnel
            .as_ref()
            .is_some_and(|tunnel| tunnel.has_tunnel_password);
        let password_outcome = form.password_outcome();
        let tunnel_outcome = form.tunnel_password_outcome();

        // A pending store claims nothing and a pending clear withdraws nothing; see
        // `main_helpers::hold_pending_secret_markers`.
        let stored = self.profiles.iter().find(|p| p.id == id);
        let password_before = stored.is_some_and(|p| p.has_keyring_password);
        let tunnel_before = stored
            .and_then(|p| p.ssh_tunnel.as_ref())
            .is_some_and(|tunnel| tunnel.has_tunnel_password);
        crate::main_helpers::hold_pending_secret_markers(
            &mut profile,
            &password_outcome,
            password_before,
            &tunnel_outcome,
            tunnel_before,
        );

        // The row lands first. On refusal the draft, dialog and list stay untouched with
        // a notice, Save is the retry, and no keyring secret is left for a missing
        // profile.
        if !self.settle_profile_write(&profile) {
            return Task::none();
        }

        // Credential ops share one generation with per-slot tracking, so superseded or
        // duplicate terminals cannot publish a marker.
        let generation = self.begin_profile_op(
            id,
            !matches!(password_outcome, PasswordOutcome::Unchanged),
            !matches!(tunnel_outcome, PasswordOutcome::Unchanged),
        );

        if connect_on_save {
            self.pending_save_connects.insert(
                id,
                crate::app_state::SavedConnectionRequest {
                    generation,
                    password: expected_password,
                    tunnel_password: expected_tunnel,
                    failed: false,
                },
            );
        }

        let mut tasks: Vec<Task<Message>> = Vec::new();
        if let Some(task) =
            self.credential_task(id, generation, SecretSlot::Password, &password_outcome)
        {
            tasks.push(task);
        }
        // The jump host's secret uses its own key
        // (`keyring::key_for_password_and_tunnel_are_distinct`) so the two secrets never
        // overwrite each other. `Cleared` also covers removing the jump host, so no
        // orphaned secret remains.
        if let Some(task) =
            self.credential_task(id, generation, SecretSlot::Tunnel, &tunnel_outcome)
        {
            tasks.push(task);
        }

        match self.profiles.iter_mut().find(|p| p.id == id) {
            Some(existing) => *existing = profile,
            None => self.profiles.push(profile),
        }
        if reset_connection {
            self.abandon_connect(id);
            self.apply_session_event(id, SessionEvent::Disconnect);
        }
        self.reconnect.cancel(id);
        self.selected_profile = Some(id);
        tasks.push(self.dismiss_form_focus(enzui_iced_core::modal::DismissCause::DefaultAction));
        Task::batch(tasks)
    }

    /// Build the async credential op a save implies for one secret slot, or
    /// `None` when the outcome is `Unchanged`.
    ///
    /// Driven through [`iced::Task::future`] and routed to
    /// [`Message::CredentialSaveResult`] under `generation`. An unlock prompt can
    /// resolve long after this returns, so a newer save may supersede it.
    fn credential_task(
        &self,
        id: Uuid,
        generation: u64,
        slot: SecretSlot,
        outcome: &PasswordOutcome,
    ) -> Option<Task<Message>> {
        let key = match slot {
            SecretSlot::Password => profile_password_key(id),
            SecretSlot::Tunnel => tunnel_password_key(id),
        };
        let (op, intent) = match outcome {
            PasswordOutcome::Unchanged => return None,
            PasswordOutcome::Set(secret) => (
                self.credentials
                    .set(key, Secret::from_string(secret.clone())),
                SaveIntent::Store,
            ),
            PasswordOutcome::Cleared => (self.credentials.delete(key), SaveIntent::Clear),
        };
        Some(Task::future(op).map(move |o| {
            Message::CredentialSaveResult(id, generation, slot, intent, CredResult::from_outcome(o))
        }))
    }
}
