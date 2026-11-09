//! Credential saves and profile deletion.

use super::*;

impl App {
    /// Record a Wake-on-LAN attempt into [`Self::wol_status`],
    /// classifying an untranslated backend string at the typed boundary.
    ///
    /// The only site that constructs a [`WolStatus`]; every raw string is consumed by
    /// [`crate::error_boundary::WolFailure::classify`], so banner readers never see
    /// it.
    pub(crate) fn record_wol_attempt(
        &mut self,
        name: String,
        outcome: Result<String, WolAttemptFailure>,
    ) {
        // A sent packet is a confirmation that needs no answer, so it is a
        // toast; a failure stays in the banner until it is dismissed.
        if let Ok(mac) = &outcome {
            let sent = WolStatus::Sent {
                name: name.clone(),
                mac: mac.clone(),
            };
            self.toasts
                .push(enzui_iced_widgets::toast_host::ToastSpec::new(sent.title()));
            self.wol_status = None;
            return;
        }
        self.wol_status = Some(match outcome {
            Ok(mac) => WolStatus::Sent { name, mac },
            Err(WolAttemptFailure::InvalidMac(mac)) => WolStatus::InvalidMac { name, mac },
            Err(WolAttemptFailure::SendFailed(reason)) => WolStatus::Failed {
                name,
                cause: crate::error_boundary::WolFailure::classify(&reason),
                raw: reason,
            },
        });
    }

    /// A form-save credential op resolved. Publishes the slot's durable secret
    /// marker only when the keyring outcome justifies one, and raises a notice on
    /// genuine failure.
    ///
    /// [`Self::settle_secret_slot`] admits the terminal, so superseded, replayed or
    /// foreign terminals are dropped whole, marker and notice.
    ///
    /// * Only a `Store` that reached [`CredResult::Stored`] raises a marker.
    /// * A failed, refused, unavailable or cancelled `Store` writes nothing; the row
    ///   already claims nothing.
    /// * A `Clear` lowers the marker only once the keyring confirms the secret is
    ///   gone.
    /// * A refused publication leaves the marker down and discloses the
    ///   disagreement.
    pub(crate) fn on_credential_save_result(
        &mut self,
        id: Uuid,
        generation: u64,
        slot: SecretSlot,
        intent: SaveIntent,
        result: CredResult,
    ) {
        if !self.settle_secret_slot(id, generation, slot) {
            return;
        }

        let success = match intent {
            SaveIntent::Store => result.stored_ok(),
            SaveIntent::Clear => matches!(result, CredResult::Deleted | CredResult::NotFound),
        };
        if !success
            && let Some(request) = self.pending_save_connects.get_mut(&id)
            && request.generation == generation
        {
            request.failed = true;
        }

        use crate::error_boundary::DbWriteOperation;
        match (intent, &result) {
            // Only a confirmed store may raise the marker.
            (SaveIntent::Store, outcome) if outcome.stored_ok() => {
                if let Err(cause) = self.publish_secret_marker(id, slot, true) {
                    self.disclose_marker_refusal(id, cause, DbWriteOperation::PublishSecretStored);
                }
                return;
            }
            // Confirmed gone; `NotFound` is the same durable end state.
            (SaveIntent::Clear, CredResult::Deleted | CredResult::NotFound) => {
                if let Err(cause) = self.publish_secret_marker(id, slot, false) {
                    self.disclose_marker_refusal(id, cause, DbWriteOperation::PublishSecretRemoved);
                }
                return;
            }
            _ => {}
        }

        // No marker moves: a pending store left the record claiming nothing, and an
        // unconfirmed clear leaves the claim over a secret the keyring may still hold.
        // Cancellations are silent.
        if result.is_cancellation() {
            return;
        }
        let profile_name = self
            .profiles
            .iter()
            .find(|p| p.id == id)
            .map(|p| crate::display::bound_display_name(&p.name));
        match (intent, &result) {
            (SaveIntent::Store, CredResult::Unavailable) => {
                if let Some(name) = profile_name {
                    self.credential_notice = Some(CredentialNotice::save_unavailable(&name));
                }
            }
            (SaveIntent::Store, CredResult::Denied) => {
                if let Some(name) = profile_name {
                    self.credential_notice = Some(CredentialNotice::save_failed(
                        &name,
                        "the system keyring refused to store the password",
                    ));
                }
            }
            (SaveIntent::Store, CredResult::Failed(reason)) => {
                if let Some(name) = profile_name {
                    // The raw D-Bus/zbus string never reaches the notice; the
                    // classifier maps it to a bounded category body.
                    let cause = crate::error_boundary::KeyringFailure::classify(reason);
                    self.credential_notice = Some(CredentialNotice::save_translated(cause, &name));
                }
            }
            // A clear that could not reach the store leaves the marker raised, correctly,
            // but the user asked for removal, so it is flagged.
            (
                SaveIntent::Clear,
                CredResult::Unavailable | CredResult::Denied | CredResult::Failed(_),
            ) => {
                if let Some(name) = profile_name {
                    self.credential_notice = Some(CredentialNotice::save_failed(
                        &name,
                        "an old stored password could not be removed",
                    ));
                }
            }
            _ => {}
        }
    }

    /// Commit profile removal after its primary secret was deleted/not found,
    /// or after the user explicitly acknowledged an unavailable store.
    ///
    /// The row leaves the store first. A refused delete keeps the profile, sessions
    /// and browser unchanged and re-stages the confirmation with
    /// `acknowledged_unavailable`, so a retry repeats only the failed leg (secret
    /// deletion is idempotent).
    pub(crate) fn commit_profile_delete(
        &mut self,
        id: Uuid,
        acknowledged_unavailable: bool,
    ) -> Task<Message> {
        let name = self
            .profiles
            .iter()
            .find(|profile| profile.id == id)
            .map(|profile| profile.name.clone())
            .unwrap_or_default();
        if crate::moonlight::identity::forget(id).is_err() {
            self.credential_notice = Some(CredentialNotice::save_failed(
                &format!(
                    "{} was not deleted",
                    crate::display::bound_display_name(&name)
                ),
                "the private Moonlight pairing identity could not be removed safely; retry after its pending operation finishes",
            ));
            self.pending_delete_profile = Some(id);
            self.delete_without_credentials_warning = acknowledged_unavailable;
            return Task::none();
        }
        if !self.settle_profile_delete(id, &name) {
            self.pending_delete_profile = Some(id);
            // Retry resumes on the same route; an acknowledged-unavailable delete skips the
            // keyring.
            self.delete_without_credentials_warning = acknowledged_unavailable;
            return Task::none();
        }
        self.profile_ops.remove(&id);
        // A deleted profile has no policy, no schedule and no recency to
        // publish; retiring them here is what makes a deadline armed before
        // the deletion inert.
        self.reconnect.cancel(id);
        self.recency_debt.retain(|debt| debt.profile_id != id);
        self.profiles.retain(|profile| profile.id != id);
        self.sessions.retain(|session| session.profile_id != id);
        // Close the channel too, or an authenticated connection would outlive any
        // surface that could end it.
        self.retire_session_surface(id);
        if self.selected_profile == Some(id) {
            self.selected_profile = self.profiles.first().map(|profile| profile.id);
        }
        if self.form.as_ref().and_then(|form| form.editing) == Some(id) {
            return self.close_form_for_host();
        }
        Task::none()
    }

    // ---- Import / export through the portal chooser --------------
}
