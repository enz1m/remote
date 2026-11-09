//! Reducer arms batch 2: browser progress through form quality.

use super::*;

impl App {
    pub(crate) fn reduce2_clipboard_to_session_46(
        &mut self,
        pid: Uuid,
        result: Result<std::sync::Arc<String>, iced::clipboard::Error>,
    ) -> Task<Message> {
        match result {
            Ok(text) => self.deliver_clipboard_to_session(pid, &text),
            Err(_) => {
                // A clipboard the compositor refuses to read is not a
                // delivery. Say so on the session rather than leaving
                // the press looking successful.
                if let Some(s) = self.sessions.iter_mut().find(|s| s.profile_id == pid) {
                    s.last_message = "Cannot read the clipboard.".into();
                }
            }
        }

        Task::none()
    }

    pub(crate) fn reduce2_focus_next_47(&mut self) -> Task<Message> {
        // Modal hosts run their own wrapping traversal for the same key, so a
        // second unscoped one here would advance twice and could reach controls
        // behind the scrim.
        if self.modal_open() {
            return Task::none();
        }
        operate(traversal_operation::<Message>(Traversal::Next))
    }

    pub(crate) fn reduce2_focus_previous_48(&mut self) -> Task<Message> {
        if self.modal_open() {
            return Task::none();
        }
        operate(traversal_operation::<Message>(Traversal::Previous))
    }

    pub(crate) fn reduce2_form_open_add_49(&mut self) -> Task<Message> {
        self.form = Some(ConnectionForm::for_add());
        // Opening the dialog dismisses the drawer: on the mobile rung
        // the drawer and the dialog would otherwise stack two scrims.
        self.nav.dismiss_overlay();

        Task::none()
    }

    pub(crate) fn reduce2_form_open_edit_50(&mut self, id: Uuid) -> Task<Message> {
        // Only a profile that exists can be edited. A stale id (a row
        // deleted between render and click) is inert rather than
        // opening a blank "edit" form that would save a new profile.
        if let Some(p) = self.profiles.iter().find(|p| p.id == id) {
            self.form = Some(ConnectionForm::for_profile(p));
            self.selected_profile = Some(id);
            self.nav.dismiss_overlay();
        }

        Task::none()
    }

    pub(crate) fn reduce2_form_name_changed_51(&mut self, v: String) -> Task<Message> {
        if let Some(f) = self.form.as_mut() {
            f.name = v;
        }

        Task::none()
    }

    pub(crate) fn reduce2_form_host_changed_52(&mut self, v: String) -> Task<Message> {
        if let Some(f) = self.form.as_mut() {
            f.host = v;
        }

        Task::none()
    }

    pub(crate) fn reduce2_form_port_changed_53(&mut self, v: String) -> Task<Message> {
        if let Some(f) = self.form.as_mut() {
            // Stored verbatim, including "" and "0", so typed text is never discarded.
            f.port = v;
            f.port_touched = true;
        }

        Task::none()
    }

    pub(crate) fn reduce2_form_protocol_picked_54(
        &mut self,
        protocol: crate::model::Protocol,
    ) -> Task<Message> {
        // Refuse a protocol the picker does not offer. A routed accessibility
        // activation or replay can still reach this arm; substituting the first
        // available protocol would discard a stored protocol on edit.
        if !self.backends.available(protocol) {
            return Task::none();
        }
        if let Some(f) = self.form.as_mut() {
            f.pick_protocol(protocol);
        }

        Task::none()
    }

    pub(crate) fn reduce2_form_username_changed_55(&mut self, v: String) -> Task<Message> {
        if let Some(f) = self.form.as_mut() {
            f.username = v;
        }

        Task::none()
    }

    pub(crate) fn reduce2_form_password_changed_56(&mut self, v: String) -> Task<Message> {
        if let Some(f) = self.form.as_mut() {
            f.password = v;
            // `dirty` is what separates "left the stored secret alone"
            // from "deliberately emptied it". Set on any edit,
            // including one that empties the field.
            f.password_dirty = true;
        }

        Task::none()
    }

    pub(crate) fn reduce2_form_password_reveal_toggled_57(&mut self) -> Task<Message> {
        if let Some(f) = self.form.as_mut() {
            f.password_revealed = !f.password_revealed;
        }

        Task::none()
    }

    pub(crate) fn reduce2_form_wol_mac_changed_59(&mut self, v: String) -> Task<Message> {
        if let Some(f) = self.form.as_mut() {
            // Verbatim, like the port text. Canonicalising here would
            // rewrite the field under the caret on every keystroke.
            f.wol_mac = v;
        }

        Task::none()
    }

    pub(crate) fn reduce2_form_disable_clipboard_toggled_60(&mut self, on: bool) -> Task<Message> {
        if let Some(f) = self.form.as_mut() {
            f.disable_clipboard = on;
        }

        Task::none()
    }

    pub(crate) fn reduce2_form_plaintext_ack_toggled_61(&mut self, on: bool) -> Task<Message> {
        if let Some(f) = self.form.as_mut() {
            f.set_plaintext_ack(on);
        }

        Task::none()
    }

    pub(crate) fn reduce2_form_reconnect_toggled_62(&mut self, on: bool) -> Task<Message> {
        if let Some(f) = self.form.as_mut() {
            f.reconnect_enabled = on;
        }

        Task::none()
    }

    pub(crate) fn reduce2_form_reconnect_attempts_changed_63(
        &mut self,
        text: String,
    ) -> Task<Message> {
        if let Some(f) = self.form.as_mut() {
            f.reconnect_attempts = text;
        }

        Task::none()
    }

    pub(crate) fn reduce2_form_reconnect_ceiling_changed_64(
        &mut self,
        text: String,
    ) -> Task<Message> {
        if let Some(f) = self.form.as_mut() {
            f.reconnect_ceiling = text;
        }

        Task::none()
    }

    pub(crate) fn reduce2_form_save_65(&mut self) -> Task<Message> {
        self.save_form()
    }

    pub(crate) fn reduce2_form_cancel_66(&mut self) -> Task<Message> {
        // Drop the draft and let the owner restore the exact add/edit
        // invoker captured when this showing opened.
        self.dismiss_form_focus(enzui_iced_core::modal::DismissCause::CancelAction)
    }

    pub(crate) fn reduce2_form_delete_67(&mut self) -> Task<Message> {
        // The form's Delete button asks for confirmation.
        if let Some(id) = self.form.as_ref().and_then(|f| f.editing) {
            self.pending_delete_profile = Some(id);
            self.delete_without_credentials_warning = false;
        }

        Task::none()
    }

    pub(crate) fn reduce2_request_delete_profile_68(&mut self, id: Uuid) -> Task<Message> {
        self.pending_delete_profile = Some(id);
        self.delete_without_credentials_warning = false;

        Task::none()
    }

    pub(crate) fn reduce2_delete_profile_confirm_event_69(
        &mut self,
        event: enzui_iced_widgets::confirm_dialog::ConfirmDialogEvent,
    ) -> Task<Message> {
        use enzui_iced_widgets::confirm_dialog::ConfirmDialogEvent;
        let Some(id) = self.pending_delete_profile else {
            return Task::none();
        };
        match event {
            // One exit for the buttons, Escape and the scrim, mapped
            // to meaning in exactly one place.
            ConfirmDialogEvent::Resolved(cause) => {
                let acknowledged_unavailable = self.delete_without_credentials_warning;
                self.pending_delete_profile = None;
                self.delete_without_credentials_warning = false;
                if enzui_iced_core::confirm::ConfirmDecision::from_cause(cause).is_confirmed() {
                    // A second confirmation after `Unavailable` acknowledges the secret could
                    // not be checked or removed; commit rather than loop.
                    if acknowledged_unavailable {
                        return self.commit_profile_delete(id, true);
                    }
                    return self.update(Message::DeleteProfile(id));
                }
            }
            ConfirmDialogEvent::FocusNext | ConfirmDialogEvent::FocusPrevious => {
                if let Some(op) = event.focus_operation::<Message>(true) {
                    return iced::advanced::widget::operate(op);
                }
            }
            ConfirmDialogEvent::CheckboxToggled(_) => {}
        }

        Task::none()
    }

    pub(crate) fn reduce2_form_modal_event_70(
        &mut self,
        event: enzui_iced_widgets::modal_host::ModalHostEvent,
    ) -> Task<Message> {
        self.reduce_form_host(event)
    }

    pub(crate) fn reduce2_rule_added_71(&mut self) -> Task<Message> {
        if let Some(f) = self.form.as_mut() {
            f.rules.push(crate::form::RuleDraft::new_local());
        }

        Task::none()
    }

    pub(crate) fn reduce2_rule_removed_72(&mut self, id: Uuid) -> Task<Message> {
        if let Some(f) = self.form.as_mut() {
            f.rules.retain(|r| r.id != id);
        }

        Task::none()
    }

    pub(crate) fn reduce2_rule_type_picked_73(&mut self, id: Uuid, index: usize) -> Task<Message> {
        if let Some(r) = self.rule_mut(id) {
            r.forward_type = crate::form_view::forward_type_from_index(index);
        }

        Task::none()
    }

    pub(crate) fn reduce2_rule_bind_address_changed_74(
        &mut self,
        id: Uuid,
        v: String,
    ) -> Task<Message> {
        if let Some(r) = self.rule_mut(id) {
            // Stored as typed: empty is the default loopback
            // listener, not a wildcard.
            r.bind_address = v;
        }

        Task::none()
    }

    pub(crate) fn reduce2_rule_bind_port_changed_75(
        &mut self,
        id: Uuid,
        v: String,
    ) -> Task<Message> {
        if let Some(r) = self.rule_mut(id) {
            r.bind_port = v;
        }

        Task::none()
    }

    pub(crate) fn reduce2_rule_dest_host_changed_76(
        &mut self,
        id: Uuid,
        v: String,
    ) -> Task<Message> {
        if let Some(r) = self.rule_mut(id) {
            r.dest_host = v;
        }

        Task::none()
    }

    pub(crate) fn reduce2_rule_dest_port_changed_77(
        &mut self,
        id: Uuid,
        v: String,
    ) -> Task<Message> {
        if let Some(r) = self.rule_mut(id) {
            r.dest_port = v;
        }

        Task::none()
    }

    pub(crate) fn reduce2_rule_enabled_toggled_78(&mut self, id: Uuid, on: bool) -> Task<Message> {
        if let Some(r) = self.rule_mut(id) {
            r.enabled = on;
        }

        Task::none()
    }

    pub(crate) fn reduce2_form_quality_picked_79(&mut self, index: usize) -> Task<Message> {
        if let Some(f) = self.form.as_mut() {
            f.pick_quality(index);
        }

        Task::none()
    }
}
