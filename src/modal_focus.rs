//! Owned focus for the connection form and Quick Connect hosts.
//!
//! The form and Quick Connect use separate `EnzModalHost`s, and one can hand
//! off to the other (`Enter details…`, `Connect` on a recent). Reconciling
//! both in one post-pass closes the old owner without restoring focus and
//! opens the replacement in the same task, so the recents dialog's invoker is
//! not restored on top of the newly opened form.

use enzui_iced_core::modal::DismissCause;
use enzui_iced_widgets::modal_host::{ModalFocusLifecycle, ModalHostEvent};
use iced::Task;

use crate::{App, Message, form_restore_id};

impl App {
    /// Reconcile both standard hosts with their owners after every turn.
    ///
    /// A model that appeared captures its exact invoker (the per-row Edit
    /// button, the New connection button, the Quick Connect button) and runs
    /// initial focus; a model that vanished retires its owner without
    /// restoring anything, because no user input dismissed it.
    pub(crate) fn sync_standard_modal_focus(&mut self) -> Task<Message> {
        let mut tasks = Vec::new();
        if self.form.is_some() && self.form_focus.is_none() {
            let invoker = form_restore_id(self.form.as_ref());
            let (lifecycle, op) =
                ModalFocusLifecycle::open::<Message>(crate::form_view::FORM_SCOPE_KEY, invoker);
            self.form_focus = Some(lifecycle);
            tasks.push(iced::advanced::widget::operate(op));
        } else if self.form.is_none()
            && let Some(lifecycle) = self.form_focus.take()
        {
            tasks.push(lifecycle.close_for_host::<Message>().into_task());
        }
        if self.quick_connect_open && self.quick_connect_focus.is_none() {
            let (lifecycle, op) = ModalFocusLifecycle::open::<Message>(
                crate::quick_connect_view::QUICK_CONNECT_SCOPE_KEY,
                Some(crate::view::quick_connect_button_id()),
            );
            self.quick_connect_focus = Some(lifecycle);
            tasks.push(iced::advanced::widget::operate(op));
        } else if !self.quick_connect_open
            && let Some(lifecycle) = self.quick_connect_focus.take()
        {
            tasks.push(lifecycle.close_for_host::<Message>().into_task());
        }
        Task::batch(tasks)
    }

    /// A logical form dismissal (Cancel, a committed Save): restore the exact
    /// invoker this showing captured and drop the owner in lockstep.
    pub(crate) fn dismiss_form_focus(&mut self, cause: DismissCause) -> Task<Message> {
        self.form = None;
        self.form_focus.take().map_or_else(Task::none, |lifecycle| {
            lifecycle
                .reduce::<Message>(ModalHostEvent::Dismissed(cause))
                .into_task()
        })
    }

    /// The same for Quick Connect.
    pub(crate) fn dismiss_quick_connect_focus(&mut self, cause: DismissCause) -> Task<Message> {
        self.quick_connect_open = false;
        self.quick_connect_focus
            .take()
            .map_or_else(Task::none, |lifecycle| {
                lifecycle
                    .reduce::<Message>(ModalHostEvent::Dismissed(cause))
                    .into_task()
            })
    }

    /// Reduce a connection-form host event through its owner.
    pub(crate) fn reduce_form_host(&mut self, event: ModalHostEvent) -> Task<Message> {
        let Some(lifecycle) = self.form_focus.as_ref() else {
            return Task::none();
        };
        let outcome = lifecycle.reduce::<Message>(event);
        if outcome.dismissed().is_some() {
            self.form = None;
            self.form_focus = None;
        }
        outcome.into_task()
    }

    /// Reduce a Quick Connect host event through its owner.
    pub(crate) fn reduce_quick_connect_host(&mut self, event: ModalHostEvent) -> Task<Message> {
        let Some(lifecycle) = self.quick_connect_focus.as_ref() else {
            return Task::none();
        };
        let outcome = lifecycle.reduce::<Message>(event);
        if outcome.dismissed().is_some() {
            self.quick_connect_open = false;
            self.quick_connect_focus = None;
        }
        outcome.into_task()
    }

    /// A host-driven form close (the edited profile was deleted underneath it):
    /// the modal is gone but focus stays exactly where it is.
    pub(crate) fn close_form_for_host(&mut self) -> Task<Message> {
        self.form = None;
        self.form_focus.take().map_or_else(Task::none, |lifecycle| {
            lifecycle.close_for_host::<Message>().into_task()
        })
    }
}
