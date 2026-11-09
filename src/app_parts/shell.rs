//! App view, theme, and subscription.

use super::*;

impl App {
    pub(crate) fn sync_fullscreen(&mut self) -> Task<Message> {
        let desired = self.selected_profile.is_some_and(|pid| {
            self.sessions
                .iter()
                .any(|s| s.profile_id == pid && s.fullscreen)
        });
        if self.native_fullscreen == desired {
            return Task::none();
        }
        let Some(window) = self.main_window else {
            return Task::none();
        };
        self.native_fullscreen = desired;
        iced::window::set_mode(
            window,
            if desired {
                iced::window::Mode::Fullscreen
            } else {
                iced::window::Mode::Windowed
            },
        )
    }

    pub(crate) fn view(&self) -> Element<'_, Message> {
        enzui_iced_widgets::exclusive_focus::exclusive_focus(
            self.transfer_picker.view(view::shell(self)),
        )
        .into()
    }

    pub(crate) fn theme(&self) -> Theme {
        // No I/O here: XDG loads and OS bootstraps were folded into `self.themes` via
        // `Message::Theme` before this frame's view.
        self.themes.iced_theme()
    }

    /// Without the center feature there is nothing to subscribe to.
    #[cfg(not(feature = "center"))]
    pub(crate) fn center_subscription(&self) -> Subscription<Message> {
        Subscription::none()
    }

    pub(crate) fn subscription(&self) -> Subscription<Message> {
        // Whether a decoded traversal runs is the reducer's decision (`modal_open`);
        // gating here would rebuild an unchanged recipe hash.
        let events = iced::event::listen_with(classify_event);

        // Capture the initial runtime id for policy-bearing titlebar commands.
        let main_window_opened = iced::event::listen_with(classify_main_window_opened);

        // The compositor's close gesture, named by window. The runtime is
        // built with `exit_on_close_request(false)`, so this reaches the
        // reducer with the window still alive.
        let close_requests = iced::event::listen_with(classify_close_request);

        // The retry wake for connections that are still closing.
        let close_wake = if self.wants_close_wake() {
            iced::time::every(CLOSE_TICK).map(|_| Message::ConnectionCloseTick)
        } else {
            Subscription::none()
        };

        // One deadline for the whole library, the earliest armed reconnect; its wake
        // collects every due profile. `Subscription::none()` when nothing waits. Keyed on
        // profile and policy generation so a cancelled schedule cannot keep its recipe.
        let reconnect_wake = match self.reconnect.armed() {
            Some(armed) => iced::time::every(armed.wait)
                .with((armed.profile_id, armed.generation))
                .map(|((profile_id, generation), _)| {
                    Message::ReconnectTick(profile_id, generation, std::time::Instant::now())
                }),
            None => Subscription::none(),
        };

        // The shared XDG theme host's subscription (bounded watcher +
        // OS appearance feed). Dropping it stops live theme edits and OS mode
        // changes.
        let theme_sub = self
            .themes
            .subscription()
            .map(|event| Message::Theme(Box::new(event)));

        // Wakes once per portal event, and is `Subscription::none()` with no chooser
        // open.
        let transfer_wake = self
            .transfer_picker
            .completion_subscription()
            .map(|_| Message::TransferPortalTick);
        // Always subscribed so an AccessKit request can wake an idle app to drain its
        // queued actions.
        let a11y_wake =
            enzui_iced_core::app_runtime::accessibility_wake_subscription(Message::A11yWake);
        // The earliest toast deadline, or nothing while no toast is showing.
        let toast_wake = match self.toast_schedule.armed() {
            Some((deadline, wait)) => iced::time::every(wait).with(deadline).map(|(_, now)| {
                Message::Toast(enzui_iced_widgets::toast_host::ToastEvent::Tick(now))
            }),
            None => Subscription::none(),
        };
        Subscription::batch([
            self.instance.subscription(|_| Message::InstanceWake),
            events,
            toast_wake,
            main_window_opened,
            close_requests,
            close_wake,
            reconnect_wake,
            transfer_wake,
            theme_sub,
            a11y_wake,
            self.center_subscription(),
        ])
    }
}
