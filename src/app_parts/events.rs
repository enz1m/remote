//! Session events and frame delivery.

use super::*;

impl App {
    /// Apply one `SessionEvent` to a profile's session, if it has one.
    ///
    /// Records no Quick Connect history. Only
    /// [`Self::apply_session_event_admitting`] can, and only a caller holding
    /// a generation-matched dispatch record can supply what it needs.
    pub(crate) fn apply_session_event(&mut self, pid: Uuid, event: SessionEvent) {
        let _ = self.apply_session_event_admitting(pid, event, None);
    }

    /// [`Self::apply_session_event`], with what to credit if this event
    /// completes a connection.
    ///
    /// `admits` is `Some` only for a `Ready` under the generation of the
    /// profile's current dispatch, carrying that dispatch's identity and this
    /// settlement's wall-clock reading; the recent row is built only on the
    /// accepted edge. Returns whether a history row was admitted, since only
    /// that caller may commit the paired durable record.
    pub(crate) fn apply_session_event_admitting(
        &mut self,
        pid: Uuid,
        event: SessionEvent,
        admits: Option<(&crate::model::DialIdentity, chrono::DateTime<chrono::Utc>)>,
    ) -> bool {
        let mut next_status = None;
        let mut previous = None;
        if let Some(session) = self.sessions.iter_mut().find(|s| s.profile_id == pid)
            && let Ok((next, msg)) = transition(session.status, &event)
        {
            previous = Some(session.status);
            session.status = next;
            next_status = Some(next);
            if let Some(m) = msg {
                session.last_message = m;
            }
        }

        if previous == Some(SessionStatus::Connecting)
            && next_status == Some(SessionStatus::Connected)
            && let Some(session) = self.sessions.iter().find(|s| s.profile_id == pid)
            && let Some(warning) =
                crate::session_view::plaintext_disclosure(&session.profile_snapshot)
        {
            self.toasts.push(
                enzui_iced_widgets::toast_host::ToastSpec::new(warning)
                    .tone(enzui_iced_widgets::toast::ToastTone::Warning)
                    .coalesce_key(format!("connection-security-{pid}"))
                    .duration(std::time::Duration::from_secs(10)),
            );
        }

        // Quick Connect history is admitted on the `Connecting -> Connected` edge,
        // produced only from `Ready`, which excludes an idempotent reconnect; the
        // capture fixture sets `Connected` directly and bypasses this.
        let mut admitted = false;
        if previous == Some(SessionStatus::Connecting)
            && next_status == Some(SessionStatus::Connected)
            && let Some((identity, at)) = admits
        {
            admitted = self.admit_recent_pending(identity.recent_at(at));
        }

        // Retire the picture and input route with the status, so no frame or press
        // outlives its connection.
        if next_status.is_some_and(|status| status != SessionStatus::Connected) {
            self.retire_session_surface(pid);
        }
        admitted
    }

    pub(crate) fn seed_capture_frame(&mut self, pid: Uuid) -> Task<Message> {
        const W: u32 = 1280;
        const H: u32 = 720;
        // Opaque, nonuniform pixels distinguish a captured frame from the theme backdrop.
        let mut pixels = Vec::with_capacity(W as usize * H as usize * 4);
        for y in 0..H {
            for x in 0..W {
                let pixel = if x % 160 < 2 || y % 90 < 2 {
                    [236, 240, 244, 255]
                } else if (x / 160 + y / 90).is_multiple_of(2) {
                    [35, 112, 164, 255]
                } else {
                    [45, 144, 102, 255]
                };
                pixels.extend_from_slice(&pixel);
            }
        }
        self.open_session_stream(pid);
        self.accept_frame(pid, W, H, crate::framebuffer::FrameBytes::new(pixels))
    }

    /// Sever a session's transports, free what its surface owns, and stop
    /// accepting for it.
    ///
    /// Every departure from `SessionStatus::Connected`, a deleted profile and a
    /// window close take this route. Dropping the
    /// [`enzui_iced_core::media::BoundedFrameSink`] frees up to
    /// `crate::framebuffer::MAX_RETAINED_BYTES` immediately. The polling task
    /// cannot be cancelled (a wedged backend may never drop its sender), so the
    /// stream generation is forgotten and its later events match nothing.
    pub(crate) fn retire_session_surface(&mut self, pid: Uuid) {
        // The VNC socket carries the screen and keystrokes in the clear, so it is
        // severed on this single route. Nothing here waits on a worker thread.
        self.backends.retire_vnc_session(pid);
        self.backends.retire_desktop_session(pid);
        // The debt this just created is visible in the same frame, and the
        // retry wake is armed by it.
        self.refresh_close_notices();
        self.frames.remove(&pid);
        if let Some(presentation) = self.frame_presenters.get_mut(&pid) {
            presentation.native.clear();
        }
        if !self.profiles.iter().any(|profile| profile.id == pid) {
            self.frame_presenters.remove(&pid);
        }
        self.held_keys.remove(&pid);
        self.held_buttons.remove(&pid);
        self.surface_slots.remove(&pid);
        self.requested_sizes.remove(&pid);
        self.session_streams.remove(&pid);
        // A reconnect's first press waits for its own move rather than reusing a
        // coordinate from the previous framebuffer.
        self.pointer_at.remove(&pid);
        if let Some(session) = self.sessions.iter_mut().find(|s| s.profile_id == pid) {
            session.surface_size = (0, 0);
        }
    }

    /// Stamp a newly opened stream and give it a fresh frame sink.
    ///
    /// Returns the generation the polling task must carry back; the previous
    /// task's generation no longer matches.
    pub(crate) fn open_session_stream(&mut self, pid: Uuid) -> u64 {
        self.session_generation = self.session_generation.wrapping_add(1);
        let generation = self.session_generation;
        self.session_streams.insert(pid, generation);
        // A fresh generation, so the sink refuses the previous stream's buffers.
        self.frame_generation = self.frame_generation.next();
        self.frames.insert(
            pid,
            enzui_iced_core::media::BoundedFrameSink::new(self.frame_generation),
        );
        let presentation = self.frame_presenters.entry(pid).or_insert_with(|| {
            crate::app_state::FramePresentation {
                instance: generation,
                native: enzui_iced_widgets::video::LatestFramePresenter::new(),
            }
        });
        presentation.native.clear();
        self.requested_sizes.remove(&pid);
        self.pointer_at.remove(&pid);
        if let Some(session) = self.sessions.iter_mut().find(|s| s.profile_id == pid) {
            session.surface_size = (0, 0);
        }
        generation
    }

    /// Admit a CPU frame and offer it to the bounded native GPU presenter.
    /// The resident image and pointer geometry remain until allocation completes.
    pub(crate) fn accept_frame(
        &mut self,
        pid: Uuid,
        width: u32,
        height: u32,
        pixels: crate::framebuffer::FrameBytes,
    ) -> Task<Message> {
        if self.session_status_for(pid) != SessionStatus::Connected {
            return Task::none();
        }
        let Some(sink) = self.frames.get_mut(&pid) else {
            return Task::none();
        };
        let seq = next_frame_seq(sink);
        let stamp = sink.generation();
        let frame = match crate::framebuffer::admit(stamp, seq, width, height, pixels) {
            Ok(frame) => frame,
            Err(refusal) => {
                if let Some(session) = self.sessions.iter_mut().find(|s| s.profile_id == pid) {
                    session.last_message = refusal.summary().to_string();
                }
                return Task::none();
            }
        };
        let retained = matches!(
            sink.deliver(frame),
            enzui_iced_core::media::Delivery::Retained
                | enzui_iced_core::media::Delivery::RetainedFreeingOlder { .. }
        );
        if !retained {
            return Task::none();
        }
        let Some(frame) = sink.present().cloned() else {
            return Task::none();
        };
        let Some(presentation) = self.frame_presenters.get_mut(&pid) else {
            return Task::none();
        };
        let instance = presentation.instance;
        presentation
            .native
            .offer(frame)
            .map_or_else(Task::none, |task| {
                task.map(move |ready| Message::FrameUploaded(pid, instance, ready))
            })
    }

    pub(crate) fn frame_handle(&self, pid: Uuid) -> Option<&iced::widget::image::Handle> {
        self.frame_presenters.get(&pid)?.native.handle()
    }

    pub(crate) fn frame_uploaded(
        &mut self,
        pid: Uuid,
        instance: u64,
        ready: enzui_iced_widgets::video::ReadyFrame,
    ) -> Task<Message> {
        let Some(presentation) = self.frame_presenters.get_mut(&pid) else {
            return Task::none();
        };
        if presentation.instance != instance {
            return Task::none();
        }
        // Retired completions still release native admission and drain a new source.
        let handover = presentation.native.ready(ready);
        if handover.accepted
            && let Some(size) = presentation.native.size()
            && let Some(session) = self
                .sessions
                .iter_mut()
                .find(|session| session.profile_id == pid)
            && session.status == SessionStatus::Connected
        {
            if session.surface_size != size {
                self.pointer_at.remove(&pid);
            }
            session.surface_size = size;
        }
        handover.next_upload.map_or_else(Task::none, |task| {
            task.map(move |ready| Message::FrameUploaded(pid, instance, ready))
        })
    }

    /// Store the surface's laid-out size and ask the backend to match it.
    ///
    /// Best-effort ([`crate::protocol::RemoteProtocol::resize_for`]); sent only on a
    /// change, for a connected session, to this profile's protocol backend.
    pub(crate) fn surface_resized(&mut self, pid: Uuid, size: iced::Size) -> Task<Message> {
        if !size.width.is_finite() || !size.height.is_finite() {
            return Task::none();
        }
        self.surface_slots.insert(pid, size);
        let Some(session) = self
            .sessions
            .iter()
            .find(|session| session.profile_id == pid)
        else {
            return Task::none();
        };
        if session.status != SessionStatus::Connected
            || (matches!(
                session.profile_snapshot.protocol,
                Protocol::Rdp | Protocol::Spice
            ) && (!session.dynamic_resize
                || !session.input_mode.forwards_input()
                || session.negotiated.view_only))
        {
            return Task::none();
        }
        let requested = (size.width.max(0.0) as u32, size.height.max(0.0) as u32);
        if requested.0 == 0 || requested.1 == 0 {
            return Task::none();
        }
        if self.requested_sizes.get(&pid) == Some(&requested) {
            return Task::none();
        }
        let Some(backend) = self.session_backend(pid) else {
            return Task::none();
        };
        if backend.resize_for(pid, requested).is_ok() {
            self.requested_sizes.insert(pid, requested);
        }
        Task::none()
    }

    pub(crate) fn toggle_session_resize(&mut self, pid: Uuid, generation: u64) -> Task<Message> {
        if self.session_streams.get(&pid) != Some(&generation) {
            return Task::none();
        }
        let Some(session) = self.sessions.iter().find(|s| s.profile_id == pid) else {
            return Task::none();
        };
        if session.status != SessionStatus::Connected
            || !matches!(
                session.profile_snapshot.protocol,
                Protocol::Rdp | Protocol::Spice
            )
            || !session.input_mode.forwards_input()
            || session.negotiated.view_only
        {
            return Task::none();
        }
        let enabled = !session.dynamic_resize;
        let Some(backend) = self.session_backend(pid) else {
            return Task::none();
        };
        match backend.set_dynamic_resize_for(pid, enabled) {
            Ok(()) => {
                self.sessions
                    .iter_mut()
                    .find(|s| s.profile_id == pid)
                    .unwrap()
                    .dynamic_resize = enabled;
                self.requested_sizes.remove(&pid);
                if enabled && let Some(size) = self.surface_slots.get(&pid).copied() {
                    return self.surface_resized(pid, size);
                }
            }
            Err(error) => {
                self.toasts.push(
                    enzui_iced_widgets::toast_host::ToastSpec::new(error.to_string())
                        .tone(enzui_iced_widgets::toast::ToastTone::Warning)
                        .coalesce_key(format!("guest-resize-{pid}")),
                );
            }
        }
        Task::none()
    }

    /// The backend serving `pid`'s protocol, if this build registers one.
    ///
    /// Every route that reaches a transport goes through here, so the
    /// availability rule holds for input and resize exactly as it holds for
    /// connect: an unregistered protocol has no backend to hand anything to.
    pub(crate) fn session_backend(
        &self,
        pid: Uuid,
    ) -> Option<std::sync::Arc<dyn crate::protocol::RemoteProtocol>> {
        let profile = self.profiles.iter().find(|p| p.id == pid)?;
        self.backends.get(profile.protocol)
    }

    /// Map a pointer gesture on the surface to a remote pixel and forward it.
    ///
    /// Silently refused unless the session is `Connected` and `Interactive`
    /// (view-only forwards nothing), a frame is displayed in a measured slot, a
    /// move lands on the picture rather than the letterbox, and, for a button, a
    /// prior move established the cursor. `mouse_area` reports no position for
    /// buttons, so the last hovered position is used.
    pub(crate) fn deliver_pointer_to_session(
        &mut self,
        pid: Uuid,
        gesture: crate::session::PointerGesture,
    ) {
        use crate::session::PointerGesture;

        let Some(session) = self.sessions.iter().find(|s| s.profile_id == pid) else {
            return;
        };
        if session.status != SessionStatus::Connected || !session.input_mode.forwards_input() {
            return;
        }
        let scaling = session.scaling;

        let input = match gesture {
            PointerGesture::Moved(at) => {
                let (Some(slot), Some(frame)) = (
                    self.surface_slots.get(&pid).copied(),
                    self.frame_presenters
                        .get(&pid)
                        .and_then(|presentation| presentation.native.size()),
                ) else {
                    return;
                };
                let Some(pixel) = crate::framebuffer::remote_pixel(slot, frame, scaling, at) else {
                    self.pointer_at.remove(&pid);
                    return;
                };
                self.pointer_at.insert(pid, pixel);
                crate::protocol::RemoteInput::PointerMove(pixel.0, pixel.1)
            }
            PointerGesture::Pressed(button) => {
                if !self.pointer_at.contains_key(&pid) {
                    return;
                }
                crate::protocol::RemoteInput::PointerButton {
                    button,
                    pressed: true,
                }
            }
            PointerGesture::Released(button) => {
                if !self
                    .held_buttons
                    .get(&pid)
                    .is_some_and(|buttons| buttons.contains(&button))
                {
                    return;
                }
                crate::protocol::RemoteInput::PointerButton {
                    button,
                    pressed: false,
                }
            }
        };

        let Some(backend) = self.session_backend(pid) else {
            return;
        };
        match backend.send_input_for(pid, input) {
            Ok(()) => match gesture {
                PointerGesture::Pressed(button) => {
                    self.held_buttons.entry(pid).or_default().insert(button);
                }
                PointerGesture::Released(button) => {
                    if let Some(buttons) = self.held_buttons.get_mut(&pid) {
                        buttons.remove(&button);
                    }
                }
                _ => {}
            },
            Err(error) => {
                if let Some(session) = self.sessions.iter_mut().find(|s| s.profile_id == pid) {
                    session.last_message = format!("Input not sent: {error}");
                }
            }
        }
    }
}
