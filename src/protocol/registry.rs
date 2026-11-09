//! Backend registry: which protocols this build can dial.

use super::*;
use std::sync::Arc;

/// Backend registry — the single authority for which protocols this build can
/// dial.
///
/// [`Self::available`] is `self.get(protocol).is_some()`. Every surface that
/// offers a session and the reducer edge that starts one read this, so a
/// protocol cannot be offered in one place and refused in another.
#[derive(Debug, Default)]
pub struct BackendRegistry {
    /// The VNC backend's transport table, when a VNC backend is registered.
    ///
    /// Held at its concrete type for the same reason as [`Self::ssh`]: a
    /// retirement names a profile, and the `RemoteProtocol` trait carries no
    /// session identity, so the only thing that can end one profile's socket
    /// is the backend that owns it.
    vnc: Option<Arc<crate::rfb::backend::RfbBackend>>,
    rdp: Arc<crate::rdp::RdpBackend>,
    spice: Option<Arc<crate::spice::SpiceBackend>>,
    rustdesk: Option<Arc<crate::rustdesk::RustDeskBackend>>,
    moonlight: Option<Arc<crate::moonlight::MoonlightBackend>>,
    slots: Vec<Arc<dyn RemoteProtocol>>,
    /// [`Self::slots`] projected into a protocol picker's options, rebuilt by
    /// [`Self::register`] so it cannot drift from [`Self::available`], and stored
    /// so pickers can borrow it for an element's lifetime.
    choices: Vec<Protocol>,
}

impl BackendRegistry {
    /// The registry a launch installs: one entry per protocol with a real
    /// implementation.
    ///
    /// Registers embedded VNC, RDP, SPICE, RustDesk and Moonlight desktops.
    /// Availability describes the transport, not host capabilities.
    pub fn production() -> Self {
        let mut r = Self::default();
        let vnc = Arc::new(crate::rfb::backend::RfbBackend::new());
        r.register(Arc::clone(&vnc) as Arc<dyn RemoteProtocol>);
        r.vnc = Some(vnc);
        r.register(Arc::clone(&r.rdp) as Arc<dyn RemoteProtocol>);
        let spice = Arc::new(crate::spice::SpiceBackend::default());
        r.register(Arc::clone(&spice) as Arc<dyn RemoteProtocol>);
        r.spice = Some(spice);
        let rustdesk = Arc::new(crate::rustdesk::RustDeskBackend::default());
        r.register(Arc::clone(&rustdesk) as Arc<dyn RemoteProtocol>);
        r.rustdesk = Some(rustdesk);
        let moonlight = Arc::new(crate::moonlight::MoonlightBackend::default());
        r.register(Arc::clone(&moonlight) as Arc<dyn RemoteProtocol>);
        r.moonlight = Some(moonlight);
        r
    }

    pub fn retire_desktop_session(&self, id: uuid::Uuid) {
        self.rdp.retire(id);
        if let Some(moonlight) = &self.moonlight {
            moonlight.retire(id);
        }
        if let Some(rustdesk) = &self.rustdesk {
            rustdesk.retire(id);
        }
        if let Some(spice) = &self.spice {
            spice.retire(id);
        }
    }

    pub fn stop_desktop_admission(&self) {
        self.rdp.stop();
        if let Some(moonlight) = &self.moonlight {
            moonlight.stop();
        }
        if let Some(rustdesk) = &self.rustdesk {
            rustdesk.stop();
        }
        if let Some(spice) = &self.spice {
            spice.stop();
        }
    }

    pub fn resume_desktop_admission(&self) {
        self.rdp.resume();
        if let Some(moonlight) = &self.moonlight {
            moonlight.resume();
        }
        if let Some(rustdesk) = &self.rustdesk {
            rustdesk.resume();
        }
        if let Some(spice) = &self.spice {
            spice.resume();
        }
    }

    pub fn desktop_closing(&self) -> Vec<uuid::Uuid> {
        let mut closing = self.rdp.closing();
        if let Some(spice) = &self.spice {
            closing.extend(spice.closing());
        }
        if let Some(rustdesk) = &self.rustdesk {
            closing.extend(rustdesk.closing());
        }
        if let Some(moonlight) = &self.moonlight {
            closing.extend(moonlight.closing());
        }
        closing.sort_unstable();
        closing.dedup();
        closing
    }

    /// Retire the VNC transport for `profile_id`, reporting whether there was
    /// one.
    ///
    /// Does not wait for a thread: the socket is shut down both ways, and a dial
    /// still opening one closes its own socket. Worker joins are collected by the
    /// next retirement or dial.
    pub fn retire_vnc_session(&self, profile_id: uuid::Uuid) -> bool {
        self.vnc
            .as_ref()
            .is_some_and(|backend| backend.begin_retire(profile_id))
    }

    /// Sever every live VNC transport, reporting the profiles that were
    /// severed. Returns without waiting for a thread.
    pub fn retire_all_vnc_sessions(&self) -> Vec<uuid::Uuid> {
        self.vnc
            .as_ref()
            .map(|backend| backend.retire_all())
            .unwrap_or_default()
    }

    /// Stop opening VNC connections, for an app that is closing.
    pub fn stop_vnc_admission(&self) {
        if let Some(backend) = self.vnc.as_ref() {
            backend.stop_admission();
        }
    }

    /// Ask to open VNC connections again after a close was abandoned.
    ///
    /// Reports whether they are open now. A backend with severed transports
    /// still being joined stays closed until they are gone, so an abandoned
    /// close never leaves a new connection running beside an old owner.
    pub fn resume_vnc_admission(&self) -> bool {
        self.vnc
            .as_ref()
            .is_none_or(|backend| backend.resume_admission())
    }

    /// Collect finished VNC closes and report how many are still outstanding.
    ///
    /// The VNC half of the app's close debt: a window close or a profile
    /// delete that reported settled while one of these was outstanding would
    /// be claiming a reader, a writer and a socket are gone while they are
    /// still running.
    pub fn vnc_close_debt(&self) -> usize {
        self.vnc
            .as_ref()
            .map_or(0, |backend| backend.settle_closes())
    }

    /// Every outstanding VNC close, for the close surface's item list.
    pub fn vnc_close_report(&self) -> Vec<crate::rfb::backend::VncCloseDebt> {
        self.vnc
            .as_ref()
            .map(|backend| backend.close_report())
            .unwrap_or_default()
    }

    /// Whether an outstanding VNC close can still advance on its own, and so
    /// whether the app still needs waking for it.
    pub fn vnc_close_work_pending(&self) -> bool {
        self.vnc
            .as_ref()
            .is_some_and(|backend| backend.close_work_pending())
    }

    /// Whether this profile's VNC transport is still closing, so a scheduled
    /// reconnect would be spent on a refusal.
    pub fn vnc_closing(&self, profile_id: uuid::Uuid) -> bool {
        self.vnc
            .as_ref()
            .is_some_and(|backend| backend.closing(profile_id))
    }

    /// How far this profile's VNC close has got, if it is closing.
    ///
    /// The surface's query. A read with no side effects, so a view may ask it
    /// every frame without collecting a join or starting one.
    pub fn vnc_close_progress(
        &self,
        profile_id: uuid::Uuid,
    ) -> Option<crate::rfb::backend::VncCloseProgress> {
        self.vnc
            .as_ref()
            .and_then(|backend| backend.close_progress(profile_id))
    }

    /// Give VNC closes that ran out of attempts their attempts back, for a
    /// user who asked to try again, and report what is still outstanding.
    pub fn retry_vnc_closes(&self) -> usize {
        self.vnc
            .as_ref()
            .map_or(0, |backend| backend.retry_closes())
    }

    /// How many SSH submissions still occupy a worker or queue slot.
    ///
    /// Zero is the other half of "nothing of this app is still running": a
    /// close with no debt but a worker still holding a channel has not
    /// finished.
    #[must_use]
    pub fn with_stubs() -> Self {
        let mut r = Self::default();
        for &p in Protocol::all() {
            r.register(Arc::new(StubBackend::new(p)));
        }
        r
    }

    /// Whether this build can open a session for `protocol`.
    ///
    /// Surfaces ask before building a Connect control, and `drive_session` asks
    /// again before `Connect`, so a message with no control behind it (an
    /// assistive-technology replay, a stale menu activation) is refused.
    pub fn available(&self, protocol: Protocol) -> bool {
        self.get(protocol).is_some()
    }

    /// The option list a protocol picker offers: one choice per protocol this
    /// build can dial, in [`Protocol::all`] order.
    ///
    /// Undialable protocols are absent, not disabled. A stored profile with such
    /// a protocol still opens its form with no selection, and `form_view` prints
    /// [`NOT_IN_THIS_BUILD`]; the stored value is not rewritten.
    pub fn choices(&self) -> &[Protocol] {
        &self.choices
    }

    pub fn register(&mut self, backend: Arc<dyn RemoteProtocol>) {
        // If there's already a backend for this protocol, replace it.
        let existing = self
            .slots
            .iter()
            .position(|b| b.protocol() == backend.protocol());
        if let Some(i) = existing {
            self.slots[i] = backend;
        } else {
            self.slots.push(backend);
        }
        let choices = Protocol::all()
            .iter()
            .copied()
            .filter(|p| self.slots.iter().any(|b| b.protocol() == *p))
            .collect();
        self.choices = choices;
    }

    pub fn get(&self, protocol: Protocol) -> Option<Arc<dyn RemoteProtocol>> {
        self.slots
            .iter()
            .find(|b| b.protocol() == protocol)
            .cloned()
    }
}

#[cfg(test)]
impl BackendRegistry {}
