use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

pub(crate) const LIMIT: usize = 256 * 1024;

#[derive(Clone, PartialEq)]
pub struct Text(pub(crate) Arc<String>);

impl std::fmt::Debug for Text {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClipboardText({} bytes)", self.0.len())
    }
}

#[derive(Default)]
struct Local {
    text: Option<zeroize::Zeroizing<String>>,
    pending: bool,
}

pub(crate) struct Clipboard {
    enabled: AtomicBool,
    available: AtomicBool,
    peer_allowed: AtomicBool,
    local: Mutex<Local>,
}

impl std::fmt::Debug for Clipboard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Clipboard").finish_non_exhaustive()
    }
}

impl Clipboard {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            available: AtomicBool::new(false),
            peer_allowed: AtomicBool::new(true),
            local: Mutex::default(),
        }
    }
    pub(crate) fn set_available(&self, available: bool) {
        self.available.store(available, Ordering::SeqCst);
    }
    pub(crate) fn set_peer_allowed(&self, allowed: bool) {
        self.peer_allowed.store(allowed, Ordering::SeqCst);
        if !allowed {
            *self
                .local
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Local::default();
        }
    }
    pub(crate) fn enable(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
        if !enabled {
            *self
                .local
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Local::default();
        }
    }
    pub(crate) fn sharing(&self, capture: &AtomicBool) -> bool {
        self.enabled.load(Ordering::SeqCst)
            && self.available.load(Ordering::SeqCst)
            && self.peer_allowed.load(Ordering::SeqCst)
            && capture.load(Ordering::SeqCst)
    }
    pub(crate) fn queue(&self, capture: &AtomicBool, text: &str) -> Result<(), String> {
        if !self.available.load(Ordering::SeqCst) {
            return Err(
                "The host's native clipboard channel is not ready or is unavailable.".into(),
            );
        }
        if !self.sharing(capture) {
            return Err("Clipboard sharing requires an interactive, captured session with clipboard permission.".into());
        }
        let text = normalize(text)?;
        let mut local = self
            .local
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.sharing(capture) {
            return Err("Clipboard permission was withdrawn.".into());
        }
        local.text = Some(zeroize::Zeroizing::new(text));
        local.pending = true;
        Ok(())
    }
    pub(crate) fn take(&self, capture: &AtomicBool) -> Option<String> {
        let mut local = self
            .local
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.sharing(capture) || !std::mem::take(&mut local.pending) {
            return None;
        }
        local.text.as_deref().map(|s| s.to_string())
    }
    pub(crate) fn snapshot(&self, capture: &AtomicBool) -> Option<String> {
        if !self.sharing(capture) {
            return None;
        }
        self.local
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .text
            .as_deref()
            .map(|s| s.to_string())
    }
}

pub(crate) fn normalize(text: &str) -> Result<String, String> {
    if text.len() > LIMIT || text.contains('\0') {
        return Err("Clipboard text exceeds 256 KiB or contains a null character.".into());
    }
    Ok(text.replace("\r\n", "\n").replace('\r', "\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_text_is_bounded_coalesced_and_revoked_without_payload_debugging() {
        let clipboard = Clipboard::new(true);
        clipboard.set_available(true);
        let capture = AtomicBool::new(true);
        clipboard.queue(&capture, "private\r\n雪").unwrap();
        clipboard.queue(&capture, "newer").unwrap();
        assert_eq!(clipboard.take(&capture).as_deref(), Some("newer"));
        assert!(clipboard.take(&capture).is_none());
        capture.store(false, Ordering::SeqCst);
        assert!(clipboard.snapshot(&capture).is_none());
        assert!(clipboard.queue(&capture, "blocked").is_err());
        capture.store(true, Ordering::SeqCst);
        clipboard.enable(false);
        clipboard.enable(true);
        assert!(clipboard.snapshot(&capture).is_none());
        clipboard.set_peer_allowed(false);
        assert!(clipboard.queue(&capture, "blocked").is_err());
        assert!(normalize(&"x".repeat(LIMIT + 1)).is_err());
        assert!(normalize("a\0b").is_err());
        assert!(!format!("{:?}", Text(Arc::new("private".into()))).contains("private"));
    }
}
