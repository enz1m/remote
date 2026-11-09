use std::path::{Path, PathBuf};

use enzui_iced_core::atomic_state::{self, StateLoad, StateLock, StateRefusal};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::model::ConnectionProfile;
use crate::protocol::ProtocolError;

#[derive(Serialize, Deserialize)]
pub(super) struct Identity {
    pub client_certificate: String,
    pub client_private_key: String,
    pub server_certificate: String,
}
impl Drop for Identity {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.client_private_key);
    }
}

#[derive(Serialize, Deserialize)]
struct Cache {
    attempt: Uuid,
    endpoint: String,
    completed_pair_request: Option<String>,
    identity: Option<Identity>,
}

pub(super) struct Reservation {
    path: PathBuf,
    attempt: Uuid,
    endpoint: String,
    pair_request: Option<String>,
    pub identity: Option<Identity>,
}

fn error() -> ProtocolError {
    ProtocolError::Refused(
        "The private Moonlight pairing identity could not be accessed safely.".into(),
    )
}
fn path(id: Uuid) -> Result<PathBuf, ProtocolError> {
    atomic_state::xdg_state_path("enzui-remote", format!("moonlight-{id}.identity"))
        .map_err(|_| error())?
        .ok_or_else(error)
}
fn endpoint(profile: &ConnectionProfile) -> String {
    format!(
        "{}:{}",
        crate::quick_connect::canonical_host(&profile.host),
        crate::quick_connect::effective_port(profile.port, profile.protocol)
    )
}
fn lock(path: &Path) -> Result<StateLock, ProtocolError> {
    StateLock::try_acquire(path)
        .map_err(|_| error())?
        .ok_or_else(error)
}
fn load(path: &Path) -> Result<Option<Cache>, ProtocolError> {
    let (loaded, reason) =
        atomic_state::load_bounded(path, "remote-moonlight-identity", 1, 32 * 1024);
    match loaded {
        StateLoad::Loaded(body) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if std::fs::symlink_metadata(path)
                    .map_err(|_| error())?
                    .permissions()
                    .mode()
                    & 0o077
                    != 0
                {
                    return Err(error());
                }
            }
            let body = zeroize::Zeroizing::new(body);
            serde_json::from_str(&body).map(Some).map_err(|_| error())
        }
        StateLoad::UsedDefaults { .. } if reason == Some(StateRefusal::Absent) => Ok(None),
        _ => Err(error()),
    }
}
fn save(path: &Path, cache: &Cache) -> Result<(), ProtocolError> {
    let body = zeroize::Zeroizing::new(serde_json::to_string(cache).map_err(|_| error())?);
    atomic_state::save_atomic(path, "remote-moonlight-identity", 1, &body).map_err(|_| error())
}

impl Reservation {
    pub(super) fn begin(profile: &ConnectionProfile) -> Result<Self, ProtocolError> {
        Self::at(
            path(profile.id)?,
            endpoint(profile),
            profile.extra.get(super::PAIR_REQUEST).cloned(),
        )
    }
    fn at(
        path: PathBuf,
        endpoint: String,
        pair_request: Option<String>,
    ) -> Result<Self, ProtocolError> {
        let _guard = lock(&path)?;
        let mut cache = load(&path)?.unwrap_or_else(|| Cache {
            attempt: Uuid::new_v4(),
            endpoint: endpoint.clone(),
            completed_pair_request: None,
            identity: None,
        });
        let reuse = cache.endpoint == endpoint
            && pair_request
                .as_ref()
                .is_none_or(|request| cache.completed_pair_request.as_ref() == Some(request));
        let attempt = Uuid::new_v4();
        cache.attempt = attempt;
        save(&path, &cache)?;
        Ok(Self {
            path,
            attempt,
            endpoint,
            pair_request,
            identity: if reuse { cache.identity.take() } else { None },
        })
    }
    pub(super) fn publish(
        &self,
        identity: Identity,
        control: &crate::desktop_worker::Control,
    ) -> Result<(), ProtocolError> {
        let _guard = lock(&self.path)?;
        let current = load(&self.path)?.ok_or_else(error)?;
        if current.attempt != self.attempt
            || control.cancelled.load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(ProtocolError::Refused(
                "The Moonlight pairing result was retired before it could be saved.".into(),
            ));
        }
        save(
            &self.path,
            &Cache {
                attempt: self.attempt,
                endpoint: self.endpoint.clone(),
                completed_pair_request: self.pair_request.clone(),
                identity: Some(identity),
            },
        )
    }
}

pub(crate) fn forget(id: Uuid) -> Result<(), ProtocolError> {
    forget_at(&path(id)?)
}
fn forget_at(path: &Path) -> Result<(), ProtocolError> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(error()),
        Ok(_) => {}
    }
    let _guard = lock(path)?;
    let _ = load(path)?;
    // The nonsecret fence prevents a retired pairing worker from recreating deleted credentials.
    save(
        path,
        &Cache {
            attempt: Uuid::new_v4(),
            endpoint: String::new(),
            completed_pair_request: None,
            identity: None,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::desktop_worker::Control;
    use std::sync::{Mutex, atomic::AtomicBool};

    fn identity() -> Identity {
        Identity {
            client_certificate: "client".into(),
            client_private_key: "private".into(),
            server_certificate: "server".into(),
        }
    }
    fn control() -> Control {
        let (events, _) = crate::protocol::SessionStream::channel();
        Control {
            route: std::sync::Mutex::new(None),
            cancelled: AtomicBool::new(false),
            input_failed: AtomicBool::new(false),
            active: AtomicBool::new(false),
            input_capture: std::sync::Arc::new(AtomicBool::new(false)),
            clipboard: crate::native_clipboard::Clipboard::new(false),
            requested_size: std::sync::atomic::AtomicU64::new(0),
            dynamic_resize: std::sync::atomic::AtomicBool::new(false),
            resize_available: std::sync::atomic::AtomicBool::new(false),
            socket: Mutex::new(None),
            events,
        }
    }
    #[test]
    fn stale_pairing_and_deleted_profiles_cannot_recreate_private_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity");
        let old = Reservation::at(path.clone(), "host:1".into(), None).unwrap();
        let current = Reservation::at(path.clone(), "host:1".into(), None).unwrap();
        assert!(old.publish(identity(), &control()).is_err());
        current.publish(identity(), &control()).unwrap();
        let reuse = Reservation::at(path.clone(), "host:1".into(), None).unwrap();
        assert!(reuse.identity.is_some());
        forget_at(&path).unwrap();
        assert!(reuse.publish(identity(), &control()).is_err());
        assert!(load(&path).unwrap().unwrap().identity.is_none());
    }
    #[test]
    fn failed_repair_preserves_previous_identity_and_private_file_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity");
        Reservation::at(path.clone(), "host:1".into(), None)
            .unwrap()
            .publish(identity(), &control())
            .unwrap();
        let repair = Reservation::at(path.clone(), "host:1".into(), Some("repair".into())).unwrap();
        assert!(repair.identity.is_none());
        drop(repair);
        assert!(
            Reservation::at(path.clone(), "host:1".into(), None)
                .unwrap()
                .identity
                .is_some()
        );
        assert!(
            Reservation::at(path.clone(), "other:1".into(), None)
                .unwrap()
                .identity
                .is_none()
        );
        use std::os::unix::fs::{PermissionsExt, symlink};
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&path).is_err());
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(load(&link).is_err());
    }
}
