//! Profile-owned OpenSSH TCP routes. Logical hostnames remain unchanged for TLS.
mod invocation;
mod refusal;
use crate::{
    model::{ConnectionProfile, Protocol, SshAuth},
    protocol::ProtocolError,
};
use invocation::{
    HostEnvironment, SshInvocation, canonical_routing_host, is_safe_routing_username,
};
use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    os::fd::OwnedFd,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

pub(crate) const SETUP_TIMEOUT: Duration = Duration::from_secs(22);

fn refused(message: &str) -> ProtocolError {
    ProtocolError::Refused(message.into())
}
fn io_error(error: ProtocolError) -> io::Error {
    io::Error::other(error.to_string())
}

#[derive(Clone, Debug)]
struct Config {
    executable: std::path::PathBuf,
    env: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    host: String,
    port: u16,
    user: String,
    control: std::path::PathBuf,
}
impl Config {
    fn slave(&self, host: &str, port: u16) -> Result<Command, ProtocolError> {
        let host = canonical_routing_host(host)
            .ok_or_else(|| refused("The SSH forward destination is invalid."))?;
        if port == 0 {
            return Err(refused("The SSH forward destination port is invalid."));
        }
        let mut c = Command::new(&self.executable);
        c.env_clear().envs(self.env.iter().cloned());
        // A missing master must fail, never create an unowned replacement connection.
        c.args(["-F", "/dev/null", "-T", "-S"])
            .arg(&self.control)
            .args([
                "-o",
                "ControlMaster=no",
                "-o",
                "ProxyCommand=false",
                "-o",
                "BatchMode=yes",
                "-W",
            ])
            .arg(format!("{host}:{port}"))
            .args(["-p", &self.port.to_string()]);
        if !self.user.is_empty() {
            c.args(["-l", &self.user]);
        }
        c.arg(&self.host).stderr(Stdio::null());
        Ok(c)
    }
}

type Channels = Arc<Mutex<Vec<Child>>>;
fn forward(
    config: &Config,
    channels: &Channels,
    peer: TcpStream,
    host: &str,
    port: u16,
) -> Result<(), ProtocolError> {
    let mut children = channels
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    children.retain_mut(|child| !matches!(child.try_wait(), Ok(Some(_))));
    if children.len() >= 32 {
        return Err(refused("The SSH tunnel has too many active channels."));
    }
    let input = peer
        .try_clone()
        .map_err(|_| refused("The SSH channel could not open."))?;
    let child = config
        .slave(host, port)?
        .stdin(Stdio::from(OwnedFd::from(input)))
        .stdout(Stdio::from(OwnedFd::from(peer)))
        .spawn()
        .map_err(|_| refused("The SSH forward could not start."))?;
    children.push(child);
    Ok(())
}

fn accepts_connect(header: &[u8], host: &str, port: u16, authorization: &str) -> bool {
    if header.len() > 8192 || !header.ends_with(b"\r\n\r\n") {
        return false;
    }
    let Ok(text) = std::str::from_utf8(header) else {
        return false;
    };
    let mut words = text
        .lines()
        .next()
        .unwrap_or_default()
        .split_ascii_whitespace();
    let authorized = text.lines().skip(1).any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("Proxy-Authorization") && value.trim() == authorization
        })
    });
    authorized
        && words.next() == Some("CONNECT")
        && words
            .next()
            .is_some_and(|authority| authority.eq_ignore_ascii_case(&format!("{host}:{port}")))
        && matches!(words.next(), Some("HTTP/1.0" | "HTTP/1.1"))
        && words.next().is_none()
}

pub(crate) struct Route {
    config: Config,
    master: Mutex<Child>,
    channels: Channels,
    stopped: Arc<AtomicBool>,
    proxy: Mutex<Option<(String, JoinHandle<()>)>>,
    _directory: tempfile::TempDir,
}
impl std::fmt::Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SshRoute")
    }
}
impl Route {
    pub fn prepare(
        profile: &ConnectionProfile,
        cancelled: &AtomicBool,
    ) -> Result<Option<Arc<Self>>, ProtocolError> {
        if cancelled.load(Ordering::SeqCst) {
            return Err(refused("The SSH tunnel was cancelled."));
        }
        let Some(hop) = &profile.ssh_tunnel else {
            if profile.port_forward_rules.iter().any(|r| r.enabled) {
                return Err(refused(
                    "Choose an SSH tunnel host before enabling forwarding rules.",
                ));
            }
            return Ok(None);
        };
        if profile.protocol == Protocol::Moonlight {
            return Err(refused(
                "Moonlight requires UDP. Use a VPN; ordinary SSH TCP forwarding cannot route its stream.",
            ));
        }
        if !matches!(
            profile.protocol,
            Protocol::Vnc | Protocol::Rdp | Protocol::Spice | Protocol::RustDesk
        ) {
            return Err(refused("This protocol does not support SSH TCP routing."));
        }
        if matches!(hop.auth, SshAuth::Password) || hop.has_tunnel_password {
            return Err(refused(
                "SSH tunnels use your SSH agent or an identity file. Remove the saved tunnel password before connecting.",
            ));
        }
        let host = canonical_routing_host(&hop.host)
            .ok_or_else(|| refused("The SSH tunnel host is invalid."))?;
        if !hop.username.is_empty() && !is_safe_routing_username(&hop.username) {
            return Err(refused("The SSH tunnel username is invalid."));
        }
        let mut target =
            ConnectionProfile::new("SSH route", Protocol::Ssh, host.trim_matches(['[', ']']));
        target.port = if hop.port == 0 { 22 } else { hop.port };
        target.username = hop.username.clone();
        target.port_forward_rules = profile.port_forward_rules.clone();
        let invocation=SshInvocation::for_profile(&target,false,&HostEnvironment::from_process()).map_err(|_|refused("The SSH tunnel or forwarding rules are invalid. Check the host, user, ports and OpenSSH installation."))?;
        let directory = tempfile::Builder::new()
            .prefix("remote-ssh-")
            .tempdir()
            .map_err(|_| refused("The private SSH control directory could not be created."))?;
        let control = directory.path().join("control");
        if control.as_os_str().len() > 100 {
            return Err(refused(
                "The temporary directory path is too long for an SSH control socket.",
            ));
        }
        let config = Config {
            executable: invocation.executable().into(),
            env: invocation.env().to_vec(),
            host: target.host.clone(),
            port: target.port,
            user: target.username.clone(),
            control,
        };
        let mut command = Command::new(invocation.executable());
        let args = invocation.args();
        let mut base = Vec::new();
        let mut forwards = Vec::new();
        let mut arguments = args[..args.len() - 1].iter();
        while let Some(argument) = arguments.next() {
            if matches!(argument.as_str(), "-L" | "-R" | "-D") {
                let specification = arguments
                    .next()
                    .ok_or_else(|| refused("The SSH forwarding rule is incomplete."))?;
                forwards.push((argument.clone(), specification.clone()));
            } else {
                base.push(argument.clone());
            }
        }
        command
            .env_clear()
            .envs(invocation.env().iter().cloned())
            .args(base);
        if let SshAuth::PrivateKey { path } = &hop.auth {
            if !std::path::Path::new(path).is_absolute()
                || !std::path::Path::new(path).is_file()
                || std::fs::File::open(path).is_err()
                || path.len() > 4096
                || path.chars().any(char::is_control)
            {
                return Err(refused(
                    "The SSH identity must name an existing absolute file path.",
                ));
            }
            command.args(["-i", path, "-o", "IdentitiesOnly=yes"]);
        }
        let master = command
            .args(["-M", "-N", "-S"])
            .arg(&config.control)
            .args([
                "-o",
                "ControlPersist=no",
                "-o",
                "ServerAliveInterval=5",
                "-o",
                "ServerAliveCountMax=2",
            ])
            .arg(&config.host)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| refused("OpenSSH could not start the tunnel."))?;
        let route = Arc::new(Self {
            config,
            master: Mutex::new(master),
            channels: Arc::new(Mutex::new(Vec::new())),
            stopped: Arc::new(AtomicBool::new(false)),
            proxy: Mutex::new(None),
            _directory: directory,
        });
        let deadline = Instant::now() + SETUP_TIMEOUT;
        loop {
            if cancelled.load(Ordering::SeqCst) {
                return Err(refused("The SSH tunnel was cancelled."));
            }
            if route
                .master
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .try_wait()
                .map_err(|_| refused("The SSH tunnel state could not be read."))?
                .is_some()
            {
                return Err(refused(
                    "SSH authentication, host-key verification or forwarding failed. Verify the tunnel host in Terminal and check the selected key or agent.",
                ));
            }
            if route.config.control.exists() {
                break;
            }
            if Instant::now() >= deadline {
                return Err(refused("The SSH tunnel exceeded its connection deadline."));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        // Mux forwarding requests return only after the listener is confirmed,
        // including the server response for -R. A rejected rule cannot look connected.
        for (flag, specification) in forwards {
            let mut setup = Command::new(&route.config.executable);
            setup
                .env_clear()
                .envs(route.config.env.iter().cloned())
                .args(["-F", "/dev/null", "-S"])
                .arg(&route.config.control)
                .args(["-o", "ClearAllForwardings=no", "-O", "forward"])
                .arg(flag)
                .arg(specification)
                .args(["-p", &route.config.port.to_string()]);
            if !route.config.user.is_empty() {
                setup.args(["-l", &route.config.user]);
            }
            let mut child = setup
                .arg(&route.config.host)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| refused("The SSH forwarding rule could not start."))?;
            loop {
                if cancelled.load(Ordering::SeqCst) || Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(refused(
                        "The SSH forwarding setup was cancelled or timed out.",
                    ));
                }
                match child.try_wait() {
                    Ok(Some(status)) if status.success() => break,
                    Ok(Some(_)) => {
                        return Err(refused(
                            "An SSH forwarding rule was refused. Check its listening address and port, and the server's forwarding policy.",
                        ));
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                    Err(_) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(refused("The SSH forwarding setup failed."));
                    }
                }
            }
        }
        Ok(Some(route))
    }
    pub fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        if self.stopped.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let client = TcpStream::connect(listener.local_addr()?)?;
        let (peer, _) = listener.accept()?;
        client.set_nodelay(true)?;
        forward(&self.config, &self.channels, peer, host, port).map_err(io_error)?;
        Ok(client)
    }
    /// SPICE's native HTTP CONNECT proxy preserves the original TLS hostname.
    pub fn spice_proxy(&self, host: &str, port: u16) -> Result<String, ProtocolError> {
        let mut proxy = self
            .proxy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((address, _)) = &*proxy {
            return Ok(address.clone());
        }
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .map_err(|_| refused("The local SPICE route could not open."))?;
        listener
            .set_nonblocking(true)
            .map_err(|_| refused("The SPICE route could not initialize."))?;
        use base64::Engine;
        let token = uuid::Uuid::new_v4().simple().to_string();
        let authorization = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("remote:{token}"))
        );
        let address = format!(
            "http://remote:{token}@{}",
            listener
                .local_addr()
                .map_err(|_| refused("The SPICE route has no address."))?
        );
        let config = self.config.clone();
        let children = self.channels.clone();
        let stopped = self.stopped.clone();
        let target = canonical_routing_host(host)
            .ok_or_else(|| refused("The SPICE tunnel destination is invalid."))?;
        let worker = std::thread::Builder::new()
            .name("remote-spice-route".into())
            .spawn(move || {
                while !stopped.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut peer, _)) => {
                            let _ = peer.set_read_timeout(Some(Duration::from_millis(200)));
                            let mut header = Vec::new();
                            let mut byte = [0];
                            let deadline = Instant::now() + Duration::from_secs(1);
                            while header.len() < 8192
                                && !header.ends_with(b"\r\n\r\n")
                                && Instant::now() < deadline
                                && !stopped.load(Ordering::SeqCst)
                            {
                                if peer.read_exact(&mut byte).is_err() {
                                    break;
                                }
                                header.push(byte[0]);
                            }
                            if !accepts_connect(&header, &target, port, &authorization)
                                || stopped.load(Ordering::SeqCst)
                            {
                                let _ = peer.write_all(b"HTTP/1.0 403 Forbidden\r\n\r\n");
                                continue;
                            }
                            let _ = peer.set_read_timeout(None);
                            if peer
                                .write_all(b"HTTP/1.0 200 Connection established\r\n\r\n")
                                .is_ok()
                            {
                                let _ = forward(&config, &children, peer, &target, port);
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(10))
                        }
                        Err(_) => break,
                    }
                }
            })
            .map_err(|_| refused("The SPICE SSH route could not start."))?;
        *proxy = Some((address.clone(), worker));
        Ok(address)
    }
}
impl Drop for Route {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some((_, worker)) = self
            .proxy
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = worker.join();
        }
        for child in self
            .channels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter_mut()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
        let master = self
            .master
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = master.kill();
        let _ = master.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SshTunnel;
    #[test]
    fn routes_reject_unsafe_hosts_password_fallback_and_cancelled_admission() {
        let mut p = ConnectionProfile::new("route", Protocol::Rdp, "localhost");
        for host in [
            "-oProxyCommand=evil",
            "user@host",
            "host;touch /tmp/x",
            "host%h",
            "host/name",
            "bad\nhost",
        ] {
            p.ssh_tunnel = Some(SshTunnel {
                host: host.into(),
                port: 22,
                username: "user".into(),
                auth: SshAuth::Agent,
                has_tunnel_password: false,
            });
            assert!(
                Route::prepare(&p, &AtomicBool::new(false)).is_err(),
                "{host}"
            );
        }
        let hop = p.ssh_tunnel.as_mut().unwrap();
        hop.host = "localhost".into();
        hop.auth = SshAuth::Password;
        assert!(Route::prepare(&p, &AtomicBool::new(false)).is_err());
        p.ssh_tunnel.as_mut().unwrap().auth = SshAuth::Agent;
        assert!(Route::prepare(&p, &AtomicBool::new(true)).is_err());
        p.protocol = Protocol::Moonlight;
        assert!(Route::prepare(&p, &AtomicBool::new(false)).is_err());
    }
    #[test]
    fn spice_proxy_accepts_only_its_exact_destination_and_bounded_connect_headers() {
        assert!(accepts_connect(
            b"CONNECT Example.COM:5930 HTTP/1.1\r\nHost: Example.COM:5930\r\nProxy-Authorization: Basic test-token\r\n\r\n",
            "example.com",
            5930,
            "Basic test-token"
        ));
        for header in [
            b"CONNECT other:5930 HTTP/1.1\r\n\r\n".as_slice(),
            b"GET example.com:5930 HTTP/1.1\r\n\r\n",
            b"CONNECT example.com:22 HTTP/1.1\r\n\r\n",
            b"CONNECT example.com:5930 HTTP/1.1 extra\r\n\r\n",
            b"CONNECT example.com:5930 HTTP/1.1\r\n",
        ] {
            assert!(!accepts_connect(
                header,
                "example.com",
                5930,
                "Basic test-token"
            ));
        }
        assert!(!accepts_connect(
            b"CONNECT example.com:5930 HTTP/1.1\r\n\r\n",
            "example.com",
            5930,
            "Basic test-token"
        ));
        let mut oversized = b"CONNECT example.com:5930 HTTP/1.1\r\n".to_vec();
        oversized.extend(vec![b'x'; 8192]);
        oversized.extend_from_slice(b"\r\n\r\n");
        assert!(!accepts_connect(
            &oversized,
            "example.com",
            5930,
            "Basic test-token"
        ));
    }
    #[test]
    fn cancelled_tunnel_startup_reaps_ssh_and_never_admits_a_desktop() {
        use crate::model::SshTunnel;
        use crate::protocol::BackendRegistry;
        if invocation::resolve_executable("ssh", std::env::var_os("PATH").as_deref()).is_none() {
            return;
        }
        for protocol in [Protocol::Vnc, Protocol::Rdp] {
            let server = TcpListener::bind("127.0.0.1:0").unwrap();
            server.set_nonblocking(true).unwrap();
            let mut p = ConnectionProfile::new("cancelled route", protocol, "127.0.0.1");
            p.port = 9;
            p.username = "reviewer".into();
            p.ssh_tunnel = Some(SshTunnel {
                host: "127.0.0.1".into(),
                port: server.local_addr().unwrap().port(),
                username: "reviewer".into(),
                auth: SshAuth::Agent,
                has_tunnel_password: false,
            });
            let registry = BackendRegistry::production();
            let backend = registry.get(protocol).unwrap();
            let copied = p.clone();
            let dial = std::thread::spawn(move || backend.connect(&copied, None).is_err());
            let deadline = Instant::now() + Duration::from_secs(4);
            let mut socket = loop {
                match server.accept() {
                    Ok((socket, _)) => break socket,
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    other => panic!("SSH did not reach startup: {other:?}"),
                }
            };
            let start = Instant::now();
            registry.retire_vnc_session(p.id);
            registry.retire_desktop_session(p.id);
            assert!(dial.join().unwrap());
            assert!(start.elapsed() < Duration::from_secs(2));
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut bytes = [0; 256];
            loop {
                match socket.read(&mut bytes) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                        ) =>
                    {
                        break;
                    }
                    other => panic!("cancelled SSH process retained its socket: {other:?}"),
                }
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            while (registry.vnc_close_debt() != 0 || !registry.desktop_closing().is_empty())
                && Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(registry.vnc_close_debt(), 0);
            assert!(registry.desktop_closing().is_empty());
        }
    }
    #[test]
    fn editing_tunnel_identity_replaces_legacy_password_auth_without_inventing_a_secret() {
        let mut profile = ConnectionProfile::new("route", Protocol::Rdp, "localhost");
        profile.username = "reviewer".into();
        profile.ssh_tunnel = Some(SshTunnel {
            host: "gateway.example".into(),
            port: 22,
            username: "reviewer".into(),
            auth: SshAuth::Password,
            has_tunnel_password: false,
        });
        let mut form = crate::form::ConnectionForm::for_profile(&profile);
        assert!(form.tunnel_legacy_password);
        form.tunnel_identity = "/tmp/selected-key".into();
        form.tunnel_password_dirty = true;
        assert!(form.apply_to(&mut profile));
        assert!(
            matches!(&profile.ssh_tunnel.as_ref().unwrap().auth,SshAuth::PrivateKey{path} if path=="/tmp/selected-key")
        );
        assert!(!profile.ssh_tunnel.as_ref().unwrap().has_tunnel_password);
        let mut form = crate::form::ConnectionForm::for_profile(&profile);
        form.tunnel_identity.clear();
        form.tunnel_password_dirty = true;
        assert!(form.apply_to(&mut profile));
        assert_eq!(profile.ssh_tunnel.as_ref().unwrap().auth, SshAuth::Agent);
        assert!(
            serde_json::to_value(&profile)
                .unwrap()
                .get("route")
                .is_none()
        );
    }
}
