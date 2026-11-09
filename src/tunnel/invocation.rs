//! Validated OpenSSH arguments for a profile-owned TCP tunnel.
//! No user shell command or SSH config is evaluated. Host trust stays with
//! OpenSSH; passwords and interactive prompts are not accepted.

use std::ffi::{OsStr, OsString};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::refusal::SshRefusal;
use crate::model::{
    ConnectionProfile, ForwardDest, ForwardKind, PortForwardRule, Protocol, SshAuth, SshTunnel,
};

/// How long OpenSSH may spend establishing the TCP connection.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// The program name resolved through the executable-authority rule.
pub const SSH_PROGRAM: &str = "ssh";

/// The config file `ssh(1)` is pointed at, which parses to no directives.
///
/// `-F` overrides the per-user file and suppresses the system one, so this is
/// the whole of the config authority: no `HostName` rewrite, no `Match exec`,
/// no `KnownHostsCommand`, no `LocalCommand`, no `ProxyCommand`, no `Include`,
/// and no identity or provider directive.
pub const NO_CONFIG_FILE: &str = "/dev/null";

/// The longest a host or username may be, in bytes, before it is refused.
///
/// The same ceiling the import path admits a stored field under
/// ([`crate::import_source::MAX_IMPORT_FIELD_BYTES`]), applied again here
/// because a profile can also be edited or restored: a value this module
/// cannot have admitted must not become an argument.
pub const MAX_ARGUMENT_BYTES: usize = crate::import_source::MAX_IMPORT_FIELD_BYTES;

/// The longest a jump host, a forward bind address or a forward destination
/// may be, in bytes.
///
/// The ceiling a DNS name has, rather than [`MAX_ARGUMENT_BYTES`]: these
/// appear inside a composed argument whose total is itself bounded by
/// [`MAX_ROUTING_ARGUMENT_BYTES`].
pub const MAX_ROUTING_HOST_BYTES: usize = 255;

/// The most enabled port-forward rules one connection may carry.
///
/// A profile may store more (an import admits
/// [`crate::import_source::MAX_IMPORT_RULES`]); the surplus is refused by
/// name rather than dropped, because a connection short of a forward it
/// promised looks like one that has it.
pub const MAX_FORWARD_RULES: usize = 8;

/// The most bytes the jump host and forward arguments may occupy together.
pub const MAX_ROUTING_ARGUMENT_BYTES: usize = 2048;

/// The environment variables a session's child is allowed to inherit.
///
/// OpenSSH uses the operating-system account’s home for default trust and keys;
/// an inherited `HOME` does not isolate them. `SSH_AUTH_SOCK` selects the agent.
/// Everything else is dropped, and two omissions are load-bearing:
/// `SSH_ASKPASS` and `DISPLAY` are together what would let OpenSSH run a
/// helper program to obtain a secret.
pub const INHERITED_ENVIRONMENT: [&str; 2] = ["HOME", "SSH_AUTH_SOCK"];

/// The outside world an invocation is resolved against.
///
/// Snapshotted once by [`Self::from_process`] at connect time.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostEnvironment {
    /// The `PATH` the `ssh` program is looked up through.
    pub path: Option<OsString>,
    /// The optional `HOME` value forwarded to the child.
    pub home: Option<OsString>,
    /// The SSH agent socket, when one is published.
    pub agent_socket: Option<OsString>,
}

impl HostEnvironment {
    /// Read the three values this module cares about from the process
    /// environment, once.
    #[must_use]
    pub fn from_process() -> Self {
        Self {
            path: std::env::var_os("PATH"),
            home: std::env::var_os("HOME"),
            agent_socket: std::env::var_os("SSH_AUTH_SOCK"),
        }
    }

    /// The allowlisted `(key, value)` pairs this environment contributes.
    ///
    /// The child's environment is cleared before these are applied, so this
    /// is the whole of what it sees.
    #[must_use]
    pub fn inherited(&self) -> Vec<(OsString, OsString)> {
        let candidates: [(&str, Option<&OsString>); INHERITED_ENVIRONMENT.len()] = [
            (INHERITED_ENVIRONMENT[0], self.home.as_ref()),
            (INHERITED_ENVIRONMENT[1], self.agent_socket.as_ref()),
        ];
        let mut pairs = Vec::new();
        for (name, value) in candidates {
            if let Some(value) = value
                && !value.is_empty()
            {
                pairs.push((OsString::from(name), value.clone()));
            }
        }
        pairs
    }
}

/// One fully decided `ssh` execution: which program, which arguments, which
/// environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshInvocation {
    executable: PathBuf,
    args: Vec<String>,
    env: Vec<(OsString, OsString)>,
}

impl SshInvocation {
    /// Decide the invocation for `profile`.
    ///
    /// `password_present` reports whether the reducer resolved a stored secret
    /// for this profile. It is a boolean rather than the secret so this module
    /// cannot place a password anywhere.
    ///
    /// # Errors
    ///
    /// Every refusal is a [`SshRefusal`] decided here, before a process
    /// exists.
    pub fn for_profile(
        profile: &ConnectionProfile,
        password_present: bool,
        host: &HostEnvironment,
    ) -> Result<Self, SshRefusal> {
        if profile.protocol != Protocol::Ssh {
            return Err(SshRefusal::NotSsh(profile.protocol));
        }
        if password_present || profile.has_keyring_password {
            return Err(SshRefusal::PasswordAuthUnsupported);
        }

        let hostname = profile.host.trim();
        if hostname.is_empty() {
            return Err(SshRefusal::MissingHost);
        }
        if !is_safe_positional(hostname) || hostname.len() > MAX_ARGUMENT_BYTES {
            return Err(SshRefusal::UnsafeHost);
        }
        let username = profile.username.trim();
        if !username.is_empty()
            && (!is_safe_positional(username) || username.len() > MAX_ARGUMENT_BYTES)
        {
            return Err(SshRefusal::UnsafeUsername);
        }
        if profile.port == 0 {
            return Err(SshRefusal::InvalidPort);
        }

        let jump = profile
            .ssh_tunnel
            .as_ref()
            .map(|tunnel| jump_specification(tunnel, hostname, profile.port))
            .transpose()?;
        // A jump expands the destination into a shell command, so it must
        // meet the routing rules too. It is still passed as written: the
        // generated command brackets the expansion itself.
        if jump.is_some() && canonical_routing_host(hostname).is_none() {
            return Err(SshRefusal::UnsafeHost);
        }
        let forwards = forward_arguments(&profile.port_forward_rules)?;
        let routing_bytes = jump.as_ref().map_or(0, String::len)
            + forwards
                .iter()
                .map(|forward| forward.flag.len() + forward.spec.len())
                .sum::<usize>();
        if routing_bytes > MAX_ROUTING_ARGUMENT_BYTES {
            return Err(SshRefusal::RoutingArgumentsTooLarge {
                cap: MAX_ROUTING_ARGUMENT_BYTES,
            });
        }

        // Every field is bounded and safe before the filesystem is consulted.
        let executable = resolve_executable(SSH_PROGRAM, host.path.as_deref())
            .ok_or(SshRefusal::ExecutableAuthority)?;

        let mut args: Vec<String> = vec![
            // No config file at all, before anything that a directive could
            // otherwise reinterpret.
            "-F".to_string(),
            NO_CONFIG_FILE.to_string(),
            // No X11 forwarding, no agent forwarding, no pty: each is a
            // channel back towards the local desktop.
            "-x".to_string(),
            "-a".to_string(),
            "-T".to_string(),
        ];
        // The proxy decision is the first option: OpenSSH keeps the first
        // proxy option it reads and ignores every later one, so a
        // `ProxyCommand` ahead of a `ProxyJump` drops the jump host without
        // saying so. `ProxyCommand=none` after it is inert and still denies
        // any other source of one.
        match &jump {
            Some(specification) => push_option(&mut args, format!("ProxyJump={specification}")),
            None => push_option(&mut args, "ProxyJump=none".to_string()),
        }
        for fixed in [
            "ProxyCommand=none",
            "BatchMode=yes",
            "StrictHostKeyChecking=yes",
            "PasswordAuthentication=no",
            "KbdInteractiveAuthentication=no",
            "NumberOfPasswordPrompts=0",
            "PreferredAuthentications=publickey",
            "Compression=no",
            "ExitOnForwardFailure=yes",
            "GatewayPorts=no",
        ] {
            push_option(&mut args, fixed.to_string());
        }
        // Clearing all forwardings would discard the ones below as well.
        push_option(
            &mut args,
            format!(
                "ClearAllForwardings={}",
                if forwards.is_empty() { "yes" } else { "no" }
            ),
        );
        for fixed in ["RequestTTY=no", "LogLevel=ERROR"] {
            push_option(&mut args, fixed.to_string());
        }
        push_option(
            &mut args,
            format!("ConnectTimeout={}", CONNECT_TIMEOUT.as_secs()),
        );
        args.push("-p".to_string());
        args.push(profile.port.to_string());
        if !username.is_empty() {
            args.push("-l".to_string());
            args.push(username.to_string());
        }
        for forward in forwards {
            args.push(forward.flag.to_string());
            args.push(forward.spec);
        }
        // The validated destination is the final positional argument.
        args.push(hostname.to_string());

        Ok(Self {
            executable,
            args,
            env: host.inherited(),
        })
    }

    /// The absolute program this invocation runs.
    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// The arguments, in order, one element per argument.
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// The complete environment the child is given. The child's environment is
    /// cleared first, so this is the whole of it.
    #[must_use]
    pub fn env(&self) -> &[(OsString, OsString)] {
        &self.env
    }
}

fn push_option(args: &mut Vec<String>, value: String) {
    args.push("-o".to_string());
    args.push(value);
}

/// One forward rule as the two arguments `ssh(1)` takes for it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ForwardArgument {
    flag: &'static str,
    spec: String,
}

/// Which side of the connection a forward's listener lives on.
///
/// A dynamic forward listens locally like a `-L`, so the two share a side and
/// can conflict with each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ListenerSide {
    Local,
    Remote,
}

/// The address a forward's listener binds.
#[derive(Clone, Debug, PartialEq, Eq)]
enum BindAddress {
    /// No bind address in the specification, which leaves the listener to
    /// OpenSSH's default under `GatewayPorts=no`: loopback locally, and the
    /// server's own policy for a remote forward.
    Omitted,
    /// An explicit request for every interface, passed through as written.
    Wildcard(String),
    Exact(String),
}

impl BindAddress {
    /// Read a stored bind address, or `None` when it cannot appear in a
    /// forward specification.
    fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value.is_empty() {
            return Some(Self::Omitted);
        }
        if crate::model::is_wildcard_bind_address(value) {
            if value == "*" {
                return Some(Self::Wildcard(value.to_string()));
            }
            return canonical_routing_host(value).map(Self::Wildcard);
        }
        canonical_routing_host(value).map(Self::Exact)
    }

    /// The address as it appears in a forward specification, or `None` when
    /// the specification carries no bind field.
    fn spec(&self) -> Option<&str> {
        match self {
            Self::Omitted => None,
            Self::Wildcard(address) | Self::Exact(address) => Some(address),
        }
    }

    /// The set of addresses a listener on this one would occupy, on the side
    /// that opens it.
    fn scope(&self, side: ListenerSide) -> ListenerScope {
        match self {
            // A remote listener's address is the server's decision under its
            // own `GatewayPorts`, so an omitted one may be anything up to
            // every interface and claims the whole port.
            Self::Omitted if side == ListenerSide::Remote => ListenerScope::Everything,
            // Locally it is loopback, and OpenSSH may open both loopback
            // families for it, so it claims that whole scope.
            Self::Omitted => ListenerScope::Loopback,
            Self::Wildcard(_) => ListenerScope::Everything,
            Self::Exact(address) if is_loopback_address(address) => ListenerScope::Loopback,
            Self::Exact(address) => ListenerScope::Address(address.to_ascii_lowercase()),
        }
    }
}

/// What a listener occupies on its port, for deciding conflicts.
///
/// Loopback is one scope rather than one address per family: an omitted local
/// bind address may open both, and refusing an overlap this app cannot rule
/// out is better than a connection that ends on the second listener. This is
/// a conflict judgement, not user-facing copy — the user reads the rule's own
/// summary, which never calls a remote listener loopback.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ListenerScope {
    Loopback,
    Everything,
    Address(String),
}

impl ListenerScope {
    fn collides_with(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Everything, _) | (_, Self::Everything) => true,
            (Self::Loopback, Self::Loopback) => true,
            (Self::Address(left), Self::Address(right)) => left == right,
            _ => false,
        }
    }
}

/// Whether a canonical routing host names this machine's loopback.
fn is_loopback_address(canonical: &str) -> bool {
    if canonical.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Some(literal) = canonical
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return literal
            .parse::<Ipv6Addr>()
            .is_ok_and(|address| address.is_loopback());
    }
    canonical
        .parse::<Ipv4Addr>()
        .is_ok_and(|address| address.is_loopback())
}

/// One listener an enabled rule would claim.
struct Listener {
    side: ListenerSide,
    scope: ListenerScope,
    port: u16,
}

/// The `ProxyJump` value for `tunnel`, or the refusal that stops the dial.
///
/// `destination` and `destination_port` are what the session itself dials, so
/// a jump host that is the destination is refused instead of routing the
/// connection through itself.
fn jump_specification(
    tunnel: &SshTunnel,
    destination: &str,
    destination_port: u16,
) -> Result<String, SshRefusal> {
    // No secret and no key path can reach the jump hop, so a jump that needs
    // either is refused rather than connected with whatever OpenSSH finds.
    if tunnel.has_tunnel_password || matches!(tunnel.auth, SshAuth::Password) {
        return Err(SshRefusal::JumpSecretUnsupported);
    }
    if matches!(tunnel.auth, SshAuth::PrivateKey { .. }) {
        return Err(SshRefusal::JumpIdentityUnsupported);
    }
    if tunnel.host.trim().is_empty() {
        return Err(SshRefusal::MissingJumpHost);
    }
    let host = canonical_routing_host(&tunnel.host).ok_or(SshRefusal::UnsafeJumpHost)?;
    if tunnel.port == 0 {
        return Err(SshRefusal::InvalidJumpPort);
    }
    let username = tunnel.username.trim();
    if !username.is_empty() && !is_safe_routing_username(username) {
        return Err(SshRefusal::UnsafeJumpUsername);
    }
    if tunnel.port == destination_port
        && canonical_routing_host(destination)
            .is_some_and(|dialled| dialled.eq_ignore_ascii_case(&host))
    {
        return Err(SshRefusal::JumpIsDestination);
    }

    let mut specification = String::new();
    if !username.is_empty() {
        specification.push_str(username);
        specification.push('@');
    }
    specification.push_str(&host);
    specification.push(':');
    specification.push_str(&tunnel.port.to_string());
    Ok(specification)
}

/// The forward arguments for every enabled rule, in the profile's own order.
///
/// A disabled rule contributes nothing. Conflicts are decided here because
/// under `ExitOnForwardFailure=yes` the loser of a race for one listener ends
/// the whole connection.
fn forward_arguments(rules: &[PortForwardRule]) -> Result<Vec<ForwardArgument>, SshRefusal> {
    let enabled: Vec<(usize, &PortForwardRule)> = rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| rule.enabled)
        .collect();
    if enabled.len() > MAX_FORWARD_RULES {
        return Err(SshRefusal::TooManyForwards {
            cap: MAX_FORWARD_RULES,
        });
    }

    let mut listeners: Vec<Listener> = Vec::new();
    let mut arguments = Vec::new();
    for (index, rule) in enabled {
        let position = index + 1;
        if rule.bind_port == 0 {
            return Err(SshRefusal::InvalidForwardPort { rule: position });
        }
        let address = BindAddress::parse(&rule.bind_address)
            .ok_or(SshRefusal::UnsafeForwardBindAddress { rule: position })?;
        let (side, flag, spec) = match &rule.kind {
            ForwardKind::Local(destination) => (
                ListenerSide::Local,
                "-L",
                forward_spec(&address, rule.bind_port, destination, position)?,
            ),
            ForwardKind::Remote(destination) => (
                ListenerSide::Remote,
                "-R",
                forward_spec(&address, rule.bind_port, destination, position)?,
            ),
            ForwardKind::Dynamic => (
                ListenerSide::Local,
                "-D",
                match address.spec() {
                    Some(bind) => format!("{bind}:{}", rule.bind_port),
                    None => rule.bind_port.to_string(),
                },
            ),
        };
        let scope = address.scope(side);
        if listeners.iter().any(|listener| {
            listener.side == side
                && listener.port == rule.bind_port
                && listener.scope.collides_with(&scope)
        }) {
            return Err(SshRefusal::ForwardListenerConflict { rule: position });
        }
        listeners.push(Listener {
            side,
            scope,
            port: rule.bind_port,
        });
        arguments.push(ForwardArgument { flag, spec });
    }
    Ok(arguments)
}

/// The `[bind:]port:host:port` specification a local or remote rule encodes
/// to, without the bind field when the rule asks for no bind address.
fn forward_spec(
    address: &BindAddress,
    bind_port: u16,
    destination: &ForwardDest,
    position: usize,
) -> Result<String, SshRefusal> {
    if destination.port == 0 {
        return Err(SshRefusal::InvalidForwardPort { rule: position });
    }
    let host = canonical_routing_host(&destination.host)
        .ok_or(SshRefusal::UnsafeForwardDestination { rule: position })?;
    Ok(match address.spec() {
        Some(bind) => format!("{bind}:{bind_port}:{host}:{}", destination.port),
        None => format!("{bind_port}:{host}:{}", destination.port),
    })
}

/// The canonical spelling of a host inside a forward specification or a
/// `ProxyJump`, or `None` when it has none.
///
/// An IPv6 literal is returned bracketed, written or not, so its colons
/// cannot be read as separators. Everything else must be a plain name or
/// address: a leading `-`, an `@`, a stray bracket, whitespace, a control
/// character and every shell metacharacter have no canonical form.
#[must_use]
pub fn canonical_routing_host(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_ROUTING_HOST_BYTES {
        return None;
    }
    if let Some(literal) = value
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return literal
            .parse::<Ipv6Addr>()
            .ok()
            .map(|address| format!("[{address}]"));
    }
    if let Ok(address) = value.parse::<Ipv6Addr>() {
        return Some(format!("[{address}]"));
    }
    let plain = value.starts_with(|c: char| c.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
    plain.then(|| value.to_string())
}

/// Whether `value` can be the user half of a `ProxyJump`.
///
/// Narrower than [`is_safe_positional`]: this name is interpolated into the
/// shell command OpenSSH generates for the hop, so a quote, a `$` or a `;` is
/// refused rather than escaped.
#[must_use]
pub fn is_safe_routing_username(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ROUTING_HOST_BYTES
        && value.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

/// Whether `value` can be passed to `ssh(1)` as a positional word without
/// changing what the command means.
///
/// The rules are narrow on purpose:
///
/// * a leading `-` is an option, not a host;
/// * `@` in the host would be read as `user@host` and would override `-l`;
/// * whitespace, `NUL` and other control characters have no legitimate place
///   in either field and are the shapes that hide a second word.
#[must_use]
pub fn is_safe_positional(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.contains('@')
        && !value
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '\0')
}

/// Resolve a bare program name through `PATH`, under the authority rule
/// [`enzui_services::process_transport`] applies.
///
/// An absolute path is taken as given. A bare name is resolved through a
/// `PATH` that must be nonempty and contain only absolute directories, and the
/// first executable regular file wins. One relative entry fails the whole
/// lookup: it would make the resolved program depend on the working
/// directory.
#[must_use]
pub fn resolve_executable(program: &str, path: Option<&OsStr>) -> Option<PathBuf> {
    let candidate = Path::new(program);
    if candidate.is_absolute() {
        return Some(candidate.to_path_buf());
    }
    // Anything with a separator is neither absolute nor PATH-resolvable.
    let mut components = candidate.components();
    let bare = matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none();
    if !bare {
        return None;
    }
    let path = path?;
    let directories: Vec<PathBuf> = std::env::split_paths(path).collect();
    if directories.is_empty()
        || directories
            .iter()
            .any(|directory| directory.as_os_str().is_empty() || !directory.is_absolute())
    {
        return None;
    }
    for directory in directories {
        let candidate = directory.join(program);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    match std::fs::metadata(path) {
        Ok(metadata) => metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.is_file())
        .unwrap_or(false)
}
