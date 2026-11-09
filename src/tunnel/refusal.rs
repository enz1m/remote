//! OpenSSH invocation validation used by desktop TCP tunnels.
use crate::model::Protocol;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SshRefusal {
    /// The backend was handed a profile for another protocol.
    NotSsh(Protocol),
    /// The profile has no host to dial.
    MissingHost,
    /// The host field cannot be passed to `ssh(1)` as a single positional
    /// argument without changing what is dialled: a leading `-` would be read
    /// as an option and an `@` would override the username.
    UnsafeHost,
    /// The username field would be read as an option or would smuggle a second
    /// host.
    UnsafeUsername,
    /// Port `0` is not dialable.
    InvalidPort,
    /// The profile carries a jump host with no host to reach.
    MissingJumpHost,
    /// The jump host cannot appear in a `ProxyJump`: OpenSSH expands that
    /// option into a command it runs through a shell, so anything beyond a
    /// plain name or a bracketed IPv6 literal is refused.
    UnsafeJumpHost,
    /// The jump username would be read as an option, a second host or shell
    /// text in the same expansion.
    UnsafeJumpUsername,
    /// The jump host's port `0` is not dialable.
    InvalidJumpPort,
    /// The jump host is the profile's own destination, which would route the
    /// connection through itself.
    JumpIsDestination,
    /// The jump host authenticates with a stored password, and no secret
    /// reaches the client.
    JumpSecretUnsupported,
    /// The jump host names a private key file, which OpenSSH's generated jump
    /// command has no argument for.
    JumpIdentityUnsupported,
    /// A forward rule's bind address cannot appear in a forward
    /// specification. `rule` is the rule's one-based position in the
    /// profile's list.
    UnsafeForwardBindAddress { rule: usize },
    /// A forward rule's destination host cannot appear in a forward
    /// specification.
    UnsafeForwardDestination { rule: usize },
    /// A forward rule binds or reaches port `0`, which names no listener this
    /// app could report and no destination it could dial.
    InvalidForwardPort { rule: usize },
    /// Two enabled forward rules would claim one listener.
    ForwardListenerConflict { rule: usize },
    /// More rules are enabled than one connection may carry.
    TooManyForwards { cap: usize },
    /// The jump host and forward rules together exceed the argument budget.
    RoutingArgumentsTooLarge { cap: usize },
    /// A password is stored for this profile, and this build has no way to
    /// hand OpenSSH a secret.
    PasswordAuthUnsupported,
    /// The `ssh` program could not be resolved under the executable-authority
    /// rule.
    ExecutableAuthority,
}

impl std::fmt::Display for SshRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSsh(protocol) => write!(
                f,
                "the SSH backend was asked to dial a {} profile",
                protocol.label()
            ),
            Self::MissingHost => f.write_str("this profile has no host to connect to"),
            Self::UnsafeHost => f.write_str(
                "this profile's host cannot be dialled safely: a host may not begin with \
                 `-`, contain `@`, a space or a control character, or exceed the stored \
                 field length",
            ),
            Self::UnsafeUsername => f.write_str(
                "this profile's username cannot be used safely: a username may not begin \
                 with `-`, contain `@`, a space or a control character, or exceed the \
                 stored field length",
            ),
            Self::InvalidPort => f.write_str("port 0 is not a port this profile can be dialled on"),
            Self::MissingJumpHost => {
                f.write_str("this profile's jump host has no host name to connect to")
            }
            Self::UnsafeJumpHost => f.write_str(
                "this profile's jump host cannot be used safely: a jump host may only be a \
                 plain host name, an address, or an IPv6 address in square brackets",
            ),
            Self::UnsafeJumpUsername => f.write_str(
                "this profile's jump username cannot be used safely: it may only be a plain \
                 name, without spaces, punctuation that starts an option, or an `@`",
            ),
            Self::InvalidJumpPort => {
                f.write_str("port 0 is not a port this profile's jump host can be reached on")
            }
            Self::JumpIsDestination => f.write_str(
                "this profile's jump host is the connection's own destination, so the \
                 session would be routed through itself",
            ),
            Self::JumpSecretUnsupported => f.write_str(
                "this profile's jump host authenticates with a stored password, and this \
                 build connects with an SSH key or agent only — it has no way to hand the \
                 password to OpenSSH",
            ),
            Self::JumpIdentityUnsupported => f.write_str(
                "this profile's jump host names a private key file, and the jump connection \
                 OpenSSH makes takes no key argument — connecting would authenticate with \
                 some other key",
            ),
            Self::UnsafeForwardBindAddress { rule } => write!(
                f,
                "port-forward rule {rule} cannot be used safely: a bind address may only be \
                 empty, `*`, a plain host name, an address, or an IPv6 address in square \
                 brackets"
            ),
            Self::UnsafeForwardDestination { rule } => write!(
                f,
                "port-forward rule {rule} cannot be used safely: a destination may only be a \
                 plain host name, an address, or an IPv6 address in square brackets"
            ),
            Self::InvalidForwardPort { rule } => write!(
                f,
                "port-forward rule {rule} uses port 0, which names no port this app could \
                 tell you about"
            ),
            Self::ForwardListenerConflict { rule } => write!(
                f,
                "port-forward rule {rule} listens where an earlier rule already does, so one \
                 of the two could never open"
            ),
            Self::TooManyForwards { cap } => write!(
                f,
                "this profile has more than {cap} enabled port-forward rules; disable some \
                 and connect again"
            ),
            Self::RoutingArgumentsTooLarge { cap } => write!(
                f,
                "this profile's jump host and port-forward rules need more than {cap} bytes \
                 of connection arguments"
            ),
            Self::PasswordAuthUnsupported => f.write_str(
                "this profile authenticates with a stored password, and this build \
                 connects with an SSH key or agent only: it has no way to hand the \
                 password to OpenSSH without putting it on a command line, in the \
                 environment or in a file",
            ),
            Self::ExecutableAuthority => {
                f.write_str("the `ssh` program could not be found on an absolute PATH directory")
            }
        }
    }
}
