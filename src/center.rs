//! Remote's enzui-center functions, behind the `center` feature.
//!
//! Saved connections and session state only: list saved connections, list
//! open sessions, and select a connection in the window. Connecting,
//! disconnecting, typing into a session and editing or deleting profiles are
//! not exposed — a connection reaches another machine, an external effect a
//! user starts themselves. Credentials never leave the keyring. Selection is
//! an ordinary [`Message`] through [`App::update`].

#[cfg(not(test))]
use enzui_iced_agent::center::{
    AppFunction, AppFunctionRegistry, AppMetadata, CenterHost, ConsentScope, FunctionRisk,
    FunctionSpec,
};
use enzui_iced_agent::center::{CenterFailure, CenterOutcome, CenterTurn, ConnectorEvent};
#[cfg(not(test))]
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::*;

/// The app id the center credential is enrolled under.
#[cfg(not(test))]
pub(crate) const CENTER_APP_ID: &str = "io.github.enzui.Remote";
/// The most rows one listing returns.
pub(crate) const LIST_LIMIT: usize = 200;

/// What an admitted call asks Remote to do.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(
    test,
    expect(
        dead_code,
        reason = "Only the desktop connector constructs admitted center calls."
    )
)]
pub(crate) enum CenterCall {
    ListConnections,
    ListSessions,
    SelectConnection { connection_id: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(not(test))]
struct ConnectionArgs {
    connection_id: String,
}

#[cfg(not(test))]
fn object(properties: Value, required: &[&str]) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties,
    })
}

/// Remote's registered functions.
#[cfg(not(test))]
pub(crate) fn registry() -> AppFunctionRegistry<CenterCall> {
    let once_or_session = vec![ConsentScope::Once, ConsentScope::Session];
    let connections = FunctionSpec::new(
        "list_connections",
        "List saved connections",
        "Lists saved connections: id, name, group, protocol, host and port. No credentials.",
        object(json!({}), &[]),
        object(
            json!({"connections": {"type": "array", "items": object(json!({
                "connection_id": {"type": "string"},
                "name": {"type": "string"},
                "group": {"type": "string"},
                "protocol": {"type": "string"},
                "host": {"type": "string"},
                "port": {"type": "integer"}
            }), &["connection_id", "name", "group", "protocol", "host", "port"])}}),
            &["connections"],
        ),
        FunctionRisk::SensitiveRead,
        once_or_session.clone(),
    );
    let sessions = FunctionSpec::new(
        "list_sessions",
        "List open sessions",
        "Lists open sessions with the connection they belong to and their status.",
        object(json!({}), &[]),
        object(
            json!({"sessions": {"type": "array", "items": object(json!({
                "connection_id": {"type": "string"},
                "name": {"type": "string"},
                "status": {"type": "string"}
            }), &["connection_id", "name", "status"])}}),
            &["sessions"],
        ),
        FunctionRisk::SensitiveRead,
        once_or_session.clone(),
    );
    let select = FunctionSpec::new(
        "select_connection",
        "Select a connection",
        "Selects the saved connection with this id in the window, without connecting.",
        object(
            json!({"connection_id": {"type": "string", "maxLength": 64}}),
            &["connection_id"],
        ),
        object(
            json!({"connection_id": {"type": "string"}}),
            &["connection_id"],
        ),
        FunctionRisk::Mutating,
        once_or_session,
    );
    AppFunctionRegistry::from_functions(vec![
        AppFunction::new(connections, |_| CenterCall::ListConnections)
            .expect("list_connections spec"),
        AppFunction::new(sessions, |_| CenterCall::ListSessions).expect("list_sessions spec"),
        AppFunction::typed(select, |args: ConnectionArgs| {
            CenterCall::SelectConnection {
                connection_id: args.connection_id,
            }
        })
        .expect("select_connection spec"),
    ])
    .expect("the remote registry is valid")
}

#[cfg(not(test))]
pub(crate) fn metadata() -> AppMetadata {
    AppMetadata {
        id: CENTER_APP_ID.into(),
        name: "Remote".into(),
        description: "Remote desktop connections".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    }
}

impl App {
    /// Connect to enzui-center when this build opted in and a credential is
    /// enrolled for [`CENTER_APP_ID`]; otherwise stay unexposed.
    #[cfg(not(test))]
    pub(crate) fn start_center(&mut self) {
        let Some(provision) = enzui_iced_agent::center::CenterProvision::discover(CENTER_APP_ID)
        else {
            return;
        };
        match CenterHost::spawn(provision, metadata(), registry()) {
            Ok(host) => self.center = Some(host),
            Err(error) => eprintln!("remote-app: center connector disabled: {error}"),
        }
    }

    pub(crate) fn center_subscription(&self) -> Subscription<Message> {
        self.center
            .as_ref()
            .map_or_else(Subscription::none, |host| {
                host.subscription(Message::Center)
            })
    }

    /// Final shutdown: refuse new calls, cancel live ones, join the connector.
    pub(crate) fn shutdown_center(&mut self) {
        if let Some(host) = self.center.take() {
            host.shutdown();
        }
    }

    pub(crate) fn center_event(&mut self, event: ConnectorEvent) -> Task<Message> {
        let Some(host) = self.center.as_mut() else {
            return Task::none();
        };
        // Registered calls complete synchronously; there is no pending app work to cancel.
        let CenterTurn::Call(call, request) = host.receive_with_ends(event).turn else {
            return Task::none();
        };
        if !host.is_live(&call) {
            return Task::none();
        }
        let (task, outcome) = self.apply_center_call(request);
        if let Some(host) = self.center.as_mut() {
            host.answer(call, outcome);
        }
        task
    }

    fn apply_center_call(&mut self, request: CenterCall) -> (Task<Message>, CenterOutcome) {
        match request {
            CenterCall::ListConnections => {
                let connections: Vec<Value> = self
                    .profiles
                    .iter()
                    .take(LIST_LIMIT)
                    .map(|profile| {
                        json!({
                            "connection_id": profile.id.to_string(),
                            "name": profile.name,
                            "group": profile.group,
                            "protocol": profile.protocol.label(),
                            "host": profile.host,
                            "port": profile.port,
                        })
                    })
                    .collect();
                (Task::none(), Ok(json!({ "connections": connections })))
            }
            CenterCall::ListSessions => {
                let sessions: Vec<Value> = self
                    .sessions
                    .iter()
                    .take(LIST_LIMIT)
                    .map(|session| {
                        json!({
                            "connection_id": session.profile_id.to_string(),
                            "name": session.profile_snapshot.name,
                            "status": session.status.label(),
                        })
                    })
                    .collect();
                (Task::none(), Ok(json!({ "sessions": sessions })))
            }
            CenterCall::SelectConnection { connection_id } => {
                let Some(id) = Uuid::parse_str(&connection_id)
                    .ok()
                    .filter(|id| self.profiles.iter().any(|profile| profile.id == *id))
                else {
                    return (
                        Task::none(),
                        Err(CenterFailure::new(
                            "not_found",
                            "no saved connection has that id",
                        )),
                    );
                };
                let task = self.update(Message::SelectProfile(id));
                let outcome = if self.selected_profile == Some(id) {
                    Ok(json!({ "connection_id": connection_id }))
                } else {
                    Err(CenterFailure::new(
                        "unavailable",
                        "the connection could not be selected",
                    ))
                };
                (task, outcome)
            }
        }
    }
}
