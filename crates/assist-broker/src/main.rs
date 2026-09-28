//! The session broker.
//!
//! 1. The agent registers (`POST /api/sessions`) and gets a 9-digit support
//!    code, which the person reads to the technician.
//! 2. Both sides open a WebSocket (`/ws/agent`, `/ws/viewer`) keyed by the code.
//! 3. The viewer's WebRTC offer is relayed to the agent with a grant the broker
//!    signed (ML-DSA, via `sigilant-token`): who the technician is and the most
//!    they may do. The agent checks it, asks the person, and answers.
//! 4. Media and input then flow peer to peer; the broker only records what the
//!    agent reports, in a hash-chained audit log (`sigilant-audit`).
//!
//! The broker never sees the screen. In the hosted product this role can move
//! to a Cloudflare Durable Object; this binary is the self-hosted variant and
//! the reference implementation.

mod audit;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use assist_proto::{Grant, NewSession, PublicKey, Scope, Signal, sign_grant};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use serde::Deserialize;
use serde_json::json;
use sigilant_token::{Algorithm, SigningKey, create_seed_file, signing_key_from_seed_file};
use tokio::sync::mpsc;

use crate::audit::AuditLog;

const VIEWER_HTML: &str = include_str!("../../../web/viewer.html");

#[derive(Parser, Debug)]
#[command(about = "CyberDoc Assist session broker")]
struct Args {
    #[arg(long, env = "ASSIST_LISTEN", default_value = "127.0.0.1:8787")]
    listen: SocketAddr,
    /// ML-DSA-65 signing key seed; created on first run.
    #[arg(long, env = "ASSIST_KEY_FILE", default_value = "broker-key.seed")]
    key_file: PathBuf,
    #[arg(long, env = "ASSIST_AUDIT_FILE", default_value = "audit.jsonl")]
    audit_file: PathBuf,
    /// Names this broker in audit records.
    #[arg(long, env = "ASSIST_BROKER_ID", default_value = "assist-broker")]
    broker_id: String,
    /// How long a grant is valid, in seconds.
    #[arg(long, default_value_t = 3600)]
    grant_ttl: u64,
    /// Highest scope granted to technicians. TODO: derive per technician from
    /// the CyberDoc plan / Cedar policy instead of one broker-wide switch.
    #[arg(long, value_enum, default_value = "control")]
    max_scope: ScopeArg,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum ScopeArg {
    View,
    Control,
}

type Tx = mpsc::UnboundedSender<Signal>;

struct Session {
    id: String,
    agent_secret: String,
    agent: Option<Tx>,
    viewer: Option<(Tx, String)>,
}

struct AppState {
    sessions: Mutex<HashMap<String, Session>>,
    key: SigningKey,
    audit: Mutex<AuditLog>,
    grant_ttl: u64,
    max_scope: Scope,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Role {
    Agent,
    Viewer,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random_hex(bytes: usize) -> String {
    let mut rng = rand::rng();
    (0..bytes)
        .map(|_| format!("{:02x}", rng.random::<u8>()))
        .collect()
}

impl AppState {
    fn record(&self, session_id: &str, event: &str, detail: serde_json::Value) {
        let record = json!({ "session_id": session_id, "event": event, "detail": detail });
        tracing::info!(%session_id, event, %detail, "audit");
        if let Err(e) = self
            .audit
            .lock()
            .expect("audit lock")
            .append(now(), &record)
        {
            // A session event that cannot be recorded is a broken promise to
            // the client; surface it loudly. TODO: end the session instead.
            tracing::error!("audit append failed: {e:#}");
        }
    }

    /// Routes one message from `role` in session `code`.
    fn route(&self, code: &str, role: Role, signal: Signal) {
        let mut sessions = self.sessions.lock().expect("sessions lock");
        let Some(session) = sessions.get_mut(code) else {
            return;
        };
        let session_id = session.id.clone();
        match (role, signal) {
            (Role::Viewer, Signal::Offer { sdp, .. }) => {
                let Some((viewer, technician)) = &session.viewer else {
                    return;
                };
                let Some(agent) = &session.agent else {
                    let _ = viewer.send(Signal::Rejected {
                        reason: "the computer is not connected".into(),
                    });
                    return;
                };
                let issued_at = now();
                let grant = Grant {
                    session_id: session_id.clone(),
                    code: code.to_owned(),
                    technician: technician.clone(),
                    max_scope: self.max_scope,
                    issued_at,
                    expires_at: issued_at + self.grant_ttl,
                };
                match sign_grant(&grant, &self.key) {
                    Ok(token) => {
                        let _ = agent.send(Signal::Offer {
                            sdp,
                            grant: Some(token),
                        });
                        drop(sessions);
                        self.record(
                            &session_id,
                            "grant_issued",
                            json!({
                                "technician": grant.technician,
                                "max_scope": grant.max_scope,
                                "expires_at": grant.expires_at,
                            }),
                        );
                    }
                    Err(e) => tracing::error!("signing grant: {e}"),
                }
            }
            (Role::Agent, signal @ (Signal::Answer { .. } | Signal::Rejected { .. })) => {
                if let Some((viewer, _)) = &session.viewer {
                    let _ = viewer.send(signal.clone());
                }
                if let Signal::Rejected { reason } = signal {
                    drop(sessions);
                    self.record(&session_id, "rejected", json!({ "reason": reason }));
                }
            }
            (Role::Agent, Signal::Event { name, detail }) => {
                drop(sessions);
                self.record(&session_id, &name, json!(detail));
            }
            (role, other) => tracing::debug!(?role, ?other, "ignored"),
        }
    }

    fn disconnect(&self, code: &str, role: Role) {
        let mut sessions = self.sessions.lock().expect("sessions lock");
        let Some(session) = sessions.get_mut(code) else {
            return;
        };
        let session_id = session.id.clone();
        match role {
            Role::Agent => {
                if let Some((viewer, _)) = &session.viewer {
                    let _ = viewer.send(Signal::PeerLeft);
                }
                sessions.remove(code);
                drop(sessions);
                self.record(&session_id, "session_ended", json!({ "by": "agent" }));
            }
            Role::Viewer => {
                if let Some((_, technician)) = session.viewer.take() {
                    if let Some(agent) = &session.agent {
                        let _ = agent.send(Signal::PeerLeft);
                    }
                    drop(sessions);
                    self.record(
                        &session_id,
                        "viewer_left",
                        json!({ "technician": technician }),
                    );
                }
            }
        }
    }
}

async fn create_session(State(state): State<Arc<AppState>>) -> Json<NewSession> {
    let session = {
        let mut sessions = state.sessions.lock().expect("sessions lock");
        let code = loop {
            let candidate = format!("{:09}", rand::rng().random_range(0..1_000_000_000u32));
            if !sessions.contains_key(&candidate) {
                break candidate;
            }
        };
        let session = NewSession {
            session_id: random_hex(16),
            code: code.clone(),
            agent_secret: random_hex(32),
        };
        sessions.insert(
            code,
            Session {
                id: session.session_id.clone(),
                agent_secret: session.agent_secret.clone(),
                agent: None,
                viewer: None,
            },
        );
        session
    };
    // TODO: expire sessions whose agent never connects.
    state.record(&session.session_id, "session_created", json!({}));
    Json(session)
}

async fn public_key(State(state): State<Arc<AppState>>) -> Json<PublicKey> {
    Json(PublicKey::from_verifying_key(state.key.verifying_key()))
}

async fn audit_log(State(state): State<Arc<AppState>>) -> Response {
    let audit = state.audit.lock().expect("audit lock");
    match audit.read() {
        Ok((rows, verdict)) => {
            let records: Vec<_> = rows
                .iter()
                .map(|r| json!({
                    "seq": r.seq,
                    "received_at": r.received_at,
                    "record": serde_json::from_str::<serde_json::Value>(&r.record).unwrap_or_default(),
                    "hash": r.hash,
                }))
                .collect();
            let chain = match verdict {
                Ok(head) => {
                    json!({ "verified": true, "head_seq": head.seq, "head_hash": sigilant_audit::chain::hex(&head.hash) })
                }
                Err(e) => json!({ "verified": false, "error": e.to_string() }),
            };
            Json(json!({ "chain": chain, "records": records })).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct AgentQuery {
    code: String,
    secret: String,
}

async fn ws_agent(
    State(state): State<Arc<AppState>>,
    Query(q): Query<AgentQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    {
        let sessions = state.sessions.lock().expect("sessions lock");
        match sessions.get(&q.code) {
            Some(s) if s.agent_secret == q.secret && s.agent.is_none() => {}
            Some(s) if s.agent_secret == q.secret => {
                return (StatusCode::CONFLICT, "agent already connected").into_response();
            }
            _ => return StatusCode::NOT_FOUND.into_response(),
        }
    }
    ws.on_upgrade(move |socket| run_socket(state, q.code, Role::Agent, None, socket))
}

#[derive(Deserialize)]
struct ViewerQuery {
    code: String,
    /// TODO(production): unauthenticated. Take the technician from the
    /// CyberDoc session (`cyberdoc_session` cookie) instead of trusting this.
    #[serde(default = "default_technician")]
    technician: String,
}

fn default_technician() -> String {
    "technician".into()
}

async fn ws_viewer(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ViewerQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    {
        let sessions = state.sessions.lock().expect("sessions lock");
        match sessions.get(&q.code) {
            Some(s) if s.agent.is_none() => {
                return (StatusCode::NOT_FOUND, "the computer is not connected").into_response();
            }
            Some(s) if s.viewer.is_some() => {
                return (StatusCode::CONFLICT, "someone is already connected").into_response();
            }
            Some(_) => {}
            None => return (StatusCode::NOT_FOUND, "unknown code").into_response(),
        }
    }
    let technician: String = q
        .technician
        .chars()
        .filter(|c| !c.is_control())
        .take(80)
        .collect();
    ws.on_upgrade(move |socket| run_socket(state, q.code, Role::Viewer, Some(technician), socket))
}

async fn run_socket(
    state: Arc<AppState>,
    code: String,
    role: Role,
    technician: Option<String>,
    socket: WebSocket,
) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Signal>();

    let session_id = {
        let mut sessions = state.sessions.lock().expect("sessions lock");
        let Some(session) = sessions.get_mut(&code) else {
            return;
        };
        // Re-check under the lock: the slot may have been taken since the upgrade was accepted.
        match role {
            Role::Agent if session.agent.is_none() => session.agent = Some(tx),
            Role::Viewer if session.viewer.is_none() && session.agent.is_some() => {
                session.viewer = Some((tx, technician.clone().unwrap_or_default()))
            }
            _ => return,
        }
        session.id.clone()
    };
    match role {
        Role::Agent => state.record(&session_id, "agent_connected", json!({})),
        Role::Viewer => state.record(
            &session_id,
            "viewer_joined",
            json!({ "technician": technician }),
        ),
    }

    let writer = tokio::spawn(async move {
        while let Some(signal) = rx.recv().await {
            let Ok(text) = serde_json::to_string(&signal) else {
                continue;
            };
            if sink.send(Message::Text(text.into())).await.is_err() {
                break;
            }
        }
    });

    while let Some(Ok(message)) = stream.next().await {
        match message {
            Message::Text(text) => match serde_json::from_str::<Signal>(text.as_str()) {
                Ok(signal) => state.route(&code, role, signal),
                Err(e) => tracing::debug!("bad message from {role:?}: {e}"),
            },
            Message::Close(_) => break,
            _ => {}
        }
    }

    state.disconnect(&code, role);
    writer.abort();
}

fn load_or_create_key(path: &std::path::Path) -> Result<SigningKey> {
    if path.exists() {
        signing_key_from_seed_file(path, Algorithm::MlDsa65)
            .with_context(|| format!("loading {}", path.display()))
    } else {
        tracing::info!("creating signing key {}", path.display());
        create_seed_file(path, Algorithm::MlDsa65)
            .with_context(|| format!("creating {}", path.display()))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();

    let key = load_or_create_key(&args.key_file)?;
    let audit = AuditLog::open(&args.audit_file, &args.broker_id)?;
    let state = Arc::new(AppState {
        sessions: Mutex::new(HashMap::new()),
        key,
        audit: Mutex::new(audit),
        grant_ttl: args.grant_ttl,
        max_scope: match args.max_scope {
            ScopeArg::View => Scope::View,
            ScopeArg::Control => Scope::Control,
        },
    });

    let app = Router::new()
        .route("/", get(|| async { Html(VIEWER_HTML) }))
        .route("/api/key", get(public_key))
        .route("/api/sessions", post(create_session))
        .route("/api/audit", get(audit_log))
        .route("/ws/agent", get(ws_agent))
        .route("/ws/viewer", get(ws_viewer))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!("broker listening on http://{}", args.listen);
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
