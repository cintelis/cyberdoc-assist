//! The CyberDoc Assist agent — runs on the client's computer.
//!
//! Flow:
//!   1. Fetch the broker's public key and register a session, getting a
//!      9-digit code the person reads to the technician.
//!   2. Connect to the broker over a WebSocket and wait for the technician's
//!      WebRTC offer, which arrives with a broker-signed grant.
//!   3. Verify the grant, ask the person for consent, then answer and start
//!      streaming the screen over WebRTC.
//!   4. Apply mouse/keyboard input from the data channel **only** after the
//!      person separately approves control (see `input` and `consent`).
//!
//! The screen never reaches the broker: media and input are peer to peer.

mod capture;
mod consent;
mod input;

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use assist_proto::{Control, Grant, NewSession, PublicKey, Scope, Signal, verify_grant};
use clap::Parser;
use ed25519_dalek::VerifyingKey;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use rtc::media::Sample;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_H264, MediaEngine};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::transport::RTCIceServer;
use rtc::rtp_transceiver::PayloadType;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::media_stream::Track;
use webrtc::media_stream::track_local::{TrackLocal, static_sample::TrackLocalStaticSample};
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCIceGatheringState,
    RTCPeerConnectionState, Registry,
};
use webrtc::runtime::{Runtime, Sender, channel, default_runtime};

use crate::capture::ScreenSource;
use crate::input::Injector;

const H264_PAYLOAD_TYPE: PayloadType = 102;
const FRAME_INTERVAL: Duration = Duration::from_millis(66); // ~15 fps

#[derive(Parser, Debug)]
#[command(about = "CyberDoc Assist agent (runs on the computer being helped)")]
struct Args {
    /// Broker base URL, e.g. https://assist.cintelis.ai
    #[arg(long, env = "ASSIST_BROKER", default_value = "http://127.0.0.1:8787")]
    broker: String,
    #[arg(long, default_value_t = 15.0)]
    fps: f32,
    #[arg(long, default_value_t = 4000)]
    kbps: u32,
    /// Skip the consent prompts. For automated testing on a machine you own
    /// ONLY — never ship or run this against someone else's computer.
    #[arg(long)]
    yes_i_own_this_machine: bool,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn ws_url(base: &str, path: &str) -> String {
    let ws = base
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1);
    format!("{}{}", ws.trim_end_matches('/'), path)
}

/// Handles peer-connection events: connection state, and the control data
/// channel the viewer opens.
struct Handler {
    runtime: Arc<dyn Runtime>,
    injector: Arc<Mutex<Injector>>,
    /// The most the broker's grant allows this technician to do.
    max_scope: Scope,
    technician: String,
    auto_consent: bool,
    connected_tx: Sender<()>,
    gather_tx: Sender<()>,
    done_tx: Sender<()>,
    /// Reports control grant/revoke to the audit log via the signaling task.
    event_tx: mpsc::UnboundedSender<Signal>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for Handler {
    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            let _ = self.gather_tx.try_send(());
        }
    }

    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        tracing::info!("connection state: {state}");
        match state {
            RTCPeerConnectionState::Connected => {
                let _ = self.connected_tx.try_send(());
            }
            RTCPeerConnectionState::Failed
            | RTCPeerConnectionState::Disconnected
            | RTCPeerConnectionState::Closed => {
                let _ = self.done_tx.try_send(());
            }
            _ => {}
        }
    }

    async fn on_data_channel(&self, dc: Arc<dyn DataChannel>) {
        let injector = self.injector.clone();
        let max_scope = self.max_scope;
        let technician = self.technician.clone();
        let auto_consent = self.auto_consent;
        let event_tx = self.event_tx.clone();

        self.runtime.spawn(Box::pin(async move {
            while let Some(event) = dc.poll().await {
                match event {
                    DataChannelEvent::OnOpen => {
                        tracing::info!("control channel open");
                    }
                    DataChannelEvent::OnMessage(msg) => {
                        let Ok(text) = String::from_utf8(msg.data.to_vec()) else { continue };
                        let Ok(control) = serde_json::from_str::<Control>(&text) else { continue };
                        match control {
                            Control::RequestControl => {
                                let granted = max_scope >= Scope::Control
                                    && (auto_consent
                                        || consent::ask(&format!(
                                            "{technician} is asking to CONTROL your computer (move the mouse and type). Allow?"
                                        )));
                                if granted {
                                    injector.lock().await.set_allowed(true);
                                    let _ = dc.send_text(&reply(Control::ControlGranted)).await;
                                    let _ = event_tx.send(Signal::Event {
                                        name: "control_granted".into(),
                                        detail: technician.clone(),
                                    });
                                } else {
                                    let reason = if max_scope < Scope::Control {
                                        "this session is view-only".to_string()
                                    } else {
                                        "the person at the computer declined".to_string()
                                    };
                                    let _ = dc.send_text(&reply(Control::ControlDenied { reason: reason.clone() })).await;
                                    let _ = event_tx.send(Signal::Event { name: "control_denied".into(), detail: reason });
                                }
                            }
                            other => {
                                if let Err(e) = injector.lock().await.apply(&other) {
                                    tracing::warn!("input error: {e}");
                                }
                            }
                        }
                    }
                    DataChannelEvent::OnClose => break,
                    _ => {}
                }
            }
        }));
    }
}

fn reply(control: Control) -> String {
    serde_json::to_string(&control).expect("control serialises")
}

async fn fetch_public_key(http: &reqwest::Client, broker: &str) -> Result<VerifyingKey> {
    let pk: PublicKey = http
        .get(format!("{}/api/key", broker.trim_end_matches('/')))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    pk.to_verifying_key()
        .ok_or_else(|| anyhow!("broker public key is not a usable ML-DSA key"))
}

async fn register_session(http: &reqwest::Client, broker: &str) -> Result<NewSession> {
    Ok(http
        .post(format!("{}/api/sessions", broker.trim_end_matches('/')))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

/// Builds the answering peer connection, adds the screen track, and returns it
/// with the track and the "connected" receiver.
async fn build_peer_connection(
    runtime: Arc<dyn Runtime>,
    handler: Arc<Handler>,
) -> Result<(Arc<dyn PeerConnection>, Arc<TrackLocalStaticSample>)> {
    let video_codec = RTCRtpCodec {
        mime_type: MIME_TYPE_H264.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f"
            .to_owned(),
        rtcp_feedback: vec![],
    };
    let mut media_engine = MediaEngine::default();
    media_engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: video_codec.clone(),
            payload_type: H264_PAYLOAD_TYPE,
        },
        RtpCodecKind::Video,
    )?;
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;

    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_string()],
            ..Default::default()
        }])
        .build();

    let pc = PeerConnectionBuilder::new()
        .with_configuration(config)
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .with_handler(handler)
        .with_runtime(runtime)
        .with_udp_addrs(vec!["0.0.0.0:0".to_string()])
        .build()
        .await?;

    let ssrc = rand::random::<u32>();
    let track = Arc::new(TrackLocalStaticSample::new(
        Instant::now(),
        MediaStreamTrack::new(
            "cyberdoc-assist".to_string(),
            "screen".to_string(),
            "screen".to_string(),
            RtpCodecKind::Video,
            vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    ssrc: Some(ssrc),
                    ..Default::default()
                },
                codec: video_codec,
                ..Default::default()
            }],
        ),
    )?);
    pc.add_track(Arc::clone(&track) as Arc<dyn TrackLocal>)
        .await?;

    Ok((Arc::new(pc) as Arc<dyn PeerConnection>, track))
}

/// Starts a dedicated OS thread that owns the screen source and H.264 encoder
/// (both hold non-`Send` OS handles, so they are built *on* this thread and
/// never cross a thread boundary) and pushes encoded frames into `frames`.
/// Blocks until the thread reports the monitor's dimensions, then returns them.
/// The thread stops when the receiver is dropped.
fn spawn_capture(fps: f32, kbps: u32, frames: mpsc::Sender<Vec<u8>>) -> Result<(u32, u32)> {
    let (dim_tx, dim_rx) = std::sync::mpsc::channel::<std::result::Result<(u32, u32), String>>();
    std::thread::spawn(move || {
        let mut source = match ScreenSource::primary(fps, kbps) {
            Ok(source) => source,
            Err(e) => {
                let _ = dim_tx.send(Err(format!("{e:#}")));
                return;
            }
        };
        if dim_tx.send(Ok(source.dimensions())).is_err() {
            return;
        }
        loop {
            match source.next_frame() {
                Ok(Some(data)) => {
                    if frames.blocking_send(data).is_err() {
                        break; // peer gone; forwarder dropped the receiver
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!("capture stopped: {e}");
                    break;
                }
            }
            std::thread::sleep(FRAME_INTERVAL);
        }
    });
    match dim_rx.recv() {
        Ok(Ok(dims)) => Ok(dims),
        Ok(Err(e)) => Err(anyhow!("screen capture failed to start: {e}")),
        Err(_) => Err(anyhow!("capture thread exited before reporting dimensions")),
    }
}

/// Forwards encoded frames to the track until the peer leaves (`done` fires) or
/// the capture thread stops. Returning here drops `frames`, stopping capture.
async fn stream_screen(
    track: Arc<TrackLocalStaticSample>,
    mut frames: mpsc::Receiver<Vec<u8>>,
    mut done: webrtc::runtime::Receiver<()>,
) -> Result<()> {
    let ssrc = *track
        .ssrcs()
        .await
        .first()
        .ok_or_else(|| anyhow!("track has no ssrc"))?;
    loop {
        tokio::select! {
            biased;
            _ = done.recv() => break,
            maybe = frames.recv() => match maybe {
                Some(data) => {
                    track
                        .sample_writer(ssrc, H264_PAYLOAD_TYPE)
                        .write_sample(&Sample { data: data.into(), duration: FRAME_INTERVAL, ..Sample::new(Instant::now()) })
                        .await?;
                }
                None => break,
            }
        }
    }
    Ok(())
}

async fn run_session(
    runtime: Arc<dyn Runtime>,
    offer_sdp: String,
    grant: Grant,
    auto_consent: bool,
    event_tx: mpsc::UnboundedSender<Signal>,
) -> Result<Option<String>> {
    if !auto_consent
        && !consent::ask(&format!(
            "{} is asking to VIEW your screen. Allow?",
            grant.technician
        ))
    {
        return Ok(None);
    }

    // Start capture on its own thread and learn the monitor size for scaling.
    let (frame_tx, frame_rx) = mpsc::channel::<Vec<u8>>(8);
    let (width, height) = spawn_capture(15.0, 4000, frame_tx).context("starting screen capture")?;
    let injector = Arc::new(Mutex::new(Injector::new(width, height)?));

    let (connected_tx, mut connected_rx) = channel::<()>(1);
    let (gather_tx, mut gather_rx) = channel::<()>(1);
    let (done_tx, done_rx) = channel::<()>(1);

    let handler = Arc::new(Handler {
        runtime: runtime.clone(),
        injector,
        max_scope: grant.max_scope,
        technician: grant.technician.clone(),
        auto_consent,
        connected_tx,
        gather_tx,
        done_tx,
        event_tx,
    });

    let (pc, track) = build_peer_connection(runtime.clone(), handler).await?;

    pc.set_remote_description(RTCSessionDescription::offer(offer_sdp)?)
        .await?;
    let answer = pc.create_answer(None).await?;
    pc.set_local_description(answer).await?;
    let _ = gather_rx.recv().await; // non-trickle: wait for ICE gathering
    let local = pc
        .local_description()
        .await
        .ok_or_else(|| anyhow!("no local description"))?;
    let answer_sdp = local.sdp;

    // The capture thread is already running; forward its frames to the track
    // once the peer connects.
    let track_for_stream = track.clone();
    runtime.spawn(Box::pin(async move {
        connected_rx.recv().await;
        tracing::info!("peer connected — streaming screen");
        if let Err(e) = stream_screen(track_for_stream, frame_rx, done_rx).await {
            tracing::warn!("screen stream ended: {e}");
        }
    }));

    Ok(Some(answer_sdp))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    if args.yes_i_own_this_machine {
        tracing::warn!("consent prompts are DISABLED (--yes-i-own-this-machine)");
    }

    let http = reqwest::Client::new();
    let broker_key = fetch_public_key(&http, &args.broker)
        .await
        .context("fetching broker key")?;
    let session = register_session(&http, &args.broker)
        .await
        .context("registering session")?;

    println!("\n=======================================================");
    println!("  Read this code to your CyberDoc technician:");
    println!("      {}", session.code);
    println!("  Waiting for them to connect. Ctrl-C to cancel.");
    println!("=======================================================\n");

    let url = ws_url(
        &args.broker,
        &format!(
            "/ws/agent?code={}&secret={}",
            session.code, session.agent_secret
        ),
    );
    let (ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .context("connecting to broker")?;
    let (mut sink, mut stream) = ws.split();

    // Outbound signaling (answers, rejections, audit events) funnels through here.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Signal>();
    let writer = tokio::spawn(async move {
        while let Some(signal) = out_rx.recv().await {
            let Ok(text) = serde_json::to_string(&signal) else {
                continue;
            };
            if sink.send(WsMessage::Text(text.into())).await.is_err() {
                break;
            }
        }
    });

    let runtime = default_runtime().context("no webrtc runtime")?;

    while let Some(message) = stream.next().await {
        let message = message.context("broker connection error")?;
        let WsMessage::Text(text) = message else {
            if matches!(message, WsMessage::Close(_)) {
                break;
            }
            continue;
        };
        let signal: Signal = match serde_json::from_str(&text) {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!("bad signal: {e}");
                continue;
            }
        };
        match signal {
            Signal::Offer { sdp, grant } => {
                let token = grant.ok_or_else(|| anyhow!("offer arrived without a grant"))?;
                let grant = match verify_grant(&token, &broker_key, &session.code, now()) {
                    Ok(g) => g,
                    Err(e) => {
                        tracing::warn!("rejecting offer: {e}");
                        let _ = out_tx.send(Signal::Rejected {
                            reason: "the connection could not be verified".into(),
                        });
                        continue;
                    }
                };
                match run_session(
                    runtime.clone(),
                    sdp,
                    grant,
                    args.yes_i_own_this_machine,
                    out_tx.clone(),
                )
                .await
                {
                    Ok(Some(answer_sdp)) => {
                        let _ = out_tx.send(Signal::Answer { sdp: answer_sdp });
                    }
                    Ok(None) => {
                        let _ = out_tx.send(Signal::Rejected {
                            reason: "the person at the computer declined".into(),
                        });
                    }
                    Err(e) => {
                        tracing::error!("session failed: {e:#}");
                        let _ = out_tx.send(Signal::Rejected {
                            reason: "the computer could not start the session".into(),
                        });
                    }
                }
            }
            Signal::PeerLeft => {
                tracing::info!("technician disconnected");
            }
            other => tracing::debug!("ignored signal: {other:?}"),
        }
    }

    writer.abort();
    Ok(())
}
