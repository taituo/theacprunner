//! The caller-facing **ACP gateway** hosted by runnerd in environment mode.
//!
//! One HTTP/1.1 request authenticates the connection, after which the socket carries plain
//! ACP JSON-RPC and nothing else:
//!
//! ```text
//! GET /v1/acp HTTP/1.1
//! Authorization: Bearer <connection ticket>       (signed, short-lived, env-scoped)
//! Upgrade: acp-ndjson | websocket
//!
//! HTTP/1.1 101 Switching Protocols
//! X-ACP-Environment: <id>   X-ACP-Workdir: <cwd for session/new>   X-ACP-Phase: Idle
//! ... newline-delimited JSON-RPC (acp-ndjson) or one JSON-RPC message per text frame (websocket)
//! ```
//!
//! The gateway knows only "this connection belongs to environment X". It does not
//! understand, rewrite or originate ACP methods: bytes are relayed to the harness through
//! agentd's data link. (runnerd *observes* the stream passively to know Idle/Busy and to
//! journal tool calls — see `tap`.) Lifecycle operations (snapshot, finish, branch, destroy)
//! are not reachable here; they arrive on runnerd's control channel from the provider.
//!
//! One caller at a time: a newly authenticated connection replaces the previous one (so a
//! client can reconnect after a network failure). Each ticket is single-use (nonce).

use acp_runner_core::environment::EnvironmentPhase;
use acp_runner_core::ticket::{self, GATEWAY_AUDIENCE, TicketError};
use acp_runner_ipc::gateway::{ACP_PATH, HDR_ENVIRONMENT, HDR_PHASE, HDR_WORKDIR, MAX_MESSAGE_BYTES, RAW_UPGRADE};
use futures::{SinkExt, StreamExt};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use uuid::Uuid;

/// Upper bound for concurrent connections that have not finished the HTTP handshake.
pub const MAX_PENDING_HANDSHAKES: usize = 32;

pub struct GatewayConfig {
    pub listen: String,
    pub environment_id: Uuid,
    /// `K_env` (see `acp_runner_core::ticket`).
    pub key: [u8; 32],
    /// Harness working directory as the agent sees it (announced to the caller).
    pub workdir: String,
}

/// Why a connection was refused (journaled by the supervisor; never contains the ticket).
#[derive(Debug, Clone)]
pub struct Rejection {
    pub status: u16,
    pub reason: String,
}

/// An authenticated caller: JSON-RPC messages in (`rx`) and out (`send`).
pub struct Caller {
    pub id: u64,
    pub transport: &'static str,
    pub rx: mpsc::Receiver<String>,
    tx: mpsc::Sender<String>,
    tasks: Vec<JoinHandle<()>>,
}

impl Caller {
    /// Relay one message to the caller. `false` when the caller is gone.
    pub async fn send(&self, msg: String) -> bool {
        self.tx.send(msg).await.is_ok()
    }
}

impl Drop for Caller {
    fn drop(&mut self) {
        // The writer task ends when `tx` is dropped (closing the socket); the reader task is
        // aborted so a half-open client cannot keep the connection alive.
        for t in &self.tasks[1..] {
            t.abort();
        }
    }
}

pub struct Gateway {
    listener: TcpListener,
    cfg: Arc<GatewayConfig>,
}

pub enum GatewayEvent {
    Attached(Caller),
    Rejected(Rejection),
}

impl Gateway {
    pub async fn bind(cfg: GatewayConfig) -> std::io::Result<Gateway> {
        let listener = TcpListener::bind(&cfg.listen).await?;
        Ok(Gateway { listener, cfg: Arc::new(cfg) })
    }

    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Serve connections forever; authenticated callers and rejections are delivered on `out`.
    pub fn spawn(self, phase: watch::Receiver<EnvironmentPhase>, out: mpsc::Sender<GatewayEvent>) -> JoinHandle<()> {
        tokio::spawn(async move {
            let nonces: Arc<Mutex<HashMap<String, i64>>> = Arc::default();
            let ids = Arc::new(AtomicU64::new(1));
            // Bound concurrent unauthenticated handshakes (each may linger up to 15 s).
            let slots = Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_HANDSHAKES));
            while let Ok((stream, _peer)) = self.listener.accept().await {
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    drop(stream);
                    let _ = out
                        .send(GatewayEvent::Rejected(Rejection {
                            status: 503,
                            reason: "too many pending handshakes".into(),
                        }))
                        .await;
                    continue;
                };
                let (cfg, nonces, phase, out, ids) =
                    (self.cfg.clone(), nonces.clone(), phase.clone(), out.clone(), ids.clone());
                tokio::spawn(async move {
                    let _permit = permit;
                    match tokio::time::timeout(Duration::from_secs(15), handshake(stream, &cfg, &nonces, &phase)).await
                    {
                        Ok(Ok(Some(conn))) => {
                            let caller = conn.into_caller(ids.fetch_add(1, Ordering::SeqCst));
                            let _ = out.send(GatewayEvent::Attached(caller)).await;
                        }
                        Ok(Ok(None)) => {} // health check etc.
                        Ok(Err(r)) => {
                            let _ = out.send(GatewayEvent::Rejected(r)).await;
                        }
                        Err(_) => {
                            let _ = out
                                .send(GatewayEvent::Rejected(Rejection {
                                    status: 408,
                                    reason: "handshake timeout".into(),
                                }))
                                .await;
                        }
                    }
                });
            }
        })
    }
}

struct Request {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
}

async fn read_request(s: &mut BufReader<TcpStream>) -> std::io::Result<Option<Request>> {
    let mut total = 0usize;
    let mut first: Option<String> = None;
    let mut headers = BTreeMap::new();
    loop {
        let mut line = Vec::new();
        let n = (&mut *s).take(8 * 1024).read_until(b'\n', &mut line).await?;
        if n == 0 {
            return Ok(None);
        }
        total += n;
        if total > 16 * 1024 {
            return Ok(None);
        }
        let text = String::from_utf8_lossy(&line).trim_end().to_string();
        if first.is_none() {
            first = Some(text);
            continue;
        }
        if text.is_empty() {
            break;
        }
        if let Some((k, v)) = text.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let first = first.unwrap_or_default();
    let mut parts = first.split_whitespace();
    let (method, target) = (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("").to_string());
    let path = target.split('?').next().unwrap_or("").to_string();
    Ok(Some(Request { method, path, headers }))
}

async fn respond(s: &mut BufReader<TcpStream>, status: u16, reason: &str) {
    let text = match status {
        200 => "OK",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        426 => "Upgrade Required",
        _ => "Bad Request",
    };
    let body = format!("{reason}\n");
    let head = format!(
        "HTTP/1.1 {status} {text}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = s.get_mut().write_all(head.as_bytes()).await;
    let _ = s.get_mut().shutdown().await;
}

enum Conn {
    Raw(BufReader<TcpStream>),
    Ws(Box<WebSocketStream<TcpStream>>),
}

fn now_unix() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Authenticate + upgrade. `Ok(None)`: served a non-ACP request (health check).
async fn handshake(
    stream: TcpStream,
    cfg: &GatewayConfig,
    nonces: &Mutex<HashMap<String, i64>>,
    phase: &watch::Receiver<EnvironmentPhase>,
) -> Result<Option<Conn>, Rejection> {
    let _ = stream.set_nodelay(true);
    let mut s = BufReader::new(stream);
    let reject = |status: u16, reason: &str| Rejection { status, reason: reason.to_string() };
    let req = match read_request(&mut s).await {
        Ok(Some(r)) => r,
        _ => return Err(reject(400, "malformed request")),
    };
    if req.path == "/healthz" {
        respond(&mut s, 200, "ok").await;
        return Ok(None);
    }
    if req.path != ACP_PATH {
        respond(&mut s, 404, "not found").await;
        return Err(reject(404, "unknown path"));
    }
    if req.method != "GET" {
        respond(&mut s, 405, "method not allowed").await;
        return Err(reject(405, "method not allowed"));
    }
    let Some(tok) = req.headers.get("authorization").and_then(|a| a.strip_prefix("Bearer ")).map(str::trim) else {
        respond(&mut s, 401, "missing connection ticket").await;
        return Err(reject(401, "missing connection ticket"));
    };
    let now = now_unix();
    let claims = match ticket::verify(&cfg.key, tok, cfg.environment_id, GATEWAY_AUDIENCE, now) {
        Ok(c) => c,
        Err(e) => {
            let status = match e {
                TicketError::WrongEnvironment | TicketError::WrongAudience => 403,
                _ => 401,
            };
            let reason = match e {
                // A ticket of another environment is MAC'd with another key.
                TicketError::BadSignature => "ticket is not valid for this environment".to_string(),
                other => other.to_string(),
            };
            respond(&mut s, status, &reason).await;
            return Err(reject(status, &reason));
        }
    };
    // Phase first: a ticket presented while the environment cannot accept a caller is not
    // consumed, so the client can retry with it once the environment is ready.
    let ph = *phase.borrow();
    if ph.is_terminal() || ph == EnvironmentPhase::Finishing || ph == EnvironmentPhase::Creating {
        respond(&mut s, 409, &format!("environment is {ph}")).await;
        return Err(reject(409, "environment not accepting connections"));
    }
    let replayed = {
        let mut n = nonces.lock().expect("nonces");
        n.retain(|_, exp| *exp > now);
        n.insert(claims.nonce.clone(), claims.exp).is_some()
    };
    if replayed {
        respond(&mut s, 401, "ticket already used").await;
        return Err(reject(401, "ticket already used"));
    }
    let upgrade = req.headers.get("upgrade").map(|u| u.to_ascii_lowercase()).unwrap_or_default();
    let extra = format!(
        "{HDR_ENVIRONMENT}: {}\r\n{HDR_WORKDIR}: {}\r\n{HDR_PHASE}: {}\r\n",
        cfg.environment_id,
        cfg.workdir,
        ph.as_str()
    );
    if upgrade == RAW_UPGRADE {
        let head =
            format!("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: {RAW_UPGRADE}\r\n{extra}\r\n");
        s.get_mut().write_all(head.as_bytes()).await.map_err(|e| reject(400, &e.to_string()))?;
        return Ok(Some(Conn::Raw(s)));
    }
    if upgrade == "websocket" {
        let Some(key) = req.headers.get("sec-websocket-key") else {
            respond(&mut s, 400, "missing Sec-WebSocket-Key").await;
            return Err(reject(400, "missing Sec-WebSocket-Key"));
        };
        let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
        let head = format!(
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n{extra}\r\n"
        );
        s.get_mut().write_all(head.as_bytes()).await.map_err(|e| reject(400, &e.to_string()))?;
        let leftover = s.buffer().to_vec();
        let mut wcfg = WebSocketConfig::default();
        wcfg.max_message_size = Some(MAX_MESSAGE_BYTES);
        wcfg.max_frame_size = Some(MAX_MESSAGE_BYTES);
        let ws = WebSocketStream::from_partially_read(s.into_inner(), leftover, Role::Server, Some(wcfg)).await;
        return Ok(Some(Conn::Ws(Box::new(ws))));
    }
    respond(&mut s, 426, "use Upgrade: acp-ndjson or websocket").await;
    Err(reject(426, "no supported upgrade"))
}

/// Make one line of newline-delimited JSON-RPC out of a WebSocket message without parsing it.
/// In valid JSON a raw CR/LF can only be insignificant whitespace between tokens (inside a
/// string it must be escaped), so replacing it with a space keeps the message exactly as sent
/// otherwise: key order, number spelling, escapes and duplicate keys are untouched.
fn ws_to_line(text: &str) -> Option<String> {
    if !text.contains(['\n', '\r']) {
        return Some(text.to_string());
    }
    Some(text.replace(['\n', '\r'], " "))
}

impl Conn {
    fn into_caller(self, id: u64) -> Caller {
        let (to_caller_tx, mut to_caller_rx) = mpsc::channel::<String>(1024);
        let (from_caller_tx, from_caller_rx) = mpsc::channel::<String>(1024);
        match self {
            Conn::Raw(s) => {
                let (rd, mut wr) = tokio::io::split(s);
                let writer = tokio::spawn(async move {
                    while let Some(mut m) = to_caller_rx.recv().await {
                        m.push('\n');
                        if wr.write_all(m.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                    let _ = wr.shutdown().await;
                });
                let reader = tokio::spawn(async move {
                    let mut rd = BufReader::new(rd);
                    loop {
                        let mut buf = Vec::new();
                        match (&mut rd).take(MAX_MESSAGE_BYTES as u64 + 1).read_until(b'\n', &mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) if n > MAX_MESSAGE_BYTES => break,
                            Ok(_) => {}
                        }
                        // Relay unchanged or not at all (no lossy conversion).
                        let Ok(text) = String::from_utf8(buf) else { break };
                        let line = text.trim_end_matches(['\r', '\n']).to_string();
                        if line.trim().is_empty() {
                            continue;
                        }
                        if from_caller_tx.send(line).await.is_err() {
                            break;
                        }
                    }
                });
                Caller {
                    id,
                    transport: "acp-ndjson",
                    rx: from_caller_rx,
                    tx: to_caller_tx,
                    tasks: vec![writer, reader],
                }
            }
            Conn::Ws(ws) => {
                let (mut sink, mut stream) = (*ws).split();
                let writer = tokio::spawn(async move {
                    while let Some(m) = to_caller_rx.recv().await {
                        if sink.send(Message::text(m)).await.is_err() {
                            break;
                        }
                    }
                    let _ = sink.send(Message::Close(None)).await;
                });
                let reader = tokio::spawn(async move {
                    while let Some(Ok(m)) = stream.next().await {
                        let line = match m {
                            Message::Text(t) => ws_to_line(t.as_str()),
                            Message::Binary(b) => match std::str::from_utf8(&b) {
                                Ok(t) => ws_to_line(t),
                                Err(_) => break,
                            },
                            Message::Close(_) => break,
                            _ => continue,
                        };
                        if let Some(line) = line
                            && !line.trim().is_empty()
                            && from_caller_tx.send(line).await.is_err()
                        {
                            break;
                        }
                    }
                });
                Caller { id, transport: "websocket", rx: from_caller_rx, tx: to_caller_tx, tasks: vec![writer, reader] }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_frames_become_single_lines_without_rewriting_json() {
        assert_eq!(ws_to_line(r#"{"a":1}"#).unwrap(), r#"{"a":1}"#);
        assert_eq!(ws_to_line("{\n \"a\": 1\r\n}").unwrap(), "{  \"a\": 1  }");
        // no canonicalization: key order, number spelling, escapes and duplicates survive
        let odd = "{\"z\":1.50,\n\"a\":\"\\u00e4\",\"a\":2,\"n\":1e3}";
        assert_eq!(ws_to_line(odd).unwrap(), odd.replace('\n', " "));
    }
}
