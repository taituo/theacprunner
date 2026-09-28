//! Ingest API used by runnerd inside the sandbox.
//!
//! Authentication: `Authorization: Bearer <per-attempt token>`. Only the SHA-256 of the
//! token is stored. A token is valid only while its attempt is active and only for that
//! attempt; it cannot read other attempts, runs or credentials. Everything a runner submits
//! is treated as untrusted input: kinds are restricted, payloads are re-redacted, artifact
//! sizes and hashes are verified, credential write-backs are validated against the enrolled
//! profile (same provider, same account, no API keys).
//!
//! | method | path                     | purpose                                  |
//! |--------|--------------------------|------------------------------------------|
//! | GET    | /v1/attempt              | fetch the AttemptSpec                    |
//! | POST   | /v1/attempt/events       | append normalized events (idempotent)    |
//! | POST   | /v1/attempt/heartbeat    | liveness; reply may carry a directive    |
//! | POST   | /v1/attempt/artifact     | upload the patch artifact                |
//! | POST   | /v1/attempt/credential   | hand back a refreshed credential file    |
//! | GET    | /v1/attempt/overlay/{id} | environment bootstrap: overlay patch     |
//! | GET    | /v1/attempt/bundle/{d}   | environment bootstrap: bundle by digest  |
//! | GET    | /v1/attempt/harness/{d}  | environment bootstrap: harness artifact  |
//!
//! Bootstrap downloads are authorized per item: only what the attempt's own spec pins can
//! be fetched with its token (runnerd verifies digests again before using anything).

use crate::backend::RunKey;
use crate::creds::CredentialStore;
use crate::metrics::Metrics;
use crate::{record_attempt_finished, token_hash};
use acp_runner_core::credentials::{CredentialMetadata, Provider, fingerprint, validate_writeback};
use acp_runner_core::events::{
    AttemptTerminalData, ChangedPath, EventEnvelope, EventKind, EventSource, HeartbeatReply, RunnerDirective,
};
use acp_runner_core::failure::FailureReason;
use acp_runner_core::redact::Redactor;
use acp_runner_core::{AttemptPhase, AttemptSpec, WIRE_VERSION};
use acp_runner_journal::{ArtifactStore, AttemptRow, Journal, JournalError, NewArtifact};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use uuid::Uuid;

pub const WIRE_HEADER: &str = "x-acp-runner-wire-version";
pub const MAX_BODY_BYTES: usize = 96 * 1024 * 1024;
const MAX_EVENTS_PER_BATCH: usize = 1000;

pub struct IngestState {
    pub journal: Journal,
    pub artifacts: Arc<dyn ArtifactStore>,
    pub creds: Arc<dyn CredentialStore>,
    pub metrics: Arc<Metrics>,
    /// Triggers an immediate reconcile of the run after terminal reports.
    pub notify: Option<UnboundedSender<RunKey>>,
    pub heartbeat_journal_every: Duration,
    /// Environment provider operations pending delivery to runnerd on the next heartbeat,
    /// keyed by attempt id. Snapshot/Finish/Cancel travel controller -> runnerd this way.
    /// Serves pinned harness artifacts to environment bootstraps.
    pub harnesses: Option<Arc<dyn crate::harness::HarnessProvider>>,
    /// Each heartbeat extends the attempt's credential lease to at least now + this window.
    pub lease_heartbeat_window: Duration,
    redactor: Redactor,
    /// Verifies refreshed Codex credentials at the provider before they are stored. Without
    /// it, Codex write-backs are refused (fail closed).
    pub refresher: Option<Arc<dyn crate::codex_refresh::TokenRefresher>>,
}

impl IngestState {
    pub fn new(
        journal: Journal,
        artifacts: Arc<dyn ArtifactStore>,
        creds: Arc<dyn CredentialStore>,
        metrics: Arc<Metrics>,
        notify: Option<UnboundedSender<RunKey>>,
    ) -> Self {
        IngestState {
            journal,
            artifacts,
            creds,
            metrics,
            notify,
            heartbeat_journal_every: Duration::from_secs(60),
            harnesses: None,
            lease_heartbeat_window: Duration::from_secs(15 * 60),
            redactor: Redactor::new(),
            refresher: None,
        }
    }

    pub fn with_refresher(mut self, r: Arc<dyn crate::codex_refresh::TokenRefresher>) -> Self {
        self.refresher = Some(r);
        self
    }

    pub fn with_harnesses(mut self, h: Arc<dyn crate::harness::HarnessProvider>) -> Self {
        self.harnesses = Some(h);
        self
    }
}

pub fn router(state: Arc<IngestState>) -> Router {
    Router::new()
        .route("/v1/attempt", get(get_spec))
        .route("/v1/attempt/events", post(post_events))
        .route("/v1/attempt/heartbeat", post(post_heartbeat))
        .route("/v1/attempt/artifact", post(post_artifact))
        .route("/v1/attempt/credential", post(post_credential))
        .route("/v1/attempt/overlay/{id}", get(get_overlay))
        .route("/v1/attempt/bundle/{digest}", get(get_bundle))
        .route("/v1/attempt/harness/{digest}", get(get_harness))
        .route("/healthz", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

impl From<JournalError> for ApiError {
    fn from(e: JournalError) -> Self {
        tracing::error!(error = %e, "ingest journal error");
        ApiError(StatusCode::SERVICE_UNAVAILABLE, "journal unavailable".into())
    }
}

type ApiResult<T> = Result<T, ApiError>;

async fn authenticate(st: &IngestState, headers: &HeaderMap, allow_pending: bool) -> ApiResult<AttemptRow> {
    if let Some(v) = headers.get(WIRE_HEADER).and_then(|v| v.to_str().ok())
        && v != WIRE_VERSION.to_string()
    {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            format!("wire version {v} unsupported (controller speaks {WIRE_VERSION})"),
        ));
    }
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "missing bearer token".into()))?;
    if token.len() < 32 {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid token".into()));
    }
    let a = st
        .journal
        .attempt_by_token_hash(&token_hash(token))
        .await?
        .ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "unknown token".into()))?;
    let ok = match a.phase() {
        AttemptPhase::Starting | AttemptPhase::Running => true,
        AttemptPhase::Pending => allow_pending,
        _ => false,
    };
    if !ok {
        return Err(ApiError(StatusCode::CONFLICT, format!("attempt is {}", a.phase)));
    }
    Ok(a)
}

/// How long after an attempt ended its runnerd may still hand a refreshed credential back
/// (the controller may end an attempt — cancel, timeout — before runnerd's own shutdown path
/// runs). The attempt must still hold its unreleased lease.
/// An unacknowledged directive is sent again after this long.
pub const DIRECTIVE_REDELIVERY: Duration = Duration::from_secs(10);

pub const WRITEBACK_GRACE: Duration = Duration::from_secs(600);

/// Like [`authenticate`], but also accepts a recently finished attempt (see [`WRITEBACK_GRACE`]).
async fn authenticate_for_writeback(st: &IngestState, headers: &HeaderMap) -> ApiResult<AttemptRow> {
    match authenticate(st, headers, false).await {
        Err(ApiError(StatusCode::CONFLICT, _)) => {}
        other => return other,
    }
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "missing bearer token".into()))?;
    let a = st
        .journal
        .attempt_by_token_hash(&token_hash(token))
        .await?
        .ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "unknown token".into()))?;
    let recent = a
        .finished_at
        .is_some_and(|f| chrono::Utc::now().signed_duration_since(f).to_std().is_ok_and(|d| d <= WRITEBACK_GRACE));
    if a.phase().is_terminal() && recent {
        Ok(a)
    } else {
        Err(ApiError(StatusCode::CONFLICT, format!("attempt is {}", a.phase)))
    }
}

async fn get_spec(State(st): State<Arc<IngestState>>, headers: HeaderMap) -> ApiResult<Json<serde_json::Value>> {
    let a = authenticate(&st, &headers, true).await?;
    Ok(Json(a.spec))
}

fn attempt_spec(a: &AttemptRow) -> ApiResult<AttemptSpec> {
    serde_json::from_value(a.spec.clone()).map_err(|_| ApiError(StatusCode::CONFLICT, "attempt spec unreadable".into()))
}

async fn get_overlay(
    State(st): State<Arc<IngestState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> ApiResult<Response> {
    let a = authenticate(&st, &headers, true).await?;
    let spec = attempt_spec(&a)?;
    if !spec.bootstrap.overlays.iter().any(|o| o.artifact_id == id) {
        return Err(ApiError(StatusCode::FORBIDDEN, "overlay is not part of this attempt".into()));
    }
    let bytes = st.artifacts.get_content(id).await?; // verifies the stored sha256
    Ok(([(axum::http::header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
}

async fn get_bundle(
    State(st): State<Arc<IngestState>>,
    headers: HeaderMap,
    axum::extract::Path(digest): axum::extract::Path<String>,
) -> ApiResult<Response> {
    let a = authenticate(&st, &headers, true).await?;
    let spec = attempt_spec(&a)?;
    if !spec.bootstrap.bundles.iter().any(|b| b.digest == digest) {
        return Err(ApiError(StatusCode::FORBIDDEN, "bundle is not part of this attempt".into()));
    }
    let b = st
        .journal
        .get_bundle(&digest)
        .await?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "bundle not stored".into()))?;
    Ok(Json(b).into_response())
}

async fn get_harness(
    State(st): State<Arc<IngestState>>,
    headers: HeaderMap,
    axum::extract::Path(digest): axum::extract::Path<String>,
) -> ApiResult<Response> {
    let a = authenticate(&st, &headers, true).await?;
    let spec = attempt_spec(&a)?;
    if spec.bootstrap.harness.as_ref().map(|h| h.digest.as_str()) != Some(digest.as_str()) {
        return Err(ApiError(StatusCode::FORBIDDEN, "harness is not part of this attempt".into()));
    }
    let Some(hp) = st.harnesses.clone() else {
        return Err(ApiError(StatusCode::NOT_FOUND, "no harness provider configured".into()));
    };
    let path = hp.open(&digest).await.map_err(|e| ApiError(StatusCode::NOT_FOUND, e.to_string()))?;
    let file = tokio::fs::File::open(&path).await.map_err(|e| ApiError(StatusCode::NOT_FOUND, e.to_string()))?;
    let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
    let body = axum::body::Body::from_stream(tokio_util_stream(file));
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (axum::http::header::CONTENT_LENGTH, len.to_string()),
        ],
        body,
    )
        .into_response())
}

/// Stream a file in chunks (no extra dependency on tokio-util).
fn tokio_util_stream(
    mut file: tokio::fs::File,
) -> impl futures::Stream<Item = Result<Vec<u8>, std::io::Error>> + Send + 'static {
    futures::stream::poll_fn(move |cx| {
        use tokio::io::AsyncRead;
        let mut buf = vec![0u8; 256 * 1024];
        let mut rb = tokio::io::ReadBuf::new(&mut buf);
        match std::pin::Pin::new(&mut file).poll_read(cx, &mut rb) {
            std::task::Poll::Ready(Ok(())) => {
                let n = rb.filled().len();
                if n == 0 {
                    std::task::Poll::Ready(None)
                } else {
                    buf.truncate(n);
                    std::task::Poll::Ready(Some(Ok(buf)))
                }
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Some(Err(e))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    })
}

#[derive(Deserialize)]
struct EventBatch {
    events: Vec<EventEnvelope>,
}

#[derive(Serialize)]
struct Accepted {
    accepted: usize,
}

fn run_key_of(journal_run: &acp_runner_journal::RunRow) -> RunKey {
    RunKey {
        namespace: journal_run.k8s_namespace.clone(),
        name: journal_run.k8s_name.clone(),
        uid: journal_run.k8s_uid.clone(),
    }
}

async fn post_events(
    State(st): State<Arc<IngestState>>,
    headers: HeaderMap,
    Json(mut batch): Json<EventBatch>,
) -> ApiResult<Json<Accepted>> {
    let a = authenticate(&st, &headers, true).await?;
    if batch.events.len() > MAX_EVENTS_PER_BATCH {
        return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE, "too many events in batch".into()));
    }
    for ev in &mut batch.events {
        if !ev.kind.runner_may_emit() {
            return Err(ApiError(StatusCode::BAD_REQUEST, format!("runner may not emit {}", ev.kind)));
        }
        // Defense in depth: runnerd never forwards these from agentd, and the ingest refuses
        // them as well — an agent claim can never become a terminal state, artifact or
        // heartbeat.
        if matches!(ev.source, EventSource::Agent | EventSource::Driver) && !ev.kind.agent_may_emit() {
            return Err(ApiError(StatusCode::BAD_REQUEST, format!("agent-sourced {} is not accepted", ev.kind)));
        }
        if matches!(ev.source, EventSource::Agent | EventSource::Driver)
            && ev.kind == EventKind::Progress
            && ev
                .data
                .get("category")
                .and_then(|c| c.as_str())
                .is_some_and(acp_runner_core::events::is_runner_owned_category)
        {
            return Err(ApiError(
                StatusCode::BAD_REQUEST,
                "agent-sourced progress uses a runner-owned category".into(),
            ));
        }
        if ev.seq.is_none() {
            return Err(ApiError(StatusCode::BAD_REQUEST, "events must carry seq".into()));
        }
        if ev.source == EventSource::Controller {
            ev.source = EventSource::Runnerd;
        }
        st.redactor.redact_json(&mut ev.data);
        if let Some(raw) = ev.raw.as_mut() {
            st.redactor.redact_json(raw);
        }
    }
    let accepted = st.journal.append_events(a.run_id, Some(a.id), &batch.events).await?;
    // Agent progress (second liveness signal, next to runnerd heartbeats): only events that
    // come from the agent, plus runnerd's report that the agent started / got its input.
    if batch.events.iter().any(|e| {
        (matches!(e.source, EventSource::Agent | EventSource::Driver) && e.kind.counts_as_progress())
            || matches!(e.kind, EventKind::AgentStarted | EventKind::InputSent)
    }) {
        st.journal.touch_progress(a.id, chrono::Utc::now()).await?;
    }
    for id in batch.events.iter().filter_map(|e| {
        (e.kind == EventKind::Progress
            && e.source == EventSource::Runnerd
            && e.data.get("category").and_then(|c| c.as_str()) == Some("directive_ack"))
        .then(|| e.data.pointer("/detail/directiveId").and_then(|v| v.as_str()).and_then(|s| s.parse::<Uuid>().ok()))
        .flatten()
    }) {
        st.journal.ack_directive(a.id, id).await?;
    }
    if let Some(ev) = batch.events.iter().find(|e| e.kind == EventKind::AgentStarted) {
        st.journal
            .transition_attempt(
                a.id,
                &[AttemptPhase::Pending, AttemptPhase::Starting],
                AttemptPhase::Running,
                None,
                None,
            )
            .await?;
        let s = |k: &str| ev.data.get(k).and_then(|v| v.as_str()).map(str::to_string);
        let version = [s("cliVersion"), s("adapterVersion")].into_iter().flatten().collect::<Vec<_>>().join(" / ");
        if !version.is_empty() {
            st.journal.set_attempt_details(a.id, Some(&version), None, None).await?;
        }
    }
    if let Some(rev) = batch.events.iter().find_map(|e| {
        (e.kind == EventKind::Progress
            && e.source == EventSource::Runnerd
            && e.data.get("category").and_then(|c| c.as_str()) == Some("workspace_ready"))
        .then(|| e.data.pointer("/detail/baseRevision").and_then(|r| r.as_str()).map(str::to_string))
        .flatten()
    }) && acp_runner_core::spec::is_safe_revision(&rev)
    {
        st.journal.set_attempt_details(a.id, None, Some(&rev), None).await?;
    }
    if let Some(term) = batch.events.iter().find(|e| e.kind.is_attempt_terminal()) {
        let mut data: AttemptTerminalData = serde_json::from_value(term.data.clone()).unwrap_or(AttemptTerminalData {
            reason: Some(FailureReason::internal("unparseable terminal event")),
            stop_reason: None,
            summary: None,
            artifact_id: None,
        });
        // The artifact a terminal report names must be one this attempt uploaded itself;
        // otherwise a runner could make its run point at another run's patch.
        let mut foreign = false;
        if let Some(id) = data.artifact_id
            && !artifact_belongs_to(&st, id, &a).await?
        {
            tracing::warn!(attempt_id = %a.id, artifact_id = %id, "terminal report names a foreign artifact");
            foreign = true;
            data.artifact_id = None;
            data.reason = Some(FailureReason::ProtocolError {
                detail: "terminal report names an artifact that this attempt did not upload".into(),
            });
        }
        let phase = match term.kind {
            EventKind::AttemptCompleted if !foreign => AttemptPhase::Succeeded,
            EventKind::AttemptTimedOut => AttemptPhase::TimedOut,
            _ => match &data.reason {
                Some(FailureReason::Cancelled { .. }) => AttemptPhase::Cancelled,
                _ => AttemptPhase::Failed,
            },
        };
        let reason = match (phase, data.reason.clone()) {
            (AttemptPhase::Succeeded, _) => None,
            (_, Some(r)) => Some(r),
            (_, None) => Some(FailureReason::internal("runner reported failure without reason")),
        };
        let outcome = json!({"stopReason": data.stop_reason, "summary": data.summary});
        if st.journal.transition_attempt(a.id, &AttemptPhase::ACTIVE, phase, reason.as_ref(), Some(&outcome)).await? {
            if let Some(id) = data.artifact_id {
                st.journal.set_attempt_details(a.id, None, None, Some(id)).await?;
            }
            record_attempt_finished(&st.metrics, &a, phase, reason.as_ref());
            tracing::info!(run_id = %a.run_id, attempt_id = %a.id, driver = %a.driver, phase = %phase,
                reason = ?reason.as_ref().map(|r| r.code()), "attempt reported terminal state");
            if let Some(n) = &st.notify
                && let Ok(run) = st.journal.get_run(a.run_id).await
            {
                let _ = n.send(run_key_of(&run));
            }
        }
    }
    Ok(Json(Accepted { accepted }))
}

/// Does artifact `id` exist and belong to attempt `a` (same run, same attempt)?
async fn artifact_belongs_to(st: &IngestState, id: Uuid, a: &AttemptRow) -> ApiResult<bool> {
    match st.artifacts.get_meta(id).await {
        Ok(m) => Ok(m.attempt_id == a.id && m.run_id == a.run_id),
        Err(JournalError::NotFound(_)) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

async fn post_heartbeat(
    State(st): State<Arc<IngestState>>,
    headers: HeaderMap,
    Json(mut hb): Json<serde_json::Value>,
) -> ApiResult<Response> {
    let a = authenticate(&st, &headers, true).await?;
    // A live sandbox keeps its credential lease alive (environment leases span the whole
    // lifetime; a dead sandbox's lease lapses after the window).
    st.journal.extend_lease(a.id, st.lease_heartbeat_window).await?;
    if st.journal.touch_heartbeat_rate_limited(a.id, st.heartbeat_journal_every).await? {
        st.redactor.redact_json(&mut hb);
        let ev = EventEnvelope::new(EventKind::Heartbeat, EventSource::Runnerd, hb);
        st.journal.append_event(a.run_id, Some(a.id), &ev).await?;
    }
    // Controller decisions travel back on the heartbeat (runnerd has no inbound port).
    // A cancel recorded on the attempt wins over anything queued.
    if let Some(reason) = a.cancel_request() {
        let reply = HeartbeatReply { directive: Some(RunnerDirective::Cancel { reason }), directive_id: None };
        return Ok(Json(reply).into_response());
    }
    if let Some((id, raw)) = st.journal.next_directive(a.id, DIRECTIVE_REDELIVERY).await? {
        match serde_json::from_value::<RunnerDirective>(raw) {
            Ok(d) => {
                return Ok(Json(HeartbeatReply { directive: Some(d), directive_id: Some(id) }).into_response());
            }
            Err(e) => {
                tracing::error!(directive_id = %id, error = %e, "undecodable directive dropped");
                st.journal.ack_directive(a.id, id).await?;
            }
        }
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactUpload {
    kind: String,
    base_revision: String,
    sha256: String,
    changed_paths: Vec<ChangedPath>,
    driver: String,
    #[serde(default)]
    driver_version: Option<String>,
    patch_b64: String,
}

async fn post_artifact(
    State(st): State<Arc<IngestState>>,
    headers: HeaderMap,
    Json(up): Json<ArtifactUpload>,
) -> ApiResult<Json<serde_json::Value>> {
    let a = authenticate(&st, &headers, false).await?;
    const KINDS: &[&str] = &["patch", "partial_patch", "snapshot", "final", "partial_final"];
    if !KINDS.contains(&up.kind.as_str()) {
        return Err(ApiError(StatusCode::BAD_REQUEST, format!("unknown artifact kind {:?}", up.kind)));
    }
    if !acp_runner_core::spec::is_safe_revision(&up.base_revision) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid base revision".into()));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(up.patch_b64.as_bytes())
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "patch is not base64".into()))?;
    let limit = serde_json::from_value::<AttemptSpec>(a.spec.clone())
        .map(|s| s.output.max_patch_bytes)
        .unwrap_or(acp_runner_core::spec::DEFAULT_MAX_PATCH_BYTES);
    if bytes.len() as u64 > limit {
        return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE, limit.to_string()));
    }
    for p in &up.changed_paths {
        if acp_runner_core::paths::validate_relative_path(&p.path).is_err() {
            return Err(ApiError(StatusCode::BAD_REQUEST, format!("invalid changed path {:?}", p.path)));
        }
    }
    // Lineage is derived server-side from trusted records, never from the upload.
    let environment_id = st.journal.environment_by_attempt(a.id).await?.map(|e| e.id);
    let lineage =
        serde_json::from_value::<AttemptSpec>(a.spec.clone()).map(|s| s.bootstrap.lineage).unwrap_or_default();
    let meta = NewArtifact {
        environment_id,
        parent_artifact_id: lineage.parent_artifact_id,
        parent_environment_id: lineage.parent_environment_id,
        run_id: a.run_id,
        attempt_id: a.id,
        kind: up.kind,
        base_revision: up.base_revision.clone(),
        sha256: up.sha256,
        changed_paths: up.changed_paths,
        driver: if up.driver == a.driver { up.driver } else { a.driver.clone() },
        driver_version: up.driver_version.clone(),
    };
    let stored = match st.artifacts.put(&meta, &bytes).await {
        Ok(s) => s,
        Err(JournalError::TooLarge { limit, .. }) => {
            return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE, limit.to_string()));
        }
        Err(JournalError::Invalid(m)) => return Err(ApiError(StatusCode::BAD_REQUEST, m)),
        Err(e) => return Err(e.into()),
    };
    st.journal.set_attempt_details(a.id, up.driver_version.as_deref(), Some(&up.base_revision), None).await?;
    Ok(Json(json!({"artifactId": stored.id, "storage": stored.storage})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialWriteback {
    key: String,
    content_b64: String,
}

async fn post_credential(
    State(st): State<Arc<IngestState>>,
    headers: HeaderMap,
    Json(wb): Json<CredentialWriteback>,
) -> ApiResult<StatusCode> {
    let a = authenticate_for_writeback(&st, &headers).await?;
    let reject = |m: String| {
        st.metrics.writeback("rejected");
        tracing::warn!(attempt_id = %a.id, reason = %m, "credential write-back rejected");
        ApiError(StatusCode::UNPROCESSABLE_ENTITY, m)
    };
    let Some(profile) = a.credential_profile.clone() else {
        return Err(reject("attempt holds no credential".into()));
    };
    // Hold the lease row locked until the store is updated: a concurrent release (and
    // therefore the next holder's lease) waits for us.
    let Some(lock) = st.journal.lock_active_lease(a.id).await? else {
        return Err(reject("attempt no longer holds the credential lease".into()));
    };
    let prof = st.journal.get_profile(&profile).await?.ok_or_else(|| reject(format!("profile {profile} unknown")))?;
    let provider: Provider =
        prof.provider.parse().map_err(|e: acp_runner_core::credentials::CredentialError| reject(e.to_string()))?;
    let enrolled: CredentialMetadata = serde_json::from_value(prof.metadata.clone())
        .map_err(|e| reject(format!("stored metadata unreadable: {e}")))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(wb.content_b64.as_bytes())
        .map_err(|_| reject("content is not base64".into()))?;
    if bytes.len() > 256 * 1024 {
        return Err(reject("credential file too large".into()));
    }
    // Structural policy first (key whitelist, no API keys, refreshable auth mode).
    validate_writeback(provider, &enrolled, &wb.key, &bytes).map_err(|e| reject(e.to_string()))?;
    // The submitted file is untrusted: never store it. Redeem its refresh token at the
    // provider, verify the returned id_token and store only what the controller obtained.
    let to_store = match provider {
        Provider::Codex => {
            let Some(refresher) = st.refresher.clone() else {
                return Err(reject("write-back verification is not configured (ACP_RUNNER_CODEX_WRITEBACK)".into()));
            };
            let submitted: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| reject("auth.json is not JSON".into()))?;
            let Some(rt) = submitted.pointer("/tokens/refresh_token").and_then(|v| v.as_str()) else {
                return Err(reject("auth.json has no refresh token".into()));
            };
            let t = refresher.refresh(rt).await.map_err(|e| reject(format!("provider refresh failed: {e}")))?;
            let Some(acct) = t.account_id() else {
                return Err(reject("verified id_token carries no account".into()));
            };
            if enrolled.account_fingerprint.as_deref() != Some(fingerprint(acct.as_bytes()).as_str()) {
                return Err(reject("refreshed credential belongs to another account".into()));
            }
            crate::codex_refresh::rebuild_auth_json(&t)
        }
        Provider::Claude | Provider::Files => {
            return Err(reject(format!("{provider} credentials are not written back")));
        }
    };
    let md = validate_writeback(provider, &enrolled, &wb.key, &to_store).map_err(|e| reject(e.to_string()))?;
    // The provider has already rotated the refresh token: losing these tokens now would leave
    // the profile needing re-enrollment, so concurrent-modification conflicts are retried.
    let mut tries = 0;
    loop {
        match st.creds.update_file(&profile, &wb.key, &to_store, &md).await {
            Ok(()) => break,
            Err(crate::creds::CredStoreError::Conflict(_)) if tries < 4 => {
                tries += 1;
                tokio::time::sleep(Duration::from_millis(200 * tries)).await;
            }
            Err(e) => {
                tracing::error!(profile = %profile, error = %e, "storing verified refreshed credential failed; profile may need re-enrollment");
                return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, format!("credential store: {e}")));
            }
        }
    }
    lock.commit().await?;
    st.journal
        .record_writeback(&profile, &serde_json::to_value(&md).unwrap_or_default(), &fingerprint(&to_store))
        .await?;
    st.metrics.writeback("accepted");
    tracing::info!(attempt_id = %a.id, profile = %profile, "refreshed credential verified at the provider and stored");
    Ok(StatusCode::NO_CONTENT)
}
