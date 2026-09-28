//! kube-runtime controller: AgentEnvironment -> EnvironmentProvider -> status.
//!
//! * First reconcile: `create_in(owner = the resource)`; idempotent per resource (the
//!   provider returns the existing environment of that owner, under a run lock).
//! * Later reconciles: `get` (refresh: phase, gateway endpoint, heartbeat loss, final
//!   artifact) mapped into status; `spec.lifecycle: finish|cancel` is acted on once.
//! * Terminal: `cleanup` until the sandbox is gone and the lease released (fencing).
//! * Deletion (finalizer): cancel, then `cleanup` until done.
//!
//! Connection tickets are never written to status. Callers obtain one from the provider
//! (`acp-runnerctl env ticket`, or an API built on `EnvironmentProvider::connect`), signed with
//! the provider master key (`ACP_RUNNER_TICKET_KEY_FILE`, a mounted Secret — stable across
//! controller restarts and shared by replicas).

use acp_runner_engine::backend::RunKey;
use acp_runner_engine::environment::{EnvironmentProvider, EnvironmentView};
use acp_runner_k8s::crds::{
    AgentEnvironment, AgentEnvironmentStatus, ENV_FINALIZER, EnvArtifactRef, EnvConnection, EnvLineage, FailureStatus,
    StatusHarness,
};
use futures::StreamExt;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::finalizer::{Event, finalizer};
use kube::runtime::watcher;
use kube::{Client, ResourceExt};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

pub struct Ctx {
    pub client: Client,
    pub provider: Arc<EnvironmentProvider>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("kubernetes: {0}")]
    Kube(#[from] kube::Error),
    #[error("provider: {0}")]
    Provider(String),
    #[error("finalizer: {0}")]
    Finalizer(String),
}

const ACTIVE_REQUEUE: Duration = Duration::from_secs(5);
const CLEANUP_REQUEUE: Duration = Duration::from_secs(2);

pub async fn run(client: Client, provider: Arc<EnvironmentProvider>, namespace: Option<String>) {
    let envs: Api<AgentEnvironment> = match &namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let ctx = Arc::new(Ctx { client, provider });
    Controller::new(envs, watcher::Config::default())
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            if let Err(e) = res {
                tracing::debug!(error = %e, "environment reconcile loop error");
            }
        })
        .await;
}

fn error_policy(env: Arc<AgentEnvironment>, err: &Error, _ctx: Arc<Ctx>) -> Action {
    tracing::warn!(environment = %env.name_any(), error = %err, "environment reconcile failed; requeueing");
    Action::requeue(Duration::from_secs(10))
}

async fn reconcile(env: Arc<AgentEnvironment>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let ns = env.namespace().unwrap_or_else(|| "default".into());
    let api: Api<AgentEnvironment> = Api::namespaced(ctx.client.clone(), &ns);
    finalizer(&api, ENV_FINALIZER, env, |event| async {
        match event {
            Event::Apply(env) => apply(env, ctx.clone()).await,
            Event::Cleanup(env) => cleanup(env, ctx.clone()).await,
        }
    })
    .await
    .map_err(|e| Error::Finalizer(e.to_string()))
}

fn owner(env: &AgentEnvironment) -> RunKey {
    RunKey { namespace: env.namespace().unwrap_or_default(), name: env.name_any(), uid: env.uid().unwrap_or_default() }
}

fn env_id(env: &AgentEnvironment) -> Option<Uuid> {
    env.status.as_ref().and_then(|s| s.environment_id.as_deref()).and_then(|s| s.parse().ok())
}

/// The environment id from status, or — when a status update was lost or overwritten —
/// from the journal (the run of this resource's uid).
async fn resolve_id(env: &AgentEnvironment, ctx: &Ctx) -> Result<Option<Uuid>, Error> {
    if let Some(id) = env_id(env) {
        return Ok(Some(id));
    }
    ctx.provider
        .environment_for_owner(&env.uid().unwrap_or_default())
        .await
        .map_err(|e| Error::Provider(format!("{e:#}")))
}

async fn apply(env: Arc<AgentEnvironment>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let generation = env.metadata.generation;
    let id = match resolve_id(&env, &ctx).await? {
        Some(id) => id,
        None => {
            let spec = match env.spec.to_core() {
                Ok(s) => s,
                Err(e) => {
                    let status = AgentEnvironmentStatus {
                        phase: Some("Failed".into()),
                        failure_reason: Some(FailureStatus { code: "Unsupported".into(), message: e }),
                        observed_generation: generation,
                        ..Default::default()
                    };
                    patch_status(&ctx.client, &env, &status).await?;
                    return Ok(Action::await_change());
                }
            };
            match ctx.provider.create_in(Some(owner(&env)), spec).await {
                Ok(view) => {
                    tracing::info!(environment = %env.name_any(), environment_id = %view.id, "environment created");
                    let status = to_status(&view, &env, generation);
                    patch_status(&ctx.client, &env, &status).await?;
                    return Ok(Action::requeue(ACTIVE_REQUEUE));
                }
                Err(e) => {
                    let status = AgentEnvironmentStatus {
                        phase: Some("Pending".into()),
                        message: Some(format!("{e:#}")),
                        observed_generation: generation,
                        ..Default::default()
                    };
                    patch_status(&ctx.client, &env, &status).await?;
                    return Ok(Action::requeue(Duration::from_secs(15)));
                }
            }
        }
    };
    let Some(view) = ctx.provider.get(id).await.map_err(|e| Error::Provider(format!("{e:#}")))? else {
        let status = AgentEnvironmentStatus {
            phase: Some("Failed".into()),
            environment_id: Some(id.to_string()),
            failure_reason: Some(FailureStatus {
                code: "Internal".into(),
                message: "environment is unknown to the provider (journal reset?)".into(),
            }),
            observed_generation: generation,
            ..Default::default()
        };
        patch_status(&ctx.client, &env, &status).await?;
        return Ok(Action::await_change());
    };
    let mut status = to_status(&view, &env, generation);
    // spec.lifecycle: finish / cancel, acted on once
    let requested = env.spec.lifecycle.clone().filter(|l| l == "finish" || l == "cancel");
    let already = env.status.as_ref().and_then(|s| s.lifecycle_requested.clone());
    if let Some(l) = &requested
        && already.as_ref() != Some(l)
        && !view.phase.is_terminal()
    {
        ctx.provider
            .request_end(id, l == "finish", "spec.lifecycle=cancel")
            .await
            .map_err(|e| Error::Provider(format!("{e:#}")))?;
        tracing::info!(environment = %env.name_any(), lifecycle = %l, "environment end requested");
        status.lifecycle_requested = Some(l.clone());
    }
    let terminal = view.phase.is_terminal();
    let cleaned =
        if terminal { ctx.provider.cleanup(id).await.map_err(|e| Error::Provider(format!("{e:#}")))? } else { false };
    if terminal && !cleaned {
        status.message = Some("waiting for the sandbox to terminate before releasing the credential lease".into());
    }
    if env.status.as_ref() != Some(&status) {
        patch_status(&ctx.client, &env, &status).await?;
    }
    Ok(match (terminal, cleaned) {
        (true, true) => Action::await_change(),
        (true, false) => Action::requeue(CLEANUP_REQUEUE),
        _ => Action::requeue(ACTIVE_REQUEUE),
    })
}

async fn cleanup(env: Arc<AgentEnvironment>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let Some(id) = resolve_id(&env, &ctx).await? else { return Ok(Action::await_change()) };
    // No graceful finish on delete: the sandbox is terminated; the finalizer stays until it
    // is gone and the credential lease is released (fencing).
    if !ctx.provider.force_end(id, "AgentEnvironment deleted").await.map_err(|e| Error::Provider(format!("{e:#}")))? {
        return Err(Error::Provider("sandbox still terminating".into()));
    }
    tracing::info!(environment = %env.name_any(), "AgentEnvironment deleted; sandbox terminated and lease released");
    Ok(Action::await_change())
}

async fn patch_status(client: &Client, env: &AgentEnvironment, status: &AgentEnvironmentStatus) -> Result<(), Error> {
    let api: Api<AgentEnvironment> = Api::namespaced(client.clone(), &env.namespace().unwrap_or_default());
    let patch = serde_json::json!({"status": status});
    api.patch_status(&env.name_any(), &PatchParams::default(), &Patch::Merge(&patch)).await?;
    Ok(())
}

pub fn to_status(v: &EnvironmentView, env: &AgentEnvironment, generation: Option<i64>) -> AgentEnvironmentStatus {
    let prev = env.status.as_ref();
    AgentEnvironmentStatus {
        phase: Some(v.phase.as_str().to_string()),
        environment_id: Some(v.id.to_string()),
        harness: Some(StatusHarness {
            name: v.harness.clone(),
            version: env.spec.harness.version.clone(),
            digest: env.spec.harness.digest.clone(),
        }),
        resolved_revision: v.base_revision.clone(),
        workdir: Some(v.workdir.clone()),
        connection: v.connection.as_ref().map(|c| EnvConnection { gateway: c.gateway.clone() }),
        lineage: (!v.lineage.is_empty()).then(|| EnvLineage {
            parent_artifact_id: v.lineage.parent_artifact_id.map(|u| u.to_string()),
            parent_environment_id: v.lineage.parent_environment_id.map(|u| u.to_string()),
        }),
        last_heartbeat_time: prev.and_then(|s| s.last_heartbeat_time.clone()),
        last_progress_time: prev.and_then(|s| s.last_progress_time.clone()),
        latest_snapshot_ref: v.snapshots.last().map(|s| EnvArtifactRef {
            artifact_id: s.artifact_id.to_string(),
            sha256: Some(s.sha256.clone()),
            base_revision: v.base_revision.clone(),
        }),
        final_artifact_ref: v.final_artifact_id.map(|id| EnvArtifactRef {
            artifact_id: id.to_string(),
            sha256: None,
            base_revision: v.base_revision.clone(),
        }),
        failure_reason: v.failure.as_ref().map(|f| FailureStatus { code: f.code().to_string(), message: f.message() }),
        observed_generation: generation,
        lifecycle_requested: prev.and_then(|s| s.lifecycle_requested.clone()),
        message: None,
    }
}
