//! acp-runner controller.
//!
//! * `run` (default): Kubernetes controller for `ACPRun`, runnerd ingest API, metrics.
//! * `crdgen`: print the CRDs as YAML.
//! * `dev-run`: execute one ACPRun manifest locally (engine + ingest + LocalProcessBackend),
//!   no Kubernetes needed — used for development and demos with the fake driver.

mod controller;
mod dev;

use acp_runner_engine::backend::SandboxBackend;
use acp_runner_engine::creds::{CredentialStore, FileCredentialStore, sync_profiles};
use acp_runner_engine::ingest::{IngestState, router};
use acp_runner_engine::metrics::Metrics;
use acp_runner_engine::{Engine, EngineConfig};
use acp_runner_journal::{ArtifactStore, BlobStore, FsBlobStore, Journal, PgArtifactStore};
use acp_runner_k8s::backends::{AgentSandboxBackend, PodBackend};
use acp_runner_k8s::pod::PodConfig;
use acp_runner_k8s::secret_store::K8sSecretStore;
use anyhow::Context;
use axum::Router;
use axum::routing::get;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "acp-runner-controller", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the controller (default).
    Run(Box<RunArgs>),
    /// Print CustomResourceDefinitions (YAML).
    Crdgen,
    /// Execute one ACPRun manifest locally without Kubernetes.
    DevRun(dev::DevRunArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum BackendKind {
    Pod,
    AgentSandbox,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum CredStoreKind {
    K8s,
    File,
}

#[derive(Args, Clone, Debug)]
pub struct CommonArgs {
    /// PostgreSQL URL.
    #[arg(long, env = "DATABASE_URL")]
    pub database_url: String,
    /// Max PostgreSQL connections.
    #[arg(long, env = "ACP_RUNNER_DB_MAX_CONNECTIONS", default_value_t = 16)]
    pub db_max_connections: u32,
    /// Patches up to this size are stored inline in PostgreSQL.
    #[arg(long, env = "ACP_RUNNER_ARTIFACT_INLINE_LIMIT", default_value_t = 8 * 1024 * 1024)]
    pub artifact_inline_limit: u64,
    /// Optional directory for larger artifacts (FsBlobStore). S3 can be added behind BlobStore.
    #[arg(long, env = "ACP_RUNNER_ARTIFACT_DIR")]
    pub artifact_dir: Option<PathBuf>,
    /// Record raw provider payloads (redacted, capped) in the journal.
    #[arg(long, env = "ACP_RUNNER_RECORD_RAW", default_value_t = true, action = clap::ArgAction::Set)]
    pub record_raw: bool,
}

#[derive(Args, Clone, Debug)]
pub struct RunArgs {
    #[command(flatten)]
    pub common: CommonArgs,
    /// URL runnerd uses to reach this controller's ingest API.
    #[arg(long, env = "ACP_RUNNER_INGEST_URL")]
    pub ingest_url: String,
    #[arg(long, env = "ACP_RUNNER_INGEST_LISTEN", default_value = "0.0.0.0:8081")]
    pub ingest_listen: String,
    #[arg(long, env = "ACP_RUNNER_METRICS_LISTEN", default_value = "0.0.0.0:8080")]
    pub metrics_listen: String,
    /// Unique controller instance id (defaults to POD_NAME / hostname).
    #[arg(long, env = "POD_NAME")]
    pub controller_id: Option<String>,
    #[arg(long, env = "ACP_RUNNER_BACKEND", value_enum, default_value = "pod")]
    pub backend: BackendKind,
    /// Run sandboxes in this namespace instead of the ACPRun's namespace.
    #[arg(long, env = "ACP_RUNNER_AGENT_NAMESPACE")]
    pub agent_namespace: Option<String>,
    /// Only watch ACPRuns in this namespace (default: all namespaces).
    #[arg(long, env = "ACP_RUNNER_WATCH_NAMESPACE")]
    pub watch_namespace: Option<String>,
    #[arg(long, env = "ACP_RUNNER_CREDENTIAL_STORE", value_enum, default_value = "k8s")]
    pub credential_store: CredStoreKind,
    /// Namespace holding credential profile Secrets.
    #[arg(long, env = "ACP_RUNNER_CREDENTIAL_NAMESPACE", default_value = "acp-runner-system")]
    pub credential_namespace: String,
    #[arg(long, env = "ACP_RUNNER_CREDENTIAL_DIR")]
    pub credential_dir: Option<PathBuf>,
    /// Fail attempts whose sandbox posture is violated (root, SA token, writable rootfs, ...).
    #[arg(long, env = "ACP_RUNNER_STRICT_POSTURE", default_value_t = true, action = clap::ArgAction::Set)]
    pub strict_posture: bool,
    /// DEVELOPMENT ONLY: allow runner classes with subscription credentials to run with
    /// `egress.mode: direct` (unrestricted public egress).
    #[arg(long, env = "ACP_RUNNER_ALLOW_DIRECT_CREDENTIAL_EGRESS", default_value_t = false, action = clap::ArgAction::Set)]
    pub allow_direct_credential_egress: bool,
    /// Codex credential write-back: `verify` redeems the handed-back refresh token at the
    /// provider and stores only verified, controller-obtained tokens; `disabled` refuses every
    /// Codex write-back (profiles then need re-enrollment when tokens rotate).
    #[arg(long, env = "ACP_RUNNER_CODEX_WRITEBACK", default_value = "verify")]
    pub codex_writeback: String,
    #[arg(long, env = "ACP_RUNNER_CODEX_TOKEN_URL", default_value = acp_runner_engine::codex_refresh::DEFAULT_TOKEN_URL)]
    pub codex_token_url: String,
    #[arg(long, env = "ACP_RUNNER_CODEX_CLIENT_ID", default_value = acp_runner_engine::codex_refresh::DEFAULT_CLIENT_ID)]
    pub codex_client_id: String,
    #[arg(long, env = "ACP_RUNNER_CODEX_ISSUER", default_value = acp_runner_engine::codex_refresh::DEFAULT_ISSUER)]
    pub codex_issuer: String,
    /// JWKS URL, or `file:<path>` for a mounted key set.
    #[arg(long, env = "ACP_RUNNER_CODEX_JWKS", default_value = acp_runner_engine::codex_refresh::DEFAULT_JWKS_URL)]
    pub codex_jwks: String,
    /// Accept `file://` repository URLs (fixtures baked into the runner image).
    #[arg(long, env = "ACP_RUNNER_ALLOW_FILE_REPOS", default_value_t = false, action = clap::ArgAction::Set)]
    pub allow_file_repos: bool,
}

pub fn init_tracing() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,kube=warn,sqlx=warn,hyper=warn".into()),
        )
        .init();
}

pub async fn build_artifacts(journal: &Journal, common: &CommonArgs) -> Arc<dyn ArtifactStore> {
    let external: Option<Arc<dyn BlobStore>> =
        common.artifact_dir.clone().map(|root| Arc::new(FsBlobStore { root }) as Arc<dyn BlobStore>);
    Arc::new(PgArtifactStore::new(journal.clone(), common.artifact_inline_limit, external))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Some(Cmd::Crdgen) => {
            print!("{}", acp_runner_k8s::crds_yaml());
            Ok(())
        }
        Some(Cmd::DevRun(args)) => {
            init_tracing();
            dev::dev_run(args).await
        }
        Some(Cmd::Run(args)) => {
            init_tracing();
            run(*args).await
        }
        None => {
            init_tracing();
            #[derive(Parser)]
            struct EnvOnly {
                #[command(flatten)]
                args: RunArgs,
            }
            let parsed =
                EnvOnly::try_parse_from(["acp-runner-controller"]).context("configure via environment variables")?;
            run(parsed.args).await
        }
    }
}

async fn run(args: RunArgs) -> anyhow::Result<()> {
    let controller_id = args
        .controller_id
        .clone()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok().map(|s| s.trim().to_string()))
        .unwrap_or_else(|| format!("acp-runner-controller-{}", std::process::id()));
    let journal = Journal::connect(&args.common.database_url, args.common.db_max_connections)
        .await
        .context("connecting to PostgreSQL")?;
    journal.migrate().await.context("migrating journal")?;
    let client = kube::Client::try_default().await.context("kubernetes client")?;
    let pod_cfg = PodConfig {
        agent_namespace: args.agent_namespace.clone(),
        strict_posture: args.strict_posture,
        ..Default::default()
    };
    let backend: Arc<dyn SandboxBackend> = match args.backend {
        BackendKind::Pod => Arc::new(PodBackend { client: client.clone(), cfg: pod_cfg }),
        BackendKind::AgentSandbox => Arc::new(AgentSandboxBackend { client: client.clone(), cfg: pod_cfg }),
    };
    let creds: Arc<dyn CredentialStore> = match args.credential_store {
        CredStoreKind::K8s => {
            Arc::new(K8sSecretStore { client: client.clone(), namespace: args.credential_namespace.clone() })
        }
        CredStoreKind::File => Arc::new(FileCredentialStore {
            root: args.credential_dir.clone().context("--credential-dir required for the file store")?,
        }),
    };
    let artifacts = build_artifacts(&journal, &args.common).await;
    let metrics = Arc::new(Metrics::new());
    let engine = Arc::new(Engine {
        journal: journal.clone(),
        backend,
        creds: creds.clone(),
        artifacts: artifacts.clone(),
        metrics: metrics.clone(),
        cfg: EngineConfig {
            controller_id: controller_id.clone(),
            ingest_url: args.ingest_url.clone(),
            record_raw_payloads: args.common.record_raw,
            require_egress_proxy_for_credentials: !args.allow_direct_credential_egress,
            allow_file_repositories: args.allow_file_repos,
            ..Default::default()
        },
    });
    if args.allow_direct_credential_egress {
        tracing::warn!(
            "ACP_RUNNER_ALLOW_DIRECT_CREDENTIAL_EGRESS=true: credentialed runner classes may run without the egress proxy"
        );
    }
    tracing::info!(controller_id = %controller_id, backend = ?args.backend, "starting acp-runner controller");

    // ingest API (runnerd -> controller)
    let mut ingest_state = IngestState::new(journal.clone(), artifacts.clone(), creds.clone(), metrics.clone(), None);
    match args.codex_writeback.as_str() {
        "verify" => {
            use acp_runner_engine::codex_refresh::{JwksSource, OAuthRefresher, RefresherConfig};
            let jwks = match args.codex_jwks.strip_prefix("file:") {
                Some(path) => {
                    JwksSource::Static(std::fs::read_to_string(path).context("reading ACP_RUNNER_CODEX_JWKS")?)
                }
                None => JwksSource::Url(args.codex_jwks.clone()),
            };
            let refresher = OAuthRefresher::new(RefresherConfig {
                token_url: args.codex_token_url.clone(),
                client_id: args.codex_client_id.clone(),
                issuer: args.codex_issuer.clone(),
                jwks,
                ..Default::default()
            })?;
            ingest_state = ingest_state.with_refresher(Arc::new(refresher));
        }
        "disabled" => tracing::warn!("ACP_RUNNER_CODEX_WRITEBACK=disabled: refreshed Codex credentials are not stored"),
        other => anyhow::bail!("ACP_RUNNER_CODEX_WRITEBACK must be verify or disabled, not {other:?}"),
    }
    let ingest_state = Arc::new(ingest_state);
    let ingest_listener = tokio::net::TcpListener::bind(&args.ingest_listen).await?;
    tokio::spawn(async move {
        if let Err(e) = axum::serve(ingest_listener, router(ingest_state)).await {
            tracing::error!(error = %e, "ingest server stopped");
        }
    });

    // metrics + health
    let m = metrics.clone();
    let j = journal.clone();
    let ops = Router::new()
        .route(
            "/metrics",
            get(move || {
                let m = m.clone();
                async move { m.render() }
            }),
        )
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/readyz",
            get(move || {
                let j = j.clone();
                async move {
                    match j.ping().await {
                        Ok(()) => (axum::http::StatusCode::OK, "ready"),
                        Err(_) => (axum::http::StatusCode::SERVICE_UNAVAILABLE, "database unavailable"),
                    }
                }
            }),
        );
    let ops_listener = tokio::net::TcpListener::bind(&args.metrics_listen).await?;
    tokio::spawn(async move {
        let _ = axum::serve(ops_listener, ops).await;
    });

    // credential profile records (non-secret) and gauges
    let (e2, c2) = (engine.clone(), creds.clone());
    tokio::spawn(async move {
        loop {
            match sync_profiles(c2.as_ref(), &e2.journal).await {
                Ok(n) => tracing::debug!(profiles = n, "credential profiles synced"),
                Err(e) => tracing::warn!(error = %e, "credential profile sync failed"),
            }
            if let Err(e) = e2.refresh_gauges().await {
                tracing::warn!(error = %e, "refreshing gauges failed");
            }
            tokio::time::sleep(Duration::from_secs(15)).await;
        }
    });

    controller::run(client, engine, args.watch_namespace.clone()).await;
    Ok(())
}
