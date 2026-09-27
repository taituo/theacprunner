//! End-to-end engine tests without Kubernetes:
//! PostgreSQL journal + ingest API + LocalProcessBackend (real runnerd processes) +
//! deterministic fake agents. Requires `ACP_TEST_DATABASE_URL`; skipped otherwise.

use acp_runner_core::credentials::{CredentialBundle, Provider, validate_bundle};
use acp_runner_core::events::EventKind;
use acp_runner_core::failure::FailureReason;
use acp_runner_core::spec::*;
use acp_runner_core::{AttemptPhase, RunPhase};
use acp_runner_engine::backend::{LocalProcessBackend, RunKey};
use acp_runner_engine::creds::{CredentialStore, FileCredentialStore, StoredProfile, sync_profiles};
use acp_runner_engine::ingest::{IngestState, router};
use acp_runner_engine::metrics::Metrics;
use acp_runner_engine::{Engine, EngineConfig, RunInput, RunView};
use acp_runner_journal::testing::{TempDb, temp_database};
use acp_runner_journal::{ArtifactStore, PgArtifactStore};
use base64::Engine as _;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

fn bins() -> (PathBuf, PathBuf) {
    static BUILD: std::sync::Once = std::sync::Once::new();
    BUILD.call_once(|| {
        let st = std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args(["build", "-q", "-p", "runnerd", "-p", "agentd", "-p", "fake-acp-agent"])
            .status()
            .unwrap();
        assert!(st.success());
    });
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().unwrap().parent().unwrap().to_path_buf();
    (dir.join("runnerd"), dir.join("fake-acp-agent"))
}

struct H {
    db: Option<TempDb>,
    engine: Arc<Engine>,
    backend: Arc<LocalProcessBackend>,
    creds: Arc<FileCredentialStore>,
    metrics: Arc<Metrics>,
    _tmp: tempfile::TempDir,
    repo_url: String,
    base_sha: String,
    fake: PathBuf,
    ingest_url: String,
}

impl H {
    async fn new() -> Option<H> {
        Self::with(|_| {}, 8 * 1024 * 1024).await
    }

    async fn with(tune: impl FnOnce(&mut EngineConfig), inline_limit: u64) -> Option<H> {
        let db = temp_database().await?;
        let (runnerd, fake) = bins();
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("upstream");
        let base_sha = acp_runner_workspace_fixture(&src).await;
        let journal = db.journal.clone();
        let metrics = Arc::new(Metrics::new());
        let artifacts: Arc<dyn ArtifactStore> = Arc::new(PgArtifactStore::new(journal.clone(), inline_limit, None));
        let creds = Arc::new(FileCredentialStore { root: tmp.path().join("creds") });
        let refresher = Arc::new(acp_runner_engine::codex_refresh::testing::FakeRefresher::new());
        let state = Arc::new(
            IngestState::new(journal.clone(), artifacts.clone(), creds.clone(), metrics.clone(), None)
                .with_refresher(refresher),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
        // `codex` / `codex-acp` resolve to the fake agent's Codex emulation.
        let fake_codex = tmp.path().join("fake-codex-bin");
        std::fs::create_dir_all(&fake_codex).unwrap();
        for name in ["codex", "codex-acp"] {
            std::os::unix::fs::symlink(&fake, fake_codex.join(name)).unwrap();
        }
        let backend = Arc::new(LocalProcessBackend::new(
            runnerd,
            tmp.path().join("sandboxes"),
            format!("{}:{}", fake_codex.display(), std::env::var("PATH").unwrap_or_default()),
        ));
        let mut cfg = EngineConfig {
            controller_id: "controller-a".into(),
            ingest_url: format!("http://{addr}"),
            active_requeue: Duration::from_millis(200),
            waiting_requeue: Duration::from_millis(300),
            supervision_lease: Duration::from_secs(30),
            // LocalProcessBackend without namespace isolation is not an isolation boundary and
            // has no egress proxy; the proxy requirement is exercised by the isolation and
            // kube_e2e suites.
            require_egress_proxy_for_credentials: false,
            allow_file_repositories: true,
            ..Default::default()
        };
        tune(&mut cfg);
        let ingest_url = cfg.ingest_url.clone();
        let engine = Arc::new(Engine {
            journal,
            backend: backend.clone(),
            creds: creds.clone(),
            artifacts,
            metrics: metrics.clone(),
            cfg,
        });
        Some(H {
            db: Some(db),
            engine,
            backend,
            creds,
            metrics,
            repo_url: format!("file://{}", src.display()),
            base_sha,
            fake,
            _tmp: tmp,
            ingest_url,
        })
    }

    fn class(&self, name: &str, scenario: &str) -> RunnerClassSpec {
        RunnerClassSpec {
            name: name.into(),
            driver: "fake".into(),
            driver_config: json!({"command": self.fake.to_string_lossy(), "scenario": scenario}),
            image: "local".into(),
            image_pull_policy: None,
            runtime_class_name: None,
            resources: None,
            credentials: CredentialRequirement::default(),
            workspace: WorkspacePolicy::default(),
            timeouts: TimeoutPolicy {
                hard_seconds: 60,
                no_progress_seconds: 20,
                grace_seconds: 2,
                heartbeat_seconds: 1,
                startup_seconds: 30,
            },
            permissions: PermissionPolicy::default(),
            egress: EgressPolicy::default(),
            env: [("FAKE_ACP_SCENARIO".to_string(), scenario.to_string())].into_iter().collect(),
            run_as_user: None,
            service_account_name: None,
        }
    }

    fn input(&self, classes: Vec<RunnerClassSpec>, max_per_runner: u32) -> RunInput {
        let uid = Uuid::new_v4().to_string();
        RunInput {
            key: RunKey { namespace: "default".into(), name: format!("run-{}", &uid[..8]), uid },
            spec: RunSpec {
                task_id: "fix-add".into(),
                prompt: "Fix add.sh so that test.sh passes.".into(),
                repository: RepositoryInput {
                    url: self.repo_url.clone(),
                    revision: self.base_sha.clone(),
                    sparse_paths: vec![],
                    depth: None,
                },
                output: OutputExpectation::default(),
                retry: RetryPolicy { max_attempts_per_runner: max_per_runner, max_total_attempts: None },
                timeouts: TimeoutOverrides::default(),
                resume: ResumePolicy::default(),
                runner_classes: classes,
            },
            cancel: false,
        }
    }

    async fn drive(&self, input: &RunInput, limit: Duration) -> RunView {
        drive_with(&self.engine, input, limit).await
    }

    async fn kinds(&self, run_id: Uuid) -> Vec<String> {
        self.engine.journal.events_for_run(run_id, 0, 10_000).await.unwrap().into_iter().map(|e| e.kind).collect()
    }

    async fn done(mut self) {
        for n in self.backend.names() {
            let _ = self.backend.simulate_disappearance(&n);
        }
        if let Some(db) = self.db.take() {
            db.drop_db().await;
        }
    }
}

async fn drive_with(engine: &Engine, input: &RunInput, limit: Duration) -> RunView {
    let start = Instant::now();
    loop {
        let v = engine.reconcile(input).await.expect("reconcile");
        if v.phase.is_terminal() || start.elapsed() > limit {
            return v;
        }
        tokio::time::sleep(v.requeue_after.unwrap_or(Duration::from_millis(200)).max(Duration::from_millis(100))).await;
    }
}

async fn acp_runner_workspace_fixture(dir: &std::path::Path) -> String {
    // same fixture as the workspace crate (kept local to avoid a dev-dependency cycle)
    tokio::fs::create_dir_all(dir).await.unwrap();
    std::fs::write(
        dir.join("add.sh"),
        "#!/bin/sh\n# add A B -> prints A+B\nadd() {\n  echo $(( $1 - $2 ))\n}\nadd \"$1\" \"$2\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("test.sh"), "#!/bin/sh\nset -e\nout=$(sh \"$(dirname \"$0\")/add.sh\" 2 3)\nif [ \"$out\" = \"5\" ]; then echo PASS; exit 0; fi\necho \"FAIL: expected 5, got $out\"; exit 1\n").unwrap();
    let git = |args: &[&str]| {
        let st = std::process::Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main"])
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();
        assert!(st.status.success(), "{}", String::from_utf8_lossy(&st.stderr));
        String::from_utf8_lossy(&st.stdout).trim().to_string()
    };
    git(&["init", "-q"]);
    git(&["add", "-A"]);
    git(&["commit", "-qm", "buggy"]);
    git(&["rev-parse", "HEAD"])
}

fn has(kinds: &[String], k: EventKind) -> bool {
    kinds.iter().any(|x| x == k.as_str())
}

// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn fake_run_succeeds_with_journal_and_patch_artifact() {
    let Some(h) = H::new().await else { return };
    let input = h.input(vec![h.class("fake-default", "fix")], 1);
    let v = h.drive(&input, Duration::from_secs(60)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    assert_eq!(v.attempt_count, 1);
    let art = v.artifact.clone().expect("artifact");
    assert_eq!(art.kind, "patch");
    assert_eq!(art.base_revision, h.base_sha);
    let content = h.engine.artifacts.get_content(art.id).await.unwrap();
    assert!(String::from_utf8_lossy(&content).contains("+  echo $(( $1 + $2 ))"));
    let kinds = h.kinds(v.run_id).await;
    for k in [
        EventKind::RunCreated,
        EventKind::AttemptStarted,
        EventKind::AgentStarted,
        EventKind::SessionStarted,
        EventKind::InputSent,
        EventKind::AgentOutput,
        EventKind::ToolCall,
        EventKind::ToolResult,
        EventKind::PermissionRequest,
        EventKind::Progress,
        EventKind::ArtifactCreated,
        EventKind::Heartbeat,
        EventKind::AttemptCompleted,
        EventKind::RunCompleted,
    ] {
        assert!(has(&kinds, k), "missing {k}: {kinds:?}");
    }
    // the sandbox is gone and the attempt is marked released
    let a = &h.engine.journal.attempts_for_run(v.run_id).await.unwrap()[0];
    assert!(a.sandbox_released_at.is_some());
    assert!(a.last_heartbeat_at.is_some());
    assert!(h.backend.names().is_empty());
    let m = h.metrics.render();
    assert!(m.contains("acp_runner_attempts_total"));
    h.done().await;
}

#[tokio::test]
async fn crashed_attempt_is_retried_with_resume_capsule() {
    let Some(h) = H::new().await else { return };
    let input = h.input(vec![h.class("fake-flaky", "crash-until:2")], 2);
    let v = h.drive(&input, Duration::from_secs(90)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    let attempts = h.engine.journal.attempts_for_run(v.run_id).await.unwrap();
    assert_eq!(attempts.len(), 2);
    assert!(matches!(attempts[0].failure(), Some(FailureReason::ProcessCrashed { .. })), "{:?}", attempts[0].failure());
    let spec2: acp_runner_core::AttemptSpec = serde_json::from_value(attempts[1].spec.clone()).unwrap();
    assert!(spec2.capsule.is_some());
    assert!(spec2.prompt.contains("resume capsule"));
    assert!(spec2.prompt.contains("ProcessCrashed"));
    assert!(has(&h.kinds(v.run_id).await, EventKind::AttemptFailed));
    h.done().await;
}

#[tokio::test]
async fn fallback_to_another_runner_class_starts_a_new_session() {
    let Some(h) = H::new().await else { return };
    let mut b = h.class("fallback-b", "fix");
    b.driver_config["scenario"] = json!("fix");
    let input = h.input(vec![h.class("primary-a", "crash"), b], 2);
    let v = h.drive(&input, Duration::from_secs(90)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    let attempts = h.engine.journal.attempts_for_run(v.run_id).await.unwrap();
    let classes: Vec<_> = attempts.iter().map(|a| a.runner_class.as_str()).collect();
    assert_eq!(classes, vec!["primary-a", "primary-a", "fallback-b"]);
    let evs = h.engine.journal.events_for_run(v.run_id, 0, 10_000).await.unwrap();
    let started: Vec<_> = evs.iter().filter(|e| e.kind == "AttemptStarted").collect();
    assert_eq!(started[2].data["fallback"], true);
    // fallback = new provider session: distinct session ids
    let sessions: Vec<_> = evs
        .iter()
        .filter(|e| e.kind == "SessionStarted")
        .filter_map(|e| e.data.get("providerSessionId").and_then(|s| s.as_str()).map(str::to_string))
        .collect();
    let uniq: std::collections::HashSet<_> = sessions.iter().collect();
    assert_eq!(uniq.len(), sessions.len());
    assert!(h.metrics.render().contains("acp_runner_fallbacks_total{from_driver=\"fake\",to_driver=\"fake\"} 1"));
    h.done().await;
}

#[tokio::test]
async fn hung_agent_times_out_then_fallback_succeeds() {
    let Some(h) = H::new().await else { return };
    let mut hung = h.class("hung", "hang");
    hung.timeouts.no_progress_seconds = 2;
    let input = h.input(vec![hung, h.class("good", "fix")], 1);
    let v = h.drive(&input, Duration::from_secs(90)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    let attempts = h.engine.journal.attempts_for_run(v.run_id).await.unwrap();
    assert_eq!(attempts[0].phase(), AttemptPhase::TimedOut);
    assert!(matches!(attempts[0].failure(), Some(FailureReason::NoProgressTimeout { seconds: 2 })));
    assert!(has(&h.kinds(v.run_id).await, EventKind::AttemptTimedOut));
    assert!(h.metrics.render().contains("acp_runner_timeouts_total"));
    // detected by the controller (agent-progress signal) and delivered as a heartbeat directive
    let evs = h.engine.journal.events_for_run(v.run_id, 0, 10_000).await.unwrap();
    assert!(
        evs.iter().any(|e| e.source == "controller" && e.data["category"] == "no_progress_detected"),
        "controller did not detect the missing progress"
    );
    assert!(attempts[0].cancel_requested_at.is_some());
    h.done().await;
}

#[tokio::test]
async fn hung_agentd_is_cancelled_then_sandbox_killed_and_retried() {
    let Some(h) = H::new().await else { return };
    let mut c = h.class("hang-once", "hang-until:2");
    c.timeouts.no_progress_seconds = 3;
    c.timeouts.grace_seconds = 1;
    let input = h.input(vec![c], 2);
    let start = Instant::now();
    let name = loop {
        let v = h.engine.reconcile(&input).await.unwrap();
        if v.current.as_ref().is_some_and(|c| c.phase == AttemptPhase::Running) {
            break h.backend.names().pop().unwrap();
        }
        assert!(start.elapsed() < Duration::from_secs(30));
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    // agentd (the agent container) freezes: no events, no reaction to Cancel.
    assert!(h.backend.simulate_agentd_hang(&name));
    let v = h.drive(&input, Duration::from_secs(90)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    let attempts = h.engine.journal.attempts_for_run(v.run_id).await.unwrap();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].phase(), AttemptPhase::TimedOut);
    assert!(matches!(attempts[0].failure(), Some(FailureReason::NoProgressTimeout { seconds: 3 })));
    assert!(attempts[0].sandbox_released_at.is_some(), "the frozen sandbox was not terminated");
    let evs = h.engine.journal.events_for_attempt(attempts[0].id, &[EventKind::Progress], 1000).await.unwrap();
    let cats: Vec<String> = evs.iter().filter_map(|e| e.data["category"].as_str().map(str::to_string)).collect();
    assert!(cats.contains(&"no_progress_detected".to_string()), "{cats:?}");
    assert!(cats.contains(&"agent_unresponsive".to_string()), "{cats:?}");
    assert!(!h.backend.names().contains(&name), "frozen agentd still registered");
    h.done().await;
}

#[tokio::test]
async fn sandbox_disappearance_is_detected_and_retried() {
    let Some(h) = H::new().await else { return };
    let input = h.input(vec![h.class("hang-long", "hang"), h.class("good", "fix")], 1);
    // drive until the first attempt is running
    let start = Instant::now();
    loop {
        let v = h.engine.reconcile(&input).await.unwrap();
        if v.current.as_ref().is_some_and(|c| c.phase == AttemptPhase::Running) {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(30), "attempt never started: {v:?}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let name = h.backend.names().pop().expect("sandbox");
    assert!(h.backend.simulate_disappearance(&name));
    let v = h.drive(&input, Duration::from_secs(60)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    let attempts = h.engine.journal.attempts_for_run(v.run_id).await.unwrap();
    assert!(matches!(attempts[0].failure(), Some(FailureReason::SandboxLost { .. })), "{:?}", attempts[0].failure());
    h.done().await;
}

#[tokio::test]
async fn frozen_runnerd_is_detected_by_heartbeat_loss() {
    let Some(h) = H::new().await else { return };
    let mut c = h.class("hang-long", "hang");
    c.timeouts.no_progress_seconds = 300;
    let input = h.input(vec![c, h.class("good", "fix")], 1);
    let start = Instant::now();
    loop {
        let v = h.engine.reconcile(&input).await.unwrap();
        if v.current.as_ref().is_some_and(|c| c.phase == AttemptPhase::Running && c.last_heartbeat_at.is_some()) {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(30));
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let name = h.backend.names().pop().unwrap();
    assert!(h.backend.simulate_hang(&name));
    let v = h.drive(&input, Duration::from_secs(90)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    let attempts = h.engine.journal.attempts_for_run(v.run_id).await.unwrap();
    assert!(matches!(attempts[0].failure(), Some(FailureReason::HeartbeatLost { .. })), "{:?}", attempts[0].failure());
    h.done().await;
}

#[tokio::test]
async fn stale_controller_is_taken_over_by_another_instance() {
    let Some(h) = H::with(|c| c.supervision_lease = Duration::from_secs(2), 8 << 20).await else { return };
    let mut slow = h.class("slow", "slow:25");
    slow.timeouts.no_progress_seconds = 30;
    let input = h.input(vec![slow], 1);
    // controller A starts the attempt, then "crashes" (stops reconciling)
    let v = h.engine.reconcile(&input).await.unwrap();
    assert!(v.current.is_some());
    // controller B shares journal + cluster (backend) but has another identity
    let b = Engine {
        journal: h.engine.journal.clone(),
        backend: h.backend.clone(),
        creds: h.creds.clone(),
        artifacts: h.engine.artifacts.clone(),
        metrics: Arc::new(Metrics::new()),
        cfg: EngineConfig { controller_id: "controller-b".into(), ..h.engine.cfg.clone() },
    };
    let v = drive_with(&b, &input, Duration::from_secs(60)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    let evs = h.engine.journal.events_for_run(v.run_id, 0, 10_000).await.unwrap();
    assert!(
        evs.iter().any(|e| e.kind == "Progress" && e.data["category"] == "supervision_takeover"),
        "no takeover event"
    );
    let a = &h.engine.journal.attempts_for_run(v.run_id).await.unwrap()[0];
    assert_eq!(a.lease_owner.as_deref(), Some("controller-b"));
    h.done().await;
}

fn fake_codex_auth(account: &str) -> Vec<u8> {
    let b64 = |v: serde_json::Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
    let jwt = |claims: serde_json::Value| {
        format!("{}.{}.{}", b64(json!({"alg":"none"})), b64(claims), b64(json!("sig-000000000")))
    };
    json!({
        "auth_mode": "chatgpt", "OPENAI_API_KEY": null,
        "tokens": {"id_token": jwt(json!({"email":"a@example.com","https://api.openai.com/auth":{"chatgpt_plan_type":"plus","chatgpt_account_id":account}})),
                   "access_token": jwt(json!({"exp": 1900000000})), "refresh_token": format!("rt_{account}_0"), "account_id": account},
        "last_refresh": "2026-09-20T00:00:00Z"
    })
    .to_string()
    .into_bytes()
}

async fn enroll_codex(h: &H, name: &str) {
    let mut bundle = CredentialBundle::new();
    bundle.insert("auth.json".into(), fake_codex_auth("acct-1"));
    let md = validate_bundle(Provider::Codex, &bundle).unwrap();
    h.creds
        .save(
            &StoredProfile {
                name: name.into(),
                provider: Provider::Codex,
                max_concurrent_leases: 5,
                metadata: md,
                store_ref: String::new(),
                policy: acp_runner_engine::creds::ProfilePolicy::any(),
            },
            &bundle,
        )
        .await
        .unwrap();
    sync_profiles(h.creds.as_ref(), &h.engine.journal).await.unwrap();
}

#[tokio::test]
async fn exclusive_credential_lease_serializes_runs_and_writeback_is_validated() {
    let Some(h) = H::new().await else { return };
    enroll_codex(&h, "codex-1").await;
    // codex profiles are exclusive regardless of the requested max
    assert_eq!(h.engine.journal.get_profile("codex-1").await.unwrap().unwrap().max_concurrent_leases, 1);
    let mut c = h.class("codexish", "slow:10");
    c.credentials = CredentialRequirement {
        provider: Some("codex".into()),
        profiles: vec!["codex-1".into()],
        file_targets: BTreeMap::new(),
    };
    let mut r = h.class("codexish-refresh", "refresh-credential");
    r.credentials = c.credentials.clone();
    let in1 = h.input(vec![c], 1);
    let in2 = h.input(vec![r], 1);
    let v1 = h.engine.reconcile(&in1).await.unwrap();
    assert_eq!(v1.current.as_ref().unwrap().credential_profile.as_deref(), Some("codex-1"));
    let v2 = h.engine.reconcile(&in2).await.unwrap();
    assert!(v2.current.is_none());
    assert!(v2.waiting_reason.as_deref().unwrap_or("").contains("credential lease"), "{v2:?}");
    let (a, b) = tokio::join!(h.drive(&in1, Duration::from_secs(60)), h.drive(&in2, Duration::from_secs(90)));
    assert_eq!(a.phase, RunPhase::Succeeded, "{a:?}");
    assert_eq!(b.phase, RunPhase::Succeeded, "{b:?}");
    assert!(h.engine.journal.active_leases().await.unwrap().is_empty());
    // the handed-back refresh token was redeemed by the controller; the store holds the
    // controller-obtained tokens, never the submitted bytes
    let (_, bundle) = h.creds.load("codex-1").await.unwrap();
    let stored: serde_json::Value = serde_json::from_slice(&bundle["auth.json"]).unwrap();
    assert!(stored["tokens"]["refresh_token"].as_str().unwrap().starts_with("rt_acct-1_10"), "{stored}");
    assert!(stored["tokens"]["access_token"].as_str().unwrap().starts_with("access-acct-1-"));
    let p = h.engine.journal.get_profile("codex-1").await.unwrap().unwrap();
    assert!(p.generation >= 1);
    assert!(h.metrics.render().contains("acp_runner_credential_writebacks_total{result=\"accepted\"} 1"));
    h.done().await;
}

const FAKE_CLAUDE_TOKEN: &str = "sk-ant-oat01-e2eFAKEtokenFAKEtokenFAKEtoken000000";

async fn enroll_claude(h: &H, name: &str) {
    let mut bundle = CredentialBundle::new();
    bundle.insert("oauth-token".into(), FAKE_CLAUDE_TOKEN.as_bytes().to_vec());
    let md = validate_bundle(Provider::Claude, &bundle).unwrap();
    h.creds
        .save(
            &StoredProfile {
                name: name.into(),
                provider: Provider::Claude,
                max_concurrent_leases: 2,
                metadata: md,
                store_ref: String::new(),
                policy: acp_runner_engine::creds::ProfilePolicy::any(),
            },
            &bundle,
        )
        .await
        .unwrap();
    sync_profiles(h.creds.as_ref(), &h.engine.journal).await.unwrap();
}

/// DoD: Claude fails (subscription login rejected) -> fallback to Codex in a new session with
/// a resume capsule; Codex authenticates from the leased auth.json, refreshes it, and the
/// refreshed file is validated and written back. No credential value reaches the journal.
#[tokio::test]
async fn claude_failure_falls_back_to_codex_with_refresh_writeback() {
    let Some(h) = H::new().await else { return };
    enroll_claude(&h, "claude-max-1").await;
    enroll_codex(&h, "codex-personal-1").await;
    let mut claude = h.class("claude-max", "auth-fail");
    claude.driver = "claude".into();
    claude.driver_config = json!({"command": h.fake.to_string_lossy(), "commandArgs": ["claude-mode"]});
    claude.credentials = CredentialRequirement {
        provider: Some("claude".into()),
        profiles: vec!["claude-max-1".into()],
        file_targets: BTreeMap::new(),
    };
    let mut codex = h.class("codex-personal", "refresh-credential");
    codex.driver = "codex".into();
    codex.driver_config = json!({});
    codex.credentials = CredentialRequirement {
        provider: Some("codex".into()),
        profiles: vec!["codex-personal-1".into()],
        file_targets: BTreeMap::new(),
    };
    let input = h.input(vec![claude, codex], 2);
    let v = h.drive(&input, Duration::from_secs(90)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    let attempts = h.engine.journal.attempts_for_run(v.run_id).await.unwrap();
    assert_eq!(attempts.len(), 2, "an auth failure must not be retried on the same class");
    assert!(
        matches!(attempts[0].failure(), Some(FailureReason::AuthEnrollmentRequired { ref provider, .. }) if provider == "claude"),
        "{:?}",
        attempts[0].failure()
    );
    assert_eq!(attempts[1].driver, "codex");
    assert_eq!(attempts[1].phase(), AttemptPhase::Succeeded);
    assert!(attempts[1].driver_version.as_deref().unwrap_or("").contains("fake"), "{:?}", attempts[1].driver_version);
    // the rejected Claude login is flagged for re-enrollment
    assert_eq!(h.engine.journal.get_profile("claude-max-1").await.unwrap().unwrap().status, "needs_reauth");
    // resume capsule across providers
    let spec2: acp_runner_core::AttemptSpec = serde_json::from_value(attempts[1].spec.clone()).unwrap();
    assert!(spec2.prompt.contains("AuthEnrollmentRequired"), "{}", spec2.prompt);
    // Codex refreshed its auth.json; the controller redeemed the token and stored its own
    let (_, bundle) = h.creds.load("codex-personal-1").await.unwrap();
    let stored: serde_json::Value = serde_json::from_slice(&bundle["auth.json"]).unwrap();
    assert_eq!(stored["tokens"]["account_id"], "acct-1");
    assert!(h.metrics.render().contains("acp_runner_credential_writebacks_total{result=\"accepted\"} 1"));
    // agent events are tagged as untrusted, the terminal events as runnerd's
    let evs = h.engine.journal.events_for_run(v.run_id, 0, 10_000).await.unwrap();
    assert!(evs.iter().filter(|e| e.kind == "SessionStarted").all(|e| e.source == "agent"));
    assert!(evs.iter().filter(|e| e.kind == "AttemptCompleted").all(|e| e.source == "runnerd"));
    assert_eq!(evs.iter().filter(|e| e.kind == "SessionStarted").count(), 2);
    // no credential material anywhere in the journal
    let all = serde_json::to_string(&evs.iter().map(|e| (&e.data, &e.raw)).collect::<Vec<_>>()).unwrap();
    for secret in [FAKE_CLAUDE_TOKEN, "rt_acct-1_0", "rt_acct-1_1"] {
        assert!(!all.contains(secret), "credential leaked into the journal");
    }
    h.done().await;
}

#[tokio::test]
async fn missing_credential_profile_skips_to_fallback() {
    let Some(h) = H::new().await else { return };
    let mut c = h.class("claude-default", "fix");
    c.credentials = CredentialRequirement {
        provider: Some("claude".into()),
        profiles: vec!["not-enrolled".into()],
        file_targets: BTreeMap::new(),
    };
    let input = h.input(vec![c, h.class("fallback", "fix")], 3);
    let v = h.drive(&input, Duration::from_secs(60)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    let attempts = h.engine.journal.attempts_for_run(v.run_id).await.unwrap();
    assert_eq!(attempts.len(), 2, "must not retry an unusable class");
    assert!(matches!(attempts[0].failure(), Some(FailureReason::CredentialUnavailable { .. })));
    h.done().await;
}

#[tokio::test]
async fn cancellation_terminates_sandbox_and_releases_lease() {
    let Some(h) = H::new().await else { return };
    enroll_codex(&h, "codex-2").await;
    let mut c = h.class("hang", "hang");
    c.credentials = CredentialRequirement {
        provider: Some("codex".into()),
        profiles: vec!["codex-2".into()],
        file_targets: BTreeMap::new(),
    };
    let mut input = h.input(vec![c], 1);
    let start = Instant::now();
    loop {
        let v = h.engine.reconcile(&input).await.unwrap();
        if v.current.as_ref().is_some_and(|c| c.phase == AttemptPhase::Running) {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(30));
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    input.cancel = true;
    let v = h.engine.reconcile(&input).await.unwrap();
    assert_eq!(v.phase, RunPhase::Cancelled);
    assert!(h.backend.names().is_empty());
    assert!(h.engine.journal.active_leases().await.unwrap().is_empty());
    let a = &h.engine.journal.attempts_for_run(v.run_id).await.unwrap()[0];
    assert_eq!(a.phase(), AttemptPhase::Cancelled);
    h.done().await;
}

#[tokio::test]
async fn oversized_artifact_is_rejected_by_ingest() {
    let Some(h) = H::with(|_| {}, 64).await else { return };
    let input = h.input(vec![h.class("fake", "fix")], 1);
    let v = h.drive(&input, Duration::from_secs(60)).await;
    assert_eq!(v.phase, RunPhase::Failed, "{v:?}");
    assert!(matches!(v.failure, Some(FailureReason::ArtifactTooLarge { limit_bytes: 64, .. })), "{:?}", v.failure);
    h.done().await;
}

#[tokio::test]
async fn previous_partial_patch_can_be_applied_for_the_next_attempt() {
    let Some(h) = H::new().await else { return };
    let mut input = h.input(vec![h.class("crashy", "fix-then-crash"), h.class("noop", "noop")], 1);
    input.spec.resume.apply_previous_patch = true;
    let v = h.drive(&input, Duration::from_secs(60)).await;
    // attempt 2 made no changes itself, but its workspace started with attempt 1's patch
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    let attempts = h.engine.journal.attempts_for_run(v.run_id).await.unwrap();
    let spec2: acp_runner_core::AttemptSpec = serde_json::from_value(attempts[1].spec.clone()).unwrap();
    assert!(spec2.apply_patch_b64.is_some());
    assert!(spec2.capsule.unwrap().previous_artifact.unwrap().applied_to_workspace);
    h.done().await;
}

#[tokio::test]
async fn ingest_rejects_bad_tokens_and_forbidden_event_kinds() {
    let Some(h) = H::new().await else { return };
    let client = reqwest_like::Client::new();
    let url = format!("{}/v1/attempt", h.ingest_url);
    assert_eq!(client.get(&url, Some("x".repeat(64).as_str())).await, 401);
    assert_eq!(client.get(&url, None).await, 401);
    h.done().await;
}

#[tokio::test]
async fn ingest_refuses_agent_sourced_authoritative_events_even_with_a_valid_token() {
    let Some(h) = H::new().await else { return };
    let input = h.input(vec![h.class("hang", "hang")], 1);
    let start = Instant::now();
    let v = loop {
        let v = h.engine.reconcile(&input).await.unwrap();
        if v.current.as_ref().is_some_and(|c| c.phase == AttemptPhase::Running) {
            break v;
        }
        assert!(start.elapsed() < Duration::from_secs(30));
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    // Read the token the way only runnerd can (from the sandbox's secret directory).
    let name = h.backend.names().pop().unwrap();
    let token = std::fs::read_to_string(h._tmp.path().join("sandboxes").join(&name).join("secret/token")).unwrap();
    let url = format!("{}/v1/attempt/events", h.ingest_url);
    let client = reqwest_like::Client::new();
    for kind in ["AttemptCompleted", "ArtifactCreated", "Heartbeat", "AgentStarted"] {
        let body = json!({"events": [{"seq": 900_000, "ts": "2026-09-26T00:00:00Z", "kind": kind, "source": "agent",
                                       "data": {"artifactId": Uuid::nil()}}]});
        assert_eq!(client.post(&url, &token, &body.to_string()).await, 400, "{kind}");
    }
    // A plain agent message is fine.
    let ok = json!({"events": [{"seq": 900_001, "ts": "2026-09-26T00:00:00Z", "kind": "AgentOutput", "source": "agent",
                                 "data": {"channel": "message", "text": "hi"}}]});
    assert_eq!(client.post(&url, &token, &ok.to_string()).await, 200);
    let a = h.engine.journal.get_attempt(v.current.unwrap().id).await.unwrap();
    assert!(a.phase().is_active(), "a forged agent event changed the attempt state");
    h.done().await;
}

/// Review finding 3/4: a terminal report may only name the attempt's own artifact, and an
/// agent cannot use a runner-owned progress category (base revision, environment phase, ...).
#[tokio::test]
async fn ingest_refuses_foreign_artifacts_and_runner_owned_categories() {
    let Some(h) = H::new().await else { return };
    // Run 1 produces an artifact that belongs to someone else from run 2's point of view.
    let done = h.drive(&h.input(vec![h.class("fake-default", "fix")], 1), Duration::from_secs(60)).await;
    assert_eq!(done.phase, RunPhase::Succeeded, "{done:?}");
    let foreign = done.artifact.clone().expect("artifact").id;
    // Run 2 hangs; we speak for its runnerd with its own token.
    let input = h.input(vec![h.class("hang", "hang")], 1);
    let start = Instant::now();
    let v = loop {
        let v = h.engine.reconcile(&input).await.unwrap();
        if v.current.as_ref().is_some_and(|c| c.phase == AttemptPhase::Running) {
            break v;
        }
        assert!(start.elapsed() < Duration::from_secs(30));
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    let attempt_id = v.current.as_ref().unwrap().id;
    let name = h
        .backend
        .names()
        .into_iter()
        .find(|n| n.contains(&attempt_id.to_string()[..8]))
        .unwrap_or_else(|| h.backend.names().pop().unwrap());
    let token = std::fs::read_to_string(h._tmp.path().join("sandboxes").join(&name).join("secret/token")).unwrap();
    let url = format!("{}/v1/attempt/events", h.ingest_url);
    let client = reqwest_like::Client::new();
    for cat in ["workspace_ready", "gateway_listening", "environment_ready", "turn_ended", "snapshot_created"] {
        let body = json!({"events": [{"seq": 910_000, "ts": "2026-09-26T00:00:00Z", "kind": "Progress", "source": "agent",
                                       "data": {"category": cat, "message": "forged", "detail": {"baseRevision": "0".repeat(40)}}}]});
        assert_eq!(client.post(&url, &token, &body.to_string()).await, 400, "{cat}");
    }
    let forged = json!({"events": [{"seq": 910_001, "ts": "2026-09-26T00:00:00Z", "kind": "AttemptCompleted", "source": "runnerd",
                                     "data": {"stopReason": "end_turn", "artifactId": foreign}}]});
    assert_eq!(client.post(&url, &token, &forged.to_string()).await, 200);
    let a = h.engine.journal.get_attempt(attempt_id).await.unwrap();
    assert_eq!(a.phase(), AttemptPhase::Failed, "a foreign artifact made the attempt succeed");
    assert_eq!(a.artifact_id, None);
    assert_eq!(a.failure().map(|f| f.code().to_string()).as_deref(), Some("ProtocolError"));
    let v = h.drive(&input, Duration::from_secs(30)).await;
    assert_ne!(v.artifact.map(|x| x.id), Some(foreign));
    // The database refuses the link as well, whoever writes it.
    assert!(h.engine.journal.set_attempt_details(attempt_id, None, None, Some(foreign)).await.is_err());
    h.done().await;
}

#[tokio::test]
async fn file_repositories_are_refused_unless_enabled() {
    let Some(h) = H::with(|c| c.allow_file_repositories = false, 8 * 1024 * 1024).await else { return };
    let v = h.drive(&h.input(vec![h.class("fake-default", "fix")], 1), Duration::from_secs(30)).await;
    assert_eq!(v.phase, RunPhase::Failed, "{v:?}");
    assert_eq!(v.attempt_count, 0);
    assert!(v.failure.unwrap().message().contains("file://"));
    h.done().await;
}

/// Review finding 1: an agent that plants its own refresh token next to the victim's account
/// id cannot get it into the credential store.
#[tokio::test]
async fn forged_credential_writeback_is_rejected_and_the_store_is_unchanged() {
    let Some(h) = H::new().await else { return };
    enroll_codex(&h, "codex-1").await;
    let before = h.creds.load("codex-1").await.unwrap().1["auth.json"].clone();
    let mut c = h.class("codexish-forge", "refresh-credential:forge");
    c.credentials = CredentialRequirement {
        provider: Some("codex".into()),
        profiles: vec!["codex-1".into()],
        file_targets: BTreeMap::new(),
    };
    let v = h.drive(&h.input(vec![c], 1), Duration::from_secs(60)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "the run itself is unaffected: {v:?}");
    assert_eq!(h.creds.load("codex-1").await.unwrap().1["auth.json"], before, "forged credential was stored");
    assert!(h.metrics.render().contains("acp_runner_credential_writebacks_total{result=\"rejected\"} 1"));
    let evs = h.engine.journal.events_for_run(v.run_id, 0, 10_000).await.unwrap();
    assert!(evs.iter().any(|e| e.data.get("category").and_then(|c| c.as_str()) == Some("credential_writeback_failed")));
    h.done().await;
}

/// Review finding 10: when the controller ends an attempt (cancel), runnerd's write-back on
/// its way out is still accepted while the attempt holds its lease; the lease is released only
/// after the sandbox is gone.
#[tokio::test]
async fn writeback_after_controller_cancel_is_accepted() {
    let Some(h) = H::new().await else { return };
    enroll_codex(&h, "codex-1").await;
    let mut c = h.class("codexish-hang", "refresh-credential:hang");
    c.credentials = CredentialRequirement {
        provider: Some("codex".into()),
        profiles: vec!["codex-1".into()],
        file_targets: BTreeMap::new(),
    };
    let mut input = h.input(vec![c], 1);
    let start = Instant::now();
    loop {
        let v = h.engine.reconcile(&input).await.unwrap();
        if v.current.as_ref().is_some_and(|c| c.phase == AttemptPhase::Running) {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(30));
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    tokio::time::sleep(Duration::from_millis(800)).await; // the agent has refreshed by now
    input.cancel = true;
    let v = h.drive(&input, Duration::from_secs(60)).await;
    assert_eq!(v.phase, RunPhase::Cancelled, "{v:?}");
    let stored: serde_json::Value =
        serde_json::from_slice(&h.creds.load("codex-1").await.unwrap().1["auth.json"]).unwrap();
    assert!(stored["tokens"]["access_token"].as_str().unwrap().starts_with("access-acct-1-"), "{stored}");
    assert!(h.engine.journal.active_leases().await.unwrap().is_empty());
    h.done().await;
}

/// Minimal HTTP client on hyper-less std TCP to avoid another dev-dependency.
mod reqwest_like {
    use std::io::{Read, Write};
    pub struct Client;
    impl Client {
        pub fn new() -> Self {
            Client
        }
        pub async fn get(&self, url: &str, bearer: Option<&str>) -> u16 {
            let url = url.to_string();
            let bearer = bearer.map(str::to_string);
            tokio::task::spawn_blocking(move || {
                let rest = url.strip_prefix("http://").unwrap();
                let (host, path) = rest.split_once('/').unwrap();
                let mut s = std::net::TcpStream::connect(host).unwrap();
                let auth = bearer.map(|b| format!("Authorization: Bearer {b}\r\n")).unwrap_or_default();
                write!(s, "GET /{path} HTTP/1.1\r\nHost: {host}\r\n{auth}Connection: close\r\n\r\n").unwrap();
                let mut buf = String::new();
                s.read_to_string(&mut buf).unwrap();
                buf.split_whitespace().nth(1).unwrap().parse().unwrap()
            })
            .await
            .unwrap()
        }
        pub async fn post(&self, url: &str, bearer: &str, body: &str) -> u16 {
            let (url, bearer, body) = (url.to_string(), bearer.trim().to_string(), body.to_string());
            tokio::task::spawn_blocking(move || {
                let rest = url.strip_prefix("http://").unwrap();
                let (host, path) = rest.split_once('/').unwrap();
                let mut s = std::net::TcpStream::connect(host).unwrap();
                write!(
                    s,
                    "POST /{path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {bearer}\r\nContent-Type: application/json\r\nx-acp-runner-wire-version: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    acp_runner_core::WIRE_VERSION,
                    body.len()
                )
                .unwrap();
                let mut buf = String::new();
                s.read_to_string(&mut buf).unwrap();
                buf.split_whitespace().nth(1).unwrap().parse().unwrap()
            })
            .await
            .unwrap()
        }
    }
}

/// Review finding 2 (trust boundary): a profile is only leased by the namespaces and classes
/// its policy names; an enrolled profile with no policy is unusable.
#[tokio::test]
async fn credential_profile_policy_limits_who_may_lease() {
    let Some(h) = H::new().await else { return };
    enroll_codex(&h, "codex-1").await;
    let codex_class = |h: &H| {
        let mut c = h.class("codexish", "ok");
        c.credentials = CredentialRequirement {
            provider: Some("codex".into()),
            profiles: vec!["codex-1".into()],
            file_targets: BTreeMap::new(),
        };
        c
    };
    for (policy, want) in [
        (acp_runner_engine::creds::ProfilePolicy::default(), "acp-runnerctl auth allow"),
        (
            acp_runner_engine::creds::ProfilePolicy {
                allowed_namespaces: vec!["team-b".into()],
                allowed_classes: vec![],
            },
            "not allowed for namespace default",
        ),
        (
            acp_runner_engine::creds::ProfilePolicy {
                allowed_namespaces: vec!["default".into()],
                allowed_classes: vec!["other".into()],
            },
            "not allowed for runner class codexish",
        ),
    ] {
        h.creds.set_policy("codex-1", &policy).await.unwrap();
        sync_profiles(h.creds.as_ref(), &h.engine.journal).await.unwrap();
        let v = h.drive(&h.input(vec![codex_class(&h)], 1), Duration::from_secs(30)).await;
        assert_eq!(v.phase, RunPhase::Failed, "{policy:?}: {v:?}");
        let evs = h.engine.journal.events_for_run(v.run_id, 0, 10_000).await.unwrap();
        assert!(evs.iter().any(|e| e.data.to_string().contains(want)), "{policy:?}: expected {want:?}");
    }
    let ok = acp_runner_engine::creds::ProfilePolicy {
        allowed_namespaces: vec!["default".into()],
        allowed_classes: vec!["codexish".into()],
    };
    h.creds.set_policy("codex-1", &ok).await.unwrap();
    sync_profiles(h.creds.as_ref(), &h.engine.journal).await.unwrap();
    let v = h.drive(&h.input(vec![codex_class(&h)], 1), Duration::from_secs(30)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    h.done().await;
}

/// Credentialed classes must run an allowlisted, digest-pinned image; named service accounts
/// must be allowlisted.
#[tokio::test]
async fn image_and_service_account_allowlists_are_enforced() {
    let Some(h) = H::with(
        |c| {
            c.allowed_images = vec!["ghcr.io/acp/runner".into()];
            c.allowed_service_accounts = vec!["acp-agent".into()];
        },
        8 * 1024 * 1024,
    )
    .await
    else {
        return;
    };
    enroll_codex(&h, "codex-1").await;
    let mut c = h.class("codexish", "ok");
    c.credentials = CredentialRequirement {
        provider: Some("codex".into()),
        profiles: vec!["codex-1".into()],
        file_targets: BTreeMap::new(),
    };
    c.image = "ghcr.io/acp/runner:latest".into();
    let v = h.drive(&h.input(vec![c.clone()], 1), Duration::from_secs(30)).await;
    assert_eq!(v.phase, RunPhase::Failed, "{v:?}");
    assert_eq!(v.attempt_count, 0);
    assert!(v.failure.unwrap().message().contains("digest-pinned"));

    let mut f = h.class("fake-default", "ok");
    f.service_account_name = Some("cluster-admin".into());
    let v = h.drive(&h.input(vec![f], 1), Duration::from_secs(30)).await;
    assert_eq!(v.phase, RunPhase::Failed, "{v:?}");
    assert!(v.failure.unwrap().message().contains("service account"));

    let mut f = h.class("fake-default", "ok");
    f.service_account_name = Some("acp-agent".into());
    let v = h.drive(&h.input(vec![f], 1), Duration::from_secs(30)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "uncredentialed classes need no pinned image: {v:?}");
    h.done().await;
}
