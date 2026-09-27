//! AgentEnvironment provider end-to-end through the real runnerd/agentd runtime
//! (LocalProcessBackend) and the provider boundary — no direct PostgreSQL for the caller.
//! Requires `ACP_TEST_DATABASE_URL`; skipped otherwise.

use acp_runner_client::{AcpClient, ClientError, Transport, connect_session};
use acp_runner_core::bundle::{Bundle, BundleKind, text_file};
use acp_runner_core::credentials::{CredentialBundle, Provider, validate_bundle};
use acp_runner_core::environment::{
    EnvironmentOutput, EnvironmentOverrides, EnvironmentPhase, EnvironmentSpec, HarnessSpec, Lifetime, OutputArtifact,
};
use acp_runner_core::spec::RepositoryInput;
use acp_runner_engine::backend::LocalProcessBackend;
use acp_runner_engine::bundles::StaticBundleProvider;
use acp_runner_engine::compat::{OneShot, execute};
use acp_runner_engine::creds::{CredentialStore, FileCredentialStore, StoredProfile, sync_profiles};
use acp_runner_engine::environment::{EnvironmentConfig, EnvironmentProvider, ProviderError};
use acp_runner_engine::harness::DirHarnessProvider;
use acp_runner_engine::ingest::{IngestState, router};
use acp_runner_engine::metrics::Metrics;
use acp_runner_journal::testing::{TempDb, temp_database};
use acp_runner_journal::{ArtifactStore, PgArtifactStore};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

fn bins() {
    static B: std::sync::Once = std::sync::Once::new();
    B.call_once(|| {
        assert!(
            std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
                .args(["build", "-q", "-p", "runnerd", "-p", "agentd", "-p", "fake-acp-agent"])
                .status()
                .unwrap()
                .success()
        );
    });
}

fn target_dir() -> PathBuf {
    std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().to_path_buf()
}

async fn fixture(dir: &std::path::Path) -> String {
    tokio::fs::create_dir_all(dir).await.unwrap();
    std::fs::write(dir.join("add.sh"), "#!/bin/sh\nadd() {\n  echo $(( $1 - $2 ))\n}\nadd \"$1\" \"$2\"\n").unwrap();
    std::fs::create_dir_all(dir.join("docs")).unwrap();
    std::fs::write(dir.join("docs/notes.md"), "notes\n").unwrap();
    let git = |a: &[&str]| {
        let o = std::process::Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main"])
            .args(a)
            .current_dir(dir)
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    };
    git(&["init", "-q"]);
    git(&["add", "-A"]);
    git(&["commit", "-qm", "buggy"]);
    git(&["rev-parse", "HEAD"])
}

struct H {
    db: Option<TempDb>,
    provider: Arc<EnvironmentProvider>,
    ingest: Arc<IngestState>,
    backend: Arc<LocalProcessBackend>,
    cfg: EnvironmentConfig,
    bundles: Arc<StaticBundleProvider>,
    creds: Arc<FileCredentialStore>,
    harness_root: PathBuf,
    _tmp: tempfile::TempDir,
    repo_url: String,
    base_sha: String,
    fake: PathBuf,
}

impl H {
    async fn new() -> Option<H> {
        bins();
        let db = temp_database().await?;
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("upstream");
        let base_sha = fixture(&src).await;
        let journal = db.journal.clone();
        let metrics = Arc::new(Metrics::new());
        let artifacts: Arc<dyn ArtifactStore> = Arc::new(PgArtifactStore::new(journal.clone(), 8 << 20, None));
        let creds = Arc::new(FileCredentialStore { root: tmp.path().join("creds") });
        let harness_root = tmp.path().join("harnesses");
        let harnesses = Arc::new(DirHarnessProvider::new(harness_root.clone()));
        let ingest = Arc::new(
            IngestState::new(journal.clone(), artifacts.clone(), creds.clone(), metrics, None)
                .with_harnesses(harnesses.clone()),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        {
            let ingest = ingest.clone();
            tokio::spawn(async move { axum::serve(listener, router(ingest)).await.unwrap() });
        }
        // `codex` / `codex-acp` resolve to the fake agent's Codex emulation.
        let fake_codex = tmp.path().join("fake-codex-bin");
        std::fs::create_dir_all(&fake_codex).unwrap();
        for name in ["codex", "codex-acp"] {
            std::os::unix::fs::symlink(target_dir().join("fake-acp-agent"), fake_codex.join(name)).unwrap();
        }
        let backend = Arc::new(LocalProcessBackend::new(
            target_dir().join("runnerd"),
            tmp.path().join("sandboxes"),
            format!("{}:{}", fake_codex.display(), std::env::var("PATH").unwrap_or_default()),
        ));
        let cfg = EnvironmentConfig {
            controller_id: "env-test".into(),
            ingest_url: format!("http://{addr}"),
            gateway_listen: "127.0.0.1:0".into(),
            require_egress_proxy_for_credentials: false,
            runner_image: "local".into(),
            allow_file_repositories: true,
            ..Default::default()
        };
        let bundles = Arc::new(StaticBundleProvider::default());
        let provider = Arc::new(
            EnvironmentProvider::new(journal, backend.clone(), creds.clone(), artifacts, ingest.clone(), cfg.clone())
                .with_bundles(bundles.clone())
                .with_harnesses(harnesses),
        );
        Some(H {
            db: Some(db),
            provider,
            ingest,
            backend,
            cfg,
            bundles,
            creds,
            harness_root,
            repo_url: format!("file://{}", src.display()),
            base_sha,
            fake: target_dir().join("fake-acp-agent"),
            _tmp: tmp,
        })
    }

    fn spec(&self, external_ref: &str) -> EnvironmentSpec {
        EnvironmentSpec::new(
            external_ref,
            HarnessSpec {
                name: "fake".into(),
                version: None,
                digest: None,
                config: json!({"command": self.fake.to_string_lossy()}),
            },
            Some(RepositoryInput {
                url: self.repo_url.clone(),
                revision: self.base_sha.clone(),
                sparse_paths: vec![],
                depth: None,
            }),
        )
    }

    async fn done(mut self) {
        if let Some(db) = self.db.take() {
            db.drop_db().await;
        }
    }
}

impl H {
    /// A second provider instance over the same journal/backend/ingest and master key —
    /// what a restarted controller looks like. It holds no per-environment secrets.
    fn restarted_provider(&self) -> EnvironmentProvider {
        EnvironmentProvider::new(
            self.provider.journal.clone(),
            self.backend.clone(),
            self.provider.creds.clone(),
            self.provider.artifacts.clone(),
            self.ingest.clone(),
            self.cfg.clone(),
        )
    }
}

#[tokio::test]
async fn provider_create_connect_turns_snapshot_finish() {
    let Some(h) = H::new().await else { return };
    let view = h.provider.create(h.spec("task-A")).await.unwrap();
    assert_eq!(view.phase, EnvironmentPhase::Creating);
    // connect (env-scoped token, distinct from provider creds).
    let conn = h.provider.connect(view.id, Duration::from_secs(60)).await.unwrap();
    assert_eq!(conn.environment_id, view.id);
    // getEnvironment exposes status through the provider (no direct DB for the caller).
    let got = h.provider.get(view.id).await.unwrap().unwrap();
    assert!(matches!(got.phase, EnvironmentPhase::Idle));
    assert_eq!(got.connection.as_ref().unwrap().gateway, conn.gateway);
    assert_eq!(got.base_revision.as_deref(), Some(h.base_sha.as_str()));

    let (mut client, session) = connect_session(&conn.gateway, &conn.ticket, Transport::Raw).await.expect("attach");
    assert_eq!(client.prompt(&session, "[[fake:fix]] fix add.sh").await.unwrap().stop_reason, "end_turn");
    // snapshot at Idle, environment stays alive.
    let snap1 = h.provider.snapshot(view.id, Some("s1".into())).await.unwrap();
    let _ = snap1;
    wait_snapshots(&h.provider, view.id, 1).await;
    // a second turn modifies a new file; a second snapshot reflects it.
    assert_eq!(client.prompt(&session, "[[fake:touch:extra.txt]] add file").await.unwrap().stop_reason, "end_turn");
    h.provider.snapshot(view.id, Some("s2".into())).await.unwrap();
    let got = wait_snapshots(&h.provider, view.id, 2).await;
    assert!(got.snapshots.last().unwrap().changed_paths >= 2, "{:?}", got.snapshots);

    // finish → final artifact, environment destroyed.
    let done = h.provider.finish(view.id, Duration::from_secs(60)).await.unwrap();
    assert_eq!(done.phase, EnvironmentPhase::Completed, "{done:?}");
    let art_id = done.final_artifact_id.expect("final artifact");
    let content = h.provider.artifacts.get_content(art_id).await.unwrap();
    let text = String::from_utf8_lossy(&content);
    assert!(text.contains("add.sh") && text.contains("extra.txt"), "final patch missing files");
    h.done().await;
}

#[tokio::test]
async fn provider_denies_cross_environment_ticket() {
    let Some(h) = H::new().await else { return };
    let a = h.provider.create(h.spec("A")).await.unwrap();
    let b = h.provider.create(h.spec("B")).await.unwrap();
    let ca = h.provider.connect(a.id, Duration::from_secs(60)).await.unwrap();
    let cb = h.provider.connect(b.id, Duration::from_secs(60)).await.unwrap();
    // A's ticket cannot open B's gateway.
    let cross = AcpClient::connect(&cb.gateway, &ca.ticket, Transport::Raw).await;
    assert!(matches!(cross, Err(ClientError::Rejected { .. })), "cross-environment ticket accepted");
    // and the matching tickets still work.
    let _ = AcpClient::connect(&ca.gateway, &ca.ticket, Transport::Raw).await.expect("A attaches");
    let _ = AcpClient::connect(&cb.gateway, &cb.ticket, Transport::WebSocket).await.expect("B attaches");
    // the connection view never carries the ticket
    let v = serde_json::to_string(&h.provider.get(a.id).await.unwrap().unwrap()).unwrap();
    assert!(!v.contains(&ca.ticket));
    h.provider.cancel(a.id, "test", Duration::from_secs(60)).await.unwrap();
    h.provider.cancel(b.id, "test", Duration::from_secs(60)).await.unwrap();
    h.done().await;
}

#[tokio::test]
async fn provider_restart_keeps_the_environment_connectable() {
    let Some(h) = H::new().await else { return };
    let view = h.provider.create(h.spec("survivor")).await.unwrap();
    let first = h.provider.connect(view.id, Duration::from_secs(60)).await.unwrap();
    // "restart": a fresh provider instance with the same master key and durable state only.
    let p2 = h.restarted_provider();
    let conn = p2.connect(view.id, Duration::from_secs(10)).await.unwrap();
    assert_ne!(conn.ticket, first.ticket);
    let (mut client, session) = connect_session(&conn.gateway, &conn.ticket, Transport::WebSocket).await.unwrap();
    assert_eq!(client.prompt(&session, "[[fake:fix]] fix").await.unwrap().stop_reason, "end_turn");
    // a provider with a different master key cannot mint working tickets
    let other = EnvironmentProvider::new(
        h.provider.journal.clone(),
        h.backend.clone(),
        h.provider.creds.clone(),
        h.provider.artifacts.clone(),
        h.ingest.clone(),
        EnvironmentConfig { ticket_key: acp_runner_engine::environment::random_ticket_key(), ..h.cfg.clone() },
    );
    let bad = other.connect(view.id, Duration::from_secs(10)).await.unwrap();
    assert!(matches!(
        AcpClient::connect(&bad.gateway, &bad.ticket, Transport::Raw).await,
        Err(ClientError::Rejected { status: 401, .. })
    ));
    let done = p2.finish(view.id, Duration::from_secs(60)).await.unwrap();
    assert_eq!(done.phase, EnvironmentPhase::Completed);
    h.done().await;
}

#[tokio::test]
async fn compat_wrapper_runs_one_shot_and_produces_the_patch() {
    let Some(h) = H::new().await else { return };
    let req = OneShot {
        external_ref: "oneshot".into(),
        harness: HarnessSpec {
            name: "fake".into(),
            version: None,
            digest: None,
            config: json!({"command": h.fake.to_string_lossy()}),
        },
        repository: RepositoryInput {
            url: h.repo_url.clone(),
            revision: h.base_sha.clone(),
            sparse_paths: vec![],
            depth: None,
        },
        credential_profile: None,
        prompt: "[[fake:fix]] fix add.sh".into(),
    };
    let view = execute(&h.provider, req, Duration::from_secs(60)).await.unwrap();
    assert_eq!(view.phase, EnvironmentPhase::Completed, "{view:?}");
    let content = h.provider.artifacts.get_content(view.final_artifact_id.expect("artifact")).await.unwrap();
    assert!(String::from_utf8_lossy(&content).contains("add.sh"));
    h.done().await;
}

async fn wait_snapshots(
    p: &EnvironmentProvider,
    id: Uuid,
    n: usize,
) -> acp_runner_engine::environment::EnvironmentView {
    let start = std::time::Instant::now();
    loop {
        let v = p.get(id).await.unwrap().unwrap();
        if v.snapshots.len() >= n {
            return v;
        }
        assert!(start.elapsed() < Duration::from_secs(30), "snapshots {}<{n}", v.snapshots.len());
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

/// implement → snapshot S1 → review (short branch: overlay S1, reviewer config, no output
/// artifact) → fix (branch of S1) → final artifact cumulative against the original base with
/// lineage S1/A. The orchestrator never handles patch bytes.
#[tokio::test]
async fn implement_review_fix_is_just_branching() {
    let Some(h) = H::new().await else { return };
    h.bundles.insert(
        Bundle::new(
            BundleKind::Config,
            "reviewer-config",
            vec![text_file("CLAUDE.md", "REVIEW RULES: be strict\n")],
            json!({}),
        )
        .unwrap(),
    );
    h.bundles.insert(
        Bundle::new(BundleKind::Skill, "review-rules", vec![text_file("SKILL.md", "# review")], json!({})).unwrap(),
    );
    // implementation environment A
    let a = h.provider.create(h.spec("impl-1")).await.unwrap();
    let ca = h.provider.connect(a.id, Duration::from_secs(60)).await.unwrap();
    let (mut client, session) = connect_session(&ca.gateway, &ca.ticket, Transport::Raw).await.unwrap();
    client.prompt(&session, "[[fake:fix]] implement").await.unwrap();
    let s1 = h.provider.snapshot_and_wait(a.id, Some("S1".into()), Duration::from_secs(30)).await.unwrap();

    // review = short branch of S1 (A stays alive)
    let review = h
        .provider
        .branch(
            s1,
            EnvironmentOverrides {
                configs: Some(vec!["reviewer-config".into()]),
                skills: Some(vec!["review-rules".into()]),
                lifetime: Some(Lifetime { idle_seconds: Some(300), max_seconds: Some(600) }),
                output: Some(EnvironmentOutput { artifact: OutputArtifact::None }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(review.lineage.parent_artifact_id, Some(s1));
    assert_eq!(review.lineage.parent_environment_id, Some(a.id));
    let cr = h.provider.connect(review.id, Duration::from_secs(60)).await.unwrap();
    let (mut rc, rs) = connect_session(&cr.gateway, &cr.ticket, Transport::WebSocket).await.unwrap();
    let seen = rc.prompt(&rs, "[[fake:read:add.sh]] review the change").await.unwrap();
    assert!(seen.text.contains("$(( $1 + $2 ))"), "reviewer does not see S1: {seen:?}");
    let rules = rc.prompt(&rs, "[[fake:read:CLAUDE.md]]").await.unwrap();
    assert!(rules.text.contains("REVIEW RULES"), "{rules:?}");
    let done = h.provider.finish(review.id, Duration::from_secs(60)).await.unwrap();
    assert_eq!(done.phase, EnvironmentPhase::Completed);
    assert!(done.final_artifact_id.is_none(), "review with output none produced an artifact");

    // fix = another branch of S1 (with the same injected config, which must not leak into the patch)
    let fix = h
        .provider
        .branch(s1, EnvironmentOverrides { configs: Some(vec!["reviewer-config".into()]), ..Default::default() })
        .await
        .unwrap();
    let cf = h.provider.connect(fix.id, Duration::from_secs(60)).await.unwrap();
    let (mut fc, fs) = connect_session(&cf.gateway, &cf.ticket, Transport::Raw).await.unwrap();
    fc.prompt(&fs, "[[fake:touch:fix.txt]] address findings").await.unwrap();
    let fixed = h.provider.finish(fix.id, Duration::from_secs(60)).await.unwrap();
    let f1 = fixed.final_artifact_id.expect("fix artifact");
    let meta = h.provider.artifacts.get_meta(f1).await.unwrap();
    // cumulative against the ORIGINAL base, lineage recorded as metadata
    assert_eq!(meta.base_revision, h.base_sha);
    assert_eq!(meta.parent_artifact_id, Some(s1));
    assert_eq!(meta.parent_environment_id, Some(a.id));
    assert_eq!(meta.environment_id, Some(fix.id));
    let patch = String::from_utf8_lossy(&h.provider.artifacts.get_content(f1).await.unwrap()).to_string();
    assert!(patch.contains("add.sh") && patch.contains("fix.txt"), "{patch}");
    assert!(!patch.contains("CLAUDE.md"), "provider-injected config leaked into the artifact");
    // finishing A still yields its own cumulative artifact
    let fa = h.provider.finish(a.id, Duration::from_secs(60)).await.unwrap();
    assert!(fa.final_artifact_id.is_some());
    h.done().await;
}

#[tokio::test]
async fn provider_verifies_overlay_hash_and_base() {
    let Some(h) = H::new().await else { return };
    let a = h.provider.create(h.spec("A")).await.unwrap();
    let ca = h.provider.connect(a.id, Duration::from_secs(60)).await.unwrap();
    let (mut c, s) = connect_session(&ca.gateway, &ca.ticket, Transport::Raw).await.unwrap();
    c.prompt(&s, "[[fake:fix]] fix").await.unwrap();
    let s1 = h.provider.snapshot_and_wait(a.id, None, Duration::from_secs(30)).await.unwrap();
    h.provider.finish(a.id, Duration::from_secs(60)).await.unwrap();
    // explicit source with another revision than the artifact's base → refused
    let mut spec = h.spec("B");
    if let Some(acp_runner_core::environment::WorkspaceSource::Git(r)) = &mut spec.workspace.source {
        r.revision = "1111111111111111111111111111111111111111".into();
    }
    spec.workspace.overlays = vec![acp_runner_core::environment::WorkspaceOverlay::PatchArtifact { artifact_id: s1 }];
    let e = h.provider.create(spec).await.unwrap_err();
    assert!(e.to_string().contains("is not the overlays' base"), "{e}");
    // tampered stored content → refused (hash verification)
    sqlx::query("UPDATE artifacts SET content = content || '\n'::bytea WHERE id = $1")
        .bind(s1)
        .execute(h.provider.journal.pool())
        .await
        .unwrap();
    let e = h.provider.branch(s1, Default::default()).await.unwrap_err();
    assert!(e.to_string().contains("sha256"), "{e}");
    // unknown artifact
    assert!(h.provider.branch(Uuid::now_v7(), Default::default()).await.is_err());
    h.done().await;
}

#[tokio::test]
async fn workdir_is_the_harness_cwd_through_the_provider() {
    let Some(h) = H::new().await else { return };
    let mut spec = h.spec("wd");
    spec.workspace.workdir = Some("./docs/".into());
    let v = h.provider.create(spec).await.unwrap();
    assert_eq!(v.workdir, "docs");
    let conn = h.provider.connect(v.id, Duration::from_secs(60)).await.unwrap();
    let (mut c, s) = connect_session(&conn.gateway, &conn.ticket, Transport::Raw).await.unwrap();
    assert!(c.info.workdir.as_deref().unwrap().ends_with("/docs"), "{:?}", c.info.workdir);
    c.prompt(&s, "[[fake:touch:in-docs.txt]]").await.unwrap();
    let done = h.provider.finish(v.id, Duration::from_secs(60)).await.unwrap();
    let patch = h.provider.artifacts.get_content(done.final_artifact_id.unwrap()).await.unwrap();
    assert!(String::from_utf8_lossy(&patch).contains("b/docs/in-docs.txt"));
    // an escaping workdir never gets past validation
    let mut bad = h.spec("wd-bad");
    bad.workspace.workdir = Some("../etc".into());
    assert!(matches!(
        h.provider.create(bad).await.unwrap_err().downcast_ref::<ProviderError>(),
        Some(ProviderError::InvalidSpec(_))
    ));
    h.done().await;
}

fn fake_codex_auth(account: &str) -> Vec<u8> {
    use base64::Engine as _;
    let b64 = |v: serde_json::Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
    let jwt = |claims: serde_json::Value| {
        format!("{}.{}.{}", b64(json!({"alg":"none"})), b64(claims), b64(json!("sig-000000000")))
    };
    json!({
        "auth_mode": "chatgpt", "OPENAI_API_KEY": null,
        "tokens": {"id_token": jwt(json!({"email":"a@example.com","https://api.openai.com/auth":{"chatgpt_plan_type":"plus","chatgpt_account_id":account}})),
                   "access_token": jwt(json!({"exp": 1900000000})), "refresh_token": "rt_test_refresh_token_value_0000000000", "account_id": account},
        "last_refresh": "2026-09-20T00:00:00Z"
    })
    .to_string()
    .into_bytes()
}

/// Subscription credentials are leased for the environment's lifetime (not per turn),
/// exclusively, renewed by heartbeats, and released only after the validated write-back.
#[tokio::test]
async fn environment_holds_an_exclusive_credential_lease_for_its_lifetime() {
    let Some(h) = H::new().await else { return };
    let mut bundle = CredentialBundle::new();
    bundle.insert("auth.json".into(), fake_codex_auth("acct-1"));
    let md = validate_bundle(Provider::Codex, &bundle).unwrap();
    h.creds
        .save(
            &StoredProfile {
                name: "codex-1".into(),
                provider: Provider::Codex,
                max_concurrent_leases: 3,
                metadata: md,
                store_ref: String::new(),
            },
            &bundle,
        )
        .await
        .unwrap();
    sync_profiles(h.creds.as_ref(), &h.provider.journal).await.unwrap();
    let codex_spec = |r: &str| {
        let mut s = h.spec(r);
        s.harness = HarnessSpec::named("codex");
        s.credentials.profile = Some("codex-1".into());
        s
    };
    let a = h.provider.create(codex_spec("A")).await.unwrap();
    let leases = h.provider.journal.active_leases().await.unwrap();
    assert_eq!(leases.len(), 1);
    let initial_expiry = leases[0].expires_at;
    // a second environment on the same exclusive profile is refused while A lives
    let e = h.provider.create(codex_spec("B")).await.unwrap_err();
    assert!(matches!(e.downcast_ref::<ProviderError>(), Some(ProviderError::CredentialBusy { .. })), "{e}");
    // the lease outlives turns: two turns, one of them refreshes the token
    let ca = h.provider.connect(a.id, Duration::from_secs(60)).await.unwrap();
    let (mut c, s) = connect_session(&ca.gateway, &ca.ticket, Transport::Raw).await.unwrap();
    c.prompt(&s, "[[fake:noop]] first turn").await.unwrap();
    c.prompt(&s, "[[fake:refresh-credential]] second turn").await.unwrap();
    assert_eq!(h.provider.journal.active_leases().await.unwrap().len(), 1, "lease must span turns");
    // heartbeats keep extending the lease
    tokio::time::sleep(Duration::from_secs(3)).await;
    let renewed = h.provider.journal.active_leases().await.unwrap()[0].expires_at;
    assert!(renewed >= initial_expiry, "{renewed} < {initial_expiry}");
    let done = h.provider.finish(a.id, Duration::from_secs(60)).await.unwrap();
    assert_eq!(done.phase, EnvironmentPhase::Completed, "{done:?}");
    // validated write-back happened before the release; the lease is gone
    let (_, stored) = h.creds.load("codex-1").await.unwrap();
    assert!(String::from_utf8_lossy(&stored["auth.json"]).contains("\"refreshed\":true"));
    assert!(h.provider.journal.active_leases().await.unwrap().is_empty());
    // now the profile is free again
    let b = h.provider.create(codex_spec("B2")).await.unwrap();
    h.provider.cancel(b.id, "test", Duration::from_secs(60)).await.unwrap();
    assert!(h.provider.journal.active_leases().await.unwrap().is_empty());
    // credential values never reach the journal
    let all = sqlx::query_scalar::<_, String>("SELECT data::text FROM session_events")
        .fetch_all(h.provider.journal.pool())
        .await
        .unwrap()
        .join("\n");
    assert!(!all.contains("rt_test_refresh_token_value"));
    h.done().await;
}

/// Publish `fake-acp-agent` as harness `fake@<version>` (tar.gz + manifest with the pin).
fn publish_fake_harness(h: &H, version: &str) -> (PathBuf, String) {
    use sha2::Digest;
    let bin = std::fs::read(&h.fake).unwrap();
    let mut b = tar::Builder::new(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast()));
    let mut hd = tar::Header::new_gnu();
    hd.set_size(bin.len() as u64);
    hd.set_mode(0o755);
    hd.set_entry_type(tar::EntryType::Regular);
    hd.set_cksum();
    b.append_data(&mut hd, "bin/fake-acp-agent", bin.as_slice()).unwrap();
    let bytes = b.into_inner().unwrap().finish().unwrap();
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&bytes)));
    let dir = h.harness_root.join("fake").join(version);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("harness.tar.gz"), &bytes).unwrap();
    std::fs::write(
        dir.join("manifest.json"),
        json!({"digest": digest, "archive": "harness.tar.gz", "executable": "bin/fake-acp-agent", "adapter": "fake",
               "driverConfig": {"command": "{harness}/bin/fake-acp-agent"}, "path": ["bin"]})
        .to_string(),
    )
    .unwrap();
    (dir.join("harness.tar.gz"), digest)
}

/// One runtime image; the harness is a pinned, digest-verified artifact materialized at
/// bootstrap (resolve(name, version) → digest, executable, adapter, manifest).
#[tokio::test]
async fn harness_provider_materializes_pinned_artifacts() {
    let Some(h) = H::new().await else { return };
    let (archive, digest) = publish_fake_harness(&h, "1.0.0");
    let harness = |version: &str, digest: Option<String>| HarnessSpec {
        name: "fake".into(),
        version: Some(version.into()),
        digest,
        config: json!({}),
    };
    let mut spec = h.spec("harness-1");
    spec.harness = harness("1.0.0", Some(digest.clone()));
    let v = h.provider.create(spec).await.unwrap();
    let conn = h.provider.connect(v.id, Duration::from_secs(60)).await.unwrap();
    let (mut c, s) = connect_session(&conn.gateway, &conn.ticket, Transport::Raw).await.unwrap();
    assert_eq!(c.prompt(&s, "[[fake:fix]]").await.unwrap().stop_reason, "end_turn");
    let done = h.provider.finish(v.id, Duration::from_secs(60)).await.unwrap();
    assert_eq!(done.phase, EnvironmentPhase::Completed, "{done:?}");
    let evs = sqlx::query_scalar::<_, String>(
        "SELECT data::text FROM session_events WHERE data->>'category' = 'harness_materialized'",
    )
    .fetch_all(h.provider.journal.pool())
    .await
    .unwrap();
    assert_eq!(evs.len(), 1);
    assert!(evs[0].contains(&digest));
    // a different pin, an unknown version, and a tampered archive are all refused
    let mut spec = h.spec("harness-2");
    spec.harness = harness("1.0.0", Some(format!("sha256:{}", "0".repeat(64))));
    assert!(h.provider.create(spec).await.unwrap_err().to_string().contains("pins"));
    let mut spec = h.spec("harness-3");
    spec.harness = harness("9.9.9", None);
    assert!(h.provider.create(spec).await.is_err());
    std::fs::write(&archive, b"tampered").unwrap();
    let mut spec = h.spec("harness-4");
    spec.harness = harness("1.0.0", None);
    let e = h.provider.create(spec).await.unwrap_err().to_string();
    assert!(e.contains("does not match the pinned"), "{e}");
    h.done().await;
}
