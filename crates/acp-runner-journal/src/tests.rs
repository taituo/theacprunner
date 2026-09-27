use super::*;
use crate::testing::temp_database;
use acp_runner_core::events::{EventEnvelope, EventKind, EventSource};
use serde_json::json;
use std::sync::Arc;

fn new_run() -> NewRun {
    let id = Uuid::now_v7();
    NewRun {
        id,
        k8s_namespace: "default".into(),
        k8s_name: format!("run-{}", id.simple()),
        k8s_uid: Uuid::new_v4().to_string(),
        task_id: "task".into(),
        spec: json!({"x": 1}),
    }
}

fn new_attempt(run: Uuid, ordinal: i32) -> NewAttempt {
    NewAttempt {
        id: Uuid::now_v7(),
        run_id: run,
        ordinal,
        class_index: 0,
        class_attempt: ordinal,
        runner_class: "codex-default".into(),
        driver: "codex".into(),
        spec: json!({}),
        ingest_token_hash: Uuid::new_v4().simple().to_string(),
        lease_owner: "controller-a".into(),
        lease_ttl: Duration::from_secs(60),
    }
}

fn lease_req(ttl: Duration) -> LeaseRequest {
    LeaseRequest { provider: "codex".into(), candidates: vec!["p1".into()], holder: "controller-a".into(), ttl }
}

async fn profile(j: &Journal, name: &str, max: i32) {
    j.upsert_profile(&ProfileUpsert {
        name: name.into(),
        provider: "codex".into(),
        store: "test".into(),
        max_concurrent_leases: max,
        metadata: json!({}),
        material_fingerprint: "fp1".into(),
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn run_creation_is_idempotent_and_journaled_once() {
    let Some(db) = temp_database().await else { return };
    let j = &db.journal;
    j.migrate().await.unwrap(); // idempotent
    let nr = new_run();
    let (r1, created1) = j.ensure_run(&nr).await.unwrap();
    let (r2, created2) = j.ensure_run(&nr).await.unwrap();
    assert!(created1 && !created2);
    assert_eq!(r1.id, r2.id);
    let evs = j.events_for_run(r1.id, 0, 100).await.unwrap();
    assert_eq!(evs.iter().filter(|e| e.kind == "RunCreated").count(), 1);
    db.drop_db().await;
}

#[tokio::test]
async fn session_events_are_append_only_and_idempotent() {
    let Some(db) = temp_database().await else { return };
    let j = &db.journal;
    let (run, _) = j.ensure_run(&new_run()).await.unwrap();
    let a = match j.start_attempt(&new_attempt(run.id, 1), None).await.unwrap() {
        StartAttempt::Started { attempt, .. } => attempt,
        other => panic!("{other:?}"),
    };
    let mut ev = EventEnvelope::new(EventKind::AgentOutput, EventSource::Driver, json!({"text": "hi"}));
    ev.seq = Some(1);
    assert_eq!(j.append_events(run.id, Some(a.id), &[ev.clone(), ev.clone()]).await.unwrap(), 1);
    assert!(!j.append_event(run.id, Some(a.id), &ev).await.unwrap());
    let upd = sqlx::query("UPDATE session_events SET kind = 'X'").execute(j.pool()).await;
    assert!(upd.unwrap_err().to_string().contains("append-only"));
    let del = sqlx::query("DELETE FROM session_events").execute(j.pool()).await;
    assert!(del.unwrap_err().to_string().contains("append-only"));
    db.drop_db().await;
}

#[tokio::test]
async fn advisory_run_lock_is_exclusive() {
    let Some(db) = temp_database().await else { return };
    let j = &db.journal;
    let id = Uuid::now_v7();
    let l1 = j.try_lock_run(id).await.unwrap().expect("first lock");
    assert!(j.try_lock_run(id).await.unwrap().is_none());
    assert!(j.try_lock_run(Uuid::now_v7()).await.unwrap().is_some());
    l1.release().await.unwrap();
    // release explicitly: a dropped lock is rolled back asynchronously by the pool
    j.try_lock_run(id).await.unwrap().expect("lock after release").release().await.unwrap();
    // dropping without release also frees it (transaction rollback)
    {
        let _l = j.try_lock_run(id).await.unwrap().unwrap();
    }
    // the rollback of a dropped transaction happens asynchronously: poll briefly
    let start = std::time::Instant::now();
    while j.try_lock_run(id).await.unwrap().is_none() {
        assert!(start.elapsed() < Duration::from_secs(5), "dropped lock was never released");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    db.drop_db().await;
}

#[tokio::test]
async fn credential_leases_are_exclusive_expire_and_respect_status() {
    let Some(db) = temp_database().await else { return };
    let j = &db.journal;
    profile(j, "p1", 1).await;
    let (run, _) = j.ensure_run(&new_run()).await.unwrap();
    let a1 = new_attempt(run.id, 1);
    let r1 = j.start_attempt(&a1, Some(&lease_req(Duration::from_secs(60)))).await.unwrap();
    let StartAttempt::Started { lease: Some(l1), attempt } = r1 else { panic!("{r1:?}") };
    assert_eq!(l1.profile_name, "p1");
    assert_eq!(attempt.credential_profile.as_deref(), Some("p1"));

    // second run cannot lease the exclusive profile; nothing is persisted for it
    let (run2, _) = j.ensure_run(&new_run()).await.unwrap();
    let a2 = new_attempt(run2.id, 1);
    let r2 = j.start_attempt(&a2, Some(&lease_req(Duration::from_secs(60)))).await.unwrap();
    assert!(matches!(r2, StartAttempt::NoCredentialAvailable { .. }), "{r2:?}");
    assert!(j.attempts_for_run(run2.id).await.unwrap().is_empty());

    // release -> available
    assert!(j.release_lease(a1.id).await.unwrap());
    let r2 = j.start_attempt(&a2, Some(&lease_req(Duration::from_millis(1)))).await.unwrap();
    assert!(matches!(r2, StartAttempt::Started { lease: Some(_), .. }));

    // an expired (stale) lease no longer blocks
    tokio::time::sleep(Duration::from_millis(20)).await;
    let (run3, _) = j.ensure_run(&new_run()).await.unwrap();
    let r3 = j.start_attempt(&new_attempt(run3.id, 1), Some(&lease_req(Duration::from_secs(60)))).await.unwrap();
    assert!(matches!(r3, StartAttempt::Started { lease: Some(_), .. }), "{r3:?}");

    // needs_reauth profiles are unusable; re-enrollment (new fingerprint) re-activates
    j.set_profile_status("p1", "needs_reauth", Some("401")).await.unwrap();
    let (run4, _) = j.ensure_run(&new_run()).await.unwrap();
    let r4 = j.start_attempt(&new_attempt(run4.id, 1), Some(&lease_req(Duration::from_secs(60)))).await.unwrap();
    assert!(matches!(r4, StartAttempt::CredentialUnusable { .. }), "{r4:?}");
    j.upsert_profile(&ProfileUpsert {
        name: "p1".into(),
        provider: "codex".into(),
        store: "test".into(),
        max_concurrent_leases: 1,
        metadata: json!({}),
        material_fingerprint: "fp2".into(),
    })
    .await
    .unwrap();
    assert_eq!(j.get_profile("p1").await.unwrap().unwrap().status, "active");
    db.drop_db().await;
}

#[tokio::test]
async fn supervision_lease_takeover_of_stale_controller() {
    let Some(db) = temp_database().await else { return };
    let j = &db.journal;
    let (run, _) = j.ensure_run(&new_run()).await.unwrap();
    let mut na = new_attempt(run.id, 1);
    na.lease_owner = "dead-controller".into();
    na.lease_ttl = Duration::from_millis(1);
    let StartAttempt::Started { attempt, .. } = j.start_attempt(&na, None).await.unwrap() else { panic!() };
    tokio::time::sleep(Duration::from_millis(20)).await;
    let r = j.renew_supervision_lease(attempt.id, "controller-b", Duration::from_secs(30)).await.unwrap();
    assert_eq!(r, Ok(Some("dead-controller".to_string())));
    // a live lease held by B cannot be taken by C
    let r = j.renew_supervision_lease(attempt.id, "controller-c", Duration::from_secs(30)).await.unwrap();
    assert_eq!(r, Err("controller-b".to_string()));
    // B renews its own lease
    assert_eq!(j.renew_supervision_lease(attempt.id, "controller-b", Duration::from_secs(30)).await.unwrap(), Ok(None));
    db.drop_db().await;
}

#[tokio::test]
async fn attempt_transitions_are_conditional() {
    let Some(db) = temp_database().await else { return };
    let j = &db.journal;
    let (run, _) = j.ensure_run(&new_run()).await.unwrap();
    let StartAttempt::Started { attempt, .. } = j.start_attempt(&new_attempt(run.id, 1), None).await.unwrap() else {
        panic!()
    };
    assert!(
        j.transition_attempt(attempt.id, &[AttemptPhase::Pending], AttemptPhase::Starting, None, None).await.unwrap()
    );
    assert!(
        !j.transition_attempt(attempt.id, &[AttemptPhase::Pending], AttemptPhase::Running, None, None).await.unwrap()
    );
    let f = FailureReason::NoChanges;
    assert!(
        j.transition_attempt(attempt.id, &AttemptPhase::ACTIVE, AttemptPhase::Failed, Some(&f), None).await.unwrap()
    );
    assert!(
        !j.transition_attempt(attempt.id, &AttemptPhase::ACTIVE, AttemptPhase::Succeeded, None, None).await.unwrap()
    );
    let a = j.get_attempt(attempt.id).await.unwrap();
    assert_eq!(a.phase(), AttemptPhase::Failed);
    assert_eq!(a.failure(), Some(FailureReason::NoChanges));
    assert!(a.finished_at.is_some());
    let r = j.get_run(run.id).await.unwrap();
    assert_eq!(r.phase(), RunPhase::Running);
    assert_eq!(r.current_attempt_id, Some(attempt.id));
    db.drop_db().await;
}

#[tokio::test]
async fn artifact_store_inline_external_and_limits() {
    let Some(db) = temp_database().await else { return };
    let j = db.journal.clone();
    let (run, _) = j.ensure_run(&new_run()).await.unwrap();
    let StartAttempt::Started { attempt, .. } = j.start_attempt(&new_attempt(run.id, 1), None).await.unwrap() else {
        panic!()
    };
    let meta = |content: &[u8]| NewArtifact {
        run_id: run.id,
        attempt_id: attempt.id,
        kind: "patch".into(),
        base_revision: "abc".into(),
        sha256: hex::encode(<sha2::Sha256 as sha2::Digest>::digest(content)),
        changed_paths: vec![],
        driver: "fake".into(),
        driver_version: None,
        environment_id: None,
        parent_artifact_id: None,
        parent_environment_id: None,
    };
    let inline_only = PgArtifactStore::new(j.clone(), 16, None);
    let small = b"diff --git a b\n";
    let s = inline_only.put(&meta(small), small).await.unwrap();
    assert_eq!(s.storage, "postgres");
    assert_eq!(inline_only.get_content(s.id).await.unwrap(), small);
    let big = vec![b'x'; 100];
    assert!(matches!(inline_only.put(&meta(&big), &big).await, Err(JournalError::TooLarge { size: 100, limit: 16 })));
    let mut bad = meta(small);
    bad.sha256 = "00".into();
    assert!(inline_only.put(&bad, small).await.is_err());

    let dir = tempfile_dir();
    let with_fs = PgArtifactStore::new(j.clone(), 16, Some(Arc::new(FsBlobStore { root: dir.clone() })));
    let s = with_fs.put(&meta(&big), &big).await.unwrap();
    assert_eq!(s.storage, "fs");
    assert_eq!(with_fs.get_content(s.id).await.unwrap(), big);
    assert_eq!(with_fs.latest_for_run(run.id).await.unwrap().unwrap().id, s.id);
    let _ = std::fs::remove_dir_all(dir);
    db.drop_db().await;
}

fn tempfile_dir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("acp-blob-{}", Uuid::new_v4().simple()));
    std::fs::create_dir_all(&d).unwrap();
    d
}
