//! `acp-conformance`: start any ACP stdio agent from a launch description and record how it
//! behaves. The output is a *profile* (values, not just pass/fail) that goes into
//! `drivers.lock.yaml` — ACP implementation differences are found by running this, never by
//! adding CLI-specific branches to the runtime.
//!
//! ```text
//! acp-conformance --launch opencode.yaml --name opencode-noauth --out profile.json
//! acp-conformance --launch opencode.yaml --home-file .local/share/opencode/auth.json=/secure/auth.json \
//!                 --prompt "Reply with the word ok." --cancel-prompt "Count slowly to 1000."
//! ```
//!
//! Recorded: `--version`, `initialize` (latency, protocol version, capabilities, auth
//! methods), `session/new` (models/modes it advertises, errors), an optional prompt (stop
//! reason, update kinds, usage, permission requests, client requests it should not make),
//! an optional cancel (stop reason and latency after `session/cancel`) and shutdown on stdin
//! EOF. Nothing secret is printed: HOME file contents and launch env values are redacted from
//! everything captured (stderr tail, error messages).

use acp_runner_acp::client::{self, choose_permission_option, permission_cancelled, permission_selected};
use acp_runner_acp::{AcpError, Connection, Incoming, codes, methods};
use acp_runner_core::launch::{Launch, is_protected_env};
use acp_runner_core::redact::Redactor;
use anyhow::{Context, bail};
use clap::Parser;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

#[derive(Parser, Debug)]
#[command(version, about = "ACP agent conformance profile")]
struct Args {
    /// Launch description (YAML or JSON): {command, args, env, files, cwd}.
    #[arg(long)]
    launch: PathBuf,
    /// Profile name (default: the command).
    #[arg(long)]
    name: Option<String>,
    /// Workspace (default: a fresh git repository with one file).
    #[arg(long)]
    workspace: Option<PathBuf>,
    /// Extra HOME file `<target>=<local path>` (e.g. a credential file). Repeatable.
    #[arg(long = "home-file")]
    home_file: Vec<String>,
    /// Prompt for one real turn (needs working credentials).
    #[arg(long)]
    prompt: Option<String>,
    /// Prompt to start and then cancel with `session/cancel`.
    #[arg(long)]
    cancel_prompt: Option<String>,
    /// Timeout for each request (seconds).
    #[arg(long, default_value_t = 120)]
    timeout: u64,
    /// Grace period after cancel / stdin EOF (seconds).
    #[arg(long, default_value_t = 10)]
    grace: u64,
    /// PATH for the agent (default: this process' PATH).
    #[arg(long)]
    path: Option<String>,
    /// HTTPS proxy for the agent (sets HTTPS_PROXY/HTTP_PROXY).
    #[arg(long)]
    https_proxy: Option<String>,
    /// Answer permission requests with allow (default) or deny.
    #[arg(long, default_value = "allow")]
    permissions: String,
    /// Write the profile here (it is always printed to stdout).
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Default)]
struct Recorded {
    update_kinds: BTreeMap<String, u64>,
    usage_seen: bool,
    permission_requests: u64,
    client_requests: BTreeMap<String, u64>,
    invalid_lines: u64,
    first_update_at: Option<Instant>,
}

fn secs(d: Duration) -> f64 {
    (d.as_secs_f64() * 1000.0).round() / 1000.0
}

fn err_json(e: &AcpError, r: &Redactor) -> Value {
    match e {
        AcpError::Rpc { code, message, .. } => json!({
            "code": code,
            "message": r.redact_string(message),
            "authRequired": *code == codes::AUTH_REQUIRED,
        }),
        other => json!({"error": r.redact_string(&other.to_string())}),
    }
}

async fn timed<T>(
    t: Duration,
    f: impl std::future::Future<Output = Result<T, AcpError>>,
) -> (Duration, Result<T, AcpError>) {
    let start = Instant::now();
    let r = match tokio::time::timeout(t, f).await {
        Ok(r) => r,
        Err(_) => Err(AcpError::Protocol(format!("no response within {t:?}"))),
    };
    (start.elapsed(), r)
}

fn load_launch(p: &Path) -> anyhow::Result<Launch> {
    let text = std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
    let v: Value =
        if text.trim_start().starts_with('{') { serde_json::from_str(&text)? } else { serde_yaml::from_str(&text)? };
    let l = Launch::from_config(&v).map_err(anyhow::Error::msg)?;
    l.validate().map_err(anyhow::Error::msg)?;
    Ok(l)
}

fn fixture_workspace(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("README.md"), "# conformance fixture\n")?;
    std::fs::write(dir.join("add.sh"), "#!/bin/sh\necho $(( $1 - $2 ))\n")?;
    for args in [
        &["init", "-q"][..],
        &["-c", "user.email=c@example.invalid", "-c", "user.name=c", "add", "."],
        &["-c", "user.email=c@example.invalid", "-c", "user.name=c", "commit", "-q", "-m", "fixture"],
    ] {
        let ok = std::process::Command::new("git").args(args).current_dir(dir).status()?.success();
        if !ok {
            bail!("git {args:?} failed in the fixture workspace");
        }
    }
    Ok(())
}

fn write_home_file(home: &Path, target: &str, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    acp_runner_core::paths::validate_relative_path(target).map_err(|e| anyhow::anyhow!("{target}: {e}"))?;
    let p = home.join(target);
    std::fs::create_dir_all(p.parent().expect("parent"))?;
    std::fs::write(&p, bytes)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn add_secret_leaves(r: &mut Redactor, bytes: &[u8]) {
    if let Ok(v) = serde_json::from_slice::<Value>(bytes) {
        fn walk(r: &mut Redactor, v: &Value) {
            match v {
                Value::String(s) if s.len() >= 8 => r.add_secret(s),
                Value::Array(a) => a.iter().for_each(|x| walk(r, x)),
                Value::Object(o) => o.values().for_each(|x| walk(r, x)),
                _ => {}
            }
        }
        walk(r, &v);
    } else if let Ok(s) = std::str::from_utf8(bytes) {
        let s = s.trim();
        if s.len() >= 8 {
            r.add_secret(s);
        }
    }
}

fn summarize_session(raw: &Value) -> Value {
    let models = raw.get("models");
    let modes = raw.get("modes");
    json!({
        "resultKeys": raw.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()).unwrap_or_default(),
        "currentModelId": models.and_then(|m| m.get("currentModelId")).cloned(),
        "availableModels": models.and_then(|m| m.get("availableModels")).and_then(|a| a.as_array()).map(|a| a.len()),
        "currentModeId": modes.and_then(|m| m.get("currentModeId")).cloned(),
        "availableModes": modes.and_then(|m| m.get("availableModes")).and_then(|a| a.as_array())
            .map(|a| a.iter().filter_map(|m| m.get("id").cloned()).collect::<Vec<_>>()),
        // session config options (ACP `configOptions`, e.g. model / mode selectors)
        "configOptions": raw.get("configOptions").and_then(|c| c.as_array()).map(|a| a.iter().map(|o| json!({
            "id": o.get("id"),
            "name": o.get("name"),
            "category": o.get("category"),
            "type": o.get("type"),
            "currentValue": o.get("currentValue"),
            "options": o.get("options").and_then(|x| x.as_array()).map(|x| x.len()),
        })).collect::<Vec<_>>()),
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let a = Args::parse();
    let launch = load_launch(&a.launch)?;
    let name = a.name.clone().unwrap_or_else(|| launch.command.clone());
    let t = Duration::from_secs(a.timeout);
    let grace = Duration::from_secs(a.grace);
    let tmp = tempfile::tempdir()?;
    let home = tmp.path().join("home");
    let workspace = match &a.workspace {
        Some(w) => w.clone(),
        None => {
            let w = tmp.path().join("workspace");
            fixture_workspace(&w)?;
            w
        }
    };
    let mut redactor = Redactor::new();
    for d in [".config", ".cache", ".local/share", ".local/state"] {
        std::fs::create_dir_all(home.join(d))?;
    }
    for f in &launch.files {
        write_home_file(&home, &f.target, f.content.as_bytes(), f.mode.unwrap_or(0o600))?;
    }
    let mut home_file_targets = vec![];
    for spec in &a.home_file {
        let (target, src) = spec.split_once('=').context("--home-file expects <target>=<path>")?;
        let bytes = std::fs::read(src).with_context(|| format!("reading {src}"))?;
        add_secret_leaves(&mut redactor, &bytes);
        write_home_file(&home, target, &bytes, 0o600)?;
        home_file_targets.push(target.to_string());
    }
    for v in launch.env.values() {
        if v.len() >= 12 {
            redactor.add_secret(v);
        }
    }
    // Same environment policy as agentd: nothing inherited, runtime keys win.
    let h = home.to_string_lossy().to_string();
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in &launch.env {
        if !is_protected_env(k) {
            env.insert(k.clone(), v.clone());
        }
    }
    let path = a.path.clone().or_else(|| std::env::var("PATH").ok()).unwrap_or_else(|| "/usr/bin:/bin".into());
    for (k, v) in [
        ("PATH", path),
        ("HOME", h.clone()),
        ("USER", "agent".into()),
        ("LANG", "C.UTF-8".into()),
        ("TERM", "dumb".into()),
        ("NO_COLOR", "1".into()),
        ("TMPDIR", tmp.path().to_string_lossy().to_string()),
        ("XDG_CONFIG_HOME", format!("{h}/.config")),
        ("XDG_CACHE_HOME", format!("{h}/.cache")),
        ("XDG_DATA_HOME", format!("{h}/.local/share")),
        ("XDG_STATE_HOME", format!("{h}/.local/state")),
        ("GIT_TERMINAL_PROMPT", "0".into()),
    ] {
        env.insert(k.into(), v);
    }
    if let Some(p) = &a.https_proxy {
        for k in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
            env.insert(k.into(), p.clone());
        }
        env.insert("NO_PROXY".into(), "localhost,127.0.0.1".into());
    }
    let cwd = match launch.cwd.as_deref().filter(|c| !c.is_empty()) {
        Some(c) => workspace.join(c),
        None => workspace.clone(),
    };

    let mut report = json!({
        "profile": name,
        "recordedAt": chrono::Utc::now().to_rfc3339(),
        "tool": format!("acp-conformance {}", env!("CARGO_PKG_VERSION")),
        "launch": {
            "command": launch.command,
            "args": launch.args,
            "envKeys": launch.env.keys().collect::<Vec<_>>(),
            "files": launch.files.iter().map(|f| &f.target).collect::<Vec<_>>(),
            "homeFiles": home_file_targets,
            "cwd": launch.cwd,
        },
    });

    // ---- --version -----------------------------------------------------------------------
    let v = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new(&launch.command)
            .arg("--version")
            .env_clear()
            .envs(&env)
            .current_dir(&cwd)
            .stdin(Stdio::null())
            .output(),
    )
    .await;
    report["version"] = match v {
        Ok(Ok(o)) => json!({
            "exitCode": o.status.code(),
            "stdout": redactor.redact_string(String::from_utf8_lossy(&o.stdout).trim()),
        }),
        Ok(Err(e)) => json!({"error": e.to_string()}),
        Err(_) => json!({"error": "timed out after 30s"}),
    };

    // ---- start ---------------------------------------------------------------------------
    let started = Instant::now();
    let mut child = tokio::process::Command::new(&launch.command)
        .args(&launch.args)
        .env_clear()
        .envs(&env)
        .current_dir(&cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("starting {}", launch.command))?;
    let stderr_tail = Arc::new(Mutex::new(Vec::<u8>::new()));
    if let Some(mut se) = child.stderr.take() {
        let tail = stderr_tail.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 8192];
            while let Ok(n) = se.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                let mut t = tail.lock().expect("tail");
                t.extend_from_slice(&buf[..n]);
                let len = t.len();
                if len > 16384 {
                    t.drain(..len - 16384);
                }
            }
        });
    }
    let (conn, incoming) =
        Connection::spawn(child.stdout.take().context("stdout")?, child.stdin.take().context("stdin")?);
    let rec = Arc::new(Mutex::new(Recorded::default()));
    spawn_recorder(conn.clone(), incoming, rec.clone(), a.permissions != "deny");

    // ---- initialize ----------------------------------------------------------------------
    let (d, init) = timed(t, client::initialize(&conn, "acp-conformance", env!("CARGO_PKG_VERSION"))).await;
    report["initialize"] = match &init {
        Ok(i) => json!({
            "ok": true,
            "seconds": secs(d),
            "secondsSinceSpawn": secs(started.elapsed()),
            "protocolVersion": i.protocol_version,
            "agentInfo": {"name": i.agent_info.name, "title": i.agent_info.title, "version": i.agent_info.version},
            "agentCapabilities": i.agent_capabilities,
            "authMethods": i.auth_methods.iter().map(|m| json!({"id": m.id, "name": m.name})).collect::<Vec<_>>(),
        }),
        Err(e) => json!({"ok": false, "seconds": secs(d), "error": err_json(e, &redactor)}),
    };

    // ---- session/new ---------------------------------------------------------------------
    let mut session_id = None;
    if init.is_ok() {
        let (d, s) = timed(t, client::new_session(&conn, &cwd)).await;
        report["sessionNew"] = match &s {
            Ok(s) => {
                session_id = Some(s.session_id.clone());
                json!({"ok": true, "seconds": secs(d), "summary": summarize_session(&s.raw)})
            }
            Err(e) => json!({"ok": false, "seconds": secs(d), "error": err_json(e, &redactor)}),
        };
    }

    // ---- prompt --------------------------------------------------------------------------
    if let (Some(sid), Some(p)) = (&session_id, &a.prompt) {
        let before = rec.lock().expect("rec").update_kinds.values().sum::<u64>();
        let (d, r) = timed(t, conn.request(methods::SESSION_PROMPT, client::prompt_params(sid, p))).await;
        let r2 = rec.lock().expect("rec");
        report["prompt"] = json!({
            "seconds": secs(d),
            "result": match &r {
                Ok(v) => json!({"stopReason": client::stop_reason(v), "resultKeys": v.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>())}),
                Err(e) => err_json(e, &redactor),
            },
            "updates": r2.update_kinds.values().sum::<u64>() - before,
            "usageSeen": r2.usage_seen,
            "permissionRequests": r2.permission_requests,
        });
    }

    // ---- cancel --------------------------------------------------------------------------
    if let (Some(sid), Some(p)) = (&session_id, &a.cancel_prompt) {
        rec.lock().expect("rec").first_update_at = None;
        let c2 = conn.clone();
        let params = client::prompt_params(sid, p);
        let pending = tokio::spawn(async move { c2.request(methods::SESSION_PROMPT, params).await });
        let wait_start = Instant::now();
        while wait_start.elapsed() < Duration::from_secs(20) && rec.lock().expect("rec").first_update_at.is_none() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let cancel_at = Instant::now();
        let sent = conn.notify(methods::SESSION_CANCEL, client::cancel_params(sid)).await;
        let res = tokio::time::timeout(grace, pending).await;
        report["cancel"] = json!({
            "updateBeforeCancel": rec.lock().expect("rec").first_update_at.is_some(),
            "cancelSent": sent.is_ok(),
            "secondsToStop": secs(cancel_at.elapsed()),
            "result": match res {
                Ok(Ok(Ok(v))) => json!({"stopReason": client::stop_reason(&v)}),
                Ok(Ok(Err(e))) => err_json(&e, &redactor),
                Ok(Err(e)) => json!({"error": e.to_string()}),
                Err(_) => json!({"error": format!("no stop within {grace:?} after session/cancel")}),
            },
        });
    }

    // ---- shutdown on stdin EOF -----------------------------------------------------------
    conn.close_input().await;
    let eof_at = Instant::now();
    report["shutdown"] = match tokio::time::timeout(grace, child.wait()).await {
        Ok(Ok(s)) => json!({"exitedOnEof": true, "seconds": secs(eof_at.elapsed()), "exitCode": s.code()}),
        _ => {
            let _ = child.kill().await;
            json!({"exitedOnEof": false, "killedAfterSeconds": secs(eof_at.elapsed())})
        }
    };

    {
        let r = rec.lock().expect("rec");
        report["observed"] = json!({
            "sessionUpdateKinds": r.update_kinds,
            "usageSeen": r.usage_seen,
            "permissionRequests": r.permission_requests,
            "clientRequests": r.client_requests,
            "invalidStdoutLines": r.invalid_lines,
        });
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let tail = String::from_utf8_lossy(&stderr_tail.lock().expect("tail")).to_string();
    let tail = redactor.redact_string(&tail);
    let tail = acp_runner_core::events::truncate_utf8(
        &tail.chars().rev().take(2000).collect::<String>().chars().rev().collect::<String>(),
        4000,
    )
    .0;
    report["stderrTail"] = json!(tail);

    let text = serde_json::to_string_pretty(&report)?;
    println!("{text}");
    if let Some(out) = &a.out {
        std::fs::write(out, format!("{text}\n"))?;
    }
    Ok(())
}

fn spawn_recorder(conn: Connection, mut incoming: mpsc::Receiver<Incoming>, rec: Arc<Mutex<Recorded>>, allow: bool) {
    tokio::spawn(async move {
        while let Some(m) = incoming.recv().await {
            match m {
                Incoming::Notification { method, params } => {
                    if method == methods::SESSION_UPDATE {
                        let kind = params
                            .pointer("/update/sessionUpdate")
                            .and_then(|k| k.as_str())
                            .unwrap_or("unknown")
                            .to_string();
                        let mut r = rec.lock().expect("rec");
                        r.usage_seen |= kind.contains("usage") || params.pointer("/update/usage").is_some();
                        *r.update_kinds.entry(kind).or_default() += 1;
                        r.first_update_at.get_or_insert_with(Instant::now);
                    }
                }
                Incoming::Request { id, method, params } => {
                    if method == methods::SESSION_REQUEST_PERMISSION {
                        rec.lock().expect("rec").permission_requests += 1;
                        let answer = match choose_permission_option(&params, allow) {
                            Some(o) => permission_selected(&o),
                            None => permission_cancelled(),
                        };
                        let _ = conn.respond(id, answer).await;
                    } else {
                        *rec.lock().expect("rec").client_requests.entry(method.clone()).or_default() += 1;
                        let _ = conn.respond_error(id, -32601, "method not supported by this client").await;
                    }
                }
                Incoming::Invalid { .. } => rec.lock().expect("rec").invalid_lines += 1,
            }
        }
    });
}
