//! The conformance tool against the deterministic fake agent: handshake, one prompt, a
//! cancelled prompt, HOME files, and no secret in the report.

use std::path::PathBuf;
use std::process::Command;

fn target_dir() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    exe.parent().unwrap().parent().unwrap().to_path_buf()
}

#[test]
fn profile_of_the_fake_agent() {
    let root = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
    let st = Command::new("cargo").args(["build", "-q", "-p", "fake-acp-agent"]).current_dir(&root).status().unwrap();
    assert!(st.success());
    let fake = target_dir().join("fake-acp-agent");
    let tmp = tempfile::tempdir().unwrap();
    let launch = tmp.path().join("launch.yaml");
    std::fs::write(
        &launch,
        format!(
            "command: {}\nenv: {{FAKE_ACP_SCENARIO: fix}}\nfiles:\n  - {{target: .config/fake/c.json, content: '{{}}'}}\n",
            fake.display()
        ),
    )
    .unwrap();
    let secret = tmp.path().join("auth.json");
    std::fs::write(&secret, r#"{"openai":{"type":"api","key":"sk-very-secret-conformance-key"}}"#).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_acp-conformance"))
        .args(["--launch", launch.to_str().unwrap(), "--name", "fake", "--timeout", "30", "--grace", "3"])
        .args(["--home-file", &format!(".local/share/fake/auth.json={}", secret.display())])
        .args(["--prompt", "fix it", "--cancel-prompt", "[[fake:hang]]"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(!text.contains("sk-very-secret"), "secret leaked into the profile");
    let p: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(p["initialize"]["ok"], true);
    assert_eq!(p["initialize"]["protocolVersion"], 1);
    assert_eq!(p["sessionNew"]["ok"], true);
    assert_eq!(p["prompt"]["result"]["stopReason"], "end_turn");
    assert_eq!(p["cancel"]["result"]["stopReason"], "cancelled");
    assert!(p["observed"]["sessionUpdateKinds"]["tool_call"].as_u64().unwrap() >= 1);
    assert_eq!(p["launch"]["homeFiles"][0], ".local/share/fake/auth.json");
}
