//! The launch primitive for ACP stdio agents: `launch {command, args, env, files, cwd}`.
//!
//! acp-runner does not model any CLI's flags. A runner class (driver `acp`) or an
//! environment's harness (`harness: {name: acp, config: <launch>}`) says how to start the
//! agent; model choice, trust prompts and update checks are ordinary launch parameters.
//! Per run, only additions to `env` and `files` are possible, and only when the class sets
//! `allowRunOverrides` — a key replaces a key, nothing is merged or appended.
//!
//! The command runs in the untrusted agent container either way; what stays protected is the
//! runtime environment runnerd/agentd set ([`PROTECTED_ENV`] is always applied last), the
//! credential store and the network (egress proxy).

use crate::paths::validate_relative_path;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Upper bound for all launch files of one attempt together.
pub const MAX_LAUNCH_FILES_BYTES: usize = 256 * 1024;

/// Variables set by the runtime that neither the launch nor a run override can change.
pub const PROTECTED_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_RUNTIME_DIR",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "NO_PROXY",
    "no_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NODE_EXTRA_CA_CERTS",
    "SSL_CERT_FILE",
];

pub fn is_protected_env(name: &str) -> bool {
    PROTECTED_ENV.contains(&name)
}

/// A file written below the synthetic HOME before the agent starts (never into the
/// workspace, so it cannot end up in the patch).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LaunchFile {
    /// Path relative to HOME, e.g. `.config/opencode/opencode.json`.
    pub target: String,
    /// UTF-8 content.
    pub content: String,
    /// File mode (default 0600).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Launch {
    /// Program (absolute path or a name resolved through the agent PATH).
    pub command: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<LaunchFile>,
    /// Working directory relative to the workspace (default: the workspace / workdir).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}

/// Per-run additions (`ACPRun.spec.overrides`), gated by the class' `allowRunOverrides`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RunOverrides {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<LaunchFile>,
}

impl RunOverrides {
    pub fn is_empty(&self) -> bool {
        self.env.is_empty() && self.files.is_empty()
    }
}

fn valid_env_name(k: &str) -> bool {
    !k.is_empty()
        && !k.starts_with(|c: char| c.is_ascii_digit())
        && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub fn validate_env(env: &BTreeMap<String, String>) -> Result<(), String> {
    for (k, v) in env {
        if !valid_env_name(k) {
            return Err(format!("env: {k:?} is not a variable name"));
        }
        if v.contains('\0') {
            return Err(format!("env {k}: NUL in value"));
        }
    }
    Ok(())
}

pub fn validate_files(files: &[LaunchFile]) -> Result<(), String> {
    let mut total = 0;
    for f in files {
        validate_relative_path(&f.target).map_err(|e| format!("files[{}]: {e}", f.target))?;
        if let Some(m) = f.mode
            && m & !0o777 != 0
        {
            return Err(format!("files[{}]: mode {m:o} is not a permission mode", f.target));
        }
        total += f.content.len();
    }
    if total > MAX_LAUNCH_FILES_BYTES {
        return Err(format!("launch files exceed {MAX_LAUNCH_FILES_BYTES} bytes"));
    }
    Ok(())
}

impl Launch {
    pub fn validate(&self) -> Result<(), String> {
        if self.command.trim().is_empty() {
            return Err("launch.command must not be empty".into());
        }
        if self.command.starts_with('-') || self.command.contains('\0') {
            return Err("launch.command is not a program".into());
        }
        validate_env(&self.env)?;
        validate_files(&self.files)?;
        if let Some(c) = &self.cwd
            && !c.is_empty()
        {
            validate_relative_path(c).map_err(|e| format!("launch.cwd: {e}"))?;
        }
        Ok(())
    }

    /// Parse a launch from an opaque harness/driver config (`{command, args, env, files, cwd}`).
    pub fn from_config(v: &serde_json::Value) -> Result<Launch, String> {
        serde_json::from_value(v.clone()).map_err(|e| format!("launch: {e}"))
    }

    /// This launch with run overrides applied (a key replaces a key; a file replaces the file
    /// with the same target).
    pub fn with_overrides(&self, o: &RunOverrides) -> Launch {
        let mut l = self.clone();
        for (k, v) in &o.env {
            l.env.insert(k.clone(), v.clone());
        }
        for f in &o.files {
            l.files.retain(|x| x.target != f.target);
            l.files.push(f.clone());
        }
        l
    }

    /// The driver configuration agentd sees (files are placed by runnerd instead).
    pub fn driver_config(&self, base: &serde_json::Value) -> serde_json::Value {
        let mut m = base.as_object().cloned().unwrap_or_default();
        m.insert("command".into(), self.command.clone().into());
        m.insert("args".into(), serde_json::to_value(&self.args).expect("json"));
        m.insert("env".into(), serde_json::to_value(&self.env).expect("json"));
        match &self.cwd {
            Some(c) if !c.is_empty() => {
                m.insert("cwd".into(), c.clone().into());
            }
            _ => {
                m.remove("cwd");
            }
        }
        m.remove("files");
        serde_json::Value::Object(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn l() -> Launch {
        Launch {
            command: "opencode".into(),
            args: vec!["acp".into()],
            env: BTreeMap::from([("OPENCODE_DISABLE_AUTOUPDATE".into(), "1".into())]),
            files: vec![LaunchFile {
                target: ".config/opencode/opencode.json".into(),
                content: "{}".into(),
                mode: None,
            }],
            cwd: None,
        }
    }

    #[test]
    fn overrides_replace_keys_and_files() {
        let o = RunOverrides {
            env: BTreeMap::from([("OPENCODE_CONFIG_CONTENT".into(), r#"{"model":"openai/x"}"#.into())]),
            files: vec![LaunchFile {
                target: ".config/opencode/opencode.json".into(),
                content: r#"{"model":"openai/y"}"#.into(),
                mode: None,
            }],
        };
        let m = l().with_overrides(&o);
        assert_eq!(m.env.len(), 2);
        assert_eq!(m.files.len(), 1);
        assert!(m.files[0].content.contains("openai/y"));
        let cfg = m.driver_config(&serde_json::json!({"scenario": "fix", "files": 1}));
        assert_eq!(cfg["command"], "opencode");
        assert_eq!(cfg["scenario"], "fix");
        assert!(cfg.get("files").is_none());
    }

    #[test]
    fn validation() {
        assert!(l().validate().is_ok());
        let mut b = l();
        b.command = String::new();
        assert!(b.validate().is_err());
        let mut b = l();
        b.files[0].target = "../escape".into();
        assert!(b.validate().is_err());
        let mut b = l();
        b.env.insert("BAD-NAME".into(), "x".into());
        assert!(b.validate().is_err());
        let mut b = l();
        b.cwd = Some("/abs".into());
        assert!(b.validate().is_err());
    }
}
