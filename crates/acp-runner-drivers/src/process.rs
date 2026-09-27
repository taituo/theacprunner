//! Supervised child process: scrubbed environment, own process group, bounded stderr
//! capture, graceful-then-forced termination.

use crate::DriverError;
use nix::sys::signal::{Signal, kill, killpg};
use nix::unistd::Pid;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::{ChildStdin, ChildStdout, Command};
use tokio::sync::watch;

const STDERR_TAIL_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct SpawnSpec {
    pub program: String,
    pub args: Vec<String>,
    /// Complete environment (the parent environment is NOT inherited).
    pub env: Vec<(String, String)>,
    pub cwd: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub struct ExitInfo {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

impl ExitInfo {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

pub struct ManagedChild {
    pub pid: u32,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    exit_rx: watch::Receiver<Option<ExitInfo>>,
    stderr_tail: Arc<Mutex<VecDeque<u8>>>,
}

impl ManagedChild {
    pub fn spawn(spec: &SpawnSpec) -> Result<ManagedChild, DriverError> {
        let mut cmd = Command::new(&spec.program);
        cmd.args(&spec.args)
            .env_clear()
            .envs(spec.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .current_dir(&spec.cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .kill_on_drop(true);
        // If runnerd dies (even by SIGKILL) the agent must not outlive it. PDEATHSIG is
        // tied to the spawning thread; tokio worker threads live as long as the runtime.
        // SAFETY: only async-signal-safe prctl(2) is called between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                nix::sys::prctl::set_pdeathsig(Some(Signal::SIGKILL)).map_err(std::io::Error::from)?;
                Ok(())
            });
        }
        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                DriverError::NotInstalled(format!("{}: {e}", spec.program))
            } else {
                DriverError::Spawn(format!("{}: {e}", spec.program))
            }
        })?;
        let pid = child.id().ok_or_else(|| DriverError::Spawn("child has no pid".into()))?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let mut stderr = child.stderr.take().expect("stderr piped");
        let tail = Arc::new(Mutex::new(VecDeque::with_capacity(4096)));
        let tail2 = tail.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            while let Ok(n) = stderr.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                let mut t = tail2.lock().expect("stderr lock");
                t.extend(&buf[..n]);
                while t.len() > STDERR_TAIL_BYTES {
                    t.pop_front();
                }
            }
        });
        let (tx, rx) = watch::channel(None);
        tokio::spawn(async move {
            let status = child.wait().await;
            let info = match status {
                Ok(s) => {
                    use std::os::unix::process::ExitStatusExt;
                    ExitInfo { code: s.code(), signal: s.signal() }
                }
                Err(_) => ExitInfo { code: None, signal: None },
            };
            let _ = tx.send(Some(info));
        });
        Ok(ManagedChild { pid, stdin, stdout, exit_rx: rx, stderr_tail: tail })
    }

    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.stdin.take()
    }

    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.stdout.take()
    }

    pub fn exit_watch(&self) -> watch::Receiver<Option<ExitInfo>> {
        self.exit_rx.clone()
    }

    pub fn exited(&self) -> Option<ExitInfo> {
        *self.exit_rx.borrow()
    }

    pub fn is_alive(&self) -> bool {
        self.exited().is_none()
    }

    pub fn stderr_tail(&self) -> String {
        let t = self.stderr_tail.lock().expect("stderr lock");
        let (a, b) = t.as_slices();
        let mut v = a.to_vec();
        v.extend_from_slice(b);
        String::from_utf8_lossy(&v).to_string()
    }

    /// Signal only the direct child.
    pub fn signal(&self, sig: Signal) {
        if self.is_alive() {
            let _ = kill(Pid::from_raw(self.pid as i32), sig);
        }
    }

    /// Signal the whole process group (the child was started as group leader).
    pub fn signal_group(&self, sig: Signal) {
        let _ = killpg(Pid::from_raw(self.pid as i32), sig);
    }

    pub async fn wait(&self) -> ExitInfo {
        let mut rx = self.exit_rx.clone();
        loop {
            if let Some(i) = *rx.borrow() {
                return i;
            }
            if rx.changed().await.is_err() {
                return ExitInfo::default();
            }
        }
    }

    pub async fn wait_timeout(&self, d: Duration) -> Option<ExitInfo> {
        tokio::time::timeout(d, self.wait()).await.ok()
    }

    /// SIGTERM the process group, wait `grace`, then SIGKILL the group.
    pub async fn terminate(&self, grace: Duration) -> ExitInfo {
        if let Some(i) = self.exited() {
            self.signal_group(Signal::SIGKILL); // reap stragglers of the group
            return i;
        }
        self.signal_group(Signal::SIGTERM);
        if let Some(i) = self.wait_timeout(grace).await {
            self.signal_group(Signal::SIGKILL);
            return i;
        }
        self.signal_group(Signal::SIGKILL);
        self.wait_timeout(Duration::from_secs(10)).await.unwrap_or_default()
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        // Never leave agent process groups behind.
        self.signal_group(Signal::SIGKILL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> SpawnSpec {
        SpawnSpec {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            env: vec![("PATH".into(), "/usr/bin:/bin".into())],
            cwd: std::env::temp_dir(),
        }
    }

    #[tokio::test]
    async fn exit_code_and_stderr_are_captured() {
        let c = ManagedChild::spawn(&sh("echo oops >&2; exit 7")).unwrap();
        let e = c.wait().await;
        assert_eq!(e.code, Some(7));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(c.stderr_tail().contains("oops"));
    }

    #[tokio::test]
    async fn environment_is_not_inherited() {
        // SAFETY: test-only, single-threaded use of the variable.
        unsafe { std::env::set_var("ACP_TEST_PARENT_SECRET", "leak-me-please") };
        let mut c = ManagedChild::spawn(&sh("env")).unwrap();
        let mut out = String::new();
        c.take_stdout().unwrap().read_to_string(&mut out).await.unwrap();
        c.wait().await;
        assert!(!out.contains("leak-me-please"));
        assert!(out.contains("PATH="));
    }

    #[tokio::test]
    async fn terminate_escalates_to_sigkill_for_the_whole_group() {
        // Ignores SIGTERM and has a grandchild.
        let c = ManagedChild::spawn(&sh("trap '' TERM; sleep 300 & sleep 300; wait")).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let started = std::time::Instant::now();
        let e = c.terminate(Duration::from_millis(300)).await;
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(e.signal, Some(9));
        // no live (non-zombie) member of the group is left; zombies are reaped by PID 1
        // (tini in the runner image)
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(live_group_members(c.pid as i32), 0);
    }

    fn live_group_members(pgid: i32) -> usize {
        let mut n = 0;
        for entry in std::fs::read_dir("/proc").unwrap().flatten() {
            let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else { continue };
            // pid (comm) state ppid pgrp ...
            let Some(rest) = stat.rsplit_once(')').map(|(_, r)| r) else { continue };
            let f: Vec<&str> = rest.split_whitespace().collect();
            if f.len() > 2 && f[2].parse::<i32>().ok() == Some(pgid) && f[0] != "Z" {
                n += 1;
            }
        }
        n
    }

    #[tokio::test]
    async fn graceful_termination_when_honoured() {
        let c = ManagedChild::spawn(&sh("sleep 300")).unwrap();
        let e = c.terminate(Duration::from_secs(5)).await;
        assert_eq!(e.signal, Some(15));
    }

    #[tokio::test]
    async fn missing_executable_is_not_installed() {
        let spec =
            SpawnSpec { program: "/nonexistent/agent".into(), args: vec![], env: vec![], cwd: std::env::temp_dir() };
        assert!(matches!(ManagedChild::spawn(&spec), Err(DriverError::NotInstalled(_))));
    }
}
