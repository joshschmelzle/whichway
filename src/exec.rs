//! Thin wrapper around `tokio::process::Command` that always enforces a
//! timeout. All shell-outs in whichway go through here so we can never get
//! stuck on a wedged subprocess.

use std::time::Duration;

use anyhow::{Context, Result};
use tokio::process::Command;
use tokio::time::timeout;

/// Default command timeouts. Documented in the spec.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);
pub const NETTOP_TIMEOUT: Duration = Duration::from_secs(5);
pub const LSOF_TIMEOUT: Duration = Duration::from_secs(8);

/// Run `bin` with `args`, capture stdout as a UTF-8 string, enforce timeout.
///
/// Returns an `Err` if the command:
///   * doesn't exist (Command spawn failure)
///   * exceeds `dur`
///   * exits non-zero (stderr included in the error)
///   * produces non-UTF-8 stdout (we treat stdout as UTF-8; macOS tools do).
pub async fn run(bin: &str, args: &[&str], dur: Duration) -> Result<String> {
    tracing::debug!(target = "exec", "running {} {:?}", bin, args);
    let fut = Command::new(bin).args(args).output();
    let out = timeout(dur, fut)
        .await
        .with_context(|| format!("`{} {}` timed out after {:?}", bin, args.join(" "), dur))?
        .with_context(|| format!("failed to spawn `{bin}`"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!(
            "`{} {}` exited {}: {}",
            bin,
            args.join(" "),
            out.status,
            stderr.trim()
        );
    }
    String::from_utf8(out.stdout)
        .with_context(|| format!("`{} {}` produced non-UTF-8 stdout", bin, args.join(" ")))
}

/// Like [`run`] but tolerates non-zero exit codes (still returns captured
/// stdout). Used for commands like `pgrep` where "no match" is a legitimate
/// non-zero exit.
pub async fn run_lenient(bin: &str, args: &[&str], dur: Duration) -> Result<String> {
    let fut = Command::new(bin).args(args).output();
    let out = timeout(dur, fut)
        .await
        .with_context(|| format!("`{} {}` timed out after {:?}", bin, args.join(" "), dur))?
        .with_context(|| format!("failed to spawn `{bin}`"))?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Whether the current process is running as root (euid == 0).
///
/// macOS has no safe `std` API for `geteuid`, and we don't want to pull in a
/// libc/rustix dependency just for one syscall. Instead we shell out to
/// `/usr/bin/id -u` once at startup and cache the answer. It runs
/// synchronously (not via tokio) because the result is needed before the
/// runtime is built.
pub fn is_root() -> bool {
    use std::sync::OnceLock;
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(|| {
        let out = std::process::Command::new("/usr/bin/id").arg("-u").output();
        match out {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim() == "0",
            _ => false,
        }
    })
}
