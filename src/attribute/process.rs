//! Anchored process detection and install-path checks.
//!
//! The bare-substring `pgrep` form is intentionally avoided — `pgrep foo`
//! matches any commandline containing `foo`, which gives constant false
//! positives. We anchor the pattern at the start of the executable path.

use std::path::Path;

use crate::exec::{DEFAULT_TIMEOUT, run_lenient};

/// Returns true if any of the given install paths exists.
pub fn any_path_exists(paths: &[&str]) -> bool {
    paths.iter().any(|p| Path::new(p).exists())
}

/// `pgrep -fl '^<anchor>'`. Returns true on at least one match. We use the
/// lenient runner because pgrep exits non-zero with no matches.
pub async fn pgrep_anchored(anchor: &str) -> bool {
    let pattern = format!("^{anchor}");
    let out = run_lenient("pgrep", &["-fl", &pattern], DEFAULT_TIMEOUT)
        .await
        .unwrap_or_default();
    out.lines().any(|l| !l.trim().is_empty())
}

/// Whether a binary is reachable on PATH.
pub fn on_path(bin: &str) -> bool {
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        if dir.join(bin).is_file() {
            return true;
        }
    }
    false
}
