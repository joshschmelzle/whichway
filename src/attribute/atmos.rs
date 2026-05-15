//! Atmos / Axis attribution. Atmos Networks ZTNA ships under
//! `/Applications/Atmos.app`; Axis Security ships as `/Applications/Axis Security`.

use crate::model::Interface;

use super::process::{any_path_exists, pgrep_anchored};

const INSTALL_PATHS: &[&str] = &[
    "/Applications/Atmos.app",
    "/Applications/Axis Security",
    "/Applications/Axis Security.app",
];

pub async fn detect(interfaces: &[Interface]) -> Option<(String, String)> {
    if !any_path_exists(INSTALL_PATHS) {
        return None;
    }
    let running = pgrep_anchored("/Applications/Atmos.app/").await
        || pgrep_anchored("/Applications/Axis Security").await;
    if !running {
        return None;
    }
    // Take the first utun with a routable address that we haven't already
    // attributed; the caller dedupes. utuns from Atmos/Axis typically have
    // a v4 address set (unlike many other utuns).
    let chosen = interfaces
        .iter()
        .find(|i| i.name.starts_with("utun") && !i.inet.is_empty())?;
    Some((
        chosen.name.clone(),
        "Atmos / Axis (install path present, agent running)".to_string(),
    ))
}
