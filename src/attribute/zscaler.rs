//! Zscaler attribution.
//!
//! The Zscaler Client Connector installs to `/Applications/Zscaler/` and
//! runs daemons under `/Applications/Zscaler/`. Their tunnel is typically
//! MTU 1400, and the peer IP is in a known range (we don't enforce that
//! strictly — we just use it as confirming evidence).

use crate::model::Interface;

use super::process::{any_path_exists, pgrep_anchored};

const INSTALL_PATHS: &[&str] = &[
    "/Applications/Zscaler",
    "/Library/Application Support/Zscaler",
];

pub async fn detect(interfaces: &[Interface]) -> Option<(String, String)> {
    if !any_path_exists(INSTALL_PATHS) {
        return None;
    }
    let running = pgrep_anchored("/Applications/Zscaler/").await;
    if !running {
        return None;
    }
    // Pick the first utun with MTU == 1400. Fall back to first utun with
    // a non-link-local inet address if no exact-MTU match exists.
    let by_mtu = interfaces
        .iter()
        .find(|i| i.name.starts_with("utun") && i.mtu == Some(1400));
    let chosen = by_mtu.or_else(|| {
        interfaces
            .iter()
            .find(|i| i.name.starts_with("utun") && !i.inet.is_empty())
    })?;
    Some((
        chosen.name.clone(),
        format!(
            "Zscaler (install path present, daemon running, MTU {})",
            chosen
                .mtu
                .map_or_else(|| "?".to_string(), |m| m.to_string())
        ),
    ))
}
