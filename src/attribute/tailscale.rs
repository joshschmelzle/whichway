//! Tailscale attribution.
//!
//! Primary signal: `tailscale status --json` returns a `Self.TailscaleIPs`
//! list which we match against utun interface addresses. We never use the
//! CGNAT range as a fallback heuristic, per spec.

use serde::Deserialize;

use crate::exec::{DEFAULT_TIMEOUT, run};
use crate::model::Interface;

use super::process::on_path;

#[derive(Deserialize)]
struct TsStatus {
    #[serde(rename = "Self", default)]
    self_: Option<TsSelf>,
}

#[derive(Deserialize)]
struct TsSelf {
    #[serde(rename = "TailscaleIPs", default)]
    tailscale_ips: Vec<String>,
}

/// Attempt to identify which interface (if any) belongs to Tailscale.
///
/// Returns `(interface_name, description)`.
pub async fn detect(interfaces: &[Interface]) -> Option<(String, String)> {
    if !on_path("tailscale") {
        return None;
    }
    let out = run("tailscale", &["status", "--json"], DEFAULT_TIMEOUT)
        .await
        .ok()?;
    let parsed: TsStatus = serde_json::from_str(&out).ok()?;
    let ips = parsed.self_?.tailscale_ips;
    if ips.is_empty() {
        return None;
    }
    for iface in interfaces {
        if !iface.name.starts_with("utun") {
            continue;
        }
        for ip in &ips {
            if iface.inet.iter().any(|a| a == ip) || iface.inet6.iter().any(|a| a == ip) {
                return Some((
                    iface.name.clone(),
                    format!("Tailscale (Self.TailscaleIPs match: {ip})"),
                ));
            }
        }
    }
    None
}
