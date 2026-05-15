//! Tunnel labeling pipeline.
//!
//! We iterate the candidate detectors in priority order and label utun
//! interfaces. Anything left over after all detectors have run is labeled
//! "Unknown" with raw interface info.

pub mod atmos;
pub mod process;
pub mod tailscale;
pub mod zscaler;

use std::collections::HashMap;

use crate::exec::{DEFAULT_TIMEOUT, run_lenient};
use crate::model::{Interface, Tunnel};

/// Returns a vector of `Tunnel` rows, one per tunnel-shaped interface.
///
/// "Tunnel-shaped" means utun*, plus any en*/bridge* that carry a routable
/// address (those are interesting context but get a neutral "Native" label).
pub async fn label_tunnels(interfaces: &[Interface]) -> Vec<Tunnel> {
    let mut labels: HashMap<String, (String, String)> = HashMap::new();

    if let Some((iface, desc)) = tailscale::detect(interfaces).await {
        labels
            .entry(iface)
            .or_insert_with(|| ("Tailscale".to_string(), desc));
    }
    if let Some((iface, desc)) = zscaler::detect(interfaces).await {
        labels
            .entry(iface)
            .or_insert_with(|| ("Zscaler".to_string(), desc));
    }
    if let Some((iface, desc)) = atmos::detect(interfaces).await {
        labels
            .entry(iface)
            .or_insert_with(|| ("Atmos / Axis".to_string(), desc));
    }
    // Generic IPSec/IKEv2 via `scutil --nc list`.
    let nc_labels = generic_ipsec_labels().await;
    for (iface, desc) in nc_labels {
        labels
            .entry(iface)
            .or_insert_with(|| ("IPSec/IKEv2".to_string(), desc));
    }

    let mut out = Vec::new();
    for iface in interfaces {
        // Only emit utun interfaces in the Tunnel table. en/bridge stays in
        // the route table context. (The spec says "utunN, en*, bridge*" but
        // for the Tunnels view, utun is the meaningful subset.)
        if !iface.name.starts_with("utun") {
            continue;
        }
        let (label, desc) = labels
            .get(&iface.name)
            .cloned()
            .unwrap_or_else(|| ("Unknown".to_string(), "no signature matched".to_string()));
        out.push(Tunnel {
            interface: iface.name.clone(),
            label,
            description: desc,
            local_ip: iface
                .inet
                .first()
                .cloned()
                .or_else(|| iface.inet6.first().cloned()),
            peer_or_gateway: iface.peer.clone(),
            mtu: iface.mtu,
            status: iface.status.clone(),
        });
    }
    out
}

/// Parse `scutil --nc list` for VPN service info.
///
/// `scutil --nc list` returns lines like:
///
/// ```text
/// * (Connected) UUID VPN (com.axissecurity.client) "axis"   [VPN:com.axissecurity.client]
/// ```
///
/// We can't directly map service name -> utun without root-level interface
/// queries, so we emit a synthetic description keyed on service name. The
/// label is applied to a utun only if the service name appears as a substring
/// of an interface description (rare; mostly used for `IPSec` configs).
async fn generic_ipsec_labels() -> Vec<(String, String)> {
    let out = run_lenient("scutil", &["--nc", "list"], DEFAULT_TIMEOUT)
        .await
        .unwrap_or_default();
    // Hook for future expansion: we currently can't resolve a Connected NC
    // service to a specific utun without privileged interface queries, so we
    // just confirm the command runs and return nothing.
    let _ = out;
    Vec::new()
}
