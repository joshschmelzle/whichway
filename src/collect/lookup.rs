//! Focused-lookup pipeline.
//!
//! Resolve a hostname with `dig`, ask the kernel how it would route the
//! result with `route get`, and correlate the resolver number against the
//! `scutil --dns` we already have.

use std::net::{IpAddr, Ipv4Addr};

use anyhow::Result;

use crate::exec::{DEFAULT_TIMEOUT, run, run_lenient};
use crate::model::{LookupResult, Resolver, ResolverScope, Tunnel};

/// Parsed output of `route get <ip>`.
#[derive(Debug, Clone, Default)]
pub struct RouteGet {
    pub destination: Option<String>,
    pub gateway: Option<String>,
    pub interface: Option<String>,
    pub flags: Option<String>,
}

pub fn parse_route_get(input: &str) -> RouteGet {
    let mut r = RouteGet::default();
    for raw in input.lines() {
        let line = raw.trim();
        let Some((key, val)) = line.split_once(':') else {
            continue;
        };
        let val = val.trim().to_string();
        match key.trim() {
            "destination" => r.destination = Some(val),
            "gateway" => r.gateway = Some(val),
            "interface" => r.interface = Some(val),
            "flags" => r.flags = Some(val),
            _ => {}
        }
    }
    r
}

/// Correlate a hostname/IP target against parsed resolvers.
///
/// Picks the first resolver whose `domain` is a suffix match of the
/// hostname, preferring supplemental over scoped over default. For bare IPs
/// nothing matches and we fall through to the first default resolver.
pub fn correlate_resolver<'a>(target: &str, resolvers: &'a [Resolver]) -> Option<&'a Resolver> {
    let is_ip = target.parse::<IpAddr>().is_ok();
    if !is_ip {
        let host = target.trim_end_matches('.').to_lowercase();
        // Pass 1: supplemental match on `domain` field (longest match wins).
        let mut best: Option<(&Resolver, usize)> = None;
        for r in resolvers {
            let Some(d) = r.domain.as_deref() else {
                continue;
            };
            let d = d.trim_end_matches('.').to_lowercase();
            if d.is_empty() {
                continue;
            }
            if host == d || host.ends_with(&format!(".{d}")) {
                let len = d.len();
                if best.is_none_or(|(_, n)| len > n) {
                    best = Some((r, len));
                }
            }
        }
        if let Some((r, _)) = best {
            return Some(r);
        }
    }
    // Fallback: lowest-`order` default resolver with nameservers.
    resolvers
        .iter()
        .filter(|r| r.scope == ResolverScope::Default && !r.nameservers.is_empty())
        .min_by_key(|r| r.order.unwrap_or(u64::MAX))
}

/// Build the verdict string for a focused lookup. We keep this in a single
/// place so the CLI and the web UI can render identical text.
pub fn build_verdict(lookup: &LookupResult) -> String {
    let iface = lookup.interface.as_deref().unwrap_or("(unknown)");
    let label = lookup
        .label
        .as_deref()
        .map(|l| format!(" ({l})"))
        .unwrap_or_default();
    format!(
        "Per the IP routing table, traffic to {target} exits via {iface}{label}.\n\
         Application-layer tools may override this. Run `whichway sockets` as\n\
         root to see live per-process connections.",
        target = lookup.target,
    )
}

/// Apply tunnel attribution to a route interface. We look up by interface
/// name; on no match the label stays `None`.
pub fn label_for_interface(iface: &str, tunnels: &[Tunnel]) -> Option<String> {
    tunnels
        .iter()
        .find(|t| t.interface == iface)
        .map(|t| t.label.clone())
}

/// Top-level lookup. `resolvers` and `tunnels` come from the already-collected
/// summary; we do not re-run those commands.
pub async fn lookup(
    target: &str,
    resolvers: &[Resolver],
    tunnels: &[Tunnel],
) -> Result<LookupResult> {
    let resolved = resolve(target).await;
    // For `route get` we need an IP. Prefer the first IPv4 resolution; fall
    // back to the literal target if it already parses as an IP.
    let route_target: String = resolved
        .iter()
        .find(|s| s.parse::<Ipv4Addr>().is_ok())
        .cloned()
        .or_else(|| {
            if target.parse::<IpAddr>().is_ok() {
                Some(target.to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| target.to_string());

    let rg_out = run("route", &["-n", "get", &route_target], DEFAULT_TIMEOUT)
        .await
        .ok();
    let rg = rg_out.as_deref().map(parse_route_get).unwrap_or_default();

    let matched = correlate_resolver(target, resolvers);
    let label = rg
        .interface
        .as_deref()
        .and_then(|i| label_for_interface(i, tunnels));

    let mut result = LookupResult {
        target: target.to_string(),
        resolved,
        resolver_number: matched.map(|r| r.number),
        resolver_match: matched.and_then(|r| r.domain.clone()),
        resolver_nameservers: matched.map(|r| r.nameservers.clone()).unwrap_or_default(),
        interface: rg.interface,
        gateway: rg.gateway,
        destination: rg.destination,
        flags: rg.flags,
        label,
        verdict: String::new(),
    };
    result.verdict = build_verdict(&result);
    Ok(result)
}

async fn resolve(target: &str) -> Vec<String> {
    if target.parse::<IpAddr>().is_ok() {
        return vec![target.to_string()];
    }
    // `dig +short` prints one address per line. Empty output = NXDOMAIN.
    let out = run_lenient(
        "dig",
        &["+short", "+time=2", "+tries=1", target],
        DEFAULT_TIMEOUT,
    )
    .await
    .unwrap_or_default();
    out.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && l.parse::<IpAddr>().is_ok())
        .collect()
}
