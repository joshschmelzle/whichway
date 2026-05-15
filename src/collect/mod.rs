//! Collector orchestration. The unprivileged summary fans out to four
//! command runs in parallel via `tokio::join!`. Each section's success or
//! failure is independent.

pub mod dns;
pub mod interfaces;
pub mod lookup;
pub mod pf;
pub mod routes;
pub mod services;
pub mod sockets;
pub mod throughput;

use anyhow::Result;

use crate::attribute;
use crate::exec::{DEFAULT_TIMEOUT, LSOF_TIMEOUT, NETTOP_TIMEOUT, run};
use crate::model::{
    Interface, IpFamily, NetworkInfo, PfRules, Resolver, Route, Section, Socket, Summary,
    ThroughputRow,
};

/// Run all unprivileged collectors concurrently. Each section's `Section::data`
/// is `Some` on success and `Section::error` is `Some` with a human-readable
/// message on failure or timeout.
pub async fn collect_summary(privileged: bool) -> Summary {
    let routes_v4 = run("netstat", &["-rn", "-f", "inet"], DEFAULT_TIMEOUT);
    let routes_v6 = run("netstat", &["-rn", "-f", "inet6"], DEFAULT_TIMEOUT);
    let ifc = run("ifconfig", &[], DEFAULT_TIMEOUT);
    let dns_out = run("scutil", &["--dns"], DEFAULT_TIMEOUT);
    let nwi_out = run("scutil", &["--nwi"], DEFAULT_TIMEOUT);

    let (v4, v6, ifc, dns_out, nwi_out) = tokio::join!(routes_v4, routes_v6, ifc, dns_out, nwi_out);

    let mut routes: Vec<Route> = Vec::new();
    let mut routes_err: Option<String> = None;
    match v4 {
        Ok(s) => routes.extend(routes::parse(&s, IpFamily::V4)),
        Err(e) => routes_err = Some(format!("ipv4: {e}")),
    }
    match v6 {
        Ok(s) => routes.extend(routes::parse(&s, IpFamily::V6)),
        Err(e) => {
            let m = format!("ipv6: {e}");
            routes_err = Some(match routes_err {
                Some(prev) => format!("{prev}; {m}"),
                None => m,
            });
        }
    }
    let routes_section = if !routes.is_empty() {
        Section::ok(routes)
    } else if let Some(err) = routes_err {
        Section::err(err)
    } else {
        Section::ok(Vec::new())
    };

    let interfaces: Vec<Interface> = ifc
        .as_ref()
        .map_or_else(|_| Vec::new(), |s| interfaces::parse(s));

    // Tunnel attribution depends on `ifconfig` and various probes.
    let tunnels_section = match &ifc {
        Ok(_) => Section::ok(attribute::label_tunnels(&interfaces).await),
        Err(e) => Section::err(format!("ifconfig: {e}")),
    };

    // Enrich route table with tunnel labels.
    let routes_section = match (routes_section.data, routes_section.error) {
        (Some(mut rs), err) => {
            if let Some(tunnels) = tunnels_section.data.as_ref() {
                for r in &mut rs {
                    r.label = tunnels
                        .iter()
                        .find(|t| t.interface == r.interface)
                        .map(|t| t.label.clone());
                }
            }
            Section {
                data: Some(rs),
                error: err,
            }
        }
        (None, err) => Section {
            data: None,
            error: err,
        },
    };

    let dns_section: Section<Vec<Resolver>> = match dns_out {
        Ok(s) => Section::ok(dns::parse(&s)),
        Err(e) => Section::err(format!("scutil --dns: {e}")),
    };

    let services_section: Section<NetworkInfo> = match nwi_out {
        Ok(s) => Section::ok(services::parse(&s)),
        Err(e) => Section::err(format!("scutil --nwi: {e}")),
    };

    let pf_section = if privileged {
        collect_pf().await
    } else {
        Section::requires_root()
    };

    Summary {
        collected_at: now_rfc3339(),
        platform: "macos",
        privileged,
        routes: routes_section,
        tunnels: tunnels_section,
        dns: dns_section,
        services: services_section,
        pf: pf_section,
    }
}

pub async fn collect_pf() -> Section<PfRules> {
    let rules = run("pfctl", &["-sr"], DEFAULT_TIMEOUT);
    let all = run("pfctl", &["-sa"], DEFAULT_TIMEOUT);
    let (r, a) = tokio::join!(rules, all);
    match (r, a) {
        (Ok(rules), Ok(all)) => Section::ok(pf::parse(&rules, &all)),
        (Err(e), _) | (_, Err(e)) => Section::err(format!("pfctl: {e}")),
    }
}

pub async fn collect_sockets() -> Result<Vec<Socket>> {
    let out = run("lsof", &["-i", "-P", "-n"], LSOF_TIMEOUT).await?;
    Ok(sockets::parse(&out))
}

pub async fn collect_throughput() -> Result<Vec<ThroughputRow>> {
    let out = run(
        "nettop",
        &["-P", "-x", "-l", "2", "-J", "bytes_in,bytes_out,interface"],
        NETTOP_TIMEOUT,
    )
    .await?;
    Ok(throughput::parse(&out))
}

/// RFC3339 UTC timestamp without pulling in `chrono`.
///
/// Good enough for a human-facing "collected at" stamp.
pub fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    // Algorithm from Howard Hinnant's date library, condensed. All casts are
    // bounded by the algorithm (era * 146_097 fits in i64 for any plausible
    // UNIX timestamp; doe, yoe, doy, mp are all in [0, 146_096]).
    #[allow(
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation,
        reason = "values are bounded by the civil-from-days algorithm"
    )]
    let (year, mon, day, hour, min, sec) = {
        let days = (secs / 86_400) as i64;
        let secs_of_day = secs % 86_400;
        let hour = secs_of_day / 3600;
        let minute = (secs_of_day % 3600) / 60;
        let second = secs_of_day % 60;
        let (y, mo, d) = civil_from_days(days + 719_468);
        (y, mo, d, hour, minute, second)
    };
    format!("{year:04}-{mon:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::bool_to_int_with_if,
    reason = "values are bounded by the civil-from-days algorithm; const fn precludes From<bool>"
)]
const fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    (year, month as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc3339_format_shape() {
        let s = now_rfc3339();
        assert_eq!(s.len(), 20, "{s}");
        assert!(s.ends_with('Z'));
    }
}
