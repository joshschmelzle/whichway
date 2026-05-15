//! CLI rendering. We use `tabled` for tables and `owo-colors` for accents.
//! `NO_COLOR` is respected via `owo_colors::supports_colors`.

use owo_colors::{OwoColorize, Stream};
use tabled::settings::object::Columns;
use tabled::settings::{Alignment, Modify, Style};
use tabled::{Table, Tabled};

use whichway::model::{
    LookupResult, NetworkInfo, PfRules, Resolver, ResolverScope, Route, Section, Socket, Summary,
    ThroughputRow, Tunnel,
};

/// Render the full summary to stdout, plus a warning footer for failed
/// collectors.
pub(crate) fn print_summary(s: &Summary) {
    print_routes(&s.routes);
    println!();
    print_tunnels(&s.tunnels);
    println!();
    print_dns(&s.dns);
    println!();
    print_services(&s.services);
    println!();
    if s.privileged {
        print_pf(&s.pf);
    } else {
        eprintln!(
            "{} packet filter (pfctl) requires root; run with sudo to enable.",
            "note:".if_supports_color(Stream::Stderr, |s| s.dimmed())
        );
    }
    print_footer(s);
}
/// Footer listing collectors that errored or timed out.
fn print_footer(s: &Summary) {
    let mut failed: Vec<(&str, &str)> = Vec::new();
    if let Some(e) = &s.routes.error {
        failed.push(("routes", e));
    }
    if let Some(e) = &s.tunnels.error {
        failed.push(("tunnels", e));
    }
    if let Some(e) = &s.dns.error {
        failed.push(("dns", e));
    }
    if let Some(e) = &s.services.error {
        failed.push(("services", e));
    }
    if s.privileged {
        if let Some(e) = &s.pf.error {
            failed.push(("pf", e));
        }
    }
    if failed.is_empty() {
        return;
    }
    eprintln!();
    eprintln!(
        "{}",
        "Some collectors failed:".if_supports_color(Stream::Stderr, |s| s.yellow())
    );
    for (name, err) in failed {
        eprintln!("  - {name}: {err}");
    }
}

#[derive(Tabled)]
struct RouteRow {
    family: &'static str,
    destination: String,
    gateway: String,
    flags: String,
    interface: String,
    label: String,
}

/// `netstat -rn` route flag legend, copied verbatim from `man netstat(1)` on
/// macOS (OUTPUT section, "The mapping between letters and flags is:").
const ROUTE_FLAG_LEGEND: &[(char, &str, &str)] = &[
    ('1', "RTF_PROTO1", "Protocol specific routing flag #1"),
    ('2', "RTF_PROTO2", "Protocol specific routing flag #2"),
    ('3', "RTF_PROTO3", "Protocol specific routing flag #3"),
    (
        'B',
        "RTF_BLACKHOLE",
        "Just discard packets (during updates)",
    ),
    (
        'b',
        "RTF_BROADCAST",
        "The route represents a broadcast address",
    ),
    ('C', "RTF_CLONING", "Generate new routes on use"),
    (
        'c',
        "RTF_PRCLONING",
        "Protocol-specified generate new routes on use",
    ),
    ('D', "RTF_DYNAMIC", "Created dynamically (by redirect)"),
    (
        'G',
        "RTF_GATEWAY",
        "Destination requires forwarding by intermediary",
    ),
    ('H', "RTF_HOST", "Host entry (net otherwise)"),
    (
        'I',
        "RTF_IFSCOPE",
        "Route is associated with an interface scope",
    ),
    (
        'i',
        "RTF_IFREF",
        "Route is holding a reference to the interface",
    ),
    (
        'L',
        "RTF_LLINFO",
        "Valid protocol to link address translation",
    ),
    ('M', "RTF_MODIFIED", "Modified dynamically (by redirect)"),
    (
        'm',
        "RTF_MULTICAST",
        "The route represents a multicast address",
    ),
    ('R', "RTF_REJECT", "Host or net unreachable"),
    ('r', "RTF_ROUTER", "Host is a default router"),
    ('S', "RTF_STATIC", "Manually added"),
    ('U', "RTF_UP", "Route usable"),
    (
        'W',
        "RTF_WASCLONED",
        "Route was generated as a result of cloning",
    ),
    (
        'X',
        "RTF_XRESOLVE",
        "External daemon translates proto to link address",
    ),
    (
        'Y',
        "RTF_PROXY",
        "Proxying; cloned routes will not be scoped",
    ),
    (
        'g',
        "RTF_GLOBAL",
        "Route to a destination of the global internet (policy hint)",
    ),
];

fn print_route_flag_legend() {
    println!("Route flag legend (man netstat):");
    let const_w = ROUTE_FLAG_LEGEND
        .iter()
        .map(|(_, c, _)| c.len())
        .max()
        .unwrap_or(0);
    for (letter, constant, desc) in ROUTE_FLAG_LEGEND {
        println!("  {letter}  {constant:<const_w$}  {desc}");
    }
    println!();
}

pub(crate) fn print_routes(section: &Section<Vec<Route>>) {
    section_header("Routes", section);
    print_route_flag_legend();
    let Some(rs) = section.data.as_ref() else {
        return;
    };
    let rows: Vec<RouteRow> = rs
        .iter()
        .map(|r| RouteRow {
            family: match r.family {
                whichway::model::IpFamily::V4 => "v4",
                whichway::model::IpFamily::V6 => "v6",
            },
            destination: r.destination.clone(),
            gateway: r.gateway.clone(),
            flags: r.flags.clone(),
            interface: r.interface.clone(),
            label: r.label.clone().unwrap_or_default(),
        })
        .collect();
    let mut table = Table::new(rows);
    table
        .with(Style::sharp())
        .with(Modify::new(Columns::new(..)).with(Alignment::left()));
    println!("{table}");
}

#[derive(Tabled)]
struct TunnelRow {
    interface: String,
    label: String,
    local_ip: String,
    peer: String,
    mtu: String,
    description: String,
}

pub(crate) fn print_tunnels(section: &Section<Vec<Tunnel>>) {
    section_header("Tunnels", section);
    let Some(ts) = section.data.as_ref() else {
        return;
    };
    let rows: Vec<TunnelRow> = ts
        .iter()
        .map(|t| TunnelRow {
            interface: t.interface.clone(),
            label: t.label.clone(),
            local_ip: t.local_ip.clone().unwrap_or_default(),
            peer: t.peer_or_gateway.clone().unwrap_or_default(),
            mtu: t.mtu.map(|m| m.to_string()).unwrap_or_default(),
            description: t.description.clone(),
        })
        .collect();
    let mut table = Table::new(rows);
    table.with(Style::sharp());
    println!("{table}");
}

#[derive(Tabled)]
struct DnsRow {
    n: u32,
    scope: &'static str,
    interface: String,
    nameservers: String,
    domain: String,
    flags: String,
}

pub(crate) fn print_dns(section: &Section<Vec<Resolver>>) {
    section_header("DNS resolvers", section);
    let Some(rs) = section.data.as_ref() else {
        return;
    };
    let rows: Vec<DnsRow> = rs
        .iter()
        .map(|r| DnsRow {
            n: r.number,
            scope: match r.scope {
                ResolverScope::Default => "default",
                ResolverScope::Scoped => "scoped",
            },
            interface: r.interface.clone().unwrap_or_default(),
            nameservers: r.nameservers.join(", "),
            domain: r
                .domain
                .clone()
                .or_else(|| {
                    if r.search.is_empty() {
                        None
                    } else {
                        Some(r.search.join(","))
                    }
                })
                .unwrap_or_default(),
            flags: r.flags.clone().unwrap_or_default(),
        })
        .collect();
    let mut table = Table::new(rows);
    table.with(Style::sharp());
    println!("{table}");
}

#[derive(Tabled)]
struct ServiceRow {
    interface: String,
    family: &'static str,
    address: String,
    reach: String,
}

pub(crate) fn print_services(section: &Section<NetworkInfo>) {
    section_header("Services / reachability", section);
    let Some(info) = section.data.as_ref() else {
        return;
    };
    if !info.order.is_empty() {
        println!("Service order: {}", info.order.join(", "));
    }
    let rows: Vec<ServiceRow> = info
        .services
        .iter()
        .map(|s| ServiceRow {
            interface: s.interface.clone(),
            family: match s.family {
                whichway::model::IpFamily::V4 => "v4",
                whichway::model::IpFamily::V6 => "v6",
            },
            address: s.address.clone().unwrap_or_default(),
            reach: s.reach.clone().unwrap_or_default(),
        })
        .collect();
    let mut table = Table::new(rows);
    table.with(Style::sharp());
    println!("{table}");
}

#[derive(Tabled)]
struct SocketRow {
    command: String,
    pid: u32,
    user: String,
    kind: String,
    proto: String,
    local: String,
    remote: String,
    state: String,
}

pub(crate) fn print_sockets(section: &Section<Vec<Socket>>) {
    section_header("Sockets (lsof)", section);
    let Some(rs) = section.data.as_ref() else {
        return;
    };
    let rows: Vec<SocketRow> = rs
        .iter()
        .map(|s| SocketRow {
            command: s.command.clone(),
            pid: s.pid,
            user: s.user.clone(),
            kind: s.kind.clone(),
            proto: s.protocol.clone(),
            local: s.local.clone(),
            remote: s.remote.clone(),
            state: s.state.clone().unwrap_or_default(),
        })
        .collect();
    let mut table = Table::new(rows);
    table.with(Style::sharp());
    println!("{table}");
}

#[derive(Tabled)]
struct ThroughputView {
    process: String,
    interface: String,
    bytes_in: u64,
    bytes_out: u64,
}

pub(crate) fn print_throughput(section: &Section<Vec<ThroughputRow>>) {
    section_header("Throughput (nettop)", section);
    let Some(rs) = section.data.as_ref() else {
        return;
    };
    let rows: Vec<ThroughputView> = rs
        .iter()
        .map(|r| ThroughputView {
            process: r.process.clone(),
            interface: r.interface.clone(),
            bytes_in: r.bytes_in,
            bytes_out: r.bytes_out,
        })
        .collect();
    let mut table = Table::new(rows);
    table.with(Style::sharp());
    println!("{table}");
}

pub(crate) fn print_pf(section: &Section<PfRules>) {
    section_header("Packet filter", section);
    let Some(p) = section.data.as_ref() else {
        return;
    };
    if !p.anchors.is_empty() {
        println!("Anchors:");
        for a in &p.anchors {
            println!("  {a}");
        }
        println!();
    }
    if !p.rules.is_empty() {
        println!("Rules:");
        for r in &p.rules {
            println!("  {r}");
        }
    }
}

pub(crate) fn print_lookup(l: &LookupResult) {
    println!(
        "{:11}{}",
        "Target:".if_supports_color(Stream::Stdout, |s| s.bold()),
        l.target
    );
    let resolved = if l.resolved.is_empty() {
        "(no answer)".to_string()
    } else {
        let mut s = l.resolved.join(", ");
        if let Some(n) = l.resolver_number {
            use std::fmt::Write as _;
            let _ = write!(s, " (via resolver #{n}");
            if let Some(m) = &l.resolver_match {
                let _ = write!(s, ", domain match: {m}");
            }
            if !l.resolver_nameservers.is_empty() {
                let _ = write!(s, ", ns: {}", l.resolver_nameservers.join(","));
            }
            s.push(')');
        }
        s
    };
    println!(
        "{:11}{}",
        "Resolved:".if_supports_color(Stream::Stdout, |s| s.bold()),
        resolved
    );
    let route_line = match (&l.destination, &l.interface) {
        (Some(d), Some(i)) => {
            let label = l
                .label
                .as_deref()
                .map(|s| format!(" ({s})"))
                .unwrap_or_default();
            format!("{d} → {i}{label}")
        }
        _ => "(no route)".to_string(),
    };
    println!(
        "{:11}{}",
        "Route:".if_supports_color(Stream::Stdout, |s| s.bold()),
        route_line
    );
    if let Some(g) = &l.gateway {
        println!(
            "{:11}{}",
            "Gateway:".if_supports_color(Stream::Stdout, |s| s.bold()),
            g
        );
    }
    println!(
        "{}",
        "Verdict:".if_supports_color(Stream::Stdout, |s| s.bold())
    );
    for line in l.verdict.lines() {
        println!("   {line}");
    }
}

fn section_header<T: serde::Serialize>(name: &str, section: &Section<T>) {
    if let Some(err) = &section.error {
        eprintln!(
            "{} {}: {}",
            "warning:".if_supports_color(Stream::Stderr, |s| s.yellow()),
            name,
            err
        );
    } else {
        println!(
            "{}",
            format!("== {name} ==").if_supports_color(Stream::Stdout, |s| s.bold())
        );
    }
}
