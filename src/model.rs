//! Shared data model. Everything is `Serialize` so the same structs back the
//! CLI tables, the `--json` output, and the HTTP API.

use serde::Serialize;

/// Wrapper used for every section in the summary. The contract is:
///
/// * `data == Some && error == None` — collector ran cleanly
/// * `data == None && error == Some` — collector failed or timed out
/// * `data == None && error == Some("requires root")` — privileged section
///
/// Both fields can be `None` for sections that simply weren't requested.
#[derive(Debug, Clone, Serialize, Default)]
pub struct Section<T> {
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T> Section<T> {
    pub const fn ok(data: T) -> Self {
        Self {
            data: Some(data),
            error: None,
        }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            data: None,
            error: Some(msg.into()),
        }
    }
    pub fn requires_root() -> Self {
        Self::err("requires root")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub collected_at: String,
    pub platform: &'static str,
    pub privileged: bool,
    pub routes: Section<Vec<Route>>,
    pub tunnels: Section<Vec<Tunnel>>,
    pub dns: Section<Vec<Resolver>>,
    pub services: Section<NetworkInfo>,
    pub pf: Section<PfRules>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Route {
    pub family: IpFamily,
    pub destination: String,
    pub gateway: String,
    pub flags: String,
    pub interface: String,
    pub expire: Option<String>,
    /// Tunnel attribution label if the egress interface is a known VPN.
    pub label: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IpFamily {
    V4,
    V6,
}

#[derive(Debug, Clone, Serialize)]
pub struct Interface {
    pub name: String,
    pub flags: String,
    pub mtu: Option<u32>,
    pub status: Option<String>,
    pub ether: Option<String>,
    pub inet: Vec<String>,
    pub inet6: Vec<String>,
    /// For utun: peer/destination if `PtP`.
    pub peer: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Tunnel {
    pub interface: String,
    /// Short label, e.g. "Tailscale", "Zscaler", "Axis", "Unknown".
    pub label: String,
    /// Longer human-readable description (signal that matched).
    pub description: String,
    pub local_ip: Option<String>,
    pub peer_or_gateway: Option<String>,
    pub mtu: Option<u32>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Resolver {
    pub number: u32,
    pub scope: ResolverScope,
    pub nameservers: Vec<String>,
    pub search: Vec<String>,
    /// Single `domain :` line (supplemental match domain).
    pub domain: Option<String>,
    pub if_index: Option<u32>,
    pub interface: Option<String>,
    pub flags: Option<String>,
    pub order: Option<u64>,
    pub options: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ResolverScope {
    /// Default DNS configuration block.
    Default,
    /// `DNS configuration (for scoped queries)` — interface-scoped.
    Scoped,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct NetworkInfo {
    /// Ordered list of service interfaces from `Network interfaces:` line.
    pub order: Vec<String>,
    /// One entry per interface that appears in the v4 or v6 block.
    pub services: Vec<ServiceEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceEntry {
    pub interface: String,
    pub family: IpFamily,
    pub flags: Option<String>,
    pub address: Option<String>,
    pub reach: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LookupResult {
    pub target: String,
    pub resolved: Vec<String>,
    /// Resolver number (`scutil --dns` numbering) that the matched supplemental
    /// or scoped block belonged to, if we could correlate.
    pub resolver_number: Option<u32>,
    pub resolver_match: Option<String>,
    pub resolver_nameservers: Vec<String>,
    pub interface: Option<String>,
    pub gateway: Option<String>,
    pub destination: Option<String>,
    pub flags: Option<String>,
    pub label: Option<String>,
    /// Verbose verdict text including the application-layer caveat.
    pub verdict: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Socket {
    pub command: String,
    pub pid: u32,
    pub user: String,
    pub fd: String,
    pub kind: String, // IPv4 / IPv6
    pub protocol: String,
    pub local: String,
    pub remote: String,
    pub state: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThroughputRow {
    pub process: String,
    pub interface: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct PfRules {
    pub rules: Vec<String>,
    pub anchors: Vec<String>,
}
