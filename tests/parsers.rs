//! Parser tests. These exercise every collector against committed fixtures
//! in `tests/fixtures/`. No commands are executed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::needless_collect,
    clippy::uninlined_format_args,
    clippy::unnecessary_debug_formatting,
    reason = "test code: panics on bad fixtures are intentional"
)]

use whichway::collect::{dns, interfaces, lookup, pf, routes, services, sockets, throughput};
use whichway::model::{IpFamily, ResolverScope};

fn fx(name: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("missing fixture {p:?}: {e}"))
}

#[test]
fn parses_netstat_inet() {
    let rs = routes::parse(&fx("netstat_inet.txt"), IpFamily::V4);
    assert!(!rs.is_empty(), "should have v4 routes");
    let default = rs
        .iter()
        .find(|r| r.destination == "default" && r.interface == "en7");
    assert!(default.is_some(), "default route on en7 should be present");
    assert!(
        rs.iter().any(|r| r.interface == "utun6"),
        "utun6 routes present"
    );
    // Sanity: every row has the four required columns parsed.
    for r in &rs {
        assert!(!r.destination.is_empty());
        assert!(!r.gateway.is_empty());
        assert!(!r.flags.is_empty());
        assert!(!r.interface.is_empty());
        assert_eq!(r.family, IpFamily::V4);
    }
}

#[test]
fn parses_netstat_inet6() {
    let rs = routes::parse(&fx("netstat_inet6.txt"), IpFamily::V6);
    assert!(!rs.is_empty());
    assert!(rs.iter().all(|r| r.family == IpFamily::V6));
}

#[test]
fn parses_multivpn_routes() {
    let s = fx("netstat_multivpn.txt");
    let v4 = routes::parse(&s, IpFamily::V4);
    let v6 = routes::parse(&s, IpFamily::V6);
    // The two `default` rows on en0 (native) and utun2 (Zscaler-shaped) and a
    // utun1 (Tailscale-shaped) /32 should all appear.
    assert!(
        v4.iter()
            .any(|r| r.destination == "default" && r.interface == "en0")
    );
    assert!(
        v4.iter()
            .any(|r| r.destination == "default" && r.interface == "utun2")
    );
    assert!(
        v4.iter()
            .any(|r| r.destination == "100.96.0.1/32" && r.interface == "utun1")
    );
    assert!(!v6.is_empty());
}

#[test]
fn parses_ifconfig() {
    let ifs = interfaces::parse(&fx("ifconfig.txt"));
    let en7 = ifs.iter().find(|i| i.name == "en7").expect("en7 present");
    assert_eq!(en7.mtu, Some(1500));
    assert_eq!(en7.status.as_deref(), Some("active"));
    assert!(en7.inet.iter().any(|a| a == "192.168.6.204"));
    assert!(!en7.inet6.is_empty());
    let utun6 = ifs
        .iter()
        .find(|i| i.name == "utun6")
        .expect("utun6 present");
    assert_eq!(utun6.mtu, Some(1300));
    assert_eq!(utun6.inet.first().map(String::as_str), Some("100.65.0.1"));
    assert_eq!(utun6.peer.as_deref(), Some("100.65.0.1"));
}

#[test]
fn parses_ifconfig_multivpn() {
    let ifs = interfaces::parse(&fx("ifconfig_multivpn.txt"));
    assert!(
        ifs.iter()
            .any(|i| i.name == "en0" && i.inet.contains(&"192.168.1.42".to_string()))
    );
    let utun1 = ifs.iter().find(|i| i.name == "utun1").expect("utun1");
    assert_eq!(utun1.inet.first().map(String::as_str), Some("100.96.0.1"));
    let utun2 = ifs.iter().find(|i| i.name == "utun2").expect("utun2");
    assert_eq!(utun2.mtu, Some(1400));
}

#[test]
fn parses_scutil_dns() {
    let rs = dns::parse(&fx("scutil_dns.txt"));
    // 8 default + 2 scoped from the fixture.
    let default: Vec<_> = rs
        .iter()
        .filter(|r| r.scope == ResolverScope::Default)
        .collect();
    let scoped: Vec<_> = rs
        .iter()
        .filter(|r| r.scope == ResolverScope::Scoped)
        .collect();
    assert_eq!(default.len(), 8);
    assert_eq!(scoped.len(), 2);
    let r1 = &default[0];
    assert_eq!(r1.number, 1);
    assert_eq!(r1.nameservers, vec!["100.65.0.2"]);
    assert_eq!(r1.if_index, Some(25));
    assert_eq!(r1.interface.as_deref(), Some("utun6"));
    // resolver #3 has a `domain : local` line.
    let r3 = default.iter().find(|r| r.number == 3).unwrap();
    assert_eq!(r3.domain.as_deref(), Some("local"));
}

#[test]
fn parses_scutil_nwi() {
    let info = services::parse(&fx("scutil_nwi.txt"));
    assert_eq!(info.order, vec!["en7", "utun6"]);
    assert!(
        info.services
            .iter()
            .any(|s| s.interface == "en7" && s.family == IpFamily::V4)
    );
    assert!(
        info.services
            .iter()
            .any(|s| s.interface == "en7" && s.family == IpFamily::V6)
    );
}

#[test]
fn parses_route_get() {
    let rg = lookup::parse_route_get(&fx("route_get.txt"));
    assert_eq!(rg.interface.as_deref(), Some("en7"));
    assert_eq!(rg.gateway.as_deref(), Some("192.168.6.1"));
    assert_eq!(rg.destination.as_deref(), Some("default"));
}

#[test]
fn parses_lsof() {
    let socks = sockets::parse(&fx("lsof.txt"));
    assert!(socks.iter().any(|s| s.command == "firefox"
        && s.protocol == "TCP"
        && s.state.as_deref() == Some("ESTABLISHED")));
    let lis = socks
        .iter()
        .find(|s| s.state.as_deref() == Some("LISTEN"))
        .unwrap();
    assert!(lis.local.contains(":631"));
}

#[test]
fn parses_nettop() {
    let rows = throughput::parse(&fx("nettop.txt"));
    assert!(!rows.is_empty());
    assert!(rows.iter().any(|r| r.process.contains("opencode")
        || r.process.contains("Microsoft")
        || r.process.contains("firefox")));
}

#[test]
fn parses_pfctl() {
    let rules = pf::parse(&fx("pfctl_sr.txt"), &fx("pfctl_sa.txt"));
    assert!(rules.anchors.iter().any(|a| a.contains("com.apple/")));
    assert!(rules.anchors.iter().any(|a| a.contains("littlesnitch")));
    assert!(rules.rules.iter().any(|r| r.contains("pass quick on lo0")));
}

#[test]
fn resolver_correlation_supplemental_domain() {
    let resolvers = dns::parse(&fx("scutil_dns.txt"));
    // No fixture domain matches example.com so we should fall back to the
    // default resolver with the lowest order — resolver #2 (ns 9.9.9.9, order 200000).
    let r = lookup::correlate_resolver("example.com", &resolvers).expect("fallback");
    assert_eq!(r.number, 2);
    assert!(r.nameservers.iter().any(|n| n == "9.9.9.9"));
}

#[test]
fn resolver_correlation_ip_target() {
    let resolvers = dns::parse(&fx("scutil_dns.txt"));
    let r = lookup::correlate_resolver("1.1.1.1", &resolvers).expect("fallback");
    // IP target -> fallback default resolver.
    assert_eq!(r.scope, ResolverScope::Default);
}
