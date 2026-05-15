//! `ifconfig` parser.
//!
//! Each interface block starts at column 0 and continues with tab-indented
//! lines. We only pull out the fields whichway cares about (MTU, status,
//! ether, inet/inet6 addresses, and the `PtP` peer for utun).

use crate::model::Interface;

pub fn parse(input: &str) -> Vec<Interface> {
    let mut out: Vec<Interface> = Vec::new();
    let mut current: Option<Interface> = None;

    for raw in input.lines() {
        let is_indented = raw.starts_with(|c: char| c.is_whitespace());
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if !is_indented {
            // New interface block. Header looks like `name: flags=... mtu N`.
            if let Some(iface) = current.take() {
                out.push(iface);
            }
            // Split on the first `:` to get the name.
            if let Some((name, rest)) = line.split_once(':') {
                let mut iface = Interface {
                    name: name.trim().to_string(),
                    flags: String::new(),
                    mtu: None,
                    status: None,
                    ether: None,
                    inet: Vec::new(),
                    inet6: Vec::new(),
                    peer: None,
                };
                // rest looks like " flags=8051<UP,POINTOPOINT,...> mtu 1500"
                for tok in rest.split_whitespace() {
                    if let Some(rest) = tok.strip_prefix("flags=") {
                        iface.flags = rest.to_string();
                    }
                }
                // Find "mtu N".
                let toks: Vec<&str> = rest.split_whitespace().collect();
                if let Some(idx) = toks.iter().position(|t| *t == "mtu") {
                    if let Some(n) = toks.get(idx + 1).and_then(|s| s.parse().ok()) {
                        iface.mtu = Some(n);
                    }
                }
                current = Some(iface);
            }
            continue;
        }
        let Some(iface) = current.as_mut() else {
            continue;
        };
        // Indented attribute line.
        if let Some(rest) = line.strip_prefix("inet ") {
            // `inet 192.168.6.204 netmask 0xffffff00 broadcast ...`
            //  or `inet 100.65.0.1 --> 100.65.0.1 netmask ...`
            let toks: Vec<&str> = rest.split_whitespace().collect();
            if let Some(addr) = toks.first() {
                iface.inet.push((*addr).to_string());
            }
            if let Some(idx) = toks.iter().position(|t| *t == "-->") {
                if let Some(peer) = toks.get(idx + 1) {
                    iface.peer = Some((*peer).to_string());
                }
            }
        } else if let Some(rest) = line.strip_prefix("inet6 ") {
            // `inet6 fe80::...%utun1 prefixlen 64 ...`
            if let Some(addr) = rest.split_whitespace().next() {
                iface.inet6.push(addr.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("ether ") {
            if let Some(mac) = rest.split_whitespace().next() {
                iface.ether = Some(mac.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("status: ") {
            iface.status = Some(rest.to_string());
        }
    }
    if let Some(iface) = current.take() {
        out.push(iface);
    }
    out
}
