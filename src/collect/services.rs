//! `scutil --nwi` parser. The output has v4 and v6 blocks plus a trailing
//! `Network interfaces:` list giving the active service order.

use crate::model::{IpFamily, NetworkInfo, ServiceEntry};

pub fn parse(input: &str) -> NetworkInfo {
    let mut info = NetworkInfo::default();
    let mut family: Option<IpFamily> = None;
    let mut current: Option<ServiceEntry> = None;

    let flush = |info: &mut NetworkInfo, cur: &mut Option<ServiceEntry>| {
        if let Some(s) = cur.take() {
            info.services.push(s);
        }
    };

    for raw in input.lines() {
        let line = raw.trim_end();
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("IPv4 network interface information") {
            flush(&mut info, &mut current);
            family = Some(IpFamily::V4);
            continue;
        }
        if trimmed.starts_with("IPv6 network interface information") {
            flush(&mut info, &mut current);
            family = Some(IpFamily::V6);
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("Network interfaces:") {
            flush(&mut info, &mut current);
            info.order = rest.split_whitespace().map(ToString::to_string).collect();
            continue;
        }
        let Some(fam) = family else { continue };
        // `REACH : flags ...` is a summary; skip.
        if trimmed.starts_with("REACH ") {
            continue;
        }
        // A new entry looks like `en7 : flags : 0x7 (IPv4,IPv6,DNS)`.
        // Continuations look like `      address    : 192.168.6.204`.
        // The crucial heuristic: a new entry line is NOT heavily indented
        // and has its name as the first token before ` :`.
        if let Some((maybe_iface, val)) = trimmed.split_once(':') {
            let key = maybe_iface.trim();
            let val = val.trim();
            // The first key has another `:` after `flags` so handle it specially.
            // Detect "iface : flags : ..." by looking for a second colon in val.
            if let Some((flags_kw, rest)) = val.split_once(':') {
                if flags_kw.trim() == "flags" {
                    flush(&mut info, &mut current);
                    current = Some(ServiceEntry {
                        interface: key.to_string(),
                        family: fam,
                        flags: Some(rest.trim().to_string()),
                        address: None,
                        reach: None,
                    });
                    continue;
                }
            }
            // Continuation attributes.
            if let Some(cur) = current.as_mut() {
                match key {
                    "address" => cur.address = Some(val.to_string()),
                    "reach" => cur.reach = Some(val.to_string()),
                    _ => {}
                }
            }
        }
    }
    flush(&mut info, &mut current);
    info
}
