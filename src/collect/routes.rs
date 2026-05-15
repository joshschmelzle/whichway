//! `netstat -rn -f inet[6]` parser.
//!
//! The output is whitespace-aligned with a variable number of columns
//! depending on whether the `Expire` column is populated. We tolerate that by
//! splitting on whitespace and taking the first four/five columns positionally.

use crate::model::{IpFamily, Route};

/// Parse the output of `netstat -rn -f inetX`.
///
/// Format reminder (macOS):
///
/// ```text
/// Routing tables
///
/// Internet:
/// Destination        Gateway            Flags               Netif Expire
/// default            192.168.6.1        UGScg                 en7
/// 10/8               link#25            UCS                 utun6
/// ```
pub fn parse(input: &str, family: IpFamily) -> Vec<Route> {
    let mut out = Vec::new();
    let mut in_table = false;
    let mut saw_header = false;
    let want = match family {
        IpFamily::V4 => "Internet:",
        IpFamily::V6 => "Internet6:",
    };
    for raw in input.lines() {
        let line = raw.trim_end();
        if !in_table {
            if line.trim() == want {
                in_table = true;
            }
            continue;
        }
        if !saw_header {
            if line.trim_start().starts_with("Destination") {
                saw_header = true;
            }
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            // Blank line ends the table; future blank lines just mean EOF.
            break;
        }
        // If we ever stumble back into a section header line, stop.
        if trimmed.ends_with(':') && !trimmed.contains(' ') {
            break;
        }
        let cols: Vec<&str> = line.split_whitespace().collect();
        let (destination, gateway, flags, interface, rest) = match cols.as_slice() {
            [d, g, f, i, rest @ ..] => (*d, *g, *f, *i, rest),
            _ => continue,
        };
        let expire = if rest.is_empty() {
            None
        } else {
            Some(rest.join(" "))
        };
        out.push(Route {
            family,
            destination: destination.to_string(),
            gateway: gateway.to_string(),
            flags: flags.to_string(),
            interface: interface.to_string(),
            expire,
            label: None,
        });
    }
    out
}
