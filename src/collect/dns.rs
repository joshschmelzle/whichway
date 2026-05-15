//! `scutil --dns` parser.
//!
//! Output is grouped into one or more sections ("DNS configuration", "DNS
//! configuration (for scoped queries)", and occasionally "DNS configuration
//! (for service-specific queries)") each containing numbered resolver blocks.

use crate::model::{Resolver, ResolverScope};

pub fn parse(input: &str) -> Vec<Resolver> {
    let mut out = Vec::new();
    let mut scope = ResolverScope::Default;
    let mut current: Option<Resolver> = None;

    let flush = |out: &mut Vec<Resolver>, cur: &mut Option<Resolver>| {
        if let Some(r) = cur.take() {
            out.push(r);
        }
    };

    for raw in input.lines() {
        let line = raw.trim_end();
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("DNS configuration") {
            flush(&mut out, &mut current);
            scope = if rest.contains("scoped") || rest.contains("service-specific") {
                ResolverScope::Scoped
            } else {
                ResolverScope::Default
            };
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("resolver #") {
            flush(&mut out, &mut current);
            let number = rest.trim().parse().unwrap_or(0);
            current = Some(Resolver {
                number,
                scope,
                nameservers: Vec::new(),
                search: Vec::new(),
                domain: None,
                if_index: None,
                interface: None,
                flags: None,
                order: None,
                options: None,
            });
            continue;
        }
        let Some(r) = current.as_mut() else { continue };
        // Indented `key : value` lines (key may include `[N]`).
        let Some((key, val)) = trimmed.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let val = val.trim();
        if key.starts_with("nameserver[") {
            r.nameservers.push(val.to_string());
        } else if key.starts_with("search domain[") {
            r.search.push(val.to_string());
        } else if key == "domain" {
            r.domain = Some(val.to_string());
        } else if key == "if_index" {
            // "13 (en7)"
            let mut parts = val.split_whitespace();
            if let Some(idx_str) = parts.next() {
                r.if_index = idx_str.parse().ok();
            }
            if let Some(iface) = parts.next() {
                r.interface = Some(iface.trim_matches(|c| c == '(' || c == ')').to_string());
            }
        } else if key == "flags" {
            r.flags = Some(val.to_string());
        } else if key == "order" {
            r.order = val.parse().ok();
        } else if key == "options" {
            r.options = Some(val.to_string());
        }
    }
    if let Some(r) = current.take() {
        out.push(r);
    }
    out
}
