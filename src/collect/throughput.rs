//! `nettop -P -x -l 2 -J bytes_in,bytes_out,interface` parser.
//!
//! Output looks like:
//!
//! ```text
//!                  interface        bytes_in       bytes_out
//! launchd.1                                  0               0
//! mDNSResponder.461                    1498396          248922
//! ```
//!
//! Columns are positional. Bytes are the last two whitespace-separated tokens
//! on each row; interface (when present) is the token before that. The process
//! identifier `name.pid` is everything else on the left. macOS truncates long
//! names so we just take it verbatim.

use crate::model::ThroughputRow;

pub fn parse(input: &str) -> Vec<ThroughputRow> {
    let mut out = Vec::new();
    let mut header_seen = false;
    for raw in input.lines() {
        let line = raw.trim_end();
        if line.trim().is_empty() {
            continue;
        }
        if !header_seen {
            if line.contains("bytes_in") && line.contains("bytes_out") {
                header_seen = true;
            }
            continue;
        }
        // nettop emits an ANSI screen clear between samples; skip header reps.
        if line.contains("bytes_in") && line.contains("bytes_out") {
            continue;
        }
        let cols: Vec<&str> = line.split_whitespace().collect();
        // The last two cols are byte counts. Need at least 3 columns (process + 2 byte cols).
        let (Some(bytes_out_s), Some(bytes_in_s)) = (cols.last(), cols.iter().rev().nth(1)) else {
            continue;
        };
        if cols.len() < 3 {
            continue;
        }
        let Ok(bytes_out) = bytes_out_s.parse::<u64>() else {
            continue;
        };
        let Ok(bytes_in) = bytes_in_s.parse::<u64>() else {
            continue;
        };
        // Interface column may be empty; the token before bytes_in could be
        // part of the process name. Heuristic: if it looks like an interface
        // name (en\d, utun\d, lo0, bridge\d, awdl\d) treat it as the
        // interface; otherwise leave interface blank.
        let third_from_end = cols.iter().rev().nth(2).copied().unwrap_or("");
        let (process, interface) = if looks_like_iface(third_from_end) && cols.len() >= 4 {
            let head_len = cols.len().saturating_sub(3);
            (
                cols.iter()
                    .take(head_len)
                    .copied()
                    .collect::<Vec<_>>()
                    .join(" "),
                third_from_end.to_string(),
            )
        } else {
            let head_len = cols.len().saturating_sub(2);
            (
                cols.iter()
                    .take(head_len)
                    .copied()
                    .collect::<Vec<_>>()
                    .join(" "),
                String::new(),
            )
        };
        out.push(ThroughputRow {
            process,
            interface,
            bytes_in,
            bytes_out,
        });
    }
    out
}

fn looks_like_iface(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let has_digit_suffix = s.chars().last().is_some_and(|c| c.is_ascii_digit());
    let prefixes = [
        "en", "utun", "lo", "bridge", "awdl", "llw", "ap", "gif", "stf", "anpi",
    ];
    has_digit_suffix && prefixes.iter().any(|p| s.starts_with(p))
}
