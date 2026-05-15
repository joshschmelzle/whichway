//! `pfctl -sr` (rules) and `pfctl -sa` (all info including anchors).
//!
//! `pfctl` requires root in practice; both commands print to stderr if not.
//! We treat them as black-box text and emit one entry per non-empty line.

use crate::model::PfRules;

pub fn parse(rules_input: &str, all_input: &str) -> PfRules {
    let rules = rules_input
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with("No ALTQ"))
        .collect();

    // From `pfctl -sa`, pull the anchors section. It's introduced by
    // "ANCHORS:" on its own line, followed by anchor paths.
    let mut anchors = Vec::new();
    let mut in_anchors = false;
    for raw in all_input.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line.ends_with(':') {
            in_anchors = line.eq_ignore_ascii_case("ANCHORS:");
            continue;
        }
        if in_anchors {
            anchors.push(line.to_string());
        }
    }

    PfRules { rules, anchors }
}
