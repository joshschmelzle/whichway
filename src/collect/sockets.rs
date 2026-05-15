//! `lsof -i -P -n` parser.
//!
//! Output is a fixed-width-ish table. The COMMAND column can contain spaces
//! (uncommon on macOS but possible) so we split greedily from the right on
//! the well-defined trailing columns.

use crate::model::Socket;

/// Parse standard `lsof -i -P -n` output.
///
/// Header line:
///
/// ```text
/// COMMAND   PID    USER   FD    TYPE  DEVICE SIZE/OFF NODE NAME
/// ```
pub fn parse(input: &str) -> Vec<Socket> {
    let mut out = Vec::new();
    let mut header_seen = false;
    for raw in input.lines() {
        let line = raw.trim_end();
        if line.is_empty() {
            continue;
        }
        if !header_seen {
            if line.trim_start().starts_with("COMMAND") {
                header_seen = true;
            }
            continue;
        }
        let cols: Vec<&str> = line.split_whitespace().collect();
        // 9 columns minimum on macOS, NAME may contain spaces.
        let (command, pid_s, user, fd, kind, protocol, name_rest) = match cols.as_slice() {
            [
                cmd,
                pid,
                usr,
                fd_,
                knd,
                _device,
                _size,
                node,
                name_rest @ ..,
            ] if !name_rest.is_empty() => (*cmd, *pid, *usr, *fd_, *knd, *node, name_rest),
            _ => continue,
        };
        let pid = pid_s.parse().unwrap_or(0);
        let name = name_rest.join(" ");
        let (local, remote, state) = parse_name(&name);
        out.push(Socket {
            command: command.to_string(),
            pid,
            user: user.to_string(),
            fd: fd.to_string(),
            kind: kind.to_string(),
            protocol: protocol.to_string(),
            local,
            remote,
            state,
        });
    }
    out
}

/// NAME column shapes:
///   `127.0.0.1:50000->127.0.0.1:80 (ESTABLISHED)`
///   `*:443 (LISTEN)`
///   `127.0.0.1:50000`
fn parse_name(name: &str) -> (String, String, Option<String>) {
    let (endpoints, state) = match name.rsplit_once(" (") {
        Some((ep, s)) => (ep, Some(s.trim_end_matches(')').to_string())),
        None => (name, None),
    };
    match endpoints.split_once("->") {
        Some((l, r)) => (l.to_string(), r.to_string(), state),
        None => (endpoints.to_string(), String::new(), state),
    }
}
