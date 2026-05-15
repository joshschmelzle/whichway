# whichway

A macOS-only network route inspector for machines running multiple concurrent
VPN, proxy, and monitoring tools (Little Snitch, Proxifier, Zscaler, Atmos
Axis, Tailscale, plus native interfaces).

`whichway` answers: *given everything currently on this machine, where does
traffic to X actually go?* It is a diagnostic tool, not a configuration tool - it never writes routes, never modifies pf, never installs anything.

## Install

```sh
git clone <repo> whichway
cd whichway
cargo build --release
install -m 0755 target/release/whichway /usr/local/bin/whichway
```

Requires Rust stable (edition 2021). macOS only (Tahoe / 26.x and newer
targeted). Other platforms refuse to run with a clear error at startup; no
panic.

## CLI

```sh
whichway                          # full summary: routes, DNS, tunnels, services
whichway <ip-or-hostname>         # focused lookup
whichway routes                   # routing table, enriched with labels
whichway dns                      # DNS resolver layout
whichway tunnels                  # tunnels with attribution
whichway services                 # network services / reachability
whichway sockets                  # lsof view (requires sudo)
whichway throughput               # nettop sample (requires sudo)
whichway pf                       # packet filter rules (requires sudo)
whichway serve [--port N] [--dev] # start web UI
whichway --json                   # machine-readable output for any subcommand
```

A focused lookup (`whichway <target>`) prints something like:

```
Target:    private.corp.example
Resolved:  10.20.30.40 (via resolver #3, domain match: corp.example, ns: 10.0.0.53)
Route:     10.20.30.0/24 → utun4 (Zscaler)
Gateway:   link#42
Verdict:
   Per the IP routing table, traffic to private.corp.example exits via utun4 (Zscaler).
   Application-layer tools may override this. Run `whichway sockets` as
   root to see live per-process connections.
```

The verdict is **IP-layer only**. Application-layer interceptors (Proxifier,
Little Snitch per-app rules, browser proxy config) may override what the
kernel routing table says. `whichway` is explicit about that - never treat
the verdict as authoritative.

Color output respects `NO_COLOR`. Tracing/logs go to stderr; control via
`RUST_LOG=...`.

## Web UI

```sh
whichway serve --port 9999
```

prints to stderr:

```
whichway serving at http://127.0.0.1:9999/?token=<random>
```

The server binds `127.0.0.1` only - never `0.0.0.0`. If the port is taken it
errors out rather than picking another.

Every `/api/*` request requires the random session token, supplied either as
`?token=<t>` or as the `X-Whichway-Token` header. The embedded `index.html`
gets the token injected as a `<meta name="whichway-token">` tag at serve
time; the bundled JS reads it from there.

`--dev` serves assets from `./assets/` instead of the embedded copy for UI
iteration.

The dashboard is htop-ish: monospace tables, sortable headers, per-table
filter inputs, click a column to sort. Auto-refresh defaults to **off**;
choices are 30s and 2min. No 5s option, intentionally. Manual-refresh-only
for the privileged tabs.

## What running as root unlocks

`whichway` runs unprivileged for the core unprivileged collectors (routes,
ifconfig, scutil --dns, scutil --nwi). Running with `sudo` additionally
enables:

* `sockets` - `lsof -i -P -n` per-process socket view.
* `throughput` - `nettop -P -x -l 2 -J bytes_in,bytes_out,interface` one-shot
  sample.
* `pf` - `pfctl -sr` rules and `pfctl -sa` anchors. Little Snitch and some
  enterprise VPN clients install anchors here.

If you don't run as root, those tabs/commands return a `requires root`
section error. They never panic and never lock up the rest of the summary.

## Token model

The session token is generated at startup from the OS RNG (`rand`). The
server requires it on every `/api/*` request. There is no password and no
persistence: restart the server, get a new token. This is enough security
for a 127.0.0.1-only diagnostic tool but is explicitly not authentication.

## JSON schema

`whichway --json` and `GET /api/summary` produce the same shape:

```json
{
  "collected_at": "2026-05-14T12:34:56Z",
  "platform": "macos",
  "privileged": false,
  "routes":   { "data": [...], "error": null },
  "tunnels":  { "data": [...], "error": null },
  "dns":      { "data": [...], "error": null },
  "services": { "data": {...}, "error": null },
  "pf":       { "data": null,  "error": "requires root" }
}
```

Every collector section is `{ "data": T | null, "error": string | null }`.
This is the contract; don't break it.

If a collector fails or times out we keep going. The failed section gets
`data: null` and a human-readable `error`. The CLI prints a warning footer
listing failed sections; the web UI shows an error badge on the affected
table.

## Tunnel attribution is heuristic

Matching `utunN` interfaces to the apps that own them is the most useful and
most fragile thing whichway does. Detector priority:

1. **Tailscale** - match `Self.TailscaleIPs` (from `tailscale status --json`)
   against utun addresses. Never the CGNAT range as a fallback; that
   false-positives.
2. **Zscaler** - install path under `/Applications/Zscaler/` or
   `/Library/Application Support/Zscaler` present *and* a Zscaler process
   running (anchored `pgrep -fl '^/Applications/Zscaler/'`). Then pick a
   utun whose MTU is 1400.
3. **Atmos / Axis** - install path present and the agent process is running.
4. **Generic IPSec/IKEv2** - `scutil --nc list` for named VPN configurations.
5. **Unknown** - labeled `Unknown`, raw interface info kept.

Install path is the **primary signal**; running processes are **confirming
evidence**. Missing tools just mean those rows are absent, never an error.

### Adding a new VPN signature

1. Drop a fixture capture of `ifconfig` + any new probe output in
   `tests/fixtures/`.
2. Add a module under `src/attribute/`, modeled on `zscaler.rs` or
   `atmos.rs`. Use anchored process detection from `attribute::process`
   (never bare-substring `pgrep`).
3. Wire it into `attribute::label_tunnels` with a priority that doesn't
   shadow more-specific detectors.
4. Add a parser test against the fixture if you introduced any new output
   parsing.

## Updating fixtures

`tests/fixtures/` holds captured command outputs. Tests run against those
files and never spawn commands themselves. To regenerate:

```sh
netstat -rn -f inet  > tests/fixtures/netstat_inet.txt
netstat -rn -f inet6 > tests/fixtures/netstat_inet6.txt
ifconfig             > tests/fixtures/ifconfig.txt
scutil --dns         > tests/fixtures/scutil_dns.txt
scutil --nwi         > tests/fixtures/scutil_nwi.txt
scutil --nc list     > tests/fixtures/scutil_nc.txt
route -n get 1.1.1.1 > tests/fixtures/route_get.txt
sudo nettop -P -x -l 2 -J bytes_in,bytes_out,interface > tests/fixtures/nettop.txt
sudo lsof -i -P -n | head -200 > tests/fixtures/lsof.txt
sudo pfctl -sr > tests/fixtures/pfctl_sr.txt
sudo pfctl -sa > tests/fixtures/pfctl_sa.txt
```

Then update the parser tests in `tests/parsers.rs` to reflect the new
expected fields. Keep at least one multi-VPN fixture
(`ifconfig_multivpn.txt`, `netstat_multivpn.txt`) so the multi-VPN test
covers Tailscale + Zscaler-shaped + native `en0` simultaneously.

## Constraints worth knowing

* Every shell-out has a timeout - 3s default, 5s for `nettop`, 8s for
  `lsof`. A timeout becomes a collector error, never a panic.
* The web UI loads no remote resources. No CDN scripts, no Google fonts,
  no analytics.
* Auto-refresh is off by default; only 30s and 2min are exposed.
* `--json` output is the same shape on success and partial-failure; consumers
  shouldn't have to parse two different schemas.

## Out of scope

Packet capture, pcap parsing, writing routes, modifying any configuration,
Linux/Windows support, IPv6-only lookups (IPv6 routes appear in tables but
the lookup card prioritizes IPv4), SMJobBless privileged helper daemon,
persistence of collected data across runs.

## License

BSD-3-Clause. See `LICENSE` for the full text.
