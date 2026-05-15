//! whichway — macOS network route inspector.
//!
//! Top-level entry. Dispatches to one of:
//!   - the full summary (default)
//!   - a focused lookup (positional argument)
//!   - a subcommand (`routes`, `dns`, `tunnels`, `sockets`, `throughput`, `pf`)
//!   - `serve` to start the local web UI.
//!
//! `--json` produces machine-readable output for any of the above.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

mod cli;
mod server;

use whichway::collect;
use whichway::exec::is_root;
use whichway::model::{self, Section, Summary};

#[derive(Parser, Debug)]
#[command(
    name = "whichway",
    version,
    about = "Inspect how macOS routes traffic across multiple VPNs/proxies",
    long_about = None,
)]
struct Cli {
    /// Emit JSON instead of human tables.
    #[arg(long, global = true)]
    json: bool,

    /// Optional positional target for the default focused-lookup mode. Can be
    /// an IP address or a hostname. Ignored when a subcommand is given.
    #[arg(value_name = "TARGET")]
    target: Option<String>,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print only the routing table (with tunnel labels).
    Routes,
    /// Print only the DNS resolver layout.
    Dns,
    /// Print only the tunnel/utun attribution table.
    Tunnels,
    /// Print only the network services / reachability block.
    Services,
    /// Print active sockets via `lsof -i -P -n`. Requires root.
    Sockets,
    /// Print a single nettop throughput sample. Requires root.
    Throughput,
    /// Print packet filter rules and anchors via `pfctl`. Requires root.
    Pf,
    /// Start the local web UI on 127.0.0.1.
    Serve {
        /// TCP port. The server refuses to fall back to another port.
        #[arg(long, default_value_t = 9999)]
        port: u16,
        /// Serve assets from disk (./assets) instead of the embedded copy.
        #[arg(long)]
        dev: bool,
        /// Do not open the default browser automatically.
        #[arg(long)]
        no_browser: bool,
    },
}

fn main() -> Result<()> {
    init_tracing();
    if !cfg!(target_os = "macos") {
        eprintln!("whichway is macOS-only. Other platforms are out of scope.");
        std::process::exit(2);
    }

    let cli = Cli::parse();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;
    rt.block_on(run(cli))
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_env("RUST_LOG").unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

async fn run(cli: Cli) -> Result<()> {
    let privileged = is_root();

    match cli.cmd {
        Some(Cmd::Serve {
            port,
            dev,
            no_browser,
        }) => {
            let dev_dir = if dev {
                Some(PathBuf::from("assets"))
            } else {
                None
            };
            server::serve(port, dev_dir, !no_browser).await
        }
        Some(Cmd::Routes) => {
            let s = collect::collect_summary(privileged).await;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&s.routes)?);
            } else {
                cli::print_routes(&s.routes);
            }
            Ok(())
        }
        Some(Cmd::Dns) => {
            let s = collect::collect_summary(privileged).await;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&s.dns)?);
            } else {
                cli::print_dns(&s.dns);
            }
            Ok(())
        }
        Some(Cmd::Tunnels) => {
            let s = collect::collect_summary(privileged).await;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&s.tunnels)?);
            } else {
                cli::print_tunnels(&s.tunnels);
            }
            Ok(())
        }
        Some(Cmd::Services) => {
            let s = collect::collect_summary(privileged).await;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&s.services)?);
            } else {
                cli::print_services(&s.services);
            }
            Ok(())
        }
        Some(Cmd::Sockets) => {
            privileged_subcommand(
                cli.json,
                privileged,
                "sockets",
                async {
                    collect::collect_sockets()
                        .await
                        .map_or_else(|e| Section::err(e.to_string()), Section::ok)
                },
                cli::print_sockets,
            )
            .await
        }
        Some(Cmd::Throughput) => {
            privileged_subcommand(
                cli.json,
                privileged,
                "throughput",
                async {
                    collect::collect_throughput()
                        .await
                        .map_or_else(|e| Section::err(e.to_string()), Section::ok)
                },
                cli::print_throughput,
            )
            .await
        }
        Some(Cmd::Pf) => run_pf(cli.json, privileged).await,
        None => match cli.target {
            Some(target) => focused_lookup(&target, cli.json, privileged).await,
            None => default_summary(cli.json, privileged).await,
        },
    }
}

async fn run_pf(json: bool, privileged: bool) -> Result<()> {
    if !privileged {
        privileged_warn("pf");
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&Section::<model::PfRules>::requires_root())?
            );
        }
        return Ok(());
    }
    let section = collect::collect_pf().await;
    if json {
        println!("{}", serde_json::to_string_pretty(&section)?);
    } else {
        cli::print_pf(&section);
    }
    Ok(())
}

async fn default_summary(json: bool, privileged: bool) -> Result<()> {
    let summary: Summary = collect::collect_summary(privileged).await;
    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        cli::print_summary(&summary);
    }
    Ok(())
}

async fn focused_lookup(target: &str, json: bool, privileged: bool) -> Result<()> {
    let summary = collect::collect_summary(privileged).await;
    let resolvers = summary.dns.data.clone().unwrap_or_default();
    let tunnels = summary.tunnels.data.clone().unwrap_or_default();
    let result = collect::lookup::lookup(target, &resolvers, &tunnels).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        cli::print_lookup(&result);
    }
    Ok(())
}

async fn privileged_subcommand<T, F, R>(
    json: bool,
    privileged: bool,
    name: &str,
    fut: F,
    render: R,
) -> Result<()>
where
    T: serde::Serialize,
    F: std::future::Future<Output = Section<T>>,
    R: Fn(&Section<T>),
{
    if !privileged {
        privileged_warn(name);
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&Section::<T>::requires_root())?
            );
        }
        return Ok(());
    }
    let section = fut.await;
    if json {
        println!("{}", serde_json::to_string_pretty(&section)?);
    } else {
        render(&section);
    }
    Ok(())
}

fn privileged_warn(name: &str) {
    use owo_colors::{OwoColorize, Stream};
    eprintln!(
        "{} {} requires root; run with sudo to enable.",
        "note:".if_supports_color(Stream::Stderr, |s| s.dimmed()),
        name
    );
}
