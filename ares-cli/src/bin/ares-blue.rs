// The blue binary compiles the same source tree as `ares` but only
// invokes a subset of the modules. Every unused module, function, and
// method surfaces as a "never used" warning here — 1000+ of them. The
// `dead_code` allow is intentional: the code IS used, just from the
// other binary, and the redundant warnings drown out anything real
// this binary might produce.
#![allow(dead_code)]

//! ares-blue — the blue-team-only entrypoint into the Ares codebase.
//!
//! Same source tree as the main `ares` binary, but this entrypoint
//! exposes only the subcommands relevant to blue-team operation
//! (`blue`, `benchmark`, `worker` in `blue_task` mode). Red-team
//! subcommands are hidden so a blue-only deployment doesn't ship the
//! surface area for launching red ops.
//!
//! Why a separate binary and not a runtime flag on `ares`? Two reasons:
//!   1. Systemd units for blue workers can point at `ares-blue worker`
//!      unambiguously — no accidental cross-mode activation if the unit
//!      file drifts from the env file.
//!   2. Packaging: a blue-only image (the replay/scoring stack) can
//!      install just this binary without dragging in the red command
//!      surface, which is what an operator running the blue analysis
//!      loop actually wants.
//!
//! Source modules are shared via `#[path]` mounts of the same files
//! `main.rs` uses. Cargo recompiles them into this crate independently
//! from the main `ares` binary — there is no runtime cross-linking, and
//! the module tree here is the ares-blue crate root, so `crate::*` in
//! blue-code paths resolves within this binary.

// The `#[path]` directives mount the same source files the primary
// `ares` binary uses. Both binaries independently compile these
// modules; there is no dependency between the two binaries.
#[path = "../benchmark/mod.rs"]
mod benchmark;
#[path = "../blue/mod.rs"]
mod blue;
#[path = "../cli/mod.rs"]
mod cli;
#[path = "../config.rs"]
mod config;
#[path = "../dedup/mod.rs"]
mod dedup;
#[path = "../detection/mod.rs"]
mod detection;
#[path = "../history/mod.rs"]
mod history;
#[path = "../ops/mod.rs"]
mod ops;
#[path = "../orchestrator/mod.rs"]
mod orchestrator;
#[path = "../redis_conn.rs"]
mod redis_conn;
#[path = "../secrets.rs"]
mod secrets;
#[path = "../transport.rs"]
mod transport;
#[path = "../util.rs"]
mod util;
#[path = "../worker/mod.rs"]
mod worker;

use std::process;

use anyhow::Result;
use clap::Parser;
use tracing::{error, info};

use cli::{Cli, Commands};

#[tokio::main]
async fn main() {
    if let Some(code) = transport::maybe_exec_k8s() {
        process::exit(code);
    }
    if let Some(code) = transport::maybe_exec_ec2() {
        process::exit(code);
    }

    let (env_file, secrets_from) = secrets::prescan_secrets_args();

    if let Some(ref path) = env_file {
        match secrets::load_env_file(path) {
            Ok(n) => eprintln!("Loaded {n} variable(s) from {path}"),
            Err(e) => {
                eprintln!("Error: {e:#}");
                process::exit(1);
            }
        }
    } else if secrets_from.is_none() {
        secrets::try_load_default_env();
    }

    // Telemetry service name is "ares-blue-cli" so blue-only nodes are
    // trivially filterable in dashboards.
    let is_service_subcommand = std::env::args().nth(1).is_some_and(|a| a == "worker");
    let _telemetry = if !is_service_subcommand {
        Some(ares_core::telemetry::init_telemetry(
            ares_core::telemetry::TelemetryConfig::new("ares-blue-cli")
                .with_default_filter("warn,ares_cli=info"),
        ))
    } else {
        None
    };

    if let Some(ref source) = secrets_from {
        match source.as_str() {
            "1password" | "1pass" | "op" => match secrets::load_1password_secrets() {
                Ok(n) => info!("Loaded {n} secret(s) from 1Password"),
                Err(e) => {
                    error!("Error loading 1Password secrets: {e:#}");
                    process::exit(1);
                }
            },
            other => {
                error!("Unknown secrets source: {other} (supported: 1password)");
                process::exit(1);
            }
        }
    }

    let mut cli = Cli::parse();

    if cli.redis_url.is_none() {
        cli.redis_url = std::env::var("REDIS_URL").ok();
    }

    if let Err(e) = run(cli).await {
        error!("{e:#}");
        process::exit(1);
    }
}

/// Blue-only subcommand dispatcher.
///
/// `Blue` and `Benchmark` are the primary blue-team surfaces. `Worker`
/// is allowed because blue task workers run under this binary's systemd
/// unit — the caller is expected to set `ARES_WORKER_MODE=blue_task`.
/// Every other subcommand is a red-team primitive and this binary
/// intentionally refuses it so a mis-invocation (wrong binary in a unit
/// file, operator muscle memory) surfaces as an obvious error rather
/// than silently kicking off a red run through the blue node.
async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Blue(cmd) => blue::run_blue(cmd, cli.redis_url).await,
        Commands::Benchmark(cmd) => benchmark::run_benchmark(cmd, cli.redis_url).await,
        Commands::Worker { .. } => {
            // Telemetry is intentionally not initialised for `worker`
            // subcommands (the worker inits its own with the proper
            // service name), so `tracing::error!` here would silently
            // drop the message. Print to stderr directly instead.
            let mode = std::env::var("ARES_WORKER_MODE").unwrap_or_default();
            if mode != "blue_task" {
                eprintln!(
                    "ares-blue worker requires ARES_WORKER_MODE=blue_task (got {mode:?}). \
                     Use the main `ares` binary for red-team worker modes."
                );
                process::exit(2);
            }
            worker::run().await
        }
        Commands::Ops(_) | Commands::History(_) | Commands::Config(_) | Commands::Orchestrator => {
            anyhow::bail!(
                "ares-blue only exposes the blue-team subcommand surface \
                 (`blue`, `benchmark`, `worker` in blue_task mode). \
                 Use the main `ares` binary for red-team subcommands."
            )
        }
    }
}
