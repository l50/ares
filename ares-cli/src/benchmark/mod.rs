//! Benchmark replay system for deterministic blue team evaluation.
//!
//! Subcommands:
//! - `capture`: snapshot a completed operation's Loki state + red team data
//! - `load`: import a snapshot into a target Loki instance
//! - `run`: full replay pipeline (EC2 Loki → investigate → score → teardown)
//! - `list`: list available snapshots from the benchmark S3 bucket

mod capture;
pub(crate) mod manifest;
mod replay;
pub(crate) mod replay_infra;

use anyhow::Result;

use crate::cli::BenchmarkCommands;

pub(crate) async fn run_benchmark(cmd: BenchmarkCommands, redis_url: Option<String>) -> Result<()> {
    match cmd {
        BenchmarkCommands::Capture {
            operation_id,
            latest,
            output_dir,
            pre_window_hours,
            post_window_minutes,
            no_upload,
        } => {
            capture::run_capture(
                redis_url,
                operation_id,
                latest,
                &output_dir,
                pre_window_hours,
                post_window_minutes,
                no_upload,
            )
            .await
        }
        BenchmarkCommands::Load {
            snapshot_dir,
            loki_url,
            loki_token,
        } => replay::run_load(&snapshot_dir, &loki_url, loki_token.as_deref()).await,
        BenchmarkCommands::Run {
            snapshot,
            snapshot_dir,
            replay_mode,
            trigger_mode,
            output_dir,
            model,
            max_steps,
            quiet_period,
            time_compression,
        } => {
            replay::run_replay(replay::ReplayParams {
                redis_url,
                snapshot,
                snapshot_dir,
                replay_mode,
                trigger_mode,
                output_dir,
                model,
                max_steps,
                quiet_period,
                time_compression,
            })
            .await
        }
        BenchmarkCommands::List => run_list(),
    }
}

/// List available benchmark snapshots from S3.
fn run_list() -> Result<()> {
    let bucket = std::env::var("BENCHMARK_S3_BUCKET")
        .unwrap_or_else(|_| "ares-benchmark-us-west-1".to_string());
    let profile = std::env::var("BENCHMARK_AWS_PROFILE").unwrap_or_else(|_| "lab".to_string());
    let region = std::env::var("BENCHMARK_AWS_REGION").unwrap_or_else(|_| "us-west-1".to_string());

    let snapshots = replay_infra::list_snapshots(&profile, &region, &bucket)?;

    if snapshots.is_empty() {
        println!("No snapshots found in s3://{bucket}/snapshots/");
        return Ok(());
    }

    println!(
        "{:<25} {:<20} {:<12} {:<6} {:<5} {:<6}",
        "SNAPSHOT", "TARGET", "DATE", "TECHS", "DA", "CREDS"
    );
    println!("{}", "-".repeat(78));

    for (op_id, m) in &snapshots {
        let date = m.captured_at.format("%Y-%m-%d").to_string();
        let da = if m.has_domain_admin { "yes" } else { "no" };
        println!(
            "{:<25} {:<20} {:<12} {:<6} {:<5} {:<6}",
            op_id,
            truncate(&m.target_domain, 18),
            date,
            m.techniques.len(),
            da,
            m.credential_count,
        );
    }

    println!("\n{} snapshot(s) available", snapshots.len());
    Ok(())
}

/// Truncate a string with ellipsis if longer than max.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}
