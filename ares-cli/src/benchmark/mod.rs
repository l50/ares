//! Benchmark replay system for deterministic blue team evaluation.
//!
//! Subcommands:
//! - `capture`: snapshot a completed operation's Loki state + red team data
//! - `load`: import a snapshot into a target Loki instance
//! - `run`: full replay pipeline (ephemeral Loki → import → investigate → score)

mod capture;
mod k8s_loki;
pub(crate) mod manifest;
mod replay;

use anyhow::Result;

use crate::cli::BenchmarkCommands;

pub(crate) async fn run_benchmark(cmd: BenchmarkCommands, redis_url: Option<String>) -> Result<()> {
    match cmd {
        BenchmarkCommands::Capture {
            operation_id,
            latest,
            output_dir,
            s3_bucket,
            pre_window_hours,
            post_window_minutes,
        } => {
            capture::run_capture(
                redis_url,
                operation_id,
                latest,
                &output_dir,
                s3_bucket,
                pre_window_hours,
                post_window_minutes,
            )
            .await
        }
        BenchmarkCommands::Load {
            snapshot_dir,
            loki_url,
            loki_token,
        } => replay::run_load(&snapshot_dir, &loki_url, loki_token.as_deref()).await,
        BenchmarkCommands::Run {
            snapshot_dir,
            loki_mode,
            loki_url,
            trigger_mode,
            output_dir,
            model,
            max_steps,
            namespace,
        } => {
            replay::run_replay(replay::ReplayParams {
                redis_url,
                snapshot_dir,
                loki_mode,
                loki_url,
                trigger_mode,
                output_dir,
                model,
                max_steps,
                namespace,
            })
            .await
        }
    }
}
