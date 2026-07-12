//! S3 snapshot metadata helpers for the benchmark path.
//!
//! Only the snapshot-metadata reads live here: `list_snapshots` (used by
//! `benchmark list`) and `download_snapshot_metadata` (used by `benchmark run`
//! to pull manifest/red-state/ground-truth/fired-alerts before the
//! investigation submits). Everything provisioning-related (EC2 launch, SSM
//! setup, teardown, AMI lookup, stack config staging) lives in the
//! `.taskfiles/benchmark/Taskfile.yaml` — that's shell orchestration of the
//! AWS CLI, not multi-agent runtime logic.

use std::process::Command;

use anyhow::{bail, Context, Result};
use tracing::{info, warn};

/// Default S3 bucket for benchmark snapshots in the labs account.
pub(crate) const DEFAULT_S3_BUCKET: &str = "ares-benchmark-us-west-1";
/// Default AWS region for the labs account.
pub(crate) const DEFAULT_AWS_REGION: &str = "us-west-1";
/// Default AWS CLI profile. Empty means use the default credential chain
/// (e.g. instance role on EC2). Set `BENCHMARK_AWS_PROFILE=lab` on laptops.
pub(crate) const DEFAULT_AWS_PROFILE: &str = "";

/// Where the snapshot-read helpers look — a slim replacement for the old
/// `ReplayConfig` that only tracks S3 access, since provisioning left the Rust
/// side.
pub(crate) struct SnapshotConfig {
    pub s3_bucket: String,
    pub aws_profile: String,
    pub aws_region: String,
}

impl SnapshotConfig {
    pub fn from_env() -> Self {
        Self {
            s3_bucket: std::env::var("BENCHMARK_S3_BUCKET")
                .unwrap_or_else(|_| DEFAULT_S3_BUCKET.to_string()),
            aws_profile: std::env::var("BENCHMARK_AWS_PROFILE")
                .unwrap_or_else(|_| DEFAULT_AWS_PROFILE.to_string()),
            aws_region: std::env::var("BENCHMARK_AWS_REGION")
                .unwrap_or_else(|_| DEFAULT_AWS_REGION.to_string()),
        }
    }
}

/// Append `--profile <p> --region <r>` to a command.
/// Skips `--profile` when profile is empty (uses default credential chain / instance role).
fn append_aws_opts<'a>(cmd: &'a mut Command, profile: &str, region: &str) -> &'a mut Command {
    if !profile.is_empty() {
        cmd.args(["--profile", profile]);
    }
    cmd.args(["--region", region])
}

/// List available snapshots from S3.
///
/// Enumerates `snapshots/<op-id>/manifest.json` objects and returns them
/// sorted by `captured_at` descending.
pub(crate) fn list_snapshots(
    profile: &str,
    region: &str,
    bucket: &str,
) -> Result<Vec<(String, super::manifest::SnapshotManifest)>> {
    let mut cmd = Command::new("aws");
    cmd.args([
        "s3api",
        "list-objects-v2",
        "--bucket",
        bucket,
        "--prefix",
        "snapshots/",
        "--delimiter",
        "/",
        "--query",
        "CommonPrefixes[].Prefix",
        "--output",
        "json",
    ]);
    append_aws_opts(&mut cmd, profile, region);
    let output = cmd.output().context("list S3 snapshot prefixes")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("s3api list-objects-v2 failed: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let prefixes: Vec<String> = match serde_json::from_str(stdout.trim()) {
        Ok(p) => p,
        Err(_) => return Ok(Vec::new()),
    };

    let mut snapshots = Vec::new();
    for prefix in &prefixes {
        let op_id = prefix
            .trim_start_matches("snapshots/")
            .trim_end_matches('/');
        if op_id.is_empty() {
            continue;
        }

        let s3_src = format!("s3://{bucket}/{prefix}manifest.json");
        let mut manifest_cmd = Command::new("aws");
        manifest_cmd.args(["s3", "cp", &s3_src, "-"]);
        append_aws_opts(&mut manifest_cmd, profile, region);
        match manifest_cmd.output() {
            Ok(out) if out.status.success() => {
                let raw = String::from_utf8_lossy(&out.stdout);
                match serde_json::from_str::<super::manifest::SnapshotManifest>(&raw) {
                    Ok(manifest) => snapshots.push((op_id.to_string(), manifest)),
                    Err(e) => warn!("failed to parse manifest for {op_id}: {e}"),
                }
            }
            _ => warn!("failed to download manifest for {op_id}"),
        }
    }

    snapshots.sort_by_key(|b| std::cmp::Reverse(b.1.captured_at));
    Ok(snapshots)
}

/// Download snapshot metadata files (manifest, red-state, ground-truth,
/// fired-alerts) from S3 to a local directory. Does NOT download loki/ data
/// (that lives on the replay stack box, staged by the Taskfile).
pub(crate) fn download_snapshot_metadata(
    op_id: &str,
    profile: &str,
    region: &str,
    bucket: &str,
    local_dir: &std::path::Path,
) -> Result<()> {
    std::fs::create_dir_all(local_dir)
        .with_context(|| format!("create local dir: {}", local_dir.display()))?;

    let files = [
        "manifest.json",
        "red-state.json",
        "ground-truth.json",
        "fired-alerts.json",
    ];
    for file in &files {
        let s3_path = format!("s3://{bucket}/snapshots/{op_id}/{file}");
        let local_path = local_dir.join(file);
        info!("downloading {file} from S3...");
        let local_str = local_path.to_str().unwrap_or(".");
        let mut cmd = Command::new("aws");
        cmd.args(["s3", "cp", &s3_path, local_str]);
        append_aws_opts(&mut cmd, profile, region);
        let status = cmd.status().with_context(|| format!("download {file}"))?;
        if !status.success() {
            bail!("failed to download {s3_path}");
        }
    }
    Ok(())
}
