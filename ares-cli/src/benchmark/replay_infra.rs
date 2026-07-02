//! EC2-based replay infrastructure for benchmark Loki instances.
//!
//! Provisions an ephemeral EC2 instance in the labs account, installs Loki,
//! downloads snapshot data from S3, and starts Loki serving on port 3100.
//! After the benchmark completes, the instance is terminated.
//!
//! This replaces the previous K8s-based approach (`k8s_loki.rs`) to avoid
//! cross-account complexity and GHCR pull secret issues.

use std::process::Command;

use anyhow::{bail, Context, Result};
use base64::Engine;
use tracing::{info, warn};

/// Default S3 bucket for benchmark snapshots in the labs account.
const DEFAULT_S3_BUCKET: &str = "ares-benchmark-us-west-1";
/// Default AWS region for the labs account.
const DEFAULT_AWS_REGION: &str = "us-west-1";
/// Default AWS CLI profile. Empty means use the default credential chain
/// (e.g. instance role on EC2). Set `BENCHMARK_AWS_PROFILE=lab` on laptops.
const DEFAULT_AWS_PROFILE: &str = "";
/// Default EC2 instance type.
const DEFAULT_INSTANCE_TYPE: &str = "t3.medium";
/// Loki version to install on replay instances.
const LOKI_VERSION: &str = "3.4.2";

/// Configuration for replay infrastructure, resolved from env vars.
pub(crate) struct ReplayConfig {
    pub s3_bucket: String,
    pub subnet_id: String,
    pub security_group_id: String,
    pub instance_profile: String,
    pub instance_type: String,
    pub aws_profile: String,
    pub aws_region: String,
}

impl ReplayConfig {
    /// Resolve config from environment variables.
    ///
    /// Required env vars: `BENCHMARK_SECURITY_GROUP_ID`, `BENCHMARK_INSTANCE_PROFILE`.
    /// Optional: `BENCHMARK_S3_BUCKET`, `BENCHMARK_SUBNET_ID`, `BENCHMARK_INSTANCE_TYPE`,
    /// `BENCHMARK_AWS_PROFILE`, `BENCHMARK_AWS_REGION`.
    pub fn from_env() -> Result<Self> {
        let security_group_id = std::env::var("BENCHMARK_SECURITY_GROUP_ID")
            .context("BENCHMARK_SECURITY_GROUP_ID is required")?;
        let instance_profile = std::env::var("BENCHMARK_INSTANCE_PROFILE")
            .context("BENCHMARK_INSTANCE_PROFILE is required")?;

        let subnet_id = match std::env::var("BENCHMARK_SUBNET_ID") {
            Ok(id) => id,
            Err(_) => detect_subnet()?,
        };

        Ok(Self {
            s3_bucket: std::env::var("BENCHMARK_S3_BUCKET")
                .unwrap_or_else(|_| DEFAULT_S3_BUCKET.to_string()),
            subnet_id,
            security_group_id,
            instance_profile,
            instance_type: std::env::var("BENCHMARK_INSTANCE_TYPE")
                .unwrap_or_else(|_| DEFAULT_INSTANCE_TYPE.to_string()),
            aws_profile: std::env::var("BENCHMARK_AWS_PROFILE")
                .unwrap_or_else(|_| DEFAULT_AWS_PROFILE.to_string()),
            aws_region: std::env::var("BENCHMARK_AWS_REGION")
                .unwrap_or_else(|_| DEFAULT_AWS_REGION.to_string()),
        })
    }
}

/// An ephemeral EC2 instance running Loki for benchmark replay.
///
/// Manages the full lifecycle: provision → configure (SSM) → health check → teardown.
/// Implements `Drop` for best-effort cleanup.
pub(crate) struct ReplayInfra {
    pub instance_id: String,
    pub private_ip: String,
    aws_profile: String,
    aws_region: String,
}

impl ReplayInfra {
    /// Provision a new replay EC2 instance and configure Loki.
    ///
    /// 1. Resolves the latest AL2023 AMI via SSM parameter
    /// 2. Launches an EC2 instance with the given config
    /// 3. Waits for the instance to pass status checks
    /// 4. Runs setup via SSM (install Loki, download data, start)
    /// 5. Polls Loki readiness from the caller's perspective
    pub fn provision(op_id: &str, config: &ReplayConfig) -> Result<Self> {
        // ── Resolve AMI ─────────────────────────────────────────────────
        let ami_id = resolve_ami(&config.aws_profile, &config.aws_region)?;
        info!("resolved AMI: {ami_id}");

        // ── Launch instance ─────────────────────────────────────────────
        let instance_name = format!("ares-replay-{op_id}");
        let tag_spec = format!(
            "ResourceType=instance,Tags=[\
             {{Key=Name,Value={instance_name}}},\
             {{Key=ares:component,Value=benchmark-replay}},\
             {{Key=ares:operation,Value={op_id}}}\
             ]"
        );

        info!("launching EC2 instance: {instance_name} ({}, {})",
            config.instance_type, config.aws_region);

        let iam_profile_arg = format!("Name={}", config.instance_profile);
        let mut cmd = Command::new("aws");
        cmd.args([
            "ec2", "run-instances",
            "--image-id", &ami_id,
            "--instance-type", &config.instance_type,
            "--subnet-id", &config.subnet_id,
            "--security-group-ids", &config.security_group_id,
            "--iam-instance-profile", &iam_profile_arg,
            "--tag-specifications", &tag_spec,
            "--count", "1",
            "--query", "Instances[0].InstanceId",
            "--output", "text",
        ]);
        append_aws_opts(&mut cmd, &config.aws_profile, &config.aws_region);
        let output = cmd.output().context("aws ec2 run-instances")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("ec2 run-instances failed: {stderr}");
        }

        let instance_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if instance_id.is_empty() {
            bail!("ec2 run-instances returned empty instance ID");
        }
        info!("launched instance: {instance_id}");

        let mut infra = Self {
            instance_id: instance_id.clone(),
            private_ip: String::new(),
            aws_profile: config.aws_profile.clone(),
            aws_region: config.aws_region.clone(),
        };

        // ── Wait for running + status checks ────────────────────────────
        info!("waiting for instance to pass status checks...");
        let mut wait_cmd = Command::new("aws");
        wait_cmd.args([
            "ec2", "wait", "instance-status-ok",
            "--instance-ids", &instance_id,
        ]);
        append_aws_opts(&mut wait_cmd, &config.aws_profile, &config.aws_region);
        let wait_result = wait_cmd.status().context("aws ec2 wait instance-status-ok")?;

        if !wait_result.success() {
            let _ = infra.teardown();
            bail!("instance {instance_id} failed status checks");
        }

        // ── Get private IP ──────────────────────────────────────────────
        let mut ip_cmd = Command::new("aws");
        ip_cmd.args([
            "ec2", "describe-instances",
            "--instance-ids", &instance_id,
            "--query", "Reservations[0].Instances[0].PrivateIpAddress",
            "--output", "text",
        ]);
        append_aws_opts(&mut ip_cmd, &config.aws_profile, &config.aws_region);
        let ip_output = ip_cmd.output().context("describe-instances for private IP")?;

        if !ip_output.status.success() {
            let _ = infra.teardown();
            let stderr = String::from_utf8_lossy(&ip_output.stderr);
            bail!("describe-instances failed: {stderr}");
        }

        infra.private_ip = String::from_utf8_lossy(&ip_output.stdout).trim().to_string();
        if infra.private_ip.is_empty() || infra.private_ip == "None" {
            let _ = infra.teardown();
            bail!("instance {instance_id} has no private IP");
        }
        info!("instance private IP: {}", infra.private_ip);

        // ── Configure via SSM ───────────────────────────────────────────
        let setup_script = build_setup_script(op_id, &config.s3_bucket, &config.aws_region);
        info!("configuring Loki via SSM...");

        // Base64-encode the entire script to avoid SSM parameter escaping issues.
        // SSM's JSON parameter parsing mangles $, quotes, heredocs, etc. when passed
        // as individual command lines. A single base64-decode-and-execute is bulletproof.
        let b64_script = base64::engine::general_purpose::STANDARD.encode(&setup_script);
        let decode_cmd = format!("echo {} | base64 -d | bash", b64_script);
        let params_arg = format!("commands=[\"{decode_cmd}\"]");
        let mut ssm_cmd = Command::new("aws");
        ssm_cmd.args([
            "ssm", "send-command",
            "--instance-ids", &instance_id,
            "--document-name", "AWS-RunShellScript",
            "--parameters", &params_arg,
            "--timeout-seconds", "900",
            "--query", "Command.CommandId",
            "--output", "text",
        ]);
        append_aws_opts(&mut ssm_cmd, &config.aws_profile, &config.aws_region);
        let ssm_output = ssm_cmd.output().context("ssm send-command")?;

        if !ssm_output.status.success() {
            let stderr = String::from_utf8_lossy(&ssm_output.stderr);
            let _ = infra.teardown();
            bail!("ssm send-command failed: {stderr}");
        }

        let command_id = String::from_utf8_lossy(&ssm_output.stdout).trim().to_string();
        info!("SSM command: {command_id}");

        // ── Wait for SSM command to complete ────────────────────────────
        wait_for_ssm_command(
            &command_id,
            &instance_id,
            &config.aws_profile,
            &config.aws_region,
        )?;

        // ── Verify Loki is queryable ────────────────────────────────────
        info!("verifying Loki readiness on {}:3100...", infra.private_ip);
        verify_loki_ready(&infra.private_ip)?;

        info!("replay infrastructure ready: {} ({})", instance_id, infra.private_ip);
        Ok(infra)
    }

    /// Return the Loki URL for this replay instance.
    pub fn loki_url(&self) -> String {
        format!("http://{}:3100", self.private_ip)
    }

    /// Terminate the replay EC2 instance.
    pub fn teardown(&mut self) -> Result<()> {
        if self.instance_id.is_empty() {
            return Ok(());
        }

        info!("terminating replay instance {}", self.instance_id);

        let mut cmd = Command::new("aws");
        cmd.args([
            "ec2", "terminate-instances",
            "--instance-ids", &self.instance_id,
        ]);
        append_aws_opts(&mut cmd, &self.aws_profile, &self.aws_region);
        let status = cmd.status().context("ec2 terminate-instances")?;

        if !status.success() {
            bail!("failed to terminate instance {}", self.instance_id);
        }

        // Mark as cleaned up so Drop doesn't retry
        self.instance_id.clear();
        Ok(())
    }
}

impl Drop for ReplayInfra {
    fn drop(&mut self) {
        if !self.instance_id.is_empty() {
            warn!("replay instance {} not explicitly torn down — terminating in Drop",
                self.instance_id);
            if let Err(e) = self.teardown() {
                warn!("replay infrastructure cleanup failed: {e}");
            }
        }
    }
}

// ─── AWS helpers ─────────────────────────────────────────────────────────

/// Append `--profile <p> --region <r>` to a command.
/// Skips `--profile` when profile is empty (uses default credential chain / instance role).
fn append_aws_opts<'a>(cmd: &'a mut Command, profile: &str, region: &str) -> &'a mut Command {
    if !profile.is_empty() {
        cmd.args(["--profile", profile]);
    }
    cmd.args(["--region", region])
}

/// Resolve the latest Amazon Linux 2023 AMI via SSM parameter.
fn resolve_ami(profile: &str, region: &str) -> Result<String> {
    let mut cmd = Command::new("aws");
    cmd.args([
        "ssm", "get-parameter",
        "--name", "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64",
        "--query", "Parameter.Value",
        "--output", "text",
    ]);
    append_aws_opts(&mut cmd, profile, region);
    let output = cmd.output().context("resolve AL2023 AMI via SSM")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("failed to resolve AMI: {stderr}");
    }

    let ami = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if ami.is_empty() || !ami.starts_with("ami-") {
        bail!("invalid AMI ID resolved: {ami}");
    }
    Ok(ami)
}

/// Auto-detect the subnet ID from the current EC2 instance's metadata.
///
/// Falls back to IMDS to find what subnet this host is in.
fn detect_subnet() -> Result<String> {
    // Try IMDSv2 token
    let token_output = Command::new("curl")
        .args([
            "-sf", "--max-time", "2",
            "-X", "PUT",
            "-H", "X-aws-ec2-metadata-token-ttl-seconds: 60",
            "http://169.254.169.254/latest/api/token",
        ])
        .output();

    let token = match token_output {
        Ok(out) if out.status.success() => {
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }
        _ => bail!(
            "BENCHMARK_SUBNET_ID not set and IMDS not available. \
             Set BENCHMARK_SUBNET_ID explicitly."
        ),
    };

    let subnet_output = Command::new("curl")
        .args([
            "-sf", "--max-time", "2",
            "-H", &format!("X-aws-ec2-metadata-token: {token}"),
            "http://169.254.169.254/latest/meta-data/network/interfaces/macs/",
        ])
        .output()
        .context("query IMDS for MAC")?;

    if !subnet_output.status.success() {
        bail!("failed to query IMDS for network interfaces");
    }

    let mac = String::from_utf8_lossy(&subnet_output.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .trim_end_matches('/')
        .to_string();

    if mac.is_empty() {
        bail!("no MAC address found in IMDS");
    }

    let sid_output = Command::new("curl")
        .args([
            "-sf", "--max-time", "2",
            "-H", &format!("X-aws-ec2-metadata-token: {token}"),
            &format!(
                "http://169.254.169.254/latest/meta-data/network/interfaces/macs/{mac}/subnet-id"
            ),
        ])
        .output()
        .context("query IMDS for subnet-id")?;

    if !sid_output.status.success() {
        bail!("failed to get subnet-id from IMDS");
    }

    let subnet_id = String::from_utf8_lossy(&sid_output.stdout).trim().to_string();
    if subnet_id.is_empty() || !subnet_id.starts_with("subnet-") {
        bail!("invalid subnet-id from IMDS: {subnet_id}");
    }

    info!("auto-detected subnet: {subnet_id}");
    Ok(subnet_id)
}

/// Build the SSM setup script that installs Loki, downloads data, and starts serving.
fn build_setup_script(op_id: &str, s3_bucket: &str, region: &str) -> String {
    format!(
        r#"#!/bin/bash
set -euo pipefail

# 1. Install Loki
curl -sLo /tmp/loki.zip https://github.com/grafana/loki/releases/download/v{loki_version}/loki-linux-amd64.zip
cd /tmp && unzip -o loki.zip && mv loki-linux-amd64 /usr/local/bin/loki && chmod +x /usr/local/bin/loki

# 2. Download snapshot data from S3
mkdir -p /opt/replay/loki
aws s3 sync s3://{s3_bucket}/snapshots/{op_id}/loki/ /opt/replay/loki/ --region {region} --quiet

# 3. Arrange data for Loki filesystem storage
mkdir -p /opt/replay/loki-store/chunks /opt/replay/loki-store/rules /opt/replay/loki-data
if [ -d /opt/replay/loki/fake ]; then
    mv /opt/replay/loki/fake /opt/replay/loki-store/chunks/fake
fi
# Index files must be under chunks/index/ (Loki's default index path_prefix)
if [ -d /opt/replay/loki/index ]; then
    mkdir -p /opt/replay/loki-store/chunks/index
    mv /opt/replay/loki/index/* /opt/replay/loki-store/chunks/index/
fi

# 3b. Rename chunk files from raw keys to base64-encoded keys
# Production Loki (S3 object store) stores chunks with raw keys like
# "19f1a6a1109:19f1c21a103:c77d5dfb". The filesystem object store expects
# base64-encoded keys like "MTlmMWE2YTExMDk6MTlmMWMyMWExMDM6Yzc3ZDVkZmI=".
# The TSDB index references the base64 form, so we must rename on disk.
if [ -d /opt/replay/loki-store/chunks/fake ]; then
    find /opt/replay/loki-store/chunks/fake -type f | while read -r f; do
        dir=$(dirname "$f")
        name=$(basename "$f")
        b64name=$(printf '%s' "$name" | base64 | tr -d '\n')
        if [ "$name" != "$b64name" ]; then
            mv "$f" "$dir/$b64name"
        fi
    done
    echo "Chunk files renamed to base64 encoding"
fi

# 4. Write Loki config
cat > /opt/replay/loki-config.yaml << 'LOKIEOF'
auth_enabled: false
server:
  http_listen_port: 3100
  log_level: warn
common:
  path_prefix: /opt/replay/loki-data
  storage:
    filesystem:
      chunks_directory: /opt/replay/loki-store/chunks
      rules_directory: /opt/replay/loki-store/rules
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory
limits_config:
  reject_old_samples: false
  reject_old_samples_max_age: "8760h"
  max_entries_limit_per_query: 50000
  max_query_length: "0"
storage_config:
  tsdb_shipper:
    active_index_directory: /opt/replay/loki-data/tsdb-active
    cache_location: /opt/replay/loki-data/tsdb-cache
    resync_interval: 5s
schema_config:
  configs:
  - from: "2020-01-01"
    store: tsdb
    object_store: filesystem
    schema: v13
    index:
      prefix: loki_index_
      period: 24h
analytics:
  reporting_enabled: false
LOKIEOF

# 5. Start Loki
nohup /usr/local/bin/loki -config.file=/opt/replay/loki-config.yaml > /var/log/loki.log 2>&1 &

# 6. Wait for ready
for i in $(seq 1 30); do
    if curl -sf http://localhost:3100/ready; then
        exit 0
    fi
    sleep 2
done
echo "Loki failed to become ready within 60s" >&2
exit 1
"#,
        loki_version = LOKI_VERSION,
        s3_bucket = s3_bucket,
        op_id = op_id,
        region = region,
    )
}

/// Wait for an SSM command to complete, polling every 5 seconds.
fn wait_for_ssm_command(
    command_id: &str,
    instance_id: &str,
    profile: &str,
    region: &str,
) -> Result<()> {
    let max_polls = 180; // 15 minutes
    for i in 0..max_polls {
        std::thread::sleep(std::time::Duration::from_secs(5));

        let mut cmd = Command::new("aws");
        cmd.args([
            "ssm", "get-command-invocation",
            "--command-id", command_id,
            "--instance-id", instance_id,
            "--query", "Status",
            "--output", "text",
        ]);
        append_aws_opts(&mut cmd, profile, region);
        let output = cmd.output().context("ssm get-command-invocation")?;

        if !output.status.success() {
            if i < 6 {
                // SSM agent may not be ready yet — keep trying
                continue;
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("ssm get-command-invocation failed: {stderr}");
        }

        let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
        match status.as_str() {
            "Success" => {
                info!("SSM setup command completed successfully");
                return Ok(());
            }
            "Failed" | "TimedOut" | "Cancelled" => {
                // Get the error output
                let mut err_cmd = Command::new("aws");
                err_cmd.args([
                    "ssm", "get-command-invocation",
                    "--command-id", command_id,
                    "--instance-id", instance_id,
                    "--query", "StandardErrorContent",
                    "--output", "text",
                ]);
                append_aws_opts(&mut err_cmd, profile, region);
                let err_output = err_cmd.output();

                let err_msg = match err_output {
                    Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
                    Err(_) => "unable to retrieve error output".to_string(),
                };

                bail!("SSM setup command {status}: {err_msg}");
            }
            "InProgress" | "Pending" | "Delayed" => {
                // Still running
                if i % 6 == 0 {
                    info!("SSM command still {status} ({i}/{})", max_polls);
                }
            }
            other => {
                info!("SSM command status: {other}");
            }
        }
    }

    bail!("SSM setup command timed out after 15 minutes");
}

/// Verify that Loki is ready and can serve queries.
///
/// Uses `curl` to check readiness and runs a test label query.
fn verify_loki_ready(private_ip: &str) -> Result<()> {
    // Check /ready endpoint
    let ready_output = Command::new("curl")
        .args([
            "-sf", "--max-time", "5",
            &format!("http://{private_ip}:3100/ready"),
        ])
        .output()
        .context("curl Loki /ready")?;

    if !ready_output.status.success() {
        bail!("Loki not ready on {private_ip}:3100");
    }

    // Verify data is queryable
    let labels_output = Command::new("curl")
        .args([
            "-sf", "--max-time", "10",
            &format!("http://{private_ip}:3100/loki/api/v1/labels"),
        ])
        .output()
        .context("curl Loki /labels")?;

    if !labels_output.status.success() {
        warn!("Loki /labels query failed — data may not be loaded yet");
    } else {
        let body = String::from_utf8_lossy(&labels_output.stdout);
        info!("Loki labels response: {}", body.chars().take(200).collect::<String>());
    }

    Ok(())
}


/// List available snapshots from the benchmark S3 bucket.
///
/// Returns a list of (op_id, manifest_json) tuples.
pub(crate) fn list_snapshots(
    profile: &str,
    region: &str,
    bucket: &str,
) -> Result<Vec<(String, super::manifest::SnapshotManifest)>> {
    // List snapshot directories
    let mut cmd = Command::new("aws");
    cmd.args([
        "s3api", "list-objects-v2",
        "--bucket", bucket,
        "--prefix", "snapshots/",
        "--delimiter", "/",
        "--query", "CommonPrefixes[].Prefix",
        "--output", "json",
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
        Err(_) => return Ok(Vec::new()), // No snapshots
    };

    let mut snapshots = Vec::new();

    for prefix in &prefixes {
        // prefix looks like "snapshots/op-20260630-222023/"
        let op_id = prefix
            .trim_start_matches("snapshots/")
            .trim_end_matches('/');
        if op_id.is_empty() {
            continue;
        }

        // Download manifest.json
        let s3_src = format!("s3://{bucket}/{prefix}manifest.json");
        let mut manifest_cmd = Command::new("aws");
        manifest_cmd.args(["s3", "cp", &s3_src, "-"]);
        append_aws_opts(&mut manifest_cmd, profile, region);
        let manifest_output = manifest_cmd.output();

        match manifest_output {
            Ok(out) if out.status.success() => {
                let raw = String::from_utf8_lossy(&out.stdout);
                match serde_json::from_str::<super::manifest::SnapshotManifest>(&raw) {
                    Ok(manifest) => snapshots.push((op_id.to_string(), manifest)),
                    Err(e) => {
                        warn!("failed to parse manifest for {op_id}: {e}");
                    }
                }
            }
            _ => {
                warn!("failed to download manifest for {op_id}");
            }
        }
    }

    // Sort by captured_at descending
    snapshots.sort_by(|a, b| b.1.captured_at.cmp(&a.1.captured_at));

    Ok(snapshots)
}

/// Download snapshot metadata files (manifest, red-state, ground-truth, fired-alerts)
/// from S3 to a local directory. Does NOT download loki/ data (that goes to the EC2).
pub(crate) fn download_snapshot_metadata(
    op_id: &str,
    profile: &str,
    region: &str,
    bucket: &str,
    local_dir: &std::path::Path,
) -> Result<()> {
    std::fs::create_dir_all(local_dir)
        .with_context(|| format!("create local dir: {}", local_dir.display()))?;

    let files = ["manifest.json", "red-state.json", "ground-truth.json", "fired-alerts.json"];
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
