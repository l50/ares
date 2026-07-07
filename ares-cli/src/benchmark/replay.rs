//! Benchmark replay: provision EC2 Loki, run blue team investigations, score.
//!
//! - `load`: import a snapshot's JSONL streams into a target Loki instance
//! - `run`: full pipeline (EC2 Loki → investigate → score → teardown)

use std::fs;
#[allow(unused_imports)]
use std::io::BufReader;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::Utc;
use redis::AsyncCommands;
use tracing::info;

use ares_core::eval::gap_analysis::analyze_detection_gaps;
use ares_core::eval::ground_truth::create_ground_truth_from_red_state;
use ares_core::eval::scorers::{self, InvestigationSnapshot};
use ares_core::eval::workflow::load_red_state_from_file;
use ares_core::nats::NatsBroker;
use ares_core::state::blue_task_queue::BlueTaskQueue;
use ares_core::state::BlueStateReader;
use ares_tools::blue::loki_bulk::{self, BulkLokiConfig};

use crate::ops::submit::{collect_env_vars, resolve_model, BLUE_ENV_VAR_NAMES};
use crate::redis_conn::connect_redis;

use super::manifest::{BenchmarkResult, FiredAlert, SnapshotManifest};
use super::snapshot_s3::SnapshotConfig;

/// Parameters for the `benchmark run` command.
pub(crate) struct ReplayParams {
    pub redis_url: Option<String>,
    pub snapshot: String,
    pub snapshot_dir: Option<String>,
    pub replay_mode: String,
    pub trigger_mode: String,
    pub output_dir: String,
    pub model: Option<String>,
    pub max_steps: u32,
    pub quiet_period: Option<f64>,
    pub time_compression: f64,
    /// Private IP of an already-provisioned replay stack. The stack is stood
    /// up by `task benchmark:replay:provision`; `benchmark run` only runs the
    /// investigation against it.
    pub stack_ip: String,
}

/// Import a snapshot's Loki data into a target Loki instance.
///
/// For `s3-chunks` snapshots, copies the chunk/index data into Loki's
/// filesystem storage directory. For legacy `api-export` snapshots,
/// pushes JSONL streams via the Loki push API.
pub(crate) async fn run_load(
    snapshot_dir: &str,
    loki_url: &str,
    loki_token: Option<&str>,
) -> Result<()> {
    let manifest = load_manifest(snapshot_dir)?;

    if manifest.loki_source == "s3-chunks" {
        println!("Snapshot uses S3-chunks Loki data.");
        println!("  Chunks:  {}", manifest.loki_chunks);
        println!("  Index:   {}", manifest.loki_index_files);
        println!();
        println!("To use this data, configure Loki with filesystem storage");
        println!("pointing at: {}/loki/", snapshot_dir);
        println!("  chunks: {}/loki/fake/", snapshot_dir);
        println!("  index:  {}/loki/index/", snapshot_dir);
        return Ok(());
    }

    // Legacy api-export path (JSONL import via push API)
    let config = BulkLokiConfig {
        base_url: loki_url.trim_end_matches('/').to_string(),
        auth_token: loki_token.map(String::from),
    };

    let import_start = std::time::Instant::now();
    let total = import_all_streams(snapshot_dir, &manifest, &config).await?;
    let duration = import_start.elapsed();

    println!("Import complete");
    println!("  Entries:  {total}");
    println!("  Duration: {:.1}s", duration.as_secs_f64());

    Ok(())
}

/// Run a blue investigation against an already-provisioned replay stack.
///
/// The stack is stood up by `task benchmark:replay:provision` (or the caller
/// running the equivalent AWS-CLI commands) and its private IP is passed as
/// `--stack-ip`. This function submits the investigation to NATS, polls
/// Redis for completion, and computes the score — no provisioning, no
/// teardown.
///
/// Replay modes:
/// - `static`: all data pre-loaded, agent knows full attack window (operation trigger)
/// - `timeline`: quiet period before first alert, alert-replay trigger (no end window),
///   simulating an unfolding attack
pub(crate) async fn run_replay(p: ReplayParams) -> Result<()> {
    let run_started_at = Utc::now();
    let run_id = format!("inv-{}", run_started_at.format("%Y%m%d-%H%M%S"));
    let is_timeline = p.replay_mode == "timeline";

    if !matches!(p.replay_mode.as_str(), "static" | "timeline") {
        bail!(
            "unknown replay-mode: {} (expected: static, timeline)",
            p.replay_mode
        );
    }

    // Point the blue agent's observability surface at the caller-supplied
    // stack and pull LLM keys from Secrets Manager if they're missing (e.g.
    // when `benchmark run` runs on an EC2 box that doesn't have `op`).
    // SAFETY: single-threaded — tokio hasn't spawned anything yet.
    let loki_url = format!("http://{}:3100", p.stack_ip);
    let grafana_url = format!("http://{}:3000", p.stack_ip);
    let prometheus_url = format!("http://{}:9090", p.stack_ip);
    let tempo_url = format!("http://{}:3200", p.stack_ip);
    unsafe {
        std::env::set_var("LOKI_URL", &loki_url);
        std::env::set_var("GRAFANA_URL", &grafana_url);
        std::env::set_var("PROMETHEUS_URL", &prometheus_url);
        std::env::set_var("TEMPO_URL", &tempo_url);
    }
    ensure_llm_secrets();

    let snapshot_config = SnapshotConfig::from_env();
    let (snapshot_path, _is_temp) =
        resolve_snapshot(&p.snapshot, p.snapshot_dir.as_deref(), &snapshot_config)?;

    let manifest = load_manifest(snapshot_path.to_str().unwrap())?;

    info!(
        "benchmark run {run_id} [mode={}, trigger={}] for operation {} against stack {}",
        p.replay_mode,
        if is_timeline {
            "alert-replay"
        } else {
            &p.trigger_mode
        },
        manifest.operation_id,
        p.stack_ip,
    );

    run_replay_inner(
        &p,
        &manifest,
        &loki_url,
        &snapshot_path,
        &run_id,
        is_timeline,
        run_started_at,
    )
    .await
}

/// Ensure LLM API keys are in the environment. Delegates to the shared
/// Secrets Manager loader in `secrets.rs` for the "re-exec'd onto an EC2 box"
/// case, where `op` is unavailable but instance credentials are — no-op when
/// the keys are already set. Region resolution favors `BENCHMARK_AWS_REGION`
/// so the fetch lands in the same account as the replay stack.
fn ensure_llm_secrets() {
    if std::env::var("OPENAI_API_KEY").is_ok() && std::env::var("ANTHROPIC_API_KEY").is_ok() {
        return;
    }
    let secret_id = std::env::var("ARES_SECRETS_ID").ok();
    let region = std::env::var("BENCHMARK_AWS_REGION").ok();
    match crate::secrets::load_secrets_manager_secrets(secret_id.as_deref(), region.as_deref()) {
        Ok(n) if n > 0 => info!("LLM keys loaded from Secrets Manager ({n})"),
        Ok(_) => {}
        Err(e) => eprintln!("WARNING: could not fetch LLM keys from Secrets Manager: {e:#}; the investigation may fail to start"),
    }
}

/// Inner replay logic, separated so teardown always runs.
async fn run_replay_inner(
    p: &ReplayParams,
    manifest: &SnapshotManifest,
    loki_url: &str,
    snapshot_path: &Path,
    run_id: &str,
    is_timeline: bool,
    run_started_at: chrono::DateTime<Utc>,
) -> Result<()> {
    // SAFETY: this is the documented mechanism for pointing the blue agent
    // at a specific Loki. The env var is read by loki_config() in loki.rs.
    unsafe {
        std::env::set_var("LOKI_URL", loki_url);
    }

    let quiet_period_secs = if is_timeline {
        let secs = p
            .quiet_period
            .unwrap_or_else(|| rand::random_range(60.0..=300.0));
        if secs > 0.0 {
            info!("timeline mode: quiet period {secs:.0}s before first alert");
            tokio::time::sleep(std::time::Duration::from_secs_f64(secs)).await;
        }
        Some(secs)
    } else {
        None
    };

    // Timeline mode always uses alert-replay (no attack_window_end).
    let snapshot_dir_str = snapshot_path.to_str().unwrap();
    let effective_trigger_mode = if is_timeline {
        "alert-replay"
    } else {
        &p.trigger_mode
    };

    let alert_json = match effective_trigger_mode {
        "alert-replay" => build_alert_replay_trigger(snapshot_dir_str, manifest)?,
        "operation" => build_operation_trigger(snapshot_dir_str, manifest)?,
        other => bail!("unknown trigger-mode: {other} (expected: alert-replay, operation)"),
    };

    info!("trigger built (mode={effective_trigger_mode})");

    // Anchor the replay clock at the trigger time so the blue agent's
    // "recent"/relative-window queries and the initial-alert prompt land on the
    // captured attack instead of wall-clock now (read via ARES_REPLAY_CLOCK_START
    // by ares-tools::blue::replay_clock and the prompt builder).
    // SAFETY: single-threaded replay setup, before the investigation runs.
    if let Some(anchor) = alert_json
        .get("startsAt")
        .and_then(|v| v.as_str())
        .or_else(|| {
            alert_json
                .pointer("/operation_context/attack_window_start")
                .and_then(|v| v.as_str())
        })
    {
        unsafe {
            std::env::set_var("ARES_REPLAY_CLOCK_START", anchor);
        }
    }

    let effective_model = resolve_model(&p.model);
    let mut env_vars = collect_env_vars(BLUE_ENV_VAR_NAMES);
    // Ensure LOKI_URL points to the replay EC2
    env_vars.insert("LOKI_URL".to_string(), loki_url.to_string());

    let mut conn = connect_redis(p.redis_url.clone()).await?;

    let request = serde_json::json!({
        "investigation_id": run_id,
        "alert": alert_json,
        "correlation_context": null,
        "model": effective_model,
        "max_steps": p.max_steps,
        "multi_agent": true,
        "auto_route": false,
        "report_dir": null,
        "submitted_at": Utc::now().to_rfc3339(),
    });

    // Store env vars (includes LOKI_URL override for per-investigation routing)
    if !env_vars.is_empty() {
        let env_key = format!("ares:blue:inv:{run_id}:env_vars");
        let env_json = serde_json::to_string(&env_vars)?;
        let _: () = conn.set(&env_key, &env_json).await?;
        let _: () = conn.expire(&env_key, 3600).await?;
    }

    let nats = NatsBroker::connect_from_env()
        .await
        .context("connect to NATS for investigation submission")?;
    nats.ensure_streams().await?;

    // Spawn an ephemeral in-process blue consumer so the investigation we submit
    // actually runs — this makes `benchmark run` self-contained (no separately
    // running blue orchestrator required). It dies with the process and uses the
    // isolated ARES_BLUE_TASKS stream, so it never interferes with a red fleet.
    let redis_url_str = p.redis_url.clone().unwrap_or_else(|| {
        std::env::var("ARES_REDIS_URL")
            .or_else(|_| std::env::var("REDIS_URL"))
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string())
    });
    let nats_url_str = NatsBroker::url_from_env();
    let consumer_model = effective_model
        .clone()
        .or_else(|| std::env::var("ARES_BLUE_LLM_MODEL").ok())
        .or_else(|| std::env::var("ARES_LLM_MODEL").ok())
        .unwrap_or_else(|| "openai/gpt-5.2".to_string());
    let (blue_handle, blue_shutdown) = crate::orchestrator::spawn_inprocess_blue_consumer(
        &consumer_model,
        &redis_url_str,
        &nats_url_str,
    )
    .await
    .context("spawn in-process blue consumer")?;

    BlueTaskQueue::submit_investigation_request(&nats, &request)
        .await
        .context("submit investigation request to NATS")?;

    info!("investigation {run_id} submitted");

    let investigation_start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(45 * 60); // 45 minutes
    let poll_interval = std::time::Duration::from_secs(10);

    loop {
        if investigation_start.elapsed() > timeout {
            bail!("investigation {run_id} timed out after 45 minutes");
        }

        let status_key = format!("ares:blue:inv:{run_id}:status");
        let status_raw: Option<String> = conn.get(&status_key).await?;

        if let Some(raw) = status_raw {
            if let Ok(status) = serde_json::from_str::<serde_json::Value>(&raw) {
                let state = status
                    .get("status")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown");

                match state {
                    "completed" | "escalated" => {
                        info!("investigation {run_id} completed (status={state})");
                        break;
                    }
                    "failed" => {
                        let err = status
                            .get("error")
                            .and_then(|e| e.as_str())
                            .unwrap_or("unknown error");
                        bail!("investigation {run_id} failed: {err}");
                    }
                    _ => {
                        // still running
                    }
                }
            }
        }

        tokio::time::sleep(poll_interval).await;
    }

    // Investigation finished — stop the in-process blue consumer cleanly.
    let _ = blue_shutdown.send(true);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(30), blue_handle).await;

    let investigation_duration = investigation_start.elapsed().as_secs_f64();

    let red_state_path = snapshot_path.join("red-state.json");
    let (red_state, techniques) = load_red_state_from_file(&red_state_path)?;
    let ground_truth = create_ground_truth_from_red_state(&red_state, &techniques);

    let blue_reader = BlueStateReader::new(run_id.to_string());
    let blue_state = blue_reader
        .load_state(&mut conn)
        .await?
        .with_context(|| format!("no blue team state found for {run_id}"))?;

    let snap = InvestigationSnapshot::from_blue_state(&blue_state);
    let model_name = effective_model.as_deref().unwrap_or("default");

    let eval_result = scorers::evaluate(
        &format!("bench-{run_id}"),
        &snap,
        &ground_truth,
        true,
        model_name,
        investigation_duration,
    );
    let gap_analysis = analyze_detection_gaps(&eval_result);

    let trigger_alert = match effective_trigger_mode {
        "alert-replay" => alert_json
            .get("labels")
            .and_then(|l| l.get("alertname"))
            .and_then(|n| n.as_str())
            .map(String::from),
        _ => None,
    };

    let result = BenchmarkResult {
        snapshot_id: manifest.operation_id.clone(),
        operation_id: manifest.operation_id.clone(),
        run_id: run_id.to_string(),
        replay_mode: p.replay_mode.clone(),
        trigger_mode: effective_trigger_mode.to_string(),
        trigger_alert,
        loki_mode: "ec2".to_string(),
        model: model_name.to_string(),
        started_at: run_started_at,
        completed_at: Utc::now(),
        quiet_period_secs,
        time_compression: if is_timeline {
            Some(p.time_compression)
        } else {
            None
        },
        investigation_duration_secs: investigation_duration,
        evaluation: eval_result.to_value(),
        gap_analysis: gap_analysis.to_markdown(),
    };

    fs::create_dir_all(&p.output_dir)
        .with_context(|| format!("create output dir: {}", p.output_dir))?;
    let result_path = Path::new(&p.output_dir).join(format!("{run_id}.json"));
    fs::write(&result_path, serde_json::to_string_pretty(&result)?)
        .with_context(|| format!("write result: {}", result_path.display()))?;

    println!("Benchmark complete: {}", result_path.display());
    println!("  Run ID:         {run_id}");
    println!("  Mode:           {}", p.replay_mode);
    println!("  Operation:      {}", manifest.operation_id);
    if let Some(qp) = quiet_period_secs {
        println!("  Quiet period:   {qp:.0}s");
    }
    println!("  Grade:          {}", eval_result.grade());
    println!(
        "  Overall score:  {:.1}%",
        eval_result.overall_score * 100.0
    );
    println!(
        "  Technique coverage: {:.1}%",
        eval_result.technique_coverage * 100.0
    );
    println!(
        "  IOC detection:  {:.1}%",
        eval_result.ioc_detection_rate * 100.0
    );
    println!("  Investigation:  {investigation_duration:.1}s");
    println!("  Pass:           {}", eval_result.passed());

    Ok(())
}

/// Resolve snapshot location: use local dir override if provided, otherwise
/// download metadata from S3.
fn resolve_snapshot(
    snapshot_id: &str,
    snapshot_dir_override: Option<&str>,
    config: &SnapshotConfig,
) -> Result<(PathBuf, bool)> {
    if let Some(dir) = snapshot_dir_override {
        info!("using local snapshot directory: {dir}");
        return Ok((PathBuf::from(dir), false));
    }

    // Download metadata from S3 to a temp directory
    let tmp_dir = PathBuf::from(format!("/tmp/ares-benchmark-{snapshot_id}"));
    info!("downloading snapshot metadata from S3 for {snapshot_id}...");
    super::snapshot_s3::download_snapshot_metadata(
        snapshot_id,
        &config.aws_profile,
        &config.aws_region,
        &config.s3_bucket,
        &tmp_dir,
    )?;

    Ok((tmp_dir, true))
}

/// Load and validate the snapshot manifest.
fn load_manifest(snapshot_dir: &str) -> Result<SnapshotManifest> {
    let manifest_path = Path::new(snapshot_dir).join("manifest.json");
    let raw = fs::read_to_string(&manifest_path)
        .with_context(|| format!("read {}", manifest_path.display()))?;
    let manifest: SnapshotManifest = serde_json::from_str(&raw).context("parse manifest.json")?;
    info!(
        "loaded manifest: op={}, loki_source={}, chunks={}, alerts={}",
        manifest.operation_id, manifest.loki_source, manifest.loki_chunks, manifest.alerts_captured,
    );
    Ok(manifest)
}

/// Import all JSONL streams from a legacy snapshot into Loki.
///
/// Scans the `loki/` subdirectory for `.jsonl` files and pushes each
/// into Loki via the push API.
async fn import_all_streams(
    snapshot_dir: &str,
    _manifest: &SnapshotManifest,
    config: &BulkLokiConfig,
) -> Result<u64> {
    let loki_dir = Path::new(snapshot_dir).join("loki");
    let mut total: u64 = 0;

    if !loki_dir.exists() {
        info!("no loki/ directory in snapshot — nothing to import");
        return Ok(0);
    }

    for entry in fs::read_dir(&loki_dir)?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }

        let file = fs::File::open(&path).with_context(|| format!("open {}", path.display()))?;
        let reader = BufReader::new(file);
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");

        info!("importing stream {name} from {}", path.display());
        let entries = loki_bulk::import_stream(config, reader, 0).await?;
        info!("  {name}: {entries} entries imported");
        total += entries;
    }

    Ok(total)
}

/// Build an alert-replay trigger from the first fired alert in the snapshot.
fn build_alert_replay_trigger(
    snapshot_dir: &str,
    manifest: &SnapshotManifest,
) -> Result<serde_json::Value> {
    let alerts_path = Path::new(snapshot_dir).join("fired-alerts.json");
    let raw = fs::read_to_string(&alerts_path).context("read fired-alerts.json")?;
    let alerts: Vec<FiredAlert> = serde_json::from_str(&raw).context("parse fired-alerts.json")?;

    let alert = alerts
        .first()
        .context("no fired alerts in snapshot — use --trigger-mode=operation instead")?;

    info!(
        "alert-replay trigger: {} at {}",
        alert.alert_name,
        alert.fired_at.to_rfc3339()
    );

    Ok(serde_json::json!({
        "labels": alert.labels,
        "annotations": alert.annotations,
        "startsAt": alert.fired_at.to_rfc3339(),
        "operation_context": {
            "operation_id": manifest.operation_id,
            "attack_window_start": alert.fired_at.to_rfc3339(),
            // Do NOT set attack_window_end — blue must determine scope
        },
    }))
}

/// Build an operation-mode trigger replicating blue_from_operation() logic.
fn build_operation_trigger(
    snapshot_dir: &str,
    manifest: &SnapshotManifest,
) -> Result<serde_json::Value> {
    let red_state_path = Path::new(snapshot_dir).join("red-state.json");
    let raw = fs::read_to_string(&red_state_path).context("read red-state.json")?;
    let state: serde_json::Value = serde_json::from_str(&raw).context("parse red-state.json")?;

    let op_id = &manifest.operation_id;
    let cred_count = state
        .get("all_credentials")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let host_count = state
        .get("all_hosts")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let has_da = state
        .get("has_domain_admin")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let target_ips: Vec<String> = state
        .get("all_hosts")
        .and_then(|v| v.as_array())
        .map(|hosts| {
            hosts
                .iter()
                .filter_map(|h| h.get("ip").and_then(|v| v.as_str()).map(String::from))
                .take(50)
                .collect()
        })
        .unwrap_or_default();

    let target_users: Vec<String> = state
        .get("all_credentials")
        .and_then(|v| v.as_array())
        .map(|creds| {
            creds
                .iter()
                .filter_map(|c| c.get("username").and_then(|v| v.as_str()).map(String::from))
                .take(50)
                .collect()
        })
        .unwrap_or_default();

    let techniques: Vec<String> = state
        .get("identified_techniques")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .take(20)
                .collect()
        })
        .unwrap_or_default();

    let window_start = manifest.started_at.to_rfc3339();
    let window_end = manifest.completed_at.to_rfc3339();

    Ok(serde_json::json!({
        "labels": {
            "alertname": format!("RedTeamOperation_{op_id}"),
            "severity": "critical",
            "source": "ares-red-team",
        },
        "annotations": {
            "summary": format!(
                "Red team operation {op_id} - {cred_count} credentials, {host_count} hosts"
            ),
            "description": format!(
                "Investigate blue team detection coverage for red team operation {op_id}. \
                 Attack window: {window_start} to {window_end}. Domain admin: {has_da}."
            ),
        },
        "operation_context": {
            "operation_id": op_id,
            "attack_window_start": window_start,
            "attack_window_end": window_end,
            "techniques_used": techniques,
        },
        "startsAt": window_start,
        "endsAt": window_end,
        "target_ips": target_ips,
        "target_users": target_users,
    }))
}
