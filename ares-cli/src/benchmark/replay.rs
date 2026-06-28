//! Benchmark replay: load snapshots into Loki and run blue team investigations.
//!
//! - `load`: import a snapshot's JSONL streams into a target Loki instance
//! - `run`: full pipeline (ephemeral Loki → import → investigate → score)

use std::fs;
use std::io::BufReader;
use std::path::Path;

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

use super::k8s_loki::EphemeralLoki;
use super::manifest::{BenchmarkResult, FiredAlert, SnapshotManifest};

/// Parameters for the `benchmark run` command.
pub(crate) struct ReplayParams {
    pub redis_url: Option<String>,
    pub snapshot_dir: String,
    pub loki_mode: String,
    pub loki_url: Option<String>,
    pub trigger_mode: String,
    pub output_dir: String,
    pub model: Option<String>,
    pub max_steps: u32,
    pub namespace: String,
}

// ─── Load command ────────────────────────────────────────────────────────

/// Import a snapshot's Loki data into a target Loki instance.
pub(crate) async fn run_load(
    snapshot_dir: &str,
    loki_url: &str,
    loki_token: Option<&str>,
) -> Result<()> {
    let manifest = load_manifest(snapshot_dir)?;

    let config = BulkLokiConfig {
        base_url: loki_url.trim_end_matches('/').to_string(),
        auth_token: loki_token.map(String::from),
    };

    let import_start = std::time::Instant::now();
    let total = import_all_streams(snapshot_dir, &manifest, &config).await?;
    let duration = import_start.elapsed();

    println!("Import complete");
    println!("  Streams:  {}", manifest.streams.len());
    println!("  Entries:  {total}");
    println!("  Duration: {:.1}s", duration.as_secs_f64());

    Ok(())
}

// ─── Run command ─────────────────────────────────────────────────────────

/// Full replay: ephemeral Loki → import → investigate → score.
pub(crate) async fn run_replay(p: ReplayParams) -> Result<()> {
    let manifest = load_manifest(&p.snapshot_dir)?;
    let run_started_at = Utc::now();
    let run_id = format!("inv-{}", run_started_at.format("%Y%m%d-%H%M%S"));

    info!(
        "benchmark run {run_id} for operation {}",
        manifest.operation_id
    );

    // ── Provision Loki ───────────────────────────────────────────────────
    let mut ephemeral_loki: Option<EphemeralLoki> = None;
    let loki_url: String;

    match p.loki_mode.as_str() {
        "ephemeral" => {
            info!("creating ephemeral Loki in namespace {}", p.namespace);
            let mut loki = EphemeralLoki::create(&p.namespace, &manifest.operation_id)?;
            let url = loki.start_port_forward()?;
            loki_url = url;
            ephemeral_loki = Some(loki);
        }
        "external" => {
            loki_url = p
                .loki_url
                .clone()
                .context("--loki-url is required when --loki-mode=external")?;
        }
        other => bail!("unknown loki-mode: {other} (expected: ephemeral, external)"),
    }

    info!("Loki URL: {loki_url}");

    // ── Import snapshot data ─────────────────────────────────────────────
    let import_config = BulkLokiConfig {
        base_url: loki_url.trim_end_matches('/').to_string(),
        auth_token: None,
    };

    let import_start = std::time::Instant::now();
    let total_imported = import_all_streams(&p.snapshot_dir, &manifest, &import_config).await?;
    let import_duration = import_start.elapsed().as_secs_f64();

    info!("imported {total_imported} entries in {import_duration:.1}s");

    // ── Override LOKI_URL so the blue team queries the ephemeral instance ─
    // SAFETY: this is the documented mechanism for pointing the blue agent
    // at a specific Loki. The env var is read by loki_config() in loki.rs.
    unsafe {
        std::env::set_var("LOKI_URL", &loki_url);
    }

    // ── Build investigation trigger ──────────────────────────────────────
    let alert_json = match p.trigger_mode.as_str() {
        "alert-replay" => build_alert_replay_trigger(&p.snapshot_dir, &manifest)?,
        "operation" => build_operation_trigger(&p.snapshot_dir, &manifest)?,
        other => bail!("unknown trigger-mode: {other} (expected: alert-replay, operation)"),
    };

    info!("trigger built (mode={})", p.trigger_mode);

    // ── Submit investigation via NATS ────────────────────────────────────
    let effective_model = resolve_model(&p.model);
    let env_vars = collect_env_vars(BLUE_ENV_VAR_NAMES);

    let mut conn = connect_redis(p.redis_url).await?;

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

    // Store env vars (includes LOKI_URL override)
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
    BlueTaskQueue::submit_investigation_request(&nats, &request)
        .await
        .context("submit investigation request to NATS")?;

    info!("investigation {run_id} submitted");

    // ── Poll for completion ──────────────────────────────────────────────
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

    let investigation_duration = investigation_start.elapsed().as_secs_f64();

    // ── Score against ground truth ───────────────────────────────────────
    let red_state_path = Path::new(&p.snapshot_dir).join("red-state.json");
    let (red_state, techniques) = load_red_state_from_file(&red_state_path)?;
    let ground_truth = create_ground_truth_from_red_state(&red_state, &techniques);

    let blue_reader = BlueStateReader::new(run_id.clone());
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

    // ── Write result ─────────────────────────────────────────────────────
    let trigger_alert = match p.trigger_mode.as_str() {
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
        run_id: run_id.clone(),
        trigger_mode: p.trigger_mode.clone(),
        trigger_alert,
        loki_mode: p.loki_mode.clone(),
        model: model_name.to_string(),
        started_at: run_started_at,
        completed_at: Utc::now(),
        import_duration_secs: import_duration,
        investigation_duration_secs: investigation_duration,
        evaluation: eval_result.to_value(),
        gap_analysis: gap_analysis.to_markdown(),
    };

    fs::create_dir_all(&p.output_dir)
        .with_context(|| format!("create output dir: {}", p.output_dir))?;
    let result_path = Path::new(&p.output_dir).join(format!("{run_id}.json"));
    fs::write(&result_path, serde_json::to_string_pretty(&result)?)
        .with_context(|| format!("write result: {}", result_path.display()))?;

    // ── Cleanup ──────────────────────────────────────────────────────────
    if let Some(mut loki) = ephemeral_loki {
        loki.destroy()?;
    }

    // ── Summary ─────────────────────────────────────────────────────────
    println!("Benchmark complete: {}", result_path.display());
    println!("  Run ID:         {run_id}");
    println!("  Operation:      {}", manifest.operation_id);
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
    println!("  Import:         {import_duration:.1}s");
    println!("  Investigation:  {investigation_duration:.1}s");
    println!("  Pass:           {}", eval_result.passed());

    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────────────

/// Load and validate the snapshot manifest.
fn load_manifest(snapshot_dir: &str) -> Result<SnapshotManifest> {
    let manifest_path = Path::new(snapshot_dir).join("manifest.json");
    let raw = fs::read_to_string(&manifest_path)
        .with_context(|| format!("read {}", manifest_path.display()))?;
    let manifest: SnapshotManifest = serde_json::from_str(&raw).context("parse manifest.json")?;
    info!(
        "loaded manifest: op={}, streams={}, entries={}",
        manifest.operation_id,
        manifest.streams.len(),
        manifest.total_log_entries,
    );
    Ok(manifest)
}

/// Import all JSONL streams from a snapshot into Loki.
async fn import_all_streams(
    snapshot_dir: &str,
    manifest: &SnapshotManifest,
    config: &BulkLokiConfig,
) -> Result<u64> {
    let mut total: u64 = 0;

    for stream in &manifest.streams {
        let file_path = Path::new(snapshot_dir).join(&stream.file);
        if !file_path.exists() {
            info!("skipping missing stream file: {}", file_path.display());
            continue;
        }

        let file =
            fs::File::open(&file_path).with_context(|| format!("open {}", file_path.display()))?;
        let reader = BufReader::new(file);

        info!("importing stream {} from {}", stream.job, stream.file);
        let entries = loki_bulk::import_stream(config, reader, 0).await?;
        info!("  {}: {entries} entries imported", stream.job);
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
