//! Snapshot capture pipeline.
//!
//! Connects to Redis, loads the completed red team state, exports all Loki
//! streams and fired Grafana alerts, generates ground truth, and writes
//! everything into a self-contained snapshot directory.

use std::fs;
use std::io::BufWriter;
use std::path::Path;

use anyhow::{bail, Context, Result};
use chrono::{Duration, Utc};
use tracing::info;

use ares_core::eval::ground_truth::create_ground_truth_from_red_state;
use ares_core::state::RedisStateReader;
use ares_tools::blue::loki_bulk::{self, BulkLokiConfig};

use crate::redis_conn::{connect_redis, resolve_operation_id};

use super::manifest::{FiredAlert, SnapshotManifest, StreamEntry, MANIFEST_VERSION};

/// Run the `benchmark capture` command.
pub(crate) async fn run_capture(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
    output_dir: &str,
    s3_bucket: Option<String>,
    pre_window_hours: u32,
    post_window_minutes: u32,
) -> Result<()> {
    // ── Resolve operation ────────────────────────────────────────────────
    let mut conn = connect_redis(redis_url).await?;
    let op_id = resolve_operation_id(&mut conn, operation_id, latest).await?;

    info!("capturing snapshot for operation {op_id}");

    let reader = RedisStateReader::new(op_id.clone());
    let state = reader
        .load_state(&mut conn)
        .await?
        .with_context(|| format!("no state found for operation: {op_id}"))?;

    if state.completed_at.is_none() {
        bail!("operation {op_id} has not completed — cannot capture snapshot");
    }
    let completed_at = state.completed_at.unwrap();

    // ── Capture window ───────────────────────────────────────────────────
    let export_start = state.started_at - Duration::hours(pre_window_hours as i64);
    let export_end = completed_at + Duration::minutes(post_window_minutes as i64);

    info!(
        "capture window: {} to {} (pre={}h, post={}m)",
        export_start.to_rfc3339(),
        export_end.to_rfc3339(),
        pre_window_hours,
        post_window_minutes,
    );

    // ── Create output directory ──────────────────────────────────────────
    let snapshot_dir = Path::new(output_dir).join(&op_id);
    let loki_dir = snapshot_dir.join("loki");
    fs::create_dir_all(&loki_dir)
        .with_context(|| format!("create snapshot directory: {}", loki_dir.display()))?;

    // ── Serialize red state ──────────────────────────────────────────────
    // SharedRedTeamState doesn't derive Serialize, so we build the
    // SavedRedState-compatible JSON manually from its Serialize-derived fields.
    let red_state_json = serialize_red_state(&state);
    let red_state_path = snapshot_dir.join("red-state.json");
    fs::write(
        &red_state_path,
        serde_json::to_string_pretty(&red_state_json)?,
    )
    .context("write red-state.json")?;
    info!("wrote {}", red_state_path.display());

    // ── Generate ground truth ────────────────────────────────────────────
    let techniques: Vec<String> = state.all_techniques.clone();
    let ground_truth = create_ground_truth_from_red_state(&state, &techniques);
    let gt_path = snapshot_dir.join("ground-truth.json");
    fs::write(&gt_path, serde_json::to_string_pretty(&ground_truth)?)
        .context("write ground-truth.json")?;
    info!("wrote {}", gt_path.display());

    // ── Export Loki streams ──────────────────────────────────────────────
    let loki_config = BulkLokiConfig::from_env();
    info!("Loki endpoint: {}", loki_config.base_url);

    let all_jobs =
        loki_bulk::export_label_values(&loki_config, "job", export_start, export_end).await?;

    // Filter to attack-simulation namespace streams — the full cluster can have
    // hundreds of irrelevant streams (argocd, observability, etc.).
    let jobs: Vec<String> = all_jobs
        .into_iter()
        .filter(|j| j.starts_with("attack-simulation/"))
        .collect();

    if jobs.is_empty() {
        info!("no Loki streams found in capture window (filtered to attack-simulation/) — snapshot will have no log data");
    } else {
        info!("discovered {} Loki stream(s): {:?}", jobs.len(), jobs);
    }

    let mut streams: Vec<StreamEntry> = Vec::new();
    let mut total_entries: u64 = 0;

    for job in &jobs {
        let selector = format!("{{job=\"{job}\"}}");
        // Sanitize job name: replace slashes with underscores for flat file names
        let safe_name = job.replace('/', "_");
        let file_name = format!("{safe_name}.jsonl");
        let file_path = loki_dir.join(&file_name);

        let file = fs::File::create(&file_path)
            .with_context(|| format!("create {}", file_path.display()))?;
        let mut writer = BufWriter::new(file);

        info!("exporting stream {selector}");
        let entries =
            loki_bulk::export_stream(&loki_config, &selector, export_start, export_end, &mut writer)
                .await
                .with_context(|| format!("export stream {selector}"))?;

        info!("  {job}: {entries} entries");
        total_entries += entries;

        streams.push(StreamEntry {
            job: job.clone(),
            selector,
            file: format!("loki/{file_name}"),
            entries,
        });
    }

    info!("total: {total_entries} log entries across {} streams", streams.len());

    // ── Export fired Grafana alerts ──────────────────────────────────────
    let fired_alerts = export_grafana_alerts(export_start, export_end).await?;
    let alerts_path = snapshot_dir.join("fired-alerts.json");
    fs::write(
        &alerts_path,
        serde_json::to_string_pretty(&fired_alerts)?,
    )
    .context("write fired-alerts.json")?;
    info!("captured {} fired alerts", fired_alerts.len());

    // ── Write manifest ──────────────────────────────────────────────────
    let target_domain = state
        .target
        .as_ref()
        .map(|t| t.domain.clone())
        .unwrap_or_default();
    let target_ip = state
        .target
        .as_ref()
        .map(|t| t.ip.clone())
        .unwrap_or_default();

    let manifest = SnapshotManifest {
        version: MANIFEST_VERSION,
        operation_id: op_id.clone(),
        target_domain,
        target_ip,
        started_at: state.started_at,
        completed_at,
        capture_window_start: export_start,
        capture_window_end: export_end,
        streams,
        total_log_entries: total_entries,
        alerts_captured: fired_alerts.len(),
        techniques: state.all_techniques.clone(),
        has_domain_admin: state.has_domain_admin,
        credential_count: state.all_credentials.len(),
        host_count: state.all_hosts.len(),
        captured_at: Utc::now(),
    };

    let manifest_path = snapshot_dir.join("manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest)?,
    )
    .context("write manifest.json")?;
    info!("wrote {}", manifest_path.display());

    // ── Optional S3 sync ─────────────────────────────────────────────────
    if let Some(bucket) = s3_bucket {
        let s3_dest = format!("s3://{bucket}/snapshots/{op_id}/");
        info!("syncing snapshot to {s3_dest}");

        let status = std::process::Command::new("aws")
            .args([
                "s3",
                "sync",
                snapshot_dir.to_str().unwrap_or("."),
                &s3_dest,
                "--quiet",
            ])
            .status()
            .context("run aws s3 sync")?;

        if !status.success() {
            bail!("aws s3 sync failed with exit code {}", status);
        }
        info!("S3 sync complete");
    }

    // ── Summary ─────────────────────────────────────────────────────────
    println!("Snapshot captured: {}", snapshot_dir.display());
    println!("  Operation:    {op_id}");
    println!("  Streams:      {}", manifest.streams.len());
    println!("  Log entries:  {total_entries}");
    println!("  Alerts:       {}", manifest.alerts_captured);
    println!("  Techniques:   {}", manifest.techniques.len());
    println!("  Domain admin: {}", manifest.has_domain_admin);
    println!("  Credentials:  {}", manifest.credential_count);
    println!("  Hosts:        {}", manifest.host_count);

    Ok(())
}

/// Build a SavedRedState-compatible JSON value from SharedRedTeamState.
///
/// Since SharedRedTeamState doesn't derive Serialize, we manually construct
/// the JSON using the individual Serialize-derived model types.
fn serialize_red_state(state: &ares_core::models::SharedRedTeamState) -> serde_json::Value {
    serde_json::json!({
        "operation_id": state.operation_id,
        "target": state.target.as_ref().map(|t| serde_json::json!({
            "ip": t.ip,
            "hostname": t.hostname,
            "domain": t.domain,
        })),
        "all_hosts": state.all_hosts.iter().map(|h| serde_json::json!({
            "ip": h.ip,
            "hostname": h.hostname,
            "os": h.os,
            "roles": h.roles,
            "services": h.services,
            "is_dc": h.is_dc,
            "owned": h.owned,
        })).collect::<Vec<_>>(),
        "all_users": state.all_users.iter().map(|u| serde_json::json!({
            "username": u.username,
            "domain": u.domain,
            "is_admin": u.is_admin,
            "source": u.source,
        })).collect::<Vec<_>>(),
        "all_credentials": state.all_credentials.iter().map(|c| serde_json::json!({
            "username": c.username,
            "domain": c.domain,
            "source": c.source,
            "is_admin": c.is_admin,
        })).collect::<Vec<_>>(),
        "all_hashes": state.all_hashes.iter().map(|h| serde_json::json!({
            "username": h.username,
            "hash_value": h.hash_value,
            "hash_type": h.hash_type,
            "domain": h.domain,
            "source": h.source,
        })).collect::<Vec<_>>(),
        "all_shares": state.all_shares.iter().map(|s| serde_json::json!({
            "host": s.host,
            "name": s.name,
            "permissions": s.permissions,
        })).collect::<Vec<_>>(),
        "all_domains": state.all_domains,
        "has_domain_admin": state.has_domain_admin,
        "has_golden_ticket": state.has_golden_ticket,
        "domain_admin_path": state.domain_admin_path,
        "identified_techniques": state.all_techniques,
        // Extra fields for replay (not in SavedRedState but useful)
        "started_at": state.started_at.to_rfc3339(),
        "completed_at": state.completed_at.map(|t| t.to_rfc3339()),
        "target_ips": state.target_ips,
    })
}

/// Export fired Grafana alerts in the capture window via the annotations API.
///
/// Falls back gracefully if Grafana is not configured.
async fn export_grafana_alerts(
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<FiredAlert>> {
    let grafana_url = match std::env::var("GRAFANA_URL") {
        Ok(url) => url,
        Err(_) => {
            info!("GRAFANA_URL not set — skipping alert export");
            return Ok(Vec::new());
        }
    };
    let api_key = std::env::var("GRAFANA_SERVICE_ACCOUNT_TOKEN").ok();

    let from_ms = start.timestamp_millis();
    let to_ms = end.timestamp_millis();

    let url = format!(
        "{grafana_url}/api/annotations?from={from_ms}&to={to_ms}&type=alert&limit=1000"
    );

    let client = reqwest::Client::new();
    let mut req = client.get(&url);
    if let Some(key) = &api_key {
        req = req.bearer_auth(key);
    }

    let resp = req.send().await.context("query Grafana annotations API")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        info!("Grafana annotations API returned {status}: {body}");
        return Ok(Vec::new());
    }

    let annotations: Vec<serde_json::Value> = resp.json().await.context("parse annotations")?;
    let mut alerts = Vec::new();

    for ann in &annotations {
        let alert_name = ann
            .get("alertName")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let time_ms = ann.get("time").and_then(|v| v.as_i64()).unwrap_or(0);
        let fired_at = chrono::DateTime::from_timestamp_millis(time_ms)
            .unwrap_or_else(|| chrono::Utc::now());

        // Extract labels from tags array (format: "key:value" or "key=value")
        let mut labels = serde_json::Map::new();
        if let Some(tags) = ann.get("tags").and_then(|t| t.as_array()) {
            for tag in tags {
                if let Some(tag_str) = tag.as_str() {
                    if let Some((k, v)) = tag_str.split_once(':').or_else(|| tag_str.split_once('='))
                    {
                        labels.insert(k.to_string(), serde_json::Value::String(v.to_string()));
                    }
                }
            }
        }
        labels.insert(
            "alertname".to_string(),
            serde_json::Value::String(alert_name.clone()),
        );

        let mut annotations_map = serde_json::Map::new();
        if let Some(text) = ann.get("text").and_then(|v| v.as_str()) {
            annotations_map.insert(
                "summary".to_string(),
                serde_json::Value::String(text.to_string()),
            );
        }

        alerts.push(FiredAlert {
            alert_name,
            fired_at,
            labels: serde_json::Value::Object(labels),
            annotations: serde_json::Value::Object(annotations_map),
        });
    }

    // Sort by fire time
    alerts.sort_by_key(|a| a.fired_at);

    Ok(alerts)
}
