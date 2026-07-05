//! Snapshot capture pipeline.
//!
//! Connects to Redis, loads the completed red team state, syncs Loki chunks
//! from S3 for the capture window, exports fired Grafana alerts, generates
//! ground truth, and writes everything into a self-contained snapshot directory.
//! Automatically uploads the snapshot to the benchmark S3 bucket.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use anyhow::{bail, Context, Result};
use chrono::{Duration, Utc};
use tracing::info;

use ares_core::eval::ground_truth::create_ground_truth_from_red_state;
use ares_core::state::RedisStateReader;

use crate::redis_conn::{connect_redis, resolve_operation_id};

use super::manifest::{FiredAlert, SnapshotManifest, MANIFEST_VERSION};

/// S3 bucket where Loki stores chunks and index (infra account).
const LOKI_S3_BUCKET: &str = "dev-argonaut-loki";
/// AWS region for the Loki S3 bucket.
const LOKI_S3_REGION: &str = "us-west-2";
/// AWS CLI profile for infrastructure account access.
const LOKI_S3_PROFILE: &str = "infrastructure";

/// Default benchmark S3 bucket in the labs account.
const DEFAULT_BENCHMARK_BUCKET: &str = "ares-benchmark-us-west-1";
/// Default AWS profile for the labs account.
const DEFAULT_BENCHMARK_PROFILE: &str = "lab";
/// Default AWS region for the labs account.
const DEFAULT_BENCHMARK_REGION: &str = "us-west-1";

/// Run the `benchmark capture` command.
pub(crate) async fn run_capture(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
    output_dir: &str,
    pre_window_hours: u32,
    post_window_minutes: u32,
    no_upload: bool,
) -> Result<()> {
    eprint!("[1/8] Loading operation state from Redis...");
    let _ = std::io::stderr().flush();
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
    eprintln!(" done ({op_id})");

    let export_start = state.started_at - Duration::hours(pre_window_hours as i64);
    let export_end = completed_at + Duration::minutes(post_window_minutes as i64);

    info!(
        "capture window: {} to {} (pre={}h, post={}m)",
        export_start.to_rfc3339(),
        export_end.to_rfc3339(),
        pre_window_hours,
        post_window_minutes,
    );

    let snapshot_dir = Path::new(output_dir).join(&op_id);
    let loki_dir = snapshot_dir.join("loki");
    fs::create_dir_all(&loki_dir)
        .with_context(|| format!("create snapshot directory: {}", loki_dir.display()))?;
    // Prometheus metrics + Grafana dashboards/annotations live in their own
    // subdirs; create_dir_all on grafana/dashboards also creates grafana/.
    let prometheus_dir = snapshot_dir.join("prometheus");
    fs::create_dir_all(&prometheus_dir)
        .with_context(|| format!("create prometheus directory: {}", prometheus_dir.display()))?;
    let dashboards_dir = snapshot_dir.join("grafana").join("dashboards");
    fs::create_dir_all(&dashboards_dir)
        .with_context(|| format!("create dashboards directory: {}", dashboards_dir.display()))?;

    let red_state_json = serialize_red_state(&state);
    let red_state_path = snapshot_dir.join("red-state.json");
    fs::write(
        &red_state_path,
        serde_json::to_string_pretty(&red_state_json)?,
    )
    .context("write red-state.json")?;
    info!("wrote {}", red_state_path.display());

    let techniques: Vec<String> = state.all_techniques.clone();
    let ground_truth = create_ground_truth_from_red_state(&state, &techniques);
    let gt_path = snapshot_dir.join("ground-truth.json");
    fs::write(&gt_path, serde_json::to_string_pretty(&ground_truth)?)
        .context("write ground-truth.json")?;
    info!("wrote {}", gt_path.display());

    eprint!("[2/8] Syncing Loki chunks from S3...");
    let _ = std::io::stderr().flush();
    let (chunk_count, index_count) = sync_loki_s3(&loki_dir, export_start, export_end).await?;
    eprintln!(" done ({chunk_count} chunks, {index_count} index files)");

    info!("synced {chunk_count} chunks + {index_count} index files from S3");

    eprint!("[3/8] Exporting Grafana alerts...");
    let _ = std::io::stderr().flush();
    let fired_alerts = export_grafana_alerts(export_start, export_end).await?;
    eprintln!(" done ({} alerts)", fired_alerts.len());
    let alerts_path = snapshot_dir.join("fired-alerts.json");
    fs::write(&alerts_path, serde_json::to_string_pretty(&fired_alerts)?)
        .context("write fired-alerts.json")?;
    info!("captured {} fired alerts", fired_alerts.len());

    eprint!("[4/8] Exporting Prometheus metrics...");
    let _ = std::io::stderr().flush();
    // Metrics only over a bounded window around the attack (the agent's
    // clock-anchored Prometheus queries land here) — the full padded log
    // window × every metric series would be gigabytes.
    let metrics_start = state.started_at - Duration::minutes(30);
    let metrics_end = completed_at + Duration::minutes(30);
    let metrics_series = export_prometheus_metrics(&snapshot_dir, metrics_start, metrics_end).await;
    eprintln!(" done ({metrics_series} series)");
    info!("captured {metrics_series} Prometheus series");

    eprint!("[5/8] Exporting Grafana dashboards...");
    let _ = std::io::stderr().flush();
    let dashboards_captured = export_dashboards(&snapshot_dir).await;
    eprintln!(" done ({dashboards_captured} dashboards)");
    info!("captured {dashboards_captured} dashboards");

    eprint!("[6/8] Exporting all annotations...");
    let _ = std::io::stderr().flush();
    let annotations_captured =
        export_all_annotations(&snapshot_dir, export_start, export_end).await;
    eprintln!(" done ({annotations_captured} annotations)");
    info!("captured {annotations_captured} annotations");

    eprint!("[7/8] Writing manifest and ground truth...");
    let _ = std::io::stderr().flush();
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
        loki_source: "s3-chunks".to_string(),
        loki_chunks: chunk_count,
        loki_index_files: index_count,
        alerts_captured: fired_alerts.len(),
        metrics_series,
        dashboards_captured,
        annotations_captured,
        techniques: state.all_techniques.clone(),
        has_domain_admin: state.has_domain_admin,
        credential_count: state.all_credentials.len(),
        host_count: state.all_hosts.len(),
        captured_at: Utc::now(),
    };

    let manifest_path = snapshot_dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)
        .context("write manifest.json")?;
    info!("wrote {}", manifest_path.display());
    eprintln!(" done");

    if !no_upload {
        let bucket = std::env::var("BENCHMARK_S3_BUCKET")
            .unwrap_or_else(|_| DEFAULT_BENCHMARK_BUCKET.to_string());
        let profile = std::env::var("BENCHMARK_AWS_PROFILE")
            .unwrap_or_else(|_| DEFAULT_BENCHMARK_PROFILE.to_string());
        let region = std::env::var("BENCHMARK_AWS_REGION")
            .unwrap_or_else(|_| DEFAULT_BENCHMARK_REGION.to_string());

        let s3_dest = format!("s3://{bucket}/snapshots/{op_id}/");
        eprint!("[8/8] Uploading snapshot to {s3_dest}...");
        let _ = std::io::stderr().flush();
        info!("uploading snapshot to {s3_dest}");

        let status = std::process::Command::new("aws")
            .args([
                "s3",
                "sync",
                snapshot_dir.to_str().unwrap_or("."),
                &s3_dest,
                "--profile",
                &profile,
                "--region",
                &region,
                "--quiet",
            ])
            .status()
            .context("aws s3 sync to benchmark bucket")?;

        if !status.success() {
            bail!("aws s3 sync to {s3_dest} failed with exit code {status}");
        }
        eprintln!(" done");
        info!("S3 upload complete: {s3_dest}");
    } else {
        eprintln!("[8/8] Skipping S3 upload (--no-upload)");
    }

    println!("Snapshot captured: {}", snapshot_dir.display());
    println!("  Operation:    {op_id}");
    println!("  Loki chunks:  {chunk_count}");
    println!("  Index files:  {index_count}");
    println!("  Alerts:       {}", manifest.alerts_captured);
    println!("  Metrics:      {}", manifest.metrics_series);
    println!("  Dashboards:   {}", manifest.dashboards_captured);
    println!("  Annotations:  {}", manifest.annotations_captured);
    println!("  Techniques:   {}", manifest.techniques.len());
    println!("  Domain admin: {}", manifest.has_domain_admin);
    println!("  Credentials:  {}", manifest.credential_count);
    println!("  Hosts:        {}", manifest.host_count);
    if !no_upload {
        let bucket = std::env::var("BENCHMARK_S3_BUCKET")
            .unwrap_or_else(|_| DEFAULT_BENCHMARK_BUCKET.to_string());
        println!("  S3:           s3://{bucket}/snapshots/{op_id}/");
    }

    Ok(())
}

/// Sync Loki S3 chunks and index files for the given time window.
///
/// 1. Lists all chunk objects modified in the date range.
/// 2. Filters chunks whose hex-encoded start/end timestamps overlap the window.
/// 3. Downloads matching chunks and relevant index files in parallel via `aws s3 cp`.
///
/// Returns `(chunk_count, index_count)`.
async fn sync_loki_s3(
    loki_dir: &Path,
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
) -> Result<(u64, u64)> {
    let chunks_dir = loki_dir.join("fake");
    let index_dir = loki_dir.join("index");
    fs::create_dir_all(&chunks_dir).context("create chunks dir")?;
    fs::create_dir_all(&index_dir).context("create index dir")?;

    let start_ms = start.timestamp_millis();
    let end_ms = end.timestamp_millis();

    // Index tables are 24h periods keyed by days since epoch.
    let start_table = start
        .date_naive()
        .signed_duration_since(chrono::NaiveDate::from_ymd_opt(1970, 1, 1).unwrap())
        .num_days();
    let end_table = end
        .date_naive()
        .signed_duration_since(chrono::NaiveDate::from_ymd_opt(1970, 1, 1).unwrap())
        .num_days();

    let mut index_count: u64 = 0;
    for table in start_table..=end_table {
        let prefix = format!("index/loki_index_{table}/");
        let local_index = index_dir.join(format!("loki_index_{table}"));
        fs::create_dir_all(&local_index)?;

        info!("syncing index table {table} from s3://{LOKI_S3_BUCKET}/{prefix}");
        let status = std::process::Command::new("aws")
            .args([
                "s3",
                "sync",
                &format!("s3://{LOKI_S3_BUCKET}/{prefix}"),
                local_index.to_str().unwrap(),
                "--profile",
                LOKI_S3_PROFILE,
                "--region",
                LOKI_S3_REGION,
                "--quiet",
            ])
            .status()
            .context("aws s3 sync index")?;
        if !status.success() {
            bail!("failed to sync index table {table}");
        }
        let count = fs::read_dir(&local_index)
            .map(|rd| rd.flatten().count() as u64)
            .unwrap_or(0);
        // Also count in subdirectories (e.g., fake/)
        let count_nested = walkdir_count(&local_index);
        index_count += count.max(count_nested);
    }

    // Use aws s3api list-objects-v2 with JSON output, filter by
    // LastModified falling in our date range.
    let list_start = start.format("%Y-%m-%d").to_string();
    // End date + 1 day to capture objects modified on the end date
    let list_end = (end + Duration::days(1)).format("%Y-%m-%d").to_string();

    info!("listing chunks modified between {list_start} and {list_end}");

    let output = std::process::Command::new("aws")
        .args([
            "s3api",
            "list-objects-v2",
            "--bucket",
            LOKI_S3_BUCKET,
            "--prefix",
            "fake/",
            "--profile",
            LOKI_S3_PROFILE,
            "--region",
            LOKI_S3_REGION,
            "--query",
            &format!("Contents[?LastModified>='{list_start}' && LastModified<'{list_end}'].Key"),
            "--output",
            "json",
        ])
        .output()
        .context("aws s3api list-objects-v2")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("s3api list-objects-v2 failed: {stderr}");
    }

    let keys: Vec<String> = serde_json::from_slice(&output.stdout).context("parse s3api output")?;

    info!("found {} chunk objects in date range", keys.len());

    let mut matching_keys: Vec<String> = Vec::new();
    for key in &keys {
        let parts: Vec<&str> = key.split('/').collect();
        if parts.len() < 3 {
            continue;
        }
        let chunk_name = parts[2];
        let ts_parts: Vec<&str> = chunk_name.split(':').collect();
        if ts_parts.len() < 2 {
            continue;
        }
        let Ok(chunk_start) = i64::from_str_radix(ts_parts[0], 16) else {
            continue;
        };
        let Ok(chunk_end) = i64::from_str_radix(ts_parts[1], 16) else {
            continue;
        };
        // Overlap: chunk_end >= window_start AND chunk_start <= window_end
        if chunk_end >= start_ms && chunk_start <= end_ms {
            matching_keys.push(key.clone());
        }
    }

    info!(
        "{} chunks overlap the capture window ({} filtered out)",
        matching_keys.len(),
        keys.len() - matching_keys.len()
    );

    // Write keys to a temp file and use a shell script for parallel download.
    let keys_file = loki_dir.join(".chunk_keys.txt");
    fs::write(&keys_file, matching_keys.join("\n")).context("write chunk keys file")?;

    let script = format!(
        r#"
DEST="{dest}"
BUCKET="{bucket}"
PROFILE="{profile}"
REGION="{region}"
TOTAL=$(wc -l < "{keys_file}" | tr -d ' ')
COUNT=0
while IFS= read -r key; do
    COUNT=$((COUNT + 1))
    dir="$DEST/$(dirname "$key")"
    mkdir -p "$dir"
    aws s3 cp "s3://$BUCKET/$key" "$DEST/$key" --profile "$PROFILE" --region "$REGION" --quiet &
    if (( COUNT % 20 == 0 )); then
        wait
    fi
done < "{keys_file}"
wait
echo "$COUNT"
"#,
        dest = loki_dir.display(),
        bucket = LOKI_S3_BUCKET,
        profile = LOKI_S3_PROFILE,
        region = LOKI_S3_REGION,
        keys_file = keys_file.display(),
    );

    info!(
        "downloading {} chunks (20 parallel)...",
        matching_keys.len()
    );
    let dl_output = std::process::Command::new("bash")
        .arg("-c")
        .arg(&script)
        .output()
        .context("download chunks")?;

    if !dl_output.status.success() {
        let stderr = String::from_utf8_lossy(&dl_output.stderr);
        bail!("chunk download failed: {stderr}");
    }

    let _ = fs::remove_file(&keys_file);

    let chunk_count = matching_keys.len() as u64;
    Ok((chunk_count, index_count))
}

/// Count files recursively under a directory.
fn walkdir_count(dir: &Path) -> u64 {
    let mut count = 0u64;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                count += 1;
            } else if path.is_dir() {
                count += walkdir_count(&path);
            }
        }
    }
    count
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
        // Extra fields for replay
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
    let Ok(grafana_url) = std::env::var("GRAFANA_URL") else {
        info!("GRAFANA_URL not set — skipping alert export");
        return Ok(Vec::new());
    };
    let api_key = std::env::var("GRAFANA_SERVICE_ACCOUNT_TOKEN").ok();

    let from_ms = start.timestamp_millis();
    let to_ms = end.timestamp_millis();

    let url =
        format!("{grafana_url}/api/annotations?from={from_ms}&to={to_ms}&type=alert&limit=5000");

    let client = reqwest::Client::new();
    let mut req = client.get(&url);
    if let Some(key) = &api_key {
        req = req.bearer_auth(key);
    }

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            info!("Grafana request failed (connection error): {e}");
            eprintln!("  warning: Grafana unreachable, continuing without alerts");
            return Ok(Vec::new());
        }
    };

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
        let fired_at =
            chrono::DateTime::from_timestamp_millis(time_ms).unwrap_or_else(chrono::Utc::now);

        // Extract labels from tags array (format: "key:value" or "key=value")
        let mut labels = serde_json::Map::new();
        if let Some(tags) = ann.get("tags").and_then(|t| t.as_array()) {
            for tag in tags {
                if let Some(tag_str) = tag.as_str() {
                    if let Some((k, v)) =
                        tag_str.split_once(':').or_else(|| tag_str.split_once('='))
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

    alerts.sort_by_key(|a| a.fired_at);

    Ok(alerts)
}

/// Resolve the Grafana base URL + optional bearer token from the environment,
/// logging and returning `None` when `GRAFANA_URL` is unset so the caller can
/// skip the export cleanly.
fn grafana_env(purpose: &str) -> Option<(String, Option<String>)> {
    match std::env::var("GRAFANA_URL") {
        Ok(url) => Some((url, std::env::var("GRAFANA_SERVICE_ACCOUNT_TOKEN").ok())),
        Err(_) => {
            info!("GRAFANA_URL not set — skipping {purpose}");
            None
        }
    }
}

/// Attach the Grafana service-account bearer token to a request when present.
fn with_grafana_auth(
    req: reqwest::RequestBuilder,
    api_key: &Option<String>,
) -> reqwest::RequestBuilder {
    match api_key {
        Some(key) => req.bearer_auth(key),
        None => req,
    }
}

/// Export Prometheus metrics over the capture window via the Grafana
/// datasource proxy.
///
/// In-cluster Prometheus is not directly reachable, so we resolve the
/// datasource with `type=="prometheus"` AND `name=="Prometheus"` (not
/// "Mimir"), then range-query all series through
/// `/api/datasources/proxy/uid/{uid}/api/v1/query_range`.
///
/// Writes the raw response body to `{snapshot_dir}/prometheus/metrics.json`
/// and returns the number of series (`.data.result` length), or 0 on any
/// failure. Failures are logged and swallowed (metrics are best-effort), so
/// this never aborts the surrounding capture.
async fn export_prometheus_metrics(
    snapshot_dir: &Path,
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
) -> usize {
    let Some((grafana_url, api_key)) = grafana_env("Prometheus metrics export") else {
        return 0;
    };

    let client = reqwest::Client::new();

    let ds_url = format!("{grafana_url}/api/datasources");
    let ds_resp = match with_grafana_auth(client.get(&ds_url), &api_key)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            info!("Grafana datasources request failed (connection error): {e}");
            eprintln!("  warning: Grafana unreachable, continuing without metrics");
            return 0;
        }
    };
    if !ds_resp.status().is_success() {
        let status = ds_resp.status();
        let body = ds_resp.text().await.unwrap_or_default();
        info!("Grafana datasources API returned {status}: {body}");
        return 0;
    }
    let datasources: Vec<serde_json::Value> = match ds_resp.json().await {
        Ok(v) => v,
        Err(e) => {
            info!("failed to parse Grafana datasources: {e}");
            return 0;
        }
    };
    let uid = datasources.iter().find_map(|ds| {
        let is_prom = ds.get("type").and_then(|v| v.as_str()) == Some("prometheus");
        let is_named = ds.get("name").and_then(|v| v.as_str()) == Some("Prometheus");
        if is_prom && is_named {
            ds.get("uid").and_then(|v| v.as_str()).map(str::to_string)
        } else {
            None
        }
    });
    let Some(uid) = uid else {
        info!("no Prometheus datasource (type=prometheus, name=Prometheus) found — skipping metrics export");
        return 0;
    };

    let names_url =
        format!("{grafana_url}/api/datasources/proxy/uid/{uid}/api/v1/label/__name__/values");
    let names: Vec<String> = match with_grafana_auth(client.get(&names_url), &api_key)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| {
                v.get("data").and_then(|d| d.as_array()).map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
            })
            .unwrap_or_default(),
        Ok(r) => {
            info!("metric-names query returned {}", r.status());
            return 0;
        }
        Err(e) => {
            info!("metric-names query failed: {e}");
            return 0;
        }
    };
    if names.is_empty() {
        info!("no Prometheus metric names returned — skipping metrics export");
        return 0;
    }

    // A single all-series query ({__name__=~".+"}) over the window times out;
    // ~80 names per batch is sub-second. Merge the matrices into one result.
    let query_url = format!("{grafana_url}/api/datasources/proxy/uid/{uid}/api/v1/query_range");
    let start_str = start.to_rfc3339();
    let end_str = end.to_rfc3339();
    const BATCH: usize = 80;
    let total_batches = names.len().div_ceil(BATCH);
    let mut all_series: Vec<serde_json::Value> = Vec::new();
    for (i, chunk) in names.chunks(BATCH).enumerate() {
        let selector = format!(r#"{{__name__=~"{}"}}"#, chunk.join("|"));
        let params: [(&str, &str); 4] = [
            ("query", selector.as_str()),
            ("start", start_str.as_str()),
            ("end", end_str.as_str()),
            // Coarse step: all-series over the window at fine resolution is
            // hundreds of MB of mostly-irrelevant k8s cardinality.
            ("step", "300s"),
        ];
        match with_grafana_auth(client.get(&query_url).query(&params), &api_key)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                if let Ok(v) = r.json::<serde_json::Value>().await {
                    if let Some(res) = v
                        .get("data")
                        .and_then(|d| d.get("result"))
                        .and_then(|r| r.as_array())
                    {
                        all_series.extend(res.iter().cloned());
                    }
                }
            }
            Ok(r) => info!(
                "metrics batch {}/{total_batches} returned {}",
                i + 1,
                r.status()
            ),
            Err(e) => info!("metrics batch {}/{total_batches} failed: {e}", i + 1),
        }
    }

    let merged = serde_json::json!({
        "status": "success",
        "data": { "resultType": "matrix", "result": all_series },
    });
    let serialized = match serde_json::to_string(&merged) {
        Ok(s) => s,
        Err(e) => {
            info!("failed to serialize merged metrics: {e}");
            return 0;
        }
    };
    let metrics_path = snapshot_dir.join("prometheus").join("metrics.json");
    if let Err(e) = fs::write(&metrics_path, serialized) {
        info!("failed to write {}: {e}", metrics_path.display());
        return 0;
    }
    let series = all_series.len();
    info!(
        "wrote {} ({series} series across {total_batches} batches)",
        metrics_path.display()
    );
    series
}

/// Export all Grafana dashboards (`type=dash-db`).
///
/// Lists dashboards via `/api/search`, then fetches each by UID and writes the
/// raw body to `{snapshot_dir}/grafana/dashboards/{uid}.json`. Returns the
/// number of dashboards captured, or 0 on any failure.
async fn export_dashboards(snapshot_dir: &Path) -> usize {
    let Some((grafana_url, api_key)) = grafana_env("dashboard export") else {
        return 0;
    };

    let client = reqwest::Client::new();

    let search_url = format!("{grafana_url}/api/search?type=dash-db&limit=500");
    let search_resp = match with_grafana_auth(client.get(&search_url), &api_key)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            info!("Grafana search request failed (connection error): {e}");
            eprintln!("  warning: Grafana unreachable, continuing without dashboards");
            return 0;
        }
    };
    if !search_resp.status().is_success() {
        let status = search_resp.status();
        let body = search_resp.text().await.unwrap_or_default();
        info!("Grafana search API returned {status}: {body}");
        return 0;
    }
    let items: Vec<serde_json::Value> = match search_resp.json().await {
        Ok(v) => v,
        Err(e) => {
            info!("failed to parse Grafana search response: {e}");
            return 0;
        }
    };

    let dashboards_dir = snapshot_dir.join("grafana").join("dashboards");
    let mut count: usize = 0;
    for item in &items {
        let Some(uid) = item.get("uid").and_then(|v| v.as_str()) else {
            continue;
        };
        let dash_url = format!("{grafana_url}/api/dashboards/uid/{uid}");
        let dash_resp = match with_grafana_auth(client.get(&dash_url), &api_key)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                info!("dashboard {uid} request failed: {e}");
                continue;
            }
        };
        if !dash_resp.status().is_success() {
            info!("dashboard {uid} returned {}", dash_resp.status());
            continue;
        }
        let body = match dash_resp.text().await {
            Ok(b) => b,
            Err(e) => {
                info!("failed to read dashboard {uid} body: {e}");
                continue;
            }
        };
        let path = dashboards_dir.join(format!("{uid}.json"));
        if let Err(e) = fs::write(&path, &body) {
            info!("failed to write {}: {e}", path.display());
            continue;
        }
        count += 1;
    }
    info!("captured {count} dashboards");
    count
}

/// Export all Grafana annotations over the capture window (no type filter).
///
/// Writes the raw response body to `{snapshot_dir}/grafana/annotations.json`
/// and returns the annotation count, or 0 on any failure. This complements the
/// alert-only `fired-alerts.json` export, which is preserved as-is.
async fn export_all_annotations(
    snapshot_dir: &Path,
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
) -> usize {
    let Some((grafana_url, api_key)) = grafana_env("annotation export") else {
        return 0;
    };

    let from_ms = start.timestamp_millis();
    let to_ms = end.timestamp_millis();
    let url = format!("{grafana_url}/api/annotations?from={from_ms}&to={to_ms}&limit=5000");

    let client = reqwest::Client::new();
    let resp = match with_grafana_auth(client.get(&url), &api_key).send().await {
        Ok(r) => r,
        Err(e) => {
            info!("Grafana annotations request failed (connection error): {e}");
            eprintln!("  warning: Grafana unreachable, continuing without annotations");
            return 0;
        }
    };
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        info!("Grafana annotations API returned {status}: {body}");
        return 0;
    }
    let body = match resp.text().await {
        Ok(b) => b,
        Err(e) => {
            info!("failed to read annotations response body: {e}");
            return 0;
        }
    };

    let path = snapshot_dir.join("grafana").join("annotations.json");
    if let Err(e) = fs::write(&path, &body) {
        info!("failed to write {}: {e}", path.display());
        return 0;
    }
    info!("wrote {}", path.display());

    serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .as_ref()
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0)
}
