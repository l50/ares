//! Snapshot manifest and benchmark result schemas.
//!
//! A snapshot is a self-contained directory with everything needed to replay
//! a blue team investigation without the original infrastructure.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Current manifest schema version.
pub const MANIFEST_VERSION: u32 = 1;

/// Manifest for a benchmark snapshot directory.
///
/// Written as `manifest.json` at the root of the snapshot directory.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SnapshotManifest {
    /// Schema version for forward compatibility.
    pub version: u32,

    /// Ares operation ID.
    pub operation_id: String,

    /// Target AD domain.
    pub target_domain: String,

    /// Primary target IP.
    pub target_ip: String,

    /// When the red team operation started.
    pub started_at: DateTime<Utc>,

    /// When the red team operation completed.
    pub completed_at: DateTime<Utc>,

    /// Start of the Loki export window (includes pre-attack buffer).
    pub capture_window_start: DateTime<Utc>,

    /// End of the Loki export window (includes post-attack buffer).
    pub capture_window_end: DateTime<Utc>,

    /// How Loki data was captured ("s3-chunks" or "api-export").
    pub loki_source: String,

    /// Number of Loki chunks synced from S3.
    pub loki_chunks: u64,

    /// Number of Loki index files synced from S3.
    pub loki_index_files: u64,

    /// Number of Grafana alert annotations captured.
    pub alerts_captured: usize,

    /// Number of Prometheus series captured over the window (via Grafana proxy).
    #[serde(default)]
    pub metrics_series: usize,

    /// Number of Grafana dashboards captured.
    #[serde(default)]
    pub dashboards_captured: usize,

    /// Number of Grafana annotations captured (all types, unfiltered).
    #[serde(default)]
    pub annotations_captured: usize,

    /// MITRE ATT&CK technique IDs used in this operation.
    pub techniques: Vec<String>,

    /// Whether domain admin was achieved.
    pub has_domain_admin: bool,

    /// Number of credentials harvested.
    pub credential_count: usize,

    /// Number of hosts discovered.
    pub host_count: usize,

    /// When this snapshot was captured.
    pub captured_at: DateTime<Utc>,
}

/// A Grafana alert that fired during the operation window.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FiredAlert {
    /// Alert rule name.
    pub alert_name: String,

    /// When the alert fired.
    pub fired_at: DateTime<Utc>,

    /// Alert labels (severity, technique, etc.).
    pub labels: serde_json::Value,

    /// Alert annotations (summary, description, etc.).
    pub annotations: serde_json::Value,
}

/// Result of a single benchmark replay run.
///
/// Written to `{output_dir}/{run_id}.json`.
#[derive(Serialize, Deserialize, Debug)]
pub struct BenchmarkResult {
    /// Snapshot operation ID.
    pub snapshot_id: String,

    /// Ares operation ID.
    pub operation_id: String,

    /// Investigation ID for this replay run.
    pub run_id: String,

    /// Replay mode: "static" or "timeline".
    pub replay_mode: String,

    /// How the blue team was triggered ("alert-replay" or "operation").
    pub trigger_mode: String,

    /// Name of the alert that triggered the investigation (if alert-replay).
    pub trigger_alert: Option<String>,

    /// How Loki was provisioned ("ephemeral" or "external").
    pub loki_mode: String,

    /// LLM model used for the blue team.
    pub model: String,

    /// When the benchmark run started.
    pub started_at: DateTime<Utc>,

    /// When the benchmark run completed.
    pub completed_at: DateTime<Utc>,

    /// Seconds of quiet period before first alert (timeline mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quiet_period_secs: Option<f64>,

    /// Time compression factor (timeline mode). 1.0 = real-time, 10.0 = 10x.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_compression: Option<f64>,

    /// Seconds the blue team investigation took.
    pub investigation_duration_secs: f64,

    /// Full evaluation result (from EvaluationResult.to_value()).
    pub evaluation: serde_json::Value,

    /// Gap analysis report in markdown format.
    pub gap_analysis: String,
}
