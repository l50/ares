//! Remote hashcat backend.
//!
//! When `HASHCAT_SERVICE_URL` (and `HASHCAT_TOKEN`) are set in the cracker
//! agent's env, [`crack_with_hashcat`](super::crack_with_hashcat) delegates to
//! an HTTP service instead of spawning hashcat locally. The remote service
//! owns the GPU and the wordlist directory; the agent becomes a thin client.
//!
//! Expected service contract:
//! - `POST /jobs` with `{hash_mode, attack_mode, hashes[], wordlist?, mask?}`
//!   and `Authorization: Bearer <token>` → `{job_id, status}`.
//! - `GET  /jobs/{id}` → `{status, log_tail?, error?}` where status is one of
//!   `starting | running | done | error`.
//! - `GET  /jobs/{id}/potfile` → `{cracked: ["<hash>:<plaintext>", ...]}`.
//!
//! Scope of remote mode: wordlist attack (`-a 0`) with a single wordlist by
//! basename. Rules-based and dynamic username wordlists stay local-only —
//! the service's wordlist directory is its own concern.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::args::{optional_i64, optional_str, required_str};
use crate::ToolOutput;

use super::{detect_hashcat_mode, DEFAULT_MAX_TIME_MINUTES};

const DEFAULT_REMOTE_WORDLIST: &str = "rockyou.txt";
const POLL_INTERVAL_SECS: u64 = 5;

/// Returns the configured remote service URL, or `None` if remote mode is off.
pub(super) fn service_url() -> Option<String> {
    std::env::var("HASHCAT_SERVICE_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

fn service_token() -> Result<String> {
    std::env::var("HASHCAT_TOKEN")
        .context("HASHCAT_SERVICE_URL is set but HASHCAT_TOKEN is missing")
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap_or_default()
}

#[derive(Serialize)]
struct JobSubmission<'a> {
    hash_mode: i64,
    attack_mode: i64,
    hashes: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wordlist: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mask: Option<&'a str>,
}

#[derive(Deserialize)]
struct JobIdResponse {
    job_id: String,
}

#[derive(Deserialize)]
struct JobStateResponse {
    status: String,
    #[serde(default)]
    log_tail: String,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize, Default)]
struct PotfileResponse {
    #[serde(default)]
    cracked: Vec<String>,
}

/// Take the basename of a path. Remote services typically refuse absolute
/// paths and only accept filenames within their own wordlist directory.
fn basename(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path)
        .to_string()
}

pub(super) async fn crack(args: &Value, base_url: &str) -> Result<ToolOutput> {
    let hash_value = required_str(args, "hash_value")?;
    let token = service_token()?;
    let mode =
        optional_i64(args, "hashcat_mode").unwrap_or_else(|| detect_hashcat_mode(hash_value));
    let max_time_minutes = optional_i64(args, "max_time_minutes")
        .unwrap_or(DEFAULT_MAX_TIME_MINUTES)
        .max(DEFAULT_MAX_TIME_MINUTES);
    let max_time_secs = (max_time_minutes * 60) as u64;
    let wordlist = optional_str(args, "wordlist_path")
        .map(basename)
        .unwrap_or_else(|| DEFAULT_REMOTE_WORDLIST.to_string());

    let client = http_client();
    let url = base_url.trim_end_matches('/');

    let submission = JobSubmission {
        hash_mode: mode,
        attack_mode: 0,
        hashes: vec![hash_value],
        wordlist: Some(wordlist),
        mask: None,
    };

    // Submit.
    let job_id = {
        let resp = client
            .post(format!("{url}/jobs"))
            .bearer_auth(&token)
            .json(&submission)
            .send()
            .await
            .context("crackd: failed to POST /jobs")?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Ok(ToolOutput {
                stdout: String::new(),
                stderr: format!("crackd submission failed ({status}): {body}"),
                exit_code: Some(1),
                success: false,
            });
        }
        serde_json::from_str::<JobIdResponse>(&body)
            .context("crackd: unexpected /jobs response shape")?
            .job_id
    };

    // Poll.
    let started = Instant::now();
    let (terminal_status, last_log, last_error) = loop {
        let resp = client
            .get(format!("{url}/jobs/{job_id}"))
            .bearer_auth(&token)
            .send()
            .await
            .context("crackd: failed to GET /jobs/{id}")?;
        let body = resp.text().await.unwrap_or_default();
        let state: JobStateResponse =
            serde_json::from_str(&body).context("crackd: unexpected /jobs/{id} response shape")?;
        if matches!(state.status.as_str(), "done" | "error") {
            break (state.status, state.log_tail, state.error);
        }
        if started.elapsed().as_secs() > max_time_secs {
            return Ok(ToolOutput {
                stdout: state.log_tail,
                stderr: format!("crackd job {job_id} exceeded {max_time_secs}s budget"),
                exit_code: Some(124),
                success: false,
            });
        }
        tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
    };

    // Pull potfile — partial cracks are useful even on error.
    let potfile: PotfileResponse = {
        let resp = client
            .get(format!("{url}/jobs/{job_id}/potfile"))
            .bearer_auth(&token)
            .send()
            .await
            .context("crackd: failed to GET /jobs/{id}/potfile")?;
        resp.json().await.unwrap_or_default()
    };

    let stdout = format!(
        "{last_log}\n--- crackd potfile ---\n{}",
        potfile.cracked.join("\n")
    );
    let success = terminal_status == "done";

    Ok(ToolOutput {
        stdout,
        stderr: last_error.unwrap_or_default(),
        exit_code: Some(if success { 0 } else { 1 }),
        success,
    })
}
