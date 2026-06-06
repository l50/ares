//! Remote hashcat backend.
//!
//! When `HASHCAT_SERVICE_URL` (and `HASHCAT_TOKEN`) are set in the cracker
//! agent's env, [`crack_with_hashcat`](super::crack_with_hashcat) delegates to
//! an HTTP service instead of spawning hashcat locally. The remote service
//! owns the GPU and the wordlist directory; the agent becomes a thin client.
//!
//! Expected service contract:
//! - `POST /jobs` with `{hash_mode, attack_mode, hashes[], wordlist?, rules?, mask?}`
//!   and `Authorization: Bearer <token>` → `{job_id, status}`.
//! - `GET  /jobs/{id}` → `{status, log_tail?, error?}` where status is one of
//!   `starting | running | done | error`.
//! - `GET  /jobs/{id}/potfile` → `{cracked: ["<hash>:<plaintext>", ...]}`.
//!
//! Cascade: a bare wordlist pass first; if that exhausts without cracking and
//! there is time budget left, retry once with a rules file (default `best66.rule`,
//! override via `HASHCAT_REMOTE_RULES`). This recovers most of the local
//! `crack_with_hashcat` rules behavior over the wire. Dynamic username
//! wordlists stay local-only.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::args::{optional_i64, optional_str, required_str};
use crate::ToolOutput;

use super::{detect_hashcat_mode, DEFAULT_MAX_TIME_MINUTES};

const DEFAULT_REMOTE_WORDLIST: &str = "rockyou.txt";
const DEFAULT_REMOTE_RULES: &str = "best66.rule";
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
    rules: Option<String>,
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

/// Outcome of a single submit→poll→potfile cycle against crackd.
struct StageOutcome {
    cracked: Vec<String>,
    log_tail: String,
    terminal_status: String,
    error: Option<String>,
    timed_out: bool,
}

/// Run one submit→poll→potfile attempt with the given submission and an
/// upper bound on wall clock spent polling. Returns whatever state the
/// service reports — caller decides whether to advance to the next stage.
async fn run_stage(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    submission: &JobSubmission<'_>,
    budget_secs: u64,
) -> Result<StageOutcome> {
    let resp = client
        .post(format!("{url}/jobs"))
        .bearer_auth(token)
        .json(submission)
        .send()
        .await
        .context("crackd: failed to POST /jobs")?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Ok(StageOutcome {
            cracked: Vec::new(),
            log_tail: String::new(),
            terminal_status: "error".into(),
            error: Some(format!("crackd submission failed ({status}): {body}")),
            timed_out: false,
        });
    }
    let job_id = serde_json::from_str::<JobIdResponse>(&body)
        .context("crackd: unexpected /jobs response shape")?
        .job_id;

    let started = Instant::now();
    let (terminal_status, last_log, last_error, timed_out) = loop {
        let resp = client
            .get(format!("{url}/jobs/{job_id}"))
            .bearer_auth(token)
            .send()
            .await
            .context("crackd: failed to GET /jobs/{id}")?;
        let body = resp.text().await.unwrap_or_default();
        let state: JobStateResponse =
            serde_json::from_str(&body).context("crackd: unexpected /jobs/{id} response shape")?;
        if matches!(state.status.as_str(), "done" | "error") {
            break (state.status, state.log_tail, state.error, false);
        }
        if started.elapsed().as_secs() > budget_secs {
            break (state.status, state.log_tail, state.error, true);
        }
        tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
    };

    let potfile: PotfileResponse = client
        .get(format!("{url}/jobs/{job_id}/potfile"))
        .bearer_auth(token)
        .send()
        .await
        .context("crackd: failed to GET /jobs/{id}/potfile")?
        .json()
        .await
        .unwrap_or_default();

    Ok(StageOutcome {
        cracked: potfile.cracked,
        log_tail: last_log,
        terminal_status,
        error: last_error,
        timed_out,
    })
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
    let rules_name = std::env::var("HASHCAT_REMOTE_RULES")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_REMOTE_RULES.to_string());

    let client = http_client();
    let url = base_url.trim_end_matches('/');
    let overall_started = Instant::now();
    let mut transcript = String::new();
    let mut last_error: Option<String> = None;

    // Stage 1: bare wordlist.
    let stage1 = run_stage(
        &client,
        url,
        &token,
        &JobSubmission {
            hash_mode: mode,
            attack_mode: 0,
            hashes: vec![hash_value],
            wordlist: Some(wordlist.clone()),
            rules: None,
            mask: None,
        },
        max_time_secs,
    )
    .await?;
    transcript.push_str(&format!(
        "--- crackd stage 1 (wordlist={wordlist}, status={}) ---\n{}\n",
        stage1.terminal_status, stage1.log_tail
    ));
    if stage1.error.is_some() {
        last_error = stage1.error.clone();
    }
    if !stage1.cracked.is_empty() || stage1.timed_out {
        return Ok(ToolOutput {
            stdout: format_result_stdout(
                &stage1.cracked,
                &transcript,
                &format!("wordlist={wordlist}"),
            ),
            stderr: last_error.unwrap_or_default(),
            exit_code: Some(if !stage1.cracked.is_empty() { 0 } else { 124 }),
            success: !stage1.cracked.is_empty(),
        });
    }
    // If stage 1 errored (submission failed or hashcat exited badly), stage 2
    // would almost certainly repeat the same failure against the same service.
    // Surface the error now rather than doubling the noise in the transcript.
    if stage1.terminal_status == "error" {
        return Ok(ToolOutput {
            stdout: transcript,
            stderr: last_error.unwrap_or_default(),
            exit_code: Some(1),
            success: false,
        });
    }

    // Stage 2: rules pass against remaining budget.
    let elapsed = overall_started.elapsed().as_secs();
    let remaining = max_time_secs.saturating_sub(elapsed);
    if remaining < POLL_INTERVAL_SECS {
        return Ok(ToolOutput {
            stdout: transcript,
            stderr: last_error.unwrap_or_default(),
            exit_code: Some(1),
            success: false,
        });
    }
    let stage2 = run_stage(
        &client,
        url,
        &token,
        &JobSubmission {
            hash_mode: mode,
            attack_mode: 0,
            hashes: vec![hash_value],
            wordlist: Some(wordlist.clone()),
            rules: Some(rules_name.clone()),
            mask: None,
        },
        remaining,
    )
    .await?;
    transcript.push_str(&format!(
        "--- crackd stage 2 (wordlist={wordlist}, rules={rules_name}, status={}) ---\n{}\n",
        stage2.terminal_status, stage2.log_tail
    ));
    if stage2.error.is_some() {
        last_error = stage2.error.clone();
    }

    let cracked = stage2.cracked;
    let success = !cracked.is_empty();
    let exit_code = if success {
        0
    } else if stage2.timed_out {
        124
    } else {
        1
    };
    Ok(ToolOutput {
        stdout: format_result_stdout(
            &cracked,
            &transcript,
            &format!("wordlist={wordlist}, rules={rules_name}"),
        ),
        stderr: last_error.unwrap_or_default(),
        exit_code: Some(exit_code),
        success,
    })
}

/// Render the crack_with_hashcat stdout with an unambiguous leading header.
///
/// The header names the tool and backend ("crack_with_hashcat via remote
/// crackd") and lists the cracked `hash:plaintext` lines up front so the
/// LLM cannot mis-attribute the result to another backend later. The full
/// stage transcript and raw potfile follow for debugging.
fn format_result_stdout(cracked: &[String], transcript: &str, attempt_desc: &str) -> String {
    let header = if cracked.is_empty() {
        format!(
            "RESULT: crack_with_hashcat via remote crackd — 0 hashes cracked ({attempt_desc})\n"
        )
    } else {
        let mut out = format!(
            "SUCCESS: crack_with_hashcat via remote crackd — {} hash(es) cracked ({attempt_desc})\nCracked credentials:\n",
            cracked.len(),
        );
        for line in cracked {
            out.push_str("  ");
            out.push_str(line);
            out.push('\n');
        }
        out
    };
    format!(
        "{header}\n{transcript}--- crackd potfile ---\n{}",
        cracked.join("\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submission_with_rules_serializes_field() {
        let s = JobSubmission {
            hash_mode: 13100,
            attack_mode: 0,
            hashes: vec!["$krb5tgs$23$..."],
            wordlist: Some("rockyou.txt".into()),
            rules: Some("best66.rule".into()),
            mask: None,
        };
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["rules"], "best66.rule");
        assert_eq!(json["wordlist"], "rockyou.txt");
        assert!(json.get("mask").is_none());
    }

    #[test]
    fn format_result_stdout_leads_with_unambiguous_success_header() {
        let cracked = vec!["$krb5tgs$23$*alice$REALM$spn*$xyz:P@ssw0rd1!".to_string()];
        let transcript = "--- crackd stage 1 (wordlist=rockyou.txt, status=done) ---\nSession..........: crackd-abc\n";
        let out = format_result_stdout(&cracked, transcript, "wordlist=rockyou.txt");
        assert!(
            out.starts_with(
                "SUCCESS: crack_with_hashcat via remote crackd — 1 hash(es) cracked (wordlist=rockyou.txt)"
            ),
            "got: {out}"
        );
        assert!(
            out.contains("Cracked credentials:\n  $krb5tgs$23$*alice$REALM$spn*$xyz:P@ssw0rd1!\n"),
            "must list the cracked entry up front"
        );
        // Transcript and raw potfile still present for debugging
        assert!(out.contains("--- crackd stage 1"));
        assert!(out.contains("--- crackd potfile ---"));
    }

    #[test]
    fn format_result_stdout_empty_when_no_cracks() {
        let out = format_result_stdout(&[], "transcript\n", "wordlist=rockyou.txt");
        assert!(out.starts_with(
            "RESULT: crack_with_hashcat via remote crackd — 0 hashes cracked (wordlist=rockyou.txt)"
        ));
    }

    #[test]
    fn submission_without_rules_omits_field() {
        let s = JobSubmission {
            hash_mode: 1000,
            attack_mode: 0,
            hashes: vec!["aad3b435"],
            wordlist: Some("rockyou.txt".into()),
            rules: None,
            mask: None,
        };
        let json = serde_json::to_value(&s).unwrap();
        assert!(
            json.get("rules").is_none(),
            "rules must be skipped when None"
        );
    }
}
