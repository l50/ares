//! Deterministic baseline detection sweep.
//!
//! Runs the entire detection-template catalog in code, once, BEFORE the
//! orchestrator LLM loop starts, and records the MITRE technique for every
//! template that fires directly into blue investigation state.
//!
//! ## Why this exists
//!
//! The LLM hunter is not a reliable way to guarantee full catalog coverage.
//! Under a finite token/context budget it tends to explore one or two
//! techniques deeply, floods its context with raw Loki output, compacts, and
//! terminates long before it has queried every template. When that happens the
//! techniques a template *would* have caught never get queried, so they never
//! get tagged — the investigation is then graded on partial coverage even
//! though the detections themselves are correct. Prompt nudges ("run the sweep
//! first") don't fix this; the truncation is structural, not a wording problem.
//!
//! The sweep makes catalog coverage deterministic. Every template runs exactly
//! once with bounded concurrency, and any hit is written to blue state
//! regardless of what the LLM later does with its remaining budget. The LLM
//! loop then starts from a recorded baseline (fed in via the task prompt) and
//! spends its budget on the work the sweep can't do — chaining, IOC-level
//! evidence, cross-correlation, timeline, and the verdict — instead of
//! rediscovering detections.
//!
//! Toggle with `ARES_BLUE_DETERMINISTIC_SWEEP=0` to fall back to the pure
//! LLM-driven hunt.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::Semaphore;
use tracing::{info, warn};

use ares_core::detection::detection_config;
use ares_tools::ToolOutput;

/// Default max concurrent Loki detection queries during the sweep. Loki through
/// the Grafana proxy is the bottleneck (~25-40s/query); a handful in flight
/// keeps the wall-clock down without stressing the datasource.
const DEFAULT_SWEEP_CONCURRENCY: usize = 6;

/// Default overall wall-clock cap for the sweep. Whatever fired by the deadline
/// is recorded; the LLM loop still runs and can cover any templates the cap cut
/// off. Comfortably under the runner's 2700s investigation timeout.
const DEFAULT_SWEEP_TIMEOUT_SECS: u64 = 360;

/// Hours of history each detection query scans. The detection runner clamps
/// this to 2 (larger windows time out through the Grafana proxy).
const SWEEP_HOURS_BACK: i64 = 2;

/// A detection template that returned matching events during the sweep.
#[derive(Debug, Clone)]
pub(crate) struct FiredDetection {
    pub template: String,
    pub mitre_id: String,
    pub description: String,
    pub tactic: String,
    pub severity: String,
    pub event_count: usize,
}

/// Result of a baseline sweep — what fired, what came back empty, and what the
/// time cap cut off before it could run.
#[derive(Debug, Default)]
pub(crate) struct SweepOutcome {
    pub templates_total: usize,
    pub fired: Vec<FiredDetection>,
    /// Templates that ran and returned no matches.
    pub no_match: Vec<String>,
    /// Templates the time cap prevented from running (empty on a clean finish).
    pub not_run: Vec<String>,
    pub timed_out: bool,
}

impl SweepOutcome {
    /// Whether the sweep produced anything worth injecting into the prompt.
    pub fn ran(&self) -> bool {
        self.templates_total > 0
    }

    /// Compact, directive summary of the baseline for the orchestrator prompt.
    ///
    /// The point is to seed coverage AND cut token burn: the LLM is told the
    /// catalog is already covered and every fired technique is already
    /// recorded, so it does not re-run detection templates or wade through raw
    /// Loki dumps — it goes straight to depth (chaining, IOCs, timeline,
    /// verdict).
    pub fn prompt_summary(&self) -> String {
        let mut s = String::new();
        s.push_str("## Baseline detection sweep — ALREADY COMPLETED\n\n");
        s.push_str(&format!(
            "A deterministic sweep ran {} detection templates against Loki before you \
             started. Every technique listed as FIRED below is ALREADY recorded as evidence \
             and a MITRE technique in this investigation's state. Do NOT re-run these \
             detection templates — that work is done.\n\n",
            self.templates_total
        ));

        if self.fired.is_empty() {
            s.push_str(
                "FIRED: none. No detection template matched in the scanned window. Investigate \
                 from the alert directly — pull host/user activity around the alert time and \
                 hunt for indicators the templates may not cover.\n\n",
            );
        } else {
            s.push_str(&format!("Detections that FIRED ({}):\n", self.fired.len()));
            for f in &self.fired {
                s.push_str(&format!(
                    "- {} ({}) — {} matching event(s) [{}]\n",
                    f.mitre_id, f.description, f.event_count, f.template
                ));
            }
            s.push('\n');
        }

        if !self.no_match.is_empty() {
            s.push_str(&format!(
                "Ran and returned no matches (do NOT re-query): {}\n\n",
                self.no_match.join(", ")
            ));
        }

        if self.timed_out && !self.not_run.is_empty() {
            s.push_str(&format!(
                "The sweep hit its time cap before running these templates — run them yourself \
                 if the alert context makes them relevant: {}\n\n",
                self.not_run.join(", ")
            ));
        }

        s.push_str(
            "Your budget is best spent on what the sweep CANNOT do — dispatch TARGETED \
             follow-ups, do not re-scan:\n\
             1. For each fired technique, dispatch_threat_hunt with that technique_id and a \
             context note, to chase its chain: affected users/hosts and what they touched.\n\
             2. Where a host or account looks central, dispatch_lateral_analysis to map movement \
             and compromised accounts.\n\
             3. Record cross-cutting findings directly with add_evidence / add_technique / \
             record_timeline_event.\n\
             4. Decide the verdict and whether to escalate, then call complete_investigation.\n\n\
             The full detection catalog is already covered, so do NOT dispatch broad \
             \"scan everything\" hunts — they just re-run finished work and exhaust the budget. \
             Dispatch narrow, technique-scoped hunts, or go straight to the verdict when the \
             picture is already clear.",
        );
        s
    }
}

/// Run the deterministic baseline detection sweep and record every hit.
///
/// Enumerates the full detection catalog, runs each template's query with
/// bounded concurrency under an overall time cap, and for every template that
/// returns matching events records the technique into blue state (technique
/// set + TTP-level evidence + a timeline event). Returns a summary the caller
/// folds into the orchestrator prompt. Best-effort throughout: a failed query
/// or a failed record is logged and skipped — the sweep never sinks the
/// investigation.
pub(crate) async fn run_detection_sweep(investigation_id: &str) -> SweepOutcome {
    let all_names: BTreeSet<String> = detection_config().templates.keys().cloned().collect();
    let templates: Vec<FiredDetection> = detection_config()
        .templates
        .iter()
        .map(|(name, e)| FiredDetection {
            template: name.clone(),
            mitre_id: e.mitre_id.clone(),
            description: e.description.clone(),
            tactic: e.tactic.clone(),
            severity: e.severity.clone(),
            event_count: 0,
        })
        .collect();
    let templates_total = templates.len();

    info!(
        investigation_id,
        templates = templates_total,
        "Starting deterministic baseline detection sweep"
    );

    let sem = Arc::new(Semaphore::new(sweep_concurrency()));
    let mut set: tokio::task::JoinSet<(String, Option<FiredDetection>)> =
        tokio::task::JoinSet::new();
    for tmpl in templates {
        let sem = Arc::clone(&sem);
        set.spawn(async move {
            let Ok(_permit) = sem.acquire_owned().await else {
                return (tmpl.template.clone(), None);
            };
            let out = ares_tools::blue::dispatch_blue(
                "run_detection_query",
                &json!({ "query_name": tmpl.template, "hours_back": SWEEP_HOURS_BACK }),
            )
            .await;
            let fired = match out {
                Ok(o) => parse_fire_count(&o).map(|count| FiredDetection {
                    event_count: count,
                    ..tmpl.clone()
                }),
                Err(e) => {
                    warn!(template = %tmpl.template, error = %e, "Sweep detection query failed");
                    None
                }
            };
            (tmpl.template, fired)
        });
    }

    let mut fired: Vec<FiredDetection> = Vec::new();
    let mut completed: BTreeSet<String> = BTreeSet::new();
    let mut timed_out = false;

    let deadline = tokio::time::sleep(Duration::from_secs(sweep_timeout_secs()));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => {
                timed_out = true;
                set.abort_all();
                break;
            }
            res = set.join_next() => {
                match res {
                    Some(Ok((name, hit))) => {
                        completed.insert(name);
                        if let Some(f) = hit {
                            fired.push(f);
                        }
                    }
                    // Task panic or abort — skip it, don't sink the sweep.
                    Some(Err(_)) => {}
                    None => break,
                }
            }
        }
    }

    fired.sort_by(|a, b| a.template.cmp(&b.template));

    // Record every hit into blue state (sequential, cheap: a few Redis writes
    // each). Deduped by the underlying tools, so overlap with the LLM's own
    // later recording is harmless.
    for f in &fired {
        record_fired(investigation_id, f).await;
    }

    let no_match: Vec<String> = completed
        .iter()
        .filter(|n| !fired.iter().any(|f| &f.template == *n))
        .cloned()
        .collect();
    let not_run: Vec<String> = all_names.difference(&completed).cloned().collect();

    info!(
        investigation_id,
        fired = fired.len(),
        no_match = no_match.len(),
        not_run = not_run.len(),
        timed_out,
        "Baseline detection sweep complete"
    );

    SweepOutcome {
        templates_total,
        fired,
        no_match,
        not_run,
        timed_out,
    }
}

/// Record a fired detection as blue-team state: a MITRE technique (for coverage
/// scoring + the report technique table), a TTP-level evidence item (for
/// evidence count, pyramid, precision, and evidence-based chaining), and a
/// timeline event (for the narrative + timeline scoring). The evidence value is
/// the MITRE ID, which auto-validates the grounding check.
async fn record_fired(investigation_id: &str, f: &FiredDetection) {
    let confidence = confidence_for_severity(&f.severity);
    let now = chrono::Utc::now().to_rfc3339();

    let calls = [
        (
            "add_technique",
            json!({
                "investigation_id": investigation_id,
                "technique_id": f.mitre_id,
                "technique_name": f.description,
            }),
        ),
        (
            "add_evidence",
            json!({
                "investigation_id": investigation_id,
                "evidence_type": evidence_type_for_tactic(&f.tactic),
                "value": f.mitre_id,
                "source": format!("detection_sweep:{}", f.template),
                "confidence": confidence,
                "pyramid_level": "ttps",
                "mitre_techniques": [f.mitre_id],
                "timestamp": now,
            }),
        ),
        (
            "record_timeline_event",
            json!({
                "investigation_id": investigation_id,
                "description": format!(
                    "Baseline detection {} fired: {} ({} event(s))",
                    f.template, f.description, f.event_count
                ),
                "timestamp": now,
                "mitre_techniques": [f.mitre_id],
                "source": "detection_sweep",
                "confidence": confidence,
            }),
        ),
    ];

    for (tool, args) in calls {
        if let Err(e) = ares_tools::blue::dispatch_blue(tool, &args).await {
            warn!(
                template = %f.template,
                tool,
                error = %e,
                "Failed to record swept detection"
            );
        }
    }
}

/// Detect a Loki hit in a detection-query result and return the event count.
///
/// The detection runner prepends a template header to the Loki output;
/// `format_loki_response` emits `"Found N log entries:"` on a hit and
/// `"No results found."` otherwise. Returns `None` for a miss, an error
/// result, or an unparsable count.
fn parse_fire_count(out: &ToolOutput) -> Option<usize> {
    if !out.success {
        return None;
    }
    let pos = out.stdout.find("Found ")?;
    let rest = &out.stdout[pos + "Found ".len()..];
    let end = rest.find(" log entries")?;
    rest[..end].trim().parse::<usize>().ok()
}

/// Map a detection's evidence confidence from its severity.
fn confidence_for_severity(severity: &str) -> f64 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 0.9,
        "high" => 0.8,
        "medium" => 0.6,
        _ => 0.5,
    }
}

/// Pick a valid `evidence_type` (see `validation::KNOWN_EVIDENCE_TYPES`) from a
/// detection's tactic. The pyramid level is passed explicitly as `ttps`, so the
/// type only drives the dedup key and report display; a fired detection is a
/// behavioural observation, so map to the closest known behavioural type.
fn evidence_type_for_tactic(tactic: &str) -> &'static str {
    let t = tactic.to_ascii_lowercase();
    if t.contains("credential") {
        "credential_access"
    } else if t.contains("lateral") {
        "lateral_movement"
    } else if t.contains("privilege") {
        "privilege_escalation"
    } else if t.contains("persistence") {
        "persistence_mechanism"
    } else {
        "log_entry"
    }
}

/// Whether the deterministic sweep should run. Defaults on; set
/// `ARES_BLUE_DETERMINISTIC_SWEEP=0` to disable.
pub(crate) fn sweep_enabled() -> bool {
    match std::env::var("ARES_BLUE_DETERMINISTIC_SWEEP") {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ),
        Err(_) => true,
    }
}

/// Concurrency for the sweep, overridable via `ARES_BLUE_SWEEP_CONCURRENCY`.
fn sweep_concurrency() -> usize {
    std::env::var("ARES_BLUE_SWEEP_CONCURRENCY")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(DEFAULT_SWEEP_CONCURRENCY)
}

/// Overall time cap for the sweep, overridable via `ARES_BLUE_SWEEP_TIMEOUT_SECS`.
fn sweep_timeout_secs() -> u64 {
    std::env::var("ARES_BLUE_SWEEP_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(DEFAULT_SWEEP_TIMEOUT_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out(success: bool, stdout: &str) -> ToolOutput {
        ToolOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: Some(if success { 0 } else { 1 }),
            success,
        }
    }

    #[test]
    fn parse_fire_count_hit() {
        let o = out(
            true,
            "## DCSync Detection (T1003.006)\n**Severity:** critical\nFound 5 log entries:\n\n[x] evt",
        );
        assert_eq!(parse_fire_count(&o), Some(5));
    }

    #[test]
    fn parse_fire_count_miss() {
        let o = out(true, "## DCSync Detection (T1003.006)\nNo results found.");
        assert_eq!(parse_fire_count(&o), None);
    }

    #[test]
    fn parse_fire_count_error_result() {
        let o = out(false, "Found 5 log entries:");
        assert_eq!(parse_fire_count(&o), None);
    }

    #[test]
    fn parse_fire_count_large() {
        let o = out(true, "header\nFound 100 log entries:\n\nrows");
        assert_eq!(parse_fire_count(&o), Some(100));
    }

    #[test]
    fn confidence_scales_with_severity() {
        assert_eq!(confidence_for_severity("critical"), 0.9);
        assert_eq!(confidence_for_severity("HIGH"), 0.8);
        assert_eq!(confidence_for_severity("medium"), 0.6);
        assert_eq!(confidence_for_severity("low"), 0.5);
        assert_eq!(confidence_for_severity("weird"), 0.5);
    }

    #[test]
    fn evidence_type_maps_known_tactics() {
        assert_eq!(
            evidence_type_for_tactic("credential_access"),
            "credential_access"
        );
        assert_eq!(
            evidence_type_for_tactic("lateral_movement"),
            "lateral_movement"
        );
        assert_eq!(
            evidence_type_for_tactic("privilege_escalation"),
            "privilege_escalation"
        );
        assert_eq!(
            evidence_type_for_tactic("persistence"),
            "persistence_mechanism"
        );
        assert_eq!(evidence_type_for_tactic("discovery"), "log_entry");
        assert_eq!(evidence_type_for_tactic("defense_evasion"), "log_entry");
    }

    #[test]
    fn evidence_types_are_all_known_to_validation() {
        // Every value this maps to must be accepted by validate_evidence, or the
        // swept add_evidence call is silently rejected.
        for tactic in [
            "credential_access",
            "lateral_movement",
            "privilege_escalation",
            "persistence",
            "discovery",
            "execution",
            "defense_evasion",
        ] {
            let et = evidence_type_for_tactic(tactic);
            let vr =
                ares_tools::blue::validation::validate_evidence(et, "T1003.006", "detection_sweep");
            assert!(
                vr.valid,
                "evidence_type '{et}' (tactic '{tactic}') rejected by validation"
            );
        }
    }

    #[test]
    fn sweep_enabled_defaults_on_and_respects_off() {
        std::env::remove_var("ARES_BLUE_DETERMINISTIC_SWEEP");
        assert!(sweep_enabled());
        std::env::set_var("ARES_BLUE_DETERMINISTIC_SWEEP", "0");
        assert!(!sweep_enabled());
        std::env::set_var("ARES_BLUE_DETERMINISTIC_SWEEP", "off");
        assert!(!sweep_enabled());
        std::env::set_var("ARES_BLUE_DETERMINISTIC_SWEEP", "1");
        assert!(sweep_enabled());
        std::env::remove_var("ARES_BLUE_DETERMINISTIC_SWEEP");
    }

    #[test]
    fn prompt_summary_lists_fired_and_no_match() {
        let outcome = SweepOutcome {
            templates_total: 3,
            fired: vec![FiredDetection {
                template: "detect_dcsync".into(),
                mitre_id: "T1003.006".into(),
                description: "DCSync Detection".into(),
                tactic: "credential_access".into(),
                severity: "critical".into(),
                event_count: 5,
            }],
            no_match: vec!["detect_golden_ticket".into()],
            not_run: vec![],
            timed_out: false,
        };
        let s = outcome.prompt_summary();
        assert!(s.contains("T1003.006"));
        assert!(s.contains("5 matching event"));
        assert!(s.contains("detect_golden_ticket"));
        assert!(s.contains("ALREADY"));
        // Clean finish → no "time cap" note.
        assert!(!s.contains("time cap"));
    }

    #[test]
    fn prompt_summary_notes_timeout_gap() {
        let outcome = SweepOutcome {
            templates_total: 3,
            fired: vec![],
            no_match: vec![],
            not_run: vec!["detect_esc1_attack".into()],
            timed_out: true,
        };
        let s = outcome.prompt_summary();
        assert!(s.contains("FIRED: none"));
        assert!(s.contains("time cap"));
        assert!(s.contains("detect_esc1_attack"));
    }

    #[test]
    fn ran_reflects_template_total() {
        assert!(!SweepOutcome::default().ran());
        assert!(SweepOutcome {
            templates_total: 1,
            ..Default::default()
        }
        .ran());
    }
}
