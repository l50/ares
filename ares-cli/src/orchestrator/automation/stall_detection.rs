//! auto_stall_detection -- detect when the operation is stuck and take action.
//!
//! When no new credentials or hashes have been discovered for a configurable
//! period (default: 5 minutes), this automation triggers fallback actions:
//!
//!   1. Re-attempt password spray with discovered users
//!   2. Re-run low-hanging-fruit discovery with all known creds
//!   3. Cold-start AS-REP enumeration when both users and creds are empty
//!
//! This prevents the operation from idling when all easy wins are exhausted.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::orchestrator::dispatcher::{Dispatcher, SubmissionOutcome};
use crate::orchestrator::state::*;

/// Collect the set of lowercased domains that have at least one pending
/// (un-exploited) constrained-delegation or RBCD vuln. The stall-recovery
/// password spray uses this set to skip domains where a spray would lock
/// out delegation accounts before S4U gets to use them.
pub(crate) fn domains_with_pending_delegation(
    state: &StateInner,
) -> std::collections::HashSet<String> {
    state
        .discovered_vulnerabilities
        .values()
        .filter(|v| {
            let vt = v.vuln_type.to_lowercase();
            (vt == "constrained_delegation" || vt == "rbcd")
                && !state.exploited_vulnerabilities.contains(&v.vuln_id)
        })
        .filter_map(|v| {
            v.details
                .get("domain")
                .or_else(|| v.details.get("Domain"))
                .and_then(|d| d.as_str())
                .map(|d| d.to_lowercase())
        })
        .collect()
}

/// Build the stall-recovery spray dedup key. The `recovery_attempts` counter
/// is embedded so each round emits a fresh, distinct key — otherwise a single
/// stall would only ever trigger one spray dispatch.
pub(crate) fn stall_spray_dedup_key(domain: &str, recovery_attempts: u32) -> String {
    format!("stall_spray:{}:{recovery_attempts}", domain.to_lowercase())
}

/// Build the stall-recovery low-hanging-fruit dedup key.
pub(crate) fn stall_lhf_dedup_key(domain: &str, username: &str, recovery_attempts: u32) -> String {
    format!(
        "stall_lhf:{}:{}:{recovery_attempts}",
        domain.to_lowercase(),
        username.to_lowercase()
    )
}

/// Resolve a DC IP for stall-recovery LHF dispatch.
///
/// Tries exact match in `domain_controllers` first, then any child-domain
/// DC (`d.ends_with(".{cred_domain}")`). Returns `None` when no DC for
/// this cred's forest is known yet.
pub(crate) fn resolve_stall_dc_ip(state: &StateInner, cred_domain: &str) -> Option<String> {
    let cred_domain = cred_domain.to_lowercase();
    state
        .domain_controllers
        .get(&cred_domain)
        .cloned()
        .or_else(|| {
            let suffix = format!(".{cred_domain}");
            state
                .domain_controllers
                .iter()
                .find(|(d, _)| d.ends_with(&suffix))
                .map(|(_, ip)| ip.clone())
        })
}

/// Select stall-recovery password-spray work items for this tick.
///
/// Returns `(domain, dc_ip)` for each known DC whose domain has no pending
/// delegation vulns AND whose round-specific dedup key
/// (`stall_spray:{domain}:{recovery_attempts}`) is unprocessed.
pub(crate) fn select_stall_spray_work(
    state: &StateInner,
    recovery_attempts: u32,
) -> Vec<(String, String)> {
    let delegation_domains = domains_with_pending_delegation(state);
    state
        .domain_controllers
        .iter()
        .filter(|(domain, _)| !state.is_domain_dominated(domain))
        .filter(|(domain, _)| !delegation_domains.contains(&domain.to_lowercase()))
        .filter(|(domain, _)| {
            let key = stall_spray_dedup_key(domain, recovery_attempts);
            !state.is_processed(DEDUP_PASSWORD_SPRAY, &key)
        })
        .map(|(domain, dc_ip)| (domain.clone(), dc_ip.clone()))
        .collect()
}

/// Select stall-recovery low-hanging-fruit work items, capped at `max_items`.
pub(crate) fn select_stall_lhf_work(
    state: &StateInner,
    recovery_attempts: u32,
    max_items: usize,
) -> Vec<(String, String, String, ares_core::models::Credential)> {
    state
        .credentials
        .iter()
        .filter(|c| !c.domain.is_empty() && !c.password.is_empty())
        .filter_map(|cred| {
            let cred_domain = cred.domain.to_lowercase();
            if state.is_domain_dominated(&cred_domain) {
                return None;
            }
            let key = stall_lhf_dedup_key(&cred_domain, &cred.username, recovery_attempts);
            if state.is_processed(DEDUP_EXPANSION_CREDS, &key) {
                return None;
            }
            let dc_ip = resolve_stall_dc_ip(state, &cred_domain)?;
            Some((key, dc_ip, cred_domain, cred.clone()))
        })
        .take(max_items)
        .collect()
}

/// Build the stall-recovery cold-start dedup key.
pub(crate) fn stall_cold_start_dedup_key(domain: &str, recovery_attempts: u32) -> String {
    format!(
        "stall_cold_start:{}:{recovery_attempts}",
        domain.to_lowercase()
    )
}

/// Select stall-recovery cold-start work items: unauth user enumeration
/// against each known DC whose domain isn't already dominated AND whose
/// round-specific dedup key is unprocessed. Used when the op has zero
/// users AND zero credentials but DCs are known — initial bootstrap
/// (petitpotam unauth, anonymous SAMR, etc.) produced nothing, so we
/// fall back to seclists + kerbrute via AS-REP roast cold-start.
pub(crate) fn select_stall_cold_start_work(
    state: &StateInner,
    recovery_attempts: u32,
) -> Vec<(String, String)> {
    state
        .domain_controllers
        .iter()
        .filter(|(domain, _)| !state.is_domain_dominated(domain))
        .filter(|(domain, _)| {
            let key = stall_cold_start_dedup_key(domain, recovery_attempts);
            !state.is_processed(DEDUP_STALL_COLD_START, &key)
        })
        .map(|(domain, dc_ip)| (domain.clone(), dc_ip.clone()))
        .collect()
}

/// Build the password-spray payload for stall recovery.
pub(crate) fn build_spray_payload(domain: &str, dc_ip: &str) -> Value {
    json!({
        "technique": "password_spray",
        "target_ip": dc_ip,
        "domain": domain,
        "use_common_passwords": true,
        "acknowledge_no_policy": true,
    })
}

/// Build the cold-start AS-REP enumeration payload (delegates to
/// `credential_access::build_asrep_payload` with empty known/excluded users
/// to emit the seclists+kerbrute instructions).
pub(crate) fn build_cold_start_payload(domain: &str, dc_ip: &str) -> Value {
    super::credential_access::build_asrep_payload(domain, dc_ip, &[], &[])
}

/// What kind of recovery action a `RecoveryAction` represents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ActionKind {
    /// Password spray against a discovered userlist.
    Spray,
    /// Low-hanging-fruit (LAPS, gMSA) against a known credential.
    LowHanging,
    /// Cold-start unauth AS-REP enumeration against a DC.
    ColdStart,
}

/// A single recovery action produced by `plan_stall_recovery`. The dispatch
/// loop consumes these and routes each to the appropriate dispatcher call.
#[derive(Debug, Clone)]
pub(crate) struct RecoveryAction {
    pub kind: ActionKind,
    pub domain: String,
    pub dc_ip: String,
    pub dedup_key: String,
    pub dedup_set: &'static str,
    /// Only set for `ActionKind::LowHanging` — the credential to use.
    pub cred: Option<ares_core::models::Credential>,
}

/// Inputs to `plan_stall_recovery` describing what corpus the op has so far
/// and which fallback techniques are currently permissible.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StallContext {
    pub has_users: bool,
    pub has_creds: bool,
    pub has_dcs: bool,
    pub allow_password_spray: bool,
    pub allow_asrep_roast: bool,
    pub lhf_max: usize,
}

/// Why a stall-recovery branch produced zero dispatchable actions this round.
///
/// Surfaced in the stall-recovery WARN so the next operator can fix data
/// (clear a dedup, add a DC, enable a technique) instead of guessing why the
/// auto-recovery is silent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BranchSkipReason {
    /// A precondition gate (`has_users` / `has_creds` / `has_dcs`) was false.
    PreconditionUnmet { needs: &'static str },
    /// The technique is disabled in the operation strategy.
    TechniqueNotAllowed { technique: &'static str },
    /// State had candidates but every one was filtered out.
    AllCandidatesFiltered {
        considered: usize,
        dedup_skipped: usize,
        dominated: usize,
        delegation_blocked: usize,
        missing_dc: usize,
        empty_creds: usize,
    },
    /// Branch is intentionally suppressed because another branch owns recovery
    /// for the current state shape (e.g. cold-start skipped when users/creds
    /// exist).
    SuppressedByState { reason: &'static str },
}

impl BranchSkipReason {
    pub(crate) fn as_log_str(&self) -> String {
        match self {
            BranchSkipReason::PreconditionUnmet { needs } => {
                format!("precondition_unmet:{needs}")
            }
            BranchSkipReason::TechniqueNotAllowed { technique } => {
                format!("technique_not_allowed:{technique}")
            }
            BranchSkipReason::AllCandidatesFiltered {
                considered,
                dedup_skipped,
                dominated,
                delegation_blocked,
                missing_dc,
                empty_creds,
            } => format!(
                "all_filtered(considered={considered},dedup_skipped={dedup_skipped},\
                 dominated={dominated},delegation_blocked={delegation_blocked},\
                 missing_dc={missing_dc},empty_creds={empty_creds})"
            ),
            BranchSkipReason::SuppressedByState { reason } => {
                format!("suppressed:{reason}")
            }
        }
    }
}

/// Result of planning a single tick of stall recovery: the actions to attempt
/// AND a per-branch explanation for every branch that produced zero actions.
///
/// `Spray`, `LowHanging`, and `ColdStart` are independent branches; each gets
/// at most one entry in `branch_skips` per tick when it could not contribute.
#[derive(Debug, Default)]
pub(crate) struct StallPlan {
    pub actions: Vec<RecoveryAction>,
    pub branch_skips: Vec<(ActionKind, BranchSkipReason)>,
}

/// Inspect spray candidate selection and explain why an empty result is empty.
///
/// `select_stall_spray_work` filters silently; this walker counts each
/// rejection bucket so the stall WARN can surface the actionable cause.
fn diagnose_empty_spray(state: &StateInner, recovery_attempts: u32) -> BranchSkipReason {
    let delegation_domains = domains_with_pending_delegation(state);
    let mut considered = 0usize;
    let mut dedup_skipped = 0usize;
    let mut dominated = 0usize;
    let mut delegation_blocked = 0usize;
    for domain in state.domain_controllers.keys() {
        considered += 1;
        if state.is_domain_dominated(domain) {
            dominated += 1;
            continue;
        }
        if delegation_domains.contains(&domain.to_lowercase()) {
            delegation_blocked += 1;
            continue;
        }
        let key = stall_spray_dedup_key(domain, recovery_attempts);
        if state.is_processed(DEDUP_PASSWORD_SPRAY, &key) {
            dedup_skipped += 1;
        }
    }
    BranchSkipReason::AllCandidatesFiltered {
        considered,
        dedup_skipped,
        dominated,
        delegation_blocked,
        missing_dc: 0,
        empty_creds: 0,
    }
}

/// Inspect LHF candidate selection and explain why an empty result is empty.
///
/// Mirror of `select_stall_lhf_work` filters: empty domain/password, dominated
/// domain, dedup-already-marked, no DC resolvable for the cred's domain.
fn diagnose_empty_lhf(state: &StateInner, recovery_attempts: u32) -> BranchSkipReason {
    let mut considered = 0usize;
    let mut dedup_skipped = 0usize;
    let mut dominated = 0usize;
    let mut missing_dc = 0usize;
    let mut empty_creds = 0usize;
    for cred in &state.credentials {
        considered += 1;
        if cred.domain.is_empty() || cred.password.is_empty() {
            empty_creds += 1;
            continue;
        }
        let cred_domain = cred.domain.to_lowercase();
        if state.is_domain_dominated(&cred_domain) {
            dominated += 1;
            continue;
        }
        if resolve_stall_dc_ip(state, &cred_domain).is_none() {
            missing_dc += 1;
            continue;
        }
        let key = stall_lhf_dedup_key(&cred_domain, &cred.username, recovery_attempts);
        if state.is_processed(DEDUP_EXPANSION_CREDS, &key) {
            dedup_skipped += 1;
        }
    }
    BranchSkipReason::AllCandidatesFiltered {
        considered,
        dedup_skipped,
        dominated,
        delegation_blocked: 0,
        missing_dc,
        empty_creds,
    }
}

/// Inspect cold-start candidate selection and explain why an empty result is empty.
fn diagnose_empty_cold_start(state: &StateInner, recovery_attempts: u32) -> BranchSkipReason {
    let mut considered = 0usize;
    let mut dedup_skipped = 0usize;
    let mut dominated = 0usize;
    for domain in state.domain_controllers.keys() {
        considered += 1;
        if state.is_domain_dominated(domain) {
            dominated += 1;
            continue;
        }
        let key = stall_cold_start_dedup_key(domain, recovery_attempts);
        if state.is_processed(DEDUP_STALL_COLD_START, &key) {
            dedup_skipped += 1;
        }
    }
    BranchSkipReason::AllCandidatesFiltered {
        considered,
        dedup_skipped,
        dominated,
        delegation_blocked: 0,
        missing_dc: 0,
        empty_creds: 0,
    }
}

/// Build the prioritized list of stall-recovery actions for this tick.
///
/// Pure function: no I/O, no Dispatcher. Inspects state + gates and returns
/// the actions the dispatch loop should attempt.
///
/// Order: spray → low-hanging-fruit → cold-start. Cold-start only fires
/// when both `has_users` and `has_creds` are false (otherwise the other
/// two branches own the recovery).
///
/// Convenience wrapper around `plan_stall_recovery_diagnostic` that drops the
/// per-branch skip reasons. Most callers should prefer the diagnostic variant
/// so they can surface why a branch contributed nothing. Retained for tests
/// that don't need the diagnostic field.
#[cfg(test)]
pub(crate) fn plan_stall_recovery(
    state: &StateInner,
    recovery_attempts: u32,
    ctx: &StallContext,
) -> Vec<RecoveryAction> {
    plan_stall_recovery_diagnostic(state, recovery_attempts, ctx).actions
}

/// Diagnostic variant of `plan_stall_recovery`: returns the actions AND a
/// per-branch explanation for every branch that produced zero actions.
///
/// This is the path the live stall-recovery loop uses so the WARN line can
/// surface the gate that excluded each candidate (precondition unmet,
/// technique disabled, all candidates filtered with per-filter counts, or
/// branch intentionally suppressed). Mirrors the diagnostic-lift contract:
/// when no action dispatches, the operator must be able to read the log and
/// know what to fix (data, config, dedup) instead of guessing.
pub(crate) fn plan_stall_recovery_diagnostic(
    state: &StateInner,
    recovery_attempts: u32,
    ctx: &StallContext,
) -> StallPlan {
    let mut plan = StallPlan::default();

    // Spray branch
    if !ctx.has_users || !ctx.has_dcs {
        plan.branch_skips.push((
            ActionKind::Spray,
            BranchSkipReason::PreconditionUnmet {
                needs: "has_users && has_dcs",
            },
        ));
    } else if !ctx.allow_password_spray {
        plan.branch_skips.push((
            ActionKind::Spray,
            BranchSkipReason::TechniqueNotAllowed {
                technique: "password_spray",
            },
        ));
    } else {
        let work = select_stall_spray_work(state, recovery_attempts);
        if work.is_empty() {
            plan.branch_skips.push((
                ActionKind::Spray,
                diagnose_empty_spray(state, recovery_attempts),
            ));
        } else {
            for (domain, dc_ip) in work {
                let dedup_key = stall_spray_dedup_key(&domain, recovery_attempts);
                plan.actions.push(RecoveryAction {
                    kind: ActionKind::Spray,
                    domain,
                    dc_ip,
                    dedup_key,
                    dedup_set: DEDUP_PASSWORD_SPRAY,
                    cred: None,
                });
            }
        }
    }

    // Low-hanging-fruit branch
    if !ctx.has_creds || !ctx.has_dcs {
        plan.branch_skips.push((
            ActionKind::LowHanging,
            BranchSkipReason::PreconditionUnmet {
                needs: "has_creds && has_dcs",
            },
        ));
    } else {
        let work = select_stall_lhf_work(state, recovery_attempts, ctx.lhf_max);
        if work.is_empty() {
            plan.branch_skips.push((
                ActionKind::LowHanging,
                diagnose_empty_lhf(state, recovery_attempts),
            ));
        } else {
            for (key, dc_ip, domain, cred) in work {
                plan.actions.push(RecoveryAction {
                    kind: ActionKind::LowHanging,
                    domain,
                    dc_ip,
                    dedup_key: key,
                    dedup_set: DEDUP_EXPANSION_CREDS,
                    cred: Some(cred),
                });
            }
        }
    }

    // Cold-start branch (only fires when both users and creds are absent)
    if ctx.has_users || ctx.has_creds {
        plan.branch_skips.push((
            ActionKind::ColdStart,
            BranchSkipReason::SuppressedByState {
                reason: "users_or_creds_present",
            },
        ));
    } else if !ctx.has_dcs {
        plan.branch_skips.push((
            ActionKind::ColdStart,
            BranchSkipReason::PreconditionUnmet { needs: "has_dcs" },
        ));
    } else if !ctx.allow_asrep_roast {
        plan.branch_skips.push((
            ActionKind::ColdStart,
            BranchSkipReason::TechniqueNotAllowed {
                technique: "asrep_roast",
            },
        ));
    } else {
        let work = select_stall_cold_start_work(state, recovery_attempts);
        if work.is_empty() {
            plan.branch_skips.push((
                ActionKind::ColdStart,
                diagnose_empty_cold_start(state, recovery_attempts),
            ));
        } else {
            for (domain, dc_ip) in work {
                let dedup_key = stall_cold_start_dedup_key(&domain, recovery_attempts);
                plan.actions.push(RecoveryAction {
                    kind: ActionKind::ColdStart,
                    domain,
                    dc_ip,
                    dedup_key,
                    dedup_set: DEDUP_STALL_COLD_START,
                    cred: None,
                });
            }
        }
    }

    plan
}

/// How long without new discoveries before we consider the op stalled.
const STALL_THRESHOLD: Duration = Duration::from_secs(180); // 3 minutes

/// Minimum interval between stall recovery actions.
const RECOVERY_COOLDOWN: Duration = Duration::from_secs(120); // 2 minutes

/// Cap on the number of recovery rounds per op (don't spam indefinitely).
const MAX_RECOVERY_ATTEMPTS: u32 = 10;

/// Upper bound on the dynamic cooldown when zero-progress backoff kicks in.
/// At 16 min the next attempt still re-enters within a reasonable window if
/// state changes externally (operator injection, blue team interaction).
const MAX_RECOVERY_COOLDOWN: Duration = Duration::from_secs(16 * 60);

/// Mutable bookkeeping for the stall detector. Tracks observed progress
/// counters and timing gates outside the Dispatcher so the gate logic can
/// be unit-tested without async I/O or a real clock.
#[derive(Debug)]
pub(crate) struct StallTracker {
    last_cred_count: usize,
    last_hash_count: usize,
    last_change: Instant,
    last_recovery: Instant,
    recovery_attempts: u32,
    /// Counter of consecutive recovery rounds that produced zero new progress.
    /// Each round that fires `note_recovery_attempt` without an intervening
    /// `observe_progress(true)` increments this. Drives exponential cooldown
    /// backoff so a stuck op doesn't keep re-dispatching the same fallback
    /// branches at full cadence (every 2 min) for the full 10-attempt budget,
    /// burning ~$1.25/min on a workload that isn't actually making progress.
    zero_progress_streak: u32,
}

impl StallTracker {
    pub(crate) fn new() -> Self {
        let now = Instant::now();
        Self {
            last_cred_count: 0,
            last_hash_count: 0,
            last_change: now,
            last_recovery: now.checked_sub(RECOVERY_COOLDOWN).unwrap_or(now),
            recovery_attempts: 0,
            zero_progress_streak: 0,
        }
    }

    /// Returns true when progress (more creds or hashes) was observed since
    /// the previous tick — caller should `continue`. Updates internal state.
    pub(crate) fn observe_progress(&mut self, cred_count: usize, hash_count: usize) -> bool {
        if cred_count > self.last_cred_count || hash_count > self.last_hash_count {
            self.last_cred_count = cred_count;
            self.last_hash_count = hash_count;
            self.last_change = Instant::now();
            self.recovery_attempts = 0;
            self.zero_progress_streak = 0;
            true
        } else {
            false
        }
    }

    pub(crate) fn is_stalled(&self) -> bool {
        self.last_change.elapsed() >= STALL_THRESHOLD
    }

    /// The effective cooldown for the next recovery attempt. Doubles for each
    /// consecutive zero-progress round on top of the base cooldown, capped at
    /// `MAX_RECOVERY_COOLDOWN` so we always retry eventually. After 1 unproductive
    /// round the next attempt waits 4 min, 2 → 8 min, 3 → 16 min, then plateaus.
    fn effective_cooldown(&self) -> Duration {
        let shift = self.zero_progress_streak.min(6);
        let scaled = RECOVERY_COOLDOWN
            .checked_mul(1u32 << shift)
            .unwrap_or(MAX_RECOVERY_COOLDOWN);
        scaled.min(MAX_RECOVERY_COOLDOWN)
    }

    pub(crate) fn cooldown_elapsed(&self) -> bool {
        self.last_recovery.elapsed() >= self.effective_cooldown()
    }

    pub(crate) fn attempts_exhausted(&self) -> bool {
        self.recovery_attempts >= MAX_RECOVERY_ATTEMPTS
    }

    /// Record a new recovery attempt: bumps the counter, resets the cooldown,
    /// and returns the new attempt number (1-indexed).
    ///
    /// Also bumps `zero_progress_streak` — `observe_progress` zeros it out
    /// when a subsequent tick finds new creds/hashes, so the streak captures
    /// "rounds since last forward step," not "rounds since startup."
    pub(crate) fn note_recovery_attempt(&mut self) -> u32 {
        self.last_recovery = Instant::now();
        self.recovery_attempts += 1;
        self.zero_progress_streak = self.zero_progress_streak.saturating_add(1);
        self.recovery_attempts
    }

    pub(crate) fn stall_duration_secs(&self) -> u64 {
        self.last_change.elapsed().as_secs()
    }

    /// Test-only: rewind `last_change` to make `is_stalled()` true.
    #[cfg(test)]
    pub(crate) fn rewind_last_change(&mut self, by: Duration) {
        self.last_change = self
            .last_change
            .checked_sub(by)
            .expect("rewind out of range");
    }

    /// Test-only: rewind `last_recovery` to make `cooldown_elapsed()` true.
    #[cfg(test)]
    pub(crate) fn rewind_last_recovery(&mut self, by: Duration) {
        self.last_recovery = self
            .last_recovery
            .checked_sub(by)
            .expect("rewind out of range");
    }

    #[cfg(test)]
    pub(crate) fn force_attempts(&mut self, n: u32) {
        self.recovery_attempts = n;
    }
}

/// Adapter trait abstracting the dispatcher operations required by the
/// stall-recovery dispatch loop. Production wires this through
/// `DispatcherStallAdapter`; tests pin a hand-rolled fake to drive every
/// branch without a real Dispatcher.
///
/// Submitters return a `SubmissionOutcome` instead of `Option<String>` so the
/// dispatch loop can tell `Submitted` (counted as a dispatch + dedup mark)
/// from `Deferred` (work landed in the deferred queue and will be picked up
/// when a worker frees) from `Dropped` (lost — no role mapping or queue full,
/// surfaced in the stall WARN so the operator knows the round produced
/// nothing actionable).
#[async_trait]
pub(crate) trait StallRecoveryAdapter: Send + Sync {
    async fn submit_spray(&self, domain: &str, dc_ip: &str) -> Result<SubmissionOutcome>;
    async fn submit_lhf(
        &self,
        dc_ip: &str,
        domain: &str,
        cred: &ares_core::models::Credential,
    ) -> Result<SubmissionOutcome>;
    async fn submit_cold_start(&self, domain: &str, dc_ip: &str) -> Result<SubmissionOutcome>;
    async fn mark_dedup(&self, set: &'static str, key: String);
}

/// Per-action breakdown of how `execute_recovery_actions` resolved one tick.
/// Surfaced in the stall WARN so an operator can see whether a recovery round
/// produced zero dispatches because the planner skipped every branch or
/// because the throttler/queue absorbed every submission.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ExecutionReport {
    pub dispatched: usize,
    pub deferred: usize,
    pub dropped: usize,
    pub errors: usize,
}

impl ExecutionReport {
    #[cfg(test)]
    pub(crate) fn total(&self) -> usize {
        self.dispatched + self.deferred + self.dropped + self.errors
    }
}

/// Execute a planned set of recovery actions and report per-outcome counts.
///
/// Only `Submitted` outcomes update the dedup ledger so a deferred or dropped
/// task can be re-considered on the next tick. The report distinguishes
/// `deferred` (in the deferred queue) from `dropped` (gone) so the stall WARN
/// can explain why a round produced zero dispatched actions.
pub(crate) async fn execute_recovery_actions<A: StallRecoveryAdapter + ?Sized>(
    adapter: &A,
    plan: Vec<RecoveryAction>,
) -> ExecutionReport {
    let mut report = ExecutionReport::default();

    for action in plan {
        let (result, label) = match action.kind {
            ActionKind::Spray => (
                adapter.submit_spray(&action.domain, &action.dc_ip).await,
                "password spray",
            ),
            ActionKind::LowHanging => {
                let cred = action
                    .cred
                    .as_ref()
                    .expect("LowHanging action must carry a credential");
                (
                    adapter
                        .submit_lhf(&action.dc_ip, &action.domain, cred)
                        .await,
                    "low-hanging fruit",
                )
            }
            ActionKind::ColdStart => (
                adapter
                    .submit_cold_start(&action.domain, &action.dc_ip)
                    .await,
                "cold-start user enumeration",
            ),
        };

        match result {
            Ok(SubmissionOutcome::Submitted(task_id)) => {
                info!(
                    task_id = %task_id,
                    domain = %action.domain,
                    branch = %label,
                    "Stall recovery dispatched"
                );
                report.dispatched += 1;
                adapter.mark_dedup(action.dedup_set, action.dedup_key).await;
            }
            Ok(SubmissionOutcome::Deferred) => {
                info!(
                    domain = %action.domain,
                    branch = %label,
                    "Stall recovery submission deferred (queued; worker capacity reached)"
                );
                report.deferred += 1;
            }
            Ok(SubmissionOutcome::Dropped) => {
                warn!(
                    domain = %action.domain,
                    branch = %label,
                    "Stall recovery submission dropped (queue full or no role mapping)"
                );
                report.dropped += 1;
            }
            Err(e) => {
                warn!(err = %e, branch = %label, "Stall recovery dispatch failed");
                report.errors += 1;
            }
        }
    }

    report
}

/// Build the low-hanging-fruit payload exactly as
/// `Dispatcher::request_low_hanging_fruit` does. Kept inline here so the
/// production adapter can route through `throttled_submit_outcome` and
/// surface `Deferred` vs `Dropped` to the stall WARN.
fn build_lhf_payload(
    target_ip: &str,
    domain: &str,
    credential: &ares_core::models::Credential,
) -> Value {
    json!({
        "techniques": [
            "sysvol_script_search",
            "gpp_password_finder",
            "ldap_search_descriptions",
            "laps_dump",
        ],
        "reason": "low_hanging_fruit",
        "target_ip": target_ip,
        "domain": domain,
        "credential": {
            "username": credential.username,
            "password": credential.password,
            "domain": credential.domain,
        },
    })
}

/// Production adapter wiring `auto_stall_detection` to a live `Dispatcher`.
/// Each method is a thin delegate — the testable orchestration lives in
/// `plan_stall_recovery_diagnostic` and `execute_recovery_actions`.
struct DispatcherStallAdapter<'a> {
    dispatcher: &'a Arc<Dispatcher>,
}

#[async_trait]
impl<'a> StallRecoveryAdapter for DispatcherStallAdapter<'a> {
    async fn submit_spray(&self, domain: &str, dc_ip: &str) -> Result<SubmissionOutcome> {
        let payload = build_spray_payload(domain, dc_ip);
        self.dispatcher
            .throttled_submit_outcome("credential_access", "credential_access", payload, 7)
            .await
    }
    async fn submit_lhf(
        &self,
        dc_ip: &str,
        domain: &str,
        cred: &ares_core::models::Credential,
    ) -> Result<SubmissionOutcome> {
        let payload = build_lhf_payload(dc_ip, domain, cred);
        self.dispatcher
            .throttled_submit_outcome("credential_access", "credential_access", payload, 6)
            .await
    }
    async fn submit_cold_start(&self, domain: &str, dc_ip: &str) -> Result<SubmissionOutcome> {
        let payload = build_cold_start_payload(domain, dc_ip);
        self.dispatcher
            .throttled_submit_outcome("credential_access", "credential_access", payload, 7)
            .await
    }
    async fn mark_dedup(&self, set: &'static str, key: String) {
        self.dispatcher
            .state
            .write()
            .await
            .mark_processed(set, key.clone());
        let _ = self
            .dispatcher
            .state
            .persist_dedup(&self.dispatcher.queue, set, &key)
            .await;
    }
}

/// Monitors for discovery stalls and triggers fallback actions.
/// Interval: 60s.
pub async fn auto_stall_detection(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let start = Instant::now();
    let mut tracker = StallTracker::new();
    let adapter = DispatcherStallAdapter {
        dispatcher: &dispatcher,
    };

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if start.elapsed() < Duration::from_secs(180) {
            continue;
        }

        let (cred_count, hash_count, has_da, has_creds, has_users, has_dcs, all_dominated) = {
            let state = dispatcher.state.read().await;
            (
                state.credentials.len(),
                state.hashes.len(),
                state.has_domain_admin,
                !state.credentials.is_empty(),
                !state.users.is_empty(),
                !state.domain_controllers.is_empty(),
                state.all_forests_dominated(),
            )
        };

        if has_da && !dispatcher.config.strategy.should_continue_after_da() && all_dominated {
            continue;
        }

        if tracker.observe_progress(cred_count, hash_count) {
            // Forward progress: clear any stall pressure on the throttler so
            // the per-role cap returns to the full configured value.
            dispatcher.throttler.set_stall_pressure(0);
            continue;
        }
        if !tracker.is_stalled() {
            continue;
        }
        if !tracker.cooldown_elapsed() {
            continue;
        }
        if tracker.attempts_exhausted() {
            continue;
        }

        let attempt = tracker.note_recovery_attempt();
        // Publish the post-bump zero-progress streak to the throttler. The
        // throttler halves the per-role cap whenever this is >0, stopping
        // parallel agent expansion against an op that isn't progressing.
        dispatcher
            .throttler
            .set_stall_pressure(tracker.zero_progress_streak);

        let plan = {
            let state = dispatcher.state.read().await;
            let ctx = StallContext {
                has_users,
                has_creds,
                has_dcs,
                allow_password_spray: dispatcher.is_technique_allowed("password_spray"),
                allow_asrep_roast: dispatcher.is_technique_allowed("asrep_roast"),
                lhf_max: 2,
            };
            plan_stall_recovery_diagnostic(&state, attempt, &ctx)
        };

        let planned = plan.actions.len();
        let branch_skips = plan.branch_skips.clone();
        let report = execute_recovery_actions(&adapter, plan.actions).await;

        if report.dispatched > 0 {
            info!(
                stall_duration_secs = tracker.stall_duration_secs(),
                cred_count,
                hash_count,
                recovery_attempt = attempt,
                zero_progress_streak = tracker.zero_progress_streak,
                next_cooldown_secs = tracker.effective_cooldown().as_secs(),
                dispatched = report.dispatched,
                deferred = report.deferred,
                dropped = report.dropped,
                errors = report.errors,
                "Operation stall detected — fallback actions dispatched"
            );
        } else {
            // No actions made it to a worker. Surface BOTH the per-branch
            // skip reasons (why the planner produced zero / few actions) AND
            // the submission breakdown (whether the throttler deferred or
            // dropped any submitted action). This is the diagnostic lift the
            // stall-recovery contract requires: the operator must be able to
            // read the WARN and tell whether to fix data (clear a dedup, add
            // a DC), config (enable a technique), or capacity (worker pool /
            // deferred queue size) — not guess.
            let skip_reasons = format_branch_skips(&branch_skips);
            warn!(
                stall_duration_secs = tracker.stall_duration_secs(),
                cred_count,
                hash_count,
                recovery_attempt = attempt,
                has_users,
                has_creds,
                has_dcs,
                planned,
                deferred = report.deferred,
                dropped = report.dropped,
                errors = report.errors,
                branch_skips = %skip_reasons,
                "Operation stall detected — no fallback branch dispatched this round"
            );
        }
    }
}

/// Format per-branch skip reasons for the stall WARN as a compact string the
/// log aggregator can grep. Empty input renders as `"none"`.
pub(crate) fn format_branch_skips(skips: &[(ActionKind, BranchSkipReason)]) -> String {
    if skips.is_empty() {
        return "none".to_string();
    }
    skips
        .iter()
        .map(|(kind, reason)| {
            let kind_str = match kind {
                ActionKind::Spray => "spray",
                ActionKind::LowHanging => "lhf",
                ActionKind::ColdStart => "cold_start",
            };
            format!("{kind_str}={}", reason.as_log_str())
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn make_cred(user: &str, password: &str, domain: &str) -> ares_core::models::Credential {
        ares_core::models::Credential {
            id: format!("c-{user}-{domain}"),
            username: user.to_string(),
            password: password.to_string(),
            domain: domain.to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_vuln_with_domain(
        vuln_id: &str,
        vuln_type: &str,
        domain: &str,
    ) -> ares_core::models::VulnerabilityInfo {
        let mut details = std::collections::HashMap::new();
        details.insert("domain".into(), serde_json::json!(domain));
        ares_core::models::VulnerabilityInfo {
            vuln_id: vuln_id.to_string(),
            vuln_type: vuln_type.to_string(),
            target: "192.168.58.10".to_string(),
            discovered_by: "test".into(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 1,
        }
    }

    #[test]
    fn stall_spray_dedup_key_includes_recovery_attempt() {
        assert_eq!(
            stall_spray_dedup_key("contoso.local", 3),
            "stall_spray:contoso.local:3"
        );
    }

    #[test]
    fn stall_spray_dedup_key_lowercases_domain() {
        assert_eq!(
            stall_spray_dedup_key("Contoso.Local", 0),
            "stall_spray:contoso.local:0"
        );
    }

    #[test]
    fn stall_lhf_dedup_key_combines_domain_user_attempt() {
        assert_eq!(
            stall_lhf_dedup_key("contoso.local", "Administrator", 1),
            "stall_lhf:contoso.local:administrator:1"
        );
    }

    #[test]
    fn pending_delegation_empty_state() {
        let s = StateInner::new("op".into());
        assert!(domains_with_pending_delegation(&s).is_empty());
    }

    #[test]
    fn pending_delegation_collects_constrained_delegation_vulns() {
        let mut s = StateInner::new("op".into());
        let v = make_vuln_with_domain("v1", "constrained_delegation", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        let set = domains_with_pending_delegation(&s);
        assert!(set.contains("contoso.local"));
    }

    #[test]
    fn pending_delegation_collects_rbcd_vulns() {
        let mut s = StateInner::new("op".into());
        let v = make_vuln_with_domain("v1", "rbcd", "fabrikam.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        let set = domains_with_pending_delegation(&s);
        assert!(set.contains("fabrikam.local"));
    }

    #[test]
    fn pending_delegation_skips_exploited_vulns() {
        let mut s = StateInner::new("op".into());
        let v = make_vuln_with_domain("v1", "constrained_delegation", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.exploited_vulnerabilities.insert("v1".into());
        assert!(domains_with_pending_delegation(&s).is_empty());
    }

    #[test]
    fn pending_delegation_skips_non_delegation_types() {
        let mut s = StateInner::new("op".into());
        let v = make_vuln_with_domain("v1", "kerberoastable_account", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        assert!(domains_with_pending_delegation(&s).is_empty());
    }

    #[test]
    fn pending_delegation_picks_up_capitalized_domain_key_alias() {
        let mut s = StateInner::new("op".into());
        let mut details = std::collections::HashMap::new();
        details.insert("Domain".into(), serde_json::json!("contoso.local"));
        let v = ares_core::models::VulnerabilityInfo {
            vuln_id: "v1".into(),
            vuln_type: "rbcd".into(),
            target: "x".into(),
            discovered_by: "test".into(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 1,
        };
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        assert!(domains_with_pending_delegation(&s).contains("contoso.local"));
    }

    #[test]
    fn resolve_stall_dc_ip_exact_match() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert_eq!(
            resolve_stall_dc_ip(&s, "contoso.local").as_deref(),
            Some("192.168.58.10")
        );
    }

    #[test]
    fn resolve_stall_dc_ip_child_fallback() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("child.contoso.local".into(), "192.168.58.11".into());
        assert_eq!(
            resolve_stall_dc_ip(&s, "contoso.local").as_deref(),
            Some("192.168.58.11")
        );
    }

    #[test]
    fn resolve_stall_dc_ip_returns_none_for_unrelated() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        assert!(resolve_stall_dc_ip(&s, "contoso.local").is_none());
    }

    #[test]
    fn select_stall_spray_empty_state() {
        let s = StateInner::new("op".into());
        assert!(select_stall_spray_work(&s, 0).is_empty());
    }

    #[test]
    fn select_stall_spray_emits_known_dc() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_stall_spray_work(&s, 1);
        assert_eq!(
            work,
            vec![("contoso.local".to_string(), "192.168.58.10".to_string())]
        );
    }

    #[test]
    fn select_stall_spray_skips_delegation_domains() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let v = make_vuln_with_domain("v1", "constrained_delegation", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        assert!(select_stall_spray_work(&s, 1).is_empty());
    }

    #[test]
    fn select_stall_spray_skips_already_processed_for_this_round() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.mark_processed(
            DEDUP_PASSWORD_SPRAY,
            stall_spray_dedup_key("contoso.local", 0),
        );
        assert!(select_stall_spray_work(&s, 0).is_empty());
        assert_eq!(select_stall_spray_work(&s, 1).len(), 1);
    }

    #[test]
    fn select_stall_spray_skips_dominated_domain() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.dominated_domains.insert("contoso.local".into());

        assert!(select_stall_spray_work(&s, 0).is_empty());
    }

    #[test]
    fn select_stall_lhf_empty_state() {
        let s = StateInner::new("op".into());
        assert!(select_stall_lhf_work(&s, 0, 2).is_empty());
    }

    #[test]
    fn select_stall_lhf_emits_when_cred_dc_match() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_stall_lhf_work(&s, 0, 5);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].3.username, "alice");
        assert_eq!(work[0].1, "192.168.58.10");
    }

    #[test]
    fn select_stall_lhf_skips_empty_credential_fields() {
        let mut s = StateInner::new("op".into());
        s.credentials.push(make_cred("alice", "", "contoso.local"));
        s.credentials.push(make_cred("bob", "Pw", ""));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert!(select_stall_lhf_work(&s, 0, 5).is_empty());
    }

    #[test]
    fn select_stall_lhf_skips_dominated_domain() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.dominated_domains.insert("contoso.local".into());

        assert!(select_stall_lhf_work(&s, 0, 5).is_empty());
    }

    #[test]
    fn select_stall_lhf_caps_at_max_items() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        for u in &["alice", "bob", "carol", "dave"] {
            s.credentials.push(make_cred(u, "Pw", "contoso.local"));
        }
        assert_eq!(select_stall_lhf_work(&s, 0, 2).len(), 2);
        assert_eq!(select_stall_lhf_work(&s, 0, 10).len(), 4);
    }

    #[test]
    fn select_stall_lhf_skips_already_processed_for_this_round() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let key = stall_lhf_dedup_key("contoso.local", "alice", 0);
        s.mark_processed(DEDUP_EXPANSION_CREDS, key);
        assert!(select_stall_lhf_work(&s, 0, 5).is_empty());
        assert_eq!(select_stall_lhf_work(&s, 1, 5).len(), 1);
    }

    #[test]
    fn stall_cold_start_dedup_key_includes_recovery_attempt() {
        assert_eq!(
            stall_cold_start_dedup_key("contoso.local", 4),
            "stall_cold_start:contoso.local:4"
        );
    }

    #[test]
    fn stall_cold_start_dedup_key_lowercases_domain() {
        assert_eq!(
            stall_cold_start_dedup_key("Contoso.Local", 0),
            "stall_cold_start:contoso.local:0"
        );
    }

    #[test]
    fn select_stall_cold_start_empty_state() {
        let s = StateInner::new("op".into());
        assert!(select_stall_cold_start_work(&s, 0).is_empty());
    }

    #[test]
    fn select_stall_cold_start_emits_known_dc() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_stall_cold_start_work(&s, 1);
        assert_eq!(
            work,
            vec![("contoso.local".to_string(), "192.168.58.10".to_string())]
        );
    }

    #[test]
    fn select_stall_cold_start_skips_dominated_domain() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.dominated_domains.insert("contoso.local".into());
        assert!(select_stall_cold_start_work(&s, 0).is_empty());
    }

    #[test]
    fn select_stall_cold_start_dedup_re_arms_per_attempt() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.mark_processed(
            DEDUP_STALL_COLD_START,
            stall_cold_start_dedup_key("contoso.local", 0),
        );
        assert!(select_stall_cold_start_work(&s, 0).is_empty());
        assert_eq!(select_stall_cold_start_work(&s, 1).len(), 1);
    }

    #[test]
    fn select_stall_cold_start_ignores_delegation_vulns() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let v = make_vuln_with_domain("v1", "constrained_delegation", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        assert_eq!(select_stall_cold_start_work(&s, 0).len(), 1);
    }

    #[test]
    fn select_stall_cold_start_emits_one_per_dc() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        assert_eq!(select_stall_cold_start_work(&s, 0).len(), 2);
    }

    #[test]
    fn build_spray_payload_shape() {
        let p = build_spray_payload("contoso.local", "192.168.58.10");
        assert_eq!(p["technique"], "password_spray");
        assert_eq!(p["target_ip"], "192.168.58.10");
        assert_eq!(p["domain"], "contoso.local");
        assert_eq!(p["use_common_passwords"], true);
        assert_eq!(p["acknowledge_no_policy"], true);
    }

    #[test]
    fn build_cold_start_payload_emits_cold_start_instructions() {
        let p = build_cold_start_payload("contoso.local", "192.168.58.10");
        let techniques = p["techniques"].as_array().expect("techniques array");
        let tech_names: Vec<&str> = techniques.iter().filter_map(|v| v.as_str()).collect();
        assert!(tech_names.contains(&"asrep_roast"));
        assert!(tech_names.contains(&"kerberos_user_enum_noauth"));
        assert_eq!(p["target_ip"], "192.168.58.10");
        assert_eq!(p["domain"], "contoso.local");
        let instructions = p["instructions"].as_str().expect("instructions");
        // Cold-start instructions must name the asrep_roast tool by name and
        // direct the agent to seclists wordlists. Older revisions also
        // mentioned `kerbrute`; the asrep-first rewrite folds that fallback
        // into the kerberos_user_enum_noauth step, so the assertion below
        // checks the stable signals instead.
        assert!(instructions.contains("asrep_roast"));
        assert!(instructions.contains("seclists"));
        assert!(instructions.contains("kerberos_user_enum_noauth"));
        assert!(instructions.contains("MANDATORY FIRST ACTION"));
    }

    fn ctx(
        has_users: bool,
        has_creds: bool,
        has_dcs: bool,
        allow_password_spray: bool,
        allow_asrep_roast: bool,
        lhf_max: usize,
    ) -> StallContext {
        StallContext {
            has_users,
            has_creds,
            has_dcs,
            allow_password_spray,
            allow_asrep_roast,
            lhf_max,
        }
    }

    #[test]
    fn plan_stall_recovery_empty_state_no_actions() {
        let s = StateInner::new("op".into());
        let plan = plan_stall_recovery(&s, 1, &ctx(false, false, false, true, true, 2));
        assert!(plan.is_empty());
    }

    #[test]
    fn plan_stall_recovery_emits_spray_when_users_present() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let plan = plan_stall_recovery(&s, 1, &ctx(true, false, true, true, false, 2));
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].kind, ActionKind::Spray);
        assert_eq!(plan[0].domain, "contoso.local");
        assert_eq!(plan[0].dedup_set, DEDUP_PASSWORD_SPRAY);
        assert_eq!(plan[0].dedup_key, "stall_spray:contoso.local:1");
    }

    #[test]
    fn plan_stall_recovery_emits_lhf_when_creds_present() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let plan = plan_stall_recovery(&s, 1, &ctx(false, true, true, false, false, 2));
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].kind, ActionKind::LowHanging);
        assert_eq!(plan[0].dedup_set, DEDUP_EXPANSION_CREDS);
        assert!(plan[0].cred.is_some());
    }

    #[test]
    fn plan_stall_recovery_emits_cold_start_when_empty() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let plan = plan_stall_recovery(&s, 2, &ctx(false, false, true, false, true, 2));
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].kind, ActionKind::ColdStart);
        assert_eq!(plan[0].dedup_set, DEDUP_STALL_COLD_START);
        assert_eq!(plan[0].dedup_key, "stall_cold_start:contoso.local:2");
    }

    #[test]
    fn plan_stall_recovery_cold_start_suppressed_when_users_or_creds_present() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());

        let plan = plan_stall_recovery(&s, 1, &ctx(true, false, true, false, true, 2));
        assert!(plan.iter().all(|a| a.kind != ActionKind::ColdStart));

        let plan = plan_stall_recovery(&s, 1, &ctx(false, true, true, false, true, 2));
        assert!(plan.iter().all(|a| a.kind != ActionKind::ColdStart));
    }

    #[test]
    fn plan_stall_recovery_spray_gated_by_technique_flag() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let plan = plan_stall_recovery(&s, 1, &ctx(true, false, true, false, true, 2));
        assert!(plan.iter().all(|a| a.kind != ActionKind::Spray));
    }

    #[test]
    fn plan_stall_recovery_cold_start_gated_by_technique_flag() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let plan = plan_stall_recovery(&s, 1, &ctx(false, false, true, true, false, 2));
        assert!(plan.is_empty());
    }

    #[test]
    fn plan_stall_recovery_requires_dcs() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        let plan = plan_stall_recovery(&s, 1, &ctx(true, true, false, true, true, 2));
        assert!(plan.is_empty());
    }

    #[test]
    fn plan_stall_recovery_lhf_respects_cap() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        for u in &["alice", "bob", "carol"] {
            s.credentials.push(make_cred(u, "Pw", "contoso.local"));
        }
        let plan = plan_stall_recovery(&s, 1, &ctx(false, true, true, false, false, 2));
        assert_eq!(plan.len(), 2);
        assert!(plan.iter().all(|a| a.kind == ActionKind::LowHanging));
    }

    #[test]
    fn stall_tracker_observe_progress_marks_change() {
        let mut t = StallTracker::new();
        assert!(t.observe_progress(1, 0));
        assert!(!t.observe_progress(1, 0));
        assert!(t.observe_progress(1, 1));
    }

    #[test]
    fn stall_tracker_observe_progress_resets_attempts() {
        let mut t = StallTracker::new();
        t.force_attempts(3);
        t.observe_progress(1, 0);
        assert!(!t.attempts_exhausted());
        t.force_attempts(MAX_RECOVERY_ATTEMPTS);
        assert!(t.attempts_exhausted());
        t.observe_progress(2, 0);
        assert!(!t.attempts_exhausted());
    }

    #[test]
    fn stall_tracker_is_stalled_after_threshold() {
        let mut t = StallTracker::new();
        assert!(!t.is_stalled());
        t.rewind_last_change(STALL_THRESHOLD + Duration::from_secs(1));
        assert!(t.is_stalled());
    }

    #[test]
    fn stall_tracker_cooldown_elapsed_on_construction() {
        let t = StallTracker::new();
        assert!(t.cooldown_elapsed());
    }

    #[test]
    fn stall_tracker_cooldown_not_elapsed_after_recovery() {
        let mut t = StallTracker::new();
        t.note_recovery_attempt();
        assert!(!t.cooldown_elapsed());
        // First recovery attempt bumps the zero-progress streak to 1, so the
        // effective cooldown is `RECOVERY_COOLDOWN * 2`. Rewind by that much
        // so the cooldown actually elapses.
        t.rewind_last_recovery(t.effective_cooldown() + Duration::from_secs(1));
        assert!(t.cooldown_elapsed());
    }

    #[test]
    fn stall_tracker_note_recovery_increments() {
        let mut t = StallTracker::new();
        assert_eq!(t.note_recovery_attempt(), 1);
        assert_eq!(t.note_recovery_attempt(), 2);
        assert_eq!(t.note_recovery_attempt(), 3);
    }

    #[test]
    fn stall_tracker_attempts_exhausted_at_cap() {
        let mut t = StallTracker::new();
        for _ in 0..MAX_RECOVERY_ATTEMPTS {
            t.note_recovery_attempt();
        }
        assert!(t.attempts_exhausted());
    }

    #[test]
    fn stall_tracker_cooldown_doubles_on_each_zero_progress_round() {
        // First round → base cooldown (2 min). The next round's wait grows
        // exponentially with the unproductive streak: 4 → 8 → 16 → capped.
        let mut t = StallTracker::new();
        t.note_recovery_attempt(); // streak=1
        assert_eq!(t.effective_cooldown(), RECOVERY_COOLDOWN * 2);

        t.note_recovery_attempt(); // streak=2
        assert_eq!(t.effective_cooldown(), RECOVERY_COOLDOWN * 4);

        t.note_recovery_attempt(); // streak=3
                                   // RECOVERY_COOLDOWN = 120s, so 120 × 2^3 = 960s, cap is 16*60 = 960s.
                                   // Exactly at the cap.
        assert_eq!(t.effective_cooldown(), MAX_RECOVERY_COOLDOWN);

        t.note_recovery_attempt(); // streak=4
        assert_eq!(
            t.effective_cooldown(),
            MAX_RECOVERY_COOLDOWN,
            "cooldown caps at MAX_RECOVERY_COOLDOWN"
        );
    }

    #[test]
    fn stall_tracker_progress_resets_backoff() {
        // A productive round must drop the streak back to zero so the next
        // recovery (if needed) re-arms at the base cadence, not the long tail.
        let mut t = StallTracker::new();
        t.note_recovery_attempt();
        t.note_recovery_attempt();
        assert_eq!(t.effective_cooldown(), RECOVERY_COOLDOWN * 4);
        t.observe_progress(1, 0);
        assert_eq!(t.effective_cooldown(), RECOVERY_COOLDOWN);
    }

    #[test]
    fn stall_tracker_backoff_keeps_cooldown_unelapsed_longer() {
        // After 2 unproductive rounds, rewinding by the base cooldown is NOT
        // enough — the dynamic cooldown is 4× longer. This is the whole point
        // of the backoff: stop the orchestrator from re-firing at full cadence
        // against a stuck op.
        let mut t = StallTracker::new();
        t.note_recovery_attempt();
        t.note_recovery_attempt(); // streak=2 → 8 min cooldown
        t.rewind_last_recovery(RECOVERY_COOLDOWN + Duration::from_secs(10));
        assert!(
            !t.cooldown_elapsed(),
            "base cooldown shouldn't satisfy backoff"
        );
        t.rewind_last_recovery(RECOVERY_COOLDOWN * 4);
        assert!(
            t.cooldown_elapsed(),
            "the full backoff window should let recovery fire again"
        );
    }

    #[test]
    fn stall_tracker_stall_duration_secs_increases() {
        let mut t = StallTracker::new();
        assert_eq!(t.stall_duration_secs(), 0);
        t.rewind_last_change(Duration::from_secs(42));
        assert!(t.stall_duration_secs() >= 42);
    }

    /// Hand-rolled fake adapter for testing `execute_recovery_actions`.
    /// Records every call and returns scripted outcomes per action kind.
    #[derive(Clone)]
    enum ScriptedOutcome {
        Ok(SubmissionOutcome),
        Err(String),
    }

    struct FakeAdapter {
        spray_outcome: Mutex<ScriptedOutcome>,
        lhf_outcome: Mutex<ScriptedOutcome>,
        cold_start_outcome: Mutex<ScriptedOutcome>,
        spray_calls: Mutex<Vec<(String, String)>>,
        lhf_calls: Mutex<Vec<(String, String, String)>>,
        cold_start_calls: Mutex<Vec<(String, String)>>,
        dedup_marks: Mutex<Vec<(&'static str, String)>>,
    }

    impl FakeAdapter {
        fn new() -> Self {
            Self {
                spray_outcome: Mutex::new(ScriptedOutcome::Ok(SubmissionOutcome::Submitted(
                    "spray-task".into(),
                ))),
                lhf_outcome: Mutex::new(ScriptedOutcome::Ok(SubmissionOutcome::Submitted(
                    "lhf-task".into(),
                ))),
                cold_start_outcome: Mutex::new(ScriptedOutcome::Ok(SubmissionOutcome::Submitted(
                    "cs-task".into(),
                ))),
                spray_calls: Mutex::new(Vec::new()),
                lhf_calls: Mutex::new(Vec::new()),
                cold_start_calls: Mutex::new(Vec::new()),
                dedup_marks: Mutex::new(Vec::new()),
            }
        }
        fn set_spray(&self, r: ScriptedOutcome) {
            *self.spray_outcome.lock().unwrap() = r;
        }
        fn set_lhf(&self, r: ScriptedOutcome) {
            *self.lhf_outcome.lock().unwrap() = r;
        }
        fn set_cold_start(&self, r: ScriptedOutcome) {
            *self.cold_start_outcome.lock().unwrap() = r;
        }
    }

    #[async_trait]
    impl StallRecoveryAdapter for FakeAdapter {
        async fn submit_spray(&self, domain: &str, dc_ip: &str) -> Result<SubmissionOutcome> {
            self.spray_calls
                .lock()
                .unwrap()
                .push((domain.to_string(), dc_ip.to_string()));
            match self.spray_outcome.lock().unwrap().clone() {
                ScriptedOutcome::Ok(v) => Ok(v),
                ScriptedOutcome::Err(e) => Err(anyhow::anyhow!(e)),
            }
        }
        async fn submit_lhf(
            &self,
            dc_ip: &str,
            domain: &str,
            cred: &ares_core::models::Credential,
        ) -> Result<SubmissionOutcome> {
            self.lhf_calls.lock().unwrap().push((
                dc_ip.to_string(),
                domain.to_string(),
                cred.username.clone(),
            ));
            match self.lhf_outcome.lock().unwrap().clone() {
                ScriptedOutcome::Ok(v) => Ok(v),
                ScriptedOutcome::Err(e) => Err(anyhow::anyhow!(e)),
            }
        }
        async fn submit_cold_start(&self, domain: &str, dc_ip: &str) -> Result<SubmissionOutcome> {
            self.cold_start_calls
                .lock()
                .unwrap()
                .push((domain.to_string(), dc_ip.to_string()));
            match self.cold_start_outcome.lock().unwrap().clone() {
                ScriptedOutcome::Ok(v) => Ok(v),
                ScriptedOutcome::Err(e) => Err(anyhow::anyhow!(e)),
            }
        }
        async fn mark_dedup(&self, set: &'static str, key: String) {
            self.dedup_marks.lock().unwrap().push((set, key));
        }
    }

    fn spray_action(domain: &str, dc_ip: &str, attempt: u32) -> RecoveryAction {
        RecoveryAction {
            kind: ActionKind::Spray,
            domain: domain.to_string(),
            dc_ip: dc_ip.to_string(),
            dedup_key: stall_spray_dedup_key(domain, attempt),
            dedup_set: DEDUP_PASSWORD_SPRAY,
            cred: None,
        }
    }

    fn lhf_action(domain: &str, dc_ip: &str, user: &str, attempt: u32) -> RecoveryAction {
        RecoveryAction {
            kind: ActionKind::LowHanging,
            domain: domain.to_string(),
            dc_ip: dc_ip.to_string(),
            dedup_key: stall_lhf_dedup_key(domain, user, attempt),
            dedup_set: DEDUP_EXPANSION_CREDS,
            cred: Some(make_cred(user, "Pw", domain)),
        }
    }

    fn cold_start_action(domain: &str, dc_ip: &str, attempt: u32) -> RecoveryAction {
        RecoveryAction {
            kind: ActionKind::ColdStart,
            domain: domain.to_string(),
            dc_ip: dc_ip.to_string(),
            dedup_key: stall_cold_start_dedup_key(domain, attempt),
            dedup_set: DEDUP_STALL_COLD_START,
            cred: None,
        }
    }

    #[tokio::test]
    async fn execute_recovery_actions_empty_plan_zero_dispatched() {
        let fake = FakeAdapter::new();
        let report = execute_recovery_actions(&fake, vec![]).await;
        assert_eq!(report.dispatched, 0);
        assert_eq!(report.deferred, 0);
        assert_eq!(report.dropped, 0);
        assert_eq!(report.errors, 0);
        assert!(fake.dedup_marks.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn execute_recovery_actions_dispatches_spray_and_marks_dedup() {
        let fake = FakeAdapter::new();
        let plan = vec![spray_action("contoso.local", "192.168.58.10", 1)];
        let report = execute_recovery_actions(&fake, plan).await;
        assert_eq!(report.dispatched, 1);
        let calls = fake.spray_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "contoso.local");
        let marks = fake.dedup_marks.lock().unwrap();
        assert_eq!(marks.len(), 1);
        assert_eq!(marks[0].0, DEDUP_PASSWORD_SPRAY);
        assert_eq!(marks[0].1, "stall_spray:contoso.local:1");
    }

    #[tokio::test]
    async fn execute_recovery_actions_dispatches_lhf_and_passes_cred() {
        let fake = FakeAdapter::new();
        let plan = vec![lhf_action("contoso.local", "192.168.58.10", "alice", 1)];
        let report = execute_recovery_actions(&fake, plan).await;
        assert_eq!(report.dispatched, 1);
        let calls = fake.lhf_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "192.168.58.10");
        assert_eq!(calls[0].1, "contoso.local");
        assert_eq!(calls[0].2, "alice");
        let marks = fake.dedup_marks.lock().unwrap();
        assert_eq!(marks[0].0, DEDUP_EXPANSION_CREDS);
    }

    #[tokio::test]
    async fn execute_recovery_actions_dispatches_cold_start_and_marks_dedup() {
        let fake = FakeAdapter::new();
        let plan = vec![cold_start_action("fabrikam.local", "192.168.58.40", 3)];
        let report = execute_recovery_actions(&fake, plan).await;
        assert_eq!(report.dispatched, 1);
        let calls = fake.cold_start_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "fabrikam.local");
        let marks = fake.dedup_marks.lock().unwrap();
        assert_eq!(marks[0].0, DEDUP_STALL_COLD_START);
        assert_eq!(marks[0].1, "stall_cold_start:fabrikam.local:3");
    }

    #[tokio::test]
    async fn execute_recovery_actions_counts_deferred_separately_from_dispatched() {
        let fake = FakeAdapter::new();
        fake.set_spray(ScriptedOutcome::Ok(SubmissionOutcome::Deferred));
        let plan = vec![spray_action("contoso.local", "192.168.58.10", 1)];
        let report = execute_recovery_actions(&fake, plan).await;
        // The diagnostic lift: Deferred is now visible to callers so the stall
        // WARN can surface it instead of collapsing to "no fallback dispatched".
        assert_eq!(report.dispatched, 0);
        assert_eq!(report.deferred, 1);
        assert_eq!(report.dropped, 0);
        assert_eq!(fake.spray_calls.lock().unwrap().len(), 1);
        // Deferred must NOT mark dedup — the deferred queue retry needs the
        // action eligible next tick.
        assert!(fake.dedup_marks.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn execute_recovery_actions_counts_dropped_separately_from_dispatched() {
        let fake = FakeAdapter::new();
        fake.set_lhf(ScriptedOutcome::Ok(SubmissionOutcome::Dropped));
        let plan = vec![lhf_action("contoso.local", "192.168.58.10", "alice", 1)];
        let report = execute_recovery_actions(&fake, plan).await;
        assert_eq!(report.dispatched, 0);
        assert_eq!(report.dropped, 1);
        assert!(fake.dedup_marks.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn execute_recovery_actions_counts_errors_separately_from_dispatched() {
        let fake = FakeAdapter::new();
        fake.set_lhf(ScriptedOutcome::Err("dispatch boom".into()));
        let plan = vec![lhf_action("contoso.local", "192.168.58.10", "alice", 1)];
        let report = execute_recovery_actions(&fake, plan).await;
        assert_eq!(report.dispatched, 0);
        assert_eq!(report.errors, 1);
        assert!(fake.dedup_marks.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn execute_recovery_actions_dispatches_mixed_plan() {
        let fake = FakeAdapter::new();
        let plan = vec![
            spray_action("contoso.local", "192.168.58.10", 1),
            lhf_action("contoso.local", "192.168.58.10", "alice", 1),
            cold_start_action("fabrikam.local", "192.168.58.40", 1),
        ];
        let report = execute_recovery_actions(&fake, plan).await;
        assert_eq!(report.dispatched, 3);
        assert_eq!(fake.spray_calls.lock().unwrap().len(), 1);
        assert_eq!(fake.lhf_calls.lock().unwrap().len(), 1);
        assert_eq!(fake.cold_start_calls.lock().unwrap().len(), 1);
        assert_eq!(fake.dedup_marks.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn execute_recovery_actions_partial_success_counts_each_outcome_separately() {
        let fake = FakeAdapter::new();
        fake.set_spray(ScriptedOutcome::Ok(SubmissionOutcome::Deferred));
        fake.set_cold_start(ScriptedOutcome::Err("boom".into()));
        let plan = vec![
            spray_action("contoso.local", "192.168.58.10", 1),
            lhf_action("contoso.local", "192.168.58.10", "alice", 1),
            cold_start_action("fabrikam.local", "192.168.58.40", 1),
        ];
        let report = execute_recovery_actions(&fake, plan).await;
        assert_eq!(report.dispatched, 1);
        assert_eq!(report.deferred, 1);
        assert_eq!(report.dropped, 0);
        assert_eq!(report.errors, 1);
        assert_eq!(report.total(), 3);
        let marks = fake.dedup_marks.lock().unwrap();
        assert_eq!(marks.len(), 1);
        assert_eq!(marks[0].0, DEDUP_EXPANSION_CREDS);
    }

    #[tokio::test]
    async fn execute_recovery_actions_each_action_marks_its_own_dedup_set() {
        let fake = FakeAdapter::new();
        let plan = vec![
            spray_action("contoso.local", "192.168.58.10", 7),
            cold_start_action("fabrikam.local", "192.168.58.40", 7),
        ];
        execute_recovery_actions(&fake, plan).await;
        let marks = fake.dedup_marks.lock().unwrap();
        let sets: Vec<&str> = marks.iter().map(|(s, _)| *s).collect();
        assert!(sets.contains(&DEDUP_PASSWORD_SPRAY));
        assert!(sets.contains(&DEDUP_STALL_COLD_START));
    }

    // -- Diagnostic plan tests ------------------------------------------------
    //
    // Live bug: the auto_stall_detection WARN repeated for hours with
    // has_creds=true, has_dcs=true but "no fallback branch dispatched" because
    // the LHF branch silently produced zero candidates (every cred had no
    // resolvable DC, every cred was an unsalted hash with empty plaintext, or
    // every dedup key was already marked). These tests pin the new
    // diagnostic-lift contract: every branch that contributes zero actions
    // emits an actionable BranchSkipReason explaining why.

    #[test]
    fn diagnostic_plan_reports_precondition_skip_for_each_branch() {
        let s = StateInner::new("op".into());
        let plan = plan_stall_recovery_diagnostic(&s, 1, &ctx(false, false, false, true, true, 2));
        assert!(plan.actions.is_empty());
        // All three branches must report a precondition-unmet skip when state
        // has nothing — that way the operator sees explicit reasons not silence.
        let kinds: Vec<&ActionKind> = plan.branch_skips.iter().map(|(k, _)| k).collect();
        assert!(kinds.contains(&&ActionKind::Spray));
        assert!(kinds.contains(&&ActionKind::LowHanging));
        assert!(kinds.contains(&&ActionKind::ColdStart));
        for (_, reason) in &plan.branch_skips {
            assert!(matches!(reason, BranchSkipReason::PreconditionUnmet { .. }));
        }
    }

    #[test]
    fn diagnostic_plan_reports_technique_not_allowed_for_spray() {
        let mut s = StateInner::new("op".into());
        s.users.push(ares_core::models::User {
            username: "alice".into(),
            domain: "contoso.local".into(),
            description: String::new(),
            is_admin: false,
            source: String::new(),
        });
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let plan = plan_stall_recovery_diagnostic(&s, 1, &ctx(true, false, true, false, true, 2));
        let spray_skip = plan
            .branch_skips
            .iter()
            .find(|(k, _)| *k == ActionKind::Spray)
            .expect("spray skip present");
        assert!(matches!(
            spray_skip.1,
            BranchSkipReason::TechniqueNotAllowed {
                technique: "password_spray"
            }
        ));
    }

    #[test]
    fn diagnostic_plan_reports_technique_not_allowed_for_cold_start() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let plan = plan_stall_recovery_diagnostic(&s, 1, &ctx(false, false, true, true, false, 2));
        let cs_skip = plan
            .branch_skips
            .iter()
            .find(|(k, _)| *k == ActionKind::ColdStart)
            .expect("cold-start skip present");
        assert!(matches!(
            cs_skip.1,
            BranchSkipReason::TechniqueNotAllowed {
                technique: "asrep_roast"
            }
        ));
    }

    #[test]
    fn diagnostic_plan_reports_cold_start_suppressed_when_users_present() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let plan = plan_stall_recovery_diagnostic(&s, 1, &ctx(true, false, true, false, true, 2));
        let cs_skip = plan
            .branch_skips
            .iter()
            .find(|(k, _)| *k == ActionKind::ColdStart)
            .expect("cold-start skip present");
        assert!(matches!(
            cs_skip.1,
            BranchSkipReason::SuppressedByState {
                reason: "users_or_creds_present"
            }
        ));
    }

    /// The live bug shape: creds exist but every cred has an empty password
    /// (only hashes), so LHF silently selects zero work. Confirm the new
    /// diagnostic surfaces `empty_creds` so the operator can crack a hash
    /// instead of staring at a useless WARN.
    #[test]
    fn diagnostic_plan_reports_empty_creds_when_only_hashes_present() {
        let mut s = StateInner::new("op".into());
        // Two "credentials" that are really just username placeholders for
        // hashes (no plaintext). This is the cred_count=2/hash_count=4 shape
        // from the live log.
        s.credentials.push(make_cred("alice", "", "contoso.local"));
        s.credentials.push(make_cred("bob", "", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let plan = plan_stall_recovery_diagnostic(&s, 1, &ctx(false, true, true, false, false, 2));
        assert!(plan.actions.is_empty());
        let lhf_skip = plan
            .branch_skips
            .iter()
            .find(|(k, _)| *k == ActionKind::LowHanging)
            .expect("lhf skip present");
        match &lhf_skip.1 {
            BranchSkipReason::AllCandidatesFiltered {
                considered,
                empty_creds,
                ..
            } => {
                assert_eq!(*considered, 2);
                assert_eq!(*empty_creds, 2);
            }
            other => panic!("expected AllCandidatesFiltered, got {other:?}"),
        }
    }

    #[test]
    fn diagnostic_plan_reports_missing_dc_for_lhf_cred() {
        let mut s = StateInner::new("op".into());
        // Credential is for a domain whose DC isn't in the state map.
        s.credentials
            .push(make_cred("alice", "Pw", "fabrikam.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let plan = plan_stall_recovery_diagnostic(&s, 1, &ctx(false, true, true, false, false, 2));
        let lhf_skip = plan
            .branch_skips
            .iter()
            .find(|(k, _)| *k == ActionKind::LowHanging)
            .expect("lhf skip present");
        match &lhf_skip.1 {
            BranchSkipReason::AllCandidatesFiltered {
                considered,
                missing_dc,
                ..
            } => {
                assert_eq!(*considered, 1);
                assert_eq!(*missing_dc, 1);
            }
            other => panic!("expected AllCandidatesFiltered, got {other:?}"),
        }
    }

    #[test]
    fn diagnostic_plan_reports_dominated_for_lhf_cred() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.dominated_domains.insert("contoso.local".into());
        let plan = plan_stall_recovery_diagnostic(&s, 1, &ctx(false, true, true, false, false, 2));
        let lhf_skip = plan
            .branch_skips
            .iter()
            .find(|(k, _)| *k == ActionKind::LowHanging)
            .expect("lhf skip present");
        match &lhf_skip.1 {
            BranchSkipReason::AllCandidatesFiltered {
                considered,
                dominated,
                ..
            } => {
                assert_eq!(*considered, 1);
                assert_eq!(*dominated, 1);
            }
            other => panic!("expected AllCandidatesFiltered, got {other:?}"),
        }
    }

    #[test]
    fn diagnostic_plan_reports_dedup_skipped_for_lhf_when_already_marked() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let key = stall_lhf_dedup_key("contoso.local", "alice", 1);
        s.mark_processed(DEDUP_EXPANSION_CREDS, key);
        let plan = plan_stall_recovery_diagnostic(&s, 1, &ctx(false, true, true, false, false, 2));
        let lhf_skip = plan
            .branch_skips
            .iter()
            .find(|(k, _)| *k == ActionKind::LowHanging)
            .expect("lhf skip present");
        match &lhf_skip.1 {
            BranchSkipReason::AllCandidatesFiltered {
                considered,
                dedup_skipped,
                ..
            } => {
                assert_eq!(*considered, 1);
                assert_eq!(*dedup_skipped, 1);
            }
            other => panic!("expected AllCandidatesFiltered, got {other:?}"),
        }
    }

    #[test]
    fn diagnostic_plan_reports_delegation_blocked_for_spray() {
        let mut s = StateInner::new("op".into());
        s.users.push(ares_core::models::User {
            username: "alice".into(),
            domain: "contoso.local".into(),
            description: String::new(),
            is_admin: false,
            source: String::new(),
        });
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let v = make_vuln_with_domain("v1", "constrained_delegation", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        let plan = plan_stall_recovery_diagnostic(&s, 1, &ctx(true, false, true, true, false, 2));
        let spray_skip = plan
            .branch_skips
            .iter()
            .find(|(k, _)| *k == ActionKind::Spray)
            .expect("spray skip present");
        match &spray_skip.1 {
            BranchSkipReason::AllCandidatesFiltered {
                considered,
                delegation_blocked,
                ..
            } => {
                assert_eq!(*considered, 1);
                assert_eq!(*delegation_blocked, 1);
            }
            other => panic!("expected AllCandidatesFiltered, got {other:?}"),
        }
    }

    #[test]
    fn diagnostic_plan_dispatches_lhf_when_state_supports_it_and_lists_other_skips() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let plan = plan_stall_recovery_diagnostic(&s, 1, &ctx(false, true, true, false, false, 2));
        assert_eq!(plan.actions.len(), 1);
        assert_eq!(plan.actions[0].kind, ActionKind::LowHanging);
        // Spray + cold-start both skipped, both with explicit reasons.
        let kinds: Vec<&ActionKind> = plan.branch_skips.iter().map(|(k, _)| k).collect();
        assert!(kinds.contains(&&ActionKind::Spray));
        assert!(kinds.contains(&&ActionKind::ColdStart));
    }

    #[test]
    fn format_branch_skips_empty_renders_none() {
        assert_eq!(format_branch_skips(&[]), "none");
    }

    #[test]
    fn format_branch_skips_renders_kind_prefix_per_entry() {
        let skips = vec![
            (
                ActionKind::Spray,
                BranchSkipReason::TechniqueNotAllowed {
                    technique: "password_spray",
                },
            ),
            (
                ActionKind::LowHanging,
                BranchSkipReason::AllCandidatesFiltered {
                    considered: 2,
                    dedup_skipped: 0,
                    dominated: 0,
                    delegation_blocked: 0,
                    missing_dc: 0,
                    empty_creds: 2,
                },
            ),
        ];
        let s = format_branch_skips(&skips);
        assert!(s.contains("spray=technique_not_allowed:password_spray"));
        assert!(s.contains("lhf=all_filtered("));
        assert!(s.contains("empty_creds=2"));
    }

    #[test]
    fn branch_skip_reason_as_log_str_renders_each_variant() {
        assert_eq!(
            BranchSkipReason::PreconditionUnmet { needs: "x" }.as_log_str(),
            "precondition_unmet:x"
        );
        assert_eq!(
            BranchSkipReason::TechniqueNotAllowed { technique: "t" }.as_log_str(),
            "technique_not_allowed:t"
        );
        assert_eq!(
            BranchSkipReason::SuppressedByState { reason: "r" }.as_log_str(),
            "suppressed:r"
        );
        let s = BranchSkipReason::AllCandidatesFiltered {
            considered: 3,
            dedup_skipped: 1,
            dominated: 0,
            delegation_blocked: 0,
            missing_dc: 2,
            empty_creds: 0,
        }
        .as_log_str();
        assert!(s.contains("considered=3"));
        assert!(s.contains("missing_dc=2"));
    }
}
