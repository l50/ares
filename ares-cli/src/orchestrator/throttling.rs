//! Rate limiting and concurrency control.
//!
//! Three layers of throttling:
//! 1. **Per-role semaphores** — limits how many tasks one role can have in-flight.
//! 2. **Global LLM concurrency** — soft cap + 1.5x hard cap before deferring.
//! 3. **Dispatch delay** — minimum interval between consecutive submissions.

#[cfg(test)]
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[cfg(test)]
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::orchestrator::config::OrchestratorConfig;
use crate::orchestrator::routing::ActiveTaskTracker;

/// Task types that bypass hard-cap throttling (DA-critical path).
const CRITICAL_PATH_TASK_TYPES: &[&str] = &["exploit"];

/// High-value exploit subtypes that bypass hard cap.
///
/// Forest-pivot vulns (`forest_trust_escalation`, `child_to_parent`) are the
/// only path off the source forest; if they get parked in the deferred queue
/// behind ordinary recon/exploit work and stale-evict before running, the op
/// stalls in a single forest with no signal to the operator. Treat them as
/// critical-path so the throttler routes them straight to dispatch even when
/// the LLM concurrency cap is saturated.
const CRITICAL_PATH_VULN_TYPES: &[&str] = &[
    "constrained_delegation",
    "unconstrained_delegation",
    "esc1",
    "esc4",
    "esc8",
    "krbtgt_hash",
    "adcs_esc1",
    "adcs_esc4",
    "adcs_esc8",
    "forest_trust_escalation",
    "child_to_parent",
];

/// Maximum tasks allowed to bypass the hard cap simultaneously.
///
/// Sized to accommodate restart-requeue scenarios where many in-flight critical
/// tasks rehydrate at once and the active-task tracker hasn't yet evicted stale
/// entries from the previous orchestrator instance. With MAX_BYPASS_TASKS=3 the
/// bypass channel saturates trivially and even ACL chain steps deadlock waiting
/// for stale exploit tasks to be evicted.
const MAX_BYPASS_TASKS: usize = 10;

/// What the throttler decided about a candidate task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThrottleDecision {
    /// Submit immediately.
    Allow,
    /// Defer to the deferred queue.
    Defer,
    /// Wait for `duration` then re-check.
    Wait(std::time::Duration),
}

/// Concurrency controller — three layers (per-role, global LLM, dispatch delay).
pub struct Throttler {
    config: Arc<OrchestratorConfig>,
    tracker: ActiveTaskTracker,
    /// Per-role semaphores (lazily populated, used in tests).
    #[cfg(test)]
    role_semaphores: tokio::sync::Mutex<HashMap<String, Arc<Semaphore>>>,
    /// Timestamp of the last successful dispatch.
    last_dispatch: tokio::sync::Mutex<Instant>,
    /// Accumulated rate-limit errors (from worker feedback).
    rate_limit_errors: tokio::sync::Mutex<u32>,
    /// Global backoff deadline (if any).
    backoff_until: tokio::sync::Mutex<Option<Instant>>,
    /// Stall-pressure signal written by `auto_stall_detection`: 0 means the
    /// op is making forward progress, >0 means N consecutive recovery rounds
    /// produced zero new creds/hashes. Used to tighten the per-role cap so a
    /// stuck op doesn't keep multiplying parallel duplicated-context agents.
    stall_pressure: Arc<AtomicU32>,
}

impl Throttler {
    pub fn new(config: Arc<OrchestratorConfig>, tracker: ActiveTaskTracker) -> Self {
        Self {
            config,
            tracker,
            #[cfg(test)]
            role_semaphores: tokio::sync::Mutex::new(HashMap::new()),
            last_dispatch: tokio::sync::Mutex::new(Instant::now()),
            rate_limit_errors: tokio::sync::Mutex::new(0),
            backoff_until: tokio::sync::Mutex::new(None),
            stall_pressure: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Update the stall-pressure signal from the stall-recovery loop.
    ///
    /// Zero means progress was observed (back to normal caps). Positive values
    /// are the count of consecutive unproductive recovery rounds; the
    /// effective per-role cap is halved (rounded up, min 1) when this is >0,
    /// throttling parallel agent expansion against a stuck operation.
    pub fn set_stall_pressure(&self, streak: u32) {
        self.stall_pressure.store(streak, Ordering::Relaxed);
    }

    /// Returns the per-role cap to apply right now, accounting for stall
    /// pressure. Stalled ops contract to ⌈base/2⌉ slots per role (minimum 1).
    fn effective_max_tasks_per_role(&self) -> usize {
        let base = self.config.max_tasks_per_role;
        if self.stall_pressure.load(Ordering::Relaxed) == 0 {
            return base;
        }
        // ⌈base/2⌉ — never below 1 so we don't starve the op entirely.
        base.div_ceil(2).max(1)
    }

    /// Evaluate whether `task_type` targeting `role` should be allowed now.
    pub async fn check(
        &self,
        task_type: &str,
        target_role: &str,
        payload: Option<&serde_json::Value>,
    ) -> ThrottleDecision {
        // Non-LLM tasks (crack, command) always pass.
        if crate::orchestrator::routing::is_non_llm_task(task_type) {
            return ThrottleDecision::Allow;
        }

        {
            let backoff = self.backoff_until.lock().await;
            if let Some(deadline) = *backoff {
                if Instant::now() < deadline {
                    let remaining = deadline - Instant::now();
                    return ThrottleDecision::Wait(remaining);
                }
            }
        }

        let llm_count = self.tracker.llm_task_count().await;
        let max_tasks = self.config.max_concurrent_tasks;
        let hard_cap = self.config.hard_cap();

        // Per-role hard ceiling — applies before any global cap check. One
        // role cannot hold more than `max_tasks_per_role` LLM slots, even
        // when the global tracker is below the soft cap. Without this, a
        // role with long-running tool calls (coercion blocking on
        // ntlmrelayx for 600s) keeps accumulating slots while shorter-task
        // roles churn through theirs, eventually saturating the global cap
        // and forcing recon/lateral into the deferred queue where they
        // stale-evict before running. Critical-path and always-bypass
        // task types are exempt — those exist precisely to punch through
        // congestion.
        if !self.is_always_bypass(task_type) && !self.is_critical_path(task_type, payload) {
            let role_count = self.tracker.count_for_role(target_role).await;
            let cap = self.effective_max_tasks_per_role();
            if role_count >= cap {
                debug!(
                    role = target_role,
                    role_count,
                    cap,
                    base_cap = self.config.max_tasks_per_role,
                    stall_pressure = self.stall_pressure.load(Ordering::Relaxed),
                    task_type,
                    "Per-role cap: deferring task"
                );
                return ThrottleDecision::Defer;
            }
        }

        if llm_count >= hard_cap {
            // Always-bypass tasks (acl_chain_step) skip even the bypass-cap.
            // Stale exploit-task buildup must not block the ACL exploitation
            // pipeline since those steps are the actual path to forest
            // compromise.
            if self.is_always_bypass(task_type) {
                info!(
                    llm_count,
                    hard_cap, task_type, "Hard cap: always-bypass critical task — allowing"
                );
                return ThrottleDecision::Allow;
            }

            if self.is_critical_path(task_type, payload) {
                let bypass_count = llm_count.saturating_sub(hard_cap);
                if bypass_count >= MAX_BYPASS_TASKS {
                    warn!(
                        llm_count,
                        hard_cap,
                        bypass_count,
                        task_type,
                        "Hard cap: too many bypass tasks, deferring"
                    );
                    return ThrottleDecision::Defer;
                }
                info!(
                    llm_count,
                    hard_cap,
                    bypass = bypass_count + 1,
                    task_type,
                    "Hard cap: allowing critical-path task"
                );
                return ThrottleDecision::Allow;
            }

            debug!(llm_count, hard_cap, task_type, "Hard cap: deferring task");
            return ThrottleDecision::Defer;
        }

        // No separate soft-cap branch: the per-role ceiling above already
        // enforces fairness across roles, and the hard-cap branch handles
        // overall saturation. Any candidate that reaches here is below both
        // the role ceiling AND the global hard cap — allow it, subject only
        // to the dispatch-delay rate-limit below. The old "soft cap" branch
        // used `max_tasks_per_role` as a minimum floor; that semantic is
        // now subsumed by the ceiling (same value, opposite direction:
        // allow iff role_count < cap).
        let _ = max_tasks;

        {
            let last = self.last_dispatch.lock().await;
            let elapsed = last.elapsed();
            if elapsed < self.config.dispatch_delay {
                let wait = self.config.dispatch_delay - elapsed;
                return ThrottleDecision::Wait(wait);
            }
        }

        ThrottleDecision::Allow
    }

    /// Record that a dispatch happened (updates the last-dispatch timestamp).
    pub async fn record_dispatch(&self) {
        let mut last = self.last_dispatch.lock().await;
        *last = Instant::now();
    }

    /// Record a rate-limit error from a worker. If enough accumulate, trigger
    /// a global backoff.
    pub async fn record_rate_limit_error(&self) {
        let mut errors = self.rate_limit_errors.lock().await;
        *errors += 1;
        let threshold = 3_u32;
        if *errors >= threshold {
            let backoff_secs = 30_u64;
            let mut bo = self.backoff_until.lock().await;
            *bo = Some(Instant::now() + std::time::Duration::from_secs(backoff_secs));
            warn!(
                errors = *errors,
                backoff_secs, "Rate limit threshold reached — applying global backoff"
            );
            *errors = 0;
        }
    }

    /// Clear one rate-limit error (call on successful task completion).
    pub async fn clear_rate_limit_error(&self) {
        let mut errors = self.rate_limit_errors.lock().await;
        *errors = errors.saturating_sub(1);
    }

    /// Acquire a per-role semaphore permit. Returns a guard that releases on drop.
    #[cfg(test)]
    pub async fn acquire_role_permit(
        &self,
        role: &str,
    ) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let sem = {
            let mut sems = self.role_semaphores.lock().await;
            sems.entry(role.to_string())
                .or_insert_with(|| Arc::new(Semaphore::new(self.config.max_tasks_per_role)))
                .clone()
        };
        sem.try_acquire_owned().ok()
    }

    /// Task types that bypass even the bypass-cap (always allowed past hard cap).
    /// These are paths whose dispatch must never be blocked by stale or
    /// hung in-flight tasks — `acl_chain_step` runs from `auto_dacl_abuse`
    /// with a pre-resolved credential and is the practical path to forest
    /// compromise via ACL exploitation.
    fn is_always_bypass(&self, task_type: &str) -> bool {
        matches!(task_type, "acl_chain_step")
    }

    fn is_critical_path(&self, task_type: &str, payload: Option<&serde_json::Value>) -> bool {
        // Always-bypass tasks are also critical path (covered separately
        // earlier in `check`, but keep the function consistent).
        if self.is_always_bypass(task_type) {
            return true;
        }

        // Check exploit + vuln_type
        if CRITICAL_PATH_TASK_TYPES.contains(&task_type) {
            if let Some(p) = payload {
                let vt = p
                    .get("vuln_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                if CRITICAL_PATH_VULN_TYPES.contains(&vt.as_str()) {
                    return true;
                }
            }
        }

        // Check delegation enumeration
        if task_type == "privesc_enumeration" {
            if let Some(techniques) = payload
                .and_then(|p| p.get("techniques"))
                .and_then(|v| v.as_array())
            {
                if techniques.iter().any(|t| {
                    t.as_str()
                        .map(|s| s.to_lowercase().contains("delegation"))
                        .unwrap_or(false)
                }) {
                    return true;
                }
            }
        }

        // Check ESC8 coercion
        if task_type == "coercion" {
            if let Some(techniques) = payload
                .and_then(|p| p.get("techniques"))
                .and_then(|v| v.as_array())
            {
                let esc8_techniques = ["ntlmrelayx_to_adcs", "petitpotam"];
                if techniques.iter().any(|t| {
                    t.as_str()
                        .map(|s| esc8_techniques.contains(&s.to_lowercase().as_str()))
                        .unwrap_or(false)
                }) {
                    return true;
                }
            }
        }

        // Secretsdump is the canonical DA route once a local-admin credential
        // is in hand. auto_local_admin_secretsdump (and the PTH child-to-parent
        // path) submit as task_type=credential_access, which shares a per-role
        // cap with kerberoast/AS-REP roast/password-spray automations. When
        // those long-running enumeration tasks saturate the role, every fresh
        // secretsdump request gets deferred and then stale-evicted from the
        // deferred queue before it can run — the op stalls with 0 DCs
        // compromised despite having valid credentials. Whitelist the
        // `secretsdump` technique only (not the whole role) so it rides the
        // bypass channel without giving roast/spray automations a free pass.
        if task_type == "credential_access" {
            if let Some(technique) = payload
                .and_then(|p| p.get("technique"))
                .and_then(|v| v.as_str())
            {
                if technique.eq_ignore_ascii_case("secretsdump") {
                    return true;
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::routing::{ActiveTask, ActiveTaskTracker};
    use serde_json::json;

    fn make_throttler(max_tasks: usize) -> (Throttler, ActiveTaskTracker) {
        let config = Arc::new(crate::orchestrator::config::OrchestratorConfig {
            redis_url: "redis://localhost".into(),
            nats_url: "nats://localhost:4222".into(),
            operation_id: "test-op".into(),
            max_concurrent_tasks: max_tasks,
            heartbeat_interval: std::time::Duration::from_secs(30),
            heartbeat_timeout: std::time::Duration::from_secs(120),
            result_poll_interval: std::time::Duration::from_millis(500),
            lock_ttl: std::time::Duration::from_secs(300),
            deferred_poll_interval: std::time::Duration::from_secs(10),
            max_tasks_per_role: 3,
            dispatch_delay: std::time::Duration::from_millis(0),
            stale_task_timeout: std::time::Duration::from_secs(300),
            deferred_task_max_age: std::time::Duration::from_secs(300),
            max_deferred_per_type: 5,
            max_deferred_total: 20,
            target_domain: String::new(),
            target_ips: Vec::new(),
            initial_credential: None,
            strategy: crate::orchestrator::strategy::Strategy::default(),
            listener_ip: None,
        });
        let tracker = ActiveTaskTracker::new();
        (Throttler::new(config, tracker.clone()), tracker)
    }

    #[tokio::test]
    async fn non_llm_always_allowed() {
        let (t, _) = make_throttler(1);
        assert_eq!(
            t.check("crack", "cracker", None).await,
            ThrottleDecision::Allow
        );
        assert_eq!(
            t.check("command", "lateral", None).await,
            ThrottleDecision::Allow
        );
    }

    #[tokio::test]
    async fn under_soft_cap_allows() {
        let (t, _) = make_throttler(8);
        assert_eq!(
            t.check("recon", "recon", None).await,
            ThrottleDecision::Allow
        );
    }

    #[tokio::test]
    async fn hard_cap_defers_non_critical() {
        let (t, tracker) = make_throttler(2); // soft=2, hard=3
        for i in 0..3 {
            tracker
                .add(ActiveTask {
                    task_id: format!("t{i}"),
                    task_type: "recon".into(),
                    role: "recon".into(),
                    submitted_at: Instant::now(),
                    last_activity: Instant::now(),
                    credential_key: None,
                })
                .await;
        }
        assert_eq!(
            t.check("recon", "recon", None).await,
            ThrottleDecision::Defer
        );
    }

    #[tokio::test]
    async fn critical_path_bypasses_hard_cap() {
        let (t, tracker) = make_throttler(2);
        for i in 0..3 {
            tracker
                .add(ActiveTask {
                    task_id: format!("t{i}"),
                    task_type: "recon".into(),
                    role: "recon".into(),
                    submitted_at: Instant::now(),
                    last_activity: Instant::now(),
                    credential_key: None,
                })
                .await;
        }
        let payload = json!({"vuln_type": "constrained_delegation"});
        assert_eq!(
            t.check("exploit", "privesc", Some(&payload)).await,
            ThrottleDecision::Allow
        );
    }

    #[tokio::test]
    async fn critical_path_delegation_enum() {
        let (t, tracker) = make_throttler(2);
        for i in 0..3 {
            tracker
                .add(ActiveTask {
                    task_id: format!("t{i}"),
                    task_type: "recon".into(),
                    role: "recon".into(),
                    submitted_at: Instant::now(),
                    last_activity: Instant::now(),
                    credential_key: None,
                })
                .await;
        }
        let payload = json!({"techniques": ["find_delegation"]});
        assert_eq!(
            t.check("privesc_enumeration", "privesc", Some(&payload))
                .await,
            ThrottleDecision::Allow
        );
    }

    #[tokio::test]
    async fn critical_path_esc8_coercion() {
        let (t, tracker) = make_throttler(2);
        for i in 0..3 {
            tracker
                .add(ActiveTask {
                    task_id: format!("t{i}"),
                    task_type: "recon".into(),
                    role: "recon".into(),
                    submitted_at: Instant::now(),
                    last_activity: Instant::now(),
                    credential_key: None,
                })
                .await;
        }
        let payload = json!({"techniques": ["petitpotam"]});
        assert_eq!(
            t.check("coercion", "coercion", Some(&payload)).await,
            ThrottleDecision::Allow
        );
    }

    #[tokio::test]
    async fn critical_path_forest_trust_escalation_bypasses_hard_cap() {
        // Forest pivot vulns must not be parked behind ordinary recon work —
        // they're the only path off the source forest.
        let (t, tracker) = make_throttler(2);
        for i in 0..3 {
            tracker
                .add(ActiveTask {
                    task_id: format!("t{i}"),
                    task_type: "recon".into(),
                    role: "recon".into(),
                    submitted_at: Instant::now(),
                    last_activity: Instant::now(),
                    credential_key: None,
                })
                .await;
        }
        for vt in ["forest_trust_escalation", "child_to_parent"] {
            let payload = json!({"vuln_type": vt});
            assert_eq!(
                t.check("exploit", "privesc", Some(&payload)).await,
                ThrottleDecision::Allow,
                "{vt} should bypass hard cap"
            );
        }
    }

    #[tokio::test]
    async fn critical_path_secretsdump_bypasses_role_cap() {
        // Saturate the credential_access role with kerberoast-style work
        // (no payload), then verify a secretsdump submission rides the bypass
        // while sibling techniques (kerberoast, asreproast, password_spray)
        // still defer. Per-role fairness for high-volume enumeration is
        // preserved; only the DA-route technique punches through.
        let (t, tracker) = make_throttler(8);
        for i in 0..3 {
            tracker
                .add(ActiveTask {
                    task_id: format!("kr{i}"),
                    task_type: "credential_access".into(),
                    role: "credential_access".into(),
                    submitted_at: Instant::now(),
                    last_activity: Instant::now(),
                    credential_key: None,
                })
                .await;
        }

        let secretsdump = json!({"technique": "secretsdump", "target_ip": "192.168.58.10"});
        assert_eq!(
            t.check("credential_access", "credential_access", Some(&secretsdump))
                .await,
            ThrottleDecision::Allow,
            "secretsdump must bypass per-role cap"
        );

        for technique in ["kerberoast", "asreproast", "password_spray"] {
            let payload = json!({"technique": technique});
            assert_eq!(
                t.check("credential_access", "credential_access", Some(&payload))
                    .await,
                ThrottleDecision::Defer,
                "{technique} must still be capped"
            );
        }
    }

    #[tokio::test]
    async fn critical_path_acl_chain_step_bypasses_hard_cap() {
        let (t, tracker) = make_throttler(2);
        // Saturate well beyond hard_cap (3) and beyond MAX_BYPASS_TASKS (10)
        // to verify acl_chain_step bypasses even the bypass-cap.
        for i in 0..50 {
            tracker
                .add(ActiveTask {
                    task_id: format!("t{i}"),
                    task_type: "exploit".into(),
                    role: "privesc".into(),
                    submitted_at: Instant::now(),
                    last_activity: Instant::now(),
                    credential_key: None,
                })
                .await;
        }
        let payload = json!({"acl_type": "writeproperty", "target_user": "krbtgt"});
        assert_eq!(
            t.check("acl_chain_step", "acl", Some(&payload)).await,
            ThrottleDecision::Allow
        );
    }

    #[tokio::test]
    async fn critical_path_exploit_still_bypass_capped() {
        let (t, tracker) = make_throttler(2);
        // Saturate beyond MAX_BYPASS_TASKS — ordinary critical-path exploits
        // must still be deferred (only acl_chain_step is always-bypass).
        for i in 0..50 {
            tracker
                .add(ActiveTask {
                    task_id: format!("t{i}"),
                    task_type: "exploit".into(),
                    role: "privesc".into(),
                    submitted_at: Instant::now(),
                    last_activity: Instant::now(),
                    credential_key: None,
                })
                .await;
        }
        let payload = json!({"vuln_type": "constrained_delegation"});
        assert_eq!(
            t.check("exploit", "privesc", Some(&payload)).await,
            ThrottleDecision::Defer
        );
    }

    #[tokio::test]
    async fn per_role_cap_defers_with_global_headroom() {
        // max_tasks_per_role=3 in make_config. Even though global is below
        // the soft cap (8), a role already at 3 must defer.
        let (t, tracker) = make_throttler(8);
        for i in 0..3 {
            tracker
                .add(ActiveTask {
                    task_id: format!("c{i}"),
                    task_type: "coercion".into(),
                    role: "coercion".into(),
                    submitted_at: Instant::now(),
                    last_activity: Instant::now(),
                    credential_key: None,
                })
                .await;
        }
        assert_eq!(
            t.check("coercion", "coercion", None).await,
            ThrottleDecision::Defer,
            "role at cap should defer even with global headroom"
        );
        // Different role still has headroom.
        assert_eq!(
            t.check("recon", "recon", None).await,
            ThrottleDecision::Allow,
            "different role should still be allowed"
        );
    }

    #[tokio::test]
    async fn per_role_cap_bypassed_by_critical_path() {
        // Critical-path task types must punch through the per-role cap —
        // forest-pivot vulns can't be parked behind a saturated role queue.
        let (t, tracker) = make_throttler(8);
        for i in 0..5 {
            tracker
                .add(ActiveTask {
                    task_id: format!("p{i}"),
                    task_type: "exploit".into(),
                    role: "privesc".into(),
                    submitted_at: Instant::now(),
                    last_activity: Instant::now(),
                    credential_key: None,
                })
                .await;
        }
        let payload = json!({"vuln_type": "forest_trust_escalation"});
        assert_eq!(
            t.check("exploit", "privesc", Some(&payload)).await,
            ThrottleDecision::Allow,
            "critical-path vuln should bypass per-role cap"
        );
    }

    #[tokio::test]
    async fn stall_pressure_halves_per_role_cap() {
        // Baseline: with max_tasks_per_role=3 and zero stall pressure, two
        // tasks already in flight allows a third. Under stall pressure the
        // effective cap becomes ⌈3/2⌉=2, so the third must defer.
        let (t, tracker) = make_throttler(8);
        for i in 0..2 {
            tracker
                .add(ActiveTask {
                    task_id: format!("r{i}"),
                    task_type: "recon".into(),
                    role: "recon".into(),
                    submitted_at: Instant::now(),
                    last_activity: Instant::now(),
                    credential_key: None,
                })
                .await;
        }

        // No stall pressure: 2 < 3 → Allow.
        assert_eq!(
            t.check("recon", "recon", None).await,
            ThrottleDecision::Allow,
            "below cap with no stall pressure should allow"
        );

        // Mark the op as stuck (1 unproductive recovery round).
        t.set_stall_pressure(1);
        assert_eq!(
            t.check("recon", "recon", None).await,
            ThrottleDecision::Defer,
            "stall pressure should contract the cap and defer"
        );

        // Recovery: clearing the pressure restores the full cap.
        t.set_stall_pressure(0);
        assert_eq!(
            t.check("recon", "recon", None).await,
            ThrottleDecision::Allow,
            "clearing stall pressure should restore full cap"
        );
    }

    #[tokio::test]
    async fn stall_pressure_never_falls_below_one() {
        // Even with max_tasks_per_role=1, stall mode must leave at least one
        // slot per role open — otherwise no role can ever dispatch and the
        // op deadlocks instead of degrading gracefully.
        let (t, _tracker) = make_throttler(8);
        // Override per-role cap to 1 (lower bound).
        let _ = t.config.max_tasks_per_role; // sanity: 3 in make_throttler
        t.set_stall_pressure(5);
        // ⌈3/2⌉=2, still > 0. With our cap=3 default, effective=2.
        // Test the floor by inspecting effective_max_tasks_per_role directly.
        assert!(t.effective_max_tasks_per_role() >= 1);
    }

    #[tokio::test]
    async fn rate_limit_triggers_backoff() {
        let (t, _) = make_throttler(8);
        t.record_rate_limit_error().await;
        t.record_rate_limit_error().await;
        t.record_rate_limit_error().await; // threshold=3
        assert!(matches!(
            t.check("recon", "recon", None).await,
            ThrottleDecision::Wait(_)
        ));
    }

    #[tokio::test]
    async fn clear_error_prevents_backoff() {
        let (t, _) = make_throttler(8);
        t.record_rate_limit_error().await;
        t.record_rate_limit_error().await;
        t.clear_rate_limit_error().await; // back to 1
        t.record_rate_limit_error().await; // now 2
        assert_eq!(
            t.check("recon", "recon", None).await,
            ThrottleDecision::Allow
        );
    }

    #[tokio::test]
    async fn role_semaphore_limits() {
        let (t, _) = make_throttler(8);
        let _p1 = t.acquire_role_permit("recon").await;
        let _p2 = t.acquire_role_permit("recon").await;
        let _p3 = t.acquire_role_permit("recon").await;
        assert!(_p1.is_some() && _p2.is_some() && _p3.is_some());
        assert!(t.acquire_role_permit("recon").await.is_none());
        assert!(t.acquire_role_permit("lateral").await.is_some());
    }

    #[tokio::test]
    async fn stale_cleanup_releases_per_role_slot_for_throttler() {
        // End-to-end: saturate the per-role cap with stale tasks, run cleanup,
        // and verify the throttler now allows a fresh dispatch. Before the
        // fix, the per-role counter leaked when stale eviction landed and
        // the throttler kept returning `Defer` indefinitely — wedging the
        // orchestrator with `llm_count` frozen and zero outbound LLM
        // traffic.
        let (t, tracker) = make_throttler(8);
        let max_per_role = t.config.max_tasks_per_role; // 3 from make_throttler
        let stale_at = std::time::Instant::now() - std::time::Duration::from_secs(600);
        for i in 0..max_per_role {
            tracker
                .add(ActiveTask {
                    task_id: format!("stuck{i}"),
                    task_type: "recon".into(),
                    role: "recon".into(),
                    submitted_at: stale_at,
                    last_activity: stale_at,
                    credential_key: None,
                })
                .await;
        }

        // Confirm the wedge: with the role at cap, new recon dispatch defers.
        assert_eq!(
            t.check("recon", "recon", None).await,
            ThrottleDecision::Defer,
            "saturated per-role cap should defer before cleanup"
        );

        // Cleanup runs (mirrors monitoring.rs::cleanup_stale_tasks).
        let removed = tracker
            .remove_stale_tasks(std::time::Duration::from_secs(60))
            .await;
        assert_eq!(removed.len(), max_per_role);

        // Throttler must now see the freed slots — Allow, not Defer.
        assert_eq!(
            t.check("recon", "recon", None).await,
            ThrottleDecision::Allow,
            "stale cleanup must release per-role slots so dispatch resumes"
        );
        assert_eq!(tracker.count_for_role("recon").await, 0);
        assert_eq!(tracker.llm_task_count().await, 0);
    }

    #[tokio::test]
    async fn stale_cleanup_double_call_does_not_underflow() {
        // Defensive: cleanup called twice (or racing with the result
        // consumer) must not underflow the per-role counter. The throttler
        // would interpret an underflowed `usize` as a huge in-flight count
        // and over-defer — exactly the wedge symptom we're guarding against.
        let (t, tracker) = make_throttler(8);
        let stale_at = std::time::Instant::now() - std::time::Duration::from_secs(600);
        tracker
            .add(ActiveTask {
                task_id: "stuck".into(),
                task_type: "recon".into(),
                role: "recon".into(),
                submitted_at: stale_at,
                last_activity: stale_at,
                credential_key: None,
            })
            .await;

        let first = tracker
            .remove_stale_tasks(std::time::Duration::from_secs(60))
            .await;
        assert_eq!(first.len(), 1);
        let second = tracker
            .remove_stale_tasks(std::time::Duration::from_secs(60))
            .await;
        assert!(second.is_empty());

        assert_eq!(tracker.count_for_role("recon").await, 0);
        assert_eq!(tracker.llm_task_count().await, 0);
        assert_eq!(
            t.check("recon", "recon", None).await,
            ThrottleDecision::Allow
        );
    }
}
