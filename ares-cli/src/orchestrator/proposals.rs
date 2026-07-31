use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::sync::{watch, Notify, RwLock};
use tracing::{debug, info, warn};

use super::deferred::DeferredTask;
use super::dispatcher::Dispatcher;

const DEFAULT_WINDOW_SECS: u64 = 60;
const DEFAULT_CAPACITY: usize = 200;
const DEFAULT_REJECTION_TTL_SECS: u64 = 600;
const SWEEP_INTERVAL_SECS: u64 = 5;

pub fn mediation_enabled() -> bool {
    match std::env::var("ARES_ORCHESTRATOR_MEDIATION") {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        ),
        Err(_) => true,
    }
}

fn secs_from_env(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn usize_from_env(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

pub struct Proposal {
    pub id: String,
    pub task: DeferredTask,
    pub proposed_at: Instant,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProposalOutcome {
    Parked,
    Duplicate,
    PreviouslyRejected,
    Full,
}

struct PoolInner {
    proposals: Vec<Proposal>,
    signatures: HashSet<String>,
    rejected: HashMap<String, Instant>,
    next_id: u64,
}

pub struct ProposalPool {
    inner: RwLock<PoolInner>,
    window: Duration,
    capacity: usize,
    rejection_ttl: Duration,
    arrival: Notify,
}

impl ProposalPool {
    pub fn new(window: Duration, capacity: usize, rejection_ttl: Duration) -> Self {
        Self {
            inner: RwLock::new(PoolInner {
                proposals: Vec::new(),
                signatures: HashSet::new(),
                rejected: HashMap::new(),
                next_id: 1,
            }),
            window,
            capacity,
            rejection_ttl,
            arrival: Notify::new(),
        }
    }

    pub async fn wait_for_arrival(&self) {
        self.arrival.notified().await
    }

    pub fn from_env() -> Self {
        Self::new(
            Duration::from_secs(secs_from_env(
                "ARES_ORCHESTRATOR_MEDIATION_WINDOW_SECS",
                DEFAULT_WINDOW_SECS,
            )),
            usize_from_env("ARES_ORCHESTRATOR_MEDIATION_CAPACITY", DEFAULT_CAPACITY),
            Duration::from_secs(secs_from_env(
                "ARES_ORCHESTRATOR_MEDIATION_REJECTION_TTL_SECS",
                DEFAULT_REJECTION_TTL_SECS,
            )),
        )
    }

    pub fn window(&self) -> Duration {
        self.window
    }

    pub async fn len(&self) -> usize {
        self.inner.read().await.proposals.len()
    }

    pub async fn propose(&self, task: DeferredTask) -> ProposalOutcome {
        let signature = task.signature();
        let mut inner = self.inner.write().await;

        inner
            .rejected
            .retain(|_, at| at.elapsed() < self.rejection_ttl);

        if inner.rejected.contains_key(&signature) {
            return ProposalOutcome::PreviouslyRejected;
        }
        if inner.signatures.contains(&signature) {
            return ProposalOutcome::Duplicate;
        }
        if inner.proposals.len() >= self.capacity {
            return ProposalOutcome::Full;
        }

        let id = format!("p{:04}", inner.next_id);
        inner.next_id += 1;
        inner.signatures.insert(signature);
        inner.proposals.push(Proposal {
            id,
            task,
            proposed_at: Instant::now(),
        });
        drop(inner);
        self.arrival.notify_one();
        ProposalOutcome::Parked
    }

    pub async fn list(&self, limit: usize) -> Vec<serde_json::Value> {
        let inner = self.inner.read().await;
        let mut views: Vec<&Proposal> = inner.proposals.iter().collect();
        views.sort_by_key(|p| p.task.priority);
        views
            .iter()
            .take(limit)
            .map(|p| proposal_view(p, self.window))
            .collect()
    }

    pub async fn approve(&self, ids: &[String]) -> (Vec<DeferredTask>, Vec<String>) {
        let mut inner = self.inner.write().await;
        let mut approved = Vec::new();
        let mut unknown = Vec::new();
        for id in ids {
            match inner.proposals.iter().position(|p| &p.id == id) {
                Some(idx) => {
                    let p = inner.proposals.remove(idx);
                    inner.signatures.remove(&p.task.signature());
                    approved.push(p.task);
                }
                None => unknown.push(id.clone()),
            }
        }
        (approved, unknown)
    }

    pub async fn reject(&self, id: &str) -> Option<DeferredTask> {
        let mut inner = self.inner.write().await;
        let idx = inner.proposals.iter().position(|p| p.id == id)?;
        let p = inner.proposals.remove(idx);
        let signature = p.task.signature();
        inner.signatures.remove(&signature);
        inner.rejected.insert(signature, Instant::now());
        Some(p.task)
    }

    pub async fn take_expired(&self) -> Vec<DeferredTask> {
        let mut inner = self.inner.write().await;
        let window = self.window;
        let mut expired = Vec::new();
        let mut i = 0;
        while i < inner.proposals.len() {
            if inner.proposals[i].proposed_at.elapsed() >= window {
                let p = inner.proposals.remove(i);
                let signature = p.task.signature();
                inner.signatures.remove(&signature);
                expired.push(p.task);
            } else {
                i += 1;
            }
        }
        expired
    }
}

fn payload_str(payload: &serde_json::Value, keys: &[&str]) -> String {
    for key in keys {
        if let Some(v) = payload.get(*key).and_then(|v| v.as_str()) {
            if !v.is_empty() {
                return v.to_string();
            }
        }
    }
    String::new()
}

fn proposal_view(p: &Proposal, window: Duration) -> serde_json::Value {
    let payload = &p.task.payload;
    let principal = payload
        .get("credential")
        .and_then(|c| {
            let user = c.get("username").and_then(|v| v.as_str()).unwrap_or("");
            let dom = c.get("domain").and_then(|v| v.as_str()).unwrap_or("");
            if user.is_empty() {
                None
            } else {
                Some(format!("{user}@{dom}"))
            }
        })
        .unwrap_or_default();
    let age = p.proposed_at.elapsed();
    json!({
        "id": p.id,
        "task_type": p.task.task_type,
        "target_role": p.task.target_role,
        "priority": p.task.priority,
        "technique": payload_str(payload, &["technique"]),
        "target": payload_str(payload, &["target_ip", "dc_ip", "target"]),
        "vuln_id": payload_str(payload, &["vuln_id"]),
        "principal": principal,
        "age_secs": age.as_secs(),
        "auto_release_in_secs": window.saturating_sub(age).as_secs(),
    })
}

pub fn spawn_proposal_sweeper(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(SWEEP_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        info!(
            window_secs = dispatcher.proposals.window().as_secs(),
            "Proposal sweeper started"
        );

        loop {
            tokio::select! {
                _ = interval.tick() => {},
                _ = shutdown.changed() => break,
            }
            if *shutdown.borrow() {
                break;
            }

            let expired = dispatcher.proposals.take_expired().await;
            if expired.is_empty() {
                continue;
            }

            warn!(
                count = expired.len(),
                "Orchestrator did not rule on proposals within the window — auto-releasing"
            );
            for task in expired {
                if let Err(e) = dispatcher
                    .submit_approved(
                        &task.task_type,
                        &task.target_role,
                        task.payload.clone(),
                        task.priority,
                    )
                    .await
                {
                    debug!(err = %e, task_type = %task.task_type, "Auto-release submit failed");
                }
            }
        }

        info!("Proposal sweeper stopped");
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(task_type: &str, role: &str, target_ip: &str, priority: i32) -> DeferredTask {
        DeferredTask {
            priority,
            enqueue_time: 0.0,
            task_type: task_type.to_string(),
            target_role: role.to_string(),
            payload: json!({"target_ip": target_ip, "technique": "secretsdump"}),
            source_agent: "orchestrator".to_string(),
        }
    }

    fn pool() -> ProposalPool {
        ProposalPool::new(Duration::from_secs(60), 10, Duration::from_secs(600))
    }

    #[tokio::test]
    async fn parks_and_lists_a_proposal() {
        let p = pool();
        assert_eq!(
            p.propose(task(
                "credential_access",
                "credential_access",
                "192.168.58.10",
                3
            ))
            .await,
            ProposalOutcome::Parked
        );
        let listed = p.list(10).await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["target"], "192.168.58.10");
        assert_eq!(listed[0]["target_role"], "credential_access");
    }

    #[tokio::test]
    async fn identical_work_proposed_twice_is_deduped() {
        let p = pool();
        let first = p
            .propose(task(
                "credential_access",
                "credential_access",
                "192.168.58.10",
                3,
            ))
            .await;
        let second = p
            .propose(task(
                "credential_access",
                "credential_access",
                "192.168.58.10",
                3,
            ))
            .await;
        assert_eq!(first, ProposalOutcome::Parked);
        assert_eq!(second, ProposalOutcome::Duplicate);
        assert_eq!(p.len().await, 1);
    }

    #[tokio::test]
    async fn distinct_targets_are_separate_proposals() {
        let p = pool();
        p.propose(task("recon", "recon", "192.168.58.10", 1)).await;
        p.propose(task("recon", "recon", "192.168.58.11", 1)).await;
        assert_eq!(p.len().await, 2);
    }

    #[tokio::test]
    async fn approve_removes_and_returns_the_task() {
        let p = pool();
        p.propose(task("recon", "recon", "192.168.58.10", 1)).await;
        let id = p.list(10).await[0]["id"].as_str().unwrap().to_string();

        let (approved, unknown) = p.approve(&[id]).await;
        assert_eq!(approved.len(), 1);
        assert!(unknown.is_empty());
        assert_eq!(approved[0].target_role, "recon");
        assert_eq!(p.len().await, 0);
    }

    #[tokio::test]
    async fn approving_an_unknown_id_is_reported_not_silently_dropped() {
        let p = pool();
        let (approved, unknown) = p.approve(&["p9999".to_string()]).await;
        assert!(approved.is_empty());
        assert_eq!(unknown, vec!["p9999".to_string()]);
    }

    #[tokio::test]
    async fn rejected_work_is_not_reproposed_within_the_ttl() {
        let p = pool();
        p.propose(task("recon", "recon", "192.168.58.10", 1)).await;
        let id = p.list(10).await[0]["id"].as_str().unwrap().to_string();

        assert!(p.reject(&id).await.is_some());
        assert_eq!(p.len().await, 0);

        assert_eq!(
            p.propose(task("recon", "recon", "192.168.58.10", 1)).await,
            ProposalOutcome::PreviouslyRejected
        );
        assert_eq!(p.len().await, 0);
    }

    #[tokio::test]
    async fn rejection_expires_after_the_ttl() {
        let p = ProposalPool::new(Duration::from_secs(60), 10, Duration::from_millis(1));
        p.propose(task("recon", "recon", "192.168.58.10", 1)).await;
        let id = p.list(10).await[0]["id"].as_str().unwrap().to_string();
        p.reject(&id).await;

        tokio::time::sleep(Duration::from_millis(10)).await;

        assert_eq!(
            p.propose(task("recon", "recon", "192.168.58.10", 1)).await,
            ProposalOutcome::Parked
        );
    }

    #[tokio::test]
    async fn unreviewed_work_expires_for_auto_release() {
        let p = ProposalPool::new(Duration::from_millis(1), 10, Duration::from_secs(600));
        p.propose(task("recon", "recon", "192.168.58.10", 1)).await;

        tokio::time::sleep(Duration::from_millis(10)).await;

        let expired = p.take_expired().await;
        assert_eq!(expired.len(), 1);
        assert_eq!(p.len().await, 0);
    }

    #[tokio::test]
    async fn fresh_work_is_not_swept_early() {
        let p = pool();
        p.propose(task("recon", "recon", "192.168.58.10", 1)).await;
        assert!(p.take_expired().await.is_empty());
        assert_eq!(p.len().await, 1);
    }

    #[tokio::test]
    async fn signature_frees_after_release() {
        let p = ProposalPool::new(Duration::from_millis(1), 10, Duration::from_secs(600));
        p.propose(task("recon", "recon", "192.168.58.10", 1)).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        p.take_expired().await;

        assert_eq!(
            p.propose(task("recon", "recon", "192.168.58.10", 1)).await,
            ProposalOutcome::Parked
        );
    }

    #[tokio::test]
    async fn capacity_is_bounded() {
        let p = ProposalPool::new(Duration::from_secs(60), 2, Duration::from_secs(600));
        p.propose(task("recon", "recon", "192.168.58.10", 1)).await;
        p.propose(task("recon", "recon", "192.168.58.11", 1)).await;
        assert_eq!(
            p.propose(task("recon", "recon", "192.168.58.12", 1)).await,
            ProposalOutcome::Full
        );
    }

    #[tokio::test]
    async fn listing_is_ordered_by_priority() {
        let p = pool();
        p.propose(task("recon", "recon", "192.168.58.10", 7)).await;
        p.propose(task("recon", "recon", "192.168.58.11", 1)).await;
        let listed = p.list(10).await;
        assert_eq!(listed[0]["target"], "192.168.58.11");
        assert_eq!(listed[0]["priority"], 1);
    }

    #[tokio::test]
    async fn a_parked_proposal_wakes_the_planner() {
        let p = Arc::new(pool());
        let waiter = p.clone();
        let woken = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(2), waiter.wait_for_arrival())
                .await
                .is_ok()
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        p.propose(task("recon", "recon", "192.168.58.10", 1)).await;

        assert!(
            woken.await.unwrap(),
            "parking work must wake the planner, or the 60s window expires before it reviews anything"
        );
    }

    #[test]
    fn mediation_defaults_on_so_the_orchestrator_directs_by_default() {
        std::env::remove_var("ARES_ORCHESTRATOR_MEDIATION");
        assert!(
            mediation_enabled(),
            "the orchestrator must direct work by default, or the rules are the team lead"
        );
        for off in ["0", "false", "off", "no", "OFF", " No "] {
            std::env::set_var("ARES_ORCHESTRATOR_MEDIATION", off);
            assert!(!mediation_enabled(), "{off} must disable mediation");
        }
        for on in ["1", "true", "on", "yes"] {
            std::env::set_var("ARES_ORCHESTRATOR_MEDIATION", on);
            assert!(mediation_enabled(), "{on} must leave mediation enabled");
        }
        std::env::remove_var("ARES_ORCHESTRATOR_MEDIATION");
    }
}
